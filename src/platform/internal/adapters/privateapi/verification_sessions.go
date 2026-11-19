package privateapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"time"

	"hukid.local/platform/internal/adapters/oid4vphttp"
	a "hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/oid4vp"
)

// VerificationCapabilityStart is granted by the local membership (ADR-0033 #5).
const VerificationCapabilityStart = "verification:start"

const (
	defaultVerificationTTL = 5 * time.Minute
	minVerificationTTL     = time.Minute
	maxVerificationBody    = 1 << 10
	// verificationExpiryMargin is how much earlier the in-memory session
	// expires than the persisted row.
	verificationExpiryMargin = 2 * time.Second
)

// VerificationStarter persists a pending session for the authorized tenant and
// returns the verifier configuration the session must use. Both identifiers
// come from the authenticated operator and the membership check, never from
// the request body.
type VerificationStarter interface {
	Start(ctx context.Context, actor, tenant string, ttl time.Duration) (sessionID, clientID, responseURI string, expiresAt time.Time, err error)
}

// VerificationHandler starts per-tenant verification sessions (VER-T11-c2).
// It lives outside internal/oid4vp and internal/adapters/oid4vphttp, which must
// not import internal/authentication (ADR-0030): it only hands the module the
// verifier configuration of the already authorized tenant.
type VerificationHandler struct {
	Operators *Handler
	// Verifier must enforce fresh MFA (the same check as invitation writes).
	Verifier InvitationVerifier
	Starter  VerificationStarter
	Sessions *oid4vp.SessionStore
	Now      func() time.Time
}

func (h *VerificationHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/v1/operator/tenants/{tenantId}/verification-sessions", h.start)
}

func (h *VerificationHandler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *VerificationHandler) ready() bool {
	return h != nil && h.Operators != nil && h.Operators.Tenancy != nil && h.Verifier != nil && h.Starter != nil && h.Sessions != nil
}

type startRequest struct {
	TTLSeconds *int `json:"ttlSeconds"`
}

func readTTL(r *http.Request) (time.Duration, error) {
	ttl := defaultVerificationTTL
	if r.Body == nil || r.ContentLength == 0 {
		return ttl, nil
	}
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		return 0, a.ErrRequest
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxVerificationBody+1))
	if err != nil || len(data) > maxVerificationBody {
		return 0, a.ErrRequest
	}
	if len(data) == 0 {
		return ttl, nil
	}
	var body startRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || decoder.Decode(new(any)) != io.EOF {
		return 0, a.ErrRequest
	}
	if body.TTLSeconds != nil {
		ttl = time.Duration(*body.TTLSeconds) * time.Second
		if *body.TTLSeconds < int(minVerificationTTL/time.Second) || ttl > oid4vp.MaxTTL {
			return 0, a.ErrRequest
		}
	}
	return ttl, nil
}

func (h *VerificationHandler) start(w http.ResponseWriter, r *http.Request) {
	if !PrepareMethod(w, r, http.MethodPost) {
		return
	}
	if !h.ready() {
		VerificationProblem(w, a.ErrDependency)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	raw, err := Bearer(r)
	if err != nil {
		VerificationProblem(w, err)
		return
	}
	// Fresh MFA first, so a stale token learns nothing about the tenant.
	operator, deadline, err := h.Verifier.VerifyInvitationOperator(ctx, raw)
	if err != nil {
		VerificationProblem(w, err)
		return
	}
	identity, err := h.Operators.Tenancy.Me(ctx, operator)
	if err != nil {
		VerificationProblem(w, err)
		return
	}
	tenant := r.PathValue("tenantId")
	member, err := h.Operators.Tenancy.Context(ctx, identity.ActorID, tenant)
	if err != nil {
		VerificationProblem(w, err)
		return
	}
	if !slices.Contains(member.Capabilities, VerificationCapabilityStart) {
		VerificationProblem(w, errVerificationForbidden)
		return
	}
	ttl, err := readTTL(r)
	if err != nil {
		VerificationProblem(w, err)
		return
	}
	if !h.now().Before(deadline) {
		VerificationProblem(w, a.ErrStepUp)
		return
	}
	sessionID, clientID, responseURI, expiresAt, err := h.Starter.Start(ctx, identity.ActorID, tenant, ttl)
	if err != nil {
		VerificationProblem(w, err)
		return
	}
	// The in-memory session must expire before the row does: complete_session
	// refuses an expired row after the anti-replay already consumed the request,
	// so a response accepted in the gap would be lost. The margin also absorbs
	// clock skew between this process and the database.
	session, err := oid4vp.NewSession(oid4vp.Config{ClientID: clientID, ResponseURI: responseURI, TTL: ttl, SessionID: sessionID, TenantID: tenant, NotAfter: expiresAt.Add(-verificationExpiryMargin)}, h.now(), nil)
	if err != nil {
		VerificationProblem(w, err)
		return
	}
	if err := h.Sessions.Put(session); err != nil {
		VerificationProblem(w, err)
		return
	}
	parsed, err := url.Parse(responseURI)
	if err != nil {
		VerificationProblem(w, oid4vp.ErrConfig)
		return
	}
	requestURI := (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: oid4vphttp.RequestPathPrefix + session.State()}).String()
	launch := url.Values{"client_id": {clientID}, "request_uri": {requestURI}, "request_uri_method": {"get"}}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"sessionId": sessionID,
		"launchUri": "openid4vp://authorize?" + launch.Encode(),
		"expiresAt": expiresAt.UTC().Format(time.RFC3339),
	})
}

var errVerificationForbidden = errors.New("verification capability required")

// VerificationProblem maps errors to generic responses: nothing about the
// verifier configuration, the store or the cause reaches the caller.
func VerificationProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errVerificationForbidden):
		writeProblem(w, 403, "forbidden", "Acceso no permitido")
	case errors.Is(err, oid4vp.ErrStoreFull):
		w.Header().Set("Retry-After", "5")
		writeProblem(w, 429, "too_many_sessions", "Demasiadas sesiones abiertas")
	case errors.Is(err, oid4vp.ErrConfig):
		w.Header().Set("Retry-After", "1")
		writeProblem(w, 503, "dependency_unavailable", "Servicio no disponible")
	default:
		InvitationProblem(w, err, true)
	}
}

// Package oid4vphttp serves the two wallet-facing OpenID4VP endpoints of the
// verification adapter (FEAT-004, VER-T10, increment d): the signed request
// object and the direct_post.jwt response. cmd/api mounts it in two ways: the
// laboratory mount (one seeded session, process-wide key) and the per-tenant
// mount (VER-T11-d), where Keys, VerifierFor and a SessionResults sink bind
// each request to a persisted session and its tenant (ADR-0033, ADR-0034).
//
// The package never logs. The response carries a vp_token, so error bodies and
// status codes are generic and the cause stays out of every output.
package oid4vphttp

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net/http"
	"strings"
	"time"

	"hukid.local/platform/internal/oid4vp"
	"hukid.local/platform/internal/verification"
)

const (
	// RequestPathPrefix is followed by the session state: GET <prefix><state>.
	RequestPathPrefix = "/oid4vp/request/"
	// ResponsePath receives the wallet's direct_post.jwt response.
	ResponsePath = "/oid4vp/response"

	maxStateLength = 128
	// formOverhead leaves room for the "response=" key and URL encoding.
	formOverhead = 16 << 10
)

// Results receives the outcome of a verified presentation. The report holds
// codes, a digest and per-credential checks, never the JWS or the claims. An
// error from Deliver is reported to the wallet as a generic failure so the
// request is not silently lost.
type Results interface {
	Deliver(state string, report verification.PresentationReport) error
}

// SessionResults is implemented by a Results that persists the outcome of a
// session bound to a tenant (ADR-0033). The handler uses it instead of Deliver
// whenever the session carries a persisted session id.
type SessionResults interface {
	DeliverSession(sessionID string, report verification.PresentationReport) error
}

// SigningKeys provides the request-signing key of a bound session's tenant
// (ADR-0034). It returns oid4vp.ErrNoSigningKey for a session that is unknown,
// finished or expired, or whose tenant has no key. The caller never retains or
// logs the key.
type SigningKeys interface {
	SigningKey(ctx context.Context, sessionID string) (*ecdsa.PrivateKey, string, [][]byte, error)
}

// Handler serves the wallet-facing endpoints of one verifier.
type Handler struct {
	Sessions *oid4vp.SessionStore
	Verifier *verification.Verifier
	// VerifierFor, when set, replaces Verifier: it returns the verifier of the
	// session's tenant, so replay is scoped per tenant (ADR-0033 #4).
	VerifierFor func(tenant string) (*verification.Verifier, error)
	Results     Results
	// SigningKey signs request objects with ES256; Chain is its certificate
	// chain (leaf first, DER) for x509_san_dns, empty in the laboratory.
	SigningKey *ecdsa.PrivateKey
	Chain      [][]byte
	// Keys, when set, replaces SigningKey and Chain with the key custodied for
	// the session's tenant. A session without a persisted id is then refused.
	Keys SigningKeys
	Now  func() time.Time
}

// Routes registers both endpoints on mux.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc(RequestPathPrefix, h.request)
	mux.HandleFunc(ResponsePath, h.response)
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handler) ready() bool {
	return h != nil && h.Sessions != nil && (h.Verifier != nil || h.VerifierFor != nil) && h.Results != nil && (h.SigningKey != nil || h.Keys != nil)
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func fail(w http.ResponseWriter, status int, code string) {
	noStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
}

// request returns the signed request object for a session (request_uri flow).
func (h *Handler) request(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		fail(w, http.StatusMethodNotAllowed, "invalid_request")
		return
	}
	if !h.ready() {
		fail(w, http.StatusServiceUnavailable, "server_error")
		return
	}
	state := strings.TrimPrefix(r.URL.Path, RequestPathPrefix)
	if state == "" || len(state) > maxStateLength || strings.Contains(state, "/") || r.URL.RawQuery != "" {
		fail(w, http.StatusNotFound, "invalid_request_uri")
		return
	}
	session, err := h.Sessions.Get(state)
	if err != nil {
		fail(w, http.StatusNotFound, "invalid_request_uri")
		return
	}
	key, chain := h.SigningKey, h.Chain
	if h.Keys != nil {
		if session.SessionID() == "" {
			fail(w, http.StatusNotFound, "invalid_request_uri")
			return
		}
		var err error
		key, _, chain, err = h.Keys.SigningKey(r.Context(), session.SessionID())
		if errors.Is(err, oid4vp.ErrNoSigningKey) {
			fail(w, http.StatusNotFound, "invalid_request_uri")
			return
		}
		if err != nil {
			fail(w, http.StatusInternalServerError, "server_error")
			return
		}
	}
	object, err := session.SignRequestObject(key, chain)
	if err != nil {
		fail(w, http.StatusInternalServerError, "server_error")
		return
	}
	noStore(w)
	w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(object))
}

// response receives the encrypted wallet response. The session is found by the
// key id in the JWE header, which is the only identifier outside the
// ciphertext; an unauthenticated sender therefore cannot burn a request, as
// HandleResponse consumes it only after the holder signature is valid.
func (h *Handler) response(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		fail(w, http.StatusMethodNotAllowed, "invalid_request")
		return
	}
	if !h.ready() {
		fail(w, http.StatusServiceUnavailable, "server_error")
		return
	}
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		fail(w, http.StatusUnsupportedMediaType, "invalid_request")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, oid4vp.MaxResponseBytes+formOverhead)
	if err := r.ParseForm(); err != nil || len(r.PostForm) != 1 || len(r.PostForm["response"]) != 1 {
		fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	response := r.PostForm.Get("response")
	kid, err := oid4vp.ResponseKeyID(response)
	if err != nil {
		fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	session, err := h.Sessions.GetByKeyID(kid)
	if err != nil {
		fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	verifier := h.Verifier
	if h.VerifierFor != nil {
		if verifier, err = h.VerifierFor(session.TenantID()); err != nil || verifier == nil {
			fail(w, http.StatusInternalServerError, "server_error")
			return
		}
	}
	report, err := session.HandleResponse(verifier, h.now(), response)
	switch {
	case errors.Is(err, oid4vp.ErrSessionExpired), errors.Is(err, oid4vp.ErrResponseInvalid):
		fail(w, http.StatusBadRequest, "invalid_request")
		return
	case err != nil:
		fail(w, http.StatusInternalServerError, "server_error")
		return
	}
	if err := h.deliver(session, report); err != nil {
		fail(w, http.StatusInternalServerError, "server_error")
		return
	}
	h.Sessions.Remove(session.State())
	noStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{}"))
}

// deliver hands the report to the persisted-session sink when the session is
// bound to one, and to the plain sink otherwise (laboratory).
func (h *Handler) deliver(session *oid4vp.Session, report verification.PresentationReport) error {
	if id := session.SessionID(); id != "" {
		sink, ok := h.Results.(SessionResults)
		if !ok {
			return errors.New("results cannot store a bound session")
		}
		return sink.DeliverSession(id, report)
	}
	return h.Results.Deliver(session.State(), report)
}

package console

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"time"

	"hukid.local/platform/internal/adapters/privateapi"
	a "hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
)

type CommandHandler struct {
	Login    *a.LoginService
	Verifier a.OperatorVerifier
	Tenancy  *tenancy.Service
	limits   *LoginHandler
}

func NewCommands(login *a.LoginService, verifier a.OperatorVerifier, tenants *tenancy.Service) *CommandHandler {
	return &CommandHandler{Login: login, Verifier: verifier, Tenancy: tenants, limits: New(login)}
}

func (h *CommandHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/console/auth/step-up", h.serve)
	mux.HandleFunc("/console/auth/tenant-context", h.serve)
}

// decodeCommand accepts exactly one required string property, including no
// duplicates, unknown claims, trailing JSON, or unbounded bodies.
func decodeCommand(w http.ResponseWriter, r *http.Request, property string) (string, error) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return "", a.ErrRequest
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return "", a.ErrRequest
	}
	key, err := d.Token()
	if err != nil || key != property {
		return "", a.ErrRequest
	}
	var value string
	if d.Decode(&value) != nil || value == "" || len(value) > 128 || d.More() {
		return "", a.ErrRequest
	}
	if closing, err := d.Token(); err != nil || closing != json.Delim('}') {
		return "", a.ErrRequest
	}
	if d.Decode(new(any)) != io.EOF {
		return "", a.ErrRequest
	}
	return value, nil
}

func (h *CommandHandler) serve(w http.ResponseWriter, r *http.Request) {
	if !privateapi.PrepareMethod(w, r, http.MethodPost) {
		return
	}
	p := h.Login.Policy
	origins, proofs := r.Header.Values("Origin"), r.Header.Values("X-CSRF-Token")
	if len(origins) != 1 || origins[0] != p.ConsoleOrigin {
		privateapi.Problem(w, a.ErrOrigin, false)
		return
	}
	if len(proofs) != 1 || len(proofs[0]) != 43 {
		privateapi.Problem(w, a.ErrCSRF, false)
		return
	}
	var cookie string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == p.CookieName {
			cookie = c.Value
			count++
		}
	}
	if count != 1 {
		privateapi.Problem(w, a.ErrCSRF, false)
		return
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		privateapi.Problem(w, a.ErrRequest, false)
		return
	}
	if !h.limits.allow("command-ip:" + ip) {
		h.limits.rateLimited(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	session, err := h.Login.Sessions.CheckCommand(ctx, cookie, proofs[0])
	if err != nil {
		privateapi.Problem(w, err, false)
		return
	}
	if !h.limits.allow("command-actor:" + hex.EncodeToString(a.Digest(session.ActorID))) {
		h.limits.rateLimited(w)
		return
	}
	property := "returnTo"
	if r.URL.Path == "/console/auth/tenant-context" {
		property = "tenantId"
	}
	value, err := decodeCommand(w, r, property)
	if err != nil {
		privateapi.Problem(w, err, false)
		return
	}
	if property == "returnTo" {
		start, err := h.Login.StartStepUp(ctx, cookie, proofs[0], value)
		if err != nil {
			privateapi.Problem(w, err, false)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: TransactionCookie, Value: start.Binding, Path: "/console/auth", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: *p.CookieSecure, Expires: start.ExpiresAt, MaxAge: p.TransactionSeconds})
		w.Header().Set("Location", start.Location)
		w.WriteHeader(http.StatusSeeOther)
		return
	}
	operator, err := h.Verifier.VerifyOperator(ctx, session.AccessToken)
	if err != nil {
		privateapi.Problem(w, err, false)
		return
	}
	identity, err := h.Tenancy.Me(ctx, operator)
	if err != nil {
		privateapi.Problem(w, err, false)
		return
	}
	if identity.ActorID != session.ActorID {
		privateapi.Problem(w, a.ErrSession, false)
		return
	}
	selection, err := h.Tenancy.Context(ctx, identity.ActorID, value)
	if err != nil {
		privateapi.Problem(w, err, false)
		return
	}
	result, err := h.Login.SelectContext(ctx, cookie, proofs[0], a.ContextSelection{TenantID: selection.TenantID, Revision: selection.AuthorizationRevision})
	if err != nil {
		privateapi.Problem(w, err, false)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: p.CookieName, Value: result.Cookie, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: *p.CookieSecure, Expires: result.ExpiresAt, MaxAge: max(1, int(result.ExpiresAt.Sub(h.Login.Now()).Seconds()))})
	w.WriteHeader(http.StatusNoContent)
}

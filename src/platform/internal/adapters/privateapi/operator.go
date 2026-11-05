// Package privateapi exposes Bearer-only operator APIs independently of browser cookies.
package privateapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
	"net/http"
	"strings"
	"time"
)

type Handler struct {
	Verifier authentication.OperatorVerifier
	Tenancy  *tenancy.Service
}
type Tenant struct {
	TenantID    string `json:"tenantId"`
	DisplayName string `json:"displayName"`
}
type Me struct {
	ActorID string   `json:"actorId"`
	Tenants []Tenant `json:"tenants"`
}
type Context struct {
	TenantID              string   `json:"tenantId"`
	Capabilities          []string `json:"capabilities"`
	IssuerIDs             []string `json:"issuerIds"`
	AuthorizationRevision int64    `json:"authorizationRevision"`
}

func IdentityDTO(i tenancy.Identity) Me {
	m := Me{ActorID: i.ActorID, Tenants: []Tenant{}}
	for _, t := range i.Tenants {
		m.Tenants = append(m.Tenants, Tenant{t.ID, t.DisplayName})
	}
	return m
}
func ContextDTO(c tenancy.Context) Context {
	return Context{c.TenantID, c.Capabilities, c.IssuerIDs, c.AuthorizationRevision}
}
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/v1/operator/me", h.Protect(h.serve))
	mux.HandleFunc("/v1/operator/tenants/{tenantId}/context", h.Protect(h.serve))
}

// Prepare also serves the cookie-facing read endpoint; challenges remain Bearer-only.
func Prepare(w http.ResponseWriter, r *http.Request) bool {
	return PrepareMethod(w, r, http.MethodGet)
}
func PrepareMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		Problem(w, authentication.ErrDependency, false)
		return false
	}
	w.Header().Set("X-Correlation-Id", hex.EncodeToString(b))
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeProblem(w, 405, "invalid_request", "Método no permitido")
		return false
	}
	return true
}
func Bearer(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) > (64<<10)+7 {
		return "", authentication.ErrCredential
	}
	parts := strings.Split(values[0], " ")
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", authentication.ErrCredential
	}
	return parts[1], nil
}

// Protect authenticates an operator and resolves only their own local identity.
// Tenant handlers must additionally revalidate membership with Tenancy.Context.
func (h *Handler) Protect(next func(http.ResponseWriter, *http.Request, tenancy.Identity)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !Prepare(w, r) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		raw, err := Bearer(r)
		if err != nil {
			Problem(w, err, true)
			return
		}
		operator, err := h.Verifier.VerifyOperator(ctx, raw)
		if err != nil {
			Problem(w, err, true)
			return
		}
		identity, err := h.Tenancy.Me(ctx, operator)
		if err != nil {
			Problem(w, err, true)
			return
		}
		next(w, r.WithContext(ctx), identity)
	}
}
func (h *Handler) serve(w http.ResponseWriter, r *http.Request, identity tenancy.Identity) {
	if r.URL.Path == "/v1/operator/me" {
		JSON(w, IdentityDTO(identity))
		return
	}
	c, err := h.Tenancy.Context(r.Context(), identity.ActorID, r.PathValue("tenantId"))
	if err != nil {
		Problem(w, err, true)
		return
	}
	JSON(w, ContextDTO(c))
}
func JSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func Problem(w http.ResponseWriter, err error, bearer bool) {
	switch {
	case errors.Is(err, authentication.ErrOrigin):
		writeProblem(w, 403, "origin_invalid", "Origen de solicitud inválido")
	case errors.Is(err, authentication.ErrCSRF):
		writeProblem(w, 403, "csrf_invalid", "Prueba de solicitud inválida")
	case errors.Is(err, authentication.ErrRefreshBusy):
		w.Header().Set("Retry-After", "1")
		writeProblem(w, 409, "refresh_in_progress", "Renovación en curso")
	case errors.Is(err, authentication.ErrRequest):
		writeProblem(w, 422, "invalid_request", "Solicitud inválida")
	case errors.Is(err, authentication.ErrSession), errors.Is(err, authentication.ErrCredential):
		code := "invalid_session"
		if bearer {
			code = "operator_token_invalid"
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		}
		writeProblem(w, 401, code, "Autenticación requerida")
	case errors.Is(err, authentication.ErrMFA):
		writeProblem(w, 403, "mfa_required", "Se requiere MFA")
	case errors.Is(err, authentication.ErrTenant):
		writeProblem(w, 404, "tenant_not_found", "Recurso no encontrado")
	default:
		w.Header().Set("Retry-After", "1")
		writeProblem(w, 503, "dependency_unavailable", "Dependencia no disponible")
	}
}
func writeProblem(w http.ResponseWriter, status int, code, title string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "title": title, "status": status, "code": code, "correlationId": w.Header().Get("X-Correlation-Id")})
}

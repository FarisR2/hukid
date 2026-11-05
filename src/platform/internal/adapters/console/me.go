package console

import (
	"context"
	"hukid.local/platform/internal/adapters/privateapi"
	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
	"net/http"
	"slices"
	"time"
)

type MeHandler struct {
	Sessions *authentication.SessionService
	Verifier authentication.OperatorVerifier
	Tenancy  *tenancy.Service
}
type consoleMe struct {
	privateapi.Me
	ActiveTenantID *string             `json:"activeTenantId"`
	Context        *privateapi.Context `json:"context"`
	CSRFToken      string              `json:"csrfToken"`
}

func (h *MeHandler) Register(mux *http.ServeMux) { mux.HandleFunc("/console/api/me", h.serve) }
func (h *MeHandler) serve(w http.ResponseWriter, r *http.Request) {
	if !privateapi.Prepare(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var cookie string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == h.Sessions.Policy.CookieName {
			count++
			cookie = c.Value
		}
	}
	if count != 1 {
		privateapi.Problem(w, authentication.ErrSession, false)
		return
	}
	session, err := h.Sessions.Read(ctx, cookie)
	if err != nil {
		privateapi.Problem(w, err, false)
		return
	}
	// The in-process Management port performs exactly the same token validation.
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
		privateapi.Problem(w, authentication.ErrSession, false)
		return
	}
	result := consoleMe{Me: privateapi.IdentityDTO(identity), CSRFToken: session.CSRF}
	if session.ActiveTenantID != "" {
		if !slices.ContainsFunc(identity.Tenants, func(t tenancy.Tenant) bool { return t.ID == session.ActiveTenantID }) {
			privateapi.Problem(w, authentication.ErrTenant, false)
			return
		}
		c, err := h.Tenancy.Context(ctx, identity.ActorID, session.ActiveTenantID)
		if err != nil {
			privateapi.Problem(w, err, false)
			return
		}
		dto := privateapi.ContextDTO(c)
		result.Context = &dto
		result.ActiveTenantID = &session.ActiveTenantID
	}
	if err := h.Sessions.Touch(ctx, cookie); err != nil {
		privateapi.Problem(w, err, false)
		return
	}
	privateapi.JSON(w, result)
}

package console

import (
	"context"
	"hukid.local/platform/internal/adapters/privateapi"
	"hukid.local/platform/internal/authentication"
	"net/http"
	"time"
)

type DirectoryHandler struct {
	Auth       *MeHandler
	Management *privateapi.DirectoryHandler
}

func (h *DirectoryHandler) Register(mux *http.ServeMux) {
	for _, kind := range []string{"memberships", "invitations"} {
		mux.HandleFunc("/console/api/tenants/{tenantId}/"+kind, func(w http.ResponseWriter, r *http.Request) { h.serve(w, r, kind) })
	}
}
func (h *DirectoryHandler) serve(w http.ResponseWriter, r *http.Request, kind string) {
	if !privateapi.Prepare(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	cookie := ""
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == h.Auth.Sessions.Policy.CookieName {
			cookie = c.Value
			count++
		}
	}
	fail := func(err error) { privateapi.DirectoryProblem(w, err, false) }
	if count != 1 {
		fail(authentication.ErrSession)
		return
	}
	session, err := h.Auth.Sessions.Read(ctx, cookie)
	if err != nil {
		fail(err)
		return
	}
	operator, err := h.Auth.Verifier.VerifyOperator(ctx, session.AccessToken)
	if err != nil {
		fail(err)
		return
	}
	identity, err := h.Auth.Tenancy.Me(ctx, operator)
	if err != nil {
		fail(err)
		return
	}
	if identity.ActorID != session.ActorID {
		fail(authentication.ErrSession)
		return
	}
	// Browser reads must use the explicitly selected context, not a URL switch.
	if session.ActiveTenantID == "" || session.ActiveTenantID != r.PathValue("tenantId") {
		fail(authentication.ErrTenant)
		return
	}
	if err = h.Auth.Sessions.Touch(ctx, cookie); err != nil {
		fail(err)
		return
	}
	h.Management.Serve(w, r.WithContext(ctx), identity.ActorID, kind, false)
}

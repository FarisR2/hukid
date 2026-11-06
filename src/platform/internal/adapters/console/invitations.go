package console

import (
	"context"
	"net/http"
	"strings"
	"time"

	"hukid.local/platform/internal/adapters/privateapi"
	a "hukid.local/platform/internal/authentication"
)

type InvitationHandler struct {
	Auth       *MeHandler
	Management *privateapi.InvitationHandler
}

func (h *InvitationHandler) Register(mux *http.ServeMux) {
	for _, path := range []string{"/console/api/tenants/{tenantId}/invitations", "/console/api/tenants/{tenantId}/invitations/{invitationId}/revocations"} {
		pattern := path
		if !strings.HasSuffix(path, "/revocations") {
			pattern = "POST " + path
		}
		mux.HandleFunc(pattern, h.serve)
	}
}
func (h *InvitationHandler) serve(w http.ResponseWriter, r *http.Request) {
	if !privateapi.PrepareMethod(w, r, http.MethodPost) {
		return
	}
	fail := func(err error) { privateapi.InvitationProblem(w, err, false) }
	origins, proofs := r.Header.Values("Origin"), r.Header.Values("X-CSRF-Token")
	if len(origins) != 1 || origins[0] != h.Auth.Sessions.Policy.ConsoleOrigin {
		fail(a.ErrOrigin)
		return
	}
	if len(proofs) != 1 {
		fail(a.ErrCSRF)
		return
	}
	cookie := ""
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == h.Auth.Sessions.Policy.CookieName {
			cookie = c.Value
			count++
		}
	}
	if count != 1 {
		fail(a.ErrSession)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	session, err := h.Auth.Sessions.CheckCommand(ctx, cookie, proofs[0])
	if err != nil {
		fail(err)
		return
	}
	if session.ActiveTenantID == "" || session.ActiveTenantID != r.PathValue("tenantId") {
		fail(a.ErrTenant)
		return
	}
	h.Management.Authenticate(w, r.WithContext(ctx), session.AccessToken, session.ActorID, false)
}

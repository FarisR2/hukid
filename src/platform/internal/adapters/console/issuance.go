package console

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"hukid.local/platform/internal/adapters/privateapi"
	a "hukid.local/platform/internal/authentication"
)

// IssuanceHandler exposes the private issuer administration API to the
// same-origin console while keeping the operator bearer token in the BFF.
type IssuanceHandler struct {
	Auth       *MeHandler
	Management http.Handler
}

func (h *IssuanceHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/console/api/tenants/{tenantId}/{rest...}", h.serve)
}

func (h *IssuanceHandler) serve(w http.ResponseWriter, r *http.Request) {
	if !privateapi.PrepareMethod(w, r, r.Method) {
		return
	}
	if h.Auth == nil || h.Auth.Sessions == nil || h.Auth.Verifier == nil || h.Auth.Tenancy == nil || h.Management == nil {
		privateapi.Problem(w, a.ErrDependency, false)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var cookie string
	cookieCount := 0
	for _, c := range r.Cookies() {
		if c.Name == h.Auth.Sessions.Policy.CookieName {
			cookie = c.Value
			cookieCount++
		}
	}
	if cookieCount != 1 {
		privateapi.Problem(w, a.ErrSession, false)
		return
	}

	var session a.SessionView
	var err error
	if r.Method == http.MethodGet {
		session, err = h.Auth.Sessions.Read(ctx, cookie)
	} else {
		origins, proofs := r.Header.Values("Origin"), r.Header.Values("X-CSRF-Token")
		if len(origins) != 1 || origins[0] != h.Auth.Sessions.Policy.ConsoleOrigin {
			privateapi.Problem(w, a.ErrOrigin, false)
			return
		}
		if len(proofs) != 1 {
			privateapi.Problem(w, a.ErrCSRF, false)
			return
		}
		session, err = h.Auth.Sessions.CheckCommand(ctx, cookie, proofs[0])
	}
	if err != nil {
		privateapi.Problem(w, err, false)
		return
	}

	operator, err := h.Auth.Verifier.VerifyOperator(ctx, session.AccessToken)
	if err != nil {
		privateapi.Problem(w, err, false)
		return
	}
	identity, err := h.Auth.Tenancy.Me(ctx, operator)
	if err != nil {
		privateapi.Problem(w, err, false)
		return
	}
	if identity.ActorID != session.ActorID {
		privateapi.Problem(w, a.ErrSession, false)
		return
	}
	tenantID := r.PathValue("tenantId")
	if tenantID == "" || session.ActiveTenantID == "" || session.ActiveTenantID != tenantID {
		privateapi.Problem(w, a.ErrTenant, false)
		return
	}
	if _, err = h.Auth.Tenancy.Context(ctx, identity.ActorID, tenantID); err != nil {
		privateapi.Problem(w, err, false)
		return
	}
	if err = h.Auth.Sessions.Touch(ctx, cookie); err != nil {
		privateapi.Problem(w, err, false)
		return
	}

	// This in-process mux contains only the explicitly registered issuer
	// administration routes. It is not a general-purpose proxy.
	managementRequest := r.Clone(ctx)
	managementURL := *r.URL
	segments := strings.Split(strings.TrimPrefix(r.PathValue("rest"), "/"), "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	managementURL.Path = "/v1/operator/tenants/" + url.PathEscape(tenantID) + "/" + strings.Join(segments, "/")
	managementURL.RawPath = ""
	managementRequest.URL = &managementURL
	managementRequest.Header = r.Header.Clone()
	managementRequest.Header.Del("Cookie")
	managementRequest.Header.Del("Origin")
	managementRequest.Header.Del("X-CSRF-Token")
	managementRequest.Header.Set("Authorization", "Bearer "+session.AccessToken)
	h.Management.ServeHTTP(w, managementRequest)
}

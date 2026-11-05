package console

import (
	"context"
	"encoding/hex"
	"net"
	"net/http"
	"time"

	"hukid.local/platform/internal/adapters/privateapi"
	a "hukid.local/platform/internal/authentication"
)

type SessionHandler struct {
	Service *a.SessionLifecycle
	limits  *LoginHandler
}

func NewSessions(service *a.SessionLifecycle) *SessionHandler {
	return &SessionHandler{Service: service, limits: New(&a.LoginService{Policy: service.Sessions.Policy, Now: service.Sessions.Now})}
}

func (h *SessionHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/console/auth/refresh", h.serve)
	mux.HandleFunc("/console/auth/logout", h.serve)
}

func (h *SessionHandler) serve(w http.ResponseWriter, r *http.Request) {
	if !privateapi.PrepareMethod(w, r, http.MethodPost) {
		return
	}
	p := h.Service.Sessions.Policy
	origins := r.Header.Values("Origin")
	proofs := r.Header.Values("X-CSRF-Token")
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
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		privateapi.Problem(w, a.ErrRequest, false)
		return
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		privateapi.Problem(w, a.ErrRequest, false)
		return
	}
	if !h.limits.allow("command-ip:"+ip) || !h.limits.allow("command-cookie:"+hex.EncodeToString(a.Digest(cookie))) {
		h.limits.rateLimited(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if r.URL.Path == "/console/auth/logout" {
		if err := h.Service.Logout(ctx, cookie, proofs[0]); err != nil {
			privateapi.Problem(w, err, false)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: p.CookieName, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: *p.CookieSecure, MaxAge: -1, Expires: time.Unix(1, 0)})
	} else {
		result, err := h.Service.Refresh(ctx, cookie, proofs[0])
		if err != nil {
			privateapi.Problem(w, err, false)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: p.CookieName, Value: result.Cookie, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: *p.CookieSecure, Expires: result.ExpiresAt, MaxAge: max(1, int(result.ExpiresAt.Sub(h.Service.Sessions.Now()).Seconds()))})
	}
	w.WriteHeader(http.StatusNoContent)
}

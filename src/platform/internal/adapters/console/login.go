// Package console is the browser-facing HTTP adapter, never a bearer API.
package console

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"hukid.local/platform/internal/authentication"
)

const TransactionCookie = "hukid_test_transaction"

type limitEntry struct {
	start time.Time
	count int
}
type LoginHandler struct {
	Service *authentication.LoginService
	mu      sync.Mutex
	limits  map[string]limitEntry
}

func New(service *authentication.LoginService) *LoginHandler {
	return &LoginHandler{Service: service, limits: make(map[string]limitEntry)}
}

func (h *LoginHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/console/auth/login", h.serve)
	mux.HandleFunc("/console/auth/callback", h.serve)
}

func (h *LoginHandler) allow(key string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.Service.Now()
	window := time.Duration(h.Service.Policy.LoginRateLimit.WindowSeconds) * time.Second
	for k, v := range h.limits {
		if !now.Before(v.start.Add(window)) {
			delete(h.limits, k)
		}
	}
	v, ok := h.limits[key]
	if !ok {
		if len(h.limits) >= 4096 {
			return false
		}
		v.start = now
	}
	v.count++
	h.limits[key] = v
	return v.count <= h.Service.Policy.LoginRateLimit.MaxAttempts
}

func (h *LoginHandler) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	correlation := make([]byte, 16)
	if _, err := rand.Read(correlation); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("X-Correlation-Id", hex.EncodeToString(correlation))
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		h.writeProblem(w, http.StatusMethodNotAllowed, "invalid_request", "Método no permitido")
		return
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		h.problem(w, authentication.ErrRequest)
		return
	}
	if !h.allow("ip:" + ip) {
		h.rateLimited(w)
		return
	}
	if len(r.URL.RawQuery) > 8192 {
		h.problem(w, authentication.ErrRequest)
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		h.problem(w, authentication.ErrRequest)
		return
	}
	for _, values := range q {
		if len(values) != 1 || len(values[0]) > 2048 {
			h.problem(w, authentication.ErrRequest)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if r.URL.Path == "/console/auth/login" {
		h.start(ctx, w, r, q)
		return
	}
	h.complete(ctx, w, r, q)
}

func (h *LoginHandler) start(ctx context.Context, w http.ResponseWriter, r *http.Request, q url.Values) {
	// The baseline deliberately accepts only the literal internal root.
	if r.URL.RawQuery != "" && r.URL.RawQuery != "returnTo=/" {
		h.problem(w, authentication.ErrRequest)
		return
	}
	start, err := h.Service.Start(ctx, q.Get("returnTo"))
	if err != nil {
		h.problem(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: TransactionCookie, Value: start.Binding, Path: "/console/auth", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: *h.Service.Policy.CookieSecure, Expires: start.ExpiresAt, MaxAge: h.Service.Policy.TransactionSeconds})
	w.Header().Set("Location", start.Location)
	w.WriteHeader(http.StatusSeeOther)
}

func (h *LoginHandler) complete(ctx context.Context, w http.ResponseWriter, r *http.Request, q url.Values) {
	var binding string
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == TransactionCookie {
			binding = cookie.Value
			count++
		}
	}
	if count != 1 || len(binding) != 43 {
		h.problem(w, authentication.ErrCallback)
		return
	}
	if !h.allow("binding:" + hex.EncodeToString(authentication.Digest(binding))) {
		h.rateLimited(w)
		return
	}
	if q.Get("state") == "" || q.Get("iss") == "" || (q.Get("code") == "") == (q.Get("error") == "") {
		h.problem(w, authentication.ErrCallback)
		return
	}
	result, err := h.Service.Complete(ctx, q.Get("state"), binding, q.Get("iss"), q.Get("code"), q.Get("error"))
	// A matching request that reached consumption cannot reuse its browser binding.
	if err != nil && !errors.Is(err, authentication.ErrCallback) {
		h.clearTransaction(w)
	}
	if err != nil {
		h.problem(w, err)
		return
	}
	h.clearTransaction(w)
	http.SetCookie(w, &http.Cookie{Name: h.Service.Policy.CookieName, Value: result.Cookie, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: *h.Service.Policy.CookieSecure, Expires: result.ExpiresAt, MaxAge: max(1, int(result.ExpiresAt.Sub(h.Service.Now()).Seconds()))})
	w.Header().Set("Location", result.ReturnTo)
	w.WriteHeader(http.StatusSeeOther)
}

func (h *LoginHandler) clearTransaction(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: TransactionCookie, Value: "", Path: "/console/auth", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: *h.Service.Policy.CookieSecure, MaxAge: -1, Expires: time.Unix(1, 0)})
}

func (h *LoginHandler) rateLimited(w http.ResponseWriter) {
	h.writeProblem(w, 429, "rate_limited", "Demasiados intentos")
}
func (h *LoginHandler) problem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, authentication.ErrRequest):
		h.writeProblem(w, 400, "invalid_request", "Solicitud inválida")
	case errors.Is(err, authentication.ErrCallback):
		h.writeProblem(w, 400, "authentication_failed", "Autenticación fallida")
	case errors.Is(err, authentication.ErrMFA):
		h.writeProblem(w, 403, "mfa_required", "Se requiere MFA")
	default:
		h.writeProblem(w, 503, "dependency_unavailable", "Dependencia no disponible")
	}
}
func (h *LoginHandler) writeProblem(w http.ResponseWriter, status int, code, title string) {
	w.Header().Set("Content-Type", "application/problem+json")
	if status == 429 || status == 503 {
		w.Header().Set("Retry-After", strconv.Itoa(h.Service.Policy.LoginRateLimit.WindowSeconds))
	}
	w.WriteHeader(status)
	// All fields are fixed or freshly generated; no IdP error descriptions escape.
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "title": title, "status": status, "code": code, "correlationId": w.Header().Get("X-Correlation-Id")})
}

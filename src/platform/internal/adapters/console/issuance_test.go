package console

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	a "hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
)

type issuanceTestSessionStore struct {
	session a.ReadSession
	err     error
	touches int
}

func (s *issuanceTestSessionStore) ReadSession(context.Context, []byte, time.Time) (a.ReadSession, error) {
	return s.session, s.err
}

func (s *issuanceTestSessionStore) TouchSession(context.Context, []byte, time.Time, time.Duration) error {
	s.touches++
	return s.err
}

func (s *issuanceTestSessionStore) ReconcileSessionContext(context.Context, []byte, a.ReadSession, a.ContextSelection, time.Time) error {
	return nil
}

type issuanceTestContextReader struct {
	selection a.ContextSelection
	err       error
}

func (r issuanceTestContextReader) SessionContext(context.Context, string, string) (a.ContextSelection, error) {
	return r.selection, r.err
}

type issuanceTestCipher struct{ plain []byte }

func (c issuanceTestCipher) Seal(b []byte, _ string) (a.Envelope, error) {
	return a.Envelope{Ciphertext: b}, nil
}

func (c issuanceTestCipher) Open(a.Envelope, string) ([]byte, error) {
	return slices.Clone(c.plain), nil
}

type issuanceTestVerifier struct {
	operator a.Operator
	err      error
}

func (v issuanceTestVerifier) VerifyOperator(context.Context, string) (a.Operator, error) {
	return v.operator, v.err
}

type issuanceTestTenancyStore struct {
	identity   tenancy.Identity
	membership tenancy.Membership
	err        error
}

func (s issuanceTestTenancyStore) Identity(_ context.Context, op a.Operator) (tenancy.Identity, error) {
	if s.err != nil {
		return tenancy.Identity{}, s.err
	}
	if op.Subject == "other-sub" {
		return tenancy.Identity{ActorID: "actor-other"}, nil
	}
	return s.identity, nil
}

func (s issuanceTestTenancyStore) Membership(context.Context, string, string) (tenancy.Membership, error) {
	if s.err != nil {
		return tenancy.Membership{}, s.err
	}
	return s.membership, nil
}

func newConsoleIssuanceTestFixture(t *testing.T, activeTenant string) (*IssuanceHandler, *int, *http.Request, a.Policy, string, string) {
	t.Helper()
	now := time.Unix(2000000000, 0)
	cookie := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	csrf := base64.RawURLEncoding.EncodeToString(append([]byte{1}, make([]byte, 31)...))
	policy := a.Policy{
		ConsoleOrigin:          "http://127.0.0.1:8080",
		CookieName:             "hukid_test_session",
		SessionIdleSeconds:     1800,
		SessionAbsoluteSeconds: 3600,
	}
	plain, err := json.Marshal(a.SessionSecrets{
		AccessToken:  "operator-access-token",
		RefreshToken: "operator-refresh-token",
		CSRF:         csrf,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &issuanceTestSessionStore{
		session: a.ReadSession{
			FamilyID:              "family-1",
			ActorID:               "actor-1",
			ActiveTenantID:        activeTenant,
			AuthorizationRevision: 1,
			PolicyVersion:         "auth-test-v1",
			Generation:            1,
			CSRFHash:              a.Digest(csrf),
			CreatedAt:             now.Add(-time.Minute),
			FamilyCreatedAt:       now.Add(-time.Minute),
			LastSeenAt:            now.Add(-time.Minute),
			IdleExpiresAt:         now.Add(time.Minute),
			AbsoluteExpiresAt:     now.Add(time.Hour),
		},
	}
	contexts := issuanceTestContextReader{selection: a.ContextSelection{TenantID: activeTenant, Revision: 1}}
	tenancySvc, err := tenancy.New(issuanceTestTenancyStore{
		identity:   tenancy.Identity{ActorID: "actor-1", Tenants: []tenancy.Tenant{{ID: "tenant-a", DisplayName: "Tenant A"}}},
		membership: tenancy.Membership{Roles: []string{"tenant_admin"}, Revision: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	auth := &MeHandler{
		Sessions: &a.SessionService{
			Store:    store,
			Contexts: contexts,
			Cipher:   issuanceTestCipher{plain: plain},
			Policy:   policy,
			Now:      func() time.Time { return now },
		},
		Verifier: issuanceTestVerifier{operator: a.Operator{Issuer: "https://auth.example", Subject: "sub-1"}},
		Tenancy:  tenancySvc,
	}
	calls := 0
	management := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	h := &IssuanceHandler{Auth: auth, Management: management}
	req := httptest.NewRequest(http.MethodPost, policy.ConsoleOrigin+"/console/api/tenants/tenant-a/issuers", strings.NewReader(`{"slug":"unas"}`))
	req.Header.Set("Origin", policy.ConsoleOrigin)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: policy.CookieName, Value: cookie})
	return h, &calls, req, policy, cookie, csrf
}

func TestConsoleIssuanceRejectsInvalidRequestsBeforeStorage(t *testing.T) {
	policy := a.Policy{ConsoleOrigin: "http://127.0.0.1:8080", CookieName: "hukid_test_session"}
	cookie := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	csrf := base64.RawURLEncoding.EncodeToString(append([]byte{1}, make([]byte, 31)...))

	cases := []struct {
		name   string
		method string
		setup  func(h *IssuanceHandler, r *http.Request)
		status int
		code   string
	}{
		{name: "missing_auth", method: http.MethodGet, setup: func(h *IssuanceHandler, _ *http.Request) { h.Auth = nil }, status: 503, code: "dependency_unavailable"},
		{name: "missing_management", method: http.MethodGet, setup: func(h *IssuanceHandler, _ *http.Request) { h.Management = nil }, status: 503, code: "dependency_unavailable"},
		{name: "cookie_missing_get", method: http.MethodGet, setup: func(_ *IssuanceHandler, r *http.Request) { r.Header.Del("Cookie") }, status: 401, code: "invalid_session"},
		{name: "cookie_duplicate_get", method: http.MethodGet, setup: func(_ *IssuanceHandler, r *http.Request) {
			r.AddCookie(&http.Cookie{Name: policy.CookieName, Value: cookie})
		}, status: 401, code: "invalid_session"},
		{name: "origin_missing_post", method: http.MethodPost, setup: func(_ *IssuanceHandler, r *http.Request) { r.Header.Del("Origin") }, status: 403, code: "origin_invalid"},
		{name: "origin_null_post", method: http.MethodPost, setup: func(_ *IssuanceHandler, r *http.Request) { r.Header.Set("Origin", "null") }, status: 403, code: "origin_invalid"},
		{name: "origin_foreign_post", method: http.MethodPost, setup: func(_ *IssuanceHandler, r *http.Request) { r.Header.Set("Origin", "http://127.0.0.1:1") }, status: 403, code: "origin_invalid"},
		{name: "origin_duplicate_post", method: http.MethodPost, setup: func(_ *IssuanceHandler, r *http.Request) { r.Header.Add("Origin", policy.ConsoleOrigin) }, status: 403, code: "origin_invalid"},
		{name: "csrf_missing_post", method: http.MethodPost, setup: func(_ *IssuanceHandler, r *http.Request) { r.Header.Del("X-CSRF-Token") }, status: 403, code: "csrf_invalid"},
		{name: "csrf_duplicate_post", method: http.MethodPost, setup: func(_ *IssuanceHandler, r *http.Request) { r.Header.Add("X-CSRF-Token", csrf) }, status: 403, code: "csrf_invalid"},
		{name: "origin_missing_delete", method: http.MethodDelete, setup: func(_ *IssuanceHandler, r *http.Request) { r.Header.Del("Origin") }, status: 403, code: "origin_invalid"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			h := &IssuanceHandler{
				Auth: &MeHandler{
					Sessions: &a.SessionService{Store: &issuanceTestSessionStore{err: a.ErrSession}, Policy: policy, Now: time.Now},
					Verifier: issuanceTestVerifier{},
					Tenancy:  &tenancy.Service{},
				},
				Management: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++ }),
			}
			r := httptest.NewRequest(tc.method, policy.ConsoleOrigin+"/console/api/tenants/tenant-a/issuers", nil)
			r.Header.Set("Origin", policy.ConsoleOrigin)
			r.Header.Set("X-CSRF-Token", csrf)
			r.AddCookie(&http.Cookie{Name: policy.CookieName, Value: cookie})
			if tc.setup != nil {
				tc.setup(h, r)
			}
			mux := http.NewServeMux()
			h.Register(mux)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)

			var problem struct {
				Code string `json:"code"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &problem); err != nil || w.Code != tc.status || problem.Code != tc.code {
				t.Fatalf("unexpected rejection: status=%d want=%d code=%q want=%q body=%s", w.Code, tc.status, problem.Code, tc.code, w.Body.String())
			}
			if calls != 0 {
				t.Fatalf("management handler should not be called, got %d calls", calls)
			}
			if len(w.Result().Cookies()) != 0 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Correlation-Id") == "" {
				t.Fatal("rejection altered cookies or missed security headers")
			}
		})
	}
}

func TestConsoleIssuanceRejectsCrossTenantActorMismatchAndBadCSRF(t *testing.T) {
	t.Run("cross_tenant", func(t *testing.T) {
		h, calls, _, policy, cookie, _ := newConsoleIssuanceTestFixture(t, "tenant-a")
		mux := http.NewServeMux()
		h.Register(mux)
		r := httptest.NewRequest(http.MethodGet, policy.ConsoleOrigin+"/console/api/tenants/tenant-b/issuers", nil)
		r.AddCookie(&http.Cookie{Name: policy.CookieName, Value: cookie})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound || *calls != 0 {
			t.Fatalf("expected 404 and 0 calls for cross-tenant access, got %d calls=%d body=%s", w.Code, *calls, w.Body.String())
		}
	})

	t.Run("no_active_tenant", func(t *testing.T) {
		h, calls, _, policy, cookie, _ := newConsoleIssuanceTestFixture(t, "")
		mux := http.NewServeMux()
		h.Register(mux)
		r := httptest.NewRequest(http.MethodGet, policy.ConsoleOrigin+"/console/api/tenants/tenant-a/issuers", nil)
		r.AddCookie(&http.Cookie{Name: policy.CookieName, Value: cookie})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound || *calls != 0 {
			t.Fatalf("expected 404 and 0 calls when active tenant is empty, got %d calls=%d", w.Code, *calls)
		}
	})

	t.Run("actor_mismatch", func(t *testing.T) {
		h, calls, _, policy, cookie, _ := newConsoleIssuanceTestFixture(t, "tenant-a")
		h.Auth.Verifier = issuanceTestVerifier{operator: a.Operator{Issuer: "https://auth.example", Subject: "other-sub"}}
		mux := http.NewServeMux()
		h.Register(mux)
		r := httptest.NewRequest(http.MethodGet, policy.ConsoleOrigin+"/console/api/tenants/tenant-a/issuers", nil)
		r.AddCookie(&http.Cookie{Name: policy.CookieName, Value: cookie})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized || *calls != 0 {
			t.Fatalf("expected 401 and 0 calls on actor mismatch, got %d calls=%d", w.Code, *calls)
		}
	})

	t.Run("wrong_csrf_token", func(t *testing.T) {
		h, calls, r, _, _, _ := newConsoleIssuanceTestFixture(t, "tenant-a")
		wrongCSRF := base64.RawURLEncoding.EncodeToString(append([]byte{9}, make([]byte, 31)...))
		r.Header.Set("X-CSRF-Token", wrongCSRF)
		mux := http.NewServeMux()
		h.Register(mux)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || *calls != 0 {
			t.Fatalf("expected 403 and 0 calls on bad CSRF, got %d calls=%d", w.Code, *calls)
		}
	})
}

func TestConsoleIssuanceForwardsSameTenantAndStripsBrowserHeaders(t *testing.T) {
	h, _, _, policy, cookie, csrf := newConsoleIssuanceTestFixture(t, "tenant-a")
	var gotMethod, gotPath, gotQuery, gotAuth, gotCookie, gotOrigin, gotCSRF string
	h.Management = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")
		gotOrigin = r.Header.Get("Origin")
		gotCSRF = r.Header.Get("X-CSRF-Token")
		w.WriteHeader(http.StatusOK)
	})
	mux := http.NewServeMux()
	h.Register(mux)

	t.Run("get_forwards_query_and_bearer", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, policy.ConsoleOrigin+"/console/api/tenants/tenant-a/issuers?limit=25", nil)
		r.AddCookie(&http.Cookie{Name: policy.CookieName, Value: cookie})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		if gotMethod != http.MethodGet || gotPath != "/v1/operator/tenants/tenant-a/issuers" || gotQuery != "limit=25" {
			t.Fatalf("unexpected forwarded request: %s %s?%s", gotMethod, gotPath, gotQuery)
		}
		if gotAuth != "Bearer operator-access-token" || gotCookie != "" || gotOrigin != "" || gotCSRF != "" {
			t.Fatalf("browser secrets leaked or bearer missing: auth=%q cookie=%q origin=%q csrf=%q", gotAuth, gotCookie, gotOrigin, gotCSRF)
		}
	})

	t.Run("post_with_valid_origin_and_csrf_forwards_and_strips", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, policy.ConsoleOrigin+"/console/api/tenants/tenant-a/clients", strings.NewReader(`{"clientId":"c1"}`))
		r.Header.Set("Origin", policy.ConsoleOrigin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(&http.Cookie{Name: policy.CookieName, Value: cookie})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		if gotMethod != http.MethodPost || gotPath != "/v1/operator/tenants/tenant-a/clients" {
			t.Fatalf("unexpected forwarded POST: %s %s", gotMethod, gotPath)
		}
		if gotAuth != "Bearer operator-access-token" || gotCookie != "" || gotOrigin != "" || gotCSRF != "" {
			t.Fatalf("browser secrets leaked or bearer missing on POST: auth=%q cookie=%q origin=%q csrf=%q", gotAuth, gotCookie, gotOrigin, gotCSRF)
		}
	})
}

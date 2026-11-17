package privateapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	a "hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/oid4vp"
	"hukid.local/platform/internal/tenancy"
)

type vsVerifier struct{ deadline time.Time }

func (v vsVerifier) VerifyInvitationOperator(_ context.Context, raw string) (a.Operator, time.Time, error) {
	switch raw {
	case "valid":
		return a.Operator{Issuer: "configured", Subject: "self"}, v.deadline, nil
	case "stale":
		return a.Operator{}, time.Time{}, a.ErrStepUp
	}
	return a.Operator{}, time.Time{}, a.ErrCredential
}

type vsMembers struct{ roles map[string][]string }

func (m vsMembers) Identity(context.Context, a.Operator) (tenancy.Identity, error) {
	return tenancy.Identity{ActorID: "self"}, nil
}
func (m vsMembers) Membership(_ context.Context, actor, tenant string) (tenancy.Membership, error) {
	roles, ok := m.roles[tenant]
	if actor != "self" || !ok {
		return tenancy.Membership{}, a.ErrTenant
	}
	return tenancy.Membership{Roles: roles, Revision: 1}, nil
}

type vsStarter struct {
	calls  int
	tenant string
	ttl    time.Duration
	err    error
}

func (s *vsStarter) Start(_ context.Context, _, tenant string, ttl time.Duration) (string, string, string, time.Time, error) {
	s.calls++
	s.tenant, s.ttl = tenant, ttl
	if s.err != nil {
		return "", "", "", time.Time{}, s.err
	}
	return "7a7f8c3e-5b0e-4a6b-9a39-0d6c1f3c9a11", "client-a", "https://a.example/oid4vp/response", time.Date(2026, 11, 16, 12, 5, 0, 0, time.UTC), nil
}

func vsRig(t *testing.T, capacity int) (*VerificationHandler, *vsStarter, *oid4vp.SessionStore, *http.ServeMux) {
	t.Helper()
	now := func() time.Time { return time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC) }
	service, err := tenancy.New(vsMembers{roles: map[string][]string{
		"admin":    {"tenant_admin"},
		"security": {"security_admin"},
		"operator": {"issuer_operator"},
		"support":  {"support_readonly"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := oid4vp.NewSessionStore(capacity, now)
	if err != nil {
		t.Fatal(err)
	}
	starter := &vsStarter{}
	h := &VerificationHandler{
		Operators: &Handler{Tenancy: service},
		Verifier:  vsVerifier{deadline: now().Add(5 * time.Minute)},
		Starter:   starter,
		Sessions:  sessions,
		Now:       now,
	}
	mux := http.NewServeMux()
	h.Register(mux)
	return h, starter, sessions, mux
}

func vsPost(mux *http.ServeMux, tenant, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/operator/tenants/"+tenant+"/verification-sessions", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestStartVerificationSessionCreatesOnlyForAuthorizedRoles(t *testing.T) {
	for _, tenant := range []string{"admin", "security"} {
		_, starter, sessions, mux := vsRig(t, 4)
		rec := vsPost(mux, tenant, "valid", "")
		if rec.Code != http.StatusCreated {
			t.Fatalf("%s: status %d body %s", tenant, rec.Code, rec.Body)
		}
		body := rec.Body.String()
		for _, forbidden := range []string{"nonce", "state=", "\"state\"", "jwk", "\"d\":"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("%s: response leaks %q: %s", tenant, forbidden, body)
			}
		}
		if !strings.Contains(body, `"sessionId":"7a7f8c3e`) || !strings.Contains(body, "openid4vp://authorize?") || !strings.Contains(body, "request_uri=https%3A%2F%2Fa.example%2Foid4vp%2Frequest%2F") {
			t.Fatalf("%s: unexpected body %s", tenant, body)
		}
		if starter.calls != 1 || starter.tenant != tenant || starter.ttl != defaultVerificationTTL || sessions.Len() != 1 {
			t.Fatalf("%s: calls=%d tenant=%q ttl=%v stored=%d", tenant, starter.calls, starter.tenant, starter.ttl, sessions.Len())
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("response must not be cacheable")
		}
	}
}

func TestStartVerificationSessionRejectsWithoutCapabilityOrTenant(t *testing.T) {
	for _, tc := range []struct {
		name, tenant, token string
		status              int
	}{
		{"issuer operator has no capability", "operator", "valid", 403},
		{"support readonly has no capability", "support", "valid", 403},
		{"foreign tenant", "other", "valid", 404},
		{"stale MFA", "admin", "stale", 403},
		{"bad token", "admin", "nope", 401},
		{"missing token", "admin", "", 401},
	} {
		_, starter, sessions, mux := vsRig(t, 4)
		rec := vsPost(mux, tc.tenant, tc.token, "")
		if rec.Code != tc.status {
			t.Fatalf("%s: status %d want %d (%s)", tc.name, rec.Code, tc.status, rec.Body)
		}
		if starter.calls != 0 || sessions.Len() != 0 {
			t.Fatalf("%s: created a session (calls=%d stored=%d)", tc.name, starter.calls, sessions.Len())
		}
	}
}

func TestStartVerificationSessionRechecksStepUpDeadline(t *testing.T) {
	h, starter, _, mux := vsRig(t, 4)
	h.Verifier = vsVerifier{deadline: h.Now()}
	if rec := vsPost(mux, "admin", "valid", ""); rec.Code != 403 || starter.calls != 0 {
		t.Fatalf("expired step-up: status %d calls %d", rec.Code, starter.calls)
	}
}

func TestStartVerificationSessionValidatesTheBody(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"unknown field (tenant override)", `{"tenantId":"other"}`},
		{"ttl too small", `{"ttlSeconds":59}`},
		{"ttl too large", `{"ttlSeconds":901}`},
		{"not json", `nope`},
		{"trailing data", `{"ttlSeconds":120} {}`},
	} {
		_, starter, _, mux := vsRig(t, 4)
		if rec := vsPost(mux, "admin", "valid", tc.body); rec.Code != 422 || starter.calls != 0 {
			t.Fatalf("%s: status %d calls %d", tc.name, rec.Code, starter.calls)
		}
	}
	_, starter, _, mux := vsRig(t, 4)
	if rec := vsPost(mux, "admin", "valid", `{"ttlSeconds":120}`); rec.Code != 201 || starter.ttl != 120*time.Second {
		t.Fatalf("explicit ttl: status %d ttl %v", rec.Code, starter.ttl)
	}
}

func TestStartVerificationSessionFailsClosed(t *testing.T) {
	_, starter, _, mux := vsRig(t, 4)
	starter.err = oid4vp.ErrConfig
	if rec := vsPost(mux, "admin", "valid", ""); rec.Code != 503 || strings.Contains(rec.Body.String(), "configuration") {
		t.Fatalf("missing configuration: status %d body %s", rec.Code, rec.Body)
	}
	starter.err = errors.New("pq: connection refused host=db")
	if rec := vsPost(mux, "admin", "valid", ""); rec.Code != 503 || strings.Contains(rec.Body.String(), "refused") {
		t.Fatalf("starter failure: status %d body %s", rec.Code, rec.Body)
	}
	_, starter, _, mux = vsRig(t, 1)
	if rec := vsPost(mux, "admin", "valid", ""); rec.Code != 201 {
		t.Fatalf("first: %d", rec.Code)
	}
	if rec := vsPost(mux, "admin", "valid", ""); rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("full store: status %d", rec.Code)
	}
}

func TestStartVerificationSessionRequiresPOST(t *testing.T) {
	_, starter, _, mux := vsRig(t, 4)
	req := httptest.NewRequest(http.MethodGet, "/v1/operator/tenants/admin/verification-sessions", nil)
	req.Header.Set("Authorization", "Bearer valid")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 405 || starter.calls != 0 {
		t.Fatalf("GET: status %d calls %d", rec.Code, starter.calls)
	}
}

package console

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	a "hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
)

type settingsMembershipErrStore struct {
	identity tenancy.Identity
	err      error
}

func (s settingsMembershipErrStore) Identity(context.Context, a.Operator) (tenancy.Identity, error) {
	return s.identity, nil
}

func (s settingsMembershipErrStore) Membership(context.Context, string, string) (tenancy.Membership, error) {
	return tenancy.Membership{}, s.err
}

func newConsoleSettingsTestFixture(t *testing.T, activeTenant string, roles []string, issuanceEnabled bool) (*SettingsHandler, *issuanceTestSessionStore, a.Policy, string) {
	t.Helper()
	ih, _, req, policy, cookie, _ := newConsoleIssuanceTestFixture(t, activeTenant)
	tenancySvc, err := tenancy.New(issuanceTestTenancyStore{
		identity: tenancy.Identity{
			ActorID: "actor-1",
			Tenants: []tenancy.Tenant{{ID: "tenant-a", DisplayName: "Organización A"}},
		},
		membership: tenancy.Membership{Roles: roles, Revision: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy.Environment = "local"
	policy.Issuer = "http://127.0.0.1:8081/realms/hukid"
	policy.ClientID = "secret-internal-client-id"
	policy.AccessTokenSeconds = 300
	policy.StepUpSeconds = 300
	policy.RequiredAMR = []string{"pwd", "otp"}
	policy.AcceptedACR = []string{"2"}
	ih.Auth.Tenancy = tenancySvc
	ih.Auth.Sessions.Policy = policy
	store := ih.Auth.Sessions.Store.(*issuanceTestSessionStore)
	_ = req
	return &SettingsHandler{Auth: ih.Auth, IssuanceRuntimeEnabled: issuanceEnabled}, store, policy, cookie
}

func TestConsoleSettingsRejectsUnauthenticatedInvalidTenantAndNonAdmin(t *testing.T) {
	cases := []struct {
		name         string
		method       string
		activeTenant string
		roles        []string
		mutate       func(h *SettingsHandler, r *http.Request)
		status       int
		code         string
	}{
		{name: "method_not_allowed", method: http.MethodPost, activeTenant: "tenant-a", roles: []string{"tenant_admin"}, status: http.StatusMethodNotAllowed, code: "invalid_request"},
		{name: "nil_auth", method: http.MethodGet, activeTenant: "tenant-a", roles: []string{"tenant_admin"}, mutate: func(h *SettingsHandler, _ *http.Request) { h.Auth = nil }, status: http.StatusServiceUnavailable, code: "dependency_unavailable"},
		{name: "missing_cookie", method: http.MethodGet, activeTenant: "tenant-a", roles: []string{"tenant_admin"}, mutate: func(_ *SettingsHandler, r *http.Request) { r.Header.Del("Cookie") }, status: http.StatusUnauthorized, code: "invalid_session"},
		{name: "duplicate_cookie", method: http.MethodGet, activeTenant: "tenant-a", roles: []string{"tenant_admin"}, mutate: func(h *SettingsHandler, r *http.Request) {
			r.AddCookie(&http.Cookie{Name: h.Auth.Sessions.Policy.CookieName, Value: "extra"})
		}, status: http.StatusUnauthorized, code: "invalid_session"},
		{name: "actor_mismatch", method: http.MethodGet, activeTenant: "tenant-a", roles: []string{"tenant_admin"}, mutate: func(h *SettingsHandler, _ *http.Request) {
			h.Auth.Verifier = issuanceTestVerifier{operator: a.Operator{Issuer: "https://auth.example", Subject: "other-sub"}}
		}, status: http.StatusUnauthorized, code: "invalid_session"},
		{name: "no_active_tenant", method: http.MethodGet, activeTenant: "", roles: []string{"tenant_admin"}, status: http.StatusNotFound, code: "tenant_not_found"},
		{name: "foreign_active_tenant", method: http.MethodGet, activeTenant: "tenant-foreign", roles: []string{"tenant_admin"}, status: http.StatusNotFound, code: "tenant_not_found"},
		{name: "suspended_membership", method: http.MethodGet, activeTenant: "tenant-a", roles: []string{"tenant_admin"}, mutate: func(h *SettingsHandler, _ *http.Request) {
			svc, _ := tenancy.New(settingsMembershipErrStore{
				identity: tenancy.Identity{ActorID: "actor-1", Tenants: []tenancy.Tenant{{ID: "tenant-a", DisplayName: "Org A"}}},
				err:      a.ErrTenant,
			})
			h.Auth.Tenancy = svc
		}, status: http.StatusNotFound, code: "tenant_not_found"},
		{name: "support_readonly_forbidden", method: http.MethodGet, activeTenant: "tenant-a", roles: []string{"support_readonly"}, status: http.StatusForbidden, code: "forbidden"},
		{name: "issuer_operator_forbidden", method: http.MethodGet, activeTenant: "tenant-a", roles: []string{"issuer_operator"}, status: http.StatusForbidden, code: "forbidden"},
		{name: "security_admin_forbidden", method: http.MethodGet, activeTenant: "tenant-a", roles: []string{"security_admin"}, status: http.StatusForbidden, code: "forbidden"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, store, policy, cookie := newConsoleSettingsTestFixture(t, tc.activeTenant, tc.roles, false)
			r := httptest.NewRequest(tc.method, policy.ConsoleOrigin+"/console/api/settings", nil)
			r.AddCookie(&http.Cookie{Name: policy.CookieName, Value: cookie})
			if tc.mutate != nil {
				tc.mutate(h, r)
			}
			mux := http.NewServeMux()
			h.Register(mux)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)

			var problem struct {
				Code string `json:"code"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &problem); err != nil || w.Code != tc.status || problem.Code != tc.code {
				t.Fatalf("unexpected status/code: status=%d want=%d code=%q want=%q body=%s", w.Code, tc.status, problem.Code, tc.code, w.Body.String())
			}
			if store.touches != 0 {
				t.Fatalf("rejected settings request must not touch session, got %d touches", store.touches)
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("X-Correlation-Id") == "" {
				t.Fatal("missing security headers on rejected settings response")
			}
		})
	}
}

func TestConsoleSettingsReturnsSanitizedReadOnlyPolicyForTenantAdmin(t *testing.T) {
	h, store, policy, cookie := newConsoleSettingsTestFixture(t, "tenant-a", []string{"tenant_admin"}, true)
	mux := http.NewServeMux()
	h.Register(mux)

	r := httptest.NewRequest(http.MethodGet, policy.ConsoleOrigin+"/console/api/settings", nil)
	r.AddCookie(&http.Cookie{Name: policy.CookieName, Value: cookie})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if store.touches != 1 {
		t.Fatalf("expected 1 session touch, got %d", store.touches)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("missing cache or referrer protection headers")
	}

	raw := w.Body.String()
	for _, sensitive := range []string{"operator-access-token", "operator-refresh-token", "secret-internal-client-id", "hukid_test_session", policy.Issuer} {
		if strings.Contains(raw, sensitive) {
			t.Fatalf("settings response leaked sensitive value %q", sensitive)
		}
	}

	var got consoleSettings
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.TenantID != "tenant-a" || got.DisplayName != "Organización A" || got.Environment != "local" || !got.IssuanceRuntimeEnabled {
		t.Fatalf("unexpected settings metadata: %+v", got)
	}
	if got.SessionPolicy.AccessTokenSeconds != 300 || got.SessionPolicy.SessionIdleSeconds != 1800 ||
		got.SessionPolicy.SessionAbsoluteSeconds != 3600 || got.SessionPolicy.StepUpSeconds != 300 ||
		!slices.Equal(got.SessionPolicy.RequiredAMR, []string{"pwd", "otp"}) ||
		!slices.Equal(got.SessionPolicy.AcceptedACR, []string{"2"}) {
		t.Fatalf("unexpected session policy: %+v", got.SessionPolicy)
	}
}

func TestConsoleSettingsSerializesEmptyAMRandACRAsArrays(t *testing.T) {
	h, _, policy, cookie := newConsoleSettingsTestFixture(t, "tenant-a", []string{"tenant_admin"}, false)
	h.Auth.Sessions.Policy.RequiredAMR = nil
	h.Auth.Sessions.Policy.AcceptedACR = nil

	mux := http.NewServeMux()
	h.Register(mux)
	r := httptest.NewRequest(http.MethodGet, policy.ConsoleOrigin+"/console/api/settings", nil)
	r.AddCookie(&http.Cookie{Name: policy.CookieName, Value: cookie})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"requiredAmr":null`) || strings.Contains(w.Body.String(), `"acceptedAcr":null`) {
		t.Fatalf("empty AMR/ACR slices must marshal as [], got %s", w.Body.String())
	}
}

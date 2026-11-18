package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	consolehttp "hukid.local/platform/internal/adapters/console"
	"hukid.local/platform/internal/adapters/oid4vphttp"
	"hukid.local/platform/internal/adapters/privateapi"
	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/bootstrap"
	"hukid.local/platform/internal/verification"
)

// The tenant verification mount shares one ServeMux with the console, the
// operator API, the directory, the dashboard and the wallet endpoints. A
// duplicate or ambiguous pattern makes ServeMux panic at startup, which a
// unit test of one handler cannot see. This registers the same handlers as
// loadAuthConfiguration, with empty dependencies (Register only binds method
// values), so a collision fails here and not on the first deploy.
func TestVerificationRoutesDoNotCollideWithTheRestOfTheAPI(t *testing.T) {
	operators := &privateapi.Handler{}
	me := &consolehttp.MeHandler{}
	directory := &privateapi.DirectoryHandler{}
	dashboard := &privateapi.DashboardHandler{}
	registrars := []func(*http.ServeMux){
		consolehttp.New(nil).Register,
		operators.Register,
		me.Register,
		consolehttp.NewSessions(&authentication.SessionLifecycle{Sessions: &authentication.SessionService{}}).Register,
		consolehttp.NewCommands(nil, nil, nil).Register,
		func(mux *http.ServeMux) {
			directory.Register(mux)
			(&consolehttp.DirectoryHandler{}).Register(mux)
			(&privateapi.InvitationHandler{}).Register(mux)
			(&consolehttp.InvitationHandler{}).Register(mux)
		},
		func(mux *http.ServeMux) {
			dashboard.Register(mux)
			(&consolehttp.DashboardHandler{}).Register(mux)
		},
		func(mux *http.ServeMux) {
			(&privateapi.VerificationHandler{}).Register(mux)
			(&oid4vphttp.Handler{}).Routes(mux)
		},
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("route registration panicked: %v", recovered)
		}
	}()
	handler := bootstrap.Handler(registrars...)
	// Each path of the new mount reaches its own handler, not a neighbour's:
	// the empty handlers answer 503 (not configured) or 401/405, never 404.
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/v1/operator/tenants/11111111-1111-4111-8111-111111111111/verification-sessions"},
		{http.MethodGet, oid4vphttp.RequestPathPrefix + "some-state"},
		{http.MethodPost, oid4vphttp.ResponsePath},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code == http.StatusNotFound {
			t.Fatalf("%s %s is not routed", tc.method, tc.path)
		}
	}
}

// tenantVerifiers caches one verifier per tenant: the same tenant gets the
// same instance (and so the same replay scope), other tenants get another.
func TestTenantVerifiersCachePerTenantAndSeparateTenants(t *testing.T) {
	base, err := verification.NewVerifier(verification.NewMemoryKeyResolver(), verification.ClockFunc(time.Now), verification.DefaultLimits, 0)
	if err != nil {
		t.Fatal(err)
	}
	verifiers := &tenantVerifiers{base: base, pool: new(pgxpool.Pool), byTenant: map[string]*verification.Verifier{}}
	a1, err := verifiers.For("11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := verifiers.For("11111111-1111-4111-8111-111111111111")
	b, err := verifiers.For("22222222-2222-4222-8222-222222222222")
	if err != nil {
		t.Fatal(err)
	}
	if a1 != a2 {
		t.Fatal("the same tenant got two verifiers: its replay scope would be split")
	}
	if a1 == b || a1 == base || b == base {
		t.Fatal("tenants share a verifier: one tenant's replay state would be visible to another")
	}
}

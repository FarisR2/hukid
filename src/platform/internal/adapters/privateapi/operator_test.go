package privateapi

import (
	"context"
	"encoding/json"
	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type verifierStub struct{ calls int }

func TestContextRolesComeFromLiveMembership(t *testing.T) {
	service, _ := tenancy.New(&storeStub{})
	c, err := service.Context(context.Background(), "self", "own")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(ContextDTO(c))
	if err != nil || !strings.Contains(string(data), `"roles":["support_readonly"]`) || strings.Contains(string(data), "tenant_admin") {
		t.Fatalf("incorrect live context roles: %s %v", data, err)
	}
}

func (v *verifierStub) VerifyOperator(_ context.Context, raw string) (authentication.Operator, error) {
	v.calls++
	if raw == "mfa" {
		return authentication.Operator{}, authentication.ErrMFA
	}
	if raw != "valid" {
		return authentication.Operator{}, authentication.ErrCredential
	}
	return authentication.Operator{Issuer: "configured", Subject: "self"}, nil
}

type storeStub struct{ reads int }

func (s *storeStub) Identity(_ context.Context, o authentication.Operator) (tenancy.Identity, error) {
	s.reads++
	return tenancy.Identity{ActorID: "self", Tenants: []tenancy.Tenant{{ID: "own", DisplayName: "Own"}}}, nil
}
func (s *storeStub) Membership(_ context.Context, actor, tenant string) (tenancy.Membership, error) {
	s.reads++
	if actor != "self" || tenant != "own" {
		return tenancy.Membership{}, authentication.ErrTenant
	}
	return tenancy.Membership{Roles: []string{"support_readonly"}, Revision: 1}, nil
}
func TestBearerOnlyAndNoDataBeforeVerification(t *testing.T) {
	v, store := &verifierStub{}, &storeStub{}
	service, _ := tenancy.New(store)
	h := &Handler{Verifier: v, Tenancy: service}
	mux := http.NewServeMux()
	h.Register(mux)
	for _, tc := range []struct {
		name, header, path string
		status             int
	}{
		{"missing", "", "/v1/operator/me", 401}, {"invalid", "Bearer invalid", "/v1/operator/me", 401}, {"id_token", "Bearer id", "/v1/operator/me", 401}, {"duplicate", "Bearer valid", "/v1/operator/me", 401}, {"mfa", "Bearer mfa", "/v1/operator/me", 403}, {"valid", "bEaReR valid", "/v1/operator/me", 200}, {"foreign", "Bearer valid", "/v1/operator/tenants/foreign/context", 404}, {"context", "Bearer valid", "/v1/operator/tenants/own/context", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := store.reads
			r := httptest.NewRequest("GET", tc.path, nil)
			r.AddCookie(&http.Cookie{Name: "hukid_test_session", Value: "valid"})
			r.Header.Set("X-Tenant-Id", "own")
			r.Header.Set("X-Roles", "tenant_admin")
			if tc.header != "" {
				r.Header.Add("Authorization", tc.header)
			}
			if tc.name == "duplicate" {
				r.Header.Add("Authorization", tc.header)
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d", w.Code)
			}
			if tc.status == 401 || tc.status == 403 {
				if store.reads != before {
					t.Fatal("queried data before authentication")
				}
			}
			if (w.Header().Get("WWW-Authenticate") != "") != (tc.status == 401) {
				t.Fatal("wrong challenge")
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("X-Correlation-Id") == "" {
				t.Fatal("missing private headers")
			}
			if tc.name == "context" && strings.Contains(w.Body.String(), "members:read") {
				t.Fatal("support gained member directory")
			}
		})
	}
}

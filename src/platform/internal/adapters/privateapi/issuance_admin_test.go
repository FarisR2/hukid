package privateapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	a "hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/issuance"
	"hukid.local/platform/internal/tenancy"
)

type adminVerifierStub struct {
	now time.Time
}

func (v *adminVerifierStub) VerifyOperator(_ context.Context, raw string) (a.Operator, error) {
	switch raw {
	case "admin-tok", "admin-expired-mfa":
		return a.Operator{Issuer: "https://idp.hukid.test", Subject: "actor-admin"}, nil
	case "sec-tok":
		return a.Operator{Issuer: "https://idp.hukid.test", Subject: "actor-sec"}, nil
	case "issuer-op-tok":
		return a.Operator{Issuer: "https://idp.hukid.test", Subject: "actor-op"}, nil
	default:
		return a.Operator{}, a.ErrCredential
	}
}

func (v *adminVerifierStub) VerifyInvitationOperator(_ context.Context, raw string) (a.Operator, time.Time, error) {
	switch raw {
	case "admin-tok":
		return a.Operator{Issuer: "https://idp.hukid.test", Subject: "actor-admin"}, v.now.Add(5 * time.Minute), nil
	case "admin-expired-mfa":
		return a.Operator{Issuer: "https://idp.hukid.test", Subject: "actor-admin"}, v.now.Add(-time.Second), nil
	case "sec-tok":
		return a.Operator{Issuer: "https://idp.hukid.test", Subject: "actor-sec"}, v.now.Add(5 * time.Minute), nil
	default:
		return a.Operator{}, time.Time{}, a.ErrCredential
	}
}

type adminTenancyStore struct {
	allowedIssuer string
}

func (s *adminTenancyStore) Identity(_ context.Context, op a.Operator) (tenancy.Identity, error) {
	switch op.Subject {
	case "actor-admin":
		return tenancy.Identity{ActorID: "actor-admin", Tenants: []tenancy.Tenant{{ID: "tenant-a", DisplayName: "UNAS"}}}, nil
	case "actor-sec":
		return tenancy.Identity{ActorID: "actor-sec", Tenants: []tenancy.Tenant{{ID: "tenant-a", DisplayName: "UNAS"}}}, nil
	case "actor-op":
		return tenancy.Identity{ActorID: "actor-op", Tenants: []tenancy.Tenant{{ID: "tenant-a", DisplayName: "UNAS"}}}, nil
	default:
		return tenancy.Identity{}, a.ErrCredential
	}
}

func (s *adminTenancyStore) Membership(_ context.Context, actor, tenant string) (tenancy.Membership, error) {
	if tenant != "tenant-a" {
		return tenancy.Membership{}, a.ErrTenant
	}
	switch actor {
	case "actor-admin":
		return tenancy.Membership{Roles: []string{"tenant_admin"}, Revision: 1}, nil
	case "actor-sec":
		return tenancy.Membership{Roles: []string{"security_admin"}, Revision: 1}, nil
	case "actor-op":
		return tenancy.Membership{Roles: []string{"issuer_operator"}, IssuerIDs: []string{s.allowedIssuer}, Revision: 1}, nil
	default:
		return tenancy.Membership{}, a.ErrTenant
	}
}

func doAdminReq(mux *http.ServeMux, method, path, token, idem, ifMatch string, body any) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestIssuanceAdminLifecycleAuthStepUpETagAndAudit(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	claimsKey := make([]byte, 32)
	_, _ = rand.Read(claimsKey)

	keyCounter := 0
	provisioner := func(_, _, kid string) (string, issuance.PublicJWK, error) {
		keyCounter++
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", issuance.PublicJWK{}, err
		}
		jwk, err := issuance.ExportPublicJWK(&priv.PublicKey, kid)
		return "vault://transit/hukid-test-" + kid + "#v1", jwk, err
	}

	svc, err := issuance.NewService(issuance.ServiceConfig{
		ClaimsKey:        claimsKey,
		ClaimsKeyVersion: "adm-v1",
		Clients:          issuance.NewClientRegistry(nil),
		Definitions:      issuance.NewDefinitionRegistry(nil),
		KeyProvisioner:   provisioner,
		Now:              func() time.Time { return now },
		Random:           rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}

	issuerID := "11111111-1111-4111-8111-111111111111"
	tenancySvc, err := tenancy.New(&adminTenancyStore{allowedIssuer: issuerID})
	if err != nil {
		t.Fatal(err)
	}
	v := &adminVerifierStub{now: now}
	operators := &Handler{Verifier: v, Tenancy: tenancySvc}
	admin := &IssuanceAdminHandler{
		Operators: operators,
		Verifier:  v,
		Service:   svc,
		Now:       func() time.Time { return now },
	}
	mux := http.NewServeMux()
	admin.Register(mux)

	// 1. Stale MFA fails closed with 403 step_up_required before any write.
	w := doAdminReq(mux, http.MethodPost, "/v1/operator/tenants/tenant-a/issuers", "admin-expired-mfa", "idem-issuer-create-01", "", map[string]any{
		"issuerId":    issuerID,
		"slug":        "unas",
		"displayName": "UNAS",
		"initialKid":  "unas-k1",
	})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "mfa_required") {
		t.Fatalf("expected 403 mfa_required, got %d %s", w.Code, w.Body.String())
	}

	// 2. security_admin cannot mutate issuers (403 forbidden), foreign tenant returns 404.
	w = doAdminReq(mux, http.MethodPost, "/v1/operator/tenants/tenant-a/issuers", "sec-tok", "idem-issuer-create-01", "", map[string]any{
		"issuerId": issuerID, "slug": "unas", "displayName": "UNAS",
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for security_admin, got %d %s", w.Code, w.Body.String())
	}
	w = doAdminReq(mux, http.MethodGet, "/v1/operator/tenants/tenant-foreign/issuers", "admin-tok", "", "", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 cross-tenant, got %d", w.Code)
	}

	// 3. Create issuer with initial KMS key -> 201 + JWKS visible.
	w = doAdminReq(mux, http.MethodPost, "/v1/operator/tenants/tenant-a/issuers", "admin-tok", "idem-issuer-create-01", "", map[string]any{
		"issuerId":    issuerID,
		"slug":        "unas",
		"displayName": "IncubaUNAS",
		"initialKid":  "unas-k1",
	})
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"kid":"unas-k1"`) {
		t.Fatalf("CreateIssuer failed: %d %s", w.Code, w.Body.String())
	}

	// 4. Rotate and compromise key.
	w = doAdminReq(mux, http.MethodPost, "/v1/operator/tenants/tenant-a/issuers/"+issuerID+"/keys/rotate", "admin-tok", "idem-key-rotate-0001", "", map[string]any{"kid": "unas-k2"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"kid":"unas-k2"`) {
		t.Fatalf("RotateKey failed: %d %s", w.Code, w.Body.String())
	}
	w = doAdminReq(mux, http.MethodPost, "/v1/operator/tenants/tenant-a/issuers/"+issuerID+"/keys/unas-k1/compromise", "admin-tok", "idem-key-comp-00001", "", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"compromised"`) {
		t.Fatalf("CompromiseKey failed: %d %s", w.Code, w.Body.String())
	}

	// 5. Draft definition -> replace requires If-Match (428 / 412 / 200) -> publish -> retire.
	defPayload := map[string]any{
		"id":                     "unas-certificate",
		"version":                "1.0.0",
		"configurationId":        "pe.edu.certificate.vc-jwt.v1",
		"displayName":            "Certificado UNAS",
		"locale":                 "es-PE",
		"contexts":               []string{"https://schemas.hukid.pe/contexts/certificate/v1"},
		"types":                  []string{"AttendanceCertificateCredential"},
		"defaultValiditySeconds": 31536000,
		"statusPurposes":         []string{"revocation", "suspension"},
		"publishSchema":          true,
		"fields": map[string]any{
			"participantName": map[string]any{"type": "string", "required": true, "maxLength": 120},
		},
	}
	w = doAdminReq(mux, http.MethodPost, "/v1/operator/tenants/tenant-a/issuers/"+issuerID+"/credential-definitions", "admin-tok", "idem-def-create-0001", "", defPayload)
	if w.Code != http.StatusCreated {
		t.Fatalf("CreateDraft failed: %d %s", w.Code, w.Body.String())
	}
	etag1 := w.Header().Get("ETag")
	if etag1 == "" {
		t.Fatal("missing ETag header on created draft")
	}

	defPath := "/v1/operator/tenants/tenant-a/issuers/" + issuerID + "/credential-definitions/unas-certificate/versions/1.0.0"
	w = doAdminReq(mux, http.MethodPut, defPath, "admin-tok", "", "", defPayload)
	if w.Code != http.StatusPreconditionRequired {
		t.Fatalf("expected 428 missing If-Match, got %d", w.Code)
	}
	w = doAdminReq(mux, http.MethodPut, defPath, "admin-tok", "", `"stale-etag"`, defPayload)
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412 etag_mismatch, got %d %s", w.Code, w.Body.String())
	}
	defPayload["displayName"] = "Certificado UNAS v1"
	w = doAdminReq(mux, http.MethodPut, defPath, "admin-tok", "", etag1, defPayload)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Certificado UNAS v1") {
		t.Fatalf("ReplaceDraft failed: %d %s", w.Code, w.Body.String())
	}

	w = doAdminReq(mux, http.MethodPost, defPath+"/publish", "admin-tok", "idem-def-publish-001", "", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"published"`) {
		t.Fatalf("PublishDefinition failed: %d %s", w.Code, w.Body.String())
	}
	// Editing a published definition fails with 409 definition_immutable.
	w = doAdminReq(mux, http.MethodPut, defPath, "admin-tok", "", w.Header().Get("ETag"), defPayload)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 immutable on PUT published, got %d", w.Code)
	}
	w = doAdminReq(mux, http.MethodPost, defPath+"/retire", "admin-tok", "idem-def-retire-0001", "", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"retired"`) {
		t.Fatalf("RetireDefinition failed: %d %s", w.Code, w.Body.String())
	}

	// 6. Clients register / list / rotate-secret / revoke.
	w = doAdminReq(mux, http.MethodPost, "/v1/operator/tenants/tenant-a/clients", "admin-tok", "idem-client-create-1", "", map[string]any{
		"clientName":     "Eventos UNAS",
		"allowedIssuers": []string{issuerID},
		"scopes":         []string{"issuance:create", "issuance:read", "status:write"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("RegisterClient failed: %d %s", w.Code, w.Body.String())
	}
	var regResp struct {
		Client       issuance.ClientSummary `json:"client"`
		ClientSecret string                 `json:"clientSecret"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &regResp)
	if regResp.Client.ClientID == "" || len(regResp.ClientSecret) < 16 {
		t.Fatalf("unexpected client registration payload: %+v", regResp)
	}

	w = doAdminReq(mux, http.MethodGet, "/v1/operator/tenants/tenant-a/clients", "admin-tok", "", "", nil)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), regResp.ClientSecret) {
		t.Fatalf("ListClients invalid or leaked secret: %d %s", w.Code, w.Body.String())
	}
	w = doAdminReq(mux, http.MethodPost, "/v1/operator/tenants/tenant-a/clients/"+regResp.Client.ClientID+"/rotate-secret", "admin-tok", "idem-client-rot-0001", "", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "clientSecret") {
		t.Fatalf("RotateClientSecret failed: %d %s", w.Code, w.Body.String())
	}
	w = doAdminReq(mux, http.MethodPost, "/v1/operator/tenants/tenant-a/clients/"+regResp.Client.ClientID+"/revoke", "admin-tok", "idem-client-rev-0001", "", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"revoked"`) {
		t.Fatalf("RevokeClient failed: %d %s", w.Code, w.Body.String())
	}

	// 7. Audit read allowed for security_admin and issuer_operator scoped read works cleanly.
	w = doAdminReq(mux, http.MethodGet, "/v1/operator/tenants/tenant-a/audit?action=definition.published", "sec-tok", "", "", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"definition.published"`) || strings.Contains(w.Body.String(), "issuer_key.rotated") {
		t.Fatalf("Audit query failed: %d %s", w.Code, w.Body.String())
	}
	w = doAdminReq(mux, http.MethodGet, "/v1/operator/tenants/tenant-a/issuers", "issuer-op-tok", "", "", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), issuerID) {
		t.Fatalf("issuer_operator scoped read failed: %d %s", w.Code, w.Body.String())
	}
}

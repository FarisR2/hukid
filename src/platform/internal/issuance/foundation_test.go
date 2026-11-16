package issuance

import (
	"errors"
	"strings"
	"testing"
	"time"

	"hukid.local/platform/internal/verification"
)

func TestFoundationIssuerRecord(t *testing.T) {
	now := time.Date(2026, 11, 16, 18, 0, 0, 0, time.UTC)
	rec, err := NewIssuerRecord("tenant-unas", "iss_01", "unas", "IncubaUNAS", now)
	if err != nil {
		t.Fatalf("new issuer record: %v", err)
	}
	if rec.IssuerURI != "https://issuer.hukid.pe/unas" || rec.State != IssuerActive {
		t.Fatalf("unexpected issuer record: %+v", rec)
	}
	if _, err := NewIssuerRecord("", "iss_01", "unas", "IncubaUNAS", now); !errors.Is(err, ErrInvalidFoundationInput) {
		t.Fatalf("expected ErrInvalidFoundationInput for empty tenant, got %v", err)
	}
	if _, err := NewIssuerRecord("tenant-unas", "iss_01", "INVALID_SLUG", "IncubaUNAS", now); !errors.Is(err, ErrInvalidFoundationInput) {
		t.Fatalf("expected ErrInvalidFoundationInput for bad slug, got %v", err)
	}
}

func TestFoundationKeyRotationAndCompromise(t *testing.T) {
	now := time.Date(2026, 11, 16, 18, 0, 0, 0, time.UTC)
	audit := NewAuditLog(nil)
	ring, err := NewKeyRing("tenant-unas", testIssuerURI, audit)
	if err != nil {
		t.Fatalf("new keyring: %v", err)
	}

	// Register initial active key k1 and mint credential vc1.
	if err := ring.RegisterKey("key-1", mustGenerateKey(t), "admin-1", "cor-1", now); err != nil {
		t.Fatalf("register key-1: %v", err)
	}
	// Registering a second active key directly without rotation must fail.
	if err := ring.RegisterKey("key-dup", mustGenerateKey(t), "admin-1", "cor-2", now); !errors.Is(err, ErrKeyConflict) {
		t.Fatalf("expected ErrKeyConflict when active key already exists, got %v", err)
	}

	s1, err := ring.ActiveSigner()
	if err != nil || s1.KeyID() != "key-1" {
		t.Fatalf("expected active signer key-1, got %v err=%v", s1, err)
	}
	holderKey := mustGenerateKey(t)
	jkt, _ := verification.JWKThumbprint(&holderKey.PublicKey)
	vu := now.Add(24 * time.Hour)
	input1, _ := NewCertificateInput("urn:uuid:vc1", now.Add(-time.Hour), &vu, map[string]any{"name": "Ana"})
	vc1, err := IssueVCJWT(s1, input1, jkt)
	if err != nil {
		t.Fatalf("issue vc1: %v", err)
	}

	// Rotate to key-2: key-1 becomes retired, key-2 becomes active, both appear in PublicJWKS.
	if err := ring.RotateKey("key-2", mustGenerateKey(t), "admin-1", "cor-3", now.Add(time.Minute)); err != nil {
		t.Fatalf("rotate to key-2: %v", err)
	}
	s2, err := ring.ActiveSigner()
	if err != nil || s2.KeyID() != "key-2" {
		t.Fatalf("expected active signer key-2, got %v err=%v", s2, err)
	}
	input2, _ := NewCertificateInput("urn:uuid:vc2", now.Add(-time.Hour), &vu, map[string]any{"name": "Luis"})
	vc2, err := IssueVCJWT(s2, input2, jkt)
	if err != nil {
		t.Fatalf("issue vc2: %v", err)
	}

	jwks, err := ring.PublicJWKS()
	if err != nil || len(jwks.Keys) != 2 || jwks.Keys[0].Kid != "key-1" || jwks.Keys[1].Kid != "key-2" {
		t.Fatalf("expected both retired key-1 and active key-2 in JWKS, got %+v err=%v", jwks, err)
	}

	// Both vc1 (signed by retired key-1) and vc2 (signed by active key-2) verify!
	res, err := ring.BuildResolver()
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}
	verifier, err := verification.NewVerifier(res, verification.ClockFunc(func() time.Time { return now }), verification.DefaultLimits, verification.DefaultClockSkew)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	verifier = verifier.WithCredentialContexts(CertificateContext)

	if rep1, err := verifier.Verify(vc1); err != nil || rep1.TechnicalResult != verification.Valid {
		t.Fatalf("expected retired key-1 credential vc1 to remain Valid, got %+v err=%v", rep1, err)
	}
	if rep2, err := verifier.Verify(vc2); err != nil || rep2.TechnicalResult != verification.Valid {
		t.Fatalf("expected active key-2 credential vc2 to be Valid, got %+v err=%v", rep2, err)
	}

	// Compromise key-1: key-1 leaves JWKS; vc1 stops verifying while vc2 stays Valid.
	if err := ring.CompromiseKey("key-1", "sec-1", "cor-4", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("compromise key-1: %v", err)
	}
	jwksAfter, err := ring.PublicJWKS()
	if err != nil || len(jwksAfter.Keys) != 1 || jwksAfter.Keys[0].Kid != "key-2" {
		t.Fatalf("expected only key-2 after compromising key-1, got %+v err=%v", jwksAfter, err)
	}

	resAfter, _ := ring.BuildResolver()
	verifierAfter, _ := verification.NewVerifier(resAfter, verification.ClockFunc(func() time.Time { return now }), verification.DefaultLimits, verification.DefaultClockSkew)
	verifierAfter = verifierAfter.WithCredentialContexts(CertificateContext)
	if rep1After, _ := verifierAfter.Verify(vc1); rep1After.TechnicalResult != verification.Invalid {
		t.Fatalf("expected compromised key-1 vc1 to fail verification, got %+v", rep1After)
	}
	if rep2After, _ := verifierAfter.Verify(vc2); rep2After.TechnicalResult != verification.Valid {
		t.Fatalf("expected key-2 vc2 to remain Valid, got %+v", rep2After)
	}

	// Compromising active key-2 leaves issuer with no active signer.
	if err := ring.CompromiseKey("key-2", "sec-1", "cor-5", now.Add(3*time.Minute)); err != nil {
		t.Fatalf("compromise key-2: %v", err)
	}
	if _, err := ring.ActiveSigner(); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("expected ErrNoActiveKey after all keys compromised, got %v", err)
	}
}

func TestFoundationClientGrantsAndIsolation(t *testing.T) {
	now := time.Date(2026, 11, 16, 18, 0, 0, 0, time.UTC)
	audit := NewAuditLog(nil)
	reg := NewClientRegistry(audit)

	secretA := "events-super-secret-0123456789abcdef"
	exp := now.Add(24 * time.Hour)
	err := reg.RegisterClient(
		"tenant-unas",
		"cli_events",
		"Events Outbound Adapter",
		secretA,
		[]string{"iss_unas"},
		[]string{ScopeIssuanceCreate, ScopeIssuanceRead},
		&exp,
		"admin-1",
		"cor-10",
		now,
	)
	if err != nil {
		t.Fatalf("register client: %v", err)
	}

	// Wrong secret fails.
	if _, err := reg.AuthenticateClient("cli_events", "wrong-secret-0123456789", []string{ScopeIssuanceCreate}, now); !errors.Is(err, ErrClientUnauthorized) {
		t.Fatalf("expected ErrClientUnauthorized for wrong secret, got %v", err)
	}

	// Valid auth issues token class 'integration' with exact audience.
	tok, err := reg.AuthenticateClient("cli_events", secretA, []string{ScopeIssuanceCreate}, now)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if tok.TokenClass != IntegrationTokenClass || tok.Audience != IntegrationAudience {
		t.Fatalf("unexpected token metadata: %+v", tok)
	}

	// Authorized issuer succeeds.
	if err := reg.AuthorizeIssuerAccess(tok, "tenant-unas", "iss_unas", ScopeIssuanceCreate, now.Add(time.Minute)); err != nil {
		t.Fatalf("expected authorized access, got %v", err)
	}
	// Missing scope fails with unauthorized.
	if err := reg.AuthorizeIssuerAccess(tok, "tenant-unas", "iss_unas", ScopeIssuanceRead, now.Add(time.Minute)); !errors.Is(err, ErrClientUnauthorized) {
		t.Fatalf("expected ErrClientUnauthorized for missing scope, got %v", err)
	}
	// Wrong token class rejected even if tenant/issuer match.
	wrongClass := tok
	wrongClass.TokenClass = "operator"
	if err := reg.AuthorizeIssuerAccess(wrongClass, "tenant-unas", "iss_unas", ScopeIssuanceCreate, now.Add(time.Minute)); !errors.Is(err, ErrClientUnauthorized) {
		t.Fatalf("expected ErrClientUnauthorized for operator token class, got %v", err)
	}
	// Cross-tenant and cross-issuer return ErrResourceNotFound (404 per HK-004).
	if err := reg.AuthorizeIssuerAccess(tok, "tenant-other", "iss_unas", ScopeIssuanceCreate, now.Add(time.Minute)); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("expected ErrResourceNotFound cross-tenant, got %v", err)
	}
	if err := reg.AuthorizeIssuerAccess(tok, "tenant-unas", "iss_other", ScopeIssuanceCreate, now.Add(time.Minute)); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("expected ErrResourceNotFound ungranted issuer, got %v", err)
	}
	// Cross-tenant rotate/revoke rejected with 404.
	if err := reg.RotateSecret("tenant-other", "cli_events", "new-secret-0123456789abcdef", "evil", "cor-11", now); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("expected ErrResourceNotFound cross-tenant rotate, got %v", err)
	}
	if err := reg.RevokeClient("tenant-other", "cli_events", "evil", "cor-12", now); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("expected ErrResourceNotFound cross-tenant revoke, got %v", err)
	}

	// Secret rotation invalidates old secret and accepts new secret.
	secretB := "rotated-secret-0123456789abcdef"
	if err := reg.RotateSecret("tenant-unas", "cli_events", secretB, "admin-1", "cor-13", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("rotate secret: %v", err)
	}
	if _, err := reg.AuthenticateClient("cli_events", secretA, nil, now.Add(2*time.Minute)); !errors.Is(err, ErrClientUnauthorized) {
		t.Fatalf("expected old secret rejected after rotation, got %v", err)
	}
	tokB, err := reg.AuthenticateClient("cli_events", secretB, nil, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("new secret auth failed: %v", err)
	}

	// Revocation blocks both existing issued token check and new authentications.
	if err := reg.RevokeClient("tenant-unas", "cli_events", "admin-1", "cor-14", now.Add(3*time.Minute)); err != nil {
		t.Fatalf("revoke client: %v", err)
	}
	if err := reg.AuthorizeIssuerAccess(tokB, "tenant-unas", "iss_unas", ScopeIssuanceCreate, now.Add(3*time.Minute)); !errors.Is(err, ErrClientUnauthorized) {
		t.Fatalf("expected revoked client token rejected, got %v", err)
	}
	if _, err := reg.AuthenticateClient("cli_events", secretB, nil, now.Add(3*time.Minute)); !errors.Is(err, ErrClientUnauthorized) {
		t.Fatalf("expected revoked client auth rejected, got %v", err)
	}

	// Verify audit trail is tenant-isolated and never carries raw secrets (HK-005).
	events := audit.ListByTenant("tenant-unas", "")
	if len(events) < 5 {
		t.Fatalf("expected audit events recorded, got %d", len(events))
	}
	for _, ev := range events {
		if strings.Contains(ev.Action+ev.TargetID+ev.Outcome, secretA) || strings.Contains(ev.Action+ev.TargetID+ev.Outcome, secretB) {
			t.Fatalf("audit record leaked secret: %+v", ev)
		}
	}
	if len(audit.ListByTenant("tenant-other", "")) != 0 {
		t.Fatal("expected zero audit records for tenant-other")
	}
}

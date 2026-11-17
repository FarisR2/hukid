//go:build integration

package postgres

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"hukid.local/platform/internal/issuance"
	"hukid.local/platform/internal/verification"
)

func (db *testDatabase) poolWithConns(t *testing.T, group string, maxConns int32) *pgxpool.Pool {
	t.Helper()
	name := "hukid_test_login_" + randomHex(t, 8)
	password := randomHex(t, 32)
	statement := fmt.Sprintf("CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '%s'", pgx.Identifier{name}.Sanitize(), password)
	if _, err := db.admin.Exec(testContext, statement); err != nil {
		t.Fatal("cannot create test login")
	}
	db.roles = append(db.roles, name)
	if _, err := db.admin.Exec(testContext, "GRANT "+pgx.Identifier{group}.Sanitize()+" TO "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(db.dsn)
	u.User = url.UserPassword(name, password)
	pool, err := OpenRuntimePool(testContext, u.String(), group, maxConns)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

type testKMSVault struct {
	mu   sync.RWMutex
	keys map[string]*ecdsa.PrivateKey
}

func newTestKMSVault() *testKMSVault {
	return &testKMSVault{keys: map[string]*ecdsa.PrivateKey{}}
}

func (v *testKMSVault) generate(t *testing.T, ref string) (*ecdsa.PrivateKey, issuance.PublicJWK) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v.mu.Lock()
	v.keys[ref] = priv
	v.mu.Unlock()
	jwk, err := issuance.ExportPublicJWK(&priv.PublicKey, "")
	if err != nil {
		t.Fatal(err)
	}
	return priv, jwk
}

func (v *testKMSVault) resolve(_, _, issuerURI, kid, kmsKeyRef string, _ *ecdsa.PublicKey) (issuance.Signer, error) {
	v.mu.RLock()
	priv, ok := v.keys[kmsKeyRef]
	v.mu.RUnlock()
	if !ok {
		return nil, issuance.ErrNoActiveKey
	}
	return issuance.NewMemorySigner(issuerURI, kid, priv, rand.Reader)
}

func signTestProofJWT(t *testing.T, holder *ecdsa.PrivateKey, aud, nonce string, now time.Time) string {
	t.Helper()
	pubJWK := jose.JSONWebKey{Key: &holder.PublicKey, Algorithm: string(jose.ES256), Use: "sig"}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: holder},
		(&jose.SignerOptions{}).WithType("openid4vci-proof+jwt").WithHeader("jwk", pubJWK),
	)
	if err != nil {
		t.Fatalf("proof signer: %v", err)
	}
	claims, err := json.Marshal(map[string]any{
		"aud":   aud,
		"nonce": nonce,
		"iat":   now.Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func sampleCertificateDefPG(tenantID, issuerID string) issuance.Definition {
	return issuance.Definition{
		TenantID:        tenantID,
		IssuerID:        issuerID,
		ID:              "unas-certificate",
		Version:         "1.0.0",
		ConfigurationID: issuance.CertificateConfigID,
		DisplayName:     "Certificado de Asistencia UNAS",
		Locale:          "es-PE",
		Contexts:        []string{issuance.CertificateContext},
		Types:           []string{issuance.CertificateType},
		DefaultValidity: 365 * 24 * time.Hour,
		Fields: map[string]issuance.FieldSpec{
			"participantName": {Type: "string", Required: true, MaxLength: 120},
			"eventName":       {Type: "string", Required: true, MaxLength: 160},
			"role":            {Type: "string", Required: false, MaxLength: 60},
		},
	}
}

type issuanceFixture struct {
	pool     *pgxpool.Pool
	backend  *IssuanceBackend
	vault    *testKMSVault
	claimsK  []byte
	issuerID string
	clientID string
	secret   string
}

func seedIssuanceFixture(t *testing.T, db *testDatabase, now time.Time) *issuanceFixture {
	t.Helper()
	pool := db.poolWithConns(t, "hukid_issuance_runtime", 8)
	backend, err := NewIssuanceBackend(pool)
	if err != nil {
		t.Fatal(err)
	}
	vault := newTestKMSVault()
	issID := "11111111-1111-4111-8111-111111111111"
	cliID := "33333333-3333-4333-8333-333333333333"
	secret := "events-secret-0123456789abcdef"

	if _, err := backend.CreateIssuer(testContext, TestTenantA, issID, "unas", "IncubaUNAS", now); err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	_, jwk1 := vault.generate(t, "kms://unas/k1")
	if err := backend.RegisterKey(testContext, TestTenantA, issID, "unas-key-1", "kms://unas/k1", jwk1, TestActorA, "cor-k1", now); err != nil {
		t.Fatalf("register key: %v", err)
	}
	def := sampleCertificateDefPG(TestTenantA, issID)
	if err := backend.CreateDraftDefinition(testContext, def, TestActorA, "cor-d1", now); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	if _, err := backend.PublishDefinition(testContext, TestTenantA, issID, def.ID, def.Version, TestActorA, "cor-d2", now); err != nil {
		t.Fatalf("publish def: %v", err)
	}
	if err := backend.RegisterClient(testContext, TestTenantA, cliID, "Events Outbound", secret,
		[]string{issID}, []string{issuance.ScopeIssuanceCreate, issuance.ScopeIssuanceRead}, nil, TestActorA, "cor-c1", now); err != nil {
		t.Fatalf("register client: %v", err)
	}
	claimsKey := make([]byte, 32)
	if _, err := rand.Read(claimsKey); err != nil {
		t.Fatal(err)
	}
	return &issuanceFixture{
		pool: pool, backend: backend, vault: vault, claimsK: claimsKey,
		issuerID: issID, clientID: cliID, secret: secret,
	}
}

func (f *issuanceFixture) newService(t *testing.T, nowFn func() time.Time) *issuance.Service {
	t.Helper()
	svc, err := issuance.NewService(issuance.ServiceConfig{
		ClaimsKey:           f.claimsK,
		ClaimsKeyVersion:    "pg-v1",
		Backend:             f.backend,
		Signers:             f.vault.resolve,
		AuthorizationServer: "https://auth.hukid.pe",
		Now:                 nowFn,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc
}

func TestIssuanceBackendPersistenceAcrossServiceRestarts(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)

	now := time.Date(2026, 11, 16, 20, 0, 0, 0, time.UTC)
	clk := func() time.Time { return now }
	fx := seedIssuanceFixture(t, db, now)

	// Phase A: boot svc1, mint M2M token, create issuance request.
	svc1 := fx.newService(t, clk)
	tokResp, err := svc1.ClientCredentialsToken(fx.clientID, fx.secret, []string{issuance.ScopeIssuanceCreate, issuance.ScopeIssuanceRead})
	if err != nil {
		t.Fatalf("client credentials token: %v", err)
	}
	intTok, err := svc1.AuthenticateIntegration(tokResp.AccessToken)
	if err != nil {
		t.Fatalf("authenticate integration: %v", err)
	}
	reqIn := issuance.IssuanceRequestInput{
		IssuerID:             fx.issuerID,
		CredentialDefinition: "unas-certificate@1.0.0",
		Claims: map[string]any{
			"participantName": "Maria Quispe",
			"eventName":       "Congreso Cloud UNAS",
			"role":            "Asistente",
		},
		Source: &issuance.SourceInput{System: "events", Reference: "cert_pg_01"},
	}
	created, replay, err := svc1.CreateIssuanceRequest(intTok, "pg-idem-key-0001-events", reqIn)
	if err != nil || replay {
		t.Fatalf("create issuance request: res=%+v replay=%v err=%v", created, replay, err)
	}

	// Verify DB never persists plaintext PII claims.
	var claimsCipher []byte
	if err := db.admin.QueryRow(testContext, `SELECT claims_ciphertext FROM issuance.issuance_requests WHERE request_id=$1`, created.ID).Scan(&claimsCipher); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(claimsCipher, []byte("Maria Quispe")) || bytes.Contains(claimsCipher, []byte("Congreso Cloud")) {
		t.Fatal("plaintext claim found in PostgreSQL column")
	}

	// Phase B: simulate process restart with a brand-new Service instance (svc2).
	svc2 := fx.newService(t, clk)

	// Re-authenticating the existing M2M token & replaying Idempotency-Key survives restart.
	intTok2, err := svc2.AuthenticateIntegration(tokResp.AccessToken)
	if err != nil {
		t.Fatalf("token lost after restart: %v", err)
	}
	replayed, replay2, err := svc2.CreateIssuanceRequest(intTok2, "pg-idem-key-0001-events", reqIn)
	if err != nil || !replay2 || replayed.ID != created.ID || replayed.CredentialOfferURI != created.CredentialOfferURI {
		t.Fatalf("idempotent replay across restart failed: res=%+v replay=%v err=%v", replayed, replay2, err)
	}
	diffIn := reqIn
	diffIn.Claims = map[string]any{"participantName": "Otro Nombre", "eventName": "Congreso Cloud UNAS"}
	if _, _, err := svc2.CreateIssuanceRequest(intTok2, "pg-idem-key-0001-events", diffIn); !errors.Is(err, issuance.ErrIdempotencyConflict) {
		t.Fatalf("expected ErrIdempotencyConflict, got %v", err)
	}

	idx := strings.LastIndex(created.CredentialOfferURI, "ofr_")
	offerRef := created.CredentialOfferURI[idx:]
	offer, err := svc2.ResolveOffer("unas", offerRef)
	if err != nil {
		t.Fatalf("resolve offer after restart: %v", err)
	}
	preCode := offer.Grants[issuance.PreAuthorizedGrantType].PreAuthorizedCode
	oidTok, err := svc2.PreAuthorizedToken(preCode)
	if err != nil {
		t.Fatalf("redeem pre-authorized code: %v", err)
	}

	// Phase C: simulate a third process restart before wallet credential proof exchange!
	svc3 := fx.newService(t, clk)

	// Redeemed offer must disappear (and ciphertext cryptographically erased in SQL).
	if _, err := svc3.ResolveOffer("unas", offerRef); !errors.Is(err, issuance.ErrResourceNotFound) {
		t.Fatalf("expected redeemed offer to vanish, got %v", err)
	}
	var nullCount int
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM issuance.issuance_requests WHERE request_id=$1 AND offer_ciphertext IS NULL`, created.ID).Scan(&nullCount); err != nil || nullCount != 1 {
		t.Fatalf("redeemed offer ciphertext not erased: err=%v count=%d", err, nullCount)
	}
	if _, err := svc3.PreAuthorizedToken(preCode); !errors.Is(err, issuance.ErrInvalidGrant) {
		t.Fatalf("expected offer replay to fail, got %v", err)
	}

	nonce, err := svc3.IssueNonce("unas")
	if err != nil {
		t.Fatalf("issue nonce: %v", err)
	}
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credReq := issuance.CredentialRequest{
		CredentialIdentifier: oidTok.AuthorizationDetails[0].CredentialIdentifiers[0],
	}
	credReq.Proofs.JWT = []string{signTestProofJWT(t, holder, "https://issuer.hukid.pe/unas", nonce, now)}
	vcJWT, err := svc3.IssueCredential("unas", oidTok.AccessToken, credReq)
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	// Verify emitted vc+jwt using published JWKS from PostgreSQL.
	jwksDoc, ok := svc3.IssuerJWKS("unas")
	if !ok || len(jwksDoc.Keys) != 1 {
		t.Fatalf("unexpected jwks: ok=%v doc=%+v", ok, jwksDoc)
	}
	resolver := verification.NewMemoryKeyResolver()
	pub, err := issuance.DecodePublicJWK(jwksDoc.Keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := resolver.Add("https://issuer.hukid.pe/unas", jwksDoc.Keys[0].Kid, pub); err != nil {
		t.Fatal(err)
	}
	verifier, err := verification.NewVerifier(resolver, verification.ClockFunc(clk), verification.DefaultLimits, 0)
	if err != nil {
		t.Fatal(err)
	}
	holderJKT, err := verification.JWKThumbprint(&holder.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier = verifier.WithCredentialContexts(issuance.CertificateContext)
	check, err := verifier.Verify(vcJWT)
	if err != nil {
		t.Fatal(err)
	}
	if check.TechnicalResult != verification.Valid {
		t.Fatalf("expected verified vc+jwt, got %+v", check)
	}
	parts := strings.Split(vcJWT, ".")
	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var verifiedClaims struct {
		Cnf struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(rawPayload, &verifiedClaims); err != nil || verifiedClaims.Cnf.JKT != holderJKT {
		t.Fatalf("expected cnf.jkt=%s, got %+v err=%v", holderJKT, verifiedClaims, err)
	}

	// Token and nonce replays rejected; GetRequest reports redeemed+issued.
	if _, err := svc3.IssueCredential("unas", oidTok.AccessToken, credReq); !errors.Is(err, issuance.ErrInvalidToken) {
		t.Fatalf("expected burned token error, got %v", err)
	}
	statusRec, err := svc3.GetRequest(intTok2, created.ID)
	if err != nil || statusRec.OfferState != "redeemed" || statusRec.IssuanceState != "issued" {
		t.Fatalf("unexpected final status: %+v err=%v", statusRec, err)
	}
	audits, err := fx.backend.ListAuditEvents(testContext, TestTenantA, "")
	if err != nil || len(audits) < 5 {
		t.Fatalf("unexpected audit trail count=%d err=%v", len(audits), err)
	}
	assertCleared(t, fx.pool)
}

func TestIssuanceBackendConcurrentOfferAndCredentialRaces(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)

	now := time.Date(2026, 11, 16, 20, 30, 0, 0, time.UTC)
	fx := seedIssuanceFixture(t, db, now)
	svc := fx.newService(t, func() time.Time { return now })

	tokResp, err := svc.ClientCredentialsToken(fx.clientID, fx.secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	intTok, err := svc.AuthenticateIntegration(tokResp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	created, _, err := svc.CreateIssuanceRequest(intTok, "pg-race-idem-0001", issuance.IssuanceRequestInput{
		IssuerID:             fx.issuerID,
		CredentialDefinition: "unas-certificate@1.0.0",
		Claims:               map[string]any{"participantName": "Race User", "eventName": "Concurrency Conf"},
	})
	if err != nil {
		t.Fatal(err)
	}
	offer, err := svc.ResolveOffer("unas", created.CredentialOfferURI[strings.LastIndex(created.CredentialOfferURI, "ofr_"):])
	if err != nil {
		t.Fatal(err)
	}
	preCode := offer.Grants[issuance.PreAuthorizedGrantType].PreAuthorizedCode

	// Race 8 goroutines redeeming the same single-use pre-authorized code.
	const workers = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var tokens []issuance.TokenResponse
	var grantFailures int
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp, err := svc.PreAuthorizedToken(preCode)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				tokens = append(tokens, resp)
			} else if errors.Is(err, issuance.ErrInvalidGrant) {
				grantFailures++
			}
		}()
	}
	close(start)
	wg.Wait()
	if len(tokens) != 1 || grantFailures != workers-1 {
		t.Fatalf("expected exactly 1 offer winner and %d grant failures, got winners=%d failures=%d", workers-1, len(tokens), grantFailures)
	}

	// Race 8 goroutines consuming the single-use OID4VCI access token.
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credID := tokens[0].AuthorizationDetails[0].CredentialIdentifiers[0]
	bearer := tokens[0].AccessToken
	nonces := make([]string, workers)
	for i := 0; i < workers; i++ {
		n, err := svc.IssueNonce("unas")
		if err != nil {
			t.Fatal(err)
		}
		nonces[i] = n
	}

	start2 := make(chan struct{})
	var creds []string
	var tokenFailures int
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := issuance.CredentialRequest{CredentialIdentifier: credID}
			req.Proofs.JWT = []string{signTestProofJWT(t, holder, "https://issuer.hukid.pe/unas", nonces[idx], now)}
			<-start2
			c, err := svc.IssueCredential("unas", bearer, req)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				creds = append(creds, c)
			} else if errors.Is(err, issuance.ErrInvalidToken) {
				tokenFailures++
			}
		}(i)
	}
	close(start2)
	wg.Wait()
	if len(creds) != 1 || tokenFailures != workers-1 {
		t.Fatalf("expected exactly 1 credential minted and %d token failures, got minted=%d failures=%d", workers-1, len(creds), tokenFailures)
	}
	assertCleared(t, fx.pool)
}

func TestIssuanceBackendDefinitionImmutabilityKeyRotationAndRLS(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)

	now := time.Date(2026, 11, 16, 21, 0, 0, 0, time.UTC)
	fx := seedIssuanceFixture(t, db, now)
	svc := fx.newService(t, func() time.Time { return now })

	// Published definition cannot be mutated via backend OR raw SQL.
	modDef := sampleCertificateDefPG(TestTenantA, fx.issuerID)
	modDef.DisplayName = "Mutado"
	if err := fx.backend.ReplaceDraftDefinition(testContext, modDef, TestActorA, "cor-mut", now); !errors.Is(err, issuance.ErrDefinitionImmutable) {
		t.Fatalf("expected ErrDefinitionImmutable, got %v", err)
	}
	_, rawMutErr := db.admin.Exec(testContext, `UPDATE definition.definition_versions SET display_name='hack' WHERE definition_id='unas-certificate'`)
	expectCode(t, rawMutErr, "22023")

	// Rotate key: active + retired both in JWKS; compromise removes compromised key and stops issuance.
	_, jwk2 := fx.vault.generate(t, "kms://unas/k2")
	if err := fx.backend.RotateKey(testContext, TestTenantA, fx.issuerID, "unas-key-2", "kms://unas/k2", jwk2, TestActorA, "cor-r1", now); err != nil {
		t.Fatalf("rotate key: %v", err)
	}
	jwks, ok := svc.IssuerJWKS("unas")
	if !ok || len(jwks.Keys) != 2 {
		t.Fatalf("expected 2 keys after rotation, got %+v", jwks)
	}
	if err := fx.backend.CompromiseKey(testContext, TestTenantA, fx.issuerID, "unas-key-2", TestActorA, "cor-comp", now); err != nil {
		t.Fatalf("compromise key: %v", err)
	}
	jwksAfterCompromise, ok := svc.IssuerJWKS("unas")
	if !ok || len(jwksAfterCompromise.Keys) != 1 || jwksAfterCompromise.Keys[0].Kid != "unas-key-1" {
		t.Fatalf("compromised key leaked into JWKS: %+v", jwksAfterCompromise)
	}

	// Wrong secret persists "denied" audit row despite TX rollback of issuance tokens.
	if _, err := svc.ClientCredentialsToken(fx.clientID, "wrong-secret-0123456789", nil); !errors.Is(err, issuance.ErrClientUnauthorized) {
		t.Fatalf("expected ErrClientUnauthorized, got %v", err)
	}
	denied, err := fx.backend.ListAuditEvents(testContext, TestTenantA, "integration_client.authenticate")
	if err != nil || len(denied) != 1 || denied[0].Outcome != "denied" {
		t.Fatalf("expected 1 denied auth audit event, got %+v err=%v", denied, err)
	}

	// Seed Tenant B issuer & client, enforce cross-tenant RLS isolation.
	issB := "22222222-2222-4222-8222-222222222222"
	cliB := "44444444-4444-4444-8444-444444444444"
	if _, err := fx.backend.CreateIssuer(testContext, TestTenantB, issB, "other-org", "Other Org", now); err != nil {
		t.Fatal(err)
	}
	if err := fx.backend.RegisterClient(testContext, TestTenantB, cliB, "Client B", "tenant-b-secret-0123456789", []string{issB}, []string{issuance.ScopeIssuanceCreate, issuance.ScopeIssuanceRead}, nil, TestActorB, "cor-b1", now); err != nil {
		t.Fatal(err)
	}
	tokB, err := svc.ClientCredentialsToken(cliB, "tenant-b-secret-0123456789", nil)
	if err != nil {
		t.Fatal(err)
	}
	intTokB, err := svc.AuthenticateIntegration(tokB.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	// Tenant B cannot issue on Tenant A's issuer (must appear as 404 resource_not_found).
	if _, _, err := svc.CreateIssuanceRequest(intTokB, "cross-tenant-idem-001", issuance.IssuanceRequestInput{
		IssuerID:             fx.issuerID,
		CredentialDefinition: "unas-certificate@1.0.0",
		Claims:               map[string]any{"participantName": "X", "eventName": "Y"},
	}); !errors.Is(err, issuance.ErrResourceNotFound) {
		t.Fatalf("expected ErrResourceNotFound across tenants, got %v", err)
	}

	// Tenant B cannot read Tenant A audit events or definitions.
	auditsB, err := fx.backend.ListAuditEvents(testContext, TestTenantB, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range auditsB {
		if ev.TenantID != TestTenantB {
			t.Fatalf("audit leak into Tenant B: %+v", ev)
		}
	}

	// Revoking client A blocks existing tokens even before expiry.
	tokA, err := svc.ClientCredentialsToken(fx.clientID, fx.secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	intTokA, err := svc.AuthenticateIntegration(tokA.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.backend.RevokeClient(testContext, TestTenantA, fx.clientID, TestActorA, "cor-rev", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.CreateIssuanceRequest(intTokA, "after-revoke-idem-0001", issuance.IssuanceRequestInput{
		IssuerID:             fx.issuerID,
		CredentialDefinition: "unas-certificate@1.0.0",
		Claims:               map[string]any{"participantName": "X", "eventName": "Y"},
	}); !errors.Is(err, issuance.ErrClientUnauthorized) {
		t.Fatalf("expected revoked client to be rejected, got %v", err)
	}

	// Retire definition prevents issuance.
	if err := fx.backend.RetireDefinition(testContext, TestTenantA, fx.issuerID, "unas-certificate", "1.0.0", TestActorA, "cor-ret", now); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.backend.GetDefinition(testContext, TestTenantB, fx.issuerID, "unas-certificate", "1.0.0"); !errors.Is(err, issuance.ErrDefinitionNotFound) {
		t.Fatalf("expected cross-tenant definition lookup to be hidden, got %v", err)
	}
	// Raw INSERT without tenant scope must be blocked by FORCE RLS (42501).
	var zero int
	if err := withUnscopedTx(testContext, fx.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(testContext, `SELECT count(*) FROM issuance.issuance_requests`).Scan(&zero)
	}); err != nil || zero != 0 {
		t.Fatalf("unscoped query saw rows or failed: count=%d err=%v", zero, err)
	}
	err = withUnscopedTx(testContext, fx.pool, func(tx pgx.Tx) error {
		sum := sha256.Sum256([]byte("x"))
		_, err := tx.Exec(testContext, `INSERT INTO issuance.nonces(nonce_hash,tenant_id,issuer_id,created_at,expires_at) VALUES($1,$2,$3,$4,$5)`, sum[:], TestTenantA, fx.issuerID, now, now.Add(time.Minute))
		return err
	})
	expectCode(t, err, "42501")
	assertCleared(t, fx.pool)
}

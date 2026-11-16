package issuance

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"hukid.local/platform/internal/verification"
)

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time          { return c.now }
func (c *testClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

type serviceHarness struct {
	clock   *testClock
	audit   *AuditLog
	clients *ClientRegistry
	defs    *DefinitionRegistry
	ring    *KeyRing
	svc     *Service
	issuer  IssuerRecord
}

func newServiceHarness(t *testing.T) *serviceHarness {
	t.Helper()
	now := time.Date(2026, 11, 16, 19, 0, 0, 0, time.UTC)
	clk := &testClock{now: now}
	audit := NewAuditLog(nil)
	clients := NewClientRegistry(audit)
	defs := NewDefinitionRegistry(audit)

	issuerRec, err := NewIssuerRecord("tenant-unas", "iss_unas", "unas", "IncubaUNAS", now)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	ring, err := NewKeyRing("tenant-unas", issuerRec.IssuerURI, audit)
	if err != nil {
		t.Fatalf("new keyring: %v", err)
	}
	if err := ring.RegisterKey(testKID, mustGenerateKey(t), "admin-1", "cor-1", now); err != nil {
		t.Fatalf("register key: %v", err)
	}

	def := sampleCertificateDefinition("tenant-unas", "iss_unas")
	if err := defs.CreateDraft(def, "admin-1", "cor-2", now); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	if _, err := defs.Publish("tenant-unas", "iss_unas", def.ID, def.Version, "admin-1", "cor-3", now); err != nil {
		t.Fatalf("publish def: %v", err)
	}

	err = clients.RegisterClient(
		"tenant-unas",
		"cli_events",
		"Events Outbound",
		"events-secret-0123456789abcdef",
		[]string{"iss_unas"},
		[]string{ScopeIssuanceCreate, ScopeIssuanceRead},
		nil,
		"admin-1",
		"cor-4",
		now,
	)
	if err != nil {
		t.Fatalf("register client: %v", err)
	}

	claimsKey := make([]byte, 32)
	if _, err := rand.Read(claimsKey); err != nil {
		t.Fatalf("claims key: %v", err)
	}
	svc, err := NewService(ServiceConfig{
		ClaimsKey:           claimsKey,
		ClaimsKeyVersion:    "lab-1",
		Clients:             clients,
		Definitions:         defs,
		Audit:               audit,
		AuthorizationServer: "https://auth.hukid.pe",
		Now:                 clk.Now,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	if err := svc.RegisterIssuer(issuerRec, ring); err != nil {
		t.Fatalf("register issuer: %v", err)
	}
	return &serviceHarness{
		clock:   clk,
		audit:   audit,
		clients: clients,
		defs:    defs,
		ring:    ring,
		svc:     svc,
		issuer:  issuerRec,
	}
}

func TestServiceEndToEndAndIdempotency(t *testing.T) {
	h := newServiceHarness(t)

	// 1. Events authenticates via client_credentials.
	tokResp, err := h.svc.ClientCredentialsToken("cli_events", "events-secret-0123456789abcdef", []string{ScopeIssuanceCreate, ScopeIssuanceRead})
	if err != nil {
		t.Fatalf("client credentials: %v", err)
	}
	intTok, err := h.svc.AuthenticateIntegration(tokResp.AccessToken)
	if err != nil {
		t.Fatalf("auth integration: %v", err)
	}

	// 2. Create issuance request.
	reqInput := IssuanceRequestInput{
		IssuerID:             "iss_unas",
		CredentialDefinition: "unas-certificate@1.0.0",
		Claims: map[string]any{
			"participantName": "Maria Quispe",
			"eventName":       "Congreso Cloud UNAS",
			"hours":           12,
			"passed":          true,
			"metadata":        map[string]any{"campus": "Tingo Maria"},
		},
		Source: &SourceInput{System: "events", Reference: "cert_001"},
	}
	res, replay, err := h.svc.CreateIssuanceRequest(intTok, "events-idem-key-0001", reqInput)
	if err != nil || replay {
		t.Fatalf("create issuance request: res=%+v replay=%v err=%v", res, replay, err)
	}
	if res.OfferState != "ready" || res.IssuanceState != "prepared" || !strings.HasPrefix(res.CredentialOfferURI, "openid-credential-offer://?credential_offer_uri=") {
		t.Fatalf("unexpected request result: %+v", res)
	}

	// Verify claims are encrypted at rest (ciphertext does not contain plaintext).
	stored := h.svc.reqs[res.ID]
	if bytes.Contains(stored.claimsCipher, []byte("Maria Quispe")) || bytes.Contains(stored.claimsCipher, []byte("Congreso Cloud")) {
		t.Fatal("claims stored in plaintext instead of AES-256-GCM ciphertext")
	}

	// 3. Idempotent replay returns identical result; different body returns ErrIdempotencyConflict.
	resReplay, replay2, err := h.svc.CreateIssuanceRequest(intTok, "events-idem-key-0001", reqInput)
	if err != nil || !replay2 || resReplay.ID != res.ID || resReplay.CredentialOfferURI != res.CredentialOfferURI {
		t.Fatalf("expected idempotent replay, got res=%+v replay=%v err=%v", resReplay, replay2, err)
	}
	diffReq := reqInput
	diffReq.Claims = map[string]any{
		"participantName": "Otra Persona",
		"eventName":       "Congreso Cloud UNAS",
	}
	if _, _, err := h.svc.CreateIssuanceRequest(intTok, "events-idem-key-0001", diffReq); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected ErrIdempotencyConflict, got %v", err)
	}

	// 4. Resolve offer by ref, redeem pre-authorized code once, obtain c_nonce & issue vc+jwt.
	idx := strings.LastIndex(res.CredentialOfferURI, "ofr_")
	if idx < 0 {
		t.Fatalf("missing offer ref in URI %q", res.CredentialOfferURI)
	}
	ref := res.CredentialOfferURI[idx:]
	// Unescape in case anything follows; here ref is the trailing path segment.
	offer, err := h.svc.ResolveOffer("unas", ref)
	if err != nil {
		t.Fatalf("resolve offer: %v", err)
	}
	preCode := offer.Grants[PreAuthorizedGrantType].PreAuthorizedCode

	vciTok, err := h.svc.PreAuthorizedToken(preCode)
	if err != nil || len(vciTok.AuthorizationDetails) != 1 || len(vciTok.AuthorizationDetails[0].CredentialIdentifiers) != 1 {
		t.Fatalf("pre-authorized token: %+v err=%v", vciTok, err)
	}
	// Second redeem fails; offer ref disappears.
	if _, err := h.svc.PreAuthorizedToken(preCode); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected ErrInvalidGrant on offer replay, got %v", err)
	}
	if _, err := h.svc.ResolveOffer("unas", ref); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("expected ErrResourceNotFound after offer redemption, got %v", err)
	}

	// Polling status reflects redeemed / prepared.
	polled, err := h.svc.GetRequest(intTok, res.ID)
	if err != nil || polled.OfferState != "redeemed" || polled.IssuanceState != "prepared" {
		t.Fatalf("unexpected polled state: %+v err=%v", polled, err)
	}

	// Cross-class rejection: OID4VCI token cannot authenticate Integration API; integration token cannot issue credential.
	if _, err := h.svc.AuthenticateIntegration(vciTok.AccessToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken when using oid4vci token as integration, got %v", err)
	}
	cNonce, err := h.svc.IssueNonce("unas")
	if err != nil {
		t.Fatalf("issue nonce: %v", err)
	}
	holderKey := mustGenerateKey(t)
	proofJWT, err := BuildHolderProof(holderKey, h.issuer.IssuerURI, cNonce, h.clock.Now(), nil)
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}
	credReq := CredentialRequest{CredentialIdentifier: vciTok.AuthorizationDetails[0].CredentialIdentifiers[0]}
	credReq.Proofs.JWT = []string{proofJWT}

	if _, err := h.svc.IssueCredential("unas", tokResp.AccessToken, credReq); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken when using integration token on credential endpoint, got %v", err)
	}

	// Issue vc+jwt and verify with verification.Verifier.
	vcJWT, err := h.svc.IssueCredential("unas", vciTok.AccessToken, credReq)
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	// Reusing the burned access token or nonce fails.
	if _, err := h.svc.IssueCredential("unas", vciTok.AccessToken, credReq); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken when reusing access token, got %v", err)
	}

	// Final poll shows issued.
	finalState, err := h.svc.GetRequest(intTok, res.ID)
	if err != nil || finalState.OfferState != "redeemed" || finalState.IssuanceState != "issued" {
		t.Fatalf("unexpected final state: %+v err=%v", finalState, err)
	}

	// Verify issued vc+jwt against verification core.
	resolver, err := h.ring.BuildResolver()
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}
	verifier, err := verification.NewVerifier(resolver, h.clock, verification.DefaultLimits, verification.DefaultClockSkew)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	verifier = verifier.WithCredentialContexts(CertificateContext).WithReplayStore(verification.NewMemoryReplayStore())
	report, err := verifier.Verify(vcJWT)
	if err != nil || report.TechnicalResult != verification.Valid {
		t.Fatalf("expected Valid vc report, got %+v err=%v", report, err)
	}
}

func TestServiceOfferExpiryAndTxCodeRejection(t *testing.T) {
	h := newServiceHarness(t)
	tokResp, err := h.svc.ClientCredentialsToken("cli_events", "events-secret-0123456789abcdef", nil)
	if err != nil {
		t.Fatalf("client credentials: %v", err)
	}
	intTok, _ := h.svc.AuthenticateIntegration(tokResp.AccessToken)

	// tx_code is outside v0.
	_, _, err = h.svc.CreateIssuanceRequest(intTok, "events-idem-key-0002", IssuanceRequestInput{
		IssuerID:             "iss_unas",
		CredentialDefinition: "unas-certificate@1.0.0",
		Claims:               map[string]any{"participantName": "Ana", "eventName": "Demo"},
		Delivery:             &DeliveryInput{Flow: "pre-authorized_code", TxCodeRequired: true},
	})
	if !errors.Is(err, ErrUnsupportedDelivery) {
		t.Fatalf("expected ErrUnsupportedDelivery, got %v", err)
	}

	// Create valid 60s offer and let clock advance past expiry.
	res, _, err := h.svc.CreateIssuanceRequest(intTok, "events-idem-key-0003", IssuanceRequestInput{
		IssuerID:             "iss_unas",
		CredentialDefinition: "unas-certificate@1.0.0",
		Claims:               map[string]any{"participantName": "Ana", "eventName": "Demo"},
		Delivery:             &DeliveryInput{Flow: "pre-authorized_code", ExpiresInSeconds: 60},
	})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	idx := strings.LastIndex(res.CredentialOfferURI, "ofr_")
	ref := res.CredentialOfferURI[idx:]
	offer, err := h.svc.ResolveOffer("unas", ref)
	if err != nil {
		t.Fatalf("resolve offer: %v", err)
	}

	h.clock.Advance(61 * time.Second)
	if _, err := h.svc.ResolveOffer("unas", ref); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("expected expired offer to return ErrResourceNotFound, got %v", err)
	}
	if _, err := h.svc.PreAuthorizedToken(offer.Grants[PreAuthorizedGrantType].PreAuthorizedCode); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected ErrInvalidGrant on expired offer, got %v", err)
	}
	polled, err := h.svc.GetRequest(intTok, res.ID)
	if err != nil || polled.OfferState != "expired" {
		t.Fatalf("expected offerState=expired, got %+v err=%v", polled, err)
	}
}

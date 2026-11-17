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
	stored := h.svc.mem.reqs[res.ID]
	if bytes.Contains(stored.ClaimsCipher, []byte("Maria Quispe")) || bytes.Contains(stored.ClaimsCipher, []byte("Congreso Cloud")) {
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

func TestPersistentPEMAndSealedSignerRoundTrip(t *testing.T) {
	key := mustGenerateKey(t)
	pemBytes, err := MarshalP256PrivateKeyPKCS8PEM(key)
	if err != nil {
		t.Fatalf("marshal pem: %v", err)
	}
	signer, err := NewMemorySignerFromPEM("https://issuer.hukid.pe/unas", "unas-key-1", pemBytes, nil)
	if err != nil {
		t.Fatalf("signer from pem: %v", err)
	}
	jwk, err := signer.JWK()
	if err != nil {
		t.Fatalf("export jwk: %v", err)
	}
	pub, err := DecodePublicJWK(jwk)
	if err != nil || !pub.Equal(&key.PublicKey) {
		t.Fatalf("decoded jwk mismatch: err=%v", err)
	}

	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	cipherKey, nonce, err := SealP256PrivateKey(key, kek, "unas-key-1", nil)
	if err != nil {
		t.Fatalf("seal key: %v", err)
	}
	reopened, err := OpenP256PrivateKey(cipherKey, nonce, kek, "unas-key-1")
	if err != nil || !reopened.Equal(key) {
		t.Fatalf("open sealed key: err=%v", err)
	}
	if _, err := OpenP256PrivateKey(cipherKey, nonce, kek, "wrong-aad"); err == nil {
		t.Fatal("expected AAD mismatch to fail")
	}
}

type serviceStatusResolver struct {
	svc    *Service
	prefix string
}

func (r *serviceStatusResolver) ResolveStatusList(credentialURL string) (string, error) {
	rest, ok := strings.CutPrefix(credentialURL, r.prefix)
	if !ok {
		return "", verification.ErrStatusResolution
	}
	purpose, listID, ok := strings.Cut(rest, "/")
	if !ok || listID == "" {
		return "", verification.ErrStatusResolution
	}
	jwt, err := r.svc.ResolveStatusList("unas", purpose, listID)
	if err != nil {
		return "", verification.ErrStatusResolution
	}
	return jwt, nil
}

func hasFailedStatusCheck(report verification.Report, want verification.Code) bool {
	for _, chk := range report.Checks {
		if chk.Name == verification.CheckStatus && chk.Result == verification.Fail && chk.Code == want {
			return true
		}
	}
	return false
}

func TestServiceStatusListsSuspendReactivateRevokeAndIdempotency(t *testing.T) {
	h := newServiceHarness(t)

	def := sampleCertificateDefinition("tenant-unas", "iss_unas")
	def.Version = "2.0.0"
	def.ConfigurationID = "unas_certificate_status_v2"
	def.StatusPurposes = []string{PurposeRevocation, PurposeSuspension}
	if err := h.defs.CreateDraft(def, "admin-1", "cor-s1", h.clock.Now()); err != nil {
		t.Fatalf("create status def draft: %v", err)
	}
	if _, err := h.defs.Publish("tenant-unas", "iss_unas", def.ID, def.Version, "admin-1", "cor-s2", h.clock.Now()); err != nil {
		t.Fatalf("publish status def: %v", err)
	}

	if err := h.clients.RegisterClient(
		"tenant-unas",
		"cli_status",
		"Events Status Writer",
		"status-secret-0123456789abcdef",
		[]string{"iss_unas"},
		[]string{ScopeIssuanceCreate, ScopeIssuanceRead, ScopeStatusWrite},
		nil,
		"admin-1",
		"cor-s3",
		h.clock.Now(),
	); err != nil {
		t.Fatalf("register cli_status: %v", err)
	}
	if err := h.clients.RegisterClient(
		"tenant-other",
		"cli_other_status",
		"Other Tenant Status Writer",
		"other-status-0123456789abcdef",
		[]string{"iss_other"},
		[]string{ScopeIssuanceCreate, ScopeIssuanceRead, ScopeStatusWrite},
		nil,
		"admin-2",
		"cor-s4",
		h.clock.Now(),
	); err != nil {
		t.Fatalf("register cli_other_status: %v", err)
	}

	tokNoScope, err := h.svc.ClientCredentialsToken("cli_events", "events-secret-0123456789abcdef", []string{ScopeIssuanceCreate, ScopeIssuanceRead})
	if err != nil {
		t.Fatalf("cli_events token: %v", err)
	}
	noScopeAuth, err := h.svc.AuthenticateIntegration(tokNoScope.AccessToken)
	if err != nil {
		t.Fatalf("auth cli_events: %v", err)
	}

	tokStatus, err := h.svc.ClientCredentialsToken("cli_status", "status-secret-0123456789abcdef", []string{ScopeIssuanceCreate, ScopeIssuanceRead, ScopeStatusWrite})
	if err != nil {
		t.Fatalf("cli_status token: %v", err)
	}
	statusAuth, err := h.svc.AuthenticateIntegration(tokStatus.AccessToken)
	if err != nil {
		t.Fatalf("auth cli_status: %v", err)
	}

	tokOther, err := h.svc.ClientCredentialsToken("cli_other_status", "other-status-0123456789abcdef", []string{ScopeStatusWrite})
	if err != nil {
		t.Fatalf("cli_other_status token: %v", err)
	}
	otherAuth, err := h.svc.AuthenticateIntegration(tokOther.AccessToken)
	if err != nil {
		t.Fatalf("auth cli_other_status: %v", err)
	}

	res, _, err := h.svc.CreateIssuanceRequest(statusAuth, "status-request-key-0001", IssuanceRequestInput{
		IssuerID:             "iss_unas",
		CredentialDefinition: "unas-certificate@2.0.0",
		Claims: map[string]any{
			"participantName": "Lucia Paredes",
			"eventName":       "Taller de Seguridad UNAS",
			"hours":           8,
		},
		Source: &SourceInput{System: "events", Reference: "cert_status_001"},
	})
	if err != nil {
		t.Fatalf("create issuance request: %v", err)
	}
	idx := strings.LastIndex(res.CredentialOfferURI, "ofr_")
	if idx < 0 {
		t.Fatalf("missing offer ref in %q", res.CredentialOfferURI)
	}
	offer, err := h.svc.ResolveOffer("unas", res.CredentialOfferURI[idx:])
	if err != nil {
		t.Fatalf("resolve offer: %v", err)
	}
	vciTok, err := h.svc.PreAuthorizedToken(offer.Grants[PreAuthorizedGrantType].PreAuthorizedCode)
	if err != nil {
		t.Fatalf("pre-authorized token: %v", err)
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
	vcJWT, err := h.svc.IssueCredential("unas", vciTok.AccessToken, credReq)
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	polled, err := h.svc.GetRequest(statusAuth, res.ID)
	if err != nil {
		t.Fatalf("get issued request: %v", err)
	}
	if polled.IssuanceState != "issued" || !strings.HasPrefix(polled.CredentialID, "vc_") {
		t.Fatalf("expected issued state and opaque vc_ credentialId, got %+v", polled)
	}
	if strings.Contains(polled.CredentialID, "Lucia") {
		t.Fatalf("credentialId leaked PII: %q", polled.CredentialID)
	}
	credID := polled.CredentialID

	resolver, err := h.ring.BuildResolver()
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}
	verifier, err := verification.NewVerifier(resolver, h.clock, verification.DefaultLimits, verification.DefaultClockSkew)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	verifier = verifier.
		WithCredentialContexts(CertificateContext).
		WithReplayStore(verification.NewMemoryReplayStore()).
		WithStatusResolver(&serviceStatusResolver{svc: h.svc, prefix: h.issuer.IssuerURI + "/status/"}, verification.StatusPolicy{})

	report, err := verifier.Verify(vcJWT)
	if err != nil || report.TechnicalResult != verification.Valid {
		t.Fatalf("expected active credential Valid, got %+v err=%v", report, err)
	}

	// Missing status:write scope fails closed; cross-tenant fails as not found; reactivating active fails transition.
	if _, _, err := h.svc.SuspendCredential(noScopeAuth, "no-scope-suspend-01", credID, StatusChangeInput{ReasonCode: "audit"}); !errors.Is(err, ErrClientUnauthorized) {
		t.Fatalf("expected ErrClientUnauthorized without status:write, got %v", err)
	}
	if _, _, err := h.svc.SuspendCredential(otherAuth, "other-tenant-susp-01", credID, StatusChangeInput{ReasonCode: "audit"}); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("expected ErrResourceNotFound across tenants, got %v", err)
	}
	if _, _, err := h.svc.ReactivateCredential(statusAuth, "reactivate-active-01", credID); !errors.Is(err, ErrInvalidStatusTransition) {
		t.Fatalf("expected ErrInvalidStatusTransition reactivating active credential, got %v", err)
	}

	// Suspend -> idempotent replay -> conflict -> verifier status.suspended.
	suspRes, replay, err := h.svc.SuspendCredential(statusAuth, "idem-suspend-0001", credID, StatusChangeInput{ReasonCode: "review", Comment: "revisando"})
	if err != nil || replay || suspRes.DesiredStatus != CredentialStatusSuspended || suspRes.PublishedStatus != CredentialStatusSuspended {
		t.Fatalf("unexpected suspend result: res=%+v replay=%v err=%v", suspRes, replay, err)
	}
	suspReplay, replay2, err := h.svc.SuspendCredential(statusAuth, "idem-suspend-0001", credID, StatusChangeInput{ReasonCode: "review", Comment: "revisando"})
	if err != nil || !replay2 || suspReplay.StatusListVersion != suspRes.StatusListVersion {
		t.Fatalf("expected idempotent suspend replay, got res=%+v replay=%v err=%v", suspReplay, replay2, err)
	}
	if _, _, err := h.svc.SuspendCredential(statusAuth, "idem-suspend-0001", credID, StatusChangeInput{ReasonCode: "different"}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected ErrIdempotencyConflict on body mismatch, got %v", err)
	}
	if _, _, err := h.svc.SuspendCredential(statusAuth, "idem-suspend-0002", credID, StatusChangeInput{ReasonCode: "review"}); !errors.Is(err, ErrInvalidStatusTransition) {
		t.Fatalf("expected ErrInvalidStatusTransition suspending already-suspended credential, got %v", err)
	}

	report, err = verifier.Verify(vcJWT)
	if err != nil || report.TechnicalResult != verification.Invalid || !hasFailedStatusCheck(report, verification.CodeStatusSuspended) {
		t.Fatalf("expected Invalid with status.suspended, got %+v err=%v", report, err)
	}

	// Reactivate -> Valid again.
	reactRes, replay, err := h.svc.ReactivateCredential(statusAuth, "idem-reactivate-0001", credID)
	if err != nil || replay || reactRes.DesiredStatus != CredentialStatusActive || reactRes.PublishedStatus != CredentialStatusActive {
		t.Fatalf("unexpected reactivate result: res=%+v replay=%v err=%v", reactRes, replay, err)
	}
	report, err = verifier.Verify(vcJWT)
	if err != nil || report.TechnicalResult != verification.Valid {
		t.Fatalf("expected Valid after reactivation, got %+v err=%v", report, err)
	}

	// Revoke -> idempotent replay -> terminal -> verifier status.revoked.
	revRes, replay, err := h.svc.RevokeCredential(statusAuth, "idem-revoke-0001", credID, StatusChangeInput{ReasonCode: "certificate_revoked"})
	if err != nil || replay || revRes.DesiredStatus != CredentialStatusRevoked || revRes.PublishedStatus != CredentialStatusRevoked {
		t.Fatalf("unexpected revoke result: res=%+v replay=%v err=%v", revRes, replay, err)
	}
	if _, replay3, err := h.svc.RevokeCredential(statusAuth, "idem-revoke-0001", credID, StatusChangeInput{ReasonCode: "certificate_revoked"}); err != nil || !replay3 {
		t.Fatalf("expected idempotent revoke replay, got replay=%v err=%v", replay3, err)
	}
	if _, _, err := h.svc.ReactivateCredential(statusAuth, "idem-reactivate-revoked", credID); !errors.Is(err, ErrInvalidStatusTransition) {
		t.Fatalf("expected ErrInvalidStatusTransition reactivating revoked credential, got %v", err)
	}
	if _, _, err := h.svc.SuspendCredential(statusAuth, "idem-suspend-revoked", credID, StatusChangeInput{ReasonCode: "review"}); !errors.Is(err, ErrInvalidStatusTransition) {
		t.Fatalf("expected ErrInvalidStatusTransition suspending revoked credential, got %v", err)
	}

	report, err = verifier.Verify(vcJWT)
	if err != nil || report.TechnicalResult != verification.Invalid || !hasFailedStatusCheck(report, verification.CodeStatusRevoked) {
		t.Fatalf("expected Invalid with status.revoked, got %+v err=%v", report, err)
	}
}

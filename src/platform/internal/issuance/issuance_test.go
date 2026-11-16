package issuance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"hukid.local/platform/internal/verification"
)

const (
	testIssuerURI = "https://issuer.hukid.pe/unas"
	testKID       = "unas-lab-key-2026-01"
	testAudience  = "https://verifier.hukid.pe/events"
)

func mustGenerateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return key
}

func buildTestVP(t *testing.T, holderKey *ecdsa.PrivateKey, vcJWT, aud, nonce string) string {
	t.Helper()
	jwk, err := ExportPublicJWK(&holderKey.PublicKey, "")
	if err != nil {
		t.Fatalf("export holder JWK: %v", err)
	}
	header := map[string]any{
		"alg": "ES256",
		"typ": "vp+jwt",
		"cty": "vp",
		"jwk": jwk,
	}
	payload := map[string]any{
		"@context": []string{VCDMBaseContext, "https://schemas.hukid.pe/contexts/presentation/v1"},
		"type":     []string{"VerifiablePresentation"},
		"aud":      aud,
		"nonce":    nonce,
		"verifiableCredential": []map[string]any{
			{
				"@context": VCDMBaseContext,
				"type":     "EnvelopedVerifiableCredential",
				"id":       "data:application/vc+jwt," + vcJWT,
			},
		},
	}
	hBytes, _ := json.Marshal(header)
	pBytes, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(hBytes) + "." + base64.RawURLEncoding.EncodeToString(pBytes)

	digest := sha256.Sum256([]byte(signingInput))
	der, err := ecdsa.SignASN1(rand.Reader, holderKey, digest[:])
	if err != nil {
		t.Fatalf("sign vp: %v", err)
	}
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		t.Fatalf("unmarshal vp sig: %v", err)
	}
	raw := make([]byte, 64)
	sig.R.FillBytes(raw[:32])
	sig.S.FillBytes(raw[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(raw)
}

func newLabVerifier(t *testing.T, signer Signer) *verification.Verifier {
	t.Helper()
	now := time.Date(2026, 11, 16, 17, 30, 0, 0, time.UTC)
	resolver := verification.NewMemoryKeyResolver()
	if err := resolver.Add(signer.Issuer(), signer.KeyID(), signer.PublicKey()); err != nil {
		t.Fatalf("add issuer key: %v", err)
	}
	v, err := verification.NewVerifier(
		resolver,
		verification.ClockFunc(func() time.Time { return now }),
		verification.DefaultLimits,
		verification.DefaultClockSkew,
	)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return v.
		WithCredentialContexts(ReceiptContext, CertificateContext).
		WithReplayStore(verification.NewMemoryReplayStore())
}

func TestPhase0EndToEndReceiptAndCertificate(t *testing.T) {
	now := time.Date(2026, 11, 16, 17, 30, 0, 0, time.UTC)
	issuerKey := mustGenerateKey(t)
	signer, err := NewMemorySigner(testIssuerURI, testKID, issuerKey, nil)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	// Verify static metadata and JWKS shapes.
	jwks, err := signer.JWKS()
	if err != nil || len(jwks.Keys) != 1 || jwks.Keys[0].Kid != testKID || jwks.Keys[0].Crv != "P-256" {
		t.Fatalf("unexpected JWKS: %+v err=%v", jwks, err)
	}
	meta := BuildIssuerMetadata(testIssuerURI, map[string]CredentialConfigurationMetadata{
		ReceiptConfigID: {
			Format:                               CredentialFormat,
			Scope:                                "pe.cpe.receipt",
			CryptographicBindingMethodsSupported: []string{"jwk"},
			CredentialSigningAlgValuesSupported:  []string{"ES256"},
			CredentialDefinition:                 CredentialDefinitionMeta{Type: []string{"VerifiableCredential", ReceiptType}},
			ProofTypesSupported:                  map[string]ProofTypeMetadata{"jwt": {ProofSigningAlgValuesSupported: []string{"ES256"}}},
		},
		CertificateConfigID: {
			Format:                               CredentialFormat,
			Scope:                                "pe.edu.certificate",
			CryptographicBindingMethodsSupported: []string{"jwk"},
			CredentialSigningAlgValuesSupported:  []string{"ES256"},
			CredentialDefinition:                 CredentialDefinitionMeta{Type: []string{"VerifiableCredential", CertificateType}},
			ProofTypesSupported:                  map[string]ProofTypeMetadata{"jwt": {ProofSigningAlgValuesSupported: []string{"ES256"}}},
		},
	})
	if meta.CredentialEndpoint != "https://issuer.hukid.pe/unas/credential" || meta.NonceEndpoint != "https://issuer.hukid.pe/unas/nonce" {
		t.Fatalf("unexpected issuer metadata: %+v", meta)
	}

	offers := NewOfferStore(nil)
	nonces := NewNonceStore(DefaultNonceTTL, nil)
	verifier := newLabVerifier(t, signer)

	validFrom := now.Add(-1 * time.Hour)
	validUntil := now.Add(24 * time.Hour)

	cases := []struct {
		name     string
		configID string
		claims   map[string]any
		build    func(id string, vf time.Time, vu *time.Time, claims map[string]any) (CredentialInput, error)
	}{
		{
			name:     "electronic receipt",
			configID: ReceiptConfigID,
			claims: map[string]any{
				"document": map[string]any{"type": "03", "series": "B001", "number": "00001234", "total": "118.00", "currency": "PEN"},
				"seller":   map[string]any{"taxId": "20123456789", "legalName": "Comercial Ejemplo SAC"},
			},
			build: NewReceiptInput,
		},
		{
			name:     "event attendance certificate",
			configID: CertificateConfigID,
			claims: map[string]any{
				"participantName": "Juan Perez",
				"eventName":       "Demo Day IncubaUNAS 2026",
				"role":            "Participante",
			},
			build: NewCertificateInput,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			holderKey := mustGenerateKey(t)

			// 1. Source system requests an offer.
			offer, err := offers.CreateOffer(testIssuerURI, tc.configID, tc.claims, now, MaxOfferTTL)
			if err != nil {
				t.Fatalf("create offer: %v", err)
			}
			code := offer.Grants[PreAuthorizedGrantType].PreAuthorizedCode

			// 2. Wallet redeems pre-authorized code once.
			record, err := offers.RedeemOffer(code, now.Add(10*time.Second))
			if err != nil {
				t.Fatalf("redeem offer: %v", err)
			}

			// 3. Wallet requests a fresh c_nonce and builds ES256 proof JWT.
			cNonce, err := nonces.IssueNonce(now)
			if err != nil {
				t.Fatalf("issue nonce: %v", err)
			}
			proofJWT, err := BuildHolderProof(holderKey, testIssuerURI, cNonce, now, nil)
			if err != nil {
				t.Fatalf("build proof: %v", err)
			}
			if err := nonces.ConsumeNonce(cNonce, now.Add(time.Second)); err != nil {
				t.Fatalf("consume nonce: %v", err)
			}
			jkt, _, err := VerifyHolderProof(proofJWT, testIssuerURI, cNonce, now.Add(time.Second), DefaultProofSkew)
			if err != nil {
				t.Fatalf("verify holder proof: %v", err)
			}

			// 4. Issuer builds and signs the vc+jwt bound to cnf.jkt.
			input, err := tc.build("urn:uuid:0192e2b0-84a1-7b83-b930-108170281901", validFrom, &validUntil, record.SubjectClaims)
			if err != nil {
				t.Fatalf("build input: %v", err)
			}
			vcJWT, err := IssueVCJWT(signer, input, jkt)
			if err != nil {
				t.Fatalf("issue vc+jwt: %v", err)
			}

			// 5. Verification core validates the issued vc+jwt directly.
			report, err := verifier.Verify(vcJWT)
			if err != nil {
				t.Fatalf("verify vc: %v", err)
			}
			if report.TechnicalResult != verification.Valid {
				t.Fatalf("expected Valid vc report, got %s checks=%+v", report.TechnicalResult, report.Checks)
			}

			// 6. Holder presents the issued vc+jwt inside a vp+jwt and verifier validates binding.
			vp := buildTestVP(t, holderKey, vcJWT, testAudience, "vp-nonce-"+tc.configID)
			presReport, err := verifier.VerifyPresentation(
				verification.Response{VP: vp, State: "state-" + tc.configID},
				verification.Request{Audience: testAudience, Nonce: "vp-nonce-" + tc.configID, State: "state-" + tc.configID},
			)
			if err != nil {
				t.Fatalf("verify presentation: %v", err)
			}
			if presReport.TechnicalResult != verification.Valid {
				t.Fatalf("expected Valid presentation report, got %s checks=%+v creds=%+v", presReport.TechnicalResult, presReport.Checks, presReport.Credentials)
			}
		})
	}
}

func TestNegativeTamperedSignature(t *testing.T) {
	now := time.Date(2026, 11, 16, 17, 30, 0, 0, time.UTC)
	signer, err := NewMemorySigner(testIssuerURI, testKID, mustGenerateKey(t), nil)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	holderKey := mustGenerateKey(t)
	jkt, err := verification.JWKThumbprint(&holderKey.PublicKey)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	vu := now.Add(24 * time.Hour)
	input, err := NewCertificateInput("urn:uuid:1", now.Add(-time.Hour), &vu, map[string]any{"name": "Ana"})
	if err != nil {
		t.Fatalf("input: %v", err)
	}
	vcJWT, err := IssueVCJWT(signer, input, jkt)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	parts := strings.Split(vcJWT, ".")
	sigBytes, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sigBytes[0] ^= 0xff
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sigBytes)

	verifier := newLabVerifier(t, signer)
	report, err := verifier.Verify(tampered)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.TechnicalResult != verification.Invalid {
		t.Fatalf("expected Invalid for tampered signature, got %s", report.TechnicalResult)
	}
	var gotSigCode verification.Code
	for _, c := range report.Checks {
		if c.Name == verification.CheckSignature {
			gotSigCode = c.Code
		}
	}
	if gotSigCode != verification.CodeSignatureInvalid {
		t.Fatalf("expected %s, got %s", verification.CodeSignatureInvalid, gotSigCode)
	}
}

func TestNegativeNonceValidation(t *testing.T) {
	now := time.Date(2026, 11, 16, 17, 30, 0, 0, time.UTC)
	holderKey := mustGenerateKey(t)
	nonces := NewNonceStore(DefaultNonceTTL, nil)

	cNonce, err := nonces.IssueNonce(now)
	if err != nil {
		t.Fatalf("issue nonce: %v", err)
	}
	proof, err := BuildHolderProof(holderKey, testIssuerURI, cNonce, now, nil)
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}

	// Wrong nonce rejected by proof check.
	if _, _, err := VerifyHolderProof(proof, testIssuerURI, "wrong-nonce", now, DefaultProofSkew); !errors.Is(err, ErrProofInvalid) {
		t.Fatalf("expected ErrProofInvalid for wrong nonce, got %v", err)
	}

	// First consume succeeds; replay fails.
	if err := nonces.ConsumeNonce(cNonce, now.Add(time.Second)); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if err := nonces.ConsumeNonce(cNonce, now.Add(2*time.Second)); !errors.Is(err, ErrNonceInvalid) {
		t.Fatalf("expected ErrNonceInvalid on replay, got %v", err)
	}

	// Expired nonce fails.
	expNonce, err := nonces.IssueNonce(now)
	if err != nil {
		t.Fatalf("issue expiring nonce: %v", err)
	}
	if err := nonces.ConsumeNonce(expNonce, now.Add(DefaultNonceTTL)); !errors.Is(err, ErrNonceInvalid) {
		t.Fatalf("expected ErrNonceInvalid on expiry, got %v", err)
	}
}

func TestNegativeOfferReplayAndExpiry(t *testing.T) {
	now := time.Date(2026, 11, 16, 17, 30, 0, 0, time.UTC)
	offers := NewOfferStore(nil)
	claims := map[string]any{"name": "Juan"}

	// TTL > 5 minutes rejected by profile §7.1.
	if _, err := offers.CreateOffer(testIssuerURI, CertificateConfigID, claims, now, MaxOfferTTL+time.Second); !errors.Is(err, ErrOfferInvalid) {
		t.Fatalf("expected ErrOfferInvalid for TTL > MaxOfferTTL, got %v", err)
	}

	offer, err := offers.CreateOffer(testIssuerURI, CertificateConfigID, claims, now, MaxOfferTTL)
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}
	code := offer.Grants[PreAuthorizedGrantType].PreAuthorizedCode

	// First redeem succeeds; second (replay) fails.
	if _, err := offers.RedeemOffer(code, now.Add(time.Second)); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if _, err := offers.RedeemOffer(code, now.Add(2*time.Second)); !errors.Is(err, ErrOfferInvalid) {
		t.Fatalf("expected ErrOfferInvalid on offer replay, got %v", err)
	}

	// Expired offer fails at exact expiry boundary.
	expOffer, err := offers.CreateOffer(testIssuerURI, CertificateConfigID, claims, now, time.Minute)
	if err != nil {
		t.Fatalf("create expiring offer: %v", err)
	}
	expCode := expOffer.Grants[PreAuthorizedGrantType].PreAuthorizedCode
	if _, err := offers.RedeemOffer(expCode, now.Add(time.Minute)); !errors.Is(err, ErrOfferInvalid) {
		t.Fatalf("expected ErrOfferInvalid on expired offer, got %v", err)
	}
}

func TestNegativeIssuerAndAudience(t *testing.T) {
	now := time.Date(2026, 11, 16, 17, 30, 0, 0, time.UTC)
	issuerKey := mustGenerateKey(t)

	invalidIssuers := []string{
		"",
		"http://issuer.hukid.pe/unas",
		"https://evil.example/unas",
		"https://issuer.hukid.pe/unas/extra",
		"https://issuer.hukid.pe/UNAS",
		"https://issuer.hukid.pe/unas?x=1",
		"https://issuer.hukid.pe/unas#frag",
	}
	for _, bad := range invalidIssuers {
		if _, err := NewMemorySigner(bad, testKID, issuerKey, nil); !errors.Is(err, ErrInvalidIssuerConfig) {
			t.Errorf("issuer %q: expected ErrInvalidIssuerConfig, got %v", bad, err)
		}
	}

	// Wrong audience in holder proof is rejected.
	holderKey := mustGenerateKey(t)
	proof, err := BuildHolderProof(holderKey, "https://issuer.hukid.pe/other", "nonce-1", now, nil)
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}
	if _, _, err := VerifyHolderProof(proof, testIssuerURI, "nonce-1", now, DefaultProofSkew); !errors.Is(err, ErrProofInvalid) {
		t.Fatalf("expected ErrProofInvalid for wrong issuer audience, got %v", err)
	}

	// Issued VC verified under a resolver belonging to another issuer fails with CodeKeyIssuerMismatch.
	signer, err := NewMemorySigner(testIssuerURI, testKID, issuerKey, nil)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	jkt, _ := verification.JWKThumbprint(&holderKey.PublicKey)
	vu := now.Add(24 * time.Hour)
	input, _ := NewCertificateInput("urn:uuid:2", now.Add(-time.Hour), &vu, map[string]any{"name": "Luis"})
	vcJWT, err := IssueVCJWT(signer, input, jkt)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	otherResolver := verification.NewMemoryKeyResolver()
	_ = otherResolver.Add("https://issuer.hukid.pe/other", testKID, signer.PublicKey())
	otherVerifier, err := verification.NewVerifier(
		otherResolver,
		verification.ClockFunc(func() time.Time { return now }),
		verification.DefaultLimits,
		verification.DefaultClockSkew,
	)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	otherVerifier = otherVerifier.WithCredentialContexts(CertificateContext)
	report, err := otherVerifier.Verify(vcJWT)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.TechnicalResult != verification.Invalid {
		t.Fatalf("expected Invalid for wrong issuer, got %s", report.TechnicalResult)
	}
	var keyCode verification.Code
	for _, c := range report.Checks {
		if c.Name == verification.CheckIssuerKey {
			keyCode = c.Code
		}
	}
	if keyCode != verification.CodeKeyIssuerMismatch {
		t.Fatalf("expected %s, got %s", verification.CodeKeyIssuerMismatch, keyCode)
	}
}

func TestNegativeHolderBindingMismatch(t *testing.T) {
	now := time.Date(2026, 11, 16, 17, 30, 0, 0, time.UTC)
	signer, err := NewMemorySigner(testIssuerURI, testKID, mustGenerateKey(t), nil)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	legitHolder := mustGenerateKey(t)
	attackerHolder := mustGenerateKey(t)

	jkt, err := verification.JWKThumbprint(&legitHolder.PublicKey)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	vu := now.Add(24 * time.Hour)
	input, err := NewCertificateInput("urn:uuid:3", now.Add(-time.Hour), &vu, map[string]any{"name": "Maria"})
	if err != nil {
		t.Fatalf("input: %v", err)
	}
	vcJWT, err := IssueVCJWT(signer, input, jkt)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Attacker presents the legitimate credential signed with attackerHolder key.
	vp := buildTestVP(t, attackerHolder, vcJWT, testAudience, "nonce-bind")
	verifier := newLabVerifier(t, signer)
	report, err := verifier.VerifyPresentation(
		verification.Response{VP: vp, State: "state-bind"},
		verification.Request{Audience: testAudience, Nonce: "nonce-bind", State: "state-bind"},
	)
	if err != nil {
		t.Fatalf("verify presentation: %v", err)
	}
	if report.TechnicalResult != verification.Invalid {
		t.Fatalf("expected Invalid for mismatched holder binding, got %s", report.TechnicalResult)
	}
	var bindCode verification.Code
	for _, c := range report.Checks {
		if c.Name == verification.CheckHolderBinding {
			bindCode = c.Code
		}
	}
	if bindCode != verification.CodeBindingMismatch {
		t.Fatalf("expected %s, got %s", verification.CodeBindingMismatch, bindCode)
	}
}

func TestNegativeProofValidation(t *testing.T) {
	now := time.Date(2026, 11, 16, 17, 30, 0, 0, time.UTC)
	holderKey := mustGenerateKey(t)
	jwk, _ := ExportPublicJWK(&holderKey.PublicKey, "")

	signRaw := func(headerJSON, payloadJSON string) string {
		input := base64.RawURLEncoding.EncodeToString([]byte(headerJSON)) + "." +
			base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
		digest := sha256.Sum256([]byte(input))
		der, _ := ecdsa.SignASN1(rand.Reader, holderKey, digest[:])
		var sig struct{ R, S *big.Int }
		_, _ = asn1.Unmarshal(der, &sig)
		raw := make([]byte, 64)
		sig.R.FillBytes(raw[:32])
		sig.S.FillBytes(raw[32:])
		return input + "." + base64.RawURLEncoding.EncodeToString(raw)
	}

	jwkWithPrivate := map[string]any{"kty": jwk.Kty, "crv": jwk.Crv, "x": jwk.X, "y": jwk.Y, "d": "secret"}
	privHeader, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": ProofJWTType, "jwk": jwkWithPrivate})
	goodPayload, _ := json.Marshal(map[string]any{"aud": testIssuerURI, "nonce": "n1", "iat": now.Unix()})
	if _, _, err := VerifyHolderProof(signRaw(string(privHeader), string(goodPayload)), testIssuerURI, "n1", now, DefaultProofSkew); !errors.Is(err, ErrProofInvalid) {
		t.Fatalf("expected ErrProofInvalid for private jwk member, got %v", err)
	}

	jwkBytes, _ := json.Marshal(jwk)
	goodHeader := `{"alg":"ES256","typ":"openid4vci-proof+jwt","jwk":` + string(jwkBytes) + `}`
	dupPayload := `{"aud":"` + testIssuerURI + `","aud":"other","nonce":"n1","iat":` + jsonInt(now.Unix()) + `}`
	if _, _, err := VerifyHolderProof(signRaw(goodHeader, dupPayload), testIssuerURI, "n1", now, DefaultProofSkew); !errors.Is(err, ErrProofInvalid) {
		t.Fatalf("expected ErrProofInvalid for duplicate JSON key, got %v", err)
	}

	// Expired proof iat.
	staleProof, err := BuildHolderProof(holderKey, testIssuerURI, "n1", now.Add(-MaxProofAge-DefaultProofSkew-time.Second), nil)
	if err != nil {
		t.Fatalf("build stale proof: %v", err)
	}
	if _, _, err := VerifyHolderProof(staleProof, testIssuerURI, "n1", now, DefaultProofSkew); !errors.Is(err, ErrProofInvalid) {
		t.Fatalf("expected ErrProofInvalid for stale iat, got %v", err)
	}
}

func jsonInt(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestIsolatedCryptographyPrimitives(t *testing.T) {
	// 1. Export P-256 public key to JWK and reconstruct via stdlib ParseUncompressedPublicKey.
	priv := mustGenerateKey(t)
	jwk, err := ExportPublicJWK(&priv.PublicKey, testKID)
	if err != nil {
		t.Fatalf("export JWK: %v", err)
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.Alg != "ES256" || jwk.Use != "sig" || jwk.Kid != testKID {
		t.Fatalf("unexpected JWK fields: %+v", jwk)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || len(xBytes) != 32 {
		t.Fatalf("expected 32-byte X coordinate, got len=%d err=%v", len(xBytes), err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil || len(yBytes) != 32 {
		t.Fatalf("expected 32-byte Y coordinate, got len=%d err=%v", len(yBytes), err)
	}
	uncompressed := append(append([]byte{0x04}, xBytes...), yBytes...)
	reconstructed, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil || !reconstructed.Equal(&priv.PublicKey) {
		t.Fatalf("reconstructed key mismatch: err=%v", err)
	}

	// 2. Sign raw 64-byte ES256 (R || S) via MemorySigner and verify directly with stdlib ecdsa.VerifyASN1.
	signer, err := NewMemorySigner(testIssuerURI, testKID, priv, nil)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	signingInput := "eyJhbGciOiJFUzI1NiJ9.eyJpc3N1ZXIiOiJodWtpZCJ9"
	rawSig, err := signer.Sign(signingInput)
	if err != nil || len(rawSig) != 64 {
		t.Fatalf("expected 64-byte raw signature, got len=%d err=%v", len(rawSig), err)
	}
	r := new(big.Int).SetBytes(rawSig[:32])
	s := new(big.Int).SetBytes(rawSig[32:])
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatalf("marshal DER: %v", err)
	}
	digest := sha256.Sum256([]byte(signingInput))
	if !ecdsa.VerifyASN1(reconstructed, digest[:], der) {
		t.Fatal("stdlib ecdsa.VerifyASN1 failed on MemorySigner signature")
	}

	// 3. Deterministic RFC 7638 thumbprint and 1-bit mutation invalidation.
	jkt1, err := verification.JWKThumbprint(&priv.PublicKey)
	if err != nil || len(jkt1) != 43 {
		t.Fatalf("unexpected thumbprint %q err=%v", jkt1, err)
	}
	jkt2, err := verification.JWKThumbprint(reconstructed)
	if err != nil || jkt1 != jkt2 {
		t.Fatalf("thumbprint not deterministic: %q vs %q (err=%v)", jkt1, jkt2, err)
	}

	// 1-bit flip in signingInput must fail verification.
	mutatedInput := []byte(signingInput)
	mutatedInput[len(mutatedInput)-1] ^= 0x01
	mutatedDigest := sha256.Sum256(mutatedInput)
	if ecdsa.VerifyASN1(reconstructed, mutatedDigest[:], der) {
		t.Fatal("expected signature verification to fail on 1-bit payload mutation")
	}

	// 1-bit flip in raw signature must fail verification.
	mutatedSig := append([]byte(nil), rawSig...)
	mutatedSig[0] ^= 0x01
	mutatedDER, err := asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(mutatedSig[:32]),
		new(big.Int).SetBytes(mutatedSig[32:]),
	})
	if err == nil && ecdsa.VerifyASN1(reconstructed, digest[:], mutatedDER) {
		t.Fatal("expected signature verification to fail on 1-bit signature mutation")
	}
}

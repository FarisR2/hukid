package oid4vcihttp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"hukid.local/platform/internal/adapters/oid4vphttp"
	"hukid.local/platform/internal/issuance"
	"hukid.local/platform/internal/oid4vp"
	"hukid.local/platform/internal/verification"
)

type httpTestEnv struct {
	now     time.Time
	mux     *http.ServeMux
	service *issuance.Service
	ring    *issuance.KeyRing
	clients *issuance.ClientRegistry
	defs    *issuance.DefinitionRegistry
	audit   *issuance.AuditLog
}

func setupHTTPTestEnv(t *testing.T) *httpTestEnv {
	t.Helper()
	now := time.Date(2026, 11, 16, 19, 30, 0, 0, time.UTC)
	audit := issuance.NewAuditLog(nil)
	clients := issuance.NewClientRegistry(audit)
	defs := issuance.NewDefinitionRegistry(audit)

	issuerRec, err := issuance.NewIssuerRecord("tenant-unas", "iss_unas", "unas", "IncubaUNAS", now)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	ring, err := issuance.NewKeyRing("tenant-unas", issuerRec.IssuerURI, audit)
	if err != nil {
		t.Fatalf("new keyring: %v", err)
	}
	if err := ring.RegisterKey("unas-key-1", mustKey(t), "admin-1", "cor-1", now); err != nil {
		t.Fatalf("register key: %v", err)
	}

	def := issuance.Definition{
		TenantID:        "tenant-unas",
		IssuerID:        "iss_unas",
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
	if err := defs.CreateDraft(def, "admin-1", "cor-2", now); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	if _, err := defs.Publish("tenant-unas", "iss_unas", def.ID, def.Version, "admin-1", "cor-3", now); err != nil {
		t.Fatalf("publish def: %v", err)
	}

	if err := clients.RegisterClient(
		"tenant-unas",
		"cli_events",
		"Events Outbound Adapter",
		"events-client-secret-0123456789abcdef",
		[]string{"iss_unas"},
		[]string{issuance.ScopeIssuanceCreate, issuance.ScopeIssuanceRead},
		nil,
		"admin-1",
		"cor-4",
		now,
	); err != nil {
		t.Fatalf("register client: %v", err)
	}

	claimsKey := make([]byte, 32)
	if _, err := rand.Read(claimsKey); err != nil {
		t.Fatalf("claims key: %v", err)
	}
	svc, err := issuance.NewService(issuance.ServiceConfig{
		ClaimsKey:           claimsKey,
		ClaimsKeyVersion:    "lab-1",
		Clients:             clients,
		Definitions:         defs,
		Audit:               audit,
		AuthorizationServer: "https://auth.hukid.pe",
		Now:                 func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	if err := svc.RegisterIssuer(issuerRec, ring); err != nil {
		t.Fatalf("register issuer: %v", err)
	}

	mux := http.NewServeMux()
	(&Handler{Catalog: svc}).Routes(mux)
	(&IssuanceHandler{Service: svc}).Routes(mux)

	return &httpTestEnv{
		now:     now,
		mux:     mux,
		service: svc,
		ring:    ring,
		clients: clients,
		defs:    defs,
		audit:   audit,
	}
}

func buildTestVPToken(t *testing.T, holderKey *ecdsa.PrivateKey, vcJWT, aud, nonce string) string {
	t.Helper()
	jwk, err := issuance.ExportPublicJWK(&holderKey.PublicKey, "")
	if err != nil {
		t.Fatalf("export holder JWK: %v", err)
	}
	header := map[string]any{"alg": "ES256", "typ": "vp+jwt", "cty": "vp", "jwk": jwk}
	payload := map[string]any{
		"@context": []string{issuance.VCDMBaseContext, "https://schemas.hukid.pe/contexts/presentation/v1"},
		"type":     []string{"VerifiablePresentation"},
		"aud":      aud,
		"nonce":    nonce,
		"verifiableCredential": []map[string]any{
			{"@context": issuance.VCDMBaseContext, "type": "EnvelopedVerifiableCredential", "id": "data:application/vc+jwt," + vcJWT},
		},
	}
	hB, _ := json.Marshal(header)
	pB, _ := json.Marshal(payload)
	input := base64.RawURLEncoding.EncodeToString(hB) + "." + base64.RawURLEncoding.EncodeToString(pB)
	digest := sha256.Sum256([]byte(input))
	der, err := ecdsa.SignASN1(rand.Reader, holderKey, digest[:])
	if err != nil {
		t.Fatalf("sign vp: %v", err)
	}
	var sig struct{ R, S *big.Int }
	_, _ = asn1.Unmarshal(der, &sig)
	raw := make([]byte, 64)
	sig.R.FillBytes(raw[:32])
	sig.S.FillBytes(raw[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(raw)
}

type captureResults struct {
	reports []verification.PresentationReport
}

func (c *captureResults) Deliver(_ string, report verification.PresentationReport) error {
	c.reports = append(c.reports, report)
	return nil
}

func TestEndToEndHTTPFlowEventsToOID4VCIAndOID4VPVerifier(t *testing.T) {
	env := setupHTTPTestEnv(t)

	// 1. Events adapter obtains an M2M integration token via POST /oauth2/token.
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"cli_events"},
		"client_secret": {"events-client-secret-0123456789abcdef"},
		"scope":         {"issuance:create issuance:read"},
	}
	tokReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRec := httptest.NewRecorder()
	env.mux.ServeHTTP(tokRec, tokReq)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("client_credentials token failed: %d %s", tokRec.Code, tokRec.Body.String())
	}
	var eventsToken issuance.TokenResponse
	if err := json.Unmarshal(tokRec.Body.Bytes(), &eventsToken); err != nil || eventsToken.AccessToken == "" {
		t.Fatalf("decode events token: %v %+v", err, eventsToken)
	}

	// 2. Events calls POST /v1/issuance-requests with Idempotency-Key.
	reqBody := `{
		"issuerId": "iss_unas",
		"credentialDefinition": "unas-certificate@1.0.0",
		"claims": {
			"participantName": "Juan Perez",
			"eventName": "Demo Day IncubaUNAS 2026",
			"role": "Participante"
		},
		"source": {"system": "events", "reference": "cert_2026_001"}
	}`
	createReq := httptest.NewRequest(http.MethodPost, "/v1/issuance-requests", strings.NewReader(reqBody))
	createReq.Header.Set("Authorization", "Bearer "+eventsToken.AccessToken)
	createReq.Header.Set("Idempotency-Key", "events-cert-2026-001")
	createReq.Header.Set("Content-Type", "application/json")
	createRec := httptest.NewRecorder()
	env.mux.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create issuance request failed: %d %s", createRec.Code, createRec.Body.String())
	}
	var created issuance.IssuanceRequestResult
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if createRec.Header().Get("Location") != "/v1/issuance-requests/"+created.ID {
		t.Fatalf("unexpected Location header: %q", createRec.Header().Get("Location"))
	}
	if created.OfferState != "ready" || created.IssuanceState != "prepared" {
		t.Fatalf("unexpected created states: %+v", created)
	}

	// 3. Idempotent replay returns 200 OK with the exact same result; different payload returns 409.
	replayReq := httptest.NewRequest(http.MethodPost, "/v1/issuance-requests", strings.NewReader(reqBody))
	replayReq.Header.Set("Authorization", "Bearer "+eventsToken.AccessToken)
	replayReq.Header.Set("Idempotency-Key", "events-cert-2026-001")
	replayReq.Header.Set("Content-Type", "application/json")
	replayRec := httptest.NewRecorder()
	env.mux.ServeHTTP(replayRec, replayReq)
	if replayRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on idempotent replay, got %d %s", replayRec.Code, replayRec.Body.String())
	}

	conflictBody := `{"issuerId":"iss_unas","credentialDefinition":"unas-certificate@1.0.0","claims":{"participantName":"Other","eventName":"Demo Day"}}`
	conflictReq := httptest.NewRequest(http.MethodPost, "/v1/issuance-requests", strings.NewReader(conflictBody))
	conflictReq.Header.Set("Authorization", "Bearer "+eventsToken.AccessToken)
	conflictReq.Header.Set("Idempotency-Key", "events-cert-2026-001")
	conflictReq.Header.Set("Content-Type", "application/json")
	conflictRec := httptest.NewRecorder()
	env.mux.ServeHTTP(conflictRec, conflictReq)
	if conflictRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 on idempotency conflict, got %d %s", conflictRec.Code, conflictRec.Body.String())
	}

	// 4. Wallet parses the QR offer URI and discovers metadata + AS + JWKS.
	offerLaunch, err := url.Parse(created.CredentialOfferURI)
	if err != nil || offerLaunch.Scheme != "openid-credential-offer" {
		t.Fatalf("invalid offer URI: %q err=%v", created.CredentialOfferURI, err)
	}
	offerURL, err := url.Parse(offerLaunch.Query().Get("credential_offer_uri"))
	if err != nil {
		t.Fatalf("invalid credential_offer_uri: %v", err)
	}

	asRec := httptest.NewRecorder()
	env.mux.ServeHTTP(asRec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	if asRec.Code != http.StatusOK {
		t.Fatalf("AS metadata failed: %d", asRec.Code)
	}
	var asMeta issuance.AuthorizationServerMetadata
	if err := json.Unmarshal(asRec.Body.Bytes(), &asMeta); err != nil || !asMeta.PreAuthorizedGrantAnonymousAccessSupp {
		t.Fatalf("unexpected AS metadata: %+v err=%v", asMeta, err)
	}

	metaRec := httptest.NewRecorder()
	env.mux.ServeHTTP(metaRec, httptest.NewRequest(http.MethodGet, "/unas/.well-known/openid-credential-issuer", nil))
	if metaRec.Code != http.StatusOK {
		t.Fatalf("issuer metadata failed: %d", metaRec.Code)
	}

	offerRec := httptest.NewRecorder()
	env.mux.ServeHTTP(offerRec, httptest.NewRequest(http.MethodGet, offerURL.Path, nil))
	if offerRec.Code != http.StatusOK {
		t.Fatalf("resolve offer failed: %d %s", offerRec.Code, offerRec.Body.String())
	}
	var offer issuance.CredentialOffer
	if err := json.Unmarshal(offerRec.Body.Bytes(), &offer); err != nil {
		t.Fatalf("decode offer: %v", err)
	}
	preCode := offer.Grants[issuance.PreAuthorizedGrantType].PreAuthorizedCode

	// 5. Wallet redeems pre-authorized_code once at /oauth2/token.
	redeemForm := url.Values{
		"grant_type":          {issuance.PreAuthorizedGrantType},
		"pre-authorized_code": {preCode},
	}
	vciTokReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(redeemForm.Encode()))
	vciTokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	vciTokRec := httptest.NewRecorder()
	env.mux.ServeHTTP(vciTokRec, vciTokReq)
	if vciTokRec.Code != http.StatusOK {
		t.Fatalf("pre-authorized token failed: %d %s", vciTokRec.Code, vciTokRec.Body.String())
	}
	var vciTok issuance.TokenResponse
	if err := json.Unmarshal(vciTokRec.Body.Bytes(), &vciTok); err != nil || len(vciTok.AuthorizationDetails) != 1 {
		t.Fatalf("decode vci token: %v %+v", err, vciTok)
	}
	credID := vciTok.AuthorizationDetails[0].CredentialIdentifiers[0]

	// 6. Wallet gets fresh c_nonce, signs proof JWT with P-256 holder key, requests vc+jwt.
	nonceRec := httptest.NewRecorder()
	env.mux.ServeHTTP(nonceRec, httptest.NewRequest(http.MethodPost, "/unas/nonce", nil))
	if nonceRec.Code != http.StatusOK {
		t.Fatalf("nonce failed: %d %s", nonceRec.Code, nonceRec.Body.String())
	}
	var nonceBody struct {
		CNonce string `json:"c_nonce"`
	}
	if err := json.Unmarshal(nonceRec.Body.Bytes(), &nonceBody); err != nil || nonceBody.CNonce == "" {
		t.Fatalf("decode nonce: %v %+v", err, nonceBody)
	}

	holderKey := mustKey(t)
	proofJWT, err := issuance.BuildHolderProof(holderKey, "https://issuer.hukid.pe/unas", nonceBody.CNonce, env.now, nil)
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}

	credReqJSON, _ := json.Marshal(map[string]any{
		"credential_identifier": credID,
		"proofs":                map[string]any{"jwt": []string{proofJWT}},
	})
	credReq := httptest.NewRequest(http.MethodPost, "/unas/credential", strings.NewReader(string(credReqJSON)))
	credReq.Header.Set("Authorization", "Bearer "+vciTok.AccessToken)
	credReq.Header.Set("Content-Type", "application/json")
	credRec := httptest.NewRecorder()
	env.mux.ServeHTTP(credRec, credReq)
	if credRec.Code != http.StatusOK {
		t.Fatalf("credential endpoint failed: %d %s", credRec.Code, credRec.Body.String())
	}
	var credResp struct {
		Credentials []struct {
			Credential string `json:"credential"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(credRec.Body.Bytes(), &credResp); err != nil || len(credResp.Credentials) != 1 {
		t.Fatalf("decode credential response: %v %+v", err, credResp)
	}
	vcJWT := credResp.Credentials[0].Credential

	// 7. Events polls GET /v1/issuance-requests/{id} and sees offerState=redeemed, issuanceState=issued.
	pollReq := httptest.NewRequest(http.MethodGet, "/v1/issuance-requests/"+created.ID, nil)
	pollReq.Header.Set("Authorization", "Bearer "+eventsToken.AccessToken)
	pollRec := httptest.NewRecorder()
	env.mux.ServeHTTP(pollRec, pollReq)
	if pollRec.Code != http.StatusOK {
		t.Fatalf("poll request failed: %d %s", pollRec.Code, pollRec.Body.String())
	}
	var polled issuance.IssuanceRequestResult
	_ = json.Unmarshal(pollRec.Body.Bytes(), &polled)
	if polled.OfferState != "redeemed" || polled.IssuanceState != "issued" {
		t.Fatalf("expected redeemed/issued, got %+v", polled)
	}

	// 8. Fetch issuer JWKS over HTTP and verify the issued vc+jwt via OpenID4VP (FEAT-004)!
	jwksRec := httptest.NewRecorder()
	env.mux.ServeHTTP(jwksRec, httptest.NewRequest(http.MethodGet, "/unas/.well-known/jwks.json", nil))
	if jwksRec.Code != http.StatusOK {
		t.Fatalf("jwks failed: %d", jwksRec.Code)
	}
	var jwksDoc issuance.JWKS
	_ = json.Unmarshal(jwksRec.Body.Bytes(), &jwksDoc)
	resolver := resolverFromHTTPJWKS(t, "https://issuer.hukid.pe/unas", jwksDoc)

	verifier, err := verification.NewVerifier(
		resolver,
		verification.ClockFunc(func() time.Time { return env.now }),
		verification.DefaultLimits,
		verification.DefaultClockSkew,
	)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	verifier = verifier.
		WithCredentialContexts(issuance.CertificateContext).
		WithReplayStore(verification.NewMemoryReplayStore())

	// Direct vc+jwt verification.
	vcReport, err := verifier.Verify(vcJWT)
	if err != nil || vcReport.TechnicalResult != verification.Valid {
		t.Fatalf("direct vc verification failed: %+v err=%v", vcReport, err)
	}

	// Full OpenID4VP HTTP presentation round-trip (direct_post.jwt JWE) using oid4vp + oid4vphttp!
	vpSigningKey := mustKey(t)
	sessionStore, err := oid4vp.NewSessionStore(16, func() time.Time { return env.now })
	if err != nil {
		t.Fatalf("new oid4vp session store: %v", err)
	}
	session, err := oid4vp.NewSession(oid4vp.Config{
		ClientID:    "x509_san_dns:verifier.hukid.pe",
		ResponseURI: "https://verifier.hukid.pe/oid4vp/response",
	}, env.now, nil)
	if err != nil {
		t.Fatalf("new oid4vp session: %v", err)
	}
	if err := sessionStore.Put(session); err != nil {
		t.Fatalf("put oid4vp session: %v", err)
	}
	results := &captureResults{}
	vpHandler := &oid4vphttp.Handler{
		Sessions:   sessionStore,
		Verifier:   verifier,
		Results:    results,
		SigningKey: vpSigningKey,
		Now:        func() time.Time { return env.now },
	}
	vpHandler.Routes(env.mux)

	// Wallet fetches signed OID4VP request object.
	vpReqRec := httptest.NewRecorder()
	env.mux.ServeHTTP(vpReqRec, httptest.NewRequest(http.MethodGet, oid4vphttp.RequestPathPrefix+session.State(), nil))
	if vpReqRec.Code != http.StatusOK {
		t.Fatalf("oid4vp request failed: %d %s", vpReqRec.Code, vpReqRec.Body.String())
	}
	signedReqObj, err := jose.ParseSigned(vpReqRec.Body.String(), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse oid4vp request object: %v", err)
	}
	reqPayloadBytes, err := signedReqObj.Verify(&vpSigningKey.PublicKey)
	if err != nil {
		t.Fatalf("verify oid4vp request signature: %v", err)
	}
	var reqClaims struct {
		ClientID       string `json:"client_id"`
		Nonce          string `json:"nonce"`
		State          string `json:"state"`
		ClientMetadata struct {
			JWKS jose.JSONWebKeySet `json:"jwks"`
		} `json:"client_metadata"`
	}
	if err := json.Unmarshal(reqPayloadBytes, &reqClaims); err != nil || len(reqClaims.ClientMetadata.JWKS.Keys) != 1 {
		t.Fatalf("decode oid4vp request claims: %v", err)
	}

	// Wallet creates vp+jwt wrapping the issued vc+jwt, encrypts direct_post.jwt JWE and POSTs it.
	vpJWT := buildTestVPToken(t, holderKey, vcJWT, reqClaims.ClientID, reqClaims.Nonce)
	encKey := reqClaims.ClientMetadata.JWKS.Keys[0]
	plaintext, _ := json.Marshal(map[string]any{
		"vp_token": map[string][]string{"credential": {vpJWT}},
		"state":    reqClaims.State,
	})
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: encKey.Key, KeyID: encKey.KeyID}, nil)
	if err != nil {
		t.Fatalf("new jwe encrypter: %v", err)
	}
	jwe, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt jwe: %v", err)
	}
	compactJWE, _ := jwe.CompactSerialize()

	vpPost := httptest.NewRequest(http.MethodPost, oid4vphttp.ResponsePath, strings.NewReader(url.Values{"response": {compactJWE}}.Encode()))
	vpPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	vpPostRec := httptest.NewRecorder()
	env.mux.ServeHTTP(vpPostRec, vpPost)
	if vpPostRec.Code != http.StatusOK {
		t.Fatalf("oid4vp response failed: %d %s", vpPostRec.Code, vpPostRec.Body.String())
	}
	if len(results.reports) != 1 || results.reports[0].TechnicalResult != verification.Valid {
		t.Fatalf("expected Valid OID4VP presentation report from issued credential, got %+v", results.reports)
	}
}

func TestIssuanceHTTPNegativeAndTokenClassIsolation(t *testing.T) {
	env := setupHTTPTestEnv(t)

	// Register a second tenant/client to verify cross-tenant 404.
	_ = env.clients.RegisterClient(
		"tenant-other", "cli_other", "Other", "other-secret-0123456789abcdef",
		[]string{"iss_other"}, []string{issuance.ScopeIssuanceCreate, issuance.ScopeIssuanceRead},
		nil, "admin-2", "cor-other", env.now,
	)

	tokForm := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"cli_events"},
		"client_secret": {"events-client-secret-0123456789abcdef"},
	}
	tokRec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(tokForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	env.mux.ServeHTTP(tokRec, req)
	var eventsTok issuance.TokenResponse
	_ = json.Unmarshal(tokRec.Body.Bytes(), &eventsTok)

	otherForm := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"cli_other"},
		"client_secret": {"other-secret-0123456789abcdef"},
	}
	otherRec := httptest.NewRecorder()
	otherReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(otherForm.Encode()))
	otherReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	env.mux.ServeHTTP(otherRec, otherReq)
	var otherTok issuance.TokenResponse
	_ = json.Unmarshal(otherRec.Body.Bytes(), &otherTok)

	// Missing Idempotency-Key -> 400.
	noIdem := httptest.NewRequest(http.MethodPost, "/v1/issuance-requests", strings.NewReader(`{"issuerId":"iss_unas","credentialDefinition":"unas-certificate@1.0.0","claims":{"participantName":"Ana","eventName":"X"}}`))
	noIdem.Header.Set("Authorization", "Bearer "+eventsTok.AccessToken)
	noIdem.Header.Set("Content-Type", "application/json")
	noIdemRec := httptest.NewRecorder()
	env.mux.ServeHTTP(noIdemRec, noIdem)
	if noIdemRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without Idempotency-Key, got %d", noIdemRec.Code)
	}

	// Invalid claims -> 422 application/problem+json.
	badClaims := httptest.NewRequest(http.MethodPost, "/v1/issuance-requests", strings.NewReader(`{"issuerId":"iss_unas","credentialDefinition":"unas-certificate@1.0.0","claims":{"unknown":"x"}}`))
	badClaims.Header.Set("Authorization", "Bearer "+eventsTok.AccessToken)
	badClaims.Header.Set("Idempotency-Key", "bad-claims-key-0001")
	badClaims.Header.Set("Content-Type", "application/json")
	badClaimsRec := httptest.NewRecorder()
	env.mux.ServeHTTP(badClaimsRec, badClaims)
	if badClaimsRec.Code != http.StatusUnprocessableEntity || badClaimsRec.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("expected 422 problem+json for bad claims, got %d %q", badClaimsRec.Code, badClaimsRec.Header().Get("Content-Type"))
	}

	// Create valid request for isolation tests.
	goodReq := httptest.NewRequest(http.MethodPost, "/v1/issuance-requests", strings.NewReader(`{"issuerId":"iss_unas","credentialDefinition":"unas-certificate@1.0.0","claims":{"participantName":"Ana","eventName":"Demo"}}`))
	goodReq.Header.Set("Authorization", "Bearer "+eventsTok.AccessToken)
	goodReq.Header.Set("Idempotency-Key", "good-key-0000000001")
	goodReq.Header.Set("Content-Type", "application/json")
	goodRec := httptest.NewRecorder()
	env.mux.ServeHTTP(goodRec, goodReq)
	var created issuance.IssuanceRequestResult
	_ = json.Unmarshal(goodRec.Body.Bytes(), &created)

	// Cross-tenant GET returns 404.
	crossGet := httptest.NewRequest(http.MethodGet, "/v1/issuance-requests/"+created.ID, nil)
	crossGet.Header.Set("Authorization", "Bearer "+otherTok.AccessToken)
	crossGetRec := httptest.NewRecorder()
	env.mux.ServeHTTP(crossGetRec, crossGet)
	if crossGetRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 cross-tenant GET, got %d", crossGetRec.Code)
	}

	// Using integration token at /unas/credential is rejected with 401 invalid_token.
	wrongClassCred := httptest.NewRequest(http.MethodPost, "/unas/credential", strings.NewReader(`{"credential_identifier":"x","proofs":{"jwt":["a.b.c"]}}`))
	wrongClassCred.Header.Set("Authorization", "Bearer "+eventsTok.AccessToken)
	wrongClassCred.Header.Set("Content-Type", "application/json")
	wrongClassRec := httptest.NewRecorder()
	env.mux.ServeHTTP(wrongClassRec, wrongClassCred)
	if wrongClassRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when integration token hits /credential, got %d", wrongClassRec.Code)
	}
}

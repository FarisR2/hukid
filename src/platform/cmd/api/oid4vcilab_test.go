package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"hukid.local/platform/internal/bootstrap"
	"hukid.local/platform/internal/issuance"
	"hukid.local/platform/internal/verification"
)

func clearVCILabEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		vciLabFlag, vciLabSlug, vciLabDisplayName, vciLabKID,
		vciLabSigningKey, vciLabCreateKey, vciLabClaimsKey,
		vciLabAuthServer, vciLabClientID, vciLabClientSecret, vciLabDatabaseURL,
	} {
		t.Setenv(k, "")
	}
}

func vciField(t *testing.T, output, name string) string {
	t.Helper()
	prefix := "oid4vci-lab " + name + " "
	for _, line := range strings.Split(output, "\n") {
		if value, ok := strings.CutPrefix(line, prefix); ok {
			return value
		}
	}
	t.Fatalf("missing %q in %q", prefix, output)
	return ""
}

func signVCILabProof(t *testing.T, holder *ecdsa.PrivateKey, aud, nonce string, now time.Time) string {
	t.Helper()
	pubJWK := jose.JSONWebKey{Key: &holder.PublicKey, Algorithm: string(jose.ES256), Use: "sig"}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: holder},
		(&jose.SignerOptions{}).WithType("openid4vci-proof+jwt").WithHeader("jwk", pubJWK),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"aud": aud, "nonce": nonce, "iat": now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func TestVCILabIsOffUnlessConfigured(t *testing.T) {
	clearVCILabEnv(t)
	var out bytes.Buffer
	routes, cleanup, err := configureOID4VCILab(context.Background(), "127.0.0.1:8080", &out, nil)
	if routes != nil || cleanup != nil || err != nil || out.Len() != 0 {
		t.Fatalf("expected nil lab mount when unset, got routes=%v err=%v out=%q", routes != nil, err, out.String())
	}
	handler := bootstrap.Handler()
	for _, path := range []string{"/unas/.well-known/jwks.json", "/.well-known/oauth-authorization-server", "/v1/issuance-requests"} {
		rec := httptest.NewRecorder()
		method := http.MethodGet
		if path == "/v1/issuance-requests" {
			method = http.MethodPost
		}
		handler.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s expected 404 when lab off, got %d", path, rec.Code)
		}
	}
}

func TestVCILabRejectsUnsafeConfiguration(t *testing.T) {
	cases := map[string]map[string]string{
		"flag invalid":             {vciLabFlag: "1"},
		"flag staging":             {vciLabFlag: "staging"},
		"env staging":              {"HUKID_ENV": "staging", vciLabFlag: "local"},
		"env production":           {"HUKID_ENV": "production", vciLabFlag: "local"},
		"env mismatch":             {"HUKID_ENV": "test", vciLabFlag: "local"},
		"reserved slug":            {vciLabFlag: "local", vciLabSlug: "v1"},
		"invalid slug":             {vciLabFlag: "local", vciLabSlug: "UNAS"},
		"missing signing key file": {vciLabFlag: "local", vciLabSigningKey: filepath.Join(t.TempDir(), "missing.pem")},
		"bad claims key":           {vciLabFlag: "local", vciLabClaimsKey: "not-base64"},
		"short secret":             {vciLabFlag: "local", vciLabClientSecret: "too-short"},
		"pg without claims key":    {vciLabFlag: "local", vciLabDatabaseURL: "postgresql://u:p@127.0.0.1:5432/db?sslmode=disable", vciLabSigningKey: filepath.Join(t.TempDir(), "k.pem"), vciLabCreateKey: "1"},
		"pg without signing key":   {vciLabFlag: "local", vciLabDatabaseURL: "postgresql://u:p@127.0.0.1:5432/db?sslmode=disable", vciLabClaimsKey: base64.StdEncoding.EncodeToString(make([]byte, 32))},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			clearVCILabEnv(t)
			t.Setenv("HUKID_ENV", "")
			for k, v := range overrides {
				t.Setenv(k, v)
			}
			var out bytes.Buffer
			if _, cleanup, err := configureOID4VCILab(context.Background(), "127.0.0.1:8080", &out, nil); err == nil {
				if cleanup != nil {
					cleanup()
				}
				t.Fatalf("expected rejection for case %q", name)
			}
		})
	}
}

func TestVCILabPersistentKeyAndDualMountE2E(t *testing.T) {
	clearVCILabEnv(t)
	t.Setenv("HUKID_ENV", "")

	keyPath := filepath.Join(t.TempDir(), "issuer-unas.pem")
	t.Setenv(vciLabFlag, "local")
	t.Setenv(vciLabSigningKey, keyPath)
	t.Setenv(vciLabCreateKey, "1")

	now := time.Date(2026, 11, 16, 22, 0, 0, 0, time.UTC)
	clk := func() time.Time { return now }

	// Boot 1: initializes persistent PEM file on disk.
	var out1 bytes.Buffer
	routes1, cleanup1, err := configureOID4VCILab(context.Background(), "127.0.0.1:8080", &out1, clk)
	if err != nil {
		t.Fatalf("boot 1: %v", err)
	}
	defer cleanup1()
	jwk1 := vciField(t, out1.String(), "public-jwk")
	jwksRec1 := httptest.NewRecorder()
	bootstrap.Handler(routes1).ServeHTTP(jwksRec1, httptest.NewRequest(http.MethodGet, "/unas/.well-known/jwks.json", nil))
	if jwksRec1.Code != http.StatusOK {
		t.Fatalf("boot 1 jwks: %d", jwksRec1.Code)
	}

	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected persistent key file created: %v", err)
	}

	// Boot 2: CREATE_KEY disabled; reloads exact same signing key from disk.
	t.Setenv(vciLabCreateKey, "")
	var out2 bytes.Buffer
	routes2, cleanup2, err := configureOID4VCILab(context.Background(), "127.0.0.1:8080", &out2, clk)
	if err != nil {
		t.Fatalf("boot 2: %v", err)
	}
	defer cleanup2()
	jwk2 := vciField(t, out2.String(), "public-jwk")
	if jwk1 != jwk2 {
		t.Fatalf("signing key changed across restart:\nboot1=%s\nboot2=%s", jwk1, jwk2)
	}
	jwksRec2 := httptest.NewRecorder()
	bootstrap.Handler(routes2).ServeHTTP(jwksRec2, httptest.NewRequest(http.MethodGet, "/unas/.well-known/jwks.json", nil))
	if jwksRec2.Code != http.StatusOK || jwksRec2.Body.String() != jwksRec1.Body.String() {
		t.Fatalf("jwks mismatch across restart:\nboot1=%s\nboot2=%s", jwksRec1.Body.String(), jwksRec2.Body.String())
	}

	// Verify dual mount alongside OID4VP lab has zero route collisions.
	labEnv(t, map[string]string{"HUKID_OID4VP_LAB": "local"})
	var vpOut bytes.Buffer
	vpRoutes, err := configureOID4VPLab(&vpOut, clk)
	if err != nil {
		t.Fatalf("vp lab: %v", err)
	}
	handler := bootstrap.Handler(vpRoutes, routes2)

	// 1. Check metadata & AS discovery.
	asRec := httptest.NewRecorder()
	handler.ServeHTTP(asRec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	if asRec.Code != http.StatusOK || !strings.Contains(asRec.Body.String(), `"http://127.0.0.1:8080/oauth2/token"`) {
		t.Fatalf("AS discovery failed: %d %s", asRec.Code, asRec.Body.String())
	}

	// 2. Obtain M2M bearer token with seeded client credentials.
	clientID := vciField(t, out2.String(), "client-id")
	clientSecret := vciField(t, out2.String(), "client-secret")
	issuerID := vciField(t, out2.String(), "issuer-id")
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {issuance.ScopeIssuanceCreate + " " + issuance.ScopeIssuanceRead},
	}
	tokReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRec := httptest.NewRecorder()
	handler.ServeHTTP(tokRec, tokReq)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("M2M token failed: %d %s", tokRec.Code, tokRec.Body.String())
	}
	var m2m issuance.TokenResponse
	if err := json.Unmarshal(tokRec.Body.Bytes(), &m2m); err != nil {
		t.Fatal(err)
	}

	// 3. Create issuance request via /v1/issuance-requests.
	reqBody, _ := json.Marshal(issuance.IssuanceRequestInput{
		IssuerID:             issuerID,
		CredentialDefinition: "unas-certificate@1.0.0",
		Claims: map[string]any{
			"participantName": "Carlos Mendoza",
			"eventName":       "Jornada Cloud UNAS",
		},
	})
	irReq := httptest.NewRequest(http.MethodPost, "/v1/issuance-requests", bytes.NewReader(reqBody))
	irReq.Header.Set("Content-Type", "application/json")
	irReq.Header.Set("Authorization", "Bearer "+m2m.AccessToken)
	irReq.Header.Set("Idempotency-Key", "cmd-api-lab-e2e-0001")
	irRec := httptest.NewRecorder()
	handler.ServeHTTP(irRec, irReq)
	if irRec.Code != http.StatusCreated {
		t.Fatalf("issuance request failed: %d %s", irRec.Code, irRec.Body.String())
	}
	var created issuance.IssuanceRequestResult
	if err := json.Unmarshal(irRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	offerRef := created.CredentialOfferURI[strings.LastIndex(created.CredentialOfferURI, "ofr_"):]

	// 4. Fetch offer -> redeem pre-authorized code -> fetch nonce -> issue vc+jwt.
	offerRec := httptest.NewRecorder()
	handler.ServeHTTP(offerRec, httptest.NewRequest(http.MethodGet, "/unas/offers/"+offerRef, nil))
	if offerRec.Code != http.StatusOK {
		t.Fatalf("resolve offer failed: %d %s", offerRec.Code, offerRec.Body.String())
	}
	var offer issuance.CredentialOffer
	if err := json.Unmarshal(offerRec.Body.Bytes(), &offer); err != nil {
		t.Fatal(err)
	}
	preCode := offer.Grants[issuance.PreAuthorizedGrantType].PreAuthorizedCode

	redeemForm := url.Values{
		"grant_type":          {issuance.PreAuthorizedGrantType},
		"pre-authorized_code": {preCode},
	}
	redeemReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(redeemForm.Encode()))
	redeemReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	redeemRec := httptest.NewRecorder()
	handler.ServeHTTP(redeemRec, redeemReq)
	if redeemRec.Code != http.StatusOK {
		t.Fatalf("redeem pre-auth failed: %d %s", redeemRec.Code, redeemRec.Body.String())
	}
	var oidTok issuance.TokenResponse
	if err := json.Unmarshal(redeemRec.Body.Bytes(), &oidTok); err != nil {
		t.Fatal(err)
	}

	nonceRec := httptest.NewRecorder()
	handler.ServeHTTP(nonceRec, httptest.NewRequest(http.MethodPost, "/unas/nonce", nil))
	if nonceRec.Code != http.StatusOK {
		t.Fatalf("nonce failed: %d %s", nonceRec.Code, nonceRec.Body.String())
	}
	var nonceBody struct {
		Nonce string `json:"c_nonce"`
	}
	if err := json.Unmarshal(nonceRec.Body.Bytes(), &nonceBody); err != nil {
		t.Fatal(err)
	}

	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credReqBody, _ := json.Marshal(map[string]any{
		"credential_identifier": oidTok.AuthorizationDetails[0].CredentialIdentifiers[0],
		"proofs":                map[string]any{"jwt": []string{signVCILabProof(t, holder, "https://issuer.hukid.pe/unas", nonceBody.Nonce, now)}},
	})
	credReq := httptest.NewRequest(http.MethodPost, "/unas/credential", bytes.NewReader(credReqBody))
	credReq.Header.Set("Content-Type", "application/json")
	credReq.Header.Set("Authorization", "Bearer "+oidTok.AccessToken)
	credRec := httptest.NewRecorder()
	handler.ServeHTTP(credRec, credReq)
	if credRec.Code != http.StatusOK {
		t.Fatalf("credential failed: %d %s", credRec.Code, credRec.Body.String())
	}
	var issuedBody struct {
		Credentials []struct {
			Credential string `json:"credential"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(credRec.Body.Bytes(), &issuedBody); err != nil || len(issuedBody.Credentials) != 1 {
		t.Fatalf("unexpected credential payload: %s", credRec.Body.String())
	}

	// 5. Verify emitted vc+jwt against the public JWKS endpoint.
	jwksRec := httptest.NewRecorder()
	handler.ServeHTTP(jwksRec, httptest.NewRequest(http.MethodGet, "/unas/.well-known/jwks.json", nil))
	if jwksRec.Code != http.StatusOK {
		t.Fatalf("jwks failed: %d", jwksRec.Code)
	}
	var jwksDoc issuance.JWKS
	if err := json.Unmarshal(jwksRec.Body.Bytes(), &jwksDoc); err != nil || len(jwksDoc.Keys) != 1 {
		t.Fatalf("bad jwks: %s", jwksRec.Body.String())
	}
	pub, err := issuance.DecodePublicJWK(jwksDoc.Keys[0])
	if err != nil {
		t.Fatal(err)
	}
	resolver := verification.NewMemoryKeyResolver()
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
	report, err := verifier.Verify(issuedBody.Credentials[0].Credential)
	if err != nil {
		t.Fatal(err)
	}
	if report.TechnicalResult != verification.Valid {
		t.Fatalf("verified vc+jwt expected valid, got %+v", report)
	}
	parts := strings.Split(issuedBody.Credentials[0].Credential, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid compact JWS")
	}
	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Cnf struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(rawPayload, &claims); err != nil || claims.Cnf.JKT != holderJKT {
		t.Fatalf("expected cnf.jkt=%s, got %+v err=%v", holderJKT, claims, err)
	}
}

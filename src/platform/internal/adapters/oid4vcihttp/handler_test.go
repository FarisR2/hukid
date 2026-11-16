package oid4vcihttp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"hukid.local/platform/internal/issuance"
	"hukid.local/platform/internal/verification"
)

type stubCatalog struct {
	rings    map[string]*issuance.KeyRing
	metadata map[string]issuance.IssuerMetadata
}

func (c *stubCatalog) IssuerJWKS(slug string) (issuance.JWKS, bool) {
	ring, ok := c.rings[slug]
	if !ok {
		return issuance.JWKS{}, false
	}
	doc, err := ring.PublicJWKS()
	if err != nil {
		return issuance.JWKS{}, false
	}
	return doc, true
}

func (c *stubCatalog) IssuerMetadata(slug string) (issuance.IssuerMetadata, bool) {
	meta, ok := c.metadata[slug]
	return meta, ok
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

func resolverFromHTTPJWKS(t *testing.T, issuerURI string, jwks issuance.JWKS) *verification.MemoryKeyResolver {
	t.Helper()
	res := verification.NewMemoryKeyResolver()
	for _, k := range jwks.Keys {
		x, errX := base64.RawURLEncoding.DecodeString(k.X)
		y, errY := base64.RawURLEncoding.DecodeString(k.Y)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			t.Fatalf("invalid JWK coordinates in %+v", k)
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{0x04}, x...), y...))
		if err != nil {
			t.Fatalf("parse public key: %v", err)
		}
		if err := res.Add(issuerURI, k.Kid, pub); err != nil {
			t.Fatalf("add key to resolver: %v", err)
		}
	}
	return res
}

func TestDiscoveryAndJWKSHTTPWithKeyRotation(t *testing.T) {
	now := time.Date(2026, 11, 16, 18, 0, 0, 0, time.UTC)
	issuerURI := "https://issuer.hukid.pe/unas"
	audit := issuance.NewAuditLog(nil)

	ring, err := issuance.NewKeyRing("tenant-unas", issuerURI, audit)
	if err != nil {
		t.Fatalf("new keyring: %v", err)
	}
	if err := ring.RegisterKey("key-1", mustKey(t), "admin-1", "cor-1", now); err != nil {
		t.Fatalf("register key-1: %v", err)
	}

	catalog := &stubCatalog{
		rings: map[string]*issuance.KeyRing{"unas": ring},
		metadata: map[string]issuance.IssuerMetadata{
			"unas": issuance.BuildIssuerMetadata(issuerURI, map[string]issuance.CredentialConfigurationMetadata{
				issuance.CertificateConfigID: {
					Format:                               issuance.CredentialFormat,
					Scope:                                "pe.edu.certificate",
					CryptographicBindingMethodsSupported: []string{"jwk"},
					CredentialSigningAlgValuesSupported:  []string{"ES256"},
					CredentialDefinition:                 issuance.CredentialDefinitionMeta{Type: []string{"VerifiableCredential", issuance.CertificateType}},
					ProofTypesSupported:                  map[string]issuance.ProofTypeMetadata{"jwt": {ProofSigningAlgValuesSupported: []string{"ES256"}}},
				},
			}),
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	(&Handler{Catalog: catalog}).Routes(mux)

	// Unrelated /healthz route remains unaffected.
	hw := httptest.NewRecorder()
	mux.ServeHTTP(hw, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if hw.Code != http.StatusNoContent {
		t.Fatalf("expected /healthz 204, got %d", hw.Code)
	}

	// Metadata discovery returns 200 and public cache headers.
	mw := httptest.NewRecorder()
	mux.ServeHTTP(mw, httptest.NewRequest(http.MethodGet, "/unas/.well-known/openid-credential-issuer", nil))
	if mw.Code != http.StatusOK {
		t.Fatalf("expected metadata 200, got %d body=%s", mw.Code, mw.Body.String())
	}
	if mw.Header().Get("Cache-Control") != "public, max-age=300" || mw.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("unexpected headers: %+v", mw.Header())
	}
	var meta issuance.IssuerMetadata
	if err := json.Unmarshal(mw.Body.Bytes(), &meta); err != nil || meta.CredentialIssuer != issuerURI {
		t.Fatalf("invalid metadata JSON: %v %+v", err, meta)
	}

	// Issue vc1 with active key-1, then rotate to key-2 and issue vc2.
	holderKey := mustKey(t)
	jkt, err := verification.JWKThumbprint(&holderKey.PublicKey)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	vu := now.Add(24 * time.Hour)
	s1, _ := ring.ActiveSigner()
	in1, _ := issuance.NewCertificateInput("urn:uuid:1", now.Add(-time.Hour), &vu, map[string]any{"name": "Ana"})
	vc1, err := issuance.IssueVCJWT(s1, in1, jkt)
	if err != nil {
		t.Fatalf("issue vc1: %v", err)
	}

	if err := ring.RotateKey("key-2", mustKey(t), "admin-1", "cor-2", now.Add(time.Minute)); err != nil {
		t.Fatalf("rotate key-2: %v", err)
	}
	s2, _ := ring.ActiveSigner()
	in2, _ := issuance.NewCertificateInput("urn:uuid:2", now.Add(-time.Hour), &vu, map[string]any{"name": "Luis"})
	vc2, err := issuance.IssueVCJWT(s2, in2, jkt)
	if err != nil {
		t.Fatalf("issue vc2: %v", err)
	}

	// GET /unas/.well-known/jwks.json returns both key-1 (retired) and key-2 (active).
	jw := httptest.NewRecorder()
	mux.ServeHTTP(jw, httptest.NewRequest(http.MethodGet, "/unas/.well-known/jwks.json", nil))
	if jw.Code != http.StatusOK {
		t.Fatalf("expected jwks 200, got %d", jw.Code)
	}
	var jwksDoc issuance.JWKS
	if err := json.Unmarshal(jw.Body.Bytes(), &jwksDoc); err != nil || len(jwksDoc.Keys) != 2 {
		t.Fatalf("expected 2 keys in JWKS, got %+v err=%v", jwksDoc, err)
	}

	res := resolverFromHTTPJWKS(t, issuerURI, jwksDoc)
	verifier, err := verification.NewVerifier(res, verification.ClockFunc(func() time.Time { return now }), verification.DefaultLimits, verification.DefaultClockSkew)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	verifier = verifier.WithCredentialContexts(issuance.CertificateContext)
	if r1, err := verifier.Verify(vc1); err != nil || r1.TechnicalResult != verification.Valid {
		t.Fatalf("vc1 from retired key-1 must verify, got %+v err=%v", r1, err)
	}
	if r2, err := verifier.Verify(vc2); err != nil || r2.TechnicalResult != verification.Valid {
		t.Fatalf("vc2 from active key-2 must verify, got %+v err=%v", r2, err)
	}

	// Compromising key-1 removes it from HTTP JWKS; vc1 stops verifying with CodeKeyUnknownKID.
	if err := ring.CompromiseKey("key-1", "sec-1", "cor-3", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("compromise key-1: %v", err)
	}
	jw2 := httptest.NewRecorder()
	mux.ServeHTTP(jw2, httptest.NewRequest(http.MethodGet, "/unas/.well-known/jwks.json", nil))
	var jwksAfter issuance.JWKS
	if err := json.Unmarshal(jw2.Body.Bytes(), &jwksAfter); err != nil || len(jwksAfter.Keys) != 1 || jwksAfter.Keys[0].Kid != "key-2" {
		t.Fatalf("expected only key-2 in JWKS after compromise, got %+v err=%v", jwksAfter, err)
	}

	resAfter := resolverFromHTTPJWKS(t, issuerURI, jwksAfter)
	verifierAfter, _ := verification.NewVerifier(resAfter, verification.ClockFunc(func() time.Time { return now }), verification.DefaultLimits, verification.DefaultClockSkew)
	verifierAfter = verifierAfter.WithCredentialContexts(issuance.CertificateContext)
	r1After, err := verifierAfter.Verify(vc1)
	if err != nil || r1After.TechnicalResult != verification.Invalid {
		t.Fatalf("expected Invalid for compromised key-1 vc1, got %+v err=%v", r1After, err)
	}
	var keyCode verification.Code
	for _, c := range r1After.Checks {
		if c.Name == verification.CheckIssuerKey {
			keyCode = c.Code
		}
	}
	if keyCode != verification.CodeKeyUnknownKID {
		t.Fatalf("expected %s, got %s", verification.CodeKeyUnknownKID, keyCode)
	}
	if r2After, err := verifierAfter.Verify(vc2); err != nil || r2After.TechnicalResult != verification.Valid {
		t.Fatalf("vc2 must remain Valid, got %+v err=%v", r2After, err)
	}
}

func TestNegativeHTTPRequests(t *testing.T) {
	mux := http.NewServeMux()
	(&Handler{Catalog: &stubCatalog{}}).Routes(mux)

	for _, tc := range []struct {
		name   string
		method string
		target string
		want   int
	}{
		{"post jwks", http.MethodPost, "/unas/.well-known/jwks.json", http.StatusMethodNotAllowed},
		{"put metadata", http.MethodPut, "/unas/.well-known/openid-credential-issuer", http.StatusMethodNotAllowed},
		{"unknown slug jwks", http.MethodGet, "/unknown/.well-known/jwks.json", http.StatusNotFound},
		{"unknown slug meta", http.MethodGet, "/unknown/.well-known/openid-credential-issuer", http.StatusNotFound},
		{"uppercase slug", http.MethodGet, "/UNAS/.well-known/jwks.json", http.StatusNotFound},
		{"query string", http.MethodGet, "/unas/.well-known/jwks.json?v=1", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(tc.method, tc.target, nil))
			if w.Code != tc.want {
				t.Fatalf("expected %d, got %d", tc.want, w.Code)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("expected no-store on error, got %q", w.Header().Get("Cache-Control"))
			}
			if tc.want == http.StatusMethodNotAllowed && w.Header().Get("Allow") != http.MethodGet {
				t.Fatalf("expected Allow: GET, got %q", w.Header().Get("Allow"))
			}
		})
	}

	// Nil catalog returns 503.
	nilMux := http.NewServeMux()
	(&Handler{}).Routes(nilMux)
	w := httptest.NewRecorder()
	nilMux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/unas/.well-known/jwks.json", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 with nil catalog, got %d", w.Code)
	}
}

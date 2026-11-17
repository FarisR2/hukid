package verifierhttp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"hukid.local/platform/internal/issuance"
	"hukid.local/platform/internal/verification"
)

func TestResolverFetchesJWKSAndBlocksCrossOriginRedirects(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := issuance.NewMemorySigner("https://issuer.hukid.pe/unas", "unas-k1", priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	jwksDoc, err := signer.JWKS()
	if err != nil {
		t.Fatal(err)
	}

	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwksDoc)
	}))
	defer evil.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/unas/.well-known/jwks.json":
			_ = json.NewEncoder(w).Encode(jwksDoc)
		case "/redirect/.well-known/jwks.json":
			http.Redirect(w, r, evil.URL+"/stolen.json", http.StatusFound)
		case "/unas/status/revocation/sl_1":
			_, _ = w.Write([]byte("eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoxfQ.sig"))
		case "/unas/schemas/unas-certificate/1.0.0.json":
			_, _ = w.Write([]byte(`{"type":"object","additionalProperties":false,"required":["participantName"]}`))
		case "/redirect/schemas/evil.json":
			http.Redirect(w, r, evil.URL+"/evil-schema.json", http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	resolver, err := NewResolver(Config{TransportBase: srv.URL})
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := resolver.ResolveKey("https://issuer.hukid.pe/unas", "unas-k1")
	if err != nil || !resolved.Key.Equal(&priv.PublicKey) || resolved.Issuer != "https://issuer.hukid.pe/unas" {
		t.Fatalf("unexpected resolved key: %+v err=%v", resolved, err)
	}
	if _, err := resolver.ResolveKey("https://issuer.hukid.pe/unas", "missing-kid"); !errors.Is(err, verification.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
	if _, err := resolver.ResolveKey("https://issuer.hukid.pe/redirect", "unas-k1"); !errors.Is(err, verification.ErrKeyResolution) {
		t.Fatalf("expected cross-origin redirect failure, got %v", err)
	}
	listJWT, err := resolver.ResolveStatusList("https://issuer.hukid.pe/unas/status/revocation/sl_1")
	if err != nil || listJWT != "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoxfQ.sig" {
		t.Fatalf("unexpected status list: %q err=%v", listJWT, err)
	}
	schemaBytes, err := resolver.ResolveSchema("https://issuer.hukid.pe/unas/schemas/unas-certificate/1.0.0.json")
	if err != nil || len(schemaBytes) == 0 {
		t.Fatalf("unexpected schema response: %q err=%v", string(schemaBytes), err)
	}
	if _, err := resolver.ResolveSchema("https://issuer.hukid.pe/redirect/schemas/evil.json"); !errors.Is(err, verification.ErrSchemaResolution) {
		t.Fatalf("expected cross-origin redirect failure on schema fetch, got %v", err)
	}
	if _, err := resolver.ResolveSchema("http://evil.example/schemas/x.json"); !errors.Is(err, verification.ErrSchemaResolution) {
		t.Fatalf("expected non-https schema rejection, got %v", err)
	}
}

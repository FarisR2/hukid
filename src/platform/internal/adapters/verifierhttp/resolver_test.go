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
}

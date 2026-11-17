package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hukid.local/platform/internal/adapters/vaultkms"
	"hukid.local/platform/internal/issuance"
)

func clearRuntimeServiceEnv(t *testing.T) {
	t.Helper()
	clearVCILabEnv(t)
	for _, k := range []string{
		"HUKID_ENV",
		envIssuanceDatabaseURL, envIssuanceAuthServer, envIssuanceClaimsKey,
		envIssuanceClaimsKeyCiphertext, envIssuanceClaimsKeyVersion,
		envVaultAddr, envVaultToken, envVaultMount, envVaultNamespace, envVaultKEKName,
		envOID4VPClientID, envOID4VPResponseURI, envOID4VPSigningKey,
		envOID4VPSigningCertPEM, envOID4VPTransportBase,
		labFlag, labClientID, labResponse, labIssuerKeys,
	} {
		t.Setenv(k, "")
	}
}

func TestIssuanceRuntimeConfigValidationAndDEKUnwrap(t *testing.T) {
	clearRuntimeServiceEnv(t)
	if err := validateIssuanceRuntimeConfiguration(); err != nil {
		t.Fatalf("empty config should be inactive: %v", err)
	}

	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	dek := make([]byte, 32)
	_, _ = rand.Read(dek)
	blk, _ := aes.NewCipher(kek)
	aead, _ := cipher.NewGCM(blk)
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	aad := []byte("hukid/claims-dek/v1|prod-k1")
	wrapped := "vault:v1:" + base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, dek, aad))

	vaultSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/transit/decrypt/claims-kek" {
			var req struct {
				Ciphertext string `json:"ciphertext"`
				Context    string `json:"context"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			rawCT, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(req.Ciphertext, "vault:v1:"))
			reqAAD, _ := base64.StdEncoding.DecodeString(req.Context)
			pt, err := aead.Open(nil, rawCT[:aead.NonceSize()], rawCT[aead.NonceSize():], reqAAD)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(pt)}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer vaultSrv.Close()

	// Complete HTTPS production config validates cleanly.
	t.Setenv("HUKID_ENV", "production")
	t.Setenv(envIssuanceDatabaseURL, "postgresql://pg.internal:5432/hukid_prod?sslmode=require")
	t.Setenv(envIssuanceAuthServer, "https://auth.hukid.pe")
	t.Setenv(envIssuanceClaimsKeyCiphertext, wrapped)
	t.Setenv(envIssuanceClaimsKeyVersion, "prod-k1")
	t.Setenv(envVaultAddr, vaultSrv.URL)
	t.Setenv(envVaultToken, "hvs.prod-token")
	t.Setenv(envVaultKEKName, "claims-kek")

	if err := validateIssuanceRuntimeConfiguration(); err != nil {
		t.Fatalf("valid production issuance config failed: %v", err)
	}

	// Verify UnwrapDEK path via vaultkms with TLS client.
	vc, err := vaultkms.NewClient(vaultkms.Config{
		BaseURL:    vaultSrv.URL,
		Token:      "hvs.prod-token",
		HTTPClient: vaultSrv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := vc.UnwrapDEK(context.Background(), "claims-kek", wrapped, string(aad))
	if err != nil || len(unwrapped) != 32 {
		t.Fatalf("DEK unwrap failed: %v", err)
	}

	// Production rejects non-TLS DB, plaintext HTTP auth server, HTTP vault, or _LAB overlap.
	for _, tc := range []struct{ key, val string }{
		{envIssuanceDatabaseURL, "postgresql://pg.internal:5432/hukid_prod?sslmode=disable"},
		{envIssuanceAuthServer, "http://127.0.0.1:8080"},
		{envVaultAddr, "http://127.0.0.1:8200"},
		{envIssuanceClaimsKey, base64.StdEncoding.EncodeToString(dek)},
		{vciLabFlag, "test"},
	} {
		t.Run("reject_"+tc.key, func(t *testing.T) {
			t.Setenv(tc.key, tc.val)
			if err := validateIssuanceRuntimeConfiguration(); err == nil {
				t.Fatalf("expected failure when %s=%s", tc.key, tc.val)
			}
		})
	}
}

func TestOID4VPRuntimeConfigAndMount(t *testing.T) {
	clearRuntimeServiceEnv(t)
	if err := validateOID4VPRuntimeConfiguration(); err != nil {
		t.Fatalf("empty vp config should be inactive: %v", err)
	}

	dir := t.TempDir()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemKey, _ := issuance.MarshalP256PrivateKeyPKCS8PEM(priv)
	keyFile := filepath.Join(dir, "vp-signing.pem")
	if err := os.WriteFile(keyFile, pemKey, 0o600); err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "verifier.hukid.pe"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"verifier.hukid.pe"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "vp-chain.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HUKID_ENV", "production")
	t.Setenv(envOID4VPClientID, "verifier.hukid.pe")
	t.Setenv(envOID4VPResponseURI, "https://verifier.hukid.pe/oid4vp/response")
	t.Setenv(envOID4VPSigningKey, keyFile)
	t.Setenv(envOID4VPSigningCertPEM, certFile)

	if err := validateOID4VPRuntimeConfiguration(); err != nil {
		t.Fatalf("valid oid4vp runtime config failed: %v", err)
	}
	routes, err := configureOID4VPRuntime(os.Stdout, time.Now)
	if err != nil || routes == nil {
		t.Fatalf("configureOID4VPRuntime failed: %v", err)
	}
	mux := http.NewServeMux()
	routes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oid4vp/request/missing", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown request_uri, got %d", rec.Code)
	}

	// Reject loopback HTTP transport override in production or _LAB overlap.
	t.Setenv(envOID4VPTransportBase, "http://127.0.0.1:8080")
	if err := validateOID4VPRuntimeConfiguration(); err == nil {
		t.Fatal("expected rejection of http transport base in production")
	}
	t.Setenv(envOID4VPTransportBase, "")
	t.Setenv(labFlag, "test")
	if err := validateOID4VPRuntimeConfiguration(); err == nil {
		t.Fatal("expected rejection of _LAB overlap")
	}
}

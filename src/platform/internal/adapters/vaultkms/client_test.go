package vaultkms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hukid.local/platform/internal/issuance"
)

func TestNewClientValidation(t *testing.T) {
	for _, cfg := range []Config{
		{BaseURL: "", Token: "tok"},
		{BaseURL: "http://vault.prod.example.com", Token: "tok"},
		{BaseURL: "https://user:pass@vault.prod.example.com", Token: "tok"},
		{BaseURL: "https://vault.prod.example.com?foo=bar", Token: "tok"},
		{BaseURL: "https://vault.prod.example.com", Token: ""},
		{BaseURL: "https://vault.prod.example.com", Token: "bad token"},
		{BaseURL: "https://vault.prod.example.com", Token: "tok", MountPath: "bad/mount"},
	} {
		if _, err := NewClient(cfg); !errors.Is(err, ErrConfig) {
			t.Fatalf("expected ErrConfig for %+v, got %v", cfg, err)
		}
	}
	if _, err := NewClient(Config{BaseURL: "http://127.0.0.1:8200", Token: "s.loopback", MountPath: "transit"}); err != nil {
		t.Fatalf("loopback http failed: %v", err)
	}
	if _, err := NewClient(Config{BaseURL: "https://vault.internal:8200", Token: "s.prod"}); err != nil {
		t.Fatalf("https failed: %v", err)
	}
}

func TestVaultProvisionSignRawAndDERAndEnvelopeKEK(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))

	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	useASN1 := false
	failVault := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "hvs.test-token" || r.Header.Get("X-Vault-Namespace") != "hukid-ns" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if failVault {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/transit/keys/"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/transit/keys/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"latest_version": 1,
					"type":           "ecdsa-p256",
					"keys": map[string]any{
						"1": map[string]any{"public_key": pubPEM},
					},
				},
			})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/transit/sign/"):
			var req struct {
				Input               string `json:"input"`
				Prehashed           bool   `json:"prehashed"`
				KeyVersion          int    `json:"key_version"`
				MarshalingAlgorithm string `json:"marshaling_algorithm"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !req.Prehashed || req.KeyVersion != 1 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			digest, err := base64.StdEncoding.DecodeString(req.Input)
			if err != nil || len(digest) != 32 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			der, err := ecdsa.SignASN1(rand.Reader, key, digest)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			var encoded string
			if useASN1 {
				encoded = base64.StdEncoding.EncodeToString(der)
			} else {
				raw64, err := issuance.ParseASN1OrRawES256Signature(der)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				encoded = base64.RawURLEncoding.EncodeToString(raw64)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"signature": "vault:v1:" + encoded},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/transit/encrypt/claims-kek":
			var req struct {
				Plaintext string `json:"plaintext"`
				Context   string `json:"context"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			pt, _ := base64.StdEncoding.DecodeString(req.Plaintext)
			blk, _ := aes.NewCipher(kek)
			aead, _ := cipher.NewGCM(blk)
			nonce := make([]byte, aead.NonceSize())
			_, _ = rand.Read(nonce)
			aad, _ := base64.StdEncoding.DecodeString(req.Context)
			ct := aead.Seal(nonce, nonce, pt, aad)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(ct)},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/transit/decrypt/claims-kek":
			var req struct {
				Ciphertext string `json:"ciphertext"`
				Context    string `json:"context"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			rawCT, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(req.Ciphertext, "vault:v1:"))
			blk, _ := aes.NewCipher(kek)
			aead, _ := cipher.NewGCM(blk)
			ns := aead.NonceSize()
			aad, _ := base64.StdEncoding.DecodeString(req.Context)
			pt, err := aead.Open(nil, rawCT[:ns], rawCT[ns:], aad)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(pt)},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, err := NewClient(Config{
		BaseURL:   srv.URL,
		Token:     "hvs.test-token",
		Namespace: "hukid-ns",
	})
	if err != nil {
		t.Fatal(err)
	}

	ref, jwk, err := client.KeyProvisioner()("tenant-1", "11111111-1111-4111-8111-111111111111", "unas-key-1")
	if err != nil || !strings.HasPrefix(ref, "vault://transit/") || jwk.Kid != "unas-key-1" {
		t.Fatalf("ProvisionKey failed: ref=%s jwk=%+v err=%v", ref, jwk, err)
	}
	pub, err := issuance.DecodePublicJWK(jwk)
	if err != nil || !pub.Equal(&key.PublicKey) {
		t.Fatalf("returned JWK mismatch: %v", err)
	}

	signer, err := client.Resolver()("tenant-1", "11111111-1111-4111-8111-111111111111", "https://issuer.hukid.pe/unas", "unas-key-1", ref, pub)
	if err != nil {
		t.Fatal(err)
	}
	for _, derMode := range []bool{false, true} {
		useASN1 = derMode
		sig, err := signer.Sign("hdr.payload")
		if err != nil || len(sig) != 64 {
			t.Fatalf("Sign(der=%v) failed: len=%d err=%v", derMode, len(sig), err)
		}
		sum := sha256.Sum256([]byte("hdr.payload"))
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(&key.PublicKey, sum[:], r, s) {
			t.Fatalf("signature did not verify (der=%v)", derMode)
		}
	}

	// Wrong expectedPub must fail closed.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongSigner, err := client.Signer("https://issuer.hukid.pe/unas", "unas-key-1", ref, &otherKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongSigner.Sign("hdr.payload"); !errors.Is(err, issuance.ErrSigningFailed) {
		t.Fatalf("expected ErrSigningFailed on mismatched public key, got %v", err)
	}

	// Envelope KEK wrap + unwrap with AAD.
	dek := make([]byte, 32)
	_, _ = rand.Read(dek)
	wrapped, err := client.WrapDEK(context.Background(), "claims-kek", dek, "hukid/claims-dek/v1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.UnwrapDEK(context.Background(), "claims-kek", wrapped, "wrong-aad"); !errors.Is(err, ErrVaultUnavailable) {
		t.Fatalf("expected ErrVaultUnavailable on wrong AAD, got %v", err)
	}
	unwrapped, err := client.UnwrapDEK(context.Background(), "claims-kek", wrapped, "hukid/claims-dek/v1")
	if err != nil || !bytes.Equal(dek, unwrapped) {
		t.Fatalf("UnwrapDEK mismatch: err=%v", err)
	}

	// Vault 503 propagates cleanly.
	failVault = true
	if _, err := signer.Sign("hdr.payload"); !errors.Is(err, issuance.ErrSigningFailed) {
		t.Fatalf("expected ErrSigningFailed on 503, got %v", err)
	}
	if _, _, err := client.ProvisionKey(context.Background(), "t", "11111111-1111-4111-8111-111111111111", "k2"); !errors.Is(err, ErrVaultUnavailable) {
		t.Fatalf("expected ErrVaultUnavailable on 503, got %v", err)
	}
}

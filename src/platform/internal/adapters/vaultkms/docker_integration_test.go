//go:build integration

package vaultkms

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const vaultDockerImage = "hashicorp/vault:1.18"

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func vaultAdminRequest(t *testing.T, baseURL, token, method, path string, body any) {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, baseURL+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("vault admin %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("vault admin %s %s returned status %d", method, path, resp.StatusCode)
	}
}

func TestVaultTransitDockerIntegration(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI not installed")
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		t.Skipf("docker engine unavailable: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	port := freeLoopbackPort(t)
	rootToken := "hukid-vault-int-token"
	containerName := fmt.Sprintf("hukid-vault-test-%d", time.Now().UnixNano())

	cmd := exec.Command(
		"docker", "run", "-d", "--rm",
		"--name", containerName,
		"-p", fmt.Sprintf("127.0.0.1:%d:8200", port),
		"-e", "VAULT_DEV_ROOT_TOKEN_ID="+rootToken,
		"-e", "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
		vaultDockerImage,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to start Vault Docker container: %v\n%s", err, string(out))
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
	})

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	httpClient := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(30 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get(baseURL + "/v1/sys/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("Vault container %s did not become healthy within 30s", containerName)
	}

	vaultAdminRequest(t, baseURL, rootToken, http.MethodPost, "/v1/sys/mounts/transit", map[string]any{"type": "transit"})

	client, err := NewClient(Config{
		BaseURL:   baseURL,
		Token:     rootToken,
		MountPath: "transit",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// 1. Provision an ES256 signing key and sign a real payload via Vault Transit.
	ctx := context.Background()
	prov := client.KeyProvisioner()
	kmsRef1, jwk1, err := prov("tenant-docker", "issuer-unas", "kid-v1")
	if err != nil {
		t.Fatalf("ProvisionKey kid-v1 failed: %v", err)
	}
	if kmsRef1 == "" || jwk1.Kid != "kid-v1" || jwk1.Crv != "P-256" || jwk1.X == "" || jwk1.Y == "" {
		t.Fatalf("unexpected JWK from real Vault Transit: ref=%q jwk=%+v", kmsRef1, jwk1)
	}

	xb, _ := base64.RawURLEncoding.DecodeString(jwk1.X)
	yb, _ := base64.RawURLEncoding.DecodeString(jwk1.Y)
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}

	resolver := client.Resolver()
	signer, err := resolver("tenant-docker", "issuer-unas", "https://issuer.hukid.pe/unas", "kid-v1", kmsRef1, pub)
	if err != nil {
		t.Fatalf("Resolve signer failed: %v", err)
	}
	signingInput := "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtpZC12MSJ9.eyJzdWIiOiJkaWQ6ZXhhbXBsZToxMjMifQ"
	rawSig, err := signer.Sign(signingInput)
	if err != nil {
		t.Fatalf("real Vault Sign failed: %v", err)
	}
	if len(rawSig) != 64 {
		t.Fatalf("expected 64-byte raw ES256 signature, got %d", len(rawSig))
	}

	digest := sha256.Sum256([]byte(signingInput))
	rSig := new(big.Int).SetBytes(rawSig[:32])
	sSig := new(big.Int).SetBytes(rawSig[32:])
	if !ecdsa.Verify(pub, digest[:], rSig, sSig) {
		t.Fatal("ECDSA signature produced by real Vault Transit failed verification against JWK")
	}

	// 2. Provision rotated key kid-v2 and verify distinct public material.
	kmsRef2, jwk2, err := prov("tenant-docker", "issuer-unas", "kid-v2")
	if err != nil {
		t.Fatalf("ProvisionKey kid-v2 failed: %v", err)
	}
	if kmsRef2 == kmsRef1 || (jwk2.X == jwk1.X && jwk2.Y == jwk1.Y) {
		t.Fatal("expected rotated key kid-v2 to have distinct ref and public coordinates")
	}

	// 3. Envelope KEK (aes256-gcm96, derived=true for AAD context binding): wrap & unwrap a 32-byte DEK.
	vaultAdminRequest(t, baseURL, rootToken, http.MethodPost, "/v1/transit/keys/hukid-claims-kek", map[string]any{
		"type":       "aes256-gcm96",
		"derived":    true,
		"exportable": false,
	})
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	aad := "hukid/claims-dek/v1|v1"
	ciphertext, err := client.WrapDEK(ctx, "hukid-claims-kek", dek, aad)
	if err != nil {
		t.Fatalf("WrapDEK failed: %v", err)
	}
	if !strings.HasPrefix(ciphertext, "vault:v") {
		t.Fatalf("expected vault:v* ciphertext, got %q", ciphertext)
	}
	unwrapped, err := client.UnwrapDEK(ctx, "hukid-claims-kek", ciphertext, aad)
	if err != nil {
		t.Fatalf("UnwrapDEK failed: %v", err)
	}
	if !bytes.Equal(unwrapped, dek) {
		t.Fatal("unwrapped DEK does not match original DEK")
	}
	if _, err := client.UnwrapDEK(ctx, "hukid-claims-kek", ciphertext, "hukid/claims-dek/v1|wrong"); err == nil {
		t.Fatal("expected UnwrapDEK with mismatched AAD context to fail")
	}
}

package secretbox

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEnvelopeAuthenticationAndConfiguration(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	box, err := New(key, "v1", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, err := box.Seal([]byte("ephemeral-test-secret"), "transaction:one")
	if err != nil {
		t.Fatal(err)
	}
	b, err := box.Seal([]byte("ephemeral-test-secret"), "transaction:one")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Nonce, b.Nonce) || bytes.Contains(a.Ciphertext, []byte("ephemeral-test-secret")) {
		t.Fatal("encryption did not protect secret")
	}
	plaintext, err := box.Open(a, "transaction:one")
	if err != nil || string(plaintext) != "ephemeral-test-secret" {
		t.Fatal("cannot decrypt")
	}
	if _, err := box.Open(a, "transaction:two"); err == nil {
		t.Fatal("AAD substitution accepted")
	}
	a.KeyVersion = "v2"
	if _, err := box.Open(a, "transaction:one"); err == nil {
		t.Fatal("unknown version accepted")
	}
	a.KeyVersion = "v1"
	a.Ciphertext[0] ^= 1
	if _, err := box.Open(a, "transaction:one"); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	for _, size := range []int{0, 16, 24, 33} {
		if _, err := New(make([]byte, size), "v1", rand.Reader); err == nil {
			t.Fatal("invalid AES key accepted")
		}
	}
	if _, err := New(key, "", rand.Reader); err == nil {
		t.Fatal("missing version accepted")
	}
	broken, _ := New(key, "v1", bytes.NewReader(nil))
	if _, err := broken.Seal([]byte("test"), "purpose"); err == nil {
		t.Fatal("entropy failure ignored")
	}
}

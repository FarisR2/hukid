package issuance_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"hukid.local/platform/internal/issuance"
	"hukid.local/platform/internal/verification"
)

func TestValidateProof(t *testing.T) {
	// Public, deterministic test-only scalar and signing nonce; never production keys.
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult([]byte{1})
	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: big.NewInt(1)}
	enc := base64.RawURLEncoding.EncodeToString
	jwk := fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":"%s","y":"%s"}`, enc(x.FillBytes(make([]byte, 32))), enc(y.FillBytes(make([]byte, 32))))
	header := `{"alg":"ES256","typ":"openid4vci-proof+jwt","jwk":` + jwk + `}`
	payload := `{"aud":"https://wallet-lab.example/wallet-lab","nonce":"challenge","iat":1700000000}`
	expected := issuance.ProofExpectation{
		Issuer: "https://wallet-lab.example/wallet-lab", Nonce: "challenge",
		Now: time.Unix(1700000060, 0), MaxAge: time.Minute, ClockSkew: time.Second,
		MaxBytes: 4096, MaxDepth: 4,
	}
	sign := func(h, p string) string {
		input := enc([]byte(h)) + "." + enc([]byte(p))
		digest := sha256.Sum256([]byte(input))
		// ECDSA with fixed k=2, deterministic and confined to this fixture.
		rx, _ := curve.ScalarBaseMult([]byte{2})
		r := new(big.Int).Mod(rx, curve.Params().N)
		s := new(big.Int).Add(new(big.Int).SetBytes(digest[:]), r)
		s.Mul(s, new(big.Int).ModInverse(big.NewInt(2), curve.Params().N)).Mod(s, curve.Params().N)
		sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		return input + "." + enc(sig)
	}
	valid := sign(header, payload)
	want, err := verification.JWKThumbprint(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	accept := func(t *testing.T, token string, policy issuance.ProofExpectation) {
		t.Helper()
		for range 2 { // Pure validation must not consume a nonce.
			if got, err := issuance.ValidateProof(token, policy); err != nil || got != want {
				t.Fatalf("got %q, %v", got, err)
			}
		}
	}
	accept(t, valid, expected)
	for _, delta := range []int64{-1, 60, 61} {
		t.Run(fmt.Sprintf("inclusive-boundary-%d", delta), func(t *testing.T) {
			accept(t, sign(header, strings.Replace(payload, "1700000000", fmt.Sprint(1700000000+delta), 1)), expected)
		})
	}
	// The explicit byte/depth bounds are inclusive.
	bounded := expected
	bounded.MaxBytes, bounded.MaxDepth = len(valid), 2
	accept(t, valid, bounded)
	for _, tc := range []struct{ name, old, replacement string }{
		{"alg", "ES256", "none"}, {"typ", "openid4vci-proof+jwt", "JWT"},
		{"private", `"kty":"EC"`, `"d":"secret","kty":"EC"`},
		{"invalid-point", enc(x.FillBytes(make([]byte, 32))), enc(make([]byte, 32))},
		{"curve", "P-256", "P-384"}, {"key-type", `"kty":"EC"`, `"kty":"RSA"`},
		{"key-null", `"x":"` + enc(x.FillBytes(make([]byte, 32))) + `"`, `"x":null`},
		{"header-unknown", `"alg":`, `"kid":"ignored","alg":`},
		{"header-case", `"alg":`, `"ALG":`},
		{"key-case", `"kty":`, `"KTY":`},
		{"payload-case", `"iat":`, `"IAT":`},
		{"key-coordinate-padding", enc(x.FillBytes(make([]byte, 32))), enc(x.FillBytes(make([]byte, 32))) + "="},
		{"header-duplicate", `"alg":`, `"alg":"ES256","alg":`},
		{"key-unknown", `"kty":`, `"use":"sig","kty":`},
		{"key-duplicate", `"kty":`, `"kty":"EC","kty":`},
		{"aud-array", `"https://wallet-lab.example/wallet-lab"`, `["https://wallet-lab.example/wallet-lab"]`},
		{"aud-mismatch", "/wallet-lab", "/wallet-lab/credential"},
		{"nonce-empty", `"challenge"`, `""`}, {"nonce-mismatch", "challenge", "other"},
		{"nonce-null", `"challenge"`, "null"},
		{"iat-missing", `,"iat":1700000000`, ""}, {"iat-fraction", "1700000000", "1700000000.0"},
		{"iat-string", "1700000000", `"1700000000"`}, {"iat-null", "1700000000", "null"},
		{"iat-future", "1700000000", "1700000062"}, {"iat-stale", "1700000000", "1699999998"},
		{"iat-overflow", "1700000000", "9223372036854775807"},
		{"payload-unknown", `"iat":`, `"iss":"unexpected","iat":`},
		{"payload-duplicate", `"iat":`, `"iat":1,"iat":`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rejectProof(t, sign(strings.Replace(header, tc.old, tc.replacement, 1), strings.Replace(payload, tc.old, tc.replacement, 1)), expected)
		})
	}
	for name, token := range map[string]string{
		"signature":        valid[:len(valid)-86] + enc(make([]byte, 64)),
		"signature-length": valid[:len(valid)-86] + "AA", "empty": "", "segments": valid + ".",
		"padding": valid + "=", "noncanonical": valid[:len(valid)-1] + "B",
		"trailing": sign(header, payload+`{}`), "header-trailing": sign(header+`{}`, payload),
		"object-null": sign(header, "null"), "object-array": sign(header, "[]"),
		"depth":                  sign(header, `{"unexpected":[[[[1]]]]}`),
		"malformed":              sign(header, `{"iat":`),
		"invalid-utf8":           sign(header, "{\"nonce\":\"\xff\"}"),
		"duplicate-nested-array": sign(header, `{"extra":[{"a":1,"a":2}]}`),
		"size":                   strings.Repeat("x", 4097), "newline": valid + "\n",
	} {
		t.Run(name, func(t *testing.T) { rejectProof(t, token, expected) })
	}
	for _, field := range []string{"issuer", "nonce", "now", "age", "skew", "bytes", "depth", "depth-cap", "bytes-cap"} {
		t.Run("policy-"+field, func(t *testing.T) {
			p := expected
			switch field {
			case "issuer":
				p.Issuer = ""
			case "nonce":
				p.Nonce = ""
			case "now":
				p.Now = time.Time{}
			case "age":
				p.MaxAge = 0
			case "skew":
				p.ClockSkew = -1
			case "bytes":
				p.MaxBytes = len(valid) - 1
			case "depth":
				p.MaxDepth = 1
			case "depth-cap":
				p.MaxDepth = 9
			case "bytes-cap":
				p.MaxBytes = 16385
			}
			rejectProof(t, valid, p)
		})
	}
	precise := expected
	precise.Now = precise.Now.Add(time.Nanosecond)
	rejectProof(t, sign(header, strings.Replace(payload, "1700000000", "1699999999", 1)), precise)
	accept(t, valid, precise)
	precise.ClockSkew = 0
	accept(t, sign(header, strings.Replace(payload, "1700000000", "1700000060", 1)), precise)
	large := expected
	large.MaxAge, large.ClockSkew = time.Duration(1<<63-1), time.Duration(1<<63-1)
	accept(t, valid, large) // No overflow when adding policy durations.
}

func rejectProof(t *testing.T, token string, expected issuance.ProofExpectation) {
	t.Helper()
	if got, err := issuance.ValidateProof(token, expected); got != "" || err == nil || err.Error() != "invalid issuance proof" {
		t.Fatalf("expected empty result and fixed sanitized error; got %q, %v", got, err)
	}
}

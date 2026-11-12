package verification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
)

func ecdsaFromJWK(t *testing.T, k jwk) *ecdsa.PublicKey {
	t.Helper()
	x, err1 := base64.RawURLEncoding.DecodeString(k.X)
	y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
	if err1 != nil || err2 != nil {
		t.Fatal("bad JWK coordinates")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
}

func vectorResolver(t *testing.T, file vectorFile) *MemoryKeyResolver {
	t.Helper()
	keys := NewMemoryKeyResolver()
	for kid, k := range file.IssuerKeys {
		if err := keys.Add(file.Issuer, kid, ecdsaFromJWK(t, k)); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

func checkByName(checks []Check, name CheckName) Check {
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	return Check{}
}

func TestIntegrityOutcomeMatchesTheVectorSet(t *testing.T) {
	file := loadVectors(t)
	keys := vectorResolver(t, file)
	for _, v := range file.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			_, checks, err := integrityChecks(v.JWS, DefaultLimits, keys)
			if err != nil {
				t.Fatal(err)
			}
			if len(checks) != 3 {
				t.Fatalf("expected format, issuerKey and signature checks, got %+v", checks)
			}
			switch v.Expected.FailedCheck {
			case CheckFormat, CheckIssuerKey, CheckSignature:
				failed := checkByName(checks, v.Expected.FailedCheck)
				if failed.Result != Fail || failed.Code != v.Expected.Code {
					t.Fatalf("expected %s/%s, got %+v", v.Expected.FailedCheck, v.Expected.Code, checks)
				}
			default:
				// Valid vectors and validity failures (VER-T04) pass all three.
				for _, c := range checks {
					if c.Result != Pass {
						t.Fatalf("integrity checks must pass here, got %+v", checks)
					}
				}
			}
		})
	}
}

func TestChecksAfterAFailureAreSkippedNotPassed(t *testing.T) {
	file := loadVectors(t)
	keys := vectorResolver(t, file)
	byID := map[string]vector{}
	for _, v := range file.Vectors {
		byID[v.ID] = v
	}

	_, checks, _ := integrityChecks(byID["v02-header-typ-wrong"].JWS, DefaultLimits, keys)
	for _, name := range []CheckName{CheckIssuerKey, CheckSignature} {
		c := checkByName(checks, name)
		if c.Result != Skipped || c.Code != CodeSkippedPrecondition || !c.Required {
			t.Fatalf("%s after a format failure must be a required skip, got %+v", name, c)
		}
	}
	_, checks, _ = integrityChecks(byID["v07-unknown-kid"].JWS, DefaultLimits, keys)
	if c := checkByName(checks, CheckSignature); c.Result != Skipped {
		t.Fatalf("signature after a key failure must be skipped, got %+v", c)
	}
	if got := NewReport([]byte("x"), checks).TechnicalResult; got != Invalid {
		t.Fatalf("a report with a failed key check must be invalid, got %q", got)
	}
}

func TestUntrustedHeadersAreRejectedBeforeAnyLookup(t *testing.T) {
	file := loadVectors(t)
	probe := &countingResolver{}
	for _, v := range file.Vectors {
		if v.ID != "v05-header-jku" {
			continue
		}
		_, checks, err := integrityChecks(v.JWS, DefaultLimits, probe)
		if err != nil {
			t.Fatal(err)
		}
		if c := checkByName(checks, CheckIssuerKey); c.Code != CodeKeyUntrustedHeader {
			t.Fatalf("unexpected %+v", c)
		}
	}
	if probe.calls != 0 {
		t.Fatalf("the resolver was called %d times for a credential carrying its own key headers", probe.calls)
	}
}

type countingResolver struct{ calls int }

func (c *countingResolver) ResolveKey(string, string) (ResolvedKey, error) {
	c.calls++
	return ResolvedKey{}, ErrKeyNotFound
}

type failingResolver struct{ err error }

func (f failingResolver) ResolveKey(string, string) (ResolvedKey, error) { return ResolvedKey{}, f.err }

func TestResolverFailuresAreErrorsNotCredentialFindings(t *testing.T) {
	file := loadVectors(t)
	jws := file.Vectors[0].JWS
	_, checks, err := integrityChecks(jws, DefaultLimits, failingResolver{errors.New("jwks fetch timed out")})
	if !errors.Is(err, ErrKeyResolution) || checks != nil {
		t.Fatalf("an infrastructure failure must be an error with no checks, got err=%v checks=%+v", err, checks)
	}
	if strings.Contains(err.Error(), jws) {
		t.Fatal("the error must not echo the credential")
	}
	_, _, err = integrityChecks(jws, DefaultLimits, nilKeyResolver{})
	if !errors.Is(err, ErrKeyResolution) {
		t.Fatalf("a resolver returning no key must be an error, got %v", err)
	}
}

type nilKeyResolver struct{}

func (nilKeyResolver) ResolveKey(string, string) (ResolvedKey, error) { return ResolvedKey{}, nil }

func TestIssuerMismatchIsDetected(t *testing.T) {
	file := loadVectors(t)
	keys := NewMemoryKeyResolver()
	// The same kid, owned by a different issuer than the credential declares.
	if err := keys.Add("https://issuer.hukid.pe/another-issuer", "synthetic-lab-key-1", ecdsaFromJWK(t, file.IssuerKeys["synthetic-lab-key-1"])); err != nil {
		t.Fatal(err)
	}
	_, checks, err := integrityChecks(file.Vectors[0].JWS, DefaultLimits, keys)
	if err != nil {
		t.Fatal(err)
	}
	if c := checkByName(checks, CheckIssuerKey); c.Result != Fail || c.Code != CodeKeyIssuerMismatch {
		t.Fatalf("expected key.issuer_mismatch, got %+v", c)
	}
}

func TestRetiredButPublishedKeyStillVerifies(t *testing.T) {
	// Rotation: the old key stays published next to the new one. A credential
	// signed with the old key must keep verifying.
	oldKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys := NewMemoryKeyResolver()
	for kid, k := range map[string]*ecdsa.PublicKey{"old": &oldKey.PublicKey, "new": &newKey.PublicKey} {
		if err := keys.Add(vectorIssuer, kid, k); err != nil {
			t.Fatal(err)
		}
	}
	signed := compact(baseHeader("old"), credentialPayload("jkt"), oldKey)
	_, checks, err := integrityChecks(signed, DefaultLimits, keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range checks {
		if c.Result != Pass {
			t.Fatalf("a retired but published key must verify, got %+v", checks)
		}
	}
}

func TestSignatureFromAnotherKeyIsRejected(t *testing.T) {
	file := loadVectors(t)
	keys := vectorResolver(t, file)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signed := compact(baseHeader("synthetic-lab-key-1"), credentialPayload(file.HolderJKT), other)
	_, checks, err := integrityChecks(signed, DefaultLimits, keys)
	if err != nil {
		t.Fatal(err)
	}
	if c := checkByName(checks, CheckSignature); c.Result != Fail || c.Code != CodeSignatureInvalid {
		t.Fatalf("expected signature.invalid for a foreign key, got %+v", checks)
	}
}

func TestMalformedSignaturesAreRejected(t *testing.T) {
	file := loadVectors(t)
	keys := vectorResolver(t, file)
	parts := strings.Split(file.Vectors[0].JWS, ".")
	zero := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	cases := map[string]string{
		"empty":        "",
		"too short":    base64.RawURLEncoding.EncodeToString(make([]byte, 63)),
		"too long":     base64.RawURLEncoding.EncodeToString(make([]byte, 65)),
		"all zero":     zero,
		"r zero":       base64.RawURLEncoding.EncodeToString(append(make([]byte, 32), repeatByte(0x01, 32)...)),
		"s zero":       base64.RawURLEncoding.EncodeToString(append(repeatByte(0x01, 32), make([]byte, 32)...)),
		"wrong values": base64.RawURLEncoding.EncodeToString(repeatByte(0x7f, 64)),
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			_, checks, err := integrityChecks(parts[0]+"."+parts[1]+"."+sig, DefaultLimits, keys)
			if err != nil {
				t.Fatal(err)
			}
			if c := checkByName(checks, CheckSignature); c.Result != Fail || c.Code != CodeSignatureInvalid {
				t.Fatalf("expected signature.invalid, got %+v", checks)
			}
		})
	}
}

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestMemoryKeyResolverRejectsUnusableKeys(t *testing.T) {
	keys := NewMemoryKeyResolver()
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, add := range map[string]error{
		"nil key":      keys.Add(vectorIssuer, "k", nil),
		"wrong curve":  keys.Add(vectorIssuer, "k", &p384.PublicKey),
		"empty kid":    keys.Add(vectorIssuer, "", &p256.PublicKey),
		"empty issuer": keys.Add("", "k", &p256.PublicKey),
		"off curve":    keys.Add(vectorIssuer, "k", &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}),
	} {
		if add == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
	if _, err := keys.ResolveKey(vectorIssuer, "k"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("rejected keys must not be published, got %v", err)
	}
}

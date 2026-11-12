package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"hukid.local/platform/internal/verification"
)

const (
	testIssuer   = "https://issuer.hukid.pe/synthetic-lab"
	testClientID = "x509_san_dns:verifier.example"
	testKid      = "synthetic-lab-key-1"
)

var testNow = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func signES256(t *testing.T, key *ecdsa.PrivateKey, input string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(input))
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	sig.R.FillBytes(raw[:32])
	sig.S.FillBytes(raw[32:])
	return b64(raw)
}

func compact(t *testing.T, header, payload map[string]any, key *ecdsa.PrivateKey) string {
	t.Helper()
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	input := b64(h) + "." + b64(p)
	return input + "." + signES256(t, key, input)
}

func publicJWK(key *ecdsa.PublicKey) map[string]any {
	raw, _ := key.Bytes()
	return map[string]any{"kty": "EC", "crv": "P-256", "x": b64(raw[1:33]), "y": b64(raw[33:65])}
}

func thumbprint(t *testing.T, key *ecdsa.PublicKey) string {
	t.Helper()
	jkt, err := verification.JWKThumbprint(key)
	if err != nil {
		t.Fatal(err)
	}
	return jkt
}

// lab holds a synthetic issuer and holder, and builds wallet-side artifacts.
type lab struct {
	issuer *ecdsa.PrivateKey
	holder *ecdsa.PrivateKey
}

func newLab(t *testing.T) lab {
	t.Helper()
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return lab{issuer: issuer, holder: holder}
}

func (l lab) verifier(t *testing.T, store verification.ReplayStore) *verification.Verifier {
	t.Helper()
	keys := verification.NewMemoryKeyResolver()
	if err := keys.Add(testIssuer, testKid, &l.issuer.PublicKey); err != nil {
		t.Fatal(err)
	}
	v, err := verification.NewVerifier(keys, verification.ClockFunc(func() time.Time { return testNow }), verification.DefaultLimits, 0)
	if err != nil {
		t.Fatal(err)
	}
	return v.WithReplayStore(store)
}

func (l lab) credential(t *testing.T) string {
	t.Helper()
	return compact(t,
		map[string]any{"alg": "ES256", "typ": "vc+jwt", "cty": "vc", "kid": testKid},
		map[string]any{
			"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
			"type":              []any{"VerifiableCredential", "SyntheticLabCredential"},
			"issuer":            testIssuer,
			"validFrom":         "2026-01-01T00:00:00Z",
			"validUntil":        "2027-01-01T00:00:00Z",
			"credentialSubject": map[string]any{"label": "synthetic-lab-subject"},
			"cnf":               map[string]any{"jkt": thumbprint(t, &l.holder.PublicKey)},
		}, l.issuer)
}

func (l lab) presentation(t *testing.T, aud, nonce string) string {
	t.Helper()
	return compact(t,
		map[string]any{"alg": "ES256", "typ": "vp+jwt", "cty": "vp", "jwk": publicJWK(&l.holder.PublicKey)},
		map[string]any{
			"@context": []any{"https://www.w3.org/ns/credentials/v2", "https://schemas.hukid.pe/contexts/presentation/v1"},
			"type":     []any{"VerifiablePresentation"},
			"aud":      aud,
			"nonce":    nonce,
			"verifiableCredential": []any{map[string]any{
				"@context": "https://www.w3.org/ns/credentials/v2",
				"type":     "EnvelopedVerifiableCredential",
				"id":       "data:application/vc+jwt," + l.credential(t),
			}},
		}, l.holder)
}

func testSession(t *testing.T) *Session {
	t.Helper()
	s, err := NewSession(Config{ClientID: testClientID, ResponseURI: "https://verifier.example/oid4vp/response"}, testNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// walletJWE is what a wallet does with the request: it encrypts the response
// to the JWK published in client_metadata.
func walletJWE(t *testing.T, s *Session, payload any, alg jose.KeyAlgorithm, enc jose.ContentEncryption, kid string) string {
	t.Helper()
	plaintext, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	encrypter, err := jose.NewEncrypter(enc, jose.Recipient{Algorithm: alg, Key: &s.encKey.PublicKey, KeyID: kid}, nil)
	if err != nil {
		t.Fatal(err)
	}
	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	out, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func answer(t *testing.T, s *Session, vp string) string {
	t.Helper()
	return walletJWE(t, s, map[string]any{"vp_token": map[string][]string{"credential": {vp}}, "state": s.State()}, jose.ECDH_ES, jose.A256GCM, s.kid)
}

func TestValidResponseVerifiesThroughTheCore(t *testing.T) {
	l := newLab(t)
	s := testSession(t)
	report, err := s.HandleResponse(l.verifier(t, verification.NewMemoryReplayStore()), testNow, answer(t, s, l.presentation(t, testClientID, s.nonce)))
	if err != nil {
		t.Fatal(err)
	}
	if report.TechnicalResult != verification.Valid {
		t.Fatalf("technicalResult = %q: %+v", report.TechnicalResult, report)
	}
}

func TestRequestBindingFailuresAreReportedByTheCore(t *testing.T) {
	l := newLab(t)
	cases := map[string]struct {
		build func(s *Session) string
		code  verification.Code
	}{
		"wrong audience": {func(s *Session) string {
			return answer(t, s, l.presentation(t, "x509_san_dns:other.example", s.nonce))
		}, verification.CodeRequestAudience},
		"wrong nonce": {func(s *Session) string { return answer(t, s, l.presentation(t, testClientID, "wrong-nonce")) }, verification.CodeRequestNonce},
		"wrong state": {func(s *Session) string {
			vp := l.presentation(t, testClientID, s.nonce)
			return walletJWE(t, s, map[string]any{"vp_token": map[string][]string{"credential": {vp}}, "state": "wrong-state"}, jose.ECDH_ES, jose.A256GCM, s.kid)
		}, verification.CodeRequestState},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := testSession(t)
			report, err := s.HandleResponse(l.verifier(t, verification.NewMemoryReplayStore()), testNow, tc.build(s))
			if err != nil {
				t.Fatal(err)
			}
			if report.TechnicalResult != verification.Invalid {
				t.Fatalf("technicalResult = %q", report.TechnicalResult)
			}
			var got verification.Code
			for _, c := range report.Checks {
				if c.Result == verification.Fail {
					got = c.Code
				}
			}
			if got != tc.code {
				t.Fatalf("code = %q, want %q", got, tc.code)
			}
		})
	}
}

func TestReplayedResponseIsRejected(t *testing.T) {
	l := newLab(t)
	s := testSession(t)
	v := l.verifier(t, verification.NewMemoryReplayStore())
	response := answer(t, s, l.presentation(t, testClientID, s.nonce))
	if report, err := s.HandleResponse(v, testNow, response); err != nil || report.TechnicalResult != verification.Valid {
		t.Fatalf("first response: %v %+v", err, report)
	}
	report, err := s.HandleResponse(v, testNow, response)
	if err != nil {
		t.Fatal(err)
	}
	if report.TechnicalResult != verification.Invalid {
		t.Fatalf("replay accepted: %+v", report)
	}
	found := false
	for _, c := range report.Checks {
		found = found || c.Code == verification.CodeRequestReplayed
	}
	if !found {
		t.Fatalf("replay code missing: %+v", report.Checks)
	}
}

func TestUnauthenticatedGarbageDoesNotBurnTheRequest(t *testing.T) {
	l := newLab(t)
	s := testSession(t)
	v := l.verifier(t, verification.NewMemoryReplayStore())
	attacker := jose.ECDH_ES
	garbage := walletJWE(t, s, map[string]any{"vp_token": map[string][]string{"credential": {"not.a.vp"}}, "state": s.State()}, attacker, jose.A256GCM, s.kid)
	if report, err := s.HandleResponse(v, testNow, garbage); err != nil || report.TechnicalResult != verification.Invalid {
		t.Fatalf("garbage: %v %+v", err, report)
	}
	if report, err := s.HandleResponse(v, testNow, answer(t, s, l.presentation(t, testClientID, s.nonce))); err != nil || report.TechnicalResult != verification.Valid {
		t.Fatalf("legitimate response after garbage: %v %+v", err, report)
	}
}

func TestResponsesThatCannotBeAuthenticatedAreRejectedWithoutDetail(t *testing.T) {
	l := newLab(t)
	s := testSession(t)
	v := l.verifier(t, verification.NewMemoryReplayStore())
	vp := l.presentation(t, testClientID, s.nonce)
	good := map[string]any{"vp_token": map[string][]string{"credential": {vp}}, "state": s.State()}

	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	encryptedToOther, _ := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: &otherKey.PublicKey, KeyID: s.kid}, nil)
	plaintext, _ := json.Marshal(good)
	otherObject, _ := encryptedToOther.Encrypt(plaintext)
	otherCompact, _ := otherObject.CompactSerialize()

	valid := answer(t, s, vp)
	parts := strings.Split(valid, ".")
	flipped := parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3][:len(parts[3])-2] + "AA." + parts[4]

	cases := map[string]string{
		"empty":                    "",
		"plain unencrypted JWT":    compact(t, map[string]any{"alg": "ES256", "typ": "JWT"}, good, l.holder),
		"raw JSON":                 string(plaintext),
		"wrong kid":                walletJWE(t, s, good, jose.ECDH_ES, jose.A256GCM, "other-kid"),
		"no kid":                   walletJWE(t, s, good, jose.ECDH_ES, jose.A256GCM, ""),
		"encrypted to another key": otherCompact,
		"alg ECDH-ES+A256KW":       walletJWE(t, s, good, jose.ECDH_ES_A256KW, jose.A256GCM, s.kid),
		"enc A128GCM":              walletJWE(t, s, good, jose.ECDH_ES, jose.A128GCM, s.kid),
		"tampered ciphertext":      flipped,
		"oversized":                strings.Repeat("A", MaxResponseBytes+1),
		"two queries":              walletJWE(t, s, map[string]any{"vp_token": map[string][]string{"credential": {vp}, "extra": {vp}}, "state": s.State()}, jose.ECDH_ES, jose.A256GCM, s.kid),
		"two presentations":        walletJWE(t, s, map[string]any{"vp_token": map[string][]string{"credential": {vp, vp}}, "state": s.State()}, jose.ECDH_ES, jose.A256GCM, s.kid),
		"vp_token as string":       walletJWE(t, s, map[string]any{"vp_token": vp, "state": s.State()}, jose.ECDH_ES, jose.A256GCM, s.kid),
		"unknown query id":         walletJWE(t, s, map[string]any{"vp_token": map[string][]string{"other": {vp}}, "state": s.State()}, jose.ECDH_ES, jose.A256GCM, s.kid),
	}
	for name, response := range cases {
		t.Run(name, func(t *testing.T) {
			report, err := s.HandleResponse(v, testNow, response)
			if !errors.Is(err, ErrResponseInvalid) {
				t.Fatalf("err = %v, report = %+v", err, report)
			}
			if err.Error() != ErrResponseInvalid.Error() || strings.Contains(err.Error(), vp) {
				t.Fatalf("error leaks detail: %q", err)
			}
		})
	}
}

func TestExpiredSessionIsRejectedBeforeDecrypting(t *testing.T) {
	l := newLab(t)
	s := testSession(t)
	response := answer(t, s, l.presentation(t, testClientID, s.nonce))
	_, err := s.HandleResponse(l.verifier(t, verification.NewMemoryReplayStore()), s.ExpiresAt(), response)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.HandleResponse(l.verifier(t, verification.NewMemoryReplayStore()), s.ExpiresAt().Add(-time.Second), response); err != nil {
		t.Fatalf("response just before expiry: %v", err)
	}
}

func TestSessionsAreIndependentAndUnpredictable(t *testing.T) {
	a, b := testSession(t), testSession(t)
	if a.nonce == b.nonce || a.state == b.state || a.kid == b.kid || a.encKey.Equal(b.encKey) {
		t.Fatal("two sessions share secrets")
	}
	if len(a.nonce) < 43 || len(a.state) < 43 {
		t.Fatalf("nonce/state too short: %d/%d", len(a.nonce), len(a.state))
	}
	// A response for one session cannot be opened by another.
	l := newLab(t)
	response := answer(t, a, l.presentation(t, testClientID, a.nonce))
	if _, err := b.HandleResponse(l.verifier(t, verification.NewMemoryReplayStore()), testNow, response); !errors.Is(err, ErrResponseInvalid) {
		t.Fatalf("cross-session response: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	good := Config{ClientID: testClientID, ResponseURI: "https://verifier.example/r"}
	bad := map[string]Config{
		"no client id":     {ResponseURI: good.ResponseURI},
		"http response":    {ClientID: good.ClientID, ResponseURI: "http://verifier.example/r"},
		"no host":          {ClientID: good.ClientID, ResponseURI: "https:///r"},
		"fragment":         {ClientID: good.ClientID, ResponseURI: "https://verifier.example/r#x"},
		"userinfo":         {ClientID: good.ClientID, ResponseURI: "https://user@verifier.example/r"},
		"ttl above max":    {ClientID: good.ClientID, ResponseURI: good.ResponseURI, TTL: MaxTTL + time.Second},
		"negative ttl":     {ClientID: good.ClientID, ResponseURI: good.ResponseURI, TTL: -time.Second},
		"padded client id": {ClientID: " " + good.ClientID, ResponseURI: good.ResponseURI},
		"bad query id":     {ClientID: good.ClientID, ResponseURI: good.ResponseURI, CredentialQueryID: "a b"},
	}
	for name, cfg := range bad {
		if _, err := NewSession(cfg, testNow, nil); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := NewSession(good, testNow, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSession(good, testNow, strings.NewReader("short")); !errors.Is(err, ErrConfig) {
		t.Fatalf("short entropy source accepted: %v", err)
	}
}

func TestSignedRequestObject(t *testing.T) {
	s := testSession(t)
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "verifier.example"}, DNSNames: []string{"verifier.example"}, NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &signer.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	compactObject, err := s.SignRequestObject(signer, [][]byte{der})
	if err != nil {
		t.Fatal(err)
	}
	object, err := jose.ParseSigned(compactObject, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	header := object.Signatures[0].Protected
	if header.Algorithm != "ES256" || header.ExtraHeaders[jose.HeaderType] != RequestObjectType {
		t.Fatalf("header = %+v", header)
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(strings.Split(compactObject, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var protected struct {
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(rawHeader, &protected); err != nil || len(protected.X5C) != 1 {
		t.Fatalf("x5c = %v (%v)", protected.X5C, err)
	}
	payload, err := object.Verify(&signer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"client_id": testClientID, "response_type": "vp_token", "response_mode": "direct_post.jwt", "response_uri": "https://verifier.example/oid4vp/response", "nonce": s.nonce, "state": s.state}
	for key, value := range want {
		if claims[key] != value {
			t.Errorf("%s = %v, want %v", key, claims[key], value)
		}
	}
	if int64(claims["exp"].(float64)) != s.ExpiresAt().Unix() {
		t.Errorf("exp = %v", claims["exp"])
	}
	dcql := claims["dcql_query"].(map[string]any)["credentials"].([]any)[0].(map[string]any)
	if dcql["id"] != "credential" || dcql["format"] != CredentialFormat {
		t.Errorf("dcql = %v", dcql)
	}

	// The published encryption JWK is public, labelled for encryption and is
	// the key that opens responses; the private half is never in the object.
	metadata := claims["client_metadata"].(map[string]any)
	keys := metadata["jwks"].(map[string]any)["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("keys = %v", keys)
	}
	key := keys[0].(map[string]any)
	if key["use"] != "enc" || key["kid"] != s.kid || key["alg"] != "ECDH-ES" || key["kty"] != "EC" {
		t.Errorf("enc jwk = %v", key)
	}
	if _, private := key["d"]; private {
		t.Fatal("private key material in the request object")
	}
	if !strings.Contains(string(payload), `"A256GCM"`) {
		t.Error("encrypted_response_enc_values_supported missing")
	}
	if _, err := s.SignRequestObject(nil, nil); !errors.Is(err, ErrConfig) {
		t.Errorf("nil signer: %v", err)
	}
}

func TestHandleResponseRequiresAVerifier(t *testing.T) {
	s := testSession(t)
	if _, err := s.HandleResponse(nil, testNow, "x"); !errors.Is(err, ErrConfig) {
		t.Fatalf("err = %v", err)
	}
}

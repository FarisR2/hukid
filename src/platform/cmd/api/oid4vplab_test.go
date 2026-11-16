package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"hukid.local/platform/internal/adapters/oid4vphttp"
	"hukid.local/platform/internal/bootstrap"
)

func writeIssuerKeys(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "issuer-keys.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func validIssuerKeys(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := (&jose.JSONWebKey{Key: &key.PublicKey, KeyID: "k1", Use: "sig", Algorithm: "ES256"}).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return writeIssuerKeys(t, `[{"issuer":"https://issuer.example","kid":"k1","jwk":`+string(jwk)+`}]`)
}

func labEnv(t *testing.T, overrides map[string]string) {
	t.Helper()
	values := map[string]string{
		"HUKID_ENV":                     "",
		"HUKID_OID4VP_LAB":              "local",
		"HUKID_OID4VP_LAB_CLIENT_ID":    "x509_san_dns:verifier.example",
		"HUKID_OID4VP_LAB_RESPONSE_URI": "https://verifier.example/oid4vp/response",
		"HUKID_OID4VP_LAB_ISSUER_KEYS":  validIssuerKeys(t),
	}
	for k, v := range overrides {
		values[k] = v
	}
	for k, v := range values {
		t.Setenv(k, v)
	}
}

func TestLabIsOffUnlessExplicitlyConfigured(t *testing.T) {
	for _, name := range []string{"HUKID_OID4VP_LAB", "HUKID_OID4VP_LAB_CLIENT_ID", "HUKID_OID4VP_LAB_RESPONSE_URI", "HUKID_OID4VP_LAB_ISSUER_KEYS"} {
		t.Setenv(name, "")
	}
	var out bytes.Buffer
	routes, err := configureOID4VPLab(&out, nil)
	if routes != nil || err != nil || out.Len() != 0 {
		t.Fatalf("%v %v %q", routes != nil, err, out.String())
	}
	// With the lab off the endpoints do not exist.
	handler := bootstrap.Handler()
	for _, target := range []string{oid4vphttp.ResponsePath, oid4vphttp.RequestPathPrefix + "x"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: %d", target, rec.Code)
		}
	}
}

func TestLabRejectsIncompleteOrUnsafeConfiguration(t *testing.T) {
	cases := map[string]map[string]string{
		"flag not an environment": {"HUKID_OID4VP_LAB": "1"},
		"flag staging":            {"HUKID_OID4VP_LAB": "staging"},
		"missing client id":       {"HUKID_OID4VP_LAB_CLIENT_ID": ""},
		"missing response uri":    {"HUKID_OID4VP_LAB_RESPONSE_URI": ""},
		"missing keys":            {"HUKID_OID4VP_LAB_ISSUER_KEYS": ""},
		"staging":                 {"HUKID_ENV": "staging"},
		"production":              {"HUKID_ENV": "production"},
		"environment mismatch":    {"HUKID_ENV": "test"},
		"http response uri":       {"HUKID_OID4VP_LAB_RESPONSE_URI": "http://verifier.example/oid4vp/response"},
		"wrong path":              {"HUKID_OID4VP_LAB_RESPONSE_URI": "https://verifier.example/other"},
		"query in uri":            {"HUKID_OID4VP_LAB_RESPONSE_URI": "https://verifier.example/oid4vp/response?x=1"},
		"missing key file":        {"HUKID_OID4VP_LAB_ISSUER_KEYS": filepath.Join(t.TempDir(), "absent.json")},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			labEnv(t, overrides)
			var out bytes.Buffer
			routes, err := configureOID4VPLab(&out, nil)
			if routes != nil || err == nil || out.Len() != 0 {
				t.Fatalf("accepted: routes=%v err=%v out=%q", routes != nil, err, out.String())
			}
		})
	}
}

func TestLabRejectsBadIssuerKeyFiles(t *testing.T) {
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privateJWK, _ := (&jose.JSONWebKey{Key: private, KeyID: "k"}).MarshalJSON()
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384JWK, _ := (&jose.JSONWebKey{Key: &p384.PublicKey, KeyID: "k"}).MarshalJSON()
	cases := map[string]string{
		"empty list":      `[]`,
		"not json":        `nope`,
		"unknown field":   `[{"issuer":"i","kid":"k","jwk":{},"extra":1}]`,
		"trailing data":   `[] []`,
		"private key":     `[{"issuer":"i","kid":"k","jwk":` + string(privateJWK) + `}]`,
		"wrong curve":     `[{"issuer":"i","kid":"k","jwk":` + string(p384JWK) + `}]`,
		"missing issuer":  `[{"kid":"k","jwk":` + string(p384JWK) + `}]`,
		"oversize":        strings.Repeat(" ", labMaxKeysFile+1),
		"jwk not a key":   `[{"issuer":"i","kid":"k","jwk":{"kty":"oct","k":"AAAA"}}]`,
		"missing jwk":     `[{"issuer":"i","kid":"k"}]`,
		"jwk is a string": `[{"issuer":"i","kid":"k","jwk":"x"}]`,
	}
	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			labEnv(t, map[string]string{"HUKID_OID4VP_LAB_ISSUER_KEYS": writeIssuerKeys(t, contents)})
			if routes, err := configureOID4VPLab(&bytes.Buffer{}, nil); routes != nil || err == nil {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}

// field returns the value after "oid4vp-lab <name> " on the first matching line.
func field(t *testing.T, out, name string) string {
	t.Helper()
	prefix := "oid4vp-lab " + name + " "
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	t.Fatalf("no %q line in %q", name, out)
	return ""
}

func TestLabServesAnExternalWalletEndToEnd(t *testing.T) {
	labEnv(t, nil)
	var out bytes.Buffer
	clock := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	routes, err := configureOID4VPLab(&out, func() time.Time { return clock })
	if err != nil || routes == nil {
		t.Fatalf("%v", err)
	}
	handler := bootstrap.Handler(routes)

	launch, err := url.Parse(field(t, out.String(), "launch"))
	if err != nil || launch.Scheme != "openid4vp" {
		t.Fatalf("launch: %v %v", launch, err)
	}
	query := launch.Query()
	if query.Get("client_id") != "x509_san_dns:verifier.example" || query.Get("request_uri_method") != "get" {
		t.Fatalf("launch query: %v", query)
	}
	requestURI, err := url.Parse(query.Get("request_uri"))
	if err != nil || requestURI.Host != "verifier.example" {
		t.Fatalf("request_uri: %v %v", requestURI, err)
	}

	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, requestURI.Path, nil))
	if get.Code != http.StatusOK {
		t.Fatalf("request object: %d %s", get.Code, get.Body)
	}
	var pinned jose.JSONWebKey
	if err := pinned.UnmarshalJSON([]byte(field(t, out.String(), "request-signing-key"))); err != nil {
		t.Fatal(err)
	}
	object, err := jose.ParseSigned(get.Body.String(), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := object.Verify(pinned.Key)
	if err != nil {
		t.Fatalf("the printed key does not verify the request object: %v", err)
	}
	var claims struct {
		ClientMetadata struct {
			JWKS jose.JSONWebKeySet `json:"jwks"`
		} `json:"client_metadata"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || len(claims.ClientMetadata.JWKS.Keys) != 1 {
		t.Fatalf("claims: %v", err)
	}

	encryptionKey := claims.ClientMetadata.JWKS.Keys[0]
	plaintext, _ := json.Marshal(map[string]any{"vp_token": map[string][]string{"credential": {"junk-vp-token"}}, "state": claims.State})
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: encryptionKey.Key, KeyID: encryptionKey.KeyID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jwe, _ := encrypter.Encrypt(plaintext)
	compact, _ := jwe.CompactSerialize()
	post := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, oid4vphttp.ResponsePath, strings.NewReader(url.Values{"response": {compact}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(post, request)
	if post.Code != http.StatusOK {
		t.Fatalf("response: %d %s", post.Code, post.Body)
	}

	report := field(t, out.String(), "report")
	if !strings.Contains(report, `"technicalResult":"invalid"`) {
		t.Fatalf("report: %s", report)
	}
	// Nothing credential-bearing reaches the operator output besides the launch URI.
	for _, secret := range []string{"junk-vp-token", compact, claims.State + "\"", "nonce"} {
		if strings.Contains(report, secret) {
			t.Fatalf("the report output leaks %q", secret)
		}
	}
	// The one seeded session is consumed.
	again := httptest.NewRecorder()
	handler.ServeHTTP(again, httptest.NewRequest(http.MethodGet, requestURI.Path, nil))
	if again.Code != http.StatusNotFound {
		t.Fatalf("session reusable after its response: %d", again.Code)
	}
}

package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"hukid.local/platform/internal/authentication"
)

type signingFixture struct {
	mu           sync.Mutex
	key          *ecdsa.PrivateKey
	kid          string
	server       *httptest.Server
	policy       authentication.Policy
	now          time.Time
	client       *Client
	tokenHandler http.Handler
}

func newSigningFixture(t *testing.T) *signingFixture {
	t.Helper()
	f, err := os.Open("../../../config/auth.test.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := authentication.LoadPolicy(f, "test")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := &signingFixture{key: key, kid: "unit-1", policy: p, now: time.Unix(2000000000, 0)}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			s.mu.Lock()
			handler := s.tokenHandler
			s.mu.Unlock()
			if handler == nil {
				w.WriteHeader(404)
			} else {
				handler.ServeHTTP(w, r)
			}
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": s.server.URL, "authorization_endpoint": s.server.URL + "/auth", "token_endpoint": s.server.URL + "/token", "jwks_uri": s.server.URL + "/jwks", "authorization_response_iss_parameter_supported": true, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"}, "id_token_signing_alg_values_supported": []string{"ES256"}})
		case "/jwks":
			s.mu.Lock()
			defer s.mu.Unlock()
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &s.key.PublicKey, KeyID: s.kid, Algorithm: "ES256", Use: "sig"}}})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(s.server.Close)
	s.policy.Issuer = s.server.URL
	s.client, err = New(context.Background(), s.policy, "ephemeral-test-client", func() time.Time { return s.now })
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func (s *signingFixture) sign(t *testing.T, claims map[string]any, typ string) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: s.key}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader(jose.HeaderKey("kid"), s.kid))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	result, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func (s *signingFixture) claims() (map[string]any, map[string]any) {
	common := func() map[string]any {
		return map[string]any{"iss": s.policy.Issuer, "sub": "operator-test", "iat": s.now.Unix(), "exp": s.now.Unix() + 300, "auth_time": s.now.Unix(), "amr": []string{"pwd", "otp"}, "acr": s.policy.AcceptedACR[0]}
	}
	id, access := common(), common()
	id["aud"] = s.policy.ClientID
	id["nonce"] = "expected-nonce"
	access["aud"] = s.policy.Audience
	access["client_id"] = s.policy.ClientID
	access["hukid_token_class"] = "operator"
	access["hukid_grant"] = "authorization_code"
	access["scope"] = "operator:read"
	access["jti"] = "unit-jti"
	return id, access
}
func TestVerifyOIDCEvidenceAndRejectTokenConfusion(t *testing.T) {
	s := newSigningFixture(t)
	for _, name := range []string{"valid", "issuer", "subject", "nonce", "aud_array", "aud_wrong", "class", "grant", "client", "scope", "jti", "expired", "deadline", "future_iat", "future_nbf", "lifetime", "missing_auth", "mfa", "amr_mismatch", "id_aud", "azp", "signature", "kid", "typ", "id_as_access"} {
		t.Run(name, func(t *testing.T) {
			id, access := s.claims()
			typ := "at+jwt"
			switch name {
			case "issuer":
				access["iss"] = "http://127.0.0.1:1"
			case "subject":
				access["sub"] = "other"
			case "nonce":
				id["nonce"] = "other"
			case "aud_array":
				access["aud"] = []string{s.policy.Audience}
			case "aud_wrong":
				access["aud"] = "integration"
			case "class":
				access["hukid_token_class"] = "integration"
			case "grant":
				access["hukid_grant"] = "client_credentials"
			case "client":
				access["client_id"] = "other"
			case "scope":
				access["scope"] = "operator:write"
			case "jti":
				delete(access, "jti")
			case "expired":
				access["exp"] = s.now.Unix() - 1
			case "deadline":
				access["exp"] = s.now.Unix()
			case "future_iat":
				access["iat"] = s.now.Unix() + 31
				access["exp"] = s.now.Unix() + 331
			case "future_nbf":
				id["nbf"] = s.now.Unix() + 31
			case "lifetime":
				access["exp"] = s.now.Unix() + 301
			case "missing_auth":
				delete(access, "auth_time")
			case "mfa":
				id["amr"] = []string{"pwd"}
				access["amr"] = []string{"pwd"}
			case "amr_mismatch":
				access["amr"] = []string{"pwd", "otp", "other"}
			case "id_aud":
				id["aud"] = []string{s.policy.ClientID, "other"}
			case "azp":
				id["azp"] = "other"
			case "typ":
				typ = "JWT"
			}
			rawID, rawAccess := s.sign(t, id, "JWT"), s.sign(t, access, typ)
			if name == "id_as_access" {
				rawAccess = rawID
			}
			if name == "signature" {
				other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				previous := s.key
				s.key = other
				rawAccess = s.sign(t, access, typ)
				s.key = previous
			}
			if name == "kid" {
				s.kid = "not-published"
				rawAccess = s.sign(t, access, typ)
				s.kid = "unit-1"
			}
			_, err := s.client.Validate(context.Background(), rawID, rawAccess, authentication.Digest("expected-nonce"))
			if (err == nil) != (name == "valid") {
				t.Fatalf("unexpected verification outcome for %s", name)
			}
		})
	}
	// A newly published key is fetched on an unknown kid; old keys are never invented.
	s.mu.Lock()
	s.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s.kid = "unit-rotated"
	s.mu.Unlock()
	id, access := s.claims()
	if _, err := s.client.Validate(context.Background(), s.sign(t, id, "JWT"), s.sign(t, access, "at+jwt"), authentication.Digest("expected-nonce")); err != nil {
		t.Fatal("key rotation failed")
	}
}

func TestDiscoveryRejectsForeignAuthorityAndRedirects(t *testing.T) {
	for _, mode := range []string{"metadata", "redirect", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "redirect" {
					http.Redirect(w, r, "http://127.0.0.1:1/metadata", 302)
					return
				}
				if mode == "oversize" {
					w.Write(make([]byte, (1<<20)+1))
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"issuer": server.URL, "authorization_endpoint": "http://127.0.0.1:1/auth", "token_endpoint": server.URL + "/token", "jwks_uri": server.URL + "/jwks", "authorization_response_iss_parameter_supported": true, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"}, "id_token_signing_alg_values_supported": []string{"ES256"}})
			}))
			defer server.Close()
			f, _ := os.Open("../../../config/auth.test.json")
			defer f.Close()
			p, _ := authentication.LoadPolicy(f, "test")
			p.Issuer = server.URL
			if _, err := New(context.Background(), p, "ephemeral", time.Now); err == nil {
				t.Fatal("untrusted discovery accepted")
			}
		})
	}
}

func TestDuplicateClaimsAreRejectedBeforeVerification(t *testing.T) {
	for _, payload := range []string{`{"iss":"one","iss":"two"}`, `[]`, `{"sub":"x"} {"sub":"y"}`, `{"sub":`} {
		if uniqueClaims([]byte(payload)) {
			t.Fatal("ambiguous claims accepted")
		}
	}
	if !uniqueClaims([]byte(`{"iss":"one","aud":["client"]}`)) {
		t.Fatal("valid structure rejected")
	}
}

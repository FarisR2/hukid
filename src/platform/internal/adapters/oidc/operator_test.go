package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestBearerVerifierRejectsUntrustedAuthority(t *testing.T) {
	s := newSigningFixture(t)
	for _, name := range []string{"valid", "integration", "oid4vci", "missing_class", "id_token", "aud_array", "aud_multiple", "issuer", "client", "grant", "scope", "subject", "expired", "future", "mfa", "stale_mfa", "signature", "unknown_kid"} {
		t.Run(name, func(t *testing.T) {
			_, e := s.claims()
			typ := "at+jwt"
			switch name {
			case "integration", "oid4vci":
				e["hukid_token_class"] = name
			case "missing_class":
				delete(e, "hukid_token_class")
			case "id_token":
				typ = "JWT"
				e["aud"] = s.policy.ClientID
			case "aud_array":
				e["aud"] = []string{s.policy.Audience}
			case "aud_multiple":
				e["aud"] = []string{s.policy.Audience, "other"}
			case "issuer":
				e["iss"] = "https://foreign.invalid"
			case "client":
				e["client_id"] = "foreign"
			case "grant":
				e["hukid_grant"] = "client_credentials"
			case "scope":
				e["scope"] = "openid"
			case "subject":
				e["sub"] = ""
			case "expired":
				e["exp"] = s.now.Unix()
			case "future":
				e["nbf"] = s.now.Unix() + 31
			case "mfa":
				e["amr"] = []string{"pwd"}
			case "stale_mfa":
				e["auth_time"] = s.now.Unix() - int64(s.policy.SessionAbsoluteSeconds)
			}
			raw := s.sign(t, e, typ)
			if name == "signature" {
				original := s.key
				s.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				raw = s.sign(t, e, typ)
				s.key = original
			}
			if name == "unknown_kid" {
				s.kid = "unpublished"
				raw = s.sign(t, e, typ)
				s.kid = "unit-1"
			}
			actor, err := s.client.VerifyOperator(context.Background(), raw)
			if (err == nil) != (name == "valid") {
				t.Fatalf("unexpected outcome for %s", name)
			}
			if err == nil && (actor.Issuer != s.policy.Issuer || actor.Subject != "operator-test") {
				t.Fatal("wrong identity")
			}
		})
	}
}

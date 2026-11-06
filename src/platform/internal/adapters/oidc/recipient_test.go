package oidc

import (
	"context"
	a "hukid.local/platform/internal/authentication"
	"testing"
)

func TestRecipientEvidenceOnlyFromVerifiedIDToken(t *testing.T) {
	s := newSigningFixture(t)
	for _, name := range []string{"verified", "false", "string", "missing", "access_only", "wrong_nonce", "wrong_subject", "wrong_audience"} {
		t.Run(name, func(t *testing.T) {
			id, access := s.claims()
			id["email"] = "recipient@example.invalid"
			id["email_verified"] = true
			switch name {
			case "false":
				id["email_verified"] = false
			case "string":
				id["email_verified"] = "true"
			case "missing":
				delete(id, "email_verified")
			case "access_only":
				delete(id, "email")
				delete(id, "email_verified")
				access["email"] = "recipient@example.invalid"
				access["email_verified"] = true
			case "wrong_nonce":
				id["nonce"] = "foreign"
			case "wrong_subject":
				id["sub"] = "foreign"
			case "wrong_audience":
				id["aud"] = "foreign"
			}
			verified, err := s.client.Validate(context.Background(), s.sign(t, id, "JWT"), s.sign(t, access, "at+jwt"), a.Digest("expected-nonce"))
			invalid := name == "wrong_nonce" || name == "wrong_subject" || name == "wrong_audience"
			if (err != nil) != invalid {
				t.Fatal("unexpected token validation", err)
			}
			if !invalid && ((verified.Recipient != nil) != (name == "verified")) {
				t.Fatal("unverified recipient evidence")
			}
		})
	}
}

package oidc

import (
	"context"
	"errors"
	a "hukid.local/platform/internal/authentication"
	"net/url"
	"testing"
)

func TestReauthenticationRequestsAndVerifiedFreshness(t *testing.T) {
	s := newSigningFixture(t)
	u, _ := url.Parse(s.client.ReauthenticationURL("state", "nonce", "challenge"))
	q := u.Query()
	for key, want := range map[string]string{"prompt": "login consent", "max_age": "0", "state": "state", "nonce": "nonce", "code_challenge": "challenge", "code_challenge_method": "S256", "acr_values": s.policy.AcceptedACR[0]} {
		if q.Get(key) != want {
			t.Fatalf("missing reauthentication parameter %s", key)
		}
	}
	for _, age := range []int64{0, int64(s.policy.StepUpSeconds) - 1, int64(s.policy.StepUpSeconds), int64(s.policy.StepUpSeconds) + 1} {
		_, e := s.claims()
		e["auth_time"] = s.now.Unix() - age
		raw := s.sign(t, e, "at+jwt")
		_, err := s.client.VerifyPrivilegedOperator(context.Background(), raw)
		if age < int64(s.policy.StepUpSeconds) {
			if err != nil {
				t.Fatal(err)
			}
		} else if !errors.Is(err, a.ErrStepUp) {
			t.Fatal("stale signed MFA authorized privileged operation")
		}
	}
	_, e := s.claims()
	e["exp"] = s.now.Unix()
	e["iat"] = s.now.Unix() - 60
	raw := s.sign(t, e, "at+jwt")
	if _, err := s.client.VerifyOperator(context.Background(), raw); err == nil {
		t.Fatal("expired authority accepted")
	}
	if _, err := s.client.VerifyPrivilegedOperator(context.Background(), raw); err == nil {
		t.Fatal("expired privilege accepted")
	}
	if _, err := s.client.SessionIdentity(context.Background(), raw); err != nil {
		t.Fatal("signed historical identity unavailable for reauthentication")
	}
	e["hukid_token_class"] = "integration"
	if _, err := s.client.SessionIdentity(context.Background(), s.sign(t, e, "at+jwt")); err == nil {
		t.Fatal("foreign historical class accepted")
	}
}

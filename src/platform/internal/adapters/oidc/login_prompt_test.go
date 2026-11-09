package oidc

import (
	"net/url"
	"testing"
)

// Every interactive login must show the provider's credential form. The console
// logout is local only, so without prompt=login a live provider session would let
// the browser re-enter silently after "Cerrar sesión".
func TestAuthorizationURLAlwaysForcesCredentials(t *testing.T) {
	s := newSigningFixture(t)
	u, err := url.Parse(s.client.AuthorizationURL("state", "nonce", "challenge"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("prompt") != "login consent" {
		t.Fatalf("login must force credentials and keep offline consent, got %q", q.Get("prompt"))
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("acr_values") != s.policy.AcceptedACR[0] {
		t.Fatal("login lost PKCE or ACR parameters")
	}
}

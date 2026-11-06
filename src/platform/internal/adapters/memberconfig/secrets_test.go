package memberconfig

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestInvitationSecretsAreCompleteTestOnlyAndSeparate(t *testing.T) {
	valid := map[string]string{"HUKID_ENV": "test", "HUKID_INVITATION_KEY": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))), "HUKID_INVITATION_HMAC_KEY": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32))), "HUKID_INVITATION_KEY_VERSION": "test-v1", "HUKID_AUTH_KEY": "", "HUKID_MEMBERS_CURSOR_KEY": ""}
	reset := func() {
		for k, v := range valid {
			t.Setenv(k, v)
		}
	}
	for _, key := range []string{"HUKID_ENV", "HUKID_INVITATION_KEY", "HUKID_INVITATION_HMAC_KEY", "HUKID_INVITATION_KEY_VERSION"} {
		reset()
		t.Setenv(key, "")
		if _, e := Load(); e == nil {
			t.Fatal("partial configuration accepted", key)
		}
	}
	for _, tc := range []struct{ k, v string }{{"HUKID_ENV", "production"}, {"HUKID_INVITATION_KEY", "bad-base64"}, {"HUKID_INVITATION_KEY_VERSION", strings.Repeat("x", 129)}, {"HUKID_INVITATION_HMAC_KEY", valid["HUKID_INVITATION_KEY"]}, {"HUKID_AUTH_KEY", valid["HUKID_INVITATION_KEY"]}, {"HUKID_MEMBERS_CURSOR_KEY", valid["HUKID_INVITATION_HMAC_KEY"]}} {
		reset()
		t.Setenv(tc.k, tc.v)
		if _, e := Load(); e == nil {
			t.Fatal("unsafe keys accepted", tc.k)
		}
	}
	reset()
	s, e := Load()
	if e != nil || s == nil {
		t.Fatal(e)
	}
	s.Clear()
	for _, name := range []string{"HUKID_INVITATION_KEY", "HUKID_INVITATION_HMAC_KEY", "HUKID_INVITATION_KEY_VERSION"} {
		t.Setenv(name, "")
	}
	if s, e := Load(); e != nil || s != nil {
		t.Fatal("optional configuration rejected")
	}
}

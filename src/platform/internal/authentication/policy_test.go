package authentication

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func testPolicy(t *testing.T) Policy {
	t.Helper()
	data, err := os.ReadFile("../../config/auth.test.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(bytes.NewReader(data), "test")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPolicyRejectsMissingFieldsAndUnsafeValues(t *testing.T) {
	p := testPolicy(t)
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var original map[string]any
	if err := json.Unmarshal(encoded, &original); err != nil {
		t.Fatal(err)
	}
	for key := range original {
		t.Run("missing_"+key, func(t *testing.T) {
			var fields map[string]any
			json.Unmarshal(encoded, &fields)
			delete(fields, key)
			data, _ := json.Marshal(fields)
			if _, err := LoadPolicy(bytes.NewReader(data), "test"); err == nil {
				t.Fatal("missing field accepted")
			}
		})
	}
	for _, environment := range []string{"", "development", "production"} {
		if _, err := LoadPolicy(bytes.NewReader(encoded), environment); err == nil {
			t.Fatal("test policy escaped test environment")
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*Policy)
	}{
		{"foreign_issuer", func(p *Policy) { p.Issuer = "https://identity.example.invalid" }},
		{"open_host", func(p *Policy) { p.ConsoleOrigin = "http://0.0.0.0:8080" }},
		{"bad_callback", func(p *Policy) { p.RedirectURI = "http://127.0.0.1:8080/other" }},
		{"audience", func(p *Policy) { p.Audience = "https://api.hukid.pe/integration" }},
		{"skew", func(p *Policy) { p.ClockSkewSeconds = 61 }},
		{"idle", func(p *Policy) { p.SessionIdleSeconds = p.SessionAbsoluteSeconds + 1 }},
		{"refresh", func(p *Policy) { p.RefreshTokenSeconds = p.SessionAbsoluteSeconds + 1 }},
		{"step_up", func(p *Policy) { p.StepUpSeconds = p.SessionIdleSeconds + 1 }},
		{"rate_limit", func(p *Policy) { p.LoginRateLimit.MaxAttempts = 0 }},
		{"return_to", func(p *Policy) { p.AllowedReturnTo = []string{"//example.invalid"} }},
		{"mfa", func(p *Policy) { p.RequiredAMR = []string{"pwd"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := p
			tc.change(&candidate)
			if candidate.Validate("test") == nil {
				t.Fatal("unsafe policy accepted")
			}
		})
	}
	for _, data := range []string{"{}", string(encoded) + " {}", string(encoded[:len(encoded)-1]) + `,"unknown":true}`, "null"} {
		if _, err := LoadPolicy(bytes.NewBufferString(data), "test"); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
}

func TestMFAFreshnessBoundaries(t *testing.T) {
	p := testPolicy(t)
	now := time.Unix(100000, 0)
	for _, tc := range []struct {
		name          string
		age           int
		methods       []string
		acr           string
		stepUp, valid bool
	}{
		{"fresh", 0, []string{"pwd", "otp"}, "urn:hukid:test:mfa", true, true},
		{"before_step_up_limit", 299, []string{"pwd", "otp"}, "urn:hukid:test:mfa", true, true},
		{"at_step_up_limit", 300, []string{"pwd", "otp"}, "urn:hukid:test:mfa", true, false},
		{"at_absolute_limit", 28800, []string{"pwd", "otp"}, "urn:hukid:test:mfa", false, false},
		{"no_second_factor", 0, []string{"pwd"}, "urn:hukid:test:mfa", false, false},
		{"wrong_assurance", 0, []string{"pwd", "otp"}, "unknown", false, false},
		{"future_at_skew", -30, []string{"pwd", "otp"}, "urn:hukid:test:mfa", true, true},
		{"future_beyond_skew", -31, []string{"pwd", "otp"}, "urn:hukid:test:mfa", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := p.CheckMFA(now.Add(-time.Duration(tc.age)*time.Second), now, tc.methods, tc.acr, tc.stepUp)
			if (err == nil) != tc.valid {
				t.Fatalf("unexpected MFA result: %v", err)
			}
		})
	}
	if p.CheckMFA(time.Time{}, now, []string{"pwd", "otp"}, "urn:hukid:test:mfa", false) == nil {
		t.Fatal("zero auth_time accepted")
	}
}

func TestSessionIdleAndAbsoluteBoundaries(t *testing.T) {
	p := testPolicy(t)
	created := time.Unix(100000, 0)
	if p.SessionExpired(created, created, created.Add(1799*time.Second)) {
		t.Fatal("session expired too early")
	}
	if !p.SessionExpired(created, created, created.Add(1800*time.Second)) {
		t.Fatal("idle boundary not enforced")
	}
	lastSeen := created.Add(28799 * time.Second)
	if p.SessionExpired(created, lastSeen, lastSeen) {
		t.Fatal("absolute lifetime shortened")
	}
	if !p.SessionExpired(created, lastSeen, created.Add(28800*time.Second)) {
		t.Fatal("absolute boundary not enforced")
	}
	if !p.SessionExpired(created, created.Add(-time.Second), created) {
		t.Fatal("invalid timestamp ordering accepted")
	}
}

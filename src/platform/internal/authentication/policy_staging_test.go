package authentication

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func stagingFields(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("../../config/auth.staging.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func loadAs(fields map[string]any, environment string) error {
	data, _ := json.Marshal(fields)
	_, err := LoadPolicy(bytes.NewReader(data), environment)
	return err
}

func TestStagingPolicyAcceptsTemplateOnlyAsStaging(t *testing.T) {
	fields := stagingFields(t)
	if err := loadAs(fields, "staging"); err != nil {
		t.Fatalf("staging template rejected: %v", err)
	}
	for _, environment := range []string{"local", "test", "", "production"} {
		if err := loadAs(fields, environment); err == nil {
			t.Fatalf("staging policy accepted as %q", environment)
		}
	}
}

func TestStagingPolicyRejectsUnsafeVariants(t *testing.T) {
	cases := map[string]map[string]any{
		"http issuer":          {"issuer": "http://id.example.com/realms/hukid"},
		"loopback issuer":      {"issuer": "https://127.0.0.1/realms/hukid"},
		"localhost issuer":     {"issuer": "https://localhost/realms/hukid"},
		"issuer with port":     {"issuer": "https://id.example.com:8443/realms/hukid"},
		"issuer without realm": {"issuer": "https://id.example.com"},
		"issuer trailing":      {"issuer": "https://id.example.com/realms/hukid/"},
		"uppercase host":       {"issuer": "https://ID.example.com/realms/hukid"},
		"internal suffix":      {"issuer": "https://id.corp.internal/realms/hukid"},
		"http console":         {"consoleOrigin": "http://app.example.com", "redirectUri": "http://app.example.com/console/auth/callback"},
		"console with path":    {"consoleOrigin": "https://app.example.com/app", "redirectUri": "https://app.example.com/app/console/auth/callback"},
		"ip console":           {"consoleOrigin": "https://10.0.0.5", "redirectUri": "https://10.0.0.5/console/auth/callback"},
		"same origin":          {"issuer": "https://app.example.com/realms/hukid"},
		"redirect mismatch":    {"redirectUri": "https://app.example.com/other"},
		"insecure cookie":      {"cookieSecure": false},
		"no host prefix":       {"cookieName": "hukid_session"},
		"samesite none":        {"cookieSameSite": "None"},
		"wrong client":         {"clientId": "hukid-console-test"},
		"wrong audience":       {"audience": "https://api.example.com"},
		"no otp":               {"requiredAmr": []string{"pwd"}},
		"empty acr":            {"acceptedAcr": []string{}},
		"acr zero":             {"acceptedAcr": []string{"0"}},
	}
	for name, override := range cases {
		fields := stagingFields(t)
		for key, value := range override {
			fields[key] = value
		}
		if err := loadAs(fields, "staging"); err == nil {
			t.Errorf("%s: staging policy accepted", name)
		}
	}
}

func TestLocalAndTestStillRejectPublicHTTPS(t *testing.T) {
	fields := localPolicyFields(t)
	fields["issuer"] = "https://id.example.com/realms/hukid"
	if err := loadLocal(fields, "local"); err == nil {
		t.Fatal("local accepted a public https issuer")
	}
	fields = localPolicyFields(t)
	fields["cookieSecure"] = true
	if err := loadLocal(fields, "local"); err == nil {
		t.Fatal("local accepted a secure cookie")
	}
}

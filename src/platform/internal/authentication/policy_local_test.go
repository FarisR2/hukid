package authentication

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func localPolicyFields(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("../../config/auth.local.json")
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func loadLocal(fields map[string]any, environment string) error {
	data, _ := json.Marshal(fields)
	_, err := LoadPolicy(bytes.NewReader(data), environment)
	return err
}

func TestLocalPolicyAcceptsShippedFileOnlyAsLocal(t *testing.T) {
	fields := localPolicyFields(t)
	if err := loadLocal(fields, "local"); err != nil {
		t.Fatalf("shipped local policy rejected: %v", err)
	}
	for _, environment := range []string{"test", "", "production", "development"} {
		if err := loadLocal(fields, environment); err == nil {
			t.Fatalf("local policy accepted as %q", environment)
		}
	}
}

func TestTestPolicyIsNotAcceptedAsLocal(t *testing.T) {
	data, err := os.ReadFile("../../config/auth.test.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(bytes.NewReader(data), "local"); err == nil {
		t.Fatal("test policy accepted as local")
	}
}

func TestLocalPolicyRejectsUnsafeValues(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"remote issuer":        func(f map[string]any) { f["issuer"] = "http://idp.example.com/realms/hukid" },
		"https issuer":         func(f map[string]any) { f["issuer"] = "https://127.0.0.1:8081/realms/hukid" },
		"issuer without realm": func(f map[string]any) { f["issuer"] = "http://127.0.0.1:8081" },
		"issuer odd path":      func(f map[string]any) { f["issuer"] = "http://127.0.0.1:8081/realms/hukid/extra" },
		"issuer query":         func(f map[string]any) { f["issuer"] = "http://127.0.0.1:8081/realms/hukid?x=1" },
		"test client":          func(f map[string]any) { f["clientId"] = "hukid-console-test" },
		"test cookie":          func(f map[string]any) { f["cookieName"] = "hukid_test_session" },
		"secure cookie":        func(f map[string]any) { f["cookieSecure"] = true },
		"no acr":               func(f map[string]any) { f["acceptedAcr"] = []string{} },
		"empty acr":            func(f map[string]any) { f["acceptedAcr"] = []string{""} },
		"zero acr":             func(f map[string]any) { f["acceptedAcr"] = []string{"0"} },
		"password only":        func(f map[string]any) { f["requiredAmr"] = []string{"pwd"} },
		"no amr":               func(f map[string]any) { f["requiredAmr"] = []string{} },
		"wide return":          func(f map[string]any) { f["allowedReturnTo"] = []string{"/", "/x"} },
		"extra scope": func(f map[string]any) {
			f["scopes"] = []string{"openid", "email", "offline_access", "operator:read", "admin"}
		},
		"same origin": func(f map[string]any) { f["issuer"] = "http://127.0.0.1:5173/realms/hukid" },
	} {
		t.Run(name, func(t *testing.T) {
			fields := localPolicyFields(t)
			mutate(fields)
			if err := loadLocal(fields, "local"); err == nil {
				t.Fatal("unsafe local policy accepted")
			}
		})
	}
}

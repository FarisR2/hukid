package main

import (
	"encoding/base64"
	"testing"
)

func TestAuthConfigurationIsExplicitAndTestOnly(t *testing.T) {
	for _, tc := range []struct {
		name, environment, file string
		valid                   bool
	}{
		{"liveness_only", "", "", true},
		{"isolated_test", "test", "../../config/auth.test.json", true},
		{"missing_environment", "", "../../config/auth.test.json", false},
		{"missing_policy", "test", "", false},
		{"production_rejects_fixture", "production", "../../config/auth.test.json", false},
		{"missing_file", "test", "../../config/absent.json", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HUKID_ENV", tc.environment)
			t.Setenv("HUKID_AUTH_POLICY", tc.file)
			for _, name := range []string{"HUKID_SESSION_DATABASE_URL", "HUKID_OIDC_CLIENT_SECRET", "HUKID_AUTH_KEY", "HUKID_AUTH_KEY_VERSION", "HUKID_CONTEXT_DATABASE_URL", "HUKID_TENANT_DATABASE_URL"} {
				t.Setenv(name, "")
			}
			if tc.name == "isolated_test" {
				t.Setenv("HUKID_SESSION_DATABASE_URL", "postgresql://127.0.0.1:5432/hukid_test_config?sslmode=disable")
				t.Setenv("HUKID_CONTEXT_DATABASE_URL", "postgresql://127.0.0.1:5432/hukid_test_config?sslmode=disable")
				t.Setenv("HUKID_TENANT_DATABASE_URL", "postgresql://127.0.0.1:5432/hukid_test_config?sslmode=disable")
				t.Setenv("HUKID_OIDC_CLIENT_SECRET", "configuration-test-only")
				t.Setenv("HUKID_AUTH_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
				t.Setenv("HUKID_AUTH_KEY_VERSION", "config-test")
			}
			if err := validateAuthConfiguration(); (err == nil) != tc.valid {
				t.Fatalf("unexpected startup validation: %v", err)
			}
		})
	}
}

func TestPartialRuntimeConfigurationFailsClosed(t *testing.T) {
	valid := map[string]string{
		"HUKID_ENV": "test", "HUKID_AUTH_POLICY": "../../config/auth.test.json",
		"HUKID_SESSION_DATABASE_URL": "postgresql://127.0.0.1:5432/hukid_test_config?sslmode=disable",
		"HUKID_CONTEXT_DATABASE_URL": "postgresql://127.0.0.1:5432/hukid_test_config?sslmode=disable",
		"HUKID_TENANT_DATABASE_URL":  "postgresql://127.0.0.1:5432/hukid_test_config?sslmode=disable",
		"HUKID_OIDC_CLIENT_SECRET":   "configuration-test-only",
		"HUKID_AUTH_KEY":             base64.StdEncoding.EncodeToString(make([]byte, 32)), "HUKID_AUTH_KEY_VERSION": "config-test",
	}
	for missing := range valid {
		t.Run("missing_"+missing, func(t *testing.T) {
			for name, value := range valid {
				t.Setenv(name, value)
			}
			t.Setenv(missing, "")
			if validateAuthConfiguration() == nil {
				t.Fatal("partial authentication configuration accepted")
			}
		})
	}
	for _, tc := range []struct{ name, value string }{
		{"HUKID_AUTH_KEY", "invalid-base64"},
		{"HUKID_AUTH_KEY", base64.StdEncoding.EncodeToString(make([]byte, 16))},
		{"HUKID_SESSION_DATABASE_URL", "postgresql://127.0.0.1:5432/production?sslmode=disable"},
		{"HUKID_SESSION_DATABASE_URL", "postgresql://external.invalid:5432/hukid_test_config?sslmode=disable"},
	} {
		t.Run(tc.name+"_invalid", func(t *testing.T) {
			for name, value := range valid {
				t.Setenv(name, value)
			}
			t.Setenv(tc.name, tc.value)
			if validateAuthConfiguration() == nil {
				t.Fatal("unsafe runtime configuration accepted")
			}
		})
	}
}

package main

import "testing"

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
			if err := validateAuthConfiguration(); (err == nil) != tc.valid {
				t.Fatalf("unexpected startup validation: %v", err)
			}
		})
	}
}

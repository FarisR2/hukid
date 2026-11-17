package main

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"hukid.local/platform/internal/oid4vp"
	"hukid.local/platform/internal/verification"
)

func validVerificationEnv() map[string]string {
	return map[string]string{
		"HUKID_ENV":                       "test",
		"HUKID_AUTH_POLICY":               "../../config/auth.test.json",
		"HUKID_VERIFICATION_DATABASE_URL": "postgresql://127.0.0.1:5432/hukid_test_config?sslmode=disable",
		"HUKID_VERIFICATION_KEY":          base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"HUKID_VERIFICATION_KEY_VERSION":  "synthetic-v1",
		"HUKID_VERIFICATION_ISSUER_KEYS":  "issuer-keys.json",
	}
}

func TestVerificationConfigurationIsOptionalCompleteAndIsolated(t *testing.T) {
	valid := validVerificationEnv()
	for _, missing := range []string{"HUKID_ENV", "HUKID_AUTH_POLICY", "HUKID_VERIFICATION_DATABASE_URL", "HUKID_VERIFICATION_KEY", "HUKID_VERIFICATION_KEY_VERSION", "HUKID_VERIFICATION_ISSUER_KEYS"} {
		t.Run("missing "+missing, func(t *testing.T) {
			for k, v := range valid {
				t.Setenv(k, v)
			}
			t.Setenv(missing, "")
			if _, err := loadVerificationConfiguration(); err == nil {
				t.Fatal("partial configuration accepted")
			}
		})
	}
	for _, tc := range []struct{ name, k, v string }{
		{"production", "HUKID_ENV", "production"},
		{"external database", "HUKID_VERIFICATION_DATABASE_URL", "postgresql://external.invalid/hukid_test_config?sslmode=disable"},
		{"key not base64", "HUKID_VERIFICATION_KEY", "invalid"},
		{"key too short", "HUKID_VERIFICATION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 16))},
		{"version too long", "HUKID_VERIFICATION_KEY_VERSION", strings.Repeat("v", 129)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range valid {
				t.Setenv(k, v)
			}
			t.Setenv(tc.k, tc.v)
			if _, err := loadVerificationConfiguration(); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	for k, v := range valid {
		t.Setenv(k, v)
	}
	config, err := loadVerificationConfiguration()
	if err != nil || config == nil || len(config.Key) != 32 {
		t.Fatalf("valid configuration refused: %v", err)
	}
	clear(config.Key)
	for k := range valid {
		if k != "HUKID_ENV" && k != "HUKID_AUTH_POLICY" {
			t.Setenv(k, "")
		}
	}
	if config, err := loadVerificationConfiguration(); err != nil || config != nil {
		t.Fatal("optional configuration failed")
	}
}

func TestVerificationMountRefusesToCoexistWithTheLaboratoryMount(t *testing.T) {
	for k, v := range validVerificationEnv() {
		t.Setenv(k, v)
	}
	// The refusal comes before any database or file access.
	if _, _, err := configureVerification(context.Background(), nil, true); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("both mounts accepted: %v", err)
	}
}

func TestVerificationMountIsANoOpWhenNotConfigured(t *testing.T) {
	for k := range validVerificationEnv() {
		t.Setenv(k, "")
	}
	register, closeMount, err := configureVerification(context.Background(), nil, true)
	if err != nil || register == nil || closeMount == nil {
		t.Fatalf("unconfigured mount must be inert even beside the laboratory: %v", err)
	}
	register(nil)
	closeMount()
}

func TestTenantVerifiersRefuseAnEmptyTenant(t *testing.T) {
	verifiers := &tenantVerifiers{byTenant: map[string]*verification.Verifier{}}
	if _, err := verifiers.For(""); err != oid4vp.ErrConfig {
		t.Fatalf("empty tenant: %v", err)
	}
}

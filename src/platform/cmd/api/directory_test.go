package main

import (
	"encoding/base64"
	"testing"
)

func TestDirectoryConfigurationIsOptionalCompleteAndIsolated(t *testing.T) {
	valid := map[string]string{"HUKID_ENV": "test", "HUKID_AUTH_POLICY": "../../config/auth.test.json", "HUKID_MEMBERS_POLICY": "../../config/user-management.test.json", "HUKID_MEMBERS_DATABASE_URL": "postgresql://127.0.0.1:5432/hukid_test_config?sslmode=disable", "HUKID_MEMBERS_CURSOR_KEY": base64.StdEncoding.EncodeToString(make([]byte, 32))}
	for _, missing := range []string{"HUKID_ENV", "HUKID_AUTH_POLICY", "HUKID_MEMBERS_POLICY", "HUKID_MEMBERS_DATABASE_URL", "HUKID_MEMBERS_CURSOR_KEY"} {
		t.Run(missing, func(t *testing.T) {
			for k, v := range valid {
				t.Setenv(k, v)
			}
			t.Setenv(missing, "")
			if _, err := loadDirectoryConfiguration(); err == nil {
				t.Fatal("partial members config accepted")
			}
		})
	}
	for _, tc := range []struct{ key, value string }{{"HUKID_ENV", "production"}, {"HUKID_MEMBERS_DATABASE_URL", "postgresql://external.invalid/hukid_test_config?sslmode=disable"}, {"HUKID_MEMBERS_CURSOR_KEY", "invalid"}, {"HUKID_MEMBERS_POLICY", "../../config/auth.test.json"}} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			for k, v := range valid {
				t.Setenv(k, v)
			}
			t.Setenv(tc.key, tc.value)
			if _, err := loadDirectoryConfiguration(); err == nil {
				t.Fatal("unsafe members config accepted")
			}
		})
	}
	for k, v := range valid {
		t.Setenv(k, v)
	}
	config, err := loadDirectoryConfiguration()
	if err != nil || config == nil {
		t.Fatal(err)
	}
	clear(config.Key)
	for _, k := range []string{"HUKID_MEMBERS_POLICY", "HUKID_MEMBERS_DATABASE_URL", "HUKID_MEMBERS_CURSOR_KEY"} {
		t.Setenv(k, "")
	}
	if config, err := loadDirectoryConfiguration(); err != nil || config != nil {
		t.Fatal("optional members config failed")
	}
}

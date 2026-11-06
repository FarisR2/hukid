package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDashboardConfigurationOptionalCompleteAndIsolated(t *testing.T) {
	valid := map[string]string{"HUKID_ENV": "test", "HUKID_AUTH_POLICY": "../../config/auth.test.json", "HUKID_DASHBOARD_POLICY": "../../config/dashboard.test.json", "HUKID_DASHBOARD_DATABASE_URL": "postgresql://127.0.0.1:5432/hukid_test_config?sslmode=disable", "HUKID_DASHBOARD_CURSOR_KEY": base64.StdEncoding.EncodeToString(make([]byte, 32))}
	for _, missing := range []string{"HUKID_ENV", "HUKID_AUTH_POLICY", "HUKID_DASHBOARD_POLICY", "HUKID_DASHBOARD_DATABASE_URL", "HUKID_DASHBOARD_CURSOR_KEY"} {
		t.Run(missing, func(t *testing.T) {
			for k, v := range valid {
				t.Setenv(k, v)
			}
			t.Setenv(missing, "")
			if _, err := loadDashboardConfiguration(); err == nil {
				t.Fatal("partial configuration accepted")
			}
		})
	}
	for _, tc := range []struct{ k, v string }{{"HUKID_ENV", "production"}, {"HUKID_DASHBOARD_DATABASE_URL", "postgresql://external.invalid/hukid_test_config?sslmode=disable"}, {"HUKID_DASHBOARD_CURSOR_KEY", "invalid"}, {"HUKID_DASHBOARD_POLICY", "../../config/auth.test.json"}} {
		t.Run(tc.k+tc.v, func(t *testing.T) {
			for k, v := range valid {
				t.Setenv(k, v)
			}
			t.Setenv(tc.k, tc.v)
			if _, err := loadDashboardConfiguration(); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	for k, v := range valid {
		t.Setenv(k, v)
	}
	c, err := loadDashboardConfiguration()
	if err != nil || c == nil {
		t.Fatal(err)
	}
	clear(c.Key)
	data, err := os.ReadFile("../../config/dashboard.test.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{string(data) + "{}", strings.Replace(string(data), "\"environment\"", "\"unexpected\"", 1), string(data) + strings.Repeat(" ", 8192) + "{}"} {
		path := filepath.Join(t.TempDir(), "policy.json")
		if os.WriteFile(path, []byte(bad), 0600) != nil {
			t.Fatal("fixture")
		}
		t.Setenv("HUKID_DASHBOARD_POLICY", path)
		if _, err := loadDashboardConfiguration(); err == nil {
			t.Fatal("malformed/oversized policy accepted")
		}
	}
	for _, k := range []string{"HUKID_DASHBOARD_POLICY", "HUKID_DASHBOARD_DATABASE_URL", "HUKID_DASHBOARD_CURSOR_KEY"} {
		t.Setenv(k, "")
	}
	if c, err := loadDashboardConfiguration(); err != nil || c != nil {
		t.Fatal("optional configuration failed")
	}
}

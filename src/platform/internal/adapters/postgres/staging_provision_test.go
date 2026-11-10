package postgres

import (
	"context"
	"testing"
)

func TestValidStagingIssuer(t *testing.T) {
	cases := map[string]bool{
		"https://hukid-id.zentrycore.com/realms/hukid":      true,
		"https://hukid-id.zentrycore.com/realms/hukid/":     false,
		"http://hukid-id.zentrycore.com/realms/hukid":       false,
		"https://user:pw@hukid-id.zentrycore.com/r":         false,
		"https://hukid-id.zentrycore.com/realms/hukid?x=1":  false,
		"https://hukid-id.zentrycore.com/realms/hukid#frag": false,
		"https:///realms/hukid":                             false,
		"":                                                  false,
	}
	for issuer, want := range cases {
		if got := validStagingIssuer(issuer); got != want {
			t.Errorf("validStagingIssuer(%q) = %v, want %v", issuer, got, want)
		}
	}
}

func TestConnectStagingDatabaseRejectsBeforeDialing(t *testing.T) {
	good := "postgres://u:p@hukid-staging-db:5432/hukid_staging?sslmode=disable"
	for name, tc := range map[string]struct{ env, dsn string }{
		"wrong environment": {"local", good},
		"empty dsn":         {"staging", ""},
		"wrong database":    {"staging", "postgres://u:p@hukid-staging-db:5432/other?sslmode=disable"},
		"implicit sslmode":  {"staging", "postgres://u:p@hukid-staging-db:5432/hukid_staging"},
		"plaintext to ip":   {"staging", "postgres://u:p@10.0.0.5:5432/hukid_staging?sslmode=disable"},
		"plaintext dotted":  {"staging", "postgres://u:p@db.example.com:5432/hukid_staging?sslmode=disable"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("HUKID_ENV", tc.env)
			if conn, err := ConnectStagingDatabase(context.Background(), tc.dsn); err == nil {
				conn.Close(context.Background())
				t.Fatal("connection accepted")
			}
		})
	}
}

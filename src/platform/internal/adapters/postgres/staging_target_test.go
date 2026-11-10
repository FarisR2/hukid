package postgres

import (
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestStagingTarget(t *testing.T) {
	cases := map[string]bool{
		"postgres://u:p@hukid-db:5432/hukid_staging?sslmode=disable":       true,
		"postgres://u:p@db.example.com:5432/hukid_staging?sslmode=require": true,
		"postgres://u:p@db.example.com:5432/hukid_staging?sslmode=disable": false,
		"postgres://u:p@10.0.0.5:5432/hukid_staging?sslmode=disable":       false,
		"postgres://u:p@10.0.0.5:5432/hukid_staging?sslmode=verify-full":   true,
		"postgres://u:p@hukid-db:5432/hukid_staging":                       false,
		"postgres://u:p@hukid-db:5432/hukid_local?sslmode=disable":         false,
		"postgres://u:p@hukid-db:5432/postgres?sslmode=disable":            false,
		"postgres://u:p@127.0.0.1:5432/hukid_test_x?sslmode=disable":       false,
	}
	for dsn, want := range cases {
		config, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatalf("%s: %v", dsn, err)
		}
		if got := stagingTarget(config); got != want {
			t.Errorf("%s: got %v, want %v", dsn, got, want)
		}
	}
}

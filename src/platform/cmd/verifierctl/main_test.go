package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const tenant = "11111111-1111-4111-8111-111111111111"

// recorder is a Querier that records what would reach the database.
type recorder struct {
	sql  []string
	args [][]any
}

func (r *recorder) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	r.sql = append(r.sql, sql)
	r.args = append(r.args, args)
	return pgconn.CommandTag{}, nil
}

func (r *recorder) QueryRow(context.Context, string, ...any) pgx.Row { panic("unexpected QueryRow") }

func env(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func masterEnv() map[string]string {
	return map[string]string{
		"HUKID_VERIFICATION_KEY":         base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
		"HUKID_VERIFICATION_KEY_VERSION": "synthetic-v1",
	}
}

func TestArgumentsAreValidatedBeforeAnythingConnects(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"unknown"},
		{"configure", tenant, "client"},
		{"configure", tenant, "client", "https://a.example/oid4vp/response", "extra"},
		{"provision-key"},
		{"provision-key", tenant, "extra"},
		{"purge", "30"},
	} {
		if err := validate(args); err == nil {
			t.Fatalf("%v accepted", args)
		}
	}
	for _, args := range [][]string{
		{"configure", tenant, "client", "https://a.example/oid4vp/response"},
		{"provision-key", tenant},
		{"purge", "30", "100"},
	} {
		if err := validate(args); err != nil {
			t.Fatalf("%v rejected: %v", args, err)
		}
	}
}

func TestProvisionKeyPrintsOnlyThePublicKeyAndSendsOnlyASealedEnvelope(t *testing.T) {
	db, out := &recorder{}, &bytes.Buffer{}
	if err := run(context.Background(), db, env(masterEnv()), []string{"provision-key", tenant}, out, rand.Reader); err != nil {
		t.Fatal(err)
	}
	if len(db.sql) != 1 || !strings.Contains(db.sql[0], "rotate_verifier_key") {
		t.Fatalf("statements: %v", db.sql)
	}
	var jwk map[string]any
	line := out.String()[strings.Index(out.String(), "public ")+len("public "):]
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &jwk); err != nil {
		t.Fatalf("public key output: %v", err)
	}
	if _, private := jwk["d"]; private || jwk["kty"] != "EC" || jwk["crv"] != "P-256" || jwk["alg"] != "ES256" || jwk["use"] != "sig" || jwk["kid"] == "" {
		t.Fatalf("unexpected JWK %v", jwk)
	}
	// Arguments: tenant, kid, ciphertext, nonce, key_version, chain. The kid and
	// version are labels; the ciphertext is the sealed key, not the PKCS#8 DER.
	args := db.args[0]
	if len(args) != 6 || args[0] != tenant || args[4] != "synthetic-v1" {
		t.Fatalf("rotate arguments: %v", args)
	}
	if ciphertext, ok := args[2].([]byte); !ok || len(ciphertext) < 16 || bytes.Contains(out.Bytes(), ciphertext) {
		t.Fatalf("ciphertext argument: %v", args[2])
	}
}

func TestProvisionKeyNeedsTheMasterKey(t *testing.T) {
	for name, values := range map[string]map[string]string{
		"none":         {},
		"no version":   {"HUKID_VERIFICATION_KEY": masterEnv()["HUKID_VERIFICATION_KEY"]},
		"not base64":   {"HUKID_VERIFICATION_KEY": "!!", "HUKID_VERIFICATION_KEY_VERSION": "v"},
		"short key":    {"HUKID_VERIFICATION_KEY": base64.StdEncoding.EncodeToString(make([]byte, 16)), "HUKID_VERIFICATION_KEY_VERSION": "v"},
		"long version": {"HUKID_VERIFICATION_KEY": masterEnv()["HUKID_VERIFICATION_KEY"], "HUKID_VERIFICATION_KEY_VERSION": strings.Repeat("v", 129)},
	} {
		db := &recorder{}
		if err := run(context.Background(), db, env(values), []string{"provision-key", tenant}, &bytes.Buffer{}, rand.Reader); err == nil || len(db.sql) != 0 {
			t.Fatalf("%s: accepted (statements %v, err %v)", name, db.sql, err)
		}
	}
}

func TestConfigureRejectsAnUnsafeResponseURIWithoutTouchingTheDatabase(t *testing.T) {
	for _, uri := range []string{
		"http://a.example/oid4vp/response",
		"https://a.example/other",
		"https://a.example/oid4vp/response?x=1",
		"https://a.example/oid4vp/response#f",
		"https://user@a.example/oid4vp/response",
		"",
	} {
		db := &recorder{}
		if err := run(context.Background(), db, env(nil), []string{"configure", tenant, "client", uri}, &bytes.Buffer{}, rand.Reader); err == nil || len(db.sql) != 0 {
			t.Fatalf("%q accepted (statements %v, err %v)", uri, db.sql, err)
		}
	}
	db := &recorder{}
	if err := run(context.Background(), db, env(nil), []string{"configure", tenant, "x509_san_dns:a.example", "https://a.example/oid4vp/response"}, &bytes.Buffer{}, rand.Reader); err != nil || len(db.sql) != 1 {
		t.Fatalf("valid configuration: %v (statements %v)", err, db.sql)
	}
}

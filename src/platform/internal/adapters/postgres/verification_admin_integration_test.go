//go:build integration

package postgres

import (
	"errors"
	"testing"
)

func TestConfigureVerifierCreatesThenReplacesAndRejectsBadInput(t *testing.T) {
	db := newTestDatabase(t)
	seedVerificationTenants(t, db)
	const uri = "https://a.example/oid4vp/response"
	if err := ConfigureVerifier(testContext, db.admin, vsTenantA, "x509_san_dns:a.example", uri); err != nil {
		t.Fatal(err)
	}
	if err := ConfigureVerifier(testContext, db.admin, vsTenantA, "x509_san_dns:b.example", "https://b.example/oid4vp/response"); err != nil {
		t.Fatalf("replacing the configuration: %v", err)
	}
	var clientID, responseURI string
	var count int
	if err := db.admin.QueryRow(testContext, `SELECT client_id,response_uri,(SELECT count(*) FROM verification.verifier_configs WHERE tenant_id=$1) FROM verification.verifier_configs WHERE tenant_id=$1`, vsTenantA).Scan(&clientID, &responseURI, &count); err != nil {
		t.Fatal(err)
	}
	if clientID != "x509_san_dns:b.example" || responseURI != "https://b.example/oid4vp/response" || count != 1 {
		t.Fatalf("stored %q %q (%d rows)", clientID, responseURI, count)
	}
	for name, call := range map[string]func() error{
		"http": func() error {
			return ConfigureVerifier(testContext, db.admin, vsTenantA, "c", "http://a.example/oid4vp/response")
		},
		"other path":   func() error { return ConfigureVerifier(testContext, db.admin, vsTenantA, "c", "https://a.example/x") },
		"empty client": func() error { return ConfigureVerifier(testContext, db.admin, vsTenantA, "", uri) },
		"padded":       func() error { return ConfigureVerifier(testContext, db.admin, vsTenantA, " c", uri) },
		"not a tenant": func() error { return ConfigureVerifier(testContext, db.admin, "not-a-uuid", "c", uri) },
	} {
		if err := call(); !errors.Is(err, ErrVerifierConfig) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A tenant that does not exist is refused by the foreign key, not created.
	if err := ConfigureVerifier(testContext, db.admin, "99999999-9999-4999-8999-999999999999", "c", uri); err == nil {
		t.Fatal("a configuration was stored for an unknown tenant")
	}
	// The runtime role can read its own tenant's row but has no way to write it.
	if _, err := db.pool(t, "hukid_verification_runtime").Exec(testContext, `UPDATE verification.verifier_configs SET client_id='x'`); err == nil {
		t.Fatal("the runtime role rewrote a verifier configuration")
	}
}

func TestPurgeVerificationRemovesOldSessionsAndUnusedRetiredKeys(t *testing.T) {
	db := newTestDatabase(t)
	provisioner, _, _ := keyFixtures(t, db)
	if _, err := provisioner.Provision(testContext, vsTenantA, newP256(t), nil); err != nil {
		t.Fatal(err)
	}
	old := mustSession(t, db, vsTenantA)
	fresh := mustSession(t, db, vsTenantA)
	mustExec(t, db.admin, `UPDATE verification.sessions SET created_at=now()-interval '40 days',expires_at=now()-interval '40 days'+interval '5 minutes' WHERE session_id=$1`, old)
	// Rotating retires the first key. Neither session is pinned to it (no wallet
	// fetched a request object), and the fresh one completes below, so nothing
	// pending needs it and the purge may drop it.
	if _, err := provisioner.Provision(testContext, vsTenantA, newP256(t), nil); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db.admin, `UPDATE verification.sessions SET status='completed',result='pass',report_digest=decode(repeat('00',32),'hex'),completed_at=clock_timestamp() WHERE session_id=$1`, fresh)

	sessions, keys, err := PurgeVerification(testContext, db.admin, 30, 100)
	if err != nil {
		t.Fatal(err)
	}
	if sessions != 1 || keys != 1 {
		t.Fatalf("purged %d sessions and %d keys, want 1 and 1", sessions, keys)
	}
	var left int
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM verification.sessions`).Scan(&left); err != nil || left != 1 {
		t.Fatalf("sessions left: %d (%v)", left, err)
	}
	for _, bad := range [][2]int{{0, 10}, {3651, 10}, {30, 0}, {30, 1001}} {
		if _, _, err := PurgeVerification(testContext, db.admin, bad[0], bad[1]); !errors.Is(err, ErrVerifierConfig) {
			t.Fatalf("purge %v: %v", bad, err)
		}
	}
}

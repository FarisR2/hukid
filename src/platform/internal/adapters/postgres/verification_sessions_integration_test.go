//go:build integration

package postgres

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	vsTenantA  = "11111111-1111-4111-8111-111111111111"
	vsTenantB  = "22222222-2222-4222-8222-222222222222"
	vsOperator = "33333333-3333-4333-8333-333333333333"
)

func seedVerificationTenants(t *testing.T, db *testDatabase) {
	t.Helper()
	mustMigrate(t, db)
	mustExec(t, db.admin, `INSERT INTO tenancy.tenants(tenant_id,display_name) VALUES($1,'Tenant A'),($2,'Tenant B')`, vsTenantA, vsTenantB)
	mustExec(t, db.admin, `INSERT INTO tenancy.operator_identities(operator_identity_id,oidc_issuer,subject) VALUES($1,'https://issuer.test','verification-operator')`, vsOperator)
	mustExec(t, db.admin, `INSERT INTO verification.verifier_configs(tenant_id,client_id,response_uri) VALUES($1,'client-a','https://a.example/oid4vp/response'),($2,'client-b','https://b.example/oid4vp/response')`, vsTenantA, vsTenantB)
}

func startSession(t *testing.T, db *testDatabase, tenant string, ttl time.Duration) (string, error) {
	t.Helper()
	pool := db.pool(t, "hukid_verification_runtime")
	var id string
	err := WithTenant(testContext, pool, vsOperator, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(testContext, `INSERT INTO verification.sessions(tenant_id,started_by,expires_at) VALUES($1,$2,clock_timestamp()+make_interval(secs=>$3)) RETURNING session_id::text`, tenant, vsOperator, ttl.Seconds()).Scan(&id)
	})
	return id, err
}

func TestVerificationSessionsAreIsolatedByTenant(t *testing.T) {
	db := newTestDatabase(t)
	seedVerificationTenants(t, db)
	idA, err := startSession(t, db, vsTenantA, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	idB, err := startSession(t, db, vsTenantB, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	pool := db.pool(t, "hukid_verification_runtime")
	count := func(tenant, sql string, args ...any) int {
		var n int
		err := WithTenant(testContext, pool, vsOperator, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(testContext, sql, args...).Scan(&n)
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(vsTenantA, `SELECT count(*) FROM verification.sessions`); n != 1 {
		t.Fatalf("tenant A sees %d sessions, want 1", n)
	}
	if n := count(vsTenantA, `SELECT count(*) FROM verification.sessions WHERE session_id=$1`, idB); n != 0 {
		t.Fatal("tenant A read tenant B's session")
	}
	if n := count(vsTenantB, `SELECT count(*) FROM verification.sessions WHERE session_id=$1`, idA); n != 0 {
		t.Fatal("tenant B read tenant A's session")
	}
	if n := count(vsTenantA, `SELECT count(*) FROM verification.verifier_configs`); n != 1 {
		t.Fatalf("tenant A sees %d verifier configs, want 1", n)
	}
	// Without a tenant context nothing is visible.
	var anon int
	if err := pool.QueryRow(testContext, `SELECT count(*) FROM verification.sessions`).Scan(&anon); err != nil || anon != 0 {
		t.Fatalf("no tenant context: %d rows (%v)", anon, err)
	}
}

func TestVerificationSessionsRejectForeignWritesAndTampering(t *testing.T) {
	db := newTestDatabase(t)
	seedVerificationTenants(t, db)
	pool := db.pool(t, "hukid_verification_runtime")
	// Inserting for a tenant other than the authorized one violates the policy.
	err := WithTenant(testContext, pool, vsOperator, vsTenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(testContext, `INSERT INTO verification.sessions(tenant_id,started_by,expires_at) VALUES($1,$2,clock_timestamp()+interval '5 minutes')`, vsTenantB, vsOperator)
		return err
	})
	expectCode(t, err, "42501")
	// The actor must be the authorized operator.
	other := "44444444-4444-4444-8444-444444444444"
	mustExec(t, db.admin, `INSERT INTO tenancy.operator_identities(operator_identity_id,oidc_issuer,subject) VALUES($1,'https://issuer.test','someone-else')`, other)
	err = WithTenant(testContext, pool, vsOperator, vsTenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(testContext, `INSERT INTO verification.sessions(tenant_id,started_by,expires_at) VALUES($1,$2,clock_timestamp()+interval '5 minutes')`, vsTenantA, other)
		return err
	})
	expectCode(t, err, "42501")
	// The runtime role cannot set result columns, update, delete or write configuration.
	id, err := startSession(t, db, vsTenantA, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO verification.sessions(tenant_id,started_by,expires_at,status) VALUES('` + vsTenantA + `','` + vsOperator + `',clock_timestamp()+interval '5 minutes','completed')`,
		`UPDATE verification.sessions SET status='completed'`,
		`DELETE FROM verification.sessions`,
		`INSERT INTO verification.verifier_configs(tenant_id,client_id,response_uri) VALUES('` + vsTenantA + `','x','https://x.example/y')`,
		`UPDATE verification.verifier_configs SET client_id='x'`,
		`SELECT verification.purge_sessions(1,1)`,
	} {
		err := WithTenant(testContext, pool, vsOperator, vsTenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(testContext, statement)
			return err
		})
		expectCode(t, err, "42501")
	}
	// A session cannot outlive the 15-minute module cap.
	if _, err := startSession(t, db, vsTenantA, 16*time.Minute); err == nil {
		t.Fatal("accepted a session longer than 15 minutes")
	}
	var status string
	if err := db.admin.QueryRow(testContext, `SELECT status FROM verification.sessions WHERE session_id=$1`, id).Scan(&status); err != nil || status != "pending" {
		t.Fatalf("status = %q (%v)", status, err)
	}
}

func TestVerificationSessionCompletesOnceAndOnlyWhilePending(t *testing.T) {
	db := newTestDatabase(t)
	seedVerificationTenants(t, db)
	id, err := startSession(t, db, vsTenantA, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	pool := db.pool(t, "hukid_verification_runtime")
	digest := make([]byte, 32)
	complete := func(id, result string, codes []string, digest []byte) (bool, error) {
		var ok bool
		err := pool.QueryRow(testContext, `SELECT verification.complete_session($1::uuid,$2,$3,$4)`, id, result, codes, digest).Scan(&ok)
		return ok, err
	}
	if ok, err := complete(id, "fail", []string{"format.header.alg"}, digest); err != nil || !ok {
		t.Fatalf("first completion: %v %v", ok, err)
	}
	if ok, err := complete(id, "pass", []string{}, digest); err != nil || ok {
		t.Fatalf("second completion must not overwrite: %v %v", ok, err)
	}
	var result string
	var codes []string
	if err := db.admin.QueryRow(testContext, `SELECT result,codes FROM verification.sessions WHERE session_id=$1`, id).Scan(&result, &codes); err != nil || result != "fail" || len(codes) != 1 {
		t.Fatalf("stored %q %v (%v)", result, codes, err)
	}
	// Unknown id and expired session return false.
	if ok, err := complete("55555555-5555-4555-8555-555555555555", "pass", []string{}, digest); err != nil || ok {
		t.Fatalf("unknown session: %v %v", ok, err)
	}
	expired, err := startSession(t, db, vsTenantA, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db.admin, `UPDATE verification.sessions SET created_at=created_at-interval '10 minutes',expires_at=clock_timestamp()-interval '1 second' WHERE session_id=$1`, expired)
	if ok, err := complete(expired, "pass", []string{}, digest); err != nil || ok {
		t.Fatalf("expired session: %v %v", ok, err)
	}
	// Malformed results are rejected, never stored.
	pending, err := startSession(t, db, vsTenantA, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		result string
		codes  []string
		digest []byte
	}{
		{"maybe", []string{}, digest},
		{"pass", []string{}, make([]byte, 31)},
		{"pass", []string{""}, digest},
		{"pass", make([]string, 33), digest},
	} {
		if _, err := complete(pending, c.result, c.codes, c.digest); err == nil {
			t.Fatalf("accepted %v", c)
		}
	}
	var status string
	if err := db.admin.QueryRow(testContext, `SELECT status FROM verification.sessions WHERE session_id=$1`, pending).Scan(&status); err != nil || status != "pending" {
		t.Fatalf("status = %q (%v)", status, err)
	}
}

func TestVerificationSessionPurgeIsBoundedAndNotForTheRuntimeRole(t *testing.T) {
	db := newTestDatabase(t)
	seedVerificationTenants(t, db)
	for i := 0; i < 3; i++ {
		if _, err := startSession(t, db, vsTenantA, 5*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	fresh, err := startSession(t, db, vsTenantA, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db.admin, `UPDATE verification.sessions SET created_at=now()-interval '40 days',expires_at=now()-interval '40 days'+interval '5 minutes' WHERE session_id<>$1`, fresh)
	var removed int
	if err := db.admin.QueryRow(testContext, `SELECT verification.purge_sessions(30,2)`).Scan(&removed); err != nil || removed != 2 {
		t.Fatalf("first purge removed %d (%v)", removed, err)
	}
	if err := db.admin.QueryRow(testContext, `SELECT verification.purge_sessions(30,2)`).Scan(&removed); err != nil || removed != 1 {
		t.Fatalf("second purge removed %d (%v)", removed, err)
	}
	var left int
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM verification.sessions WHERE session_id=$1`, fresh).Scan(&left); err != nil || left != 1 {
		t.Fatalf("recent session purged: %d (%v)", left, err)
	}
	if err := db.admin.QueryRow(testContext, `SELECT verification.purge_sessions(0,1)`).Scan(&removed); err == nil {
		t.Fatal("accepted a zero-day retention")
	}
}

//go:build integration

package postgres

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var testContext = context.Background()

func randomHex(t *testing.T, size int) string {
	t.Helper()
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func testEnvelope(t *testing.T, aad string) ([]byte, []byte) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return aead.Seal(nil, nonce, []byte("synthetic-session-test"), []byte(aad)), nonce
}

type testDatabase struct {
	admin *pgx.Conn
	dsn   string
	roles []string
}

func newTestDatabase(t *testing.T) *testDatabase {
	t.Helper()
	if os.Getenv("HUKID_TEST_DATABASE") != "1" || os.Getenv("HUKID_ENV") != "test" {
		t.Fatal("run npm run test:postgres; integration tests never silently skip")
	}
	config, err := pgx.ParseConfig(os.Getenv("HUKID_TEST_ADMIN_URL"))
	if err != nil {
		t.Fatal("invalid isolated cluster configuration")
	}
	ip := net.ParseIP(config.Host)
	if ip == nil || !ip.IsLoopback() || config.User != "hukid_test_admin" || config.Database != "postgres" {
		t.Fatal("only the dedicated loopback test cluster is allowed")
	}
	cluster, err := pgx.ConnectConfig(testContext, config)
	if err != nil {
		t.Fatal("isolated cluster connection failed")
	}
	name := "hukid_test_" + randomHex(t, 10)
	if _, err = cluster.Exec(testContext, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		cluster.Close(testContext)
		t.Fatal(err)
	}
	u := url.URL{Scheme: "postgresql", Host: net.JoinHostPort(config.Host, fmt.Sprint(config.Port)), Path: "/" + name, User: url.UserPassword(config.User, config.Password), RawQuery: "sslmode=disable"}
	admin, err := pgx.Connect(testContext, u.String())
	if err != nil {
		t.Fatal("new test database connection failed")
	}
	db := &testDatabase{admin: admin, dsn: u.String()}
	t.Cleanup(func() {
		admin.Close(testContext)
		// The generated name was created above; no existing DB is ever dropped.
		if _, err := cluster.Exec(testContext, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Error("cannot drop owned test database")
		}
		for _, role := range db.roles {
			if _, err := cluster.Exec(testContext, "DROP ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Error("cannot remove owned test login")
			}
		}
		cluster.Close(testContext)
	})
	return db
}

func (db *testDatabase) pool(t *testing.T, group string) *pgxpool.Pool {
	t.Helper()
	name := "hukid_test_login_" + randomHex(t, 8)
	password := randomHex(t, 32)
	// Both strings are generated hex, never user input. Identifier is quoted.
	statement := fmt.Sprintf("CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '%s'", pgx.Identifier{name}.Sanitize(), password)
	if _, err := db.admin.Exec(testContext, statement); err != nil {
		t.Fatal("cannot create test login")
	}
	db.roles = append(db.roles, name)
	if _, err := db.admin.Exec(testContext, "GRANT "+pgx.Identifier{group}.Sanitize()+" TO "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(db.dsn)
	u.User = url.UserPassword(name, password)
	pool, err := OpenRuntimePool(testContext, u.String(), group, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func mustExec(t *testing.T, conn *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := conn.Exec(testContext, sql, args...); err != nil {
		t.Fatal(err)
	}
}
func mustMigrate(t *testing.T, db *testDatabase) {
	t.Helper()
	if err := Migrate(testContext, db.admin); err != nil {
		t.Fatal(err)
	}
}
func mustBootstrap(t *testing.T, db *testDatabase) {
	t.Helper()
	if err := BootstrapTest(testContext, db.admin); err != nil {
		t.Fatal(err)
	}
}
func expectCode(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("expected SQLSTATE %s, received %v", code, err)
	}
}
func assertCleared(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var clear bool
	if err := pool.QueryRow(testContext, `SELECT NULLIF(current_setting('app.tenant_id',true),'') IS NULL AND NULLIF(current_setting('app.operator_id',true),'') IS NULL`).Scan(&clear); err != nil || !clear {
		t.Fatal("pool retained transaction context")
	}
}
func countTenants(t *testing.T, pool *pgxpool.Pool, actor, tenant string) (int, int) {
	t.Helper()
	var count, pid int
	err := WithTenant(testContext, pool, actor, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(testContext, `SELECT count(*),pg_backend_pid() FROM tenancy.tenants`).Scan(&count, &pid)
	})
	if err != nil {
		t.Fatal(err)
	}
	assertCleared(t, pool)
	return count, pid
}

func TestMigrateEmptyAndRejectChangedHistory(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustMigrate(t, db)
	var count int
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM public.hukid_schema_migrations`).Scan(&count); err != nil || count != 6 {
		t.Fatal("migration history incorrect")
	}
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('tenancy','platform') AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity`).Scan(&count); err != nil || count != 5 {
		t.Fatal("tenant tables must force RLS")
	}
	if pool, err := OpenRuntimePool(testContext, db.dsn, "hukid_tenant_runtime", 1); err == nil {
		pool.Close()
		t.Fatal("superuser accepted as runtime")
	}
	mustExec(t, db.admin, `INSERT INTO public.hukid_schema_migrations(name,checksum) VALUES ('9999_unknown.sql','unknown')`)
	if Migrate(testContext, db.admin) == nil {
		t.Fatal("unknown migration accepted")
	}
	mustExec(t, db.admin, `DELETE FROM public.hukid_schema_migrations WHERE name='9999_unknown.sql'`)
	mustExec(t, db.admin, `UPDATE public.hukid_schema_migrations SET checksum='changed' WHERE name='0001_console_foundation.sql'`)
	if Migrate(testContext, db.admin) == nil {
		t.Fatal("changed migration accepted")
	}
}

func TestUpgradePreviousSchemaPreservesDataAndLimitsDiscovery(t *testing.T) {
	db := newTestDatabase(t)
	if err := migrateThrough(testContext, db.admin, "0001_console_foundation.sql"); err != nil {
		t.Fatal(err)
	}
	mustBootstrap(t, db)
	mustMigrate(t, db)
	contextPool := db.pool(t, "hukid_context_runtime")
	for _, tc := range []struct{ subject, actor, tenant string }{{"operator-test-a", TestActorA, TestTenantA}, {"operator-test-b", TestActorB, TestTenantB}} {
		actor, tenants, err := DiscoverTenants(testContext, contextPool, "http://127.0.0.1:19090", tc.subject)
		if err != nil || actor != tc.actor || len(tenants) != 1 || tenants[0].TenantID != tc.tenant {
			t.Fatal("operator discovery crossed identity/tenant boundary", err)
		}
		assertCleared(t, contextPool)
	}
	actor, tenants, err := DiscoverTenants(testContext, contextPool, "http://127.0.0.1:19091", "operator-test-a")
	if err != nil || actor != "" || len(tenants) != 0 {
		t.Fatal("issuer/subject identity pair was not enforced")
	}
	actor, tenants, err = DiscoverTenants(testContext, contextPool, "http://127.0.0.1:19090", "operator-test-pending")
	if err != nil || actor != TestActorPending || len(tenants) != 0 {
		t.Fatal("identity without memberships did not preserve pending access")
	}
	_, err = contextPool.Exec(testContext, `SELECT * FROM tenancy.memberships`)
	expectCode(t, err, "42501")
	_, err = contextPool.Exec(testContext, `SET ROLE hukid_context_reader`)
	expectCode(t, err, "42501")
	mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='suspended',authorization_revision=2 WHERE membership_id=$1`, TestMemberA)
	_, tenants, err = DiscoverTenants(testContext, contextPool, "http://127.0.0.1:19090", "operator-test-a")
	if err != nil || len(tenants) != 0 {
		t.Fatal("suspended membership remained discoverable")
	}
}

func TestTenantRLSAndPoolReuseOnCommitRollbackAndPanic(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)
	pool := db.pool(t, "hukid_tenant_runtime")
	var noContext int
	if err := pool.QueryRow(testContext, `SELECT count(*) FROM tenancy.tenants`).Scan(&noContext); err != nil || noContext != 0 {
		t.Fatal("unset context was not default deny")
	}
	a, pidA := countTenants(t, pool, TestActorA, TestTenantA)
	foreign, pidForeign := countTenants(t, pool, TestActorA, TestTenantB)
	b, pidB := countTenants(t, pool, TestActorB, TestTenantB)
	if a != 1 || b != 1 || foreign != 0 || pidA != pidB || pidA != pidForeign {
		t.Fatal("RLS failed or test did not reuse one physical connection")
	}
	cancelled, cancel := context.WithCancel(testContext)
	if err := WithTenant(cancelled, pool, TestActorA, TestTenantA, func(pgx.Tx) error { cancel(); return nil }); err == nil {
		t.Fatal("cancelled transaction committed")
	}
	assertCleared(t, pool)
	rollback := errors.New("rollback requested")
	if err := WithTenant(testContext, pool, TestActorA, TestTenantA, func(pgx.Tx) error { return rollback }); !errors.Is(err, rollback) {
		t.Fatal("rollback not propagated")
	}
	assertCleared(t, pool)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected callback panic")
			}
		}()
		WithTenant(testContext, pool, TestActorA, TestTenantA, func(pgx.Tx) error { panic("synthetic callback failure") })
	}()
	assertCleared(t, pool)
	_, err := pool.Exec(testContext, `SELECT * FROM console_auth.sessions`)
	expectCode(t, err, "42501")
	_, err = pool.Exec(testContext, `SELECT * FROM tenancy.operator_identities`)
	expectCode(t, err, "42501")
	_, err = pool.Exec(testContext, `UPDATE tenancy.memberships SET state='active'`)
	expectCode(t, err, "42501")
	_, err = pool.Exec(testContext, `TRUNCATE tenancy.tenants CASCADE`)
	expectCode(t, err, "42501")
	if WithTenant(testContext, pool, "not-a-uuid", TestTenantA, func(pgx.Tx) error { return nil }) == nil {
		t.Fatal("invalid actor context accepted")
	}
	mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='revoked',authorization_revision=2 WHERE membership_id=$1`, TestMemberA)
	if count, _ := countTenants(t, pool, TestActorA, TestTenantA); count != 0 {
		t.Fatal("revoked membership retained tenant access")
	}
	mustExec(t, db.admin, `UPDATE tenancy.tenants SET state='suspended' WHERE tenant_id=$1`, TestTenantB)
	if count, _ := countTenants(t, pool, TestActorB, TestTenantB); count != 0 {
		t.Fatal("suspended tenant remained visible")
	}
}

func TestBootstrapAtomicityAndCompositeConstraints(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustExec(t, db.admin, `ALTER TABLE platform.outbox_events ADD CONSTRAINT injected_failure CHECK (tenant_id IS NULL)`)
	if BootstrapTest(testContext, db.admin) == nil {
		t.Fatal("injected outbox failure did not abort bootstrap")
	}
	for _, table := range []string{"tenancy.tenants", "tenancy.operator_identities", "tenancy.memberships", "platform.audit_events", "platform.outbox_events"} {
		var count int
		if err := db.admin.QueryRow(testContext, "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatal("bootstrap left partial state")
		}
	}
	mustExec(t, db.admin, `ALTER TABLE platform.outbox_events DROP CONSTRAINT injected_failure`)
	mustBootstrap(t, db)
	mustBootstrap(t, db)
	_, err := db.admin.Exec(testContext, `INSERT INTO tenancy.operator_identities(oidc_issuer,subject) VALUES ('http://127.0.0.1:19090','operator-test-a')`)
	expectCode(t, err, "23505")
	_, err = db.admin.Exec(testContext, `INSERT INTO tenancy.membership_roles(tenant_id,membership_id,role) VALUES ($1,$2,'security_admin')`, TestTenantB, TestMemberA)
	expectCode(t, err, "23503")
	_, err = db.admin.Exec(testContext, `INSERT INTO tenancy.memberships(tenant_id,operator_identity_id) VALUES ($1,$2)`, TestTenantA, TestActorA)
	expectCode(t, err, "23505")
	mustExec(t, db.admin, `DELETE FROM tenancy.membership_roles WHERE membership_id=$1`, TestMemberA)
	mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='suspended' WHERE membership_id=$1`, TestMemberA)
	mustBootstrap(t, db)
	var state string
	var roles int
	if err := db.admin.QueryRow(testContext, `SELECT state,(SELECT count(*) FROM tenancy.membership_roles WHERE membership_id=$1) FROM tenancy.memberships WHERE membership_id=$1`, TestMemberA).Scan(&state, &roles); err != nil || state != "suspended" || roles != 0 {
		t.Fatal("bootstrap re-granted existing access")
	}
	sessions := db.pool(t, "hukid_session_runtime")
	_, err = sessions.Exec(testContext, `SELECT * FROM tenancy.memberships`)
	expectCode(t, err, "42501")
	var family string
	err = sessions.QueryRow(testContext, `INSERT INTO console_auth.session_families(operator_identity_id,created_at,absolute_expires_at,auth_time,amr,acr,original_grant,policy_version) VALUES ($1,now(),now()+interval '1 hour',now(),ARRAY['pwd','otp'],'urn:hukid:test:mfa','authorization_code','test-v1') RETURNING family_id::text`, TestActorA).Scan(&family)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, nonce := testEnvelope(t, "session-secrets/"+family+"/1")
	insert := `INSERT INTO console_auth.sessions(family_id,operator_identity_id,generation,cookie_hash,csrf_hash,created_at,last_seen_at,idle_expires_at,absolute_expires_at,active_tenant_id,authorization_revision,secret_ciphertext,secret_nonce,secret_key_version,refresh_digest) VALUES ($1,$2,1,decode(repeat('ab',32),'hex'),decode(repeat('cd',32),'hex'),now(),now(),now()+interval '30 minutes',(SELECT absolute_expires_at FROM console_auth.session_families WHERE family_id=$1),$3,1,$4,$5,'test-key-v1',decode(repeat('ef',32),'hex'))`
	_, err = sessions.Exec(testContext, insert, family, TestActorA, TestTenantB, encrypted, nonce)
	expectCode(t, err, "23503")
	_, err = sessions.Exec(testContext, insert, family, TestActorB, TestTenantB, encrypted, nonce)
	expectCode(t, err, "23503")
	_, err = sessions.Exec(testContext, insert, family, TestActorA, TestTenantA, encrypted, nonce[:11])
	expectCode(t, err, "23514")
	_, err = sessions.Exec(testContext, insert, family, TestActorA, TestTenantA, encrypted, nonce)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sessions.Exec(testContext, `UPDATE console_auth.sessions SET idle_expires_at=absolute_expires_at+interval '1 second'`)
	expectCode(t, err, "23514")
	_, err = sessions.Exec(testContext, `UPDATE console_auth.sessions SET absolute_expires_at=absolute_expires_at+interval '1 hour'`)
	expectCode(t, err, "23503")
	_, err = sessions.Exec(testContext, insert, family, TestActorA, TestTenantA, encrypted, nonce)
	expectCode(t, err, "23505")
	var stored []byte
	if err := sessions.QueryRow(testContext, `SELECT secret_ciphertext FROM console_auth.sessions`).Scan(&stored); err != nil || strings.Contains(string(stored), "synthetic-session-test") {
		t.Fatal("envelope storage invalid")
	}
	_, err = sessions.Exec(testContext, `UPDATE console_auth.sessions SET secret_ciphertext=NULL,secret_nonce=NULL,secret_key_version=NULL,refresh_digest=NULL`)
	expectCode(t, err, "23514")
	_, err = sessions.Exec(testContext, `UPDATE console_auth.sessions SET state='revoked',secret_ciphertext=NULL,secret_nonce=NULL,secret_key_version=NULL,refresh_digest=NULL`)
	if err != nil {
		t.Fatal(err)
	}
	if err := BootstrapTest(testContext, db.admin); err != nil {
		t.Fatal(err)
	}
}

func TestProvisioningGuardAndRuntimeRoleDrift(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)
	pool := db.pool(t, "hukid_tenant_runtime")
	conn, err := pool.Acquire(testContext)
	if err != nil {
		t.Fatal(err)
	}
	if BootstrapTest(testContext, conn.Conn()) == nil {
		t.Fatal("runtime login could bootstrap")
	}
	conn.Release()
	t.Setenv("HUKID_ENV", "production")
	if conn, err := ConnectTestDatabase(testContext, db.dsn); err == nil {
		conn.Close(testContext)
		t.Fatal("production could execute test provisioning")
	}
	t.Setenv("HUKID_ENV", "test")
	for _, dsn := range []string{"postgresql://127.0.0.1/production", "postgresql://db.example.invalid/hukid_test_anything", "host=127.0.0.1,db.example.invalid dbname=hukid_test_fallback sslmode=disable"} {
		if conn, err := ConnectTestDatabase(testContext, dsn); err == nil {
			conn.Close(testContext)
			t.Fatal("unsafe target accepted")
		}
	}
	// Escalating an inherited group must invalidate new pool initialization too.
	mustExec(t, db.admin, `ALTER ROLE hukid_tenant_runtime BYPASSRLS`)
	defer mustExec(t, db.admin, `ALTER ROLE hukid_tenant_runtime NOBYPASSRLS`)
	u, _ := url.Parse(db.dsn)
	config := pool.Config().ConnConfig
	u.User = url.UserPassword(config.User, config.Password)
	if unsafe, err := OpenRuntimePool(testContext, u.String(), "hukid_tenant_runtime", 1); err == nil {
		unsafe.Close()
		t.Fatal("unsafe inherited role accepted")
	}
}

func TestOIDCTransactionEnvelopeAndSingleUseStorage(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	pool := db.pool(t, "hukid_session_runtime")
	encrypted, nonce := testEnvelope(t, "oidc-verifier/50000000-0000-4000-8000-000000000001")
	insert := `INSERT INTO console_auth.oidc_transactions(transaction_id,purpose,state_hash,nonce_hash,binding_hash,oidc_issuer,client_id,redirect_uri,return_to,verifier_ciphertext,verifier_nonce,verifier_key_version,created_at,expires_at) VALUES ('50000000-0000-4000-8000-000000000001','login',decode(repeat('ab',32),'hex'),decode(repeat('cd',32),'hex'),decode(repeat('ef',32),'hex'),'http://127.0.0.1:19090','hukid-console-test','http://127.0.0.1:8080/console/auth/callback',$1,$2,$3,'test-key-v1',now(),now()+interval '5 minutes')`
	_, err := pool.Exec(testContext, insert, "https://other.example.invalid", encrypted, nonce)
	expectCode(t, err, "23514")
	_, err = pool.Exec(testContext, insert, "/", encrypted, nonce[:11])
	expectCode(t, err, "23514")
	_, err = pool.Exec(testContext, insert, "/", encrypted, nonce)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(testContext, `UPDATE console_auth.oidc_transactions SET consumed_at=now()`)
	expectCode(t, err, "23514")
	consume := `UPDATE console_auth.oidc_transactions SET consumed_at=now(),verifier_ciphertext=NULL,verifier_nonce=NULL,verifier_key_version=NULL WHERE transaction_id='50000000-0000-4000-8000-000000000001' AND consumed_at IS NULL AND expires_at>now()`
	first, err := pool.Exec(testContext, consume)
	if err != nil || first.RowsAffected() != 1 {
		t.Fatal("transaction was not consumed")
	}
	second, err := pool.Exec(testContext, consume)
	if err != nil || second.RowsAffected() != 0 {
		t.Fatal("transaction replay succeeded")
	}
}

func TestMigrationChecksumIgnoresOnlyCRLF(t *testing.T) {
	if migrationChecksum([]byte("SELECT 1;\r\n")) != migrationChecksum([]byte("SELECT 1;\n")) {
		t.Fatal("line endings changed migration identity")
	}
	if migrationChecksum([]byte("SELECT 1;\n")) == migrationChecksum([]byte("SELECT 2;\n")) {
		t.Fatal("changed SQL kept checksum")
	}
}

func TestTestDBCLIUsesOnlyExplicitTestDatabase(t *testing.T) {
	db := newTestDatabase(t)
	goName := "go"
	if runtime.GOOS == "windows" {
		goName = "go.exe"
	}
	for _, operation := range []string{"migrate", "migrate", "bootstrap", "bootstrap", "invalidate-auth", "invalidate-auth"} {
		command := exec.Command(filepath.Join(runtime.GOROOT(), "bin", goName), "run", "../../../cmd/testdb", operation)
		command.Env = append(os.Environ(), "HUKID_DATABASE_URL="+db.dsn, "HUKID_ENV=test", "HUKID_TEST_DATABASE=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("testdb CLI failed: %s", output)
		}
	}
	var count int
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM tenancy.tenants`).Scan(&count); err != nil || count != 2 {
		t.Fatal("CLI did not create the synthetic fixture")
	}
	command := exec.Command(filepath.Join(runtime.GOROOT(), "bin", goName), "run", "../../../cmd/testdb", "bootstrap")
	command.Env = append(os.Environ(), "HUKID_DATABASE_URL="+db.dsn, "HUKID_ENV=production", "HUKID_TEST_DATABASE=1")
	if err := command.Run(); err == nil {
		t.Fatal("CLI accepted production flags")
	}
}

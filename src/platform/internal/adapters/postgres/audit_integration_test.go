//go:build integration

package postgres

import (
	"hukid.local/platform/internal/audit"
	a "hukid.local/platform/internal/authentication"
	"strings"
	"sync"
	"testing"
	"time"
)

// Seed the historical schema explicitly: current runtime requires migration 0006.
func seedLegacySession(t *testing.T, db *testDatabase, v a.InitialSession) {
	t.Helper()
	var actor string
	if err := db.admin.QueryRow(testContext, `SELECT console_auth.register_operator($1,$2)::text`, v.Identity.Issuer, v.Identity.Subject).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db.admin, `INSERT INTO console_auth.session_families(family_id,operator_identity_id,created_at,absolute_expires_at,auth_time,amr,acr,original_grant,policy_version) VALUES($1,$2,$3,$4,$3,$5,$6,'authorization_code',$7)`, v.FamilyID, actor, v.CreatedAt, v.AbsoluteExpiresAt, v.Identity.AMR, v.Identity.ACR, v.PolicyVersion)
	mustExec(t, db.admin, `INSERT INTO console_auth.sessions(session_id,family_id,operator_identity_id,generation,cookie_hash,csrf_hash,created_at,last_seen_at,idle_expires_at,absolute_expires_at,secret_ciphertext,secret_nonce,secret_key_version,refresh_digest) VALUES($1,$2,$3,1,$4,$5,$6,$6,$7,$8,$9,$10,$11,$12)`, v.SessionID, v.FamilyID, actor, v.CookieHash, v.CSRFHash, v.CreatedAt, v.IdleExpiresAt, v.AbsoluteExpiresAt, v.Secrets.Ciphertext, v.Secrets.Nonce, v.Secrets.KeyVersion, v.RefreshDigest)
}
func TestAuthAuditAtomicityPermissionsAndUpgrade(t *testing.T) {
	db := newTestDatabase(t)
	if err := migrateThrough(testContext, db.admin, "0005_console_reauthentication.sql"); err != nil {
		t.Fatal(err)
	}
	mustBootstrap(t, db)
	mustMigrate(t, db)
	var historical int
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM platform.audit_events WHERE action='test.bootstrap.completed'`).Scan(&historical); err != nil || historical != 2 {
		t.Fatal("upgrade lost history")
	}
	pool := db.pool(t, "hukid_session_runtime")
	store := &LoginStore{Pool: pool}
	id, _ := audit.NewID()
	ctx := audit.WithCorrelation(testContext, id)
	if err := store.RecordFailure(ctx, false); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		"SELECT * FROM platform.audit_events", "SELECT * FROM platform.outbox_events",
		"UPDATE platform.audit_events SET outcome='success'", "DELETE FROM platform.audit_events",
		"UPDATE platform.outbox_events SET published_at=now()", "DELETE FROM platform.outbox_events",
	} {
		_, err := pool.Exec(testContext, sql)
		expectCode(t, err, "42501")
	}
	for _, role := range []string{"hukid_context_runtime", "hukid_tenant_runtime"} {
		other := db.pool(t, role)
		if (&LoginStore{Pool: other}).RecordFailure(ctx, false) == nil {
			t.Fatal("other runtime wrote audit")
		}
	}

	// Scope FK rejects global/tenant mixing, including the all-zero UUID tenant.
	mustExec(t, db.admin, `INSERT INTO tenancy.tenants(tenant_id,display_name) VALUES('00000000-0000-0000-0000-000000000000','synthetic-zero')`)
	event, _ := audit.NewID()
	mustExec(t, db.admin, `INSERT INTO platform.audit_events(event_id,tenant_id,target_id,action,outcome,correlation_id) VALUES($1,'00000000-0000-0000-0000-000000000000',$1,'auth.context.changed','success',$1)`, event)
	_, mismatch := db.admin.Exec(testContext, `INSERT INTO platform.outbox_events(event_id) VALUES($1)`, event)
	expectCode(t, mismatch, "23503")
	mustExec(t, db.admin, `INSERT INTO platform.outbox_events(event_id,tenant_id) VALUES($1,'00000000-0000-0000-0000-000000000000')`, event)

	// A closed action vocabulary is enforced even if the runtime SQL is misused.
	_, err := pool.Exec(testContext, `INSERT INTO platform.audit_events(event_id,target_id,action,outcome,correlation_id) VALUES(gen_random_uuid(),gen_random_uuid(),'secret.free_text','denied',gen_random_uuid())`)
	expectCode(t, err, "42501")
	now := time.Now().UTC().Truncate(time.Microsecond)
	ciphertext, nonce := testEnvelope(t, "audit")
	family, _ := audit.NewID()
	session, _ := audit.NewID()
	initial := a.InitialSession{FamilyID: family, SessionID: session, PolicyVersion: "auth-test-v1", CookieHash: a.Digest("audit-cookie"), CSRFHash: a.Digest("audit-csrf"), RefreshDigest: a.Digest("audit-refresh"), Secrets: a.Envelope{Ciphertext: ciphertext, Nonce: nonce, KeyVersion: "audit"}, CreatedAt: now, IdleExpiresAt: now.Add(time.Minute), AbsoluteExpiresAt: now.Add(time.Hour), Identity: a.VerifiedLogin{Issuer: "http://127.0.0.1:19090", Subject: "audit-rollback", AuthTime: now, AMR: []string{"pwd", "otp"}, ACR: "urn:hukid:test:mfa"}}
	mustExec(t, db.admin, `ALTER TABLE platform.outbox_events ADD CONSTRAINT inject_audit_failure CHECK(false) NOT VALID`)
	if store.CreateInitialSession(ctx, initial) == nil {
		t.Fatal("outbox failure permitted login")
	}
	var count int
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM tenancy.operator_identities WHERE subject='audit-rollback'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("identity survived failed audit")
	}
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM platform.audit_events WHERE target_id=$1`, family).Scan(&count); err != nil || count != 0 {
		t.Fatal("event survived failed outbox")
	}
	mustExec(t, db.admin, `ALTER TABLE platform.outbox_events DROP CONSTRAINT inject_audit_failure`)
	if err := store.CreateInitialSession(ctx, initial); err != nil {
		t.Fatal(err)
	}
	old, err := store.ReadSession(ctx, initial.CookieHash, now)
	if err != nil {
		t.Fatal(err)
	}
	nextID, _ := audit.NewID()
	next := a.SessionRotation{SessionID: nextID, CookieHash: a.Digest("rotated-cookie"), CSRFHash: a.Digest("rotated-csrf"), RefreshDigest: a.Digest("rotated-refresh"), Secrets: initial.Secrets, IdleExpiresAt: now.Add(time.Minute)}
	mustExec(t, db.admin, `ALTER TABLE platform.audit_events ADD CONSTRAINT inject_event_failure CHECK(action<>'auth.step_up.completed') NOT VALID`)
	if store.RotateSession(ctx, old, next, &initial.Identity, nil, now) == nil {
		t.Fatal("audit failure permitted rotation")
	}
	if _, err := store.ReadSession(ctx, initial.CookieHash, now); err != nil {
		t.Fatal("audit failure invalidated original session")
	}
	mustExec(t, db.admin, `ALTER TABLE platform.audit_events DROP CONSTRAINT inject_event_failure`)
	if err := store.RotateSession(ctx, old, next, &initial.Identity, nil, now); err != nil {
		t.Fatal(err)
	}
	// Repeated/concurrent logout records its state transition only once.
	var wg sync.WaitGroup
	failures := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.Logout(ctx, next.CookieHash, next.CSRFHash, now)
			failures <- err
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, action := range []string{"auth.login.completed", "auth.step_up.completed", "auth.logout.completed", "auth.family.revoked"} {
		if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM platform.audit_events WHERE target_id=$1 AND action=$2 AND correlation_id=$3`, family, action, id).Scan(&count); err != nil || count != 1 {
			t.Fatalf("incorrect atomic event %s: %d", action, count)
		}
	}
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM platform.audit_events a LEFT JOIN platform.outbox_events o USING(event_id) WHERE o.event_id IS NULL OR a.tenant_id IS DISTINCT FROM o.tenant_id`).Scan(&count); err != nil || count != 0 {
		t.Fatal("audit/outbox mismatch")
	}
	// Event schema and contents contain no protocol payload or digest copies.
	var dump string
	if err := db.admin.QueryRow(testContext, `SELECT string_agg(row_to_json(a)::text,'') FROM platform.audit_events a`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"audit-cookie", "audit-csrf", "audit-refresh", "audit-rollback"} {
		if strings.Contains(dump, secret) {
			t.Fatal("secret in audit storage")
		}
	}
}

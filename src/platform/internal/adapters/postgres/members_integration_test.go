//go:build integration

package postgres

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"hukid.local/platform/internal/tenancy"
)

const testSecondAdmin = "30000000-0000-4000-8000-000000000003"

func seedSecondAdmin(t *testing.T, db *testDatabase) {
	t.Helper()
	mustExec(t, db.admin, `INSERT INTO tenancy.memberships(tenant_id,membership_id,operator_identity_id) VALUES($1,$2,$3)`, TestTenantA, testSecondAdmin, TestActorPending)
	mustExec(t, db.admin, `INSERT INTO tenancy.membership_roles(tenant_id,membership_id,role) VALUES($1,$2,'tenant_admin')`, TestTenantA, testSecondAdmin)
}

func insertMemberInvitation(ctx context.Context, tx pgx.Tx, tenant, actor, id string, digest []byte) error {
	_, err := tx.Exec(ctx, `INSERT INTO tenancy.invitations(invitation_id,tenant_id,created_by,token_hash,
	 recipient_hmac,recipient_ciphertext,recipient_nonce,recipient_key_version,roles,issuer_ids,created_at,expires_at,recipient_delete_after)
	 VALUES($1,$2,$3,$4,$4,decode(repeat('ac',32),'hex'),decode(repeat('cd',12),'hex'),'synthetic-key',
	 ARRAY['support_readonly'],ARRAY[]::uuid[],now(),now()+interval '24 hours',now()+interval '7 days')`, id, tenant, actor, digest)
	return err
}

func TestMembersUpgradePreservesIdentityAndRevokedHistory(t *testing.T) {
	db := newTestDatabase(t)
	if err := migrateThrough(testContext, db.admin, "0006_auth_audit.sql"); err != nil {
		t.Fatal(err)
	}
	mustBootstrap(t, db)
	mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='revoked',authorization_revision=7 WHERE membership_id=$1`, TestMemberB)
	var before, after string
	query := `SELECT json_build_object('identities',(SELECT json_agg(i ORDER BY operator_identity_id) FROM tenancy.operator_identities i),'audit',(SELECT json_agg(a ORDER BY event_id) FROM platform.audit_events a),'outbox',(SELECT json_agg(o ORDER BY event_id) FROM platform.outbox_events o))::text`
	if err := db.admin.QueryRow(testContext, query).Scan(&before); err != nil {
		t.Fatal(err)
	}
	mustMigrate(t, db)
	mustMigrate(t, db)
	if err := db.admin.QueryRow(testContext, query).Scan(&after); err != nil || before != after {
		t.Fatal("upgrade changed identity or historical evidence", err)
	}
	var lifecycle, revision int64
	var roles []string
	var revoked time.Time
	if err := db.admin.QueryRow(testContext, `SELECT lifecycle,authorization_revision,roles,revoked_at FROM tenancy.membership_history WHERE membership_id=$1`, TestMemberB).Scan(&lifecycle, &revision, &roles, &revoked); err != nil || lifecycle != 1 || revision != 7 || len(roles) != 1 || roles[0] != "tenant_admin" || revoked.IsZero() {
		t.Fatal("legacy revoked lifecycle was not preserved", err)
	}
	// AUTH still discovers the same live membership, without a second identity.
	actor, tenants, err := DiscoverTenants(testContext, db.pool(t, "hukid_context_runtime"), "http://127.0.0.1:19090", "operator-test-a")
	if err != nil || actor != TestActorA || len(tenants) != 1 || tenants[0].MembershipID != TestMemberA {
		t.Fatal("AUTH compatibility lost", err)
	}
}

func TestMembersRLSConstraintsAndCredentialSeparation(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)
	seedSecondAdmin(t, db)
	pool := db.pool(t, "hukid_members_runtime")
	var count int
	if err := pool.QueryRow(testContext, `SELECT count(*) FROM tenancy.memberships`).Scan(&count); err != nil || count != 0 {
		t.Fatal("unscoped members runtime did not deny", err)
	}
	var pids []int
	for _, tc := range []struct {
		actor, tenant string
		want          int
	}{{TestActorA, TestTenantA, 2}, {TestActorB, TestTenantB, 1}, {TestActorA, TestTenantA, 2}} {
		err := WithTenant(testContext, pool, tc.actor, tc.tenant, func(tx pgx.Tx) error {
			var pid int
			if err := tx.QueryRow(testContext, `SELECT count(*),pg_backend_pid() FROM tenancy.memberships`).Scan(&count, &pid); err != nil {
				return err
			}
			pids = append(pids, pid)
			if count != tc.want {
				t.Fatal("directory crossed tenant scope")
			}
			var foreign int
			if err := tx.QueryRow(testContext, `SELECT count(*) FROM tenancy.memberships WHERE tenant_id<>$1`, tc.tenant).Scan(&foreign); err != nil {
				return err
			}
			if foreign != 0 {
				t.Fatal("foreign directory rows visible")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		assertCleared(t, pool)
	}
	if pids[0] != pids[1] || pids[1] != pids[2] {
		t.Fatal("pool test did not reuse a physical connection")
	}
	for _, statement := range []string{
		`SELECT * FROM tenancy.operator_identities`, `SELECT * FROM console_auth.sessions`,
		`UPDATE tenancy.memberships SET operator_identity_id=gen_random_uuid()`,
		`DELETE FROM tenancy.memberships`, `UPDATE tenancy.tenants SET state='suspended'`,
		`UPDATE tenancy.membership_history SET lifecycle=2`, `DELETE FROM tenancy.membership_history`,
		`UPDATE platform.outbox_events SET published_at=now()`, `SELECT * FROM platform.audit_events`,
		`TRUNCATE tenancy.invitations`,
	} {
		_, err := pool.Exec(testContext, statement)
		expectCode(t, err, "42501")
	}
	for _, group := range []string{"hukid_tenant_runtime", "hukid_session_runtime", "hukid_context_runtime"} {
		other := db.pool(t, group)
		_, err := other.Exec(testContext, `SELECT * FROM tenancy.invitations`)
		expectCode(t, err, "42501")
	}
	// Composite constraints still reject foreign membership IDs even to admin.
	_, err := db.admin.Exec(testContext, `INSERT INTO tenancy.membership_issuer_scopes VALUES($1,$2,gen_random_uuid())`, TestTenantB, TestMemberA)
	expectCode(t, err, "23503")
	// A login combining the new write role and an AUTH credential is rejected.
	config := pool.Config().ConnConfig
	mustExec(t, db.admin, "GRANT hukid_session_runtime TO "+pgx.Identifier{config.User}.Sanitize())
	u, _ := url.Parse(db.dsn)
	u.User = url.UserPassword(config.User, config.Password)
	if unsafe, err := OpenRuntimePool(testContext, u.String(), "hukid_members_runtime", 1); err == nil {
		unsafe.Close()
		t.Fatal("mixed runtime credentials accepted")
	}
}

func TestMembersHistoryIdempotencyAndRetentionStorage(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)
	pool := db.pool(t, "hukid_members_runtime")
	invitation := "60000000-0000-4000-8000-000000000005"
	err := WithMemberMutation(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) (MemberEvent, error) {
		if err := insertMemberInvitation(testContext, tx, TestTenantA, TestActorA, invitation, []byte(strings.Repeat("e", 32))); err != nil {
			return MemberEvent{}, err
		}
		_, err := tx.Exec(testContext, `UPDATE tenancy.memberships SET state='revoked',authorization_revision=2,revoked_at=clock_timestamp(),updated_at=clock_timestamp() WHERE membership_id=$1`, TestMemberA)
		if err != nil {
			return MemberEvent{}, err
		}
		if err = ArchiveRevokedMembership(testContext, tx, TestTenantA, TestMemberA); err != nil {
			return MemberEvent{}, err
		}
		return MemberEvent{Action: "members.membership.revoked", Target: TestMemberA}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A future acceptance must compare its creation time to this cutoff under
	// the same lock. Unknown recipients remain unbound until verified in T05.
	var oldInvitation bool
	if err := db.admin.QueryRow(testContext, `SELECT i.created_at<=m.revoked_at FROM tenancy.invitations i JOIN tenancy.memberships m USING(tenant_id) WHERE i.invitation_id=$1 AND m.membership_id=$2`, invitation, TestMemberA).Scan(&oldInvitation); err != nil || !oldInvitation {
		t.Fatal("reentry cutoff unavailable", err)
	}
	// Exercise replacement of the projection without changing logical identity
	// or archived grants. This is storage compatibility, not an acceptance API.
	err = WithMemberMutation(testContext, pool, TestActorPending, TestTenantA, func(tx pgx.Tx) (MemberEvent, error) {
		_, err := tx.Exec(testContext, `UPDATE tenancy.memberships SET state='active',lifecycle=2,authorization_revision=3,lifecycle_started_at=clock_timestamp(),revoked_at=NULL,updated_at=clock_timestamp() WHERE membership_id=$1`, TestMemberA)
		if err != nil {
			return MemberEvent{}, err
		}
		_, err = tx.Exec(testContext, `DELETE FROM tenancy.membership_roles WHERE membership_id=$1`, TestMemberA)
		if err != nil {
			return MemberEvent{}, err
		}
		_, err = tx.Exec(testContext, `INSERT INTO tenancy.membership_roles VALUES($1,$2,'support_readonly')`, TestTenantA, TestMemberA)
		return MemberEvent{Action: "members.membership.reentered", Target: TestMemberA}, err
	})
	if err != nil {
		t.Fatal(err)
	}
	var archivedRoles []string
	if err := db.admin.QueryRow(testContext, `SELECT roles FROM tenancy.membership_history WHERE membership_id=$1 AND lifecycle=1`, TestMemberA).Scan(&archivedRoles); err != nil || len(archivedRoles) != 1 || archivedRoles[0] != "tenant_admin" {
		t.Fatal("history changed during reentry", err)
	}
	var logical int
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM tenancy.memberships WHERE tenant_id=$1 AND operator_identity_id=$2`, TestTenantA, TestActorA).Scan(&logical); err != nil || logical != 1 {
		t.Fatal("second logical membership created", err)
	}
	// Store only irreversible key/request fingerprints and resource references.
	insert := `INSERT INTO tenancy.member_idempotency(tenant_id,actor_id,operation,key_hash,request_hash,invitation_id,created_at,expires_at)
	 VALUES($1,$2,'invitation.create',decode(repeat('ab',32),'hex'),decode(repeat('bc',32),'hex'),$3,now(),now()+interval '24 hours')`
	err = WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(testContext, insert, TestTenantA, TestActorA, invitation)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	err = WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(testContext, insert, TestTenantA, TestActorA, invitation)
		return err
	})
	expectCode(t, err, "23505")
	err = WithTenant(testContext, pool, TestActorB, TestTenantB, func(tx pgx.Tx) error {
		_, err := tx.Exec(testContext, insert, TestTenantB, TestActorB, invitation)
		return err
	})
	expectCode(t, err, "23503")
	accept := `INSERT INTO tenancy.member_idempotency(tenant_id,actor_id,operation,key_hash,request_hash,token_hash,invitation_id,membership_id,created_at,expires_at)
	 VALUES($1,$2,'invitation.accept',decode(repeat('ab',32),'hex'),decode(repeat('bc',32),'hex'),$3,$4,$5,now(),now()+interval '24 hours')`
	// Acceptance fingerprints are tied to the exact token/resource, not merely
	// to a resource UUID supplied independently of that digest.
	err = WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(testContext, accept, TestTenantA, TestActorA, []byte(strings.Repeat("x", 32)), invitation, TestMemberA)
		return err
	})
	expectCode(t, err, "23503")
	err = WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(testContext, accept, TestTenantA, TestActorA, []byte(strings.Repeat("e", 32)), invitation, TestMemberA)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	err = WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(testContext, accept, TestTenantA, TestActorA, []byte(strings.Repeat("e", 32)), invitation, TestMemberA)
		return err
	})
	expectCode(t, err, "23505")
	// Purging fingerprints/recipient does not delete identity, membership,
	// token hash or archive. The scheduled worker and TTL policy are later tasks.
	err = WithMemberMutation(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) (MemberEvent, error) {
		_, err := tx.Exec(testContext, `DELETE FROM tenancy.member_idempotency WHERE invitation_id=$1`, invitation)
		if err != nil {
			return MemberEvent{}, err
		}
		_, err = tx.Exec(testContext, `UPDATE tenancy.invitations SET recipient_hmac=NULL,recipient_ciphertext=NULL,recipient_nonce=NULL,recipient_key_version=NULL WHERE invitation_id=$1`, invitation)
		return MemberEvent{Action: "members.retention.purged", Target: invitation}, err
	})
	if err != nil {
		t.Fatal(err)
	}
	var retained bool
	if err := db.admin.QueryRow(testContext, `SELECT recipient_hmac IS NULL AND recipient_ciphertext IS NULL AND octet_length(token_hash)=32 FROM tenancy.invitations WHERE invitation_id=$1`, invitation).Scan(&retained); err != nil || !retained {
		t.Fatal("unsafe retention storage", err)
	}
	assertCleared(t, pool)
}

func TestMembersTenantLockCanonicalUUIDAndCancellation(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)
	tenant := "abcdef00-0000-4000-8000-000000000001"
	mustExec(t, db.admin, `INSERT INTO tenancy.tenants(tenant_id,display_name) VALUES($1,'synthetic canonical UUID')`, tenant)
	p1, p2 := db.pool(t, "hukid_members_runtime"), db.pool(t, "hukid_members_runtime")
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	rollback := errors.New("synthetic rollback")
	go func() {
		finished <- WithMemberMutation(testContext, p1, TestActorA, tenant, func(pgx.Tx) (MemberEvent, error) { close(entered); <-release; return MemberEvent{}, rollback })
	}()
	<-entered
	ctx, cancel := context.WithTimeout(testContext, 150*time.Millisecond)
	called := false
	err := WithMemberMutation(ctx, p2, TestActorA, strings.ToUpper(tenant), func(pgx.Tx) (MemberEvent, error) { called = true; return MemberEvent{}, rollback })
	cancel()
	close(release)
	if !errors.Is(<-finished, rollback) {
		t.Fatal("holder did not roll back")
	}
	if err == nil || called {
		t.Fatal("UUID spelling bypassed the tenant lock")
	}
	assertCleared(t, p1)
	assertCleared(t, p2)
	ctx, cancel = context.WithTimeout(testContext, 2*time.Second)
	defer cancel()
	if err := WithMemberMutation(ctx, p2, TestActorA, tenant, func(pgx.Tx) (MemberEvent, error) { return MemberEvent{}, rollback }); !errors.Is(err, rollback) {
		t.Fatal("cancelled lock waiter leaked context", err)
	}
}

func TestMembersInvitationIntegrityAndAtomicEvidence(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)
	pool := db.pool(t, "hukid_members_runtime")
	id := "60000000-0000-4000-8000-000000000001"
	digest := make([]byte, 32)
	digest[0] = 1
	create := func(tx pgx.Tx) (MemberEvent, error) {
		err := insertMemberInvitation(testContext, tx, TestTenantA, TestActorA, id, digest)
		return MemberEvent{Action: "members.invitation.created", Target: id}, err
	}
	for _, table := range []string{"platform.audit_events", "platform.outbox_events"} {
		mustExec(t, db.admin, "ALTER TABLE "+table+" ADD CONSTRAINT injected_members_failure CHECK(false) NOT VALID")
		if WithMemberMutation(testContext, pool, TestActorA, TestTenantA, create) == nil {
			t.Fatal("evidence failure allowed commit")
		}
		var count int
		if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM tenancy.invitations`).Scan(&count); err != nil || count != 0 {
			t.Fatal("partial invitation survived", err)
		}
		if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM platform.audit_events WHERE target_id=$1`, id).Scan(&count); err != nil || count != 0 {
			t.Fatal("partial event survived", err)
		}
		mustExec(t, db.admin, "ALTER TABLE "+table+" DROP CONSTRAINT injected_members_failure")
		assertCleared(t, pool)
	}
	if err := WithMemberMutation(testContext, pool, TestActorA, TestTenantA, create); err != nil {
		t.Fatal(err)
	}
	var dump string
	if err := db.admin.QueryRow(testContext, `SELECT row_to_json(a)::text FROM platform.audit_events a WHERE target_id=$1`, id).Scan(&dump); err != nil || strings.Contains(dump, "synthetic-key") || strings.Contains(dump, "token_hash") {
		t.Fatal("unsafe audit", err)
	}
	// No free text actions, global evidence or cross-scope records from members.
	err := WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(testContext, `INSERT INTO platform.audit_events(tenant_id,actor_operator_identity_id,target_id,action,outcome,correlation_id) VALUES($1,$2,$2,'auth.login.completed','success',$2)`, TestTenantA, TestActorA)
		return err
	})
	expectCode(t, err, "42501")
	// One pending per tenant/HMAC. Replacing requires ending the old token first.
	err = WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(testContext, `INSERT INTO tenancy.invitations SELECT '60000000-0000-4000-8000-000000000002'::uuid,tenant_id,created_by,decode(repeat('dd',32),'hex'),recipient_hmac,recipient_ciphertext,recipient_nonce,recipient_key_version,roles,issuer_ids,state,delivery_state,revision,created_at,expires_at,recipient_delete_after,accepted_at,revoked_at,accepted_membership_id,accepted_lifecycle,target_membership_id,target_lifecycle,target_revoked_at FROM tenancy.invitations WHERE invitation_id=$1`, id)
		return err
	})
	expectCode(t, err, "23505")
	for _, set := range []string{
		`roles=ARRAY['unknown']`, `roles=ARRAY['tenant_admin','tenant_admin']`,
		`issuer_ids=ARRAY[gen_random_uuid()]`, `roles=ARRAY['issuer_operator']`,
		`roles=ARRAY[NULL]::text[]`, `recipient_nonce=decode('ab','hex')`,
		`recipient_hmac=NULL`, `state='accepted'`, `expires_at=created_at`,
		`accepted_membership_id='30000000-0000-4000-8000-000000000002',accepted_lifecycle=1,state='accepted',accepted_at=created_at`,
	} {
		_, err := db.admin.Exec(testContext, `UPDATE tenancy.invitations SET `+set+` WHERE invitation_id=$1`, id)
		if err == nil {
			t.Fatalf("invalid invitation accepted: %s", set)
		}
	}
	err = WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		return insertMemberInvitation(testContext, tx, TestTenantB, TestActorA, "60000000-0000-4000-8000-000000000003", []byte(strings.Repeat("d", 32)))
	})
	expectCode(t, err, "42501")
	// Ciphertext envelopes are separate and deletable; no recipient/plain token
	// fields exist in audit or idempotency. Retention worker is USR-T04/T09.
	err = WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(testContext, `INSERT INTO tenancy.invitation_delivery_secrets(tenant_id,invitation_id,ciphertext,nonce,key_version,created_at,delete_after) VALUES($1,$2,decode(repeat('ac',32),'hex'),decode(repeat('cd',12),'hex'),'synthetic-key',now(),now()+interval '1 hour')`, TestTenantA, id)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	assertCleared(t, pool)
}

// This fixture exercises the real transaction primitive and pure guard. It is
// deliberately not a public ChangeMembership handler (USR-T06).
func suspendTestAdmin(ctx context.Context, pool *pgxpool.Pool, actor, member string) error {
	return WithMemberMutation(ctx, pool, actor, TestTenantA, func(tx pgx.Tx) (MemberEvent, error) {
		var current tenancy.MemberAccess
		var admins int
		err := tx.QueryRow(ctx, `SELECT state,authorization_revision,ARRAY(SELECT role FROM tenancy.membership_roles r WHERE r.tenant_id=m.tenant_id AND r.membership_id=m.membership_id ORDER BY role) FROM tenancy.memberships m WHERE tenant_id=$1 AND membership_id=$2 FOR UPDATE`, TestTenantA, member).Scan(&current.State, &current.Revision, &current.Roles)
		if err != nil {
			return MemberEvent{}, err
		}
		err = tx.QueryRow(ctx, `SELECT count(*) FROM tenancy.memberships m JOIN tenancy.membership_roles r USING(tenant_id,membership_id) WHERE m.tenant_id=$1 AND m.state='active' AND r.role='tenant_admin'`, TestTenantA).Scan(&admins)
		if err != nil {
			return MemberEvent{}, err
		}
		if err = tenancy.CheckMembershipChange(current, "suspended", current.Roles, current.Revision, admins); err != nil {
			return MemberEvent{}, err
		}
		_, err = tx.Exec(ctx, `UPDATE tenancy.memberships SET state='suspended',authorization_revision=authorization_revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND membership_id=$2`, TestTenantA, member)
		return MemberEvent{Action: "members.membership.changed", Target: member}, err
	})
}

func TestMembersTenantLockSerializesLastAdminAndReleases(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)
	seedSecondAdmin(t, db)
	pools := []*pgxpool.Pool{db.pool(t, "hukid_members_runtime"), db.pool(t, "hukid_members_runtime")}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i, tc := range []struct{ actor, member string }{{TestActorA, TestMemberA}, {TestActorPending, testSecondAdmin}} {
		wg.Add(1)
		go func(i int, actor, member string) {
			defer wg.Done()
			<-start
			results <- suspendTestAdmin(testContext, pools[i], actor, member)
		}(i, tc.actor, tc.member)
	}
	close(start)
	wg.Wait()
	close(results)
	var success, blocked int
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, tenancy.ErrLastAdmin) {
			blocked++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || blocked != 1 {
		t.Fatal("last administrator race was not serialized")
	}
	var active, events int
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM tenancy.memberships WHERE tenant_id=$1 AND state='active'`, TestTenantA).Scan(&active); err != nil || active != 1 {
		t.Fatal("lost last administrator", err)
	}
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM platform.audit_events WHERE action='members.membership.changed'`).Scan(&events); err != nil || events != 1 {
		t.Fatal("loser emitted an event", err)
	}
	rollback := errors.New("synthetic rollback")
	if err := WithMemberMutation(testContext, pools[0], TestActorA, TestTenantA, func(pgx.Tx) (MemberEvent, error) { return MemberEvent{}, rollback }); !errors.Is(err, rollback) {
		t.Fatal("lost rollback")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic")
			}
		}()
		WithMemberMutation(testContext, pools[0], TestActorA, TestTenantA, func(pgx.Tx) (MemberEvent, error) { panic("synthetic panic") })
	}()
	cancelled, cancel := context.WithCancel(testContext)
	if err := WithMemberMutation(cancelled, pools[0], TestActorA, TestTenantA, func(pgx.Tx) (MemberEvent, error) {
		cancel()
		return MemberEvent{Action: "members.membership.changed", Target: TestMemberA}, nil
	}); err == nil {
		t.Fatal("cancelled mutation committed")
	}
	for _, pool := range pools {
		assertCleared(t, pool)
	}
	// A fresh connection takes the same lock after rollback/panic/cancellation.
	ctx, done := context.WithTimeout(testContext, 2*time.Second)
	defer done()
	if err := WithMemberMutation(ctx, pools[1], TestActorA, TestTenantA, func(pgx.Tx) (MemberEvent, error) { return MemberEvent{}, rollback }); !errors.Is(err, rollback) {
		t.Fatal("tenant lock leaked", err)
	}
}

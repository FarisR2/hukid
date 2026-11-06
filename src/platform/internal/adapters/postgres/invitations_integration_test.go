//go:build integration

package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"hukid.local/platform/internal/adapters/secretbox"
	a "hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
)

func invitationFixture(t *testing.T) (*testDatabase, *tenancy.InvitationService, *InvitationStore, *time.Time) {
	t.Helper()
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)
	f, e := os.Open("../../../config/user-management.test.json")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	p, e := tenancy.LoadMembershipPolicy(f, "test")
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	store := &InvitationStore{Pool: db.pool(t, "hukid_members_runtime"), Now: func() time.Time { return now }, Policy: p}
	box, e := secretbox.New([]byte(strings.Repeat("k", 32)), "invitations-test", rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	s := &tenancy.InvitationService{Store: store, Cipher: box, HMACKey: []byte(strings.Repeat("h", 32)), Random: rand.Reader, Policy: p}
	return db, s, store, &now
}
func inviteCommand(now time.Time, key string) tenancy.InvitationCommand {
	return tenancy.InvitationCommand{Actor: TestActorA, Tenant: TestTenantA, Operation: "invitation.create", Key: key, PrivilegeDeadline: now.Add(5 * time.Minute), Input: tenancy.InviteInput{Email: "Lab+recipient@EXAMPLE.invalid", Roles: []string{"support_readonly"}, IssuerIDs: []string{}}}
}
func mustInvite(t *testing.T, s *tenancy.InvitationService, c tenancy.InvitationCommand) tenancy.InvitationView {
	t.Helper()
	v, e := s.Execute(testContext, c)
	if e != nil {
		t.Fatal("invitation command", e)
	}
	return v
}
func invitationCounts(t *testing.T, db *testDatabase) (invitations, events, secrets, keys int) {
	t.Helper()
	e := db.admin.QueryRow(testContext, `SELECT (SELECT count(*) FROM tenancy.invitations),(SELECT count(*) FROM platform.audit_events WHERE action LIKE 'members.%'),(SELECT count(*) FROM tenancy.invitation_delivery_secrets),(SELECT count(*) FROM tenancy.member_idempotency)`).Scan(&invitations, &events, &secrets, &keys)
	if e != nil {
		t.Fatal(e)
	}
	return
}

func TestInvitationCommandsReplayReplacementRevocationAndReauthorization(t *testing.T) {
	db, s, store, now := invitationFixture(t)
	c := inviteCommand(*now, "create_invitation_001")
	v := mustInvite(t, s, c)
	if v.State != "pending" || v.DeliveryState != "queued" || v.Revision != 1 || v.RecipientHint != "***" {
		t.Fatal("wrong initial representation")
	}
	replay := c
	replay.Input.Email = "Lab+recipient@example.invalid"
	if got := mustInvite(t, s, replay); got.InvitationID != v.InvitationID {
		t.Fatal("domain normalization did not replay")
	}
	n, events, secrets, keys := invitationCounts(t, db)
	if n != 1 || events != 1 || secrets != 1 || keys != 1 {
		t.Fatal("duplicate replay effects")
	}
	changed := c
	changed.Input.Email = "different@example.invalid"
	if _, e := s.Execute(testContext, changed); !errors.Is(e, tenancy.ErrInvitationConflict) {
		t.Fatal("different payload allowed", e)
	}
	for _, role := range []string{"security_admin", "support_readonly", "issuer_operator"} {
		mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role=$1 WHERE membership_id=$2`, role, TestMemberA)
		if _, e := s.Execute(testContext, c); !errors.Is(e, tenancy.ErrDirectoryForbidden) {
			t.Fatal("replay not reauthorized", e)
		}
	}
	mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role='tenant_admin' WHERE membership_id=$1`, TestMemberA)
	mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='suspended' WHERE membership_id=$1`, TestMemberA)
	if _, e := s.Execute(testContext, c); !errors.Is(e, a.ErrTenant) {
		t.Fatal("suspended replay", e)
	}
	mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='active' WHERE membership_id=$1`, TestMemberA)
	expiredProof := c
	expiredProof.PrivilegeDeadline = *now
	if _, e := s.Execute(testContext, expiredProof); !errors.Is(e, a.ErrStepUp) {
		t.Fatal("stale MFA replay", e)
	}
	foreign := c
	foreign.Tenant = TestTenantB
	if _, e := s.Execute(testContext, foreign); !errors.Is(e, a.ErrTenant) {
		t.Fatal("foreign tenant command", e)
	}
	issuer := c
	issuer.Key = "issuer_invitation_001"
	issuer.Input.Roles = []string{"issuer_operator"}
	issuer.Input.IssuerIDs = []string{"70000000-0000-4000-8000-000000000001"}
	if _, e := s.Execute(testContext, issuer); !errors.Is(e, a.ErrDependency) {
		t.Fatal("invented issuer ownership", e)
	}
	replacement := c
	replacement.Key = "create_invitation_002"
	next := mustInvite(t, s, replacement)
	if next.InvitationID == v.InvitationID {
		t.Fatal("reinvitación reused token")
	}
	previous := mustInvite(t, s, c)
	if previous.State != "revoked" || previous.Revision != 2 || previous.RevokedAt == nil {
		t.Fatal("old invitation revived")
	}
	revoke := tenancy.InvitationCommand{Actor: c.Actor, Tenant: c.Tenant, Operation: "invitation.revoke", Key: "revoke_invitation_001", InvitationID: next.InvitationID, Reason: "invitation_cancelled", Revision: 2, PrivilegeDeadline: c.PrivilegeDeadline}
	if _, e := s.Execute(testContext, revoke); !errors.Is(e, tenancy.ErrInvitationRevision) {
		t.Fatal("stale revision allowed", e)
	}
	revoke.Revision = 1
	revoked := mustInvite(t, s, revoke)
	if revoked.State != "revoked" || revoked.Revision != 2 {
		t.Fatal("not revoked")
	}
	if got := mustInvite(t, s, revoke); got.Revision != 2 {
		t.Fatal("revoke replay compared stale If-Match")
	}
	revoke.Key = "revoke_invitation_002"
	revoke.Revision = 2
	if _, e := s.Execute(testContext, revoke); !errors.Is(e, tenancy.ErrInvitationState) {
		t.Fatal("terminal transition allowed", e)
	}
	_, _, secrets, _ = invitationCounts(t, db)
	if secrets != 0 {
		t.Fatal("revoked secrets retained")
	}
	assertCleared(t, store.Pool)
}

func TestInvitationAtomicEvidenceAndConcurrentCommands(t *testing.T) {
	db, s, store, now := invitationFixture(t)
	c := inviteCommand(*now, "atomic_invitation_001")
	for _, table := range []string{"audit_events", "outbox_events"} {
		mustExec(t, db.admin, `ALTER TABLE platform.`+table+` ADD CONSTRAINT invitation_test_reject CHECK(false) NOT VALID`)
		_, e := s.Execute(testContext, c)
		mustExec(t, db.admin, `ALTER TABLE platform.`+table+` DROP CONSTRAINT invitation_test_reject`)
		if !errors.Is(e, a.ErrDependency) {
			t.Fatal("evidence failure not reported", e)
		}
		n, events, secrets, keys := invitationCounts(t, db)
		if n+events+secrets+keys != 0 {
			t.Fatal("partial mutation")
		}
	}
	// A closed constraint forces outbox failure regardless of column grants.
	mustExec(t, db.admin, `ALTER TABLE platform.outbox_events ADD CONSTRAINT invitation_test_reject CHECK(false) NOT VALID`)
	c.Key = "atomic_invitation_002"
	c.Input.Email = "rollback@example.invalid"
	before, ev, sec, key := invitationCounts(t, db)
	if _, e := s.Execute(testContext, c); !errors.Is(e, a.ErrDependency) {
		t.Fatal("outbox failure not reported", e)
	}
	after, ev2, sec2, key2 := invitationCounts(t, db)
	if before != after || ev != ev2 || sec != sec2 || key != key2 {
		t.Fatal("mutation survived outbox failure")
	}
	mustExec(t, db.admin, `ALTER TABLE platform.outbox_events DROP CONSTRAINT invitation_test_reject`)
	// Hold the SAME tenant lock using a separate physical connection.
	tx, e := db.admin.Begin(testContext)
	if e != nil {
		t.Fatal(e)
	}
	if e = lockInvitationTenant(testContext, tx, TestTenantA, false); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Execute(testContext, c); !errors.Is(e, tenancy.ErrInvitationBusy) {
		t.Fatal("concurrent command did not signal retry", e)
	}
	foreign := c
	foreign.Actor = TestActorB
	if _, e = s.Execute(testContext, foreign); !errors.Is(e, a.ErrTenant) {
		t.Fatal("foreign actor learned tenant contention", e)
	}
	tx.Rollback(testContext)
	v := mustInvite(t, s, c)
	if mustInvite(t, s, c).InvitationID != v.InvitationID {
		t.Fatal("retry duplicated")
	}
	// Two simultaneous creates converge to a single pending recipient. Busy
	// callers retry after the winner; distinct keys must never revive old tokens.
	secondPool := db.pool(t, "hukid_members_runtime")
	otherStore := &InvitationStore{Pool: secondPool, Now: store.Now, Policy: store.Policy}
	other := *s
	other.Store = otherStore
	command := c
	command.Key = "atomic_invitation_003"
	done := make(chan error, 2)
	for _, service := range []*tenancy.InvitationService{s, &other} {
		go func(service *tenancy.InvitationService) { _, e := service.Execute(testContext, command); done <- e }(service)
	}
	for range 2 {
		if e := <-done; e != nil && !errors.Is(e, tenancy.ErrInvitationBusy) {
			t.Fatal(e)
		}
	}
	mustInvite(t, s, command)
	var pending int
	if e = db.admin.QueryRow(testContext, `SELECT count(*) FROM tenancy.invitations WHERE state='pending' AND tenant_id=$1`, TestTenantA).Scan(&pending); e != nil || pending != 1 {
		t.Fatal("duplicate pending", e)
	}
	assertCleared(t, store.Pool)
}

type notificationFunc func(context.Context, string, string, int64, tenancy.DeliveryPayload) error

func (f notificationFunc) Send(ctx context.Context, tenant, id string, generation int64, p tenancy.DeliveryPayload) error {
	return f(ctx, tenant, id, generation, p)
}

func TestInvitationDeliveryFailureRetryCrashDedupAndRetention(t *testing.T) {
	db, s, store, now := invitationFixture(t)
	c := inviteCommand(*now, "delivery_invitation_001")
	v := mustInvite(t, s, c)
	provider := &SyntheticNotifications{Store: store, Actor: c.Actor}
	var captured tenancy.DeliveryPayload
	calls := 0
	worker := &tenancy.InvitationWorker{Store: store, Cipher: s.Cipher, Now: store.Now}
	worker.Provider = notificationFunc(func(ctx context.Context, tenant, id string, g int64, p tenancy.DeliveryPayload) error {
		calls++
		captured = p
		return errors.New("provider details and secret must not escape")
	})
	if e := worker.Run(testContext, c.Actor, c.Tenant); e != nil {
		t.Fatal(e)
	}
	failed := mustInvite(t, s, c)
	if failed.State != "pending" || failed.DeliveryState != "failed" || calls != 1 {
		t.Fatal("provider failure changed invitation lifecycle")
	}
	digest := sha256.Sum256([]byte(captured.Token))
	var stored []byte
	if e := db.admin.QueryRow(testContext, `SELECT token_hash FROM tenancy.invitations WHERE invitation_id=$1`, v.InvitationID).Scan(&stored); e != nil || string(stored) != string(digest[:]) {
		t.Fatal("wrong token hash", e)
	}
	var serialized string
	if e := db.admin.QueryRow(testContext, `SELECT (SELECT row_to_json(i)::text FROM tenancy.invitations i WHERE invitation_id=$1)|| (SELECT row_to_json(d)::text FROM tenancy.invitation_delivery_secrets d WHERE invitation_id=$1)`, v.InvitationID).Scan(&serialized); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(serialized, captured.Email) || strings.Contains(serialized, captured.Token) {
		t.Fatal("plaintext at rest")
	}
	// Provider accepted, process dies before local FinishDelivery. Recreate it to
	// prove durable dedup does not rely on in-process memory.
	if e := provider.Send(testContext, c.Tenant, v.InvitationID, 1, captured); e != nil {
		t.Fatal(e)
	}
	changedPayload := captured
	changedPayload.Token = "different-synthetic-token"
	if e := provider.Send(testContext, c.Tenant, v.InvitationID, 1, changedPayload); e == nil {
		t.Fatal("provider accepted different payload for same generation")
	}
	worker.Provider = &SyntheticNotifications{Store: store, Actor: c.Actor}
	if e := worker.Run(testContext, c.Actor, c.Tenant); e != nil {
		t.Fatal(e)
	}
	sent := mustInvite(t, s, c)
	if sent.DeliveryState != "sent" || sent.State != "pending" {
		t.Fatal("delivery confused with acceptance")
	}
	var receipts int
	if e := db.admin.QueryRow(testContext, `SELECT count(*) FROM tenancy.synthetic_notification_receipts`).Scan(&receipts); e != nil || receipts != 1 {
		t.Fatal("duplicate provider acceptance", e)
	}
	if e := worker.Run(testContext, c.Actor, c.Tenant); e != nil {
		t.Fatal(e)
	}
	_, _, secrets, _ := invitationCounts(t, db)
	if secrets != 0 {
		t.Fatal("sent envelope retained")
	}
	next := c
	next.Key = "delivery_invitation_002"
	next.Input.Email = "expired-secret@example.invalid"
	pending := mustInvite(t, s, next)
	*now = now.Add(time.Duration(s.Policy.DeliverySecretSeconds) * time.Second)
	worker.Provider = notificationFunc(func(context.Context, string, string, int64, tenancy.DeliveryPayload) error {
		t.Fatal("expired secret sent")
		return nil
	})
	if e := worker.Run(testContext, c.Actor, c.Tenant); e != nil {
		t.Fatal(e)
	}
	var state, delivery string
	if e := db.admin.QueryRow(testContext, `SELECT state,delivery_state FROM tenancy.invitations WHERE invitation_id=$1`, pending.InvitationID).Scan(&state, &delivery); e != nil || state != "pending" || delivery != "queued" {
		t.Fatal("secret expiry changed acceptance state", e)
	}
	*now = v.ExpiresAt
	if e := worker.Run(testContext, c.Actor, c.Tenant); e != nil {
		t.Fatal(e)
	}
	*now = v.CreatedAt.Add(time.Duration(s.Policy.RecipientRetentionSeconds) * time.Second)
	if e := worker.Run(testContext, c.Actor, c.Tenant); e != nil {
		t.Fatal(e)
	}
	var remaining int
	if e := db.admin.QueryRow(testContext, `SELECT (SELECT count(*) FROM tenancy.invitations WHERE recipient_hmac IS NOT NULL)+(SELECT count(*) FROM tenancy.invitation_delivery_secrets)+(SELECT count(*) FROM tenancy.member_idempotency)`).Scan(&remaining); e != nil || remaining != 0 {
		t.Fatal("retention did not purge", e)
	}
	if e := db.admin.QueryRow(testContext, `SELECT count(*) FROM tenancy.invitations WHERE state='expired' AND octet_length(token_hash)=32`).Scan(&remaining); e != nil || remaining != 2 {
		t.Fatal("expiry erased hash or evidence", e)
	}
	assertCleared(t, store.Pool)
}

func TestInvitationUpgradeFrom0007PreservesRowsAndReceiptIsolation(t *testing.T) {
	db := newTestDatabase(t)
	if e := migrateThrough(testContext, db.admin, "0007_console_members.sql"); e != nil {
		t.Fatal(e)
	}
	mustBootstrap(t, db)
	pool := db.pool(t, "hukid_members_runtime")
	id := "60000000-0000-4000-8000-000000000008"
	if e := WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		return insertMemberInvitation(testContext, tx, TestTenantA, TestActorA, id, []byte(strings.Repeat("z", 32)))
	}); e != nil {
		t.Fatal(e)
	}
	var before, after string
	query := `SELECT row_to_json(i)::text FROM tenancy.invitations i WHERE invitation_id=$1`
	if e := db.admin.QueryRow(testContext, query, id).Scan(&before); e != nil {
		t.Fatal(e)
	}
	mustMigrate(t, db)
	mustMigrate(t, db)
	if e := db.admin.QueryRow(testContext, query, id).Scan(&after); e != nil || before != after {
		t.Fatal("0008 changed invitations", e)
	}
	if e := WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		_, e := tx.Exec(testContext, `INSERT INTO tenancy.synthetic_notification_receipts(tenant_id,invitation_id,generation,payload_hash) VALUES($1,$2,1,$3)`, TestTenantA, id, []byte(strings.Repeat("q", 32)))
		return e
	}); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		actor, tenant string
		want          int
	}{{TestActorA, TestTenantA, 1}, {TestActorB, TestTenantB, 0}, {TestActorA, TestTenantA, 1}} {
		e := WithTenant(testContext, pool, tc.actor, tc.tenant, func(tx pgx.Tx) error {
			var count int
			e := tx.QueryRow(testContext, `SELECT count(*) FROM tenancy.synthetic_notification_receipts`).Scan(&count)
			if e == nil && count != tc.want {
				t.Fatal("receipt crossed tenant")
			}
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
	}
	_, e := db.pool(t, "hukid_session_runtime").Exec(testContext, `SELECT * FROM tenancy.synthetic_notification_receipts`)
	expectCode(t, e, "42501")
	assertCleared(t, pool)
}

type invitationReader func([]byte) (int, error)

func (f invitationReader) Read(b []byte) (int, error) { return f(b) }

func TestInvitationFailureDuringReplacementKeepsOldTokenAndFreshness(t *testing.T) {
	db, s, _, now := invitationFixture(t)
	c := inviteCommand(*now, "replacement_atomic_001")
	first := mustInvite(t, s, c)
	c.Key = "replacement_atomic_002"
	mustExec(t, db.admin, `ALTER TABLE platform.outbox_events ADD CONSTRAINT invitation_test_reject CHECK(false) NOT VALID`)
	if _, e := s.Execute(testContext, c); !errors.Is(e, a.ErrDependency) {
		t.Fatal(e)
	}
	mustExec(t, db.admin, `ALTER TABLE platform.outbox_events DROP CONSTRAINT invitation_test_reject`)
	var state string
	var secrets int
	if e := db.admin.QueryRow(testContext, `SELECT state,(SELECT count(*) FROM tenancy.invitation_delivery_secrets WHERE invitation_id=$1) FROM tenancy.invitations WHERE invitation_id=$1`, first.InvitationID).Scan(&state, &secrets); e != nil || state != "pending" || secrets != 1 {
		t.Fatal("replacement failure destroyed old invitation", e)
	}
	s.Random = invitationReader(func(b []byte) (int, error) { *now = c.PrivilegeDeadline; return rand.Read(b) })
	if _, e := s.Execute(testContext, c); !errors.Is(e, a.ErrStepUp) {
		t.Fatal("MFA expired during material creation", e)
	}
	n, events, secrets, keys := invitationCounts(t, db)
	if n != 1 || events != 1 || secrets != 1 || keys != 1 {
		t.Fatal("expired proof committed replacement")
	}
}

func TestInvitationDeliveryRevocationDuringProviderAndCorruptEnvelope(t *testing.T) {
	db, s, store, now := invitationFixture(t)
	c := inviteCommand(*now, "delivery_race_invite_001")
	v := mustInvite(t, s, c)
	worker := &tenancy.InvitationWorker{Store: store, Cipher: s.Cipher, Now: store.Now}
	worker.Provider = notificationFunc(func(context.Context, string, string, int64, tenancy.DeliveryPayload) error {
		// This would deadlock if the worker held the tenant transaction during I/O.
		mustInvite(t, s, tenancy.InvitationCommand{Actor: c.Actor, Tenant: c.Tenant, Operation: "invitation.revoke", Key: "delivery_race_revoke_001", InvitationID: v.InvitationID, Reason: "security_response", Revision: 1, PrivilegeDeadline: c.PrivilegeDeadline})
		return nil
	})
	if e := worker.Run(testContext, c.Actor, c.Tenant); e != nil {
		t.Fatal(e)
	}
	if current := mustInvite(t, s, c); current.State != "revoked" || current.DeliveryState == "sent" {
		t.Fatal("late provider result revived invitation")
	}
	c.Key = "delivery_race_invite_002"
	v = mustInvite(t, s, c)
	mustExec(t, db.admin, `UPDATE tenancy.invitation_delivery_secrets SET ciphertext=decode(repeat('ab',32),'hex') WHERE invitation_id=$1`, v.InvitationID)
	worker.Provider = notificationFunc(func(context.Context, string, string, int64, tenancy.DeliveryPayload) error {
		t.Fatal("corrupt envelope delivered")
		return nil
	})
	if e := worker.Run(testContext, c.Actor, c.Tenant); e != nil {
		t.Fatal(e)
	}
	if current := mustInvite(t, s, c); current.State != "pending" || current.DeliveryState != "failed" {
		t.Fatal("cipher failure changed lifecycle")
	}
	// Prove additional table is default deny and tenant-scoped too.
	var count int
	if e := store.Pool.QueryRow(testContext, `SELECT count(*) FROM tenancy.synthetic_notification_receipts`).Scan(&count); e != nil || count != 0 {
		t.Fatal("receipt RLS", e)
	}
}

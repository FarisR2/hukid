//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	a "hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
	"strings"
	"testing"
	"time"
)

func acceptanceToken(t *testing.T, db *testDatabase, s *tenancy.InvitationService, v tenancy.InvitationView) string {
	t.Helper()
	var envelope a.Envelope
	if err := db.admin.QueryRow(testContext, `SELECT ciphertext,nonce,key_version FROM tenancy.invitation_delivery_secrets WHERE invitation_id=$1`, v.InvitationID).Scan(&envelope.Ciphertext, &envelope.Nonce, &envelope.KeyVersion); err != nil {
		t.Fatal(err)
	}
	plain, err := s.Cipher.Open(envelope, "hukid:invitation:v1:"+v.TenantID+":"+v.InvitationID+":delivery")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	var payload tenancy.DeliveryPayload
	if json.Unmarshal(plain, &payload) != nil {
		t.Fatal("payload")
	}
	return payload.Token
}
func acceptanceFixture(t *testing.T) (*testDatabase, *tenancy.InvitationService, *InvitationStore, *time.Time, *tenancy.AcceptanceService, tenancy.AcceptanceCommand) {
	db, s, store, now := invitationFixture(t)
	pool, err := OpenRuntimePool(testContext, store.Pool.Config().ConnString(), "hukid_members_runtime", 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store.Pool = pool
	v := mustInvite(t, s, inviteCommand(*now, "acceptance_invite_001"))
	token := acceptanceToken(t, db, s, v)
	accept := &tenancy.AcceptanceService{Store: store, Policy: s.Policy, HMACKey: s.HMACKey, Now: store.Now}
	command := tenancy.AcceptanceCommand{Actor: TestActorB, Key: "acceptance_command_001", Token: token, Proof: a.RecipientEvidence{Issuer: "test", Subject: "recipient", Email: "Lab+recipient@example.invalid", IssuedAt: *now, AuthTime: *now, ExpiresAt: now.Add(5 * time.Minute)}}
	return db, s, store, now, accept, command
}
func TestAcceptanceIdentityOneUseAndLiveReplay(t *testing.T) {
	db, _, store, now, s, c := acceptanceFixture(t)
	bad := c
	bad.Proof.Email = "other@example.invalid"
	if _, e := s.Execute(testContext, bad); !errors.Is(e, tenancy.ErrInvitationInvalid) {
		t.Fatal("wrong recipient", e)
	}
	bad = c
	bad.Proof.Email = "lab+recipient@example.invalid"
	if _, e := s.Execute(testContext, bad); !errors.Is(e, tenancy.ErrInvitationInvalid) {
		t.Fatal("local case folded", e)
	}
	bad = c
	bad.Proof.AuthTime = now.Add(-5 * time.Minute)
	if _, e := s.Execute(testContext, bad); !errors.Is(e, a.ErrRecipient) {
		t.Fatal("stale evidence", e)
	}
	bad = c
	bad.Token = strings.Repeat("A", 43)
	if _, e := s.Execute(testContext, bad); !errors.Is(e, tenancy.ErrInvitationInvalid) {
		t.Fatal("unknown token", e)
	}
	v, e := s.Execute(testContext, c)
	if e != nil {
		t.Fatal(e)
	}
	if v.TenantID != TestTenantA || v.Membership.OperatorIdentityID != TestActorB || v.Membership.Lifecycle != 1 || v.Membership.Revision != 1 || v.Membership.State != "active" {
		t.Fatal("incorrect membership")
	}
	if replay, e := s.Execute(testContext, c); e != nil || replay.Membership.MembershipID != v.Membership.MembershipID {
		t.Fatal("exact replay", e)
	}
	bad = c
	bad.Key = "acceptance_command_002"
	if _, e = s.Execute(testContext, bad); !errors.Is(e, tenancy.ErrInvitationInvalid) {
		t.Fatal("consumed token", e)
	}
	bad = c
	bad.Actor = TestActorA
	if _, e = s.Execute(testContext, bad); !errors.Is(e, tenancy.ErrInvitationInvalid) {
		t.Fatal("actor replay leak", e)
	}
	var count int
	if e = db.admin.QueryRow(testContext, `SELECT count(*) FROM platform.audit_events WHERE action='members.invitation.accepted'`).Scan(&count); e != nil || count != 1 {
		t.Fatal("duplicate evidence", e)
	}
	if e = db.admin.QueryRow(testContext, `SELECT count(*) FROM tenancy.invitation_delivery_secrets`).Scan(&count); e != nil || count != 0 {
		t.Fatal("secret retained", e)
	}
	mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='suspended' WHERE membership_id=$1`, v.Membership.MembershipID)
	if _, e = s.Execute(testContext, c); !errors.Is(e, tenancy.ErrMembershipExists) {
		t.Fatal("suspended replay", e)
	}
	mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='revoked',revoked_at=$2,authorization_revision=authorization_revision+1 WHERE membership_id=$1`, v.Membership.MembershipID, *now)
	if _, e = s.Execute(testContext, c); !errors.Is(e, tenancy.ErrMemberRevoked) {
		t.Fatal("revoked replay", e)
	}
	assertCleared(t, store.Pool)
}

func TestAcceptanceReentryAndOldInvitationCutoff(t *testing.T) {
	db, invites, store, now, s, c := acceptanceFixture(t)
	v, e := s.Execute(testContext, c)
	if e != nil {
		t.Fatal(e)
	}
	*now = now.Add(time.Second)
	// A still-pending invitation predating revocation must never reopen access.
	old := mustInvite(t, invites, inviteCommand(*now, "acceptance_old_invite"))
	oldToken := acceptanceToken(t, db, invites, old)
	*now = now.Add(time.Second)
	mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='revoked',revoked_at=$2,authorization_revision=2 WHERE membership_id=$1`, v.Membership.MembershipID, *now)
	if e = WithTenant(testContext, store.Pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		return ArchiveRevokedMembership(testContext, tx, TestTenantA, v.Membership.MembershipID)
	}); e != nil {
		t.Fatal(e)
	}
	bad := c
	bad.Token = oldToken
	bad.Key = "acceptance_old_command"
	if _, e = s.Execute(testContext, bad); !errors.Is(e, tenancy.ErrInvitationInvalid) {
		t.Fatal("old token reopened", e)
	}
	*now = now.Add(time.Second)
	fresh := inviteCommand(*now, "acceptance_new_invite")
	fresh.Input.Roles = []string{"security_admin"}
	next := mustInvite(t, invites, fresh)
	c.Token = acceptanceToken(t, db, invites, next)
	c.Key = "acceptance_new_command"
	reentered, e := s.Execute(testContext, c)
	if e != nil {
		t.Fatal(e)
	}
	m := reentered.Membership
	if m.MembershipID != v.Membership.MembershipID || m.Lifecycle != 2 || m.Revision != 3 || len(m.Roles) != 1 || m.Roles[0] != "security_admin" {
		t.Fatal("reentry restored wrong grants")
	}
	c.Token = oldToken
	c.Key = "acceptance_old_again"
	if _, e = s.Execute(testContext, c); !errors.Is(e, tenancy.ErrInvitationInvalid) {
		t.Fatal("replacement revived", e)
	}
	var count int
	if e = db.admin.QueryRow(testContext, `SELECT count(*) FROM tenancy.membership_history WHERE membership_id=$1 AND lifecycle=1 AND authorization_revision=2`, m.MembershipID).Scan(&count); e != nil || count != 1 {
		t.Fatal("history lost", e)
	}
}

func TestAcceptanceConcurrentAndAtomicRollback(t *testing.T) {
	db, _, store, _, s, c := acceptanceFixture(t)
	mustExec(t, db.admin, `CREATE FUNCTION platform.fail_acceptance() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='members.invitation.accepted' THEN RAISE EXCEPTION 'test rollback'; END IF; RETURN NEW; END $$`)
	mustExec(t, db.admin, `CREATE TRIGGER fail_acceptance BEFORE INSERT ON platform.audit_events FOR EACH ROW EXECUTE FUNCTION platform.fail_acceptance()`)
	if _, e := s.Execute(testContext, c); !errors.Is(e, a.ErrDependency) {
		t.Fatal("audit failure accepted", e)
	}
	var count int
	if e := db.admin.QueryRow(testContext, `SELECT count(*) FROM tenancy.memberships WHERE tenant_id=$1 AND operator_identity_id=$2`, TestTenantA, TestActorB).Scan(&count); e != nil || count != 0 {
		t.Fatal("partial membership", e)
	}
	mustExec(t, db.admin, `DROP TRIGGER fail_acceptance ON platform.audit_events`)
	tx, e := store.Pool.Begin(testContext)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(testContext, `SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text,6721587303))`, TestTenantA); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Execute(testContext, c); !errors.Is(e, tenancy.ErrInvitationBusy) {
		t.Fatal("tenant lock bypass", e)
	}
	tx.Rollback(testContext)
	results := make(chan error, 2)
	for range 2 {
		go func() { _, e := s.Execute(testContext, c); results <- e }()
	}
	successes := 0
	for range 2 {
		e := <-results
		if e == nil {
			successes++
		} else if !errors.Is(e, tenancy.ErrInvitationBusy) {
			t.Fatal(e)
		}
	}
	if successes < 1 {
		t.Fatal("no successful acceptance")
	}
	if _, e = s.Execute(testContext, c); e != nil {
		t.Fatal("retry", e)
	}
	if e = db.admin.QueryRow(testContext, `SELECT count(*) FROM tenancy.memberships WHERE tenant_id=$1 AND operator_identity_id=$2`, TestTenantA, TestActorB).Scan(&count); e != nil || count != 1 {
		t.Fatal("duplicate membership", e)
	}
	assertCleared(t, store.Pool)
}

func TestAcceptanceExpiredRevokedExistingAndInactive(t *testing.T) {
	for _, name := range []string{"expired", "revoked", "inactive_tenant", "active_member", "suspended_member"} {
		t.Run(name, func(t *testing.T) {
			db, _, _, now, s, c := acceptanceFixture(t)
			expected := tenancy.ErrInvitationInvalid
			switch name {
			case "expired":
				*now = now.Add(24 * time.Hour)
				c.Proof.IssuedAt = *now
				c.Proof.AuthTime = *now
				c.Proof.ExpiresAt = now.Add(time.Minute)
			case "revoked":
				mustExec(t, db.admin, `UPDATE tenancy.invitations SET state='revoked',revoked_at=created_at WHERE token_hash=$1`, a.Digest(c.Token))
			case "inactive_tenant":
				mustExec(t, db.admin, `UPDATE tenancy.tenants SET state='suspended' WHERE tenant_id=$1`, TestTenantA)
			default:
				state := "active"
				if name == "suspended_member" {
					state = "suspended"
				}
				mustExec(t, db.admin, `INSERT INTO tenancy.memberships(tenant_id,operator_identity_id,state) VALUES($1,$2,$3)`, TestTenantA, TestActorB, state)
				expected = tenancy.ErrMembershipExists
			}
			if _, err := s.Execute(testContext, c); !errors.Is(err, expected) {
				t.Fatal(name, err)
			}
			var count int
			if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM platform.audit_events WHERE action='members.invitation.accepted'`).Scan(&count); err != nil || count != 0 {
				t.Fatal("failed acceptance wrote success", err)
			}
		})
	}
}

func TestAcceptanceUpgradeAndLocatorPrivileges(t *testing.T) {
	db := newTestDatabase(t)
	if err := migrateThrough(testContext, db.admin, "0008_invitation_delivery.sql"); err != nil {
		t.Fatal(err)
	}
	mustBootstrap(t, db)
	mustMigrate(t, db)
	mustMigrate(t, db)
	pool := db.pool(t, "hukid_members_runtime")
	var found pgtype.UUID
	if err := pool.QueryRow(testContext, `SELECT tenancy.locate_invitation($1)`, a.Digest("unknown")).Scan(&found); err != nil || found.Valid {
		t.Fatal("locator leaked tenant", err)
	}
	for _, statement := range []string{`SELECT * FROM tenancy.invitations`, `SELECT * FROM tenancy.operator_identities`, `SELECT * FROM console_auth.sessions`, `SET ROLE hukid_invitation_locator`} {
		_, err := pool.Exec(testContext, statement)
		// Tenant RLS allows an empty invitation directory; it must never return a
		// global one. Other statements must fail for the isolated runtime.
		if statement == `SELECT * FROM tenancy.invitations` {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err == nil {
			t.Fatal("runtime inherited locator/identity authority")
		}
	}
	if _, err := (&LoginStore{Pool: db.pool(t, "hukid_session_runtime")}).ReadRecipientSession(testContext, a.Digest("no evidence"), time.Now()); !errors.Is(err, a.ErrRecipient) {
		t.Fatal("legacy evidence invented", err)
	}
}

//go:build integration

package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	a "hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
)

func membershipFixture(t *testing.T) (*testDatabase, *tenancy.MembershipService, *InvitationStore, *time.Time) {
	db, _, store, now := invitationFixture(t)
	seedSecondAdmin(t, db)
	*now = time.Now().UTC().Truncate(time.Microsecond)
	return db, &tenancy.MembershipService{Store: store, Policy: store.Policy}, store, now
}
func memberCommand(now time.Time) tenancy.MembershipCommand {
	return tenancy.MembershipCommand{Actor: TestActorA, Tenant: TestTenantA, MembershipID: testSecondAdmin, Key: "membership_change_001", Revision: 1, PrivilegeDeadline: now.Add(time.Minute), Input: tenancy.ChangeMembershipInput{State: "suspended", ReasonCode: "security_response"}}
}
func mustChange(t *testing.T, s *tenancy.MembershipService, c tenancy.MembershipCommand) tenancy.MemberView {
	t.Helper()
	v, e := s.Execute(testContext, c)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func readMember(t *testing.T, db *testDatabase, id string) (state string, rev int64) {
	t.Helper()
	if e := db.admin.QueryRow(testContext, `SELECT state,authorization_revision FROM tenancy.memberships WHERE membership_id=$1`, id).Scan(&state, &rev); e != nil {
		t.Fatal(e)
	}
	return
}
func TestMembershipLifecycleETagReplayAndHistory(t *testing.T) {
	db, s, store, now := membershipFixture(t)
	c := memberCommand(*now)
	if v := mustChange(t, s, c); v.State != "suspended" || v.Revision != 2 || v.Lifecycle != 1 {
		t.Fatal("suspension", v)
	}
	if v := mustChange(t, s, c); v.Revision != 2 {
		t.Fatal("duplicate replay")
	}
	conflict := c
	conflict.Input.State = "active"
	if _, e := s.Execute(testContext, conflict); !errors.Is(e, tenancy.ErrInvitationConflict) {
		t.Fatal("key reused", e)
	}
	c.Key = "membership_change_002"
	if _, e := s.Execute(testContext, c); !errors.Is(e, tenancy.ErrMemberRevision) {
		t.Fatal("stale ETag", e)
	}
	c.Revision = 2
	c.Input = tenancy.ChangeMembershipInput{State: "active", Roles: []string{"security_admin", "support_readonly"}, IssuerIDs: []string{}, ReasonCode: "access_change"}
	if v := mustChange(t, s, c); v.Revision != 3 || v.State != "active" || len(v.Roles) != 2 {
		t.Fatal("reactivation/grants", v)
	}
	c.Input.Roles = []string{"support_readonly", "security_admin"}
	if v := mustChange(t, s, c); v.Revision != 3 {
		t.Fatal("set canonicalization")
	}
	if v := mustChange(t, s, memberCommand(*now)); v.State != "active" || v.Revision != 3 {
		t.Fatal("replay must return current projection")
	}
	c.Key = "membership_change_003"
	c.Revision = 3
	c.Input = tenancy.ChangeMembershipInput{State: "revoked", ReasonCode: "operator_request"}
	if v := mustChange(t, s, c); v.State != "revoked" || v.Revision != 4 {
		t.Fatal("revocation", v)
	}
	if v := mustChange(t, s, c); v.Revision != 4 {
		t.Fatal("revocation replay")
	}
	c.Key = "membership_change_004"
	c.Revision = 4
	c.Input.State = "active"
	if _, e := s.Execute(testContext, c); !errors.Is(e, tenancy.ErrMemberRevoked) {
		t.Fatal("terminal lifecycle", e)
	}
	var revision int64
	var roles []string
	var events, outbox, keys int
	if e := db.admin.QueryRow(testContext, `SELECT authorization_revision,roles FROM tenancy.membership_history WHERE membership_id=$1 AND lifecycle=1`, testSecondAdmin).Scan(&revision, &roles); e != nil || revision != 4 || len(roles) != 2 {
		t.Fatal("archive", e)
	}
	if e := db.admin.QueryRow(testContext, `SELECT (SELECT count(*) FROM platform.audit_events WHERE action LIKE 'members.membership.%'),(SELECT count(*) FROM platform.outbox_events o JOIN platform.audit_events a USING(event_id) WHERE action LIKE 'members.membership.%'),(SELECT count(*) FROM tenancy.member_idempotency WHERE operation='membership.change')`).Scan(&events, &outbox, &keys); e != nil || events != 3 || outbox != 3 || keys != 3 {
		t.Fatal("atomic evidence", events, outbox, keys, e)
	}
	assertCleared(t, store.Pool)
}

func TestMembershipAuthorizationScopeAndAtomicRollback(t *testing.T) {
	db, s, store, now := membershipFixture(t)
	c := memberCommand(*now)
	for _, role := range []string{"security_admin", "support_readonly", "issuer_operator"} {
		mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role=$1 WHERE membership_id=$2`, role, TestMemberA)
		if _, e := s.Execute(testContext, c); !errors.Is(e, tenancy.ErrDirectoryForbidden) {
			t.Fatal("unauthorized role", e)
		}
	}
	mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role='tenant_admin' WHERE membership_id=$1`, TestMemberA)
	invalid := c
	invalid.Tenant = TestTenantB
	if _, e := s.Execute(testContext, invalid); !errors.Is(e, a.ErrTenant) {
		t.Fatal("foreign tenant", e)
	}
	invalid = c
	invalid.MembershipID = TestMemberB
	if _, e := s.Execute(testContext, invalid); !errors.Is(e, a.ErrTenant) {
		t.Fatal("foreign target", e)
	}
	invalid = c
	invalid.PrivilegeDeadline = *now
	if _, e := s.Execute(testContext, invalid); !errors.Is(e, a.ErrStepUp) {
		t.Fatal("expired MFA", e)
	}
	invalid = c
	invalid.Input = tenancy.ChangeMembershipInput{Roles: []string{"issuer_operator"}, IssuerIDs: []string{"70000000-0000-4000-8000-000000000001"}, ReasonCode: "access_change"}
	if _, e := s.Execute(testContext, invalid); !errors.Is(e, a.ErrDependency) {
		t.Fatal("unverified issuer grant", e)
	}
	// Failures after state, roles, history and key writes must roll back all effects.
	c.Input.State = "revoked"
	for _, table := range []string{"audit_events", "outbox_events"} {
		mustExec(t, db.admin, `ALTER TABLE platform.`+table+` ADD CONSTRAINT membership_test_reject CHECK(false) NOT VALID`)
		_, e := s.Execute(testContext, c)
		mustExec(t, db.admin, `ALTER TABLE platform.`+table+` DROP CONSTRAINT membership_test_reject`)
		if !errors.Is(e, a.ErrDependency) {
			t.Fatal("missing dependency failure", e)
		}
		state, rev := readMember(t, db, testSecondAdmin)
		var keys, history int
		if e := db.admin.QueryRow(testContext, `SELECT (SELECT count(*) FROM tenancy.member_idempotency),(SELECT count(*) FROM tenancy.membership_history WHERE membership_id=$1)`, testSecondAdmin).Scan(&keys, &history); e != nil || keys+history != 0 || state != "active" || rev != 1 {
			t.Fatal("partial mutation", e)
		}
	}
	mustChange(t, s, c)
	mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role='security_admin' WHERE membership_id=$1`, TestMemberA)
	if _, e := s.Execute(testContext, c); !errors.Is(e, tenancy.ErrDirectoryForbidden) {
		t.Fatal("replay authorization", e)
	}
	assertCleared(t, store.Pool)
}

func TestMembershipConcurrentLastAdministrators(t *testing.T) {
	for _, change := range []string{"suspended", "revoked", "demoted"} {
		t.Run(change, func(t *testing.T) {
			db, s, store, now := membershipFixture(t)
			config, e := pgxpool.ParseConfig(store.Pool.Config().ConnString())
			if e != nil {
				t.Fatal(e)
			}
			config.MaxConns = 4
			pool, e := pgxpool.NewWithConfig(testContext, config)
			if e != nil {
				t.Fatal(e)
			}
			defer pool.Close()
			concurrentStore := *store
			concurrentStore.Pool = pool
			service := *s
			service.Store = &concurrentStore
			commands := []tenancy.MembershipCommand{memberCommand(*now), memberCommand(*now)}
			commands[0].MembershipID = TestMemberA
			commands[1].Actor = TestActorPending
			commands[1].Key = "membership_second_001"
			for i := range commands {
				commands[i].Input.State = change
				if change == "demoted" {
					commands[i].Input = tenancy.ChangeMembershipInput{Roles: []string{"support_readonly"}, IssuerIDs: []string{}, ReasonCode: "access_change"}
				}
			}
			start := make(chan struct{})
			results := make(chan error, 2)
			var wg sync.WaitGroup
			for _, c := range commands {
				wg.Add(1)
				go func(c tenancy.MembershipCommand) {
					defer wg.Done()
					<-start
					_, err := service.Execute(testContext, c)
					results <- err
				}(c)
			}
			close(start)
			wg.Wait()
			close(results)
			successes := 0
			for err := range results {
				if err == nil {
					successes++
				} else if !errors.Is(err, tenancy.ErrLastAdmin) && !errors.Is(err, tenancy.ErrInvitationBusy) {
					t.Fatal("unexpected race error", err)
				}
			}
			if successes != 1 {
				t.Fatal("expected one winner", successes)
			}
			var admins int
			if e := db.admin.QueryRow(testContext, `SELECT count(*) FROM tenancy.memberships m JOIN tenancy.membership_roles r USING(tenant_id,membership_id) WHERE m.tenant_id=$1 AND m.state='active' AND r.role='tenant_admin'`, TestTenantA).Scan(&admins); e != nil || admins != 1 {
				t.Fatal("last admin lost", admins, e)
			}
			// Retry the loser after contention; it must now see the invariant under lock.
			for i, c := range commands {
				state, rev := readMember(t, db, c.MembershipID)
				if rev == 1 && state == "active" {
					c.Key = fmt.Sprintf("membership_retry_%03d", i)
					if _, e := service.Execute(testContext, c); !errors.Is(e, tenancy.ErrLastAdmin) {
						t.Fatal("last admin retry", e)
					}
				}
			}
			assertCleared(t, pool)
		})
	}
}

func TestMembershipLockAndCancelledCommand(t *testing.T) {
	db, s, _, now := membershipFixture(t)
	c := memberCommand(*now)
	tx, e := db.admin.Begin(testContext)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(testContext)
	if e = lockInvitationTenant(testContext, tx, TestTenantA, false); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Execute(testContext, c); !errors.Is(e, tenancy.ErrInvitationBusy) {
		t.Fatal("lock bypass", e)
	}
	tx.Rollback(testContext)
	ctx, cancel := context.WithCancel(testContext)
	cancel()
	if _, e = s.Execute(ctx, c); e == nil {
		t.Fatal("cancelled mutation")
	}
	if state, rev := readMember(t, db, testSecondAdmin); state != "active" || rev != 1 {
		t.Fatal("cancelled command wrote")
	}
	mustChange(t, s, c)
}

func TestMembershipSameValuesMFADeadlineAndExpiredKey(t *testing.T) {
	db, s, store, now := membershipFixture(t)
	c := memberCommand(*now)
	c.Input.State = "active"
	if v := mustChange(t, s, c); v.Revision != 2 {
		t.Fatal("no-op did not increment revision")
	}
	c.Key = "membership_same_values_002"
	c.Revision = 2
	if v := mustChange(t, s, c); v.Revision != 3 {
		t.Fatal("new write did not increment revision")
	}
	c.Key = "membership_mfa_expired_001"
	c.Revision = 3
	c.Input.State = "revoked"
	calls := 0
	store.Now = func() time.Time {
		calls++
		if calls >= 4 {
			return c.PrivilegeDeadline
		}
		return *now
	}
	if _, e := s.Execute(testContext, c); !errors.Is(e, a.ErrStepUp) {
		t.Fatal("MFA expired during transaction", e)
	}
	if state, rev := readMember(t, db, testSecondAdmin); state != "active" || rev != 3 {
		t.Fatal("expired proof committed")
	}
	store.Now = func() time.Time { return *now }
	mustChange(t, s, c)
	// Expired keys cease to be replays, but never undo terminality or revisions.
	*now = now.Add(time.Duration(store.Policy.IdempotencySeconds) * time.Second)
	c.PrivilegeDeadline = now.Add(time.Minute)
	if _, e := s.Execute(testContext, c); !errors.Is(e, tenancy.ErrMemberRevision) {
		t.Fatal("expired key replayed", e)
	}
}

func TestMembershipPatchRevocationThenInvitationReentry(t *testing.T) {
	db, invites, store, now, accept, c := acceptanceFixture(t)
	first, e := accept.Execute(testContext, c)
	if e != nil {
		t.Fatal(e)
	}
	*now = now.Add(time.Second)
	old := mustInvite(t, invites, inviteCommand(*now, "membership_old_invite_001"))
	oldToken := acceptanceToken(t, db, invites, old)
	*now = now.Add(time.Second)
	members := &tenancy.MembershipService{Store: store, Policy: store.Policy}
	command := memberCommand(*now)
	command.MembershipID = first.Membership.MembershipID
	command.Input.State = "revoked"
	mustChange(t, members, command)
	c.Key = "membership_old_accept_001"
	c.Token = oldToken
	if _, e = accept.Execute(testContext, c); !errors.Is(e, tenancy.ErrInvitationInvalid) {
		t.Fatal("old invitation reopened access", e)
	}
	*now = now.Add(time.Second)
	freshCommand := inviteCommand(*now, "membership_new_invite_001")
	freshCommand.Input.Roles = []string{"security_admin"}
	fresh := mustInvite(t, invites, freshCommand)
	c.Key = "membership_new_accept_001"
	c.Token = acceptanceToken(t, db, invites, fresh)
	reentered, e := accept.Execute(testContext, c)
	if e != nil || reentered.Membership.MembershipID != first.Membership.MembershipID || reentered.Membership.Revision != 3 || reentered.Membership.Lifecycle != 2 || len(reentered.Membership.Roles) != 1 || reentered.Membership.Roles[0] != "security_admin" {
		t.Fatal("PATCH/reentry compatibility", e)
	}
	var roles []string
	if e = db.admin.QueryRow(testContext, `SELECT roles FROM tenancy.membership_history WHERE membership_id=$1 AND lifecycle=1`, first.Membership.MembershipID).Scan(&roles); e != nil || len(roles) != 1 || roles[0] != "support_readonly" {
		t.Fatal("history overwritten", e)
	}
}

func TestMembershipIssuerScopePreservationRemovalAndLegacyRepair(t *testing.T) {
	db, s, _, now := membershipFixture(t)
	mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role='issuer_operator' WHERE membership_id=$1`, testSecondAdmin)
	c := memberCommand(*now)
	// Incomplete legacy grants cannot produce a success outside the public schema.
	if _, e := s.Execute(testContext, c); !errors.Is(e, a.ErrDependency) {
		t.Fatal("invalid legacy projection", e)
	}
	if state, rev := readMember(t, db, testSecondAdmin); state != "active" || rev != 1 {
		t.Fatal("invalid projection committed")
	}
	const issuer = "70000000-0000-4000-8000-000000000001"
	mustExec(t, db.admin, `INSERT INTO tenancy.membership_issuer_scopes(tenant_id,membership_id,issuer_id) VALUES($1,$2,$3)`, TestTenantA, testSecondAdmin, issuer)
	if v := mustChange(t, s, c); len(v.IssuerIDs) != 1 || v.IssuerIDs[0] != issuer {
		t.Fatal("suspension dropped scope")
	}
	c.Key = "membership_issuer_active_001"
	c.Revision = 2
	c.Input.State = "active"
	if v := mustChange(t, s, c); len(v.IssuerIDs) != 1 || v.IssuerIDs[0] != issuer {
		t.Fatal("reactivation changed scope")
	}
	// Explicit replacement removes issuer access; it never needs fabricated ownership.
	c.Key = "membership_issuer_remove_001"
	c.Revision = 3
	c.Input = tenancy.ChangeMembershipInput{Roles: []string{"security_admin"}, IssuerIDs: []string{}, ReasonCode: "access_change"}
	if v := mustChange(t, s, c); len(v.IssuerIDs) != 0 || len(v.Roles) != 1 || v.Roles[0] != "security_admin" {
		t.Fatal("issuer scope not removed")
	}
	mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role='issuer_operator' WHERE membership_id=$1`, testSecondAdmin)
	c.Key = "membership_legacy_repair_001"
	c.Revision = 4
	if v := mustChange(t, s, c); v.Revision != 5 || v.Roles[0] != "security_admin" {
		t.Fatal("cannot repair legacy grants")
	}
}

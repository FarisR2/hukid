//go:build integration

package postgres

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"hukid.local/platform/internal/adapters/secretbox"
	"hukid.local/platform/internal/audit"
	a "hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
)

func contextSession(t *testing.T, db *testDatabase, now *time.Time, tenant string) (*a.SessionService, *LoginStore, string) {
	t.Helper()
	store := &LoginStore{Pool: db.pool(t, "hukid_session_runtime")}
	contexts, err := tenancy.New(&OperatorStore{Discovery: db.pool(t, "hukid_context_runtime"), Tenant: db.pool(t, "hukid_tenant_runtime")})
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	rand.Read(key)
	box, _ := secretbox.New(key, "context-test", rand.Reader)
	family, _ := audit.NewID()
	id, _ := audit.NewID()
	raw := make([]byte, 32)
	rand.Read(raw)
	cookie := base64.RawURLEncoding.EncodeToString(raw)
	rand.Read(raw)
	csrf := base64.RawURLEncoding.EncodeToString(raw)
	plain, _ := json.Marshal(a.SessionSecrets{AccessToken: "access", RefreshToken: "refresh", CSRF: csrf})
	envelope, _ := box.Seal(plain, a.SessionGenerationAAD(family, 1))
	clear(plain)
	initial := a.InitialSession{FamilyID: family, SessionID: id, PolicyVersion: "auth-test-v1", CookieHash: a.Digest(cookie), CSRFHash: a.Digest(csrf), RefreshDigest: a.Digest("refresh"), Secrets: envelope, CreatedAt: *now, IdleExpiresAt: now.Add(time.Minute), AbsoluteExpiresAt: now.Add(time.Hour), Identity: a.VerifiedLogin{Issuer: "http://127.0.0.1:19090", Subject: "operator-test-a", AuthTime: *now, AMR: []string{"pwd", "otp"}, ACR: "urn:hukid:test:mfa"}}
	if err := store.CreateInitialSession(testContext, initial); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db.admin, `UPDATE console_auth.sessions SET active_tenant_id=$2,authorization_revision=1 WHERE cookie_hash=$1`, a.Digest(cookie), tenant)
	f, err := os.Open("../../../config/auth.test.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := a.LoadPolicy(f, "test")
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	service := &a.SessionService{Store: store, Contexts: contexts, Cipher: box, Policy: policy, Now: func() time.Time { return *now }}
	return service, store, cookie
}

func TestMembershipChangesReconcileSessionsAcrossTenants(t *testing.T) {
	db, members, memberStore, now := membershipFixture(t)
	const otherMember = "30000000-0000-4000-8000-000000000007"
	mustExec(t, db.admin, `INSERT INTO tenancy.memberships(tenant_id,membership_id,operator_identity_id) VALUES($1,$2,$3)`, TestTenantB, otherMember, TestActorA)
	mustExec(t, db.admin, `INSERT INTO tenancy.membership_roles(tenant_id,membership_id,role) VALUES($1,$2,'support_readonly')`, TestTenantB, otherMember)
	sessions, store, cookie := contextSession(t, db, now, TestTenantA)
	other, _, otherCookie := contextSession(t, db, now, TestTenantB)
	second, _, secondCookie := contextSession(t, db, now, TestTenantA)
	command := memberCommand(*now)
	command.Actor = TestActorPending
	command.MembershipID = TestMemberA
	command.Input = tenancy.ChangeMembershipInput{Roles: []string{"support_readonly"}, IssuerIDs: []string{}, ReasonCode: "access_change"}
	mustChange(t, members, command)
	view, err := sessions.Read(testContext, cookie)
	stored, readErr := store.ReadSession(testContext, a.Digest(cookie), *now)
	if err != nil || readErr != nil || view.ActiveTenantID != TestTenantA || stored.AuthorizationRevision != 2 {
		t.Fatal("role revision not reconciled", err, readErr)
	}
	contexts := sessions.Contexts.(*tenancy.Service)
	current, err := contexts.Context(testContext, TestActorA, TestTenantA)
	if err != nil || slices.Contains(current.Capabilities, "members:read") || current.AuthorizationRevision != 2 {
		t.Fatal("stale capabilities", err)
	}
	// A failed mutation must not clear context or advance the cached revision.
	command.Key = "context_suspend_001"
	command.Revision = 2
	command.Input = tenancy.ChangeMembershipInput{State: "suspended", ReasonCode: "security_response"}
	mustExec(t, db.admin, `ALTER TABLE platform.outbox_events ADD CONSTRAINT context_reject CHECK(false) NOT VALID`)
	_, err = members.Execute(testContext, command)
	mustExec(t, db.admin, `ALTER TABLE platform.outbox_events DROP CONSTRAINT context_reject`)
	if !errors.Is(err, a.ErrDependency) {
		t.Fatal("mutation should roll back", err)
	}
	if v, e := sessions.Read(testContext, cookie); e != nil || v.ActiveTenantID != TestTenantA {
		t.Fatal("rollback invalidated context", e)
	}
	mustChange(t, members, command)
	if v, e := sessions.Read(testContext, cookie); e != nil || v.ActiveTenantID != "" || v.CSRF != view.CSRF || v.AccessToken != view.AccessToken {
		t.Fatal("suspension must clear selection, preserve authentication", e)
	}
	if v, e := other.Read(testContext, otherCookie); e != nil || v.ActiveTenantID != TestTenantB {
		t.Fatal("independent tenant lost", e)
	}
	if _, e := contexts.Context(testContext, TestActorA, TestTenantA); !errors.Is(e, a.ErrTenant) {
		t.Fatal("suspended membership authorized", e)
	}
	identity, e := contexts.Me(testContext, a.Operator{Issuer: "http://127.0.0.1:19090", Subject: "operator-test-a"})
	if e != nil || len(identity.Tenants) != 1 || identity.Tenants[0].ID != TestTenantB {
		t.Fatal("wrong remaining contexts", e)
	}
	command.Key = "context_active_001"
	command.Revision = 3
	command.Input.State = "active"
	mustChange(t, members, command)
	if v, e := sessions.Read(testContext, cookie); e != nil || v.ActiveTenantID != "" {
		t.Fatal("reactivation silently selected tenant", e)
	}
	// Another session that has not read the suspension still revalidates live state.
	if v, e := second.Read(testContext, secondCookie); e != nil || v.ActiveTenantID != TestTenantA {
		t.Fatal("reactivated membership unavailable", e)
	}
	command.Key = "context_revoke_001"
	command.Revision = 4
	command.Input.State = "revoked"
	mustChange(t, members, command)
	if v, e := second.Read(testContext, secondCookie); e != nil || v.ActiveTenantID != "" {
		t.Fatal("revocation kept stale selection", e)
	}
	if v, e := other.Read(testContext, otherCookie); e != nil || v.ActiveTenantID != TestTenantB {
		t.Fatal("revocation affected other tenant", e)
	}
	assertCleared(t, memberStore.Pool)
}

func TestContextReconciliationCASLeaseRotationAndFailure(t *testing.T) {
	db, _, _, now := membershipFixture(t)
	sessions, store, cookie := contextSession(t, db, now, TestTenantA)
	old, err := store.ReadSession(testContext, a.Digest(cookie), *now)
	if err != nil {
		t.Fatal(err)
	}
	// A failed write must fail closed and retain the prior stored selection.
	mustExec(t, db.admin, `ALTER TABLE console_auth.sessions ADD CONSTRAINT context_revision_reject CHECK(authorization_revision=1) NOT VALID`)
	err = store.ReconcileSessionContext(testContext, a.Digest(cookie), old, a.ContextSelection{TenantID: TestTenantA, Revision: 2}, *now)
	mustExec(t, db.admin, `ALTER TABLE console_auth.sessions DROP CONSTRAINT context_revision_reject`)
	if !errors.Is(err, a.ErrDependency) {
		t.Fatal("failed reconciliation succeeded", err)
	}
	if err = store.ReconcileSessionContext(testContext, a.Digest(cookie), old, a.ContextSelection{}, *now); err != nil {
		t.Fatal(err)
	}
	if err = store.ReconcileSessionContext(testContext, a.Digest(cookie), old, a.ContextSelection{TenantID: TestTenantA, Revision: 1}, *now); !errors.Is(err, a.ErrDependency) {
		t.Fatal("obsolete reader overwrote selection", err)
	}
	if err = store.ReconcileSessionContext(testContext, a.Digest(cookie), old, a.ContextSelection{}, *now); err != nil {
		t.Fatal("identical reconciliation must be idempotent", err)
	}
	v, err := store.ClaimRefresh(testContext, a.Digest(cookie), old.CSRFHash, "79000000-0000-4000-8000-000000000001", *now, now.Add(a.RefreshLease))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.ReconcileSessionContext(testContext, a.Digest(cookie), v, a.ContextSelection{}, *now); !errors.Is(err, a.ErrSession) {
		t.Fatal("refresh lease was ignored", err)
	}
	if err = store.InvalidateFamily(testContext, old.FamilyID); err != nil {
		t.Fatal(err)
	}
	if _, err = sessions.Read(testContext, cookie); !errors.Is(err, a.ErrSession) {
		t.Fatal("revoked family survived", err)
	}
	if err = store.ReconcileSessionContext(testContext, a.Digest(cookie), v, a.ContextSelection{}, *now); !errors.Is(err, a.ErrSession) {
		t.Fatal("reconciliation revived revoked family", err)
	}
}

func TestContextScopesUpgradeAndOwnMembershipRLS(t *testing.T) {
	db := newTestDatabase(t)
	if err := migrateThrough(testContext, db.admin, "0009_invitation_acceptance.sql"); err != nil {
		t.Fatal(err)
	}
	mustBootstrap(t, db)
	now := time.Now().UTC().Truncate(time.Microsecond)
	sessions, store, cookie := contextSession(t, db, &now, TestTenantA)
	before, err := store.ReadSession(testContext, a.Digest(cookie), now)
	if err != nil {
		t.Fatal(err)
	}
	const issuerA = "70000000-0000-4000-8000-000000000001"
	const issuerB = "70000000-0000-4000-8000-000000000002"
	for _, v := range []struct{ tenant, member, issuer string }{{TestTenantA, TestMemberA, issuerA}, {TestTenantB, TestMemberB, issuerB}} {
		mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role='issuer_operator' WHERE membership_id=$1`, v.member)
		mustExec(t, db.admin, `INSERT INTO tenancy.membership_issuer_scopes(tenant_id,membership_id,issuer_id) VALUES($1,$2,$3)`, v.tenant, v.member, v.issuer)
	}
	mustMigrate(t, db)
	mustMigrate(t, db)
	after, err := store.ReadSession(testContext, a.Digest(cookie), now)
	if err != nil || after.Generation != before.Generation || after.FamilyID != before.FamilyID || !a.EqualDigest(after.CSRFHash, before.CSRFHash) {
		t.Fatal("upgrade changed existing session", err)
	}
	if v, e := sessions.Read(testContext, cookie); e != nil || v.ActiveTenantID != TestTenantA {
		t.Fatal("upgrade lost context", e)
	}
	pool := db.pool(t, "hukid_tenant_runtime")
	contexts, _ := tenancy.New(&OperatorStore{Discovery: db.pool(t, "hukid_context_runtime"), Tenant: pool})
	c, err := contexts.Context(testContext, TestActorA, TestTenantA)
	if err != nil || len(c.IssuerIDs) != 1 || c.IssuerIDs[0] != issuerA || slices.Contains(c.Capabilities, "members:read") {
		t.Fatal("incorrect scope projection", err)
	}
	for _, v := range []struct {
		actor, tenant string
		n             int
	}{{TestActorA, TestTenantA, 1}, {TestActorA, TestTenantB, 0}, {TestActorB, TestTenantB, 1}} {
		err := WithTenant(testContext, pool, v.actor, v.tenant, func(tx pgx.Tx) error {
			var n int
			if e := tx.QueryRow(testContext, `SELECT count(*) FROM tenancy.membership_issuer_scopes`).Scan(&n); e != nil {
				return e
			}
			if n != v.n {
				t.Fatal("scope RLS leaked")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		assertCleared(t, pool)
	}
	if _, err = pool.Exec(testContext, `DELETE FROM tenancy.membership_issuer_scopes`); err == nil {
		t.Fatal("AUTH gained scope write access")
	}
	if _, err = pool.Exec(testContext, `SELECT * FROM tenancy.invitations`); err == nil {
		t.Fatal("AUTH gained directory access")
	}
	mustExec(t, db.admin, `DELETE FROM tenancy.membership_issuer_scopes WHERE membership_id=$1`, TestMemberA)
	mustExec(t, db.admin, `UPDATE tenancy.memberships SET authorization_revision=2 WHERE membership_id=$1`, TestMemberA)
	c, err = contexts.Context(testContext, TestActorA, TestTenantA)
	if err != nil || len(c.IssuerIDs) != 0 || c.AuthorizationRevision != 2 {
		t.Fatal("stale issuer scope/revision", err)
	}
	mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='suspended',authorization_revision=3 WHERE membership_id=$1`, TestMemberA)
	if _, err = contexts.Context(testContext, TestActorA, TestTenantA); !errors.Is(err, a.ErrTenant) {
		t.Fatal("suspended scope remained authorized", err)
	}
	mustExec(t, db.admin, `UPDATE tenancy.tenants SET state='suspended' WHERE tenant_id=$1`, TestTenantB)
	if err := WithTenant(testContext, pool, TestActorB, TestTenantB, func(tx pgx.Tx) error {
		var n int
		err := tx.QueryRow(testContext, `SELECT count(*) FROM tenancy.membership_issuer_scopes`).Scan(&n)
		if err == nil && n != 0 {
			t.Fatal("suspended tenant leaked scopes")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshAndStepUpRotationCannotRestoreLostContext(t *testing.T) {
	for _, mode := range []string{"refresh", "step_up"} {
		t.Run(mode, func(t *testing.T) {
			db, members, _, now := membershipFixture(t)
			sessions, store, cookie := contextSession(t, db, now, TestTenantA)
			old, err := store.ReadSession(testContext, a.Digest(cookie), *now)
			if err != nil {
				t.Fatal(err)
			}
			command := memberCommand(*now)
			command.Actor = TestActorPending
			command.MembershipID = TestMemberA
			provider := &lifecycleOIDC{identity: a.VerifiedLogin{AccessToken: "next-access", RefreshToken: "next-refresh", AuthTime: *now, AMR: []string{"pwd", "otp"}, ACR: "urn:hukid:test:mfa"}}
			nextCookie := ""
			if mode == "refresh" {
				provider.refresh = func(_ context.Context) error { mustChange(t, members, command); return nil }
				lifecycle := &a.SessionLifecycle{Sessions: sessions, Store: store, OIDC: provider, Random: rand.Reader}
				v, err := sessions.Read(testContext, cookie)
				if err != nil {
					t.Fatal(err)
				}
				next, err := lifecycle.Refresh(testContext, cookie, v.CSRF)
				if err != nil {
					t.Fatal(err)
				}
				nextCookie = next.Cookie
			} else {
				// Model a completed OIDC exchange racing a committed suspension. The store
				// preserves the stored context; its next use must revalidate membership.
				mustChange(t, members, command)
				raw := make([]byte, 32)
				rand.Read(raw)
				nextCookie = base64.RawURLEncoding.EncodeToString(raw)
				id, _ := audit.NewID()
				plain, _ := json.Marshal(a.SessionSecrets{AccessToken: "next-access", RefreshToken: "next-refresh", CSRF: nextCookie})
				envelope, _ := sessions.Cipher.Seal(plain, a.SessionGenerationAAD(old.FamilyID, 2))
				clear(plain)
				rotation := a.SessionRotation{SessionID: id, CookieHash: a.Digest(nextCookie), CSRFHash: a.Digest(nextCookie), RefreshDigest: a.Digest("next-refresh"), Secrets: envelope, IdleExpiresAt: now.Add(time.Minute)}
				if err := store.RotateSession(testContext, old, rotation, &provider.identity, nil, *now); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := sessions.Read(testContext, cookie); !errors.Is(err, a.ErrSession) {
				t.Fatal("obsolete generation usable", err)
			}
			if v, err := sessions.Read(testContext, nextCookie); err != nil || v.ActiveTenantID != "" {
				t.Fatal("rotation restored suspended context", err)
			}
			if err := store.ReconcileSessionContext(testContext, a.Digest(cookie), old, a.ContextSelection{}, *now); !errors.Is(err, a.ErrSession) {
				t.Fatal("obsolete generation reconciled", err)
			}
		})
	}
}

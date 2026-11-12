//go:build integration

package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDirectoryReadIsolationFiltersAndLivePermissions(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)
	seedSecondAdmin(t, db)
	// Equal timestamps force the ID tie-breaker to participate in pagination.
	mustExec(t, db.admin, `UPDATE tenancy.memberships SET created_at='2026-01-01',updated_at=now(),lifecycle_started_at=now()`)
	pool := db.pool(t, "hukid_members_runtime")
	store := &DirectoryStore{Pool: pool}
	file, err := os.Open("../../../config/user-management.test.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := tenancy.LoadMembershipPolicy(file, "test")
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	service, err := tenancy.NewDirectory(store, []byte(strings.Repeat("c", 32)), policy, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.List(testContext, TestActorA, TestTenantA, "memberships", "limit=1")
	if err != nil || first.NextCursor == nil {
		t.Fatal("first page", err)
	}
	second, err := service.List(testContext, TestActorA, TestTenantA, "memberships", "limit=1&cursor="+*first.NextCursor)
	if err != nil || second.NextCursor != nil {
		t.Fatal("second page", err)
	}
	a, b := first.Items.([]tenancy.MemberView)[0], second.Items.([]tenancy.MemberView)[0]
	if a.MembershipID != TestMemberA || b.MembershipID != testSecondAdmin || a.TenantID != TestTenantA || b.TenantID != TestTenantA {
		t.Fatal("unstable or foreign page")
	}
	for _, q := range []string{"query=" + TestMemberA, "query=" + TestActorA, "state=active&role=tenant_admin&limit=100"} {
		p, e := service.List(testContext, TestActorA, TestTenantA, "memberships", q)
		if e != nil || len(p.Items.([]tenancy.MemberView)) == 0 {
			t.Fatal("filter", e)
		}
	}
	p, e := service.List(testContext, TestActorA, TestTenantA, "memberships", "state=revoked")
	if e != nil || len(p.Items.([]tenancy.MemberView)) != 0 {
		t.Fatal("empty filter", e)
	}
	for _, tc := range []struct {
		actor, tenant string
		count         int
	}{{TestActorB, TestTenantB, 1}, {TestActorA, TestTenantA, 2}} {
		p, e := service.List(testContext, tc.actor, tc.tenant, "memberships", "")
		if e != nil || len(p.Items.([]tenancy.MemberView)) != tc.count {
			t.Fatal("pool tenant scope", e)
		}
		assertCleared(t, pool)
	}
	if _, err = service.List(testContext, TestActorA, TestTenantB, "memberships", ""); !errors.Is(err, authentication.ErrTenant) {
		t.Fatal("foreign tenant allowed", err)
	}
	// Removing table SELECT proves denied roles never query the directory.
	for _, role := range []string{"issuer_operator", "support_readonly"} {
		mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role=$1 WHERE membership_id=$2`, role, TestMemberA)
		mustExec(t, db.admin, `REVOKE SELECT ON tenancy.invitations FROM hukid_members_runtime`)
		_, err = service.List(testContext, TestActorA, TestTenantA, "invitations", "")
		mustExec(t, db.admin, `GRANT SELECT ON tenancy.invitations TO hukid_members_runtime`)
		if !errors.Is(err, tenancy.ErrDirectoryForbidden) {
			t.Fatal("denied actor queried directory", err)
		}
		if _, err = service.List(testContext, TestActorA, TestTenantA, "memberships", ""); !errors.Is(err, tenancy.ErrDirectoryForbidden) {
			t.Fatal("member directory granted", err)
		}
	}
	mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role='security_admin' WHERE membership_id=$1`, TestMemberA)
	if _, err = service.List(testContext, TestActorA, TestTenantA, "memberships", ""); err != nil {
		t.Fatal(err)
	}
	if _, err = service.List(testContext, TestActorA, TestTenantA, "invitations", ""); !errors.Is(err, tenancy.ErrDirectoryForbidden) {
		t.Fatal("security admin invitation leak")
	}
	mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role='issuer_operator' WHERE membership_id=$1`, testSecondAdmin)
	if _, err = service.List(testContext, TestActorA, TestTenantA, "memberships", ""); !errors.Is(err, authentication.ErrDependency) {
		t.Fatal("incomplete legacy grants returned", err)
	}
	mustExec(t, db.admin, `INSERT INTO tenancy.membership_issuer_scopes(tenant_id,membership_id,issuer_id) VALUES($1,$2,$3)`, TestTenantA, testSecondAdmin, "70000000-0000-4000-8000-000000000001")
	if _, err = service.List(testContext, TestActorA, TestTenantA, "memberships", ""); err != nil {
		t.Fatal("complete stored projection rejected", err)
	}
	mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='suspended' WHERE membership_id=$1`, TestMemberA)
	if _, err = service.List(testContext, TestActorA, TestTenantA, "memberships", ""); !errors.Is(err, authentication.ErrTenant) {
		t.Fatal("stale suspended access")
	}
	assertCleared(t, pool)
	canceled, cancel := context.WithCancel(testContext)
	cancel()
	if _, err = service.List(canceled, TestActorB, TestTenantB, "memberships", ""); err == nil {
		t.Fatal("canceled read succeeded")
	}
	assertCleared(t, pool)
}

func TestDirectoryInvitationEffectiveExpiryAndMinimalProjection(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)
	pool := db.pool(t, "hukid_members_runtime")
	id := "60000000-0000-4000-8000-000000000001"
	err := WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		return insertMemberInvitation(testContext, tx, TestTenantA, TestActorA, id, []byte(strings.Repeat("h", 32)))
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &DirectoryStore{Pool: pool}
	now := time.Now().UTC()
	f := tenancy.DirectoryFilter{Limit: 25}
	rows, err := store.ReadDirectory(testContext, TestActorA, TestTenantA, "invitations", f, tenancy.DirectoryPosition{}, now)
	if err != nil || len(rows.Invitations) != 1 || rows.Invitations[0].RecipientHint != "***" || rows.Invitations[0].State != "pending" {
		t.Fatal("minimal invitation", err)
	}
	expires := rows.Invitations[0].ExpiresAt
	f.State = "expired"
	rows, err = store.ReadDirectory(testContext, TestActorA, TestTenantA, "invitations", f, tenancy.DirectoryPosition{}, expires)
	if err != nil || len(rows.Invitations) != 1 || rows.Invitations[0].State != "expired" || rows.Invitations[0].DeliveryState != "queued" {
		t.Fatal("effective deadline", err)
	}
	f.State = "pending"
	rows, err = store.ReadDirectory(testContext, TestActorA, TestTenantA, "invitations", f, tenancy.DirectoryPosition{}, expires)
	if err != nil || len(rows.Invitations) != 0 {
		t.Fatal("expired pending filter")
	}
	f.State = ""
	f.DeliveryState = "failed"
	rows, err = store.ReadDirectory(testContext, TestActorA, TestTenantA, "invitations", f, tenancy.DirectoryPosition{}, now)
	if err != nil || len(rows.Invitations) != 0 {
		t.Fatal("delivery filter")
	}
	f.DeliveryState = ""
	rows, err = store.ReadDirectory(testContext, TestActorA, TestTenantA, "invitations", f, tenancy.DirectoryPosition{}, expires.Add(8*24*time.Hour))
	if err != nil || rows.Invitations[0].RecipientHint != "redacted" {
		t.Fatal("retention disclosure")
	}
	rows, err = store.ReadDirectory(testContext, TestActorB, TestTenantB, "invitations", f, tenancy.DirectoryPosition{}, now)
	if err != nil || len(rows.Invitations) != 0 {
		t.Fatal("foreign invitation")
	}
	err = WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		return insertMemberInvitation(testContext, tx, TestTenantA, TestActorA, "60000000-0000-4000-8000-000000000002", []byte(strings.Repeat("j", 32)))
	})
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open("../../../config/user-management.test.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := tenancy.LoadMembershipPolicy(file, "test")
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	service, err := tenancy.NewDirectory(store, []byte(strings.Repeat("p", 32)), policy, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.List(testContext, TestActorA, TestTenantA, "invitations", "limit=1")
	if err != nil || first.NextCursor == nil {
		t.Fatal("invitation first page", err)
	}
	second, err := service.List(testContext, TestActorA, TestTenantA, "invitations", "limit=1&cursor="+*first.NextCursor)
	if err != nil || second.NextCursor != nil || len(second.Items.([]tenancy.InvitationView)) != 1 || first.Items.([]tenancy.InvitationView)[0].InvitationID == second.Items.([]tenancy.InvitationView)[0].InvitationID {
		t.Fatal("invitation continuation", err)
	}
	assertCleared(t, pool)
}

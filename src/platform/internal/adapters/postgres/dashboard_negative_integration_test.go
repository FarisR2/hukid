//go:build integration

package postgres

import (
	"errors"
	"net/url"
	"testing"
	"time"

	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/dashboard"
)

func TestDashboardNanosecondWindowAgainstMicrosecondSource(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)
	pool := db.pool(t, "hukid_dashboard_runtime")
	s := dashboardService(t, pool)
	a, _ := dashboard.NewActivity(s, make([]byte, 32))
	at := time.Date(2026, 1, 1, 12, 0, 0, 123456000, time.UTC)
	id := "97000000-0000-4000-8000-000000000001"
	mustExec(t, db.admin, `INSERT INTO platform.audit_events(event_id,tenant_id,target_id,action,outcome,correlation_id,recorded_at) VALUES($1,$2,$1,'members.invitation.created','success',$1,$3)`, id, TestTenantA, at)
	for _, tc := range []struct {
		name     string
		from, to time.Time
		want     int
	}{
		{"inclusive from", at, at.Add(time.Microsecond), 1},
		{"exclusive to", at.Add(-time.Microsecond), at, 0},
		{"one nanosecond after from", at.Add(time.Nanosecond), at.Add(time.Microsecond), 0},
		{"one nanosecond before to", at.Add(-time.Microsecond), at.Add(time.Nanosecond), 1},
		{"submicrosecond empty interval", at.Add(time.Nanosecond), at.Add(2 * time.Nanosecond), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{"from": {tc.from.Format(time.RFC3339Nano)}, "to": {tc.to.Format(time.RFC3339Nano)}}
			page, err := a.List(testContext, TestActorA, TestTenantA, q.Encode())
			if err != nil || len(page.Items) != tc.want || !page.Window.From.Equal(tc.from) || !page.Window.To.Equal(tc.to) {
				t.Fatalf("UTC [from,to) changed at storage precision: items=%d want=%d err=%v", len(page.Items), tc.want, err)
			}
			if tc.want == 1 && page.Items[0].EventID != id {
				t.Fatal("foreign event")
			}
			assertCleared(t, pool)
		})
	}
}

func TestDashboardCursorReauthorizesStoredMembershipAndScopes(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)
	seedSecondAdmin(t, db)
	pool := db.pool(t, "hukid_dashboard_runtime")
	s := dashboardService(t, pool)
	a, _ := dashboard.NewActivity(s, make([]byte, 32))
	from := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	for _, id := range []string{"97000000-0000-4000-8000-000000000002", "97000000-0000-4000-8000-000000000003"} {
		mustExec(t, db.admin, `INSERT INTO platform.audit_events(event_id,tenant_id,target_id,action,outcome,correlation_id,recorded_at) VALUES($1,$2,$1,'members.invitation.created','success',$1,$3)`, id, TestTenantA, from)
	}
	q := url.Values{"from": {from.Format(time.RFC3339)}, "to": {from.Add(time.Minute).Format(time.RFC3339)}, "limit": {"1"}}
	first, err := a.List(testContext, TestActorA, TestTenantA, q.Encode())
	if err != nil || first.NextCursor == nil {
		t.Fatal("first page", err)
	}
	q.Set("cursor", *first.NextCursor)
	denied := func(actor, tenant string, want error) {
		t.Helper()
		page, err := a.List(testContext, actor, tenant, q.Encode())
		if !errors.Is(err, want) || page.Items != nil || page.NextCursor != nil || page.TenantID != "" {
			t.Fatalf("denied read leaked page: %v", err)
		}
		assertCleared(t, pool)
	}
	var secondActor string
	if err := db.admin.QueryRow(testContext, `SELECT operator_identity_id::text FROM tenancy.memberships WHERE membership_id=$1`, testSecondAdmin).Scan(&secondActor); err != nil {
		t.Fatal(err)
	}
	denied(secondActor, TestTenantA, dashboard.ErrCursor)
	denied(TestActorB, TestTenantB, dashboard.ErrCursor)
	denied(TestActorA, TestTenantB, authentication.ErrTenant)
	// Authorization precedes cursor handling, even if the audit source is broken.
	mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role='support_readonly' WHERE membership_id=$1`, TestMemberA)
	mustExec(t, db.admin, `REVOKE SELECT(event_id,tenant_id,actor_operator_identity_id,target_id,action,outcome,recorded_at) ON platform.audit_events FROM hukid_dashboard_runtime`)
	denied(TestActorA, TestTenantA, dashboard.ErrForbidden)
	mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='revoked',authorization_revision=authorization_revision+1 WHERE membership_id=$1`, TestMemberA)
	denied(TestActorA, TestTenantA, authentication.ErrTenant)
	mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='active' WHERE membership_id=$1`, TestMemberA)
	mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role='tenant_admin' WHERE membership_id=$1`, TestMemberA)
	denied(TestActorA, TestTenantA, dashboard.ErrCursor)
	// Even an accidental grant change without a revision update fails closed.
	mustExec(t, db.admin, `INSERT INTO tenancy.membership_roles VALUES($1,$2,'issuer_operator')`, TestTenantA, TestMemberA)
	mustExec(t, db.admin, `INSERT INTO tenancy.membership_issuer_scopes VALUES($1,$2,'70000000-0000-4000-8000-000000000001')`, TestTenantA, TestMemberA)
	denied(TestActorA, TestTenantA, authentication.ErrDependency)
}

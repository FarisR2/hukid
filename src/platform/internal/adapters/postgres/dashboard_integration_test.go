//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/dashboard"
)

func dashboardService(t *testing.T, pool *pgxpool.Pool) *dashboard.Service {
	t.Helper()
	data, err := os.ReadFile("../../../config/dashboard.test.json")
	if err != nil {
		t.Fatal(err)
	}
	var p dashboard.Policy
	if json.Unmarshal(data, &p) != nil {
		t.Fatal("policy")
	}
	s, err := dashboard.New(&DashboardStore{Pool: pool}, p, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDashboardOverviewIsolationLivePermissionsAndNoWrites(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)
	seedSecondAdmin(t, db)
	// Two roles on one membership must still count it once.
	mustExec(t, db.admin, `INSERT INTO tenancy.membership_roles VALUES($1,$2,'security_admin')`, TestTenantA, TestMemberA)
	pool := db.pool(t, "hukid_dashboard_runtime")
	s := dashboardService(t, pool)
	var before, after string
	evidence := `SELECT json_build_array((SELECT count(*) FROM platform.audit_events),(SELECT count(*) FROM platform.outbox_events))::text`
	if err := db.admin.QueryRow(testContext, evidence).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		actor, tenant string
		count         int64
	}{{TestActorA, TestTenantA, 2}, {TestActorB, TestTenantB, 1}, {TestActorA, TestTenantA, 2}} {
		o, err := s.Overview(testContext, tc.actor, tc.tenant, "")
		if err != nil {
			t.Fatal(err)
		}
		section := o.Sections["activeMembers"]
		if section.State != "available" || section.Value == nil || *section.Value != tc.count || section.AsOf == nil || section.AsOf.After(o.GeneratedAt) {
			t.Fatal("wrong tenant aggregate", section)
		}
		for name, section := range o.Sections {
			if name != "activeMembers" && (section.State != "notAuthorized" || section.Value != nil || section.AsOf != nil) {
				t.Fatal("future permission leaked", name)
			}
		}
		assertCleared(t, pool)
	}
	for _, tenant := range []string{TestTenantB, "10000000-0000-4000-8000-000000000099"} {
		if _, err := s.Overview(testContext, TestActorA, tenant, ""); !errors.Is(err, authentication.ErrTenant) {
			t.Fatal("foreign/missing tenant", err)
		}
	}
	// Snapshot membership metric ignores the selected historical window.
	o, err := s.Overview(testContext, TestActorA, TestTenantA, "from=2020-01-01T00:00:00Z&to=2020-01-02T00:00:00Z")
	if err != nil || *o.Sections["activeMembers"].Value != 2 {
		t.Fatal("historical member count", err)
	}
	mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='suspended',authorization_revision=authorization_revision+1 WHERE membership_id=$1`, testSecondAdmin)
	o, err = s.Overview(testContext, TestActorA, TestTenantA, "")
	if err != nil || *o.Sections["activeMembers"].Value != 1 {
		t.Fatal("inactive counted", err)
	}
	mustExec(t, db.admin, `DELETE FROM tenancy.membership_roles WHERE membership_id=$1`, TestMemberA)
	mustExec(t, db.admin, `INSERT INTO tenancy.membership_roles VALUES($1,$2,'support_readonly')`, TestTenantA, TestMemberA)
	// Force an error if audit is touched: forbidden must happen first.
	mustExec(t, db.admin, `REVOKE SELECT(event_id,tenant_id,actor_operator_identity_id,target_id,action,outcome,recorded_at) ON platform.audit_events FROM hukid_dashboard_runtime`)
	err = s.ReadActivity(testContext, TestActorA, TestTenantA, "", func(dashboard.Snapshot, dashboard.Filter) error { t.Fatal("denied callback"); return nil })
	if !errors.Is(err, dashboard.ErrForbidden) {
		t.Fatal("audit capability not checked first", err)
	}
	o, err = s.Overview(testContext, TestActorA, TestTenantA, "")
	if err != nil || o.Sections["activeMembers"].State != "notAuthorized" {
		t.Fatal("stale capabilities", err)
	}
	mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='suspended' WHERE membership_id=$1`, TestMemberA)
	if _, err = s.Overview(testContext, TestActorA, TestTenantA, ""); !errors.Is(err, authentication.ErrTenant) {
		t.Fatal("suspended actor", err)
	}
	assertCleared(t, pool)
	ctx, cancel := context.WithCancel(testContext)
	cancel()
	if _, err = s.Overview(ctx, TestActorB, TestTenantB, ""); err == nil {
		t.Fatal("cancellation ignored")
	}
	assertCleared(t, pool)
	if err = db.admin.QueryRow(testContext, evidence).Scan(&after); err != nil || before != after {
		t.Fatal("dashboard emitted business events", err)
	}
}

func TestDashboardActivityWindowAllowlistKeysetAndIssuerClosure(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)
	pool := db.pool(t, "hukid_dashboard_runtime")
	s := dashboardService(t, pool)
	from := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	to := from.Add(30 * time.Minute)
	insert := func(id, tenant, action, outcome string, at time.Time) {
		t.Helper()
		var tenantValue any = tenant
		if tenant == "" {
			tenantValue = nil
		}
		mustExec(t, db.admin, `INSERT INTO platform.audit_events(event_id,tenant_id,target_id,action,outcome,correlation_id,recorded_at) VALUES($1,$2,$1,$3,$4,$1,$5)`, id, tenantValue, action, outcome, at)
	}
	ids := []string{"80000000-0000-4000-8000-000000000001", "80000000-0000-4000-8000-000000000002", "80000000-0000-4000-8000-000000000003"}
	insert(ids[0], TestTenantA, "members.invitation.created", "success", from)
	insert(ids[1], TestTenantA, "auth.context.changed", "success", from)
	insert(ids[2], TestTenantA, "auth.refresh.completed", "success", from.Add(time.Minute))
	insert("80000000-0000-4000-8000-000000000004", TestTenantA, "members.invitation.created", "success", to)
	insert("80000000-0000-4000-8000-000000000005", TestTenantB, "members.invitation.created", "success", from)
	insert("80000000-0000-4000-8000-000000000006", "", "auth.context.changed", "success", from)
	insert("80000000-0000-4000-8000-000000000007", TestTenantA, "auth.request.denied", "denied", from)
	insert("80000000-0000-4000-8000-000000000008", TestTenantA, "test.other.success", "success", from)
	insert("80000000-0000-4000-8000-000000000009", TestTenantA, "auth.logout.completed", "success", from.Add(-time.Microsecond))
	raw := "from=" + from.Format(time.RFC3339) + "&to=" + to.Format(time.RFC3339) + "&limit=1"
	var all []dashboard.Event
	var pos dashboard.Position
	for page := 0; page < 3; page++ {
		err := s.ReadActivity(testContext, TestActorA, TestTenantA, raw, func(r dashboard.Snapshot, f dashboard.Filter) error {
			rows, err := r.Activity(testContext, f, pos, to)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				t.Fatal("missing page")
			}
			all = append(all, rows[0])
			pos = dashboard.Position{At: rows[0].OccurredAt, ID: rows[0].EventID}
			if page < 2 && len(rows) != 2 {
				t.Fatal("missing lookahead")
			}
			if page == 2 && len(rows) != 1 {
				t.Fatal("foreign or nonallowlisted events included")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		assertCleared(t, pool)
	}
	for index, event := range all {
		if event.EventID != ids[2-index] || event.ActorID != nil || event.Outcome != "success" {
			t.Fatal("order/projection", event)
		}
	}
	encoded, _ := json.Marshal(all)
	for _, secret := range []string{"correlation", "tenantId", "subject", "email", "token", "payload"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("unsafe projection", secret)
		}
	}
	// asOf excludes a later event even within the effective window.
	err := s.ReadActivity(testContext, TestActorA, TestTenantA, raw, func(r dashboard.Snapshot, f dashboard.Filter) error {
		rows, err := r.Activity(testContext, f, dashboard.Position{}, from)
		if err != nil {
			return err
		}
		if len(rows) != 2 || rows[0].EventID != ids[1] {
			t.Fatal("asOf not applied")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Restricted grants and generic capabilities never authorize implicit ALL.
	mustExec(t, db.admin, `INSERT INTO tenancy.membership_roles VALUES($1,$2,'issuer_operator')`, TestTenantA, TestMemberA)
	mustExec(t, db.admin, `INSERT INTO tenancy.membership_issuer_scopes VALUES($1,$2,$3)`, TestTenantA, TestMemberA, "70000000-0000-4000-8000-000000000001")
	for _, q := range []string{"", "issuerId=70000000-0000-4000-8000-000000000001"} {
		if _, err := s.Overview(testContext, TestActorA, TestTenantA, q); !errors.Is(err, authentication.ErrDependency) {
			t.Fatal("ownership inferred", err)
		}
	}
	if _, err := s.Overview(testContext, TestActorA, TestTenantA, "issuerId=70000000-0000-4000-8000-000000000002"); !errors.Is(err, authentication.ErrTenant) {
		t.Fatal("foreign issuer", err)
	}
	// Defense in depth: unattributed events excluded even through the store port.
	err = (&DashboardStore{Pool: pool}).Read(testContext, TestActorA, TestTenantA, func(r dashboard.Snapshot) error {
		rows, err := r.Activity(testContext, dashboard.Filter{From: from, To: to, Limit: 25}, dashboard.Position{}, to)
		if err != nil {
			return err
		}
		if len(rows) != 0 {
			t.Fatal("unattributed issuer events")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDashboardCredentialUpgradeRLSAndFailure(t *testing.T) {
	db := newTestDatabase(t)
	if err := migrateThrough(testContext, db.admin, "0010_console_context_scopes.sql"); err != nil {
		t.Fatal(err)
	}
	mustBootstrap(t, db)
	var before, after string
	query := `SELECT json_build_array((SELECT json_agg(m ORDER BY membership_id) FROM tenancy.memberships m),(SELECT json_agg(a ORDER BY event_id) FROM platform.audit_events a))::text`
	if err := db.admin.QueryRow(testContext, query).Scan(&before); err != nil {
		t.Fatal(err)
	}
	mustMigrate(t, db)
	if err := db.admin.QueryRow(testContext, query).Scan(&after); err != nil || before != after {
		t.Fatal("upgrade modified data", err)
	}
	pool := db.pool(t, "hukid_dashboard_runtime")
	// No context means no rows. Tenant-local RLS also blocks a foreign selector.
	var count int
	if err := pool.QueryRow(testContext, `SELECT count(*) FROM tenancy.memberships`).Scan(&count); err != nil || count != 0 {
		t.Fatal("unscoped RLS", err)
	}
	err := WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(testContext, `SELECT count(*) FROM tenancy.memberships WHERE tenant_id=$1`, TestTenantB).Scan(&count)
	})
	if err != nil || count != 0 {
		t.Fatal("tenant RLS", err)
	}
	for _, statement := range []string{`SELECT correlation_id FROM platform.audit_events`, `SELECT * FROM console_auth.sessions`, `SELECT * FROM tenancy.operator_identities`, `SELECT * FROM tenancy.invitations`, `SELECT * FROM platform.outbox_events`, `UPDATE tenancy.memberships SET state='suspended'`, `DELETE FROM platform.audit_events`, `INSERT INTO tenancy.tenants(display_name) VALUES('forbidden')`} {
		_, err := pool.Exec(testContext, statement)
		expectCode(t, err, "42501")
	}
	// Runtime pool rejects a login that combines dashboard and writer privileges.
	var login string
	if err = pool.QueryRow(testContext, `SELECT current_user`).Scan(&login); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db.admin, "GRANT hukid_members_runtime TO "+pgx.Identifier{login}.Sanitize())
	u, _ := url.Parse(db.dsn)
	config := pool.Config().ConnConfig
	u.User = url.UserPassword(config.User, config.Password)
	unsafe, err := OpenRuntimePool(testContext, u.String(), "hukid_dashboard_runtime", 1)
	if err == nil {
		unsafe.Close()
		t.Fatal("combined runtime accepted")
	}
	mustExec(t, db.admin, "REVOKE hukid_members_runtime FROM "+pgx.Identifier{login}.Sanitize())
	// Read-only snapshot rejects writes even if a future SQL grant is accidental.
	mustExec(t, db.admin, `GRANT UPDATE ON tenancy.memberships TO hukid_dashboard_runtime`)
	err = (&DashboardStore{Pool: pool}).Read(testContext, TestActorA, TestTenantA, func(r dashboard.Snapshot) error {
		_, err := r.(*dashboardSnapshot).tx.Exec(testContext, `UPDATE tenancy.memberships SET state='suspended'`)
		return err
	})
	expectCode(t, err, "25006")
	assertCleared(t, pool)
	// Source failures are dependency errors, never successful empty activity.
	mustExec(t, db.admin, `REVOKE SELECT(event_id,tenant_id,actor_operator_identity_id,target_id,action,outcome,recorded_at) ON platform.audit_events FROM hukid_dashboard_runtime`)
	s := dashboardService(t, pool)
	err = s.ReadActivity(testContext, TestActorA, TestTenantA, "", func(r dashboard.Snapshot, f dashboard.Filter) error {
		_, err := r.Activity(testContext, f, dashboard.Position{}, time.Now().UTC())
		return err
	})
	if !errors.Is(err, authentication.ErrDependency) {
		t.Fatal("source failed as empty", err)
	}
	assertCleared(t, pool)
}

func TestDashboardSnapshotRevisionAndNextReadReauthorization(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)
	pool := db.pool(t, "hukid_dashboard_runtime")
	store := &DashboardStore{Pool: pool}
	err := store.Read(testContext, TestActorA, TestTenantA, func(r dashboard.Snapshot) error {
		before := r.Access()
		mustExec(t, db.admin, `UPDATE tenancy.memberships SET authorization_revision=authorization_revision+1 WHERE membership_id=$1`, TestMemberA)
		mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role='support_readonly' WHERE membership_id=$1`, TestMemberA)
		// The in-flight snapshot stays consistent; the following read must not.
		var revision int64
		if err := r.(*dashboardSnapshot).tx.QueryRow(testContext, `SELECT authorization_revision FROM tenancy.memberships WHERE membership_id=$1`, TestMemberA).Scan(&revision); err != nil {
			return err
		}
		if revision != before.Revision {
			t.Fatal("mixed authorization snapshots")
		}
		// Access returns copies: a cursor consumer cannot mutate scope in place.
		before.Roles[0] = "issuer_operator"
		if r.Access().Roles[0] != "tenant_admin" {
			t.Fatal("access alias")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = store.Read(testContext, TestActorA, TestTenantA, func(r dashboard.Snapshot) error {
		if r.Access().Revision != 2 || r.Access().Roles[0] != "support_readonly" {
			t.Fatal("stale authorization revision")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s := dashboardService(t, pool)
	err = s.ReadActivity(testContext, TestActorA, TestTenantA, "", func(dashboard.Snapshot, dashboard.Filter) error { t.Fatal("removed permission used"); return nil })
	if !errors.Is(err, dashboard.ErrForbidden) {
		t.Fatal(err)
	}
	mustExec(t, db.admin, `UPDATE tenancy.tenants SET state='suspended' WHERE tenant_id=$1`, TestTenantA)
	if _, err = s.Overview(testContext, TestActorA, TestTenantA, ""); !errors.Is(err, authentication.ErrTenant) {
		t.Fatal("suspended tenant", err)
	}
	assertCleared(t, pool)
}

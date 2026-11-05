//go:build integration

package postgres

import "testing"

func assertAuthEvents(t *testing.T, db *testDatabase) {
	t.Helper()
	for _, action := range []string{"auth.login.started", "auth.login.completed", "auth.step_up.started", "auth.step_up.completed", "auth.context.changed", "auth.refresh.completed", "auth.logout.completed", "auth.request.denied"} {
		var n int
		if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM platform.audit_events WHERE action=$1`, action).Scan(&n); err != nil || n == 0 {
			t.Fatalf("no integrated event for %s", action)
		}
	}
	var missing int
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM platform.audit_events a LEFT JOIN platform.outbox_events o USING(event_id) WHERE o.event_id IS NULL OR a.tenant_id IS DISTINCT FROM o.tenant_id`).Scan(&missing); err != nil || missing != 0 {
		t.Fatal("incomplete audit/outbox")
	}
}

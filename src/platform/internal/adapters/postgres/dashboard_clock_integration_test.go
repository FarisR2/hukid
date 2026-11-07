//go:build integration

package postgres

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"hukid.local/platform/internal/dashboard"
)

func TestDashboardOverviewUsesDatabaseClockForFreshness(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)
	store := &DashboardStore{Pool: db.pool(t, "hukid_dashboard_runtime")}
	data, err := os.ReadFile("../../../config/dashboard.test.json")
	if err != nil {
		t.Fatal(err)
	}
	var policy dashboard.Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatal(err)
	}
	// The process clock is deliberately behind the database. No timing race,
	// sleeps or tolerated future timestamps are needed to reproduce the bug.
	appTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	service, err := dashboard.New(store, policy, func() time.Time { return appTime })
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		o, err := service.Overview(testContext, TestActorA, TestTenantA, "")
		if err != nil {
			t.Fatal("valid database observation rejected", err)
		}
		s := o.Sections["activeMembers"]
		if s.State != "available" || s.Value == nil || *s.Value != 1 || s.AsOf == nil || s.AsOf.After(o.GeneratedAt) || !o.GeneratedAt.After(appTime) {
			t.Fatal("inconsistent source-clock metadata", s)
		}
	}
}

//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"hukid.local/platform/internal/dashboard"
)

type dashboardQueryStart struct{}

// Test-only tracer: never retain SQL, arguments, errors, row data or IDs.
// The owned pool is used serially, including by its tracer callbacks.
type dashboardQueryTiming struct {
	enabled bool
	samples map[string][]float64
}

func (m *dashboardQueryTiming) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	label := "transaction"
	switch {
	case strings.Contains(data.SQL, "set_config"):
		label = "context"
	case strings.Contains(data.SQL, "authorization_revision"):
		label = "authorization"
	case strings.Contains(data.SQL, "count(*)"):
		label = "members"
	case strings.Contains(data.SQL, "FROM platform.audit_events"):
		label = "activity"
	case strings.Contains(data.SQL, "clock_timestamp"):
		label = "clock"
	}
	return context.WithValue(ctx, dashboardQueryStart{}, struct {
		label string
		at    time.Time
	}{label, time.Now()})
}

func (m *dashboardQueryTiming) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	start := ctx.Value(dashboardQueryStart{}).(struct {
		label string
		at    time.Time
	})
	if m.enabled {
		m.samples[start.label] = append(m.samples[start.label], float64(time.Since(start.at).Nanoseconds())/1e6)
	}
}

type dashboardTimingSummary struct {
	Samples int     `json:"samples"`
	P50MS   float64 `json:"p50Ms"`
	P95MS   float64 `json:"p95Ms"`
	MaxMS   float64 `json:"maxMs"`
}

func summarizeDashboardTiming(values []float64) dashboardTimingSummary {
	sort.Float64s(values)
	// Nearest-rank percentiles, including small sample sets.
	return dashboardTimingSummary{len(values), values[(len(values)*50+99)/100-1], values[(len(values)*95+99)/100-1], values[len(values)-1]}
}

func TestDashboardQueryMeasurement(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)
	// Both tenants carry equal volume. Only A is authorized for this actor.
	for _, tenant := range []string{TestTenantA, TestTenantB} {
		mustExec(t, db.admin, `INSERT INTO platform.audit_events(event_id,tenant_id,target_id,action,outcome,correlation_id,recorded_at)
 SELECT md5($1::text||n::text)::uuid,$1::uuid,md5($1::text||n::text)::uuid,'auth.context.changed','success',
 md5($1::text||n::text)::uuid,'2026-01-02T00:00:00Z'::timestamptz-n*interval '1 second'
 FROM generate_series(1,10000) n`, tenant)
	}
	mustExec(t, db.admin, `ANALYZE platform.audit_events`)
	base := db.pool(t, "hukid_dashboard_runtime")
	config := base.Config()
	timing := &dashboardQueryTiming{samples: map[string][]float64{}}
	config.ConnConfig.Tracer = timing
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(testContext, config)
	if err != nil {
		t.Fatal("measurement pool unavailable")
	}
	defer pool.Close()
	service := dashboardService(t, pool)
	operations := map[string][]float64{}
	for sample := -3; sample < 30; sample++ {
		timing.enabled = sample >= 0
		start := time.Now()
		if _, err := service.Overview(testContext, TestActorA, TestTenantA, ""); err != nil {
			t.Fatal("measurement overview failed")
		}
		if sample >= 0 {
			operations["overview"] = append(operations["overview"], float64(time.Since(start).Nanoseconds())/1e6)
		}
		for _, limit := range []int{1, 100} {
			label := "activity-first"
			if limit == 100 {
				label = "activity-next"
			}
			start = time.Now()
			err = service.ReadActivity(testContext, TestActorA, TestTenantA, "", func(snapshot dashboard.Snapshot, _ dashboard.Filter) error {
				at := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
				filter := dashboard.Filter{From: at.Add(-24 * time.Hour), To: at, Limit: limit}
				position := dashboard.Position{}
				if limit == 100 {
					position = dashboard.Position{At: at.Add(-5000 * time.Second), ID: "00000000-0000-4000-8000-000000000000"}
				}
				rows, readErr := snapshot.Activity(testContext, filter, position, at)
				if readErr == nil && len(rows) != limit+1 {
					t.Fatal("measurement page did not enforce lookahead bound")
				}
				return readErr
			})
			if err != nil {
				t.Fatal("measurement activity failed")
			}
			if sample >= 0 {
				operations[label] = append(operations[label], float64(time.Since(start).Nanoseconds())/1e6)
			}
		}
	}
	timing.enabled = false
	queries := map[string]dashboardTimingSummary{}
	for label, values := range timing.samples {
		queries[label] = summarizeDashboardTiming(values)
	}
	if queries["members"].Samples != 30 || queries["activity"].Samples != 60 || queries["authorization"].Samples != 90 {
		t.Fatal("measurement query coverage changed")
	}
	requests := map[string]dashboardTimingSummary{}
	for label, values := range operations {
		requests[label] = summarizeDashboardTiming(values)
	}
	report := struct {
		Profile    string                            `json:"profile"`
		Queries    map[string]dashboardTimingSummary `json:"queries"`
		Operations map[string]dashboardTimingSummary `json:"operations"`
	}{"synthetic; PostgreSQL 18.6 loopback; 2 tenants x 10000 events; 1 connection; serial; 3 warmups; 30 samples; no SLA", queries, requests}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal("measurement encoding failed")
	}
	destination := filepath.Join("..", "..", "..", "..", "..", ".cache", "dashboard-queries.json")
	if err = os.WriteFile(destination, append(encoded, '\n'), 0600); err != nil {
		t.Fatal("cannot write sanitized measurement")
	}
	t.Log("Sanitized dashboard query measurement: .cache/dashboard-queries.json")
}

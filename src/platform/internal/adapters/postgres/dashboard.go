package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/dashboard"
)

type DashboardStore struct{ Pool *pgxpool.Pool }
type dashboardSnapshot struct {
	tx     pgx.Tx
	tenant string
	access dashboard.Access
}

func (r *dashboardSnapshot) Access() dashboard.Access {
	a := r.access
	a.Roles = append([]string{}, a.Roles...)
	a.IssuerIDs = append([]string{}, a.IssuerIDs...)
	return a
}

// Read accepts a previously authenticated actor ID. RLS is tenant defense in
// depth, not bearer validation or a replacement for the use-case capability gate.
func (s *DashboardStore) Read(ctx context.Context, actor, tenant string, fn func(dashboard.Snapshot) error) error {
	if !validID(actor) || !validID(tenant) {
		return authentication.ErrTenant
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return authentication.ErrDependency
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, `SELECT set_config('app.operator_id',$1,true),set_config('app.tenant_id',$2,true)`, actor, tenant); err != nil {
		return authentication.ErrDependency
	}
	r := &dashboardSnapshot{tx: tx, tenant: tenant}
	err = tx.QueryRow(ctx, `SELECT m.authorization_revision,
 ARRAY(SELECT role FROM tenancy.membership_roles WHERE tenant_id=m.tenant_id AND membership_id=m.membership_id ORDER BY role),
 ARRAY(SELECT issuer_id::text FROM tenancy.membership_issuer_scopes WHERE tenant_id=m.tenant_id AND membership_id=m.membership_id ORDER BY issuer_id)
 FROM tenancy.memberships m JOIN tenancy.tenants t ON t.tenant_id=m.tenant_id
 WHERE m.tenant_id=$1 AND m.operator_identity_id=$2 AND m.state='active' AND t.state='active'`, tenant, actor).Scan(&r.access.Revision, &r.access.Roles, &r.access.IssuerIDs)
	if errors.Is(err, pgx.ErrNoRows) {
		return authentication.ErrTenant
	}
	if err != nil {
		return authentication.ErrDependency
	}
	if err = fn(r); err != nil {
		return err
	}
	if tx.Commit(ctx) != nil {
		return authentication.ErrDependency
	}
	return nil
}

func (r *dashboardSnapshot) GeneratedAt(ctx context.Context) (time.Time, error) {
	var at time.Time
	if err := r.tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return time.Time{}, authentication.ErrDependency
	}
	return at.UTC(), nil
}

func (r *dashboardSnapshot) ActiveMembers(ctx context.Context) (int64, time.Time, error) {
	var count int64
	var asOf time.Time
	err := r.tx.QueryRow(ctx, `SELECT count(*),transaction_timestamp() FROM tenancy.memberships WHERE tenant_id=$1 AND state='active'`, r.tenant).Scan(&count, &asOf)
	if err != nil {
		return 0, time.Time{}, authentication.ErrDependency
	}
	return count, asOf.UTC(), nil
}

func (r *dashboardSnapshot) Activity(ctx context.Context, f dashboard.Filter, pos dashboard.Position, asOf time.Time) ([]dashboard.Event, error) {
	// This source has no issuer attribution. Do not treat tenant events as events
	// of every issuer, even if a future caller bypasses the use-case scope guard.
	if f.IssuerID != "" || len(r.access.IssuerIDs) > 0 {
		return []dashboard.Event{}, nil
	}
	if f.Limit < 1 || f.Limit > 100 || !f.From.Before(f.To) || asOf.IsZero() {
		return nil, dashboard.ErrInput
	}
	id := pos.ID
	if id == "" {
		id = "00000000-0000-0000-0000-000000000000"
	}
	if (pos.ID == "") != pos.At.IsZero() || pos.ID != "" && !validID(id) {
		return nil, dashboard.ErrCursor
	}
	rows, err := r.tx.Query(ctx, `SELECT event_id::text,action,outcome,recorded_at,actor_operator_identity_id::text,target_id::text
 FROM platform.audit_events WHERE tenant_id=$1 AND outcome='success'
 AND recorded_at >= $2 AND recorded_at < $3 AND recorded_at <= $4
 AND ($5 OR (recorded_at,event_id)<($6,$7::uuid))
 ORDER BY recorded_at DESC,event_id DESC LIMIT $8`, r.tenant, f.From, f.To, asOf, pos.ID == "", pos.At, id, f.Limit+1)
	if err != nil {
		return nil, authentication.ErrDependency
	}
	defer rows.Close()
	result := []dashboard.Event{}
	for rows.Next() {
		var event dashboard.Event
		if rows.Scan(&event.EventID, &event.Action, &event.Outcome, &event.OccurredAt, &event.ActorID, &event.TargetID) != nil {
			return nil, authentication.ErrDependency
		}
		event.OccurredAt = event.OccurredAt.UTC()
		result = append(result, event)
	}
	if rows.Err() != nil {
		return nil, authentication.ErrDependency
	}
	return result, nil
}

package postgres

import (
	"context"
	"github.com/jackc/pgx/v5"
	"hukid.local/platform/internal/audit"
)

// appendAuthEvent joins the mutation transaction. No payload, claims or errors.
func appendAuthEvent(ctx context.Context, tx pgx.Tx, action, outcome, actor, tenant, target string) error {
	return appendEvent(ctx, tx, action, outcome, actor, tenant, target)
}

// appendEvent keeps the minimal envelope shared by AUTH and membership stores.
func appendEvent(ctx context.Context, tx pgx.Tx, action, outcome, actor, tenant, target string) error {
	id, err := audit.NewID()
	if err != nil {
		return err
	}
	correlation := audit.Correlation(ctx)
	if correlation == "" {
		correlation, err = audit.NewID()
		if err != nil {
			return err
		}
	}
	if target == "" {
		target = correlation
	}
	_, err = tx.Exec(ctx, `INSERT INTO platform.audit_events(event_id,tenant_id,actor_operator_identity_id,target_id,action,outcome,correlation_id) VALUES($1,NULLIF($2,'')::uuid,NULLIF($3,'')::uuid,$4,$5,$6,$7)`, id, tenant, actor, target, action, outcome, correlation)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO platform.outbox_events(event_id,tenant_id) VALUES($1,NULLIF($2,'')::uuid)`, id, tenant)
	return err
}

// RecordFailure never infers actor or tenant from unverified credentials.
func (s *LoginStore) RecordFailure(ctx context.Context, failed bool) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackLogin(tx)
	action := "auth.request.denied"
	if failed {
		action = "auth.request.failed"
	}
	if err = appendAuthEvent(ctx, tx, action, "denied", "", "", ""); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

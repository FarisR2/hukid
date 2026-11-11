package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OpenRuntimePool checks the login's effective privileges before serving queries.
func OpenRuntimePool(ctx context.Context, dsn, role string, maxConnections int32) (*pgxpool.Pool, error) {
	if role != "hukid_tenant_runtime" && role != "hukid_context_runtime" && role != "hukid_session_runtime" && role != "hukid_members_runtime" && role != "hukid_dashboard_runtime" && role != "hukid_verification_runtime" {
		return nil, errors.New("unknown runtime role")
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("invalid database configuration")
	}
	if maxConnections > 0 {
		config.MaxConns = maxConnections
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, errors.New("cannot initialize runtime pool")
	}
	var safe bool
	err = pool.QueryRow(ctx, `SELECT NOT (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication)
AND NOT pg_has_role(current_user,'hukid_owner','MEMBER')
AND NOT pg_has_role(current_user,'hukid_context_reader','MEMBER')
AND NOT pg_has_role(current_user,'hukid_identity_writer','MEMBER')
AND NOT pg_has_role(current_user,'hukid_invitation_locator','MEMBER')
AND NOT EXISTS (SELECT FROM pg_catalog.pg_roles other WHERE other.rolname IN ('hukid_tenant_runtime','hukid_context_runtime','hukid_session_runtime','hukid_members_runtime','hukid_dashboard_runtime','hukid_verification_runtime') AND other.rolname<>$1 AND pg_has_role(current_user,other.oid,'MEMBER'))
AND NOT EXISTS (SELECT FROM pg_catalog.pg_roles inherited WHERE pg_has_role(current_user,inherited.oid,'MEMBER') AND (inherited.rolsuper OR inherited.rolbypassrls OR inherited.rolcreaterole OR inherited.rolcreatedb OR inherited.rolreplication))
AND NOT EXISTS (SELECT FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('tenancy','console_auth','platform') AND pg_has_role(current_user,c.relowner,'MEMBER'))
AND pg_has_role(current_user,$1,'USAGE') FROM pg_catalog.pg_roles WHERE rolname=current_user`, role).Scan(&safe)
	if err != nil || !safe {
		pool.Close()
		return nil, errors.New("unsafe runtime database role")
	}
	return pool, nil
}

func validID(value string) bool {
	var id pgtype.UUID
	return id.Scan(value) == nil && id.Valid && id.Bytes != [16]byte{}
}

// WithTenant accepts only actor/tenant IDs already authorized by the application.
// Transaction-local settings are parameters, never interpolated SQL. RLS is a
// second boundary; this helper does not authenticate the caller or grant access.
func WithTenant(ctx context.Context, pool *pgxpool.Pool, actorID, tenantID string, fn func(pgx.Tx) error) error {
	if !validID(actorID) || !validID(tenantID) {
		return errors.New("invalid actor or tenant ID")
	}
	return scoped(ctx, pool, actorID, tenantID, fn)
}

func scoped(ctx context.Context, pool *pgxpool.Pool, actorID, tenantID string, fn func(pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, `SELECT set_config('app.operator_id',$1,true),set_config('app.tenant_id',$2,true)`, actorID, tenantID); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type TenantContext struct {
	TenantID              string
	DisplayName           string
	MembershipID          string
	AuthorizationRevision int64
}

// DiscoverTenants is a minimal separate-port lookup after issuer/subject validation.
// It cannot read tenant tables or session secrets directly with its runtime role.
func DiscoverTenants(ctx context.Context, pool *pgxpool.Pool, issuer, subject string) (string, []TenantContext, error) {
	var actor string
	var result []TenantContext
	err := scoped(ctx, pool, "", "", func(tx pgx.Tx) error {
		var id pgtype.UUID
		if err := tx.QueryRow(ctx, `SELECT console_auth.resolve_operator($1,$2)`, issuer, subject).Scan(&id); err != nil {
			return err
		}
		if !id.Valid {
			return nil
		}
		actor = id.String()
		if _, err := tx.Exec(ctx, `SELECT set_config('app.operator_id',$1,true)`, actor); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT tenant_id::text,display_name,membership_id::text,authorization_revision FROM console_auth.operator_tenants()`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var tenant TenantContext
			if err := rows.Scan(&tenant.TenantID, &tenant.DisplayName, &tenant.MembershipID, &tenant.AuthorizationRevision); err != nil {
				return err
			}
			result = append(result, tenant)
		}
		return rows.Err()
	})
	return actor, result, err
}

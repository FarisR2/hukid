package postgres

import (
	"context"
	"errors"
	"net/url"
	"os"

	"github.com/jackc/pgx/v5"
)

// ConnectLocalDatabase opens the persistent single-machine database as its
// administrator. It is a provisioning helper for the "local" profile, not a
// production command: it needs HUKID_ENV=local and a loopback hukid_local target.
func ConnectLocalDatabase(ctx context.Context, dsn string) (*pgx.Conn, error) {
	config, err := pgx.ParseConfig(dsn)
	if err != nil || os.Getenv("HUKID_ENV") != "local" || dsn == "" {
		return nil, errors.New("explicit local database configuration is required")
	}
	if !localTarget(config) {
		return nil, errors.New("local database must use a loopback IP and the hukid_local database")
	}
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return nil, errors.New("cannot connect to the local database")
	}
	return conn, nil
}

// BootstrapLocal links one real IdP identity (issuer + subject) to one new tenant
// as tenant_admin. It never resets or re-grants: when the identity already exists
// the call is a no-op, so reruns cannot reactivate revoked memberships.
func BootstrapLocal(ctx context.Context, conn *pgx.Conn, issuer, subject, tenantName string) error {
	if os.Getenv("HUKID_ENV") != "local" || !localTarget(conn.Config()) {
		return errors.New("bootstrap is restricted to the loopback local database")
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "http" || u.Host == "" || len(subject) == 0 || len(subject) > 255 || len(tenantName) == 0 || len(tenantName) > 200 {
		return errors.New("issuer, subject and tenant name are required")
	}
	var superuser bool
	if err := conn.QueryRow(ctx, `SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname=current_user`).Scan(&superuser); err != nil || !superuser {
		return errors.New("local bootstrap requires the cluster administrator, never a runtime login")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(6721587303)`); err != nil {
		return err
	}
	var existing int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM tenancy.operator_identities WHERE oidc_issuer=$1 AND subject=$2`, issuer, subject).Scan(&existing); err != nil {
		return err
	}
	if existing != 0 {
		return tx.Commit(ctx)
	}
	var tenant, actor, member string
	if err = tx.QueryRow(ctx, `INSERT INTO tenancy.tenants(display_name) VALUES ($1) RETURNING tenant_id`, tenantName).Scan(&tenant); err != nil {
		return err
	}
	if err = tx.QueryRow(ctx, `INSERT INTO tenancy.operator_identities(oidc_issuer,subject) VALUES ($1,$2) RETURNING operator_identity_id`, issuer, subject).Scan(&actor); err != nil {
		return err
	}
	if err = tx.QueryRow(ctx, `INSERT INTO tenancy.memberships(tenant_id,operator_identity_id) VALUES ($1,$2) RETURNING membership_id`, tenant, actor).Scan(&member); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO tenancy.membership_roles(tenant_id,membership_id,role) VALUES ($1,$2,'tenant_admin')`, tenant, member); err != nil {
		return err
	}
	var event string
	if err = tx.QueryRow(ctx, `INSERT INTO platform.audit_events(tenant_id,actor_operator_identity_id,target_id,action,outcome,correlation_id) VALUES ($1,$2,$3,'local.bootstrap.completed','success',gen_random_uuid()) RETURNING event_id`, tenant, actor, member).Scan(&event); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO platform.outbox_events(event_id,tenant_id) VALUES ($1,$2)`, event, tenant); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

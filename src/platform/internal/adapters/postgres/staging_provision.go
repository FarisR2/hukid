package postgres

import (
	"context"
	"errors"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ConnectStagingDatabase opens the staging database as its owner for provisioning
// (migrate, first administrator). Like ConnectLocalDatabase it is a command-line
// helper, not a runtime path: it needs HUKID_ENV=staging and a target that passes
// stagingTarget (hukid_staging, explicit sslmode, plaintext only to a single-label alias).
func ConnectStagingDatabase(ctx context.Context, dsn string) (*pgx.Conn, error) {
	config, err := pgx.ParseConfig(dsn)
	if err != nil || os.Getenv("HUKID_ENV") != "staging" || dsn == "" {
		return nil, errors.New("explicit staging database configuration is required")
	}
	if !stagingTarget(config) {
		return nil, errors.New("staging database must be hukid_staging with an explicit sslmode and no fallbacks")
	}
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return nil, errors.New("cannot connect to the staging database")
	}
	return conn, nil
}

// validStagingIssuer accepts only a clean public https issuer: no credentials, query,
// fragment or trailing slash, which matches how the OIDC provider names itself.
func validStagingIssuer(issuer string) bool {
	u, err := url.Parse(issuer)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && !strings.HasSuffix(issuer, "/")
}

// RuntimeLoginRoles are the runtime roles the API opens pools for. Each login created
// here is a plain member of exactly one of them (OpenRuntimePool rejects anything else).
var RuntimeLoginRoles = []string{"session", "context", "tenant", "members", "dashboard"}

var runtimePassword = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)

// RuntimeLoginName is the staging login that carries one runtime role.
func RuntimeLoginName(role string) string { return "hukid_staging_" + role }

// ProvisionRuntimeLogins creates (or re-keys) one LOGIN per runtime role with the given
// password. It is idempotent so a rotation is just a rerun with new passwords. The
// logins are NOSUPERUSER and carry no other privilege than membership in their role.
// Passwords come from the caller's environment and are never logged or returned.
func ProvisionRuntimeLogins(ctx context.Context, conn *pgx.Conn, passwords map[string]string) error {
	if os.Getenv("HUKID_ENV") != "staging" || !stagingTarget(conn.Config()) {
		return errors.New("runtime logins are restricted to the staging database")
	}
	var superuser bool
	if err := conn.QueryRow(ctx, `SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname=current_user`).Scan(&superuser); err != nil || !superuser {
		return errors.New("runtime login provisioning requires the cluster administrator")
	}
	for _, role := range RuntimeLoginRoles {
		if !runtimePassword.MatchString(passwords[role]) {
			return errors.New("every runtime login needs a password of 32..128 characters in [A-Za-z0-9_-]")
		}
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	for _, role := range RuntimeLoginRoles {
		login, runtime := RuntimeLoginName(role), "hukid_"+role+"_runtime"
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname=$1)`, login).Scan(&exists); err != nil {
			return err
		}
		verb := "CREATE"
		if exists {
			verb = "ALTER"
		}
		// Identifiers are fixed constants and the password matched the allowlist above,
		// so plain formatting is safe here (DDL cannot take bind parameters).
		if _, err := tx.Exec(ctx, verb+" ROLE "+login+" LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+passwords[role]+"'"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "GRANT "+runtime+" TO "+login); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// BootstrapStaging links one real IdP identity (issuer + subject) to one new tenant as
// tenant_admin. Idempotent: an existing identity is left untouched, so reruns never
// reactivate a revoked membership.
func BootstrapStaging(ctx context.Context, conn *pgx.Conn, issuer, subject, tenantName string) error {
	if os.Getenv("HUKID_ENV") != "staging" || !stagingTarget(conn.Config()) {
		return errors.New("bootstrap is restricted to the staging database")
	}
	if !validStagingIssuer(issuer) || len(subject) == 0 || len(subject) > 255 || len(tenantName) == 0 || len(tenantName) > 200 {
		return errors.New("an https issuer, subject and tenant name are required")
	}
	return bootstrapIdentity(ctx, conn, issuer, subject, tenantName, "staging.bootstrap.completed", "staging bootstrap")
}

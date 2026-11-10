package postgres

import (
	"context"
	"errors"
	"net/url"
	"os"
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

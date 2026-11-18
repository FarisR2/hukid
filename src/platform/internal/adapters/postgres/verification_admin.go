package postgres

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"hukid.local/platform/internal/adapters/oid4vphttp"
)

// Maintenance operations for tenant verification (VER-T11 provisioning). They
// run from the command line with a privileged login (owner or a provisioning
// role), never from the runtime role and never over HTTP.

// Querier is what the maintenance operations need from a database handle; both
// *pgxpool.Pool and *pgx.Conn satisfy it.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ErrVerifierConfig reports an invalid verifier configuration or purge request.
var ErrVerifierConfig = errors.New("invalid verifier configuration")

const (
	maxClientIDLength = 256
	maxResponseURI    = 2048
)

// ConfigureVerifier creates or replaces the verifier configuration of a tenant:
// the client_id the wallet sees and the https response_uri that receives its
// answer. The response_uri must be the wallet endpoint this API serves
// (oid4vphttp.ResponsePath) with no userinfo, query or fragment, so a typo
// cannot send responses somewhere else. The tenant must exist.
func ConfigureVerifier(ctx context.Context, q Querier, tenant, clientID, responseURI string) error {
	if q == nil || !validID(tenant) || !validClientID(clientID) || !validResponseURI(responseURI) {
		return ErrVerifierConfig
	}
	if _, err := q.Exec(ctx, `INSERT INTO verification.verifier_configs(tenant_id,client_id,response_uri) VALUES($1::uuid,$2,$3)
ON CONFLICT (tenant_id) DO UPDATE SET client_id=EXCLUDED.client_id,response_uri=EXCLUDED.response_uri,updated_at=now()`,
		tenant, clientID, responseURI); err != nil {
		return err
	}
	return nil
}

func validClientID(value string) bool {
	return value != "" && len(value) <= maxClientIDLength && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\t\"")
}

func validResponseURI(value string) bool {
	if value == "" || len(value) > maxResponseURI {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.RawQuery == "" && !parsed.ForceQuery && parsed.Fragment == "" && parsed.Path == oid4vphttp.ResponsePath
}

// PurgeVerification deletes sessions older than retentionDays and the retired
// signing keys that no pending session still needs, at most limit of each. It
// returns how many of each it removed.
func PurgeVerification(ctx context.Context, q Querier, retentionDays, limit int) (sessions, keys int, err error) {
	if q == nil || retentionDays < 1 || retentionDays > 3650 || limit < 1 || limit > 1000 {
		return 0, 0, ErrVerifierConfig
	}
	if err = q.QueryRow(ctx, `SELECT verification.purge_sessions($1,$2)`, retentionDays, limit).Scan(&sessions); err != nil {
		return 0, 0, err
	}
	if err = q.QueryRow(ctx, `SELECT verification.purge_retired_keys($1)`, limit).Scan(&keys); err != nil {
		return sessions, 0, err
	}
	return sessions, keys, nil
}

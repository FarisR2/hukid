package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"hukid.local/platform/internal/oid4vp"
)

// VerificationStartStore starts per-tenant verification sessions (ADR-0033,
// VER-T11-c2). Pool must belong to hukid_verification_runtime: row security
// limits it to the tenant and operator set by WithTenant, so the caller must
// have authorized both (membership and capability) before calling Start.
type VerificationStartStore struct{ Pool *pgxpool.Pool }

// Start reads the tenant's verifier configuration and inserts a pending
// session that expires after ttl (the table caps it at 15 minutes). A tenant
// without configuration yields oid4vp.ErrConfig and creates nothing.
func (s *VerificationStartStore) Start(ctx context.Context, actor, tenant string, ttl time.Duration) (sessionID, clientID, responseURI string, expiresAt time.Time, err error) {
	if s == nil || s.Pool == nil || ttl <= 0 || ttl > oid4vp.MaxTTL {
		return "", "", "", time.Time{}, oid4vp.ErrConfig
	}
	err = WithTenant(ctx, s.Pool, actor, tenant, func(tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, `SELECT client_id,response_uri FROM verification.verifier_configs WHERE tenant_id=$1`, tenant).Scan(&clientID, &responseURI); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return oid4vp.ErrConfig
			}
			return e
		}
		return tx.QueryRow(ctx, `INSERT INTO verification.sessions(tenant_id,started_by,expires_at)
VALUES($1,$2,clock_timestamp()+make_interval(secs=>$3)) RETURNING session_id::text,expires_at`, tenant, actor, ttl.Seconds()).Scan(&sessionID, &expiresAt)
	})
	if err != nil {
		return "", "", "", time.Time{}, err
	}
	return sessionID, clientID, responseURI, expiresAt, nil
}

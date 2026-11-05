package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"hukid.local/platform/internal/authentication"
	"time"
)

func (s *LoginStore) ReadSession(ctx context.Context, hash []byte, now time.Time) (authentication.ReadSession, error) {
	var v authentication.ReadSession
	err := s.Pool.QueryRow(ctx, `SELECT `+sessionColumns+` FROM console_auth.sessions s JOIN console_auth.session_families f ON f.family_id=s.family_id WHERE s.cookie_hash=$1 AND s.state='active' AND f.state='active' AND f.refresh_lease IS NULL AND s.created_at<=$2 AND s.last_seen_at<=$2 AND s.idle_expires_at>$2 AND s.absolute_expires_at>$2 AND f.absolute_expires_at>$2`, hash, now).Scan(sessionTargets(&v)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, authentication.ErrSession
	}
	if err != nil {
		return v, authentication.ErrDependency
	}
	return v, nil
}

const sessionColumns = `s.family_id::text,s.operator_identity_id::text,COALESCE(s.active_tenant_id::text,''),f.policy_version,s.generation,s.csrf_hash,s.secret_ciphertext,s.secret_nonce,COALESCE(s.secret_key_version,''),s.created_at,s.last_seen_at,s.idle_expires_at,s.absolute_expires_at,f.created_at,s.refresh_digest`

func sessionTargets(v *authentication.ReadSession) []any {
	return []any{&v.FamilyID, &v.ActorID, &v.ActiveTenantID, &v.PolicyVersion, &v.Generation, &v.CSRFHash, &v.Secrets.Ciphertext, &v.Secrets.Nonce, &v.Secrets.KeyVersion, &v.CreatedAt, &v.LastSeenAt, &v.IdleExpiresAt, &v.AbsoluteExpiresAt, &v.FamilyCreatedAt, &v.RefreshDigest}
}

func (s *LoginStore) TouchSession(ctx context.Context, hash []byte, now time.Time, idle time.Duration) error {
	result, err := s.Pool.Exec(ctx, `UPDATE console_auth.sessions s SET last_seen_at=$2,idle_expires_at=LEAST($3,s.absolute_expires_at),revision=s.revision+1 FROM console_auth.session_families f WHERE s.family_id=f.family_id AND s.cookie_hash=$1 AND s.state='active' AND f.state='active' AND f.refresh_lease IS NULL AND s.created_at<=$2 AND s.last_seen_at<=$2 AND s.idle_expires_at>$2 AND s.absolute_expires_at>$2`, hash, now, now.Add(idle))
	if err != nil {
		return authentication.ErrDependency
	}
	if result.RowsAffected() != 1 {
		return authentication.ErrSession
	}
	return nil
}

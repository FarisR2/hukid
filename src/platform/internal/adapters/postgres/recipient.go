package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	a "hukid.local/platform/internal/authentication"
	"time"
)

func (s *LoginStore) ReadRecipientSession(ctx context.Context, hash []byte, now time.Time) (a.ReadSession, error) {
	var v a.ReadSession
	err := s.Pool.QueryRow(ctx, `SELECT `+sessionColumns+` FROM console_auth.sessions s JOIN console_auth.session_families f ON f.family_id=s.family_id WHERE s.access_hash=$1 AND s.state='active' AND f.state='active' AND f.refresh_lease IS NULL AND s.created_at<=$2 AND s.last_seen_at<=$2 AND s.idle_expires_at>$2 AND s.absolute_expires_at>$2 AND f.absolute_expires_at>$2 ORDER BY s.created_at DESC LIMIT 1`, hash, now).Scan(sessionTargets(&v)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, a.ErrRecipient
	}
	if err != nil {
		return v, a.ErrDependency
	}
	return v, nil
}

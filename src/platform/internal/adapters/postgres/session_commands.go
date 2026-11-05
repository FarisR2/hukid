package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	a "hukid.local/platform/internal/authentication"
)

type commandSession struct {
	a.ReadSession
	state, familyState string
	deadline           *time.Time
}

// Lock the family first, then read its generation with a fresh READ COMMITTED
// snapshot. All rotation/logout paths take locks in this same order.
func lockCommandSession(ctx context.Context, tx pgx.Tx, hash []byte) (commandSession, error) {
	var v commandSession
	var family string
	if err := tx.QueryRow(ctx, `SELECT family_id::text FROM console_auth.sessions WHERE cookie_hash=$1`, hash).Scan(&family); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return v, a.ErrSession
		}
		return v, a.ErrDependency
	}
	if err := tx.QueryRow(ctx, `SELECT state,refresh_deadline FROM console_auth.session_families WHERE family_id=$1 FOR UPDATE`, family).Scan(&v.familyState, &v.deadline); err != nil {
		return v, a.ErrDependency
	}
	targets := append(sessionTargets(&v.ReadSession), &v.state)
	if err := tx.QueryRow(ctx, `SELECT `+sessionColumns+`,s.state FROM console_auth.sessions s JOIN console_auth.session_families f ON f.family_id=s.family_id WHERE s.cookie_hash=$1`, hash).Scan(targets...); err != nil {
		return v, a.ErrDependency
	}
	return v, nil
}

func invalidateFamily(ctx context.Context, tx pgx.Tx, family string) error {
	result, err := tx.Exec(ctx, `UPDATE console_auth.session_families SET state='revoked',refresh_lease=NULL,refresh_deadline=NULL,revision=revision+1 WHERE family_id=$1 AND state='active'`, family)
	if err != nil {
		return a.ErrDependency
	}
	if _, err := tx.Exec(ctx, `UPDATE console_auth.sessions SET state='revoked',secret_ciphertext=NULL,secret_nonce=NULL,secret_key_version=NULL,refresh_digest=NULL,revision=revision+1 WHERE family_id=$1`, family); err != nil {
		return a.ErrDependency
	}
	if result.RowsAffected() == 1 {
		if err := appendAuthEvent(ctx, tx, "auth.family.revoked", "success", "", "", family); err != nil {
			return a.ErrDependency
		}
	}
	return nil
}

func (s *LoginStore) InvalidateFamily(ctx context.Context, family string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return a.ErrDependency
	}
	defer rollbackLogin(tx)
	// UPDATE takes the same family lock as all other lifecycle commands.
	if err := invalidateFamily(ctx, tx, family); err != nil {
		return err
	}
	if tx.Commit(ctx) != nil {
		return a.ErrDependency
	}
	return nil
}

func (s *LoginStore) ClaimRefresh(ctx context.Context, cookie, csrf []byte, lease string, now, deadline time.Time) (a.ReadSession, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return a.ReadSession{}, a.ErrDependency
	}
	defer rollbackLogin(tx)
	v, err := lockCommandSession(ctx, tx, cookie)
	if err != nil {
		return a.ReadSession{}, err
	}
	if !a.EqualDigest(csrf, v.CSRFHash) {
		return a.ReadSession{}, a.ErrCSRF
	}
	if v.familyState != "active" {
		return a.ReadSession{}, a.ErrSession
	}
	// Proof from an obsolete generation can never recover its successor.
	// Reuse or an abandoned/uncertain lease revokes the entire family.
	if v.state != "active" || now.Before(v.LastSeenAt) || !now.Before(v.IdleExpiresAt) || !now.Before(v.AbsoluteExpiresAt) || (v.deadline != nil && !now.Before(*v.deadline)) {
		if err := invalidateFamily(ctx, tx, v.FamilyID); err != nil {
			return a.ReadSession{}, err
		}
		if tx.Commit(ctx) != nil {
			return a.ReadSession{}, a.ErrDependency
		}
		return a.ReadSession{}, a.ErrSession
	}
	if v.deadline != nil {
		return a.ReadSession{}, a.ErrRefreshBusy
	}
	if _, err := tx.Exec(ctx, `UPDATE console_auth.session_families SET refresh_lease=$2,refresh_deadline=$3,revision=revision+1 WHERE family_id=$1`, v.FamilyID, lease, deadline); err != nil {
		return a.ReadSession{}, a.ErrDependency
	}
	if tx.Commit(ctx) != nil {
		return a.ReadSession{}, a.ErrDependency
	}
	return v.ReadSession, nil
}

func (s *LoginStore) FinishRefresh(ctx context.Context, old a.ReadSession, lease string, next a.SessionRotation, now time.Time) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return a.ErrDependency
	}
	defer rollbackLogin(tx)
	var valid bool
	if err := tx.QueryRow(ctx, `SELECT state='active' AND refresh_lease=$2 AND refresh_deadline>$3 AND absolute_expires_at>$3 FROM console_auth.session_families WHERE family_id=$1 FOR UPDATE`, old.FamilyID, lease, now).Scan(&valid); err != nil {
		return a.ErrDependency
	}
	if !valid {
		return a.ErrSession
	}
	// Preserve context and its revision from the stored generation, never HTTP.
	result, err := tx.Exec(ctx, `UPDATE console_auth.sessions SET state='rotated',secret_ciphertext=NULL,secret_nonce=NULL,secret_key_version=NULL,refresh_digest=NULL,revision=revision+1 WHERE family_id=$1 AND generation=$2 AND state='active' AND idle_expires_at>$3`, old.FamilyID, old.Generation, now)
	if err != nil {
		return a.ErrDependency
	}
	if result.RowsAffected() != 1 {
		return a.ErrSession
	}
	_, err = tx.Exec(ctx, `INSERT INTO console_auth.sessions(session_id,family_id,operator_identity_id,generation,cookie_hash,csrf_hash,created_at,last_seen_at,idle_expires_at,absolute_expires_at,active_tenant_id,authorization_revision,secret_ciphertext,secret_nonce,secret_key_version,refresh_digest) SELECT $3,family_id,operator_identity_id,generation+1,$4,$5,$6,$6,$7,absolute_expires_at,active_tenant_id,authorization_revision,$8,$9,$10,$11 FROM console_auth.sessions WHERE family_id=$1 AND generation=$2`, old.FamilyID, old.Generation, next.SessionID, next.CookieHash, next.CSRFHash, now, next.IdleExpiresAt, next.Secrets.Ciphertext, next.Secrets.Nonce, next.Secrets.KeyVersion, next.RefreshDigest)
	if err != nil {
		return a.ErrDependency
	}
	if _, err := tx.Exec(ctx, `UPDATE console_auth.session_families SET refresh_lease=NULL,refresh_deadline=NULL,revision=revision+1 WHERE family_id=$1`, old.FamilyID); err != nil {
		return a.ErrDependency
	}
	if err := appendAuthEvent(ctx, tx, "auth.refresh.completed", "success", old.ActorID, old.ActiveTenantID, old.FamilyID); err != nil {
		return a.ErrDependency
	}
	if tx.Commit(ctx) != nil {
		return a.ErrDependency
	}
	return nil
}

func (s *LoginStore) Logout(ctx context.Context, cookie, csrf []byte, now time.Time) (a.ReadSession, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return a.ReadSession{}, a.ErrDependency
	}
	defer rollbackLogin(tx)
	v, err := lockCommandSession(ctx, tx, cookie)
	if errors.Is(err, a.ErrSession) {
		return a.ReadSession{}, a.ErrCSRF
	}
	if err != nil {
		return a.ReadSession{}, err
	}
	if now.Before(v.CreatedAt) || !now.Before(v.AbsoluteExpiresAt) || !a.EqualDigest(csrf, v.CSRFHash) {
		return a.ReadSession{}, a.ErrCSRF
	}
	// An old tombstone may close the current family, but grants no read/refresh.
	var active a.ReadSession
	err = tx.QueryRow(ctx, `SELECT `+sessionColumns+` FROM console_auth.sessions s JOIN console_auth.session_families f ON f.family_id=s.family_id WHERE s.family_id=$1 AND s.state='active'`, v.FamilyID).Scan(sessionTargets(&active)...)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return a.ReadSession{}, a.ErrDependency
	}
	if err := invalidateFamily(ctx, tx, v.FamilyID); err != nil {
		return a.ReadSession{}, err
	}
	if v.familyState == "active" {
		if err := appendAuthEvent(ctx, tx, "auth.logout.completed", "success", v.ActorID, v.ActiveTenantID, v.FamilyID); err != nil {
			return a.ReadSession{}, a.ErrDependency
		}
	}
	if tx.Commit(ctx) != nil {
		return a.ReadSession{}, a.ErrDependency
	}
	return active, nil
}

package postgres

import (
	"context"
	a "hukid.local/platform/internal/authentication"
	"time"
)

// All session mutations lock family then generation, including refresh/logout.
// No provider exchange occurs while holding database locks.
func (s *LoginStore) RotateSession(ctx context.Context, old a.ReadSession, next a.SessionRotation, identity *a.VerifiedLogin, selection *a.ContextSelection, now time.Time) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return a.ErrDependency
	}
	defer rollbackLogin(tx)
	var active bool
	err = tx.QueryRow(ctx, `SELECT state='active' AND refresh_lease IS NULL AND absolute_expires_at>$2 FROM console_auth.session_families WHERE family_id=$1 FOR UPDATE`, old.FamilyID, now).Scan(&active)
	if err != nil {
		return a.ErrDependency
	}
	if !active {
		return a.ErrSession
	}
	result, err := tx.Exec(ctx, `UPDATE console_auth.sessions SET state='rotated',secret_ciphertext=NULL,secret_nonce=NULL,secret_key_version=NULL,refresh_digest=NULL,revision=revision+1 WHERE family_id=$1 AND generation=$2 AND state='active' AND operator_identity_id=$3 AND last_seen_at<=$4 AND idle_expires_at>$4 AND absolute_expires_at>$4`, old.FamilyID, old.Generation, old.ActorID, now)
	if err != nil {
		return a.ErrDependency
	}
	if result.RowsAffected() != 1 {
		return a.ErrSession
	}
	_, err = tx.Exec(ctx, `INSERT INTO console_auth.sessions(session_id,family_id,operator_identity_id,generation,cookie_hash,csrf_hash,created_at,last_seen_at,idle_expires_at,absolute_expires_at,active_tenant_id,authorization_revision,secret_ciphertext,secret_nonce,secret_key_version,refresh_digest) SELECT $3,family_id,operator_identity_id,generation+1,$4,$5,$6,$6,$7,absolute_expires_at,active_tenant_id,authorization_revision,$8,$9,$10,$11 FROM console_auth.sessions WHERE family_id=$1 AND generation=$2`, old.FamilyID, old.Generation, next.SessionID, next.CookieHash, next.CSRFHash, now, next.IdleExpiresAt, next.Secrets.Ciphertext, next.Secrets.Nonce, next.Secrets.KeyVersion, next.RefreshDigest)
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE console_auth.sessions SET access_hash=$2 WHERE session_id=$1`, next.SessionID, next.AccessHash)
	}
	if err != nil {
		return a.ErrDependency
	}
	if identity != nil {
		_, err = tx.Exec(ctx, `UPDATE console_auth.session_families SET auth_time=$2,amr=$3,acr=$4,revision=revision+1 WHERE family_id=$1`, old.FamilyID, identity.AuthTime, identity.AMR, identity.ACR)
		if err != nil {
			return a.ErrDependency
		}
	}
	if selection != nil {
		_, err = tx.Exec(ctx, `UPDATE console_auth.sessions SET active_tenant_id=$2,authorization_revision=$3 WHERE session_id=$1`, next.SessionID, selection.TenantID, selection.Revision)
		if err != nil {
			return a.ErrDependency
		}
	}
	action, tenant := "auth.step_up.completed", old.ActiveTenantID
	if selection != nil {
		action, tenant = "auth.context.changed", selection.TenantID
	}
	if err := appendAuthEvent(ctx, tx, action, "success", old.ActorID, tenant, old.FamilyID); err != nil {
		return a.ErrDependency
	}
	if tx.Commit(ctx) != nil {
		return a.ErrDependency
	}
	return nil
}

package postgres

import (
	"context"
	"time"

	a "hukid.local/platform/internal/authentication"
)

// PurgeSessions locks families in the same order as refresh/logout. Batches
// bound maintenance work; leased exchanges are never retried after a crash.
func (s *LoginStore) PurgeSessions(ctx context.Context, now time.Time) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return a.ErrDependency
	}
	defer rollbackLogin(tx)
	rows, err := tx.Query(ctx, `SELECT f.family_id::text,f.absolute_expires_at<=$1 FROM console_auth.session_families f WHERE f.absolute_expires_at<=$1 OR (f.state='active' AND (f.refresh_deadline<=$1 OR EXISTS(SELECT FROM console_auth.sessions s WHERE s.family_id=f.family_id AND s.state='active' AND s.idle_expires_at<=$1))) ORDER BY f.family_id FOR UPDATE SKIP LOCKED LIMIT 100`, now)
	if err != nil {
		return a.ErrDependency
	}
	type expiredFamily struct {
		id     string
		remove bool
	}
	var families []expiredFamily
	for rows.Next() {
		var f expiredFamily
		if err := rows.Scan(&f.id, &f.remove); err != nil {
			rows.Close()
			return a.ErrDependency
		}
		families = append(families, f)
	}
	rows.Close()
	if rows.Err() != nil {
		return a.ErrDependency
	}
	for _, f := range families {
		if err := invalidateFamily(ctx, tx, f.id); err != nil {
			return err
		}
		if f.remove {
			for _, query := range []string{
				`DELETE FROM console_auth.oidc_transactions WHERE family_id=$1`,
				`DELETE FROM console_auth.sessions WHERE family_id=$1`,
				`DELETE FROM console_auth.session_families WHERE family_id=$1`,
			} {
				if _, err := tx.Exec(ctx, query, f.id); err != nil {
					return a.ErrDependency
				}
			}
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM console_auth.oidc_transactions WHERE transaction_id IN (SELECT transaction_id FROM console_auth.oidc_transactions WHERE expires_at<=$1 ORDER BY expires_at LIMIT 100)`, now); err != nil {
		return a.ErrDependency
	}
	if tx.Commit(ctx) != nil {
		return a.ErrDependency
	}
	return nil
}

// StartSessionCleanup is owned by the API lifetime; stop joins the worker before
// its pool is closed. Errors do not authorize sessions or expose stored secrets.
func (s *LoginStore) StartSessionCleanup(parent context.Context) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			run, stop := context.WithTimeout(ctx, 5*time.Second)
			_ = s.PurgeSessions(run, time.Now())
			stop()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}

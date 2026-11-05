package postgres

import (
	"context"
	"errors"
	"os"

	"github.com/jackc/pgx/v5"
	"hukid.local/platform/internal/audit"
)

// InvalidateAuthTest is an offline laboratory recovery command, not a runtime
// API. Stop every API instance before running it. It preserves schema and history.
func InvalidateAuthTest(ctx context.Context, conn *pgx.Conn) error {
	if os.Getenv("HUKID_ENV") != "test" || os.Getenv("HUKID_TEST_DATABASE") != "1" || !testTarget(conn.Config()) {
		return errors.New("auth invalidation requires an explicit loopback test database")
	}
	var admin bool
	if err := conn.QueryRow(ctx, `SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname=current_user`).Scan(&admin); err != nil || !admin {
		return errors.New("auth invalidation requires the isolated cluster administrator")
	}
	id, err := audit.NewID()
	if err != nil {
		return err
	}
	ctx = audit.WithCorrelation(ctx, id)
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackLogin(tx)
	// No SKIP LOCKED: success must never mean only part of the lab was invalidated.
	// The offline precondition keeps this lock order separate from live commands.
	if _, err = tx.Exec(ctx, `LOCK TABLE console_auth.session_families,console_auth.sessions,console_auth.oidc_transactions IN EXCLUSIVE MODE`); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT family_id::text FROM console_auth.session_families ORDER BY family_id`)
	if err != nil {
		return err
	}
	var families []string
	for rows.Next() {
		var family string
		if err := rows.Scan(&family); err != nil {
			rows.Close()
			return err
		}
		families = append(families, family)
	}
	rows.Close()
	if rows.Err() != nil {
		return rows.Err()
	}
	for _, family := range families {
		if err := invalidateFamily(ctx, tx, family); err != nil {
			return err
		}
	}
	// Pending callbacks must not recreate a session after the service is enabled.
	if _, err = tx.Exec(ctx, `UPDATE console_auth.oidc_transactions SET consumed_at=GREATEST(clock_timestamp(),created_at),verifier_ciphertext=NULL,verifier_nonce=NULL,verifier_key_version=NULL WHERE consumed_at IS NULL`); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

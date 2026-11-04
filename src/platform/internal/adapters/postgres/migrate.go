package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migrate applies immutable, forward-only migrations under a session advisory lock.
// The caller must provision a dedicated migration connection, never a runtime pool.
func Migrate(ctx context.Context, conn *pgx.Conn) error {
	return migrateThrough(ctx, conn, "")
}

func migrateThrough(ctx context.Context, conn *pgx.Conn, last string) error {
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(6721587301)"); err != nil {
		return err
	}
	defer conn.Exec(context.Background(), "SELECT pg_advisory_unlock(6721587301)")
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS public.hukid_schema_migrations (name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now()); REVOKE ALL ON public.hukid_schema_migrations FROM PUBLIC;`); err != nil {
		return err
	}
	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	rows, err := conn.Query(ctx, "SELECT name, checksum FROM public.hukid_schema_migrations ORDER BY name")
	if err != nil {
		return err
	}
	applied := map[string]string{}
	for rows.Next() {
		var name, checksum string
		if err := rows.Scan(&name, &checksum); err != nil {
			rows.Close()
			return err
		}
		applied[name] = checksum
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	gap := false
	for _, name := range names {
		data, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		checksum := migrationChecksum(data)
		if previous, exists := applied[name]; exists {
			if gap || previous != checksum {
				return errors.New("migration history has changed or contains a gap")
			}
			delete(applied, name)
		} else {
			gap = true
		}
	}
	if len(applied) != 0 {
		return errors.New("database contains unknown migrations")
	}
	for _, name := range names {
		if last != "" && name > last {
			break
		}
		var exists bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT FROM public.hukid_schema_migrations WHERE name=$1)", name).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		data, _ := migrationFiles.ReadFile("migrations/" + name)
		if err := applyMigration(ctx, conn, name, data, migrationChecksum(data)); err != nil {
			return fmt.Errorf("migration %s failed: %w", name, err)
		}
	}
	return nil
}

func migrationChecksum(data []byte) string {
	digest := sha256.Sum256(bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")))
	return hex.EncodeToString(digest[:])
}

func applyMigration(ctx context.Context, conn *pgx.Conn, name string, sql []byte, checksum string) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, string(sql)); err != nil {
		return err
	}
	// Migration SQL uses SET LOCAL ROLE; restore before updating the admin ledger.
	if _, err := tx.Exec(ctx, "RESET ROLE"); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO public.hukid_schema_migrations(name,checksum) VALUES ($1,$2)", name, checksum); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

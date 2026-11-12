package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"hukid.local/platform/internal/oid4vp"
)

const replayQueryTimeout = 5 * time.Second

// ReplayStore implements verification.ReplayStore on PostgreSQL (ADR-0032).
// The pool must belong to hukid_verification_runtime, which can only execute
// verification.consume_presentation. Only a hash of the key is sent and stored.
type ReplayStore struct {
	pool     *pgxpool.Pool
	scope    string
	ttl      time.Duration
	capacity int32
}

// NewReplayStore binds a store to one verifier scope. ttl must cover the
// longest request lifetime (oid4vp.MaxTTL).
func NewReplayStore(pool *pgxpool.Pool, scope string, ttl time.Duration, capacity int32) (*ReplayStore, error) {
	if pool == nil || scope == "" || len(scope) > 256 || ttl < oid4vp.MaxTTL || ttl > 24*time.Hour || capacity <= 0 || capacity > 1_000_000 {
		return nil, oid4vp.ErrConfig
	}
	return &ReplayStore{pool: pool, scope: scope, ttl: ttl, capacity: capacity}, nil
}

// Consume reports whether key is used for the first time within the TTL. A
// full scope returns oid4vp.ErrStoreFull; any other failure is wrapped without
// the database message.
func (s *ReplayStore) Consume(key string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), replayQueryTimeout)
	defer cancel()
	sum := sha256.Sum256([]byte(key))
	var first bool
	err := s.pool.QueryRow(ctx, `SELECT verification.consume_presentation($1,$2,$3,$4)`,
		s.scope, sum[:], int32(s.ttl/time.Second), s.capacity).Scan(&first)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "53400" {
			return false, oid4vp.ErrStoreFull
		}
		return false, errors.New("replay store unavailable")
	}
	return first, nil
}

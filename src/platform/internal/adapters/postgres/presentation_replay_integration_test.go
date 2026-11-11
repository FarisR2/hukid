//go:build integration

package postgres

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"hukid.local/platform/internal/oid4vp"
	"hukid.local/platform/internal/verification"
)

var _ verification.ReplayStore = (*ReplayStore)(nil)

func replayStore(t *testing.T, db *testDatabase, scope string, capacity int32) *ReplayStore {
	t.Helper()
	pool := db.pool(t, "hukid_verification_runtime")
	store, err := NewReplayStore(pool, scope, oid4vp.MaxTTL, capacity)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestPresentationReplayIsAtomicPersistentAndScoped(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	a := replayStore(t, db, "tenant-a", 100)
	if first, err := a.Consume("request-1"); err != nil || !first {
		t.Fatalf("first use: %v %v", first, err)
	}
	if first, err := a.Consume("request-1"); err != nil || first {
		t.Fatalf("replay: %v %v", first, err)
	}
	// A second store over a fresh pool stands for a restart or another replica.
	again := replayStore(t, db, "tenant-a", 100)
	if first, err := again.Consume("request-1"); err != nil || first {
		t.Fatalf("replay seen by another replica: %v %v", first, err)
	}
	other := replayStore(t, db, "tenant-b", 100)
	if first, err := other.Consume("request-1"); err != nil || !first {
		t.Fatalf("same key in another scope must be independent: %v %v", first, err)
	}

	// Pools are created up front: db.pool uses t.Fatal and mutates db.roles.
	replicas := make([]*ReplayStore, 24)
	for i := range replicas {
		replicas[i] = replayStore(t, db, "tenant-a", 100)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for _, replica := range replicas {
		wg.Add(1)
		go func(replica *ReplayStore) {
			defer wg.Done()
			first, err := replica.Consume("concurrent")
			if err != nil {
				t.Error(err)
			}
			if first {
				wins.Add(1)
			}
		}(replica)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("concurrent first uses = %d, want exactly 1", wins.Load())
	}
}

func TestPresentationReplayStoresOnlyAHashAndRuntimeCannotReadTheTable(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	store := replayStore(t, db, "tenant-a", 10)
	if _, err := store.Consume("secret-nonce-and-state"); err != nil {
		t.Fatal(err)
	}
	var rows, hashBytes int
	var dump string
	if err := db.admin.QueryRow(testContext, `SELECT count(*),min(octet_length(key_hash)),string_agg(scope||encode(key_hash,'hex'),',') FROM verification.presentation_replay`).Scan(&rows, &hashBytes, &dump); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || hashBytes != 32 || strings.Contains(dump, "secret-nonce-and-state") {
		t.Fatalf("rows=%d hashBytes=%d", rows, hashBytes)
	}
	pool := db.pool(t, "hukid_verification_runtime")
	for _, statement := range []string{
		`SELECT * FROM verification.presentation_replay`,
		`INSERT INTO verification.presentation_replay VALUES('x',decode(repeat('00',32),'hex'),now())`,
		`DELETE FROM verification.presentation_replay`,
		`SELECT * FROM tenancy.tenants`,
	} {
		if _, err := pool.Exec(testContext, statement); err == nil {
			t.Fatalf("runtime role could run %q", statement)
		}
	}
	// The function rejects malformed input instead of storing it.
	for _, args := range [][]any{
		{"", make([]byte, 32), 300, 10},
		{"s", make([]byte, 31), 300, 10},
		{"s", make([]byte, 32), 0, 10},
		{"s", make([]byte, 32), 300, 0},
	} {
		if _, err := pool.Exec(testContext, `SELECT verification.consume_presentation($1,$2,$3,$4)`, args...); err == nil {
			t.Fatalf("invalid arguments accepted: %v", args[0])
		}
	}
}

func TestPresentationReplayFailsClosedWhenTheScopeIsFullAndRecoversOnExpiry(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	store := replayStore(t, db, "tenant-a", 2)
	for _, key := range []string{"a", "b"} {
		if first, err := store.Consume(key); err != nil || !first {
			t.Fatalf("%s: %v %v", key, first, err)
		}
	}
	if _, err := store.Consume("c"); !errors.Is(err, oid4vp.ErrStoreFull) {
		t.Fatalf("err = %v", err)
	}
	// A live record is never evicted to make room.
	if first, err := store.Consume("a"); err != nil || first {
		t.Fatalf("a after full: %v %v", first, err)
	}
	// Another scope has its own capacity.
	if first, err := replayStore(t, db, "tenant-b", 2).Consume("c"); err != nil || !first {
		t.Fatalf("other scope: %v %v", first, err)
	}
	mustExec(t, db.admin, `UPDATE verification.presentation_replay SET expires_at=now()-interval '1 second' WHERE scope='tenant-a' AND key_hash=sha256('a')`)
	if first, err := store.Consume("c"); err != nil || !first {
		t.Fatalf("after one record expired: %v %v", first, err)
	}
	mustExec(t, db.admin, `UPDATE verification.presentation_replay SET expires_at=now()-interval '1 second' WHERE scope='tenant-a'`)
	if first, err := store.Consume("a"); err != nil || !first {
		t.Fatalf("an expired key can be used again once its record is gone: %v %v", first, err)
	}
	var remaining int
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM verification.presentation_replay WHERE scope='tenant-a'`).Scan(&remaining); err != nil || remaining > 2 {
		t.Fatalf("remaining = %d (%v)", remaining, err)
	}
}

func TestPresentationReplayEndToEndThroughTheCore(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	store := replayStore(t, db, "tenant-a", 10)
	var core verification.ReplayStore = store
	if first, err := core.Consume(verification.Digest([]byte("nonce\x00state"))); err != nil || !first {
		t.Fatalf("%v %v", first, err)
	}
	if first, err := core.Consume(verification.Digest([]byte("nonce\x00state"))); err != nil || first {
		t.Fatalf("%v %v", first, err)
	}
}

func TestReplayStoreRejectsUnsafeConfiguration(t *testing.T) {
	if _, err := NewReplayStore(nil, "tenant-a", oid4vp.MaxTTL, 1); !errors.Is(err, oid4vp.ErrConfig) {
		t.Fatalf("nil pool: %v", err)
	}
}

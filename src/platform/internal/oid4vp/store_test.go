package oid4vp

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hukid.local/platform/internal/verification"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

var _ verification.ReplayStore = (*ScopedReplayStore)(nil)

func TestReplayStoreAllowsExactlyOneFirstUse(t *testing.T) {
	store, err := NewScopedReplayStore("tenant-a", MaxTTL, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	var firsts atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			first, err := store.Consume("nonce\x00state")
			if err != nil {
				t.Error(err)
			}
			if first {
				firsts.Add(1)
			}
		}()
	}
	wg.Wait()
	if firsts.Load() != 1 {
		t.Fatalf("first uses = %d, want exactly 1", firsts.Load())
	}
}

func TestReplayStoreScopesVerifiersApart(t *testing.T) {
	a, _ := NewScopedReplayStore("tenant-a", MaxTTL, 10, nil)
	b, _ := NewScopedReplayStore("tenant-b", MaxTTL, 10, nil)
	if first, _ := a.Consume("k"); !first {
		t.Fatal("tenant-a first use rejected")
	}
	if first, _ := b.Consume("k"); !first {
		t.Fatal("same key in another verifier must be independent")
	}
	if scopedKey("a", "bc") == scopedKey("ab", "c") {
		t.Fatal("scope and value are not separated")
	}
}

func TestReplayRecordsExpireAfterTheTTLAndNotBefore(t *testing.T) {
	clock := &fakeClock{now: testNow}
	store, _ := NewScopedReplayStore("t", MaxTTL, 10, clock.Now)
	store.Consume("k")
	clock.Advance(MaxTTL - time.Second)
	if first, _ := store.Consume("k"); first {
		t.Fatal("record forgotten before the TTL")
	}
	clock.Advance(time.Second)
	if first, _ := store.Consume("k"); !first {
		t.Fatal("record kept past the TTL")
	}
}

func TestReplayStoreFailsClosedWhenFullOfLiveRecords(t *testing.T) {
	clock := &fakeClock{now: testNow}
	store, _ := NewScopedReplayStore("t", MaxTTL, 2, clock.Now)
	store.Consume("a")
	store.Consume("b")
	if _, err := store.Consume("c"); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("err = %v", err)
	}
	// A live record is never evicted to make room: "a" is still a replay.
	if first, err := store.Consume("a"); err != nil || first {
		t.Fatalf("a: first=%v err=%v", first, err)
	}
	clock.Advance(MaxTTL)
	if first, err := store.Consume("c"); err != nil || !first {
		t.Fatalf("after expiry: first=%v err=%v", first, err)
	}
	if store.Len() > 2 {
		t.Fatalf("len = %d exceeds the capacity", store.Len())
	}
}

func TestReplayStoreRejectsUnsafeConfiguration(t *testing.T) {
	cases := map[string]func() error{
		"no scope":      func() error { _, err := NewScopedReplayStore("", MaxTTL, 1, nil); return err },
		"ttl below max": func() error { _, err := NewScopedReplayStore("t", MaxTTL-time.Second, 1, nil); return err },
		"no capacity":   func() error { _, err := NewScopedReplayStore("t", MaxTTL, 0, nil); return err },
		"session store": func() error { _, err := NewSessionStore(0, nil); return err },
	}
	for name, build := range cases {
		if err := build(); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestStoreFullIsAnInfrastructureErrorNotAVerdict(t *testing.T) {
	l := newLab(t)
	s := testSession(t)
	store, _ := NewScopedReplayStore("t", MaxTTL, 1, nil)
	store.Consume("other")
	_, err := s.HandleResponse(l.verifier(t, store), testNow, answer(t, s, l.presentation(t, testClientID, s.nonce)))
	if !errors.Is(err, verification.ErrReplayStore) {
		t.Fatalf("err = %v", err)
	}
}

func TestSessionStoreLifecycle(t *testing.T) {
	clock := &fakeClock{now: testNow}
	store, _ := NewSessionStore(2, clock.Now)
	a, b := testSession(t), testSession(t)
	if err := store.Put(a); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(b); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Get(a.State()); err != nil || got != a {
		t.Fatalf("get: %v %v", got, err)
	}
	if err := store.Put(testSession(t)); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("put when full: %v", err)
	}
	if _, err := store.Get("unknown-state"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	store.Remove(a.State())
	if _, err := store.Get(a.State()); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("removed: %v", err)
	}
	clock.Advance(DefaultTTL)
	if _, err := store.Get(b.State()); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expired: %v", err)
	}
	if err := store.Put(testSession(t)); err != nil {
		t.Fatalf("put after expiry sweep: %v", err)
	}
	if err := store.Put(nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("nil: %v", err)
	}
}

func TestSessionStoreIndexesByHashedState(t *testing.T) {
	store, _ := NewSessionStore(2, nil)
	s := testSession(t)
	_ = store.Put(s)
	for key := range store.sessions {
		if key == s.State() || key == s.nonce {
			t.Fatal("the raw state or nonce is the index key")
		}
	}
}

func TestEndToEndThroughTheStores(t *testing.T) {
	l := newLab(t)
	sessions, _ := NewSessionStore(10, nil)
	replay, _ := NewScopedReplayStore("tenant-a", MaxTTL, 10, nil)
	started := testSession(t)
	if err := sessions.Put(started); err != nil {
		t.Fatal(err)
	}
	// The endpoint (a later increment) will look the session up by state.
	session, err := sessions.Get(started.State())
	if err != nil {
		t.Fatal(err)
	}
	report, err := session.HandleResponse(l.verifier(t, replay), testNow, answer(t, session, l.presentation(t, testClientID, session.nonce)))
	if err != nil || report.TechnicalResult != verification.Valid {
		t.Fatalf("%v %+v", err, report)
	}
	sessions.Remove(session.State())
	if _, err := sessions.Get(started.State()); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("session still open after a verified response: %v", err)
	}
}

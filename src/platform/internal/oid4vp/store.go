package oid4vp

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// ErrStoreFull reports that a bounded store has no room for a new entry after
// dropping the expired ones. Both stores fail closed: they never evict a live
// entry, because evicting a replay record would let a presentation be replayed
// and evicting a session would break a legitimate wallet.
var ErrStoreFull = errors.New("oid4vp store is full")

// DefaultStoreCapacity bounds each in-memory store. It is a proposed value.
const DefaultStoreCapacity = 10_000

func scopedKey(scope, value string) string {
	sum := sha256.Sum256([]byte(scope + "\x00" + value))
	return hex.EncodeToString(sum[:])
}

// ScopedReplayStore implements verification.ReplayStore in memory, with a
// per-verifier scope and a TTL. It is correct for one process only: a restart
// forgets consumed requests (still bounded by session expiry, because
// HandleResponse rejects expired sessions) and several replicas do not share
// state. A persistent store shared across replicas is a separate decision
// (ADR-0031 does not decide it) and would implement the same port.
type ScopedReplayStore struct {
	mu       sync.Mutex
	scope    string
	ttl      time.Duration
	capacity int
	now      func() time.Time
	seen     map[string]time.Time
}

// NewScopedReplayStore creates a store for one verifier. ttl must cover the
// longest request lifetime (MaxTTL), otherwise a record could expire while its
// request could still be answered. now may be nil to use time.Now.
func NewScopedReplayStore(scope string, ttl time.Duration, capacity int, now func() time.Time) (*ScopedReplayStore, error) {
	if scope == "" || ttl < MaxTTL || capacity <= 0 {
		return nil, ErrConfig
	}
	if now == nil {
		now = time.Now
	}
	return &ScopedReplayStore{scope: scope, ttl: ttl, capacity: capacity, now: now, seen: map[string]time.Time{}}, nil
}

// Consume records key and reports whether this is its first use within the
// TTL. It is atomic. When the store is full of live records it returns
// ErrStoreFull, which the core reports as an infrastructure failure.
func (s *ScopedReplayStore) Consume(key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	hashed := scopedKey(s.scope, key)
	if expiry, used := s.seen[hashed]; used && now.Before(expiry) {
		return false, nil
	}
	if _, used := s.seen[hashed]; !used && len(s.seen) >= s.capacity {
		s.sweepLocked(now)
		if len(s.seen) >= s.capacity {
			return false, ErrStoreFull
		}
	}
	s.seen[hashed] = now.Add(s.ttl)
	return true, nil
}

func (s *ScopedReplayStore) sweepLocked(now time.Time) {
	for key, expiry := range s.seen {
		if !now.Before(expiry) {
			delete(s.seen, key)
		}
	}
}

// Len is the number of retained records, expired ones included until swept.
func (s *ScopedReplayStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

// SessionStore keeps open presentation requests of one verifier, looked up by
// the state the wallet echoes. Sessions hold the private response-decryption
// key, so this store lives in memory only and is lost on restart; wallets with
// an open request then get ErrSessionNotFound and must start again.
type SessionStore struct {
	mu       sync.Mutex
	capacity int
	now      func() time.Time
	sessions map[string]*Session
}

// ErrSessionNotFound reports an unknown, expired or already removed session.
var ErrSessionNotFound = errors.New("presentation request not found")

// NewSessionStore creates a bounded store. now may be nil to use time.Now.
func NewSessionStore(capacity int, now func() time.Time) (*SessionStore, error) {
	if capacity <= 0 {
		return nil, ErrConfig
	}
	if now == nil {
		now = time.Now
	}
	return &SessionStore{capacity: capacity, now: now, sessions: map[string]*Session{}}, nil
}

// Put registers a session under its state. It fails closed when full.
func (s *SessionStore) Put(session *Session) error {
	if session == nil {
		return ErrConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if len(s.sessions) >= s.capacity {
		for key, held := range s.sessions {
			if !now.Before(held.expiresAt) {
				delete(s.sessions, key)
			}
		}
		if len(s.sessions) >= s.capacity {
			return ErrStoreFull
		}
	}
	s.sessions[scopedKey("state", session.state)] = session
	return nil
}

// Get returns the open session for state. The lookup key is a hash of the
// state, so the stored index reveals nothing usable.
func (s *SessionStore) Get(state string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scopedKey("state", state)
	held, ok := s.sessions[key]
	if !ok {
		return nil, ErrSessionNotFound
	}
	if !s.now().Before(held.expiresAt) {
		delete(s.sessions, key)
		return nil, ErrSessionNotFound
	}
	return held, nil
}

// Remove discards a session, typically once its response was verified.
func (s *SessionStore) Remove(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, scopedKey("state", state))
}

// Len is the number of retained sessions, expired ones included until swept.
func (s *SessionStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

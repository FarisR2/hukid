package verification

import (
	"errors"
	"sync"
)

// ErrReplayStore wraps a failure of the replay store itself. It says nothing
// about the presentation.
var ErrReplayStore = errors.New("replay store failed")

// ReplayStore records which presentation requests already received a
// response. Consume must be atomic: of two concurrent calls with the same key,
// exactly one reports firstUse. It is a port; the laboratory implementation is
// in memory and unbounded, and a persistent one (with TTL and per-verifier
// scope) belongs to the OpenID4VP adapter (VER-T10).
type ReplayStore interface {
	Consume(key string) (firstUse bool, err error)
}

// MemoryReplayStore is the laboratory ReplayStore.
type MemoryReplayStore struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func NewMemoryReplayStore() *MemoryReplayStore {
	return &MemoryReplayStore{seen: map[string]struct{}{}}
}

func (m *MemoryReplayStore) Consume(key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, used := m.seen[key]; used {
		return false, nil
	}
	m.seen[key] = struct{}{}
	return true, nil
}

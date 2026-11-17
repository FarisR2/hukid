// Package issuance provides pure, process-local laboratory issuance primitives.
// It does not issue tokens or credentials and has no transport integration.
package issuance

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"
)

var (
	ErrConfig      = errors.New("invalid offer configuration")
	ErrStoreFull   = errors.New("offer store is full")
	ErrEntropy     = errors.New("offer entropy unavailable")
	ErrCollision   = errors.New("offer random value collision")
	ErrInvalidCode = errors.New("invalid pre-authorized code")
)

// OfferConfig requires explicit 0 < TTL <= 300s and Capacity > 0.
// Nil Now and Random use time.Now and crypto/rand.Reader. Injected functions
// run serially under the store lock and must not reenter the store.
// Random must supply independent unpredictable bytes outside deterministic tests.
type OfferConfig struct {
	TTL      time.Duration
	Capacity int
	Now      func() time.Time
	Random   io.Reader
}

// Offer is a value copy. Code is a bearer secret returned only at creation;
// callers must not log it. ID is independent, nonsecret correlation metadata.
type Offer struct {
	Code      string
	ID        string
	ExpiresAt time.Time
}

// Redemption is only an atomic code-consumption receipt. It is not an access
// token, proof, human consent, or a credential, and cannot authorize issuance.
type Redemption struct {
	ID        string
	ExpiresAt time.Time
}

type record struct {
	id        string
	expiresAt time.Time
	redeemed  bool
}

// OfferStore retains only domain-separated code hashes and record metadata.
// Every record, including a consumed one, counts toward capacity until expiry.
// State is lost on restart and is not shared between processes or replicas.
type OfferStore struct {
	mu      sync.Mutex
	cfg     OfferConfig
	records map[[32]byte]record
}

func NewOfferStore(cfg OfferConfig) (*OfferStore, error) {
	if cfg.TTL <= 0 || cfg.TTL > 300*time.Second || cfg.Capacity <= 0 {
		return nil, ErrConfig
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}
	return &OfferStore{cfg: cfg, records: make(map[[32]byte]record)}, nil
}

func codeHash(code string) [32]byte {
	return sha256.Sum256([]byte("hukid:wallet-lab:pre-authorized-code:v1\x00" + code))
}

// Create never evicts a live record or retries an entropy collision. Failed
// creation inserts nothing; sweeping may still reclaim already expired entries.
func (s *OfferStore) Create() (Offer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	for key, held := range s.records {
		if !now.Before(held.expiresAt) {
			delete(s.records, key)
		}
	}
	if len(s.records) >= s.cfg.Capacity {
		return Offer{}, ErrStoreFull
	}
	var entropy [64]byte
	if _, err := io.ReadFull(s.cfg.Random, entropy[:]); err != nil {
		return Offer{}, ErrEntropy
	}
	code := base64.RawURLEncoding.EncodeToString(entropy[:32])
	id := base64.RawURLEncoding.EncodeToString(entropy[32:])
	key := codeHash(code)
	if _, exists := s.records[key]; exists {
		return Offer{}, ErrCollision
	}
	for _, held := range s.records {
		if held.id == id {
			return Offer{}, ErrCollision
		}
	}
	expiry := now.Add(s.cfg.TTL)
	s.records[key] = record{id: id, expiresAt: expiry}
	return Offer{Code: code, ID: id, ExpiresAt: expiry}, nil
}

// Redeem atomically consumes a live code exactly once. Unknown, malformed,
// expired and already redeemed codes all return the same fixed error.
func (s *OfferStore) Redeem(code string) (Redemption, error) {
	if len(code) != 43 {
		return Redemption{}, ErrInvalidCode
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := codeHash(code)
	held, exists := s.records[key]
	if !exists || held.redeemed || !s.cfg.Now().Before(held.expiresAt) {
		return Redemption{}, ErrInvalidCode
	}
	held.redeemed = true
	s.records[key] = held
	return Redemption{ID: held.id, ExpiresAt: held.expiresAt}, nil
}

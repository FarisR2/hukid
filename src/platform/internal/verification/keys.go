package verification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"sync"
)

// ErrKeyNotFound is returned by a resolver when the issuer does not publish
// the requested kid. Any other error means the resolver itself failed and is
// not a statement about the credential.
var ErrKeyNotFound = errors.New("issuer key not found")

// ErrKeyResolution wraps a resolver failure that is not ErrKeyNotFound.
var ErrKeyResolution = errors.New("issuer key resolution failed")

// ResolvedKey is a published issuer key together with the identifier of the
// issuer whose key set contained it.
type ResolvedKey struct {
	Key    *ecdsa.PublicKey
	Issuer string
}

// IssuerKeyResolver returns the public key published for a kid. It is a port:
// the core performs no network access. The real adapter (VER-T12) must apply
// the profile section 3 rules (single host, no cross-origin redirects).
// A retired key that is still published must still be returned, so credentials
// signed before a rotation keep verifying.
type IssuerKeyResolver interface {
	ResolveKey(issuer, kid string) (ResolvedKey, error)
}

// MemoryKeyResolver is the laboratory implementation. It indexes keys by kid
// only and remembers the owning issuer, which lets tests exercise the
// issuer-mismatch path that a per-issuer HTTPS adapter cannot produce.
type MemoryKeyResolver struct {
	mu   sync.RWMutex
	keys map[string]ResolvedKey
}

func NewMemoryKeyResolver() *MemoryKeyResolver {
	return &MemoryKeyResolver{keys: map[string]ResolvedKey{}}
}

// Add publishes key under kid for issuer. Only P-256 keys are accepted.
func (m *MemoryKeyResolver) Add(issuer, kid string, key *ecdsa.PublicKey) error {
	if key == nil || key.Curve != elliptic.P256() || !key.Curve.IsOnCurve(key.X, key.Y) || kid == "" || issuer == "" {
		return errors.New("invalid key, kid or issuer")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[kid] = ResolvedKey{Key: key, Issuer: issuer}
	return nil
}

func (m *MemoryKeyResolver) ResolveKey(_, kid string) (ResolvedKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	resolved, ok := m.keys[kid]
	if !ok {
		return ResolvedKey{}, ErrKeyNotFound
	}
	return resolved, nil
}

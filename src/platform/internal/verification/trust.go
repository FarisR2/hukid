package verification

import (
	"errors"
	"fmt"
	"sync"
)

// ErrTrustPolicy wraps a failure of the trust policy itself, or a decision
// outside the closed set. It says nothing about the credential.
var ErrTrustPolicy = errors.New("trust policy failed")

// TrustPolicy decides whether a verifier trusts an issuer. It is a port kept
// apart from cryptographic validation (HK-043, profile): it receives only the
// issuer identifier, never the credential, and its answer is recorded next to
// the technical result without changing it in either direction.
type TrustPolicy interface {
	Evaluate(issuer string) (Decision, error)
}

// evaluateTrust calls the policy and rejects any answer outside the closed
// decision set, so a buggy policy cannot invent a state.
func evaluateTrust(policy TrustPolicy, issuer string) (Decision, error) {
	decision, err := policy.Evaluate(issuer)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTrustPolicy, err)
	}
	switch decision {
	case Trusted, Untrusted:
		return decision, nil
	}
	return "", fmt.Errorf("%w: unsupported decision %q", ErrTrustPolicy, decision)
}

// AllowlistTrustPolicy is the laboratory policy: it trusts exactly the issuers
// it was given. A production policy (HK-043, ADR-010 of the roadmap) is a
// separate decision of the owner.
type AllowlistTrustPolicy struct {
	mu      sync.RWMutex
	issuers map[string]struct{}
}

func NewAllowlistTrustPolicy(issuers ...string) *AllowlistTrustPolicy {
	policy := &AllowlistTrustPolicy{issuers: map[string]struct{}{}}
	for _, issuer := range issuers {
		policy.issuers[issuer] = struct{}{}
	}
	return policy
}

func (p *AllowlistTrustPolicy) Evaluate(issuer string) (Decision, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if _, ok := p.issuers[issuer]; ok {
		return Trusted, nil
	}
	return Untrusted, nil
}

// aggregateTrust summarises the trust of a presentation's credentials: any
// untrusted credential makes the presentation untrusted; otherwise any credential
// whose trust was not evaluated makes it not evaluated; otherwise it is trusted.
// A presentation with no verified credentials is not evaluated.
func aggregateTrust(credentials []Report) Decision {
	if len(credentials) == 0 {
		return NotEvaluated
	}
	result := Trusted
	for _, credential := range credentials {
		switch {
		case credential.Trust == nil || credential.Trust.Decision == NotEvaluated:
			if result == Trusted {
				result = NotEvaluated
			}
		case credential.Trust.Decision == Untrusted:
			return Untrusted
		}
	}
	return result
}

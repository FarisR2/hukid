package verification

import (
	"errors"
	"time"
)

// Clock is the injected time source. The core never reads the system clock.
type Clock interface{ Now() time.Time }

// ClockFunc adapts a function to Clock.
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

// Proposed clock-skew bounds (FEAT-004 supuestos propuestos). The profile only
// asks for "clock skew limitado"; the values are for the owner to approve.
const (
	DefaultClockSkew = time.Minute
	MaxClockSkew     = 5 * time.Minute
)

// ErrConfig reports an invalid Verifier configuration.
var ErrConfig = errors.New("invalid verifier configuration")

// Verifier verifies single credentials. It performs no network or database
// access: keys come from the injected resolver and time from the injected clock.
type Verifier struct {
	keys      IssuerKeyResolver
	clock     Clock
	limits    Limits
	clockSkew time.Duration
	replay    ReplayStore
	trust     TrustPolicy
}

// WithCredentialContexts returns a copy that accepts the given JSON-LD contexts
// in credentials, in place of the minimal default. Contexts are never fetched.
func (v *Verifier) WithCredentialContexts(contexts ...string) *Verifier {
	copied := *v
	copied.limits.Contexts = append([]string{vcdmBaseContext}, contexts...)
	return &copied
}

// WithTrustPolicy returns a copy of the verifier that records a trust decision
// next to the technical result. Without a policy the reports carry no trust.
func (v *Verifier) WithTrustPolicy(policy TrustPolicy) *Verifier {
	copied := *v
	copied.trust = policy
	return &copied
}

// WithReplayStore returns a copy of the verifier that can verify presentations.
// Credential verification does not need a store.
func (v *Verifier) WithReplayStore(store ReplayStore) *Verifier {
	copied := *v
	copied.replay = store
	return &copied
}

// NewVerifier validates its configuration. clockSkew must be within
// [0, MaxClockSkew].
func NewVerifier(keys IssuerKeyResolver, clock Clock, limits Limits, clockSkew time.Duration) (*Verifier, error) {
	if keys == nil || clock == nil || limits.MaxJWSBytes <= 0 || limits.MaxJSONDepth <= 0 || limits.MaxCredentials <= 0 || limits.MaxPresentationBytes <= 0 || clockSkew < 0 || clockSkew > MaxClockSkew {
		return nil, ErrConfig
	}
	return &Verifier{keys: keys, clock: clock, limits: limits, clockSkew: clockSkew}, nil
}

// checkValidity compares now with the credential's validity window. The window
// is [validFrom, validUntil): at validUntil the credential is no longer valid,
// following VCDM's definition of validUntil. The skew widens the accepted
// window on both sides. A credential declaring no bounds has no time limit.
func checkValidity(parsed *ParsedCredential, now time.Time, skew time.Duration) Check {
	now = now.UTC()
	if parsed.ValidFromAt != nil && now.Add(skew).Before(*parsed.ValidFromAt) {
		return Failed(CheckValidity, CodeValidityNotYetValid)
	}
	if parsed.ValidUntilAt != nil && !now.Add(-skew).Before(*parsed.ValidUntilAt) {
		return Failed(CheckValidity, CodeValidityExpired)
	}
	return Passed(CheckValidity, true)
}

// Verify checks one compact vc+jwt and returns the structured report. The
// error is non-nil only when key resolution itself failed; it carries no
// statement about the credential. The report holds a digest and codes, never
// the credential. Status and schema are reported as required skips when the
// credential declares them, because their checks do not exist yet.
func (v *Verifier) Verify(jws string) (Report, error) {
	parsed, checks, err := integrityChecks(jws, v.limits, v.keys)
	if err != nil {
		return Report{}, err
	}
	if parsed == nil || checks[len(checks)-1].Result != Pass || checks[len(checks)-2].Result != Pass {
		// Format, key or signature did not pass: the validity window of an
		// unauthenticated credential is not evaluated.
		checks = append(checks,
			SkippedCheck(CheckValidity, CodeSkippedPrecondition, true),
			optionalSkip(CheckStatus, false),
			optionalSkip(CheckSchema, false),
		)
		report := NewReport([]byte(jws), checks)
		if v.trust != nil {
			// The issuer of an unauthenticated credential is only a claim.
			report = report.WithTrust(NotEvaluated)
		}
		return report, nil
	}
	checks = append(checks,
		checkValidity(parsed, v.clock.Now(), v.clockSkew),
		optionalSkip(CheckStatus, parsed.DeclaresStatus),
		optionalSkip(CheckSchema, parsed.DeclaresSchema),
	)
	report := NewReport([]byte(jws), checks)
	if v.trust != nil {
		// The issuer is authenticated here (key and signature passed), whatever
		// the validity outcome. The decision never changes the technical result.
		decision, err := evaluateTrust(v.trust, parsed.Issuer)
		if err != nil {
			return Report{}, err
		}
		report = report.WithTrust(decision)
	}
	return report, nil
}

// optionalSkip reports a check that is not run yet. It is required (and so
// makes the report invalid) only when the credential declares the member.
func optionalSkip(name CheckName, declared bool) Check {
	if declared {
		return SkippedCheck(name, CodeSkippedNotImplemented, true)
	}
	return SkippedCheck(name, CodeSkippedNotDeclared, false)
}

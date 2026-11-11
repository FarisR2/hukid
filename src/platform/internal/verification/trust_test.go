package verification

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type spyPolicy struct {
	decision Decision
	err      error
	calls    []string
}

func (s *spyPolicy) Evaluate(issuer string) (Decision, error) {
	s.calls = append(s.calls, issuer)
	return s.decision, s.err
}

// authenticated reports whether a vector reaches the trust decision: format,
// issuer key and signature must all pass.
func authenticated(v vector) bool {
	switch v.Expected.FailedCheck {
	case CheckFormat, CheckIssuerKey, CheckSignature:
		return false
	}
	return true
}

func TestTrustNeverChangesTheTechnicalOutcomeOfACredential(t *testing.T) {
	file := loadVectors(t)
	for _, vec := range file.Vectors {
		t.Run(vec.ID, func(t *testing.T) {
			base := newTestVerifier(t, file, at(t, vec.EvaluationTime), 0)
			baseline, err := base.Verify(vec.JWS)
			if err != nil {
				t.Fatal(err)
			}
			if baseline.Trust != nil {
				t.Fatal("without a policy the report must carry no trust")
			}
			for name, tc := range map[string]struct {
				policy TrustPolicy
				want   Decision
			}{
				"trusts the issuer": {NewAllowlistTrustPolicy(file.Issuer), Trusted},
				"trusts nobody":     {NewAllowlistTrustPolicy(), Untrusted},
			} {
				report, err := base.WithTrustPolicy(tc.policy).Verify(vec.JWS)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if report.TechnicalResult != baseline.TechnicalResult || report.Digest != baseline.Digest || !reflect.DeepEqual(report.Checks, baseline.Checks) {
					t.Fatalf("%s: the policy changed the technical outcome: %+v vs %+v", name, report, baseline)
				}
				want := tc.want
				if !authenticated(vec) {
					want = NotEvaluated
				}
				if report.Trust == nil || report.Trust.Decision != want {
					t.Fatalf("%s: trust = %+v, want %q", name, report.Trust, want)
				}
			}
		})
	}
}

func TestTrustDoesNotRescueAnInvalidCredentialNorSinkAValidOne(t *testing.T) {
	file := loadVectors(t)
	byID := map[string]vector{}
	for _, v := range file.Vectors {
		byID[v.ID] = v
	}
	valid, tampered := byID["v01-valid"], byID["v06-signature-tampered"]

	rescued, err := newTestVerifier(t, file, at(t, tampered.EvaluationTime), 0).WithTrustPolicy(NewAllowlistTrustPolicy(file.Issuer)).Verify(tampered.JWS)
	if err != nil || rescued.TechnicalResult != Invalid || rescued.Trust.Decision != NotEvaluated {
		t.Fatalf("a trusted issuer must not make a tampered credential valid: err=%v %+v", err, rescued)
	}
	sunk, err := newTestVerifier(t, file, at(t, valid.EvaluationTime), 0).WithTrustPolicy(NewAllowlistTrustPolicy()).Verify(valid.JWS)
	if err != nil || sunk.TechnicalResult != Valid || sunk.Trust.Decision != Untrusted {
		t.Fatalf("an untrusted issuer must not make a valid credential invalid: err=%v %+v", err, sunk)
	}
}

func TestPolicyIsCalledOnlyForAuthenticatedIssuersAndReceivesOnlyTheIssuer(t *testing.T) {
	file := loadVectors(t)
	spy := &spyPolicy{decision: Trusted}
	want := 0
	for _, vec := range file.Vectors {
		v := newTestVerifier(t, file, at(t, vec.EvaluationTime), 0).WithTrustPolicy(spy)
		if _, err := v.Verify(vec.JWS); err != nil {
			t.Fatal(err)
		}
		if authenticated(vec) {
			want++
		}
	}
	if len(spy.calls) != want || want == 0 {
		t.Fatalf("policy called %d times, want %d (authenticated vectors only)", len(spy.calls), want)
	}
	for _, issuer := range spy.calls {
		if issuer != file.Issuer {
			t.Fatalf("the policy must receive only the issuer identifier, got %q", issuer)
		}
	}
}

func TestPolicyFailuresAndOutOfSetDecisionsAreErrors(t *testing.T) {
	file := loadVectors(t)
	vec := file.Vectors[0]
	for name, policy := range map[string]TrustPolicy{
		"policy error":        &spyPolicy{err: errors.New("trust list unavailable")},
		"notEvaluated answer": &spyPolicy{decision: NotEvaluated},
		"empty answer":        &spyPolicy{decision: ""},
		"invented answer":     &spyPolicy{decision: "maybe"},
	} {
		report, err := newTestVerifier(t, file, at(t, vec.EvaluationTime), 0).WithTrustPolicy(policy).Verify(vec.JWS)
		if !errors.Is(err, ErrTrustPolicy) || report.Digest != "" || len(report.Checks) != 0 {
			t.Fatalf("%s: expected ErrTrustPolicy and an empty report, got err=%v %+v", name, err, report)
		}
	}
}

func TestWithTrustPolicyDoesNotMutateTheReceiverAndOmitsTrustWhenAbsent(t *testing.T) {
	file := loadVectors(t)
	vec := file.Vectors[0]
	base := newTestVerifier(t, file, at(t, vec.EvaluationTime), 0)
	_ = base.WithTrustPolicy(NewAllowlistTrustPolicy(file.Issuer))
	report, err := base.Verify(vec.JWS)
	if err != nil || report.Trust != nil {
		t.Fatalf("the original verifier must stay policy-free: err=%v %+v", err, report.Trust)
	}
	if blob, _ := json.Marshal(report); strings.Contains(string(blob), `"trust"`) {
		t.Fatalf("trust must be omitted when no policy is configured: %s", blob)
	}
}

func TestPresentationTrustIsAggregatedAndNeverAltersTheResult(t *testing.T) {
	file := loadVectors(t)
	run := func(id string, policy TrustPolicy) PresentationReport {
		vec := presentationVectorByID(t, file, id)
		v := presentationVerifier(t, file, vec.EvaluationTime, NewMemoryReplayStore()).WithTrustPolicy(policy)
		report, err := v.VerifyPresentation(Response{VP: vec.VP, State: vec.ResponseState}, Request(vec.Request))
		if err != nil {
			t.Fatal(err)
		}
		return report
	}
	trusting, distrusting := NewAllowlistTrustPolicy(file.Issuer), NewAllowlistTrustPolicy()

	if r := run("p01-valid", trusting); r.TechnicalResult != Valid || r.Trust == nil || r.Trust.Decision != Trusted {
		t.Fatalf("expected valid and trusted, got %+v", r)
	}
	if r := run("p01-valid", distrusting); r.TechnicalResult != Valid || r.Trust.Decision != Untrusted {
		t.Fatalf("an untrusted issuer must not invalidate a valid presentation, got %+v", r)
	}
	// An authenticated credential that is expired: trust is still evaluated,
	// and the presentation stays invalid whatever the policy says.
	if r := run("p10-credential-expired", trusting); r.TechnicalResult != Invalid || r.Trust.Decision != Trusted {
		t.Fatalf("trust must not rescue an expired credential, got %+v", r)
	}
	// Failures before any credential is verified leave trust not evaluated.
	for _, id := range []string{"p08-vp-header-typ-wrong", "p06-vp-signature-tampered", "p03-audience-mismatch"} {
		if r := run(id, trusting); r.TechnicalResult != Invalid || r.Trust == nil || r.Trust.Decision != NotEvaluated || len(r.Credentials) != 0 {
			t.Fatalf("%s: expected invalid and notEvaluated with no credentials, got %+v", id, r)
		}
	}
	vec := presentationVectorByID(t, file, "p01-valid")
	withoutPolicy, err := presentationVerifier(t, file, vec.EvaluationTime, NewMemoryReplayStore()).VerifyPresentation(Response{VP: vec.VP, State: vec.ResponseState}, Request(vec.Request))
	if err != nil || withoutPolicy.Trust != nil {
		t.Fatalf("without a policy a presentation carries no trust: err=%v %+v", err, withoutPolicy.Trust)
	}
}

func TestAggregateTrust(t *testing.T) {
	report := func(d Decision) Report {
		if d == "" {
			return Report{}
		}
		return Report{Trust: &Trust{Decision: d}}
	}
	cases := []struct {
		name string
		in   []Decision
		want Decision
	}{
		{"none", nil, NotEvaluated},
		{"all trusted", []Decision{Trusted, Trusted}, Trusted},
		{"one untrusted wins", []Decision{Trusted, Untrusted, NotEvaluated}, Untrusted},
		{"not evaluated beats trusted", []Decision{Trusted, NotEvaluated}, NotEvaluated},
		{"missing trust counts as not evaluated", []Decision{Trusted, ""}, NotEvaluated},
		{"untrusted after a not evaluated", []Decision{NotEvaluated, Untrusted}, Untrusted},
	}
	for _, tc := range cases {
		var reports []Report
		for _, d := range tc.in {
			reports = append(reports, report(d))
		}
		if got := aggregateTrust(reports); got != tc.want {
			t.Fatalf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestAllowlistTrustPolicy(t *testing.T) {
	policy := NewAllowlistTrustPolicy("https://issuer.hukid.pe/a")
	for issuer, want := range map[string]Decision{
		"https://issuer.hukid.pe/a":  Trusted,
		"https://issuer.hukid.pe/b":  Untrusted,
		"https://issuer.hukid.pe/a/": Untrusted,
		"":                           Untrusted,
	} {
		if got, err := policy.Evaluate(issuer); err != nil || got != want {
			t.Fatalf("Evaluate(%q) = %q, %v; want %q", issuer, got, err, want)
		}
	}
}

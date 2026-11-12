package verification

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTechnicalResultIsDerivedFromChecks(t *testing.T) {
	cases := []struct {
		name   string
		checks []Check
		want   TechnicalResult
	}{
		{"no checks is invalid", nil, Invalid},
		{"all required pass", []Check{Passed(CheckFormat, true), Passed(CheckSignature, true)}, Valid},
		{"one failure invalidates", []Check{Passed(CheckFormat, true), Failed(CheckSignature, CodeSignatureInvalid)}, Invalid},
		{"skipped required is not a pass", []Check{Passed(CheckFormat, true), SkippedCheck(CheckHolderBinding, CodeSkippedPrecondition, true)}, Invalid},
		{"skipped optional does not invalidate", []Check{Passed(CheckFormat, true), SkippedCheck(CheckStatus, CodeSkippedNotDeclared, false)}, Valid},
		{"failure in an optional check still invalidates", []Check{Passed(CheckFormat, true), {Name: CheckStatus, Result: Fail, Code: CodeSkippedNotDeclared}}, Invalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NewReport([]byte("input"), tc.checks).TechnicalResult; got != tc.want {
				t.Fatalf("technicalResult = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTrustNeverChangesTheTechnicalResult(t *testing.T) {
	valid := NewReport([]byte("a"), []Check{Passed(CheckSignature, true)})
	invalid := NewReport([]byte("b"), []Check{Failed(CheckSignature, CodeSignatureInvalid)})
	for _, d := range []Decision{Trusted, Untrusted, NotEvaluated} {
		if got := valid.WithTrust(d).TechnicalResult; got != Valid {
			t.Fatalf("trust %q turned a valid report into %q", d, got)
		}
		if got := invalid.WithTrust(d).TechnicalResult; got != Invalid {
			t.Fatalf("trust %q turned an invalid report into %q", d, got)
		}
	}
	if valid.Trust != nil {
		t.Fatal("WithTrust must not mutate the receiver")
	}
	if blob, _ := json.Marshal(valid); strings.Contains(string(blob), `"trust"`) {
		t.Fatalf("trust must be omitted when it was not evaluated: %s", blob)
	}
}

func TestFailureCodesBelongToTheirCheck(t *testing.T) {
	if got := Failed(CheckValidity, CodeValidityExpired); got.Result != Fail || !got.Required || got.Code != CodeValidityExpired {
		t.Fatalf("unexpected failed check: %+v", got)
	}
	mustPanic(t, func() { Failed(CheckSignature, CodeValidityExpired) })
	mustPanic(t, func() { Failed(CheckStatus, CodeSignatureInvalid) })
	mustPanic(t, func() { SkippedCheck(CheckStatus, CodeSignatureInvalid, false) })
}

func TestCodeSetIsClosedUniqueAndStable(t *testing.T) {
	seen := map[Code]bool{}
	for _, c := range AllCodes() {
		if c == "" || seen[c] {
			t.Fatalf("code %q is empty or duplicated", c)
		}
		if strings.ContainsAny(string(c), " \t\n") || strings.ToLower(string(c)) != string(c) {
			t.Fatalf("code %q must be lower-case without whitespace", c)
		}
		seen[c] = true
		if !IsKnown(c) {
			t.Fatalf("code %q listed but not known", c)
		}
	}
	if IsKnown("format.unknown") || IsKnown("") {
		t.Fatal("unlisted codes must not be known")
	}
	if len(seen) != 21 {
		t.Fatalf("closed set has %d codes; changing it requires a new CodesVersion and this assertion", len(seen))
	}
}

func TestReportCarriesDigestAndNeverTheInput(t *testing.T) {
	secret := "eyJhbGciOiJFUzI1NiJ9.eyJzZWNyZXQiOiJjbGFpbS12YWx1ZSJ9.c2ln"
	report := NewReport([]byte(secret), []Check{Passed(CheckFormat, true), Failed(CheckSignature, CodeSignatureInvalid)}).WithTrust(Untrusted)
	blob, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{secret, "claim-value", "eyJ"} {
		if strings.Contains(string(blob), leak) {
			t.Fatalf("report leaks input material %q: %s", leak, blob)
		}
	}
	if report.Digest != Digest([]byte(secret)) || !strings.HasPrefix(report.Digest, "sha256:") || len(report.Digest) != len("sha256:")+64 {
		t.Fatalf("unexpected digest %q", report.Digest)
	}
	if report.CodesVersion != CodesVersion {
		t.Fatalf("codesVersion = %d", report.CodesVersion)
	}
}

func TestNewReportCopiesItsChecks(t *testing.T) {
	checks := []Check{Passed(CheckFormat, true)}
	report := NewReport(nil, checks)
	checks[0].Result = Fail
	if report.Checks[0].Result != Pass {
		t.Fatal("report must not alias the caller's slice")
	}
}

func mustPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic for a code outside the check's set")
		}
	}()
	fn()
}

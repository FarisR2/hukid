package verification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func at(t *testing.T, s string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func fixedClock(now time.Time) Clock { return ClockFunc(func() time.Time { return now }) }

func newTestVerifier(t *testing.T, file vectorFile, now time.Time, skew time.Duration) *Verifier {
	t.Helper()
	v, err := NewVerifier(vectorResolver(t, file), fixedClock(now), DefaultLimits, skew)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func failedCheck(report Report) (Check, bool) {
	for _, c := range report.Checks {
		if c.Result == Fail {
			return c, true
		}
	}
	return Check{}, false
}

func TestVerifierMatchesEveryVector(t *testing.T) {
	file := loadVectors(t)
	for _, vec := range file.Vectors {
		t.Run(vec.ID, func(t *testing.T) {
			report, err := newTestVerifier(t, file, at(t, vec.EvaluationTime), 0).Verify(vec.JWS)
			if err != nil {
				t.Fatal(err)
			}
			if report.TechnicalResult != vec.Expected.TechnicalResult {
				t.Fatalf("technicalResult = %q, want %q: %+v", report.TechnicalResult, vec.Expected.TechnicalResult, report.Checks)
			}
			failed, any := failedCheck(report)
			if vec.Expected.TechnicalResult == Valid {
				if any {
					t.Fatalf("unexpected failure %+v", failed)
				}
				return
			}
			if !any || failed.Name != vec.Expected.FailedCheck || failed.Code != vec.Expected.Code {
				t.Fatalf("expected %s/%s, got %+v", vec.Expected.FailedCheck, vec.Expected.Code, report.Checks)
			}
		})
	}
}

func TestValidityWindowBoundaries(t *testing.T) {
	file := loadVectors(t)
	jws := file.Vectors[0].JWS // valid 2026-01-01T00:00:00Z .. 2027-01-01T00:00:00Z
	from, until := at(t, validFrom), at(t, validUntil)
	cases := []struct {
		name string
		now  time.Time
		skew time.Duration
		want Code
	}{
		{"one second before validFrom", from.Add(-time.Second), 0, CodeValidityNotYetValid},
		{"exactly validFrom", from, 0, ""},
		{"one second after validFrom", from.Add(time.Second), 0, ""},
		{"one second before validUntil", until.Add(-time.Second), 0, ""},
		{"exactly validUntil is already expired", until, 0, CodeValidityExpired},
		{"one second after validUntil", until.Add(time.Second), 0, CodeValidityExpired},
		{"skew accepts a clock slightly behind validFrom", from.Add(-30 * time.Second), time.Minute, ""},
		{"skew boundary: exactly skew before validFrom", from.Add(-time.Minute), time.Minute, ""},
		{"beyond the skew before validFrom", from.Add(-time.Minute - time.Second), time.Minute, CodeValidityNotYetValid},
		{"skew accepts a clock slightly after validUntil", until.Add(30 * time.Second), time.Minute, ""},
		{"beyond the skew after validUntil", until.Add(time.Minute), time.Minute, CodeValidityExpired},
		{"a non-UTC clock is normalised", until.In(time.FixedZone("UTC-5", -5*3600)), 0, CodeValidityExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := newTestVerifier(t, file, tc.now, tc.skew).Verify(jws)
			if err != nil {
				t.Fatal(err)
			}
			failed, any := failedCheck(report)
			if tc.want == "" {
				if any || report.TechnicalResult != Valid {
					t.Fatalf("expected valid, got %+v", report.Checks)
				}
				return
			}
			if !any || failed.Name != CheckValidity || failed.Code != tc.want {
				t.Fatalf("expected validity/%s, got %+v", tc.want, report.Checks)
			}
		})
	}
}

func TestCredentialWithoutBoundsHasNoTimeLimit(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys := NewMemoryKeyResolver()
	if err := keys.Add(vectorIssuer, "k", &key.PublicKey); err != nil {
		t.Fatal(err)
	}
	payload := credentialPayload("jkt")
	delete(payload, "validFrom")
	delete(payload, "validUntil")
	v, _ := NewVerifier(keys, fixedClock(at(t, "2099-01-01T00:00:00Z")), DefaultLimits, 0)
	report, err := v.Verify(compact(baseHeader("k"), payload, key))
	if err != nil || report.TechnicalResult != Valid {
		t.Fatalf("expected valid, err=%v report=%+v", err, report.Checks)
	}
}

func TestMalformedValidityIsAFormatFailure(t *testing.T) {
	ctx := `"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"i"`
	for name, extra := range map[string]string{
		"not a date":                  `,"validFrom":"yesterday"`,
		"date without a time zone":    `,"validFrom":"2026-01-01T00:00:00"`,
		"date only":                   `,"validUntil":"2026-01-01"`,
		"validFrom after validUntil":  `,"validFrom":"2027-01-01T00:00:00Z","validUntil":"2026-01-01T00:00:00Z"`,
		"validFrom equals validUntil": `,"validFrom":"2026-01-01T00:00:00Z","validUntil":"2026-01-01T00:00:00Z"`,
	} {
		t.Run(name, func(t *testing.T) { wantFormat(t, token(goodHeader, `{`+ctx+extra+`}`), CodeFormatMalformed) })
	}
	parsed, check := ParseCredential(token(goodHeader, `{`+ctx+`,"validFrom":"2026-01-01T00:00:00+02:00"}`), DefaultLimits)
	if check.Result != Pass || parsed.ValidFromAt == nil || !parsed.ValidFromAt.Equal(at(t, "2025-12-31T22:00:00Z")) || parsed.ValidFromAt.Location() != time.UTC {
		t.Fatalf("offsets must be accepted and normalised to UTC, got %+v %+v", check, parsed)
	}
}

func TestDeclaredStatusAndSchemaPreventAValidReport(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys := NewMemoryKeyResolver()
	_ = keys.Add(vectorIssuer, "k", &key.PublicKey)
	v, _ := NewVerifier(keys, fixedClock(at(t, insideWindow)), DefaultLimits, 0)

	run := func(mutate func(map[string]any)) Report {
		payload := credentialPayload("jkt")
		mutate(payload)
		report, err := v.Verify(compact(baseHeader("k"), payload, key))
		if err != nil {
			t.Fatal(err)
		}
		return report
	}
	none := run(func(map[string]any) {})
	if none.TechnicalResult != Valid {
		t.Fatalf("a credential declaring neither must be valid, got %+v", none.Checks)
	}
	for _, c := range none.Checks {
		if (c.Name == CheckStatus || c.Name == CheckSchema) && (c.Result != Skipped || c.Code != CodeSkippedNotDeclared || c.Required) {
			t.Fatalf("undeclared %s must be an optional skip, got %+v", c.Name, c)
		}
	}
	for name, mutate := range map[string]func(map[string]any){
		"status": func(p map[string]any) {
			p["credentialStatus"] = []any{map[string]any{"type": "BitstringStatusListEntry"}}
		},
		"schema": func(p map[string]any) { p["credentialSchema"] = map[string]any{"type": "JsonSchema"} },
	} {
		report := run(mutate)
		if report.TechnicalResult != Invalid {
			t.Fatalf("declared %s must not be reported valid while unchecked: %+v", name, report.Checks)
		}
		if _, any := failedCheck(report); any {
			t.Fatalf("declared %s is an unchecked skip, not a failure: %+v", name, report.Checks)
		}
		var found bool
		for _, c := range report.Checks {
			if string(c.Name) == name && c.Result == Skipped && c.Code == CodeSkippedNotImplemented && c.Required {
				found = true
			}
		}
		if !found {
			t.Fatalf("declared %s must be a required skip.not_implemented: %+v", name, report.Checks)
		}
	}
}

func TestValidityIsNotEvaluatedForAnUnauthenticatedCredential(t *testing.T) {
	file := loadVectors(t)
	var tampered vector
	for _, v := range file.Vectors {
		if v.ID == "v06-signature-tampered" {
			tampered = v
		}
	}
	report, err := newTestVerifier(t, file, at(t, "2099-01-01T00:00:00Z"), 0).Verify(tampered.JWS)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range report.Checks {
		if c.Name == CheckValidity && (c.Result != Skipped || c.Code != CodeSkippedPrecondition || !c.Required) {
			t.Fatalf("validity of an unauthenticated credential must be a required skip, got %+v", c)
		}
	}
}

func TestVerifierPropagatesResolverFailureWithoutAReport(t *testing.T) {
	file := loadVectors(t)
	v, _ := NewVerifier(failingResolver{errors.New("jwks fetch timed out")}, fixedClock(at(t, insideWindow)), DefaultLimits, 0)
	report, err := v.Verify(file.Vectors[0].JWS)
	if !errors.Is(err, ErrKeyResolution) || report.Digest != "" || len(report.Checks) != 0 {
		t.Fatalf("expected an error and an empty report, got err=%v report=%+v", err, report)
	}
}

func TestReportNeverLeaksTheCredential(t *testing.T) {
	file := loadVectors(t)
	report, err := newTestVerifier(t, file, at(t, insideWindow), 0).Verify(file.Vectors[0].JWS)
	if err != nil {
		t.Fatal(err)
	}
	if report.Digest != Digest([]byte(file.Vectors[0].JWS)) {
		t.Fatal("digest must be the SHA-256 of the verified input")
	}
	parts := strings.Split(file.Vectors[0].JWS, ".")
	for _, c := range report.Checks {
		for _, piece := range parts {
			if strings.Contains(string(c.Code), piece) {
				t.Fatal("a check code leaks credential material")
			}
		}
	}
}

func TestNewVerifierValidatesItsConfiguration(t *testing.T) {
	keys := NewMemoryKeyResolver()
	clock := fixedClock(time.Unix(0, 0))
	bad := map[string]func() (*Verifier, error){
		"nil keys":        func() (*Verifier, error) { return NewVerifier(nil, clock, DefaultLimits, 0) },
		"nil clock":       func() (*Verifier, error) { return NewVerifier(keys, nil, DefaultLimits, 0) },
		"zero byte limit": func() (*Verifier, error) { return NewVerifier(keys, clock, Limits{MaxJSONDepth: 8}, 0) },
		"zero depth":      func() (*Verifier, error) { return NewVerifier(keys, clock, Limits{MaxJWSBytes: 1}, 0) },
		"negative skew":   func() (*Verifier, error) { return NewVerifier(keys, clock, DefaultLimits, -time.Second) },
		"skew above max":  func() (*Verifier, error) { return NewVerifier(keys, clock, DefaultLimits, MaxClockSkew+time.Second) },
	}
	for name, build := range bad {
		if v, err := build(); !errors.Is(err, ErrConfig) || v != nil {
			t.Fatalf("%s must be rejected, got %v", name, err)
		}
	}
	for _, skew := range []time.Duration{0, DefaultClockSkew, MaxClockSkew} {
		if _, err := NewVerifier(keys, clock, DefaultLimits, skew); err != nil {
			t.Fatalf("skew %v must be accepted: %v", skew, err)
		}
	}
}

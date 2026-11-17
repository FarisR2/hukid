package postgres

import (
	"errors"
	"slices"
	"testing"

	"hukid.local/platform/internal/verification"
)

func TestSummarizeReportKeepsOnlyTheClosedSet(t *testing.T) {
	report := verification.PresentationReport{
		TechnicalResult: verification.Invalid,
		Digest:          verification.Digest([]byte("synthetic presentation")),
		Checks: []verification.Check{
			{Name: verification.CheckRequestBinding, Result: verification.Fail, Code: verification.CodeRequestNonce, Required: true},
			{Name: verification.CheckFormat, Result: verification.Pass, Required: true},
			{Name: verification.CheckRequestBinding, Result: verification.Fail, Code: "free.text.not.in.the.set"},
		},
		Credentials: []verification.Report{{Checks: []verification.Check{
			{Name: verification.CheckSignature, Result: verification.Fail, Code: verification.CodeSignatureInvalid, Required: true},
			{Name: verification.CheckValidity, Result: verification.Fail, Code: verification.CodeRequestNonce},
		}}},
	}
	result, codes, digest, err := summarizeReport(report)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{string(verification.CodeRequestNonce), string(verification.CodeSignatureInvalid)}
	slices.Sort(want)
	if result != "fail" || !slices.Equal(codes, want) || len(digest) != 32 {
		t.Fatalf("%s %v %d bytes", result, codes, len(digest))
	}
}

func TestSummarizeReportMapsAValidPresentationToPass(t *testing.T) {
	report := verification.PresentationReport{TechnicalResult: verification.Valid, Digest: verification.Digest([]byte("x"))}
	result, codes, _, err := summarizeReport(report)
	if err != nil || result != "pass" || len(codes) != 0 {
		t.Fatalf("%s %v %v", result, codes, err)
	}
}

func TestSummarizeReportRejectsAMalformedReport(t *testing.T) {
	good := verification.Digest([]byte("x"))
	for name, report := range map[string]verification.PresentationReport{
		"unknown result": {TechnicalResult: "maybe", Digest: good},
		"no result":      {Digest: good},
		"no prefix":      {TechnicalResult: verification.Valid, Digest: good[len("sha256:"):]},
		"short digest":   {TechnicalResult: verification.Valid, Digest: "sha256:abcd"},
		"not hex":        {TechnicalResult: verification.Valid, Digest: "sha256:" + string(make([]byte, 64))},
	} {
		if _, _, _, err := summarizeReport(report); !errors.Is(err, ErrResultNotStored) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestResultStoreRefusesAnInvalidSessionIDWithoutTouchingTheDatabase(t *testing.T) {
	store := &VerificationResultStore{}
	report := verification.PresentationReport{TechnicalResult: verification.Valid, Digest: verification.Digest([]byte("x"))}
	if err := store.DeliverSession("not-a-uuid", report); !errors.Is(err, ErrResultNotStored) {
		t.Fatalf("%v", err)
	}
}

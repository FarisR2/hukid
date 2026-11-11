package verification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func presentationVerifier(t *testing.T, file vectorFile, evaluationTime string, store ReplayStore) *Verifier {
	t.Helper()
	return newTestVerifier(t, file, at(t, evaluationTime), 0).WithReplayStore(store)
}

func firstFailure(report PresentationReport) (Check, bool) {
	for _, c := range report.Checks {
		if c.Result == Fail {
			return c, true
		}
	}
	for _, credential := range report.Credentials {
		if c, any := failedCheck(credential); any {
			return c, true
		}
	}
	return Check{}, false
}

func TestPresentationOutcomeMatchesTheVectorSet(t *testing.T) {
	file := loadVectors(t)
	if len(file.PresentationVectors) < 10 {
		t.Fatalf("expected the presentation vector set, got %d", len(file.PresentationVectors))
	}
	for _, vec := range file.PresentationVectors {
		t.Run(vec.ID, func(t *testing.T) {
			v := presentationVerifier(t, file, vec.EvaluationTime, NewMemoryReplayStore())
			report, err := v.VerifyPresentation(Response{VP: vec.VP, State: vec.ResponseState}, Request(vec.Request))
			if err != nil {
				t.Fatal(err)
			}
			if report.TechnicalResult != vec.Expected.TechnicalResult {
				t.Fatalf("technicalResult = %q, want %q: %+v", report.TechnicalResult, vec.Expected.TechnicalResult, report)
			}
			failed, any := firstFailure(report)
			if vec.Expected.TechnicalResult == Valid {
				if any {
					t.Fatalf("unexpected failure %+v", failed)
				}
				return
			}
			if !any || failed.Name != vec.Expected.FailedCheck || failed.Code != vec.Expected.Code {
				t.Fatalf("expected %s/%s, got %+v (%+v)", vec.Expected.FailedCheck, vec.Expected.Code, failed, report)
			}
		})
	}
}

func presentationVectorByID(t *testing.T, file vectorFile, id string) presentationVector {
	t.Helper()
	for _, v := range file.PresentationVectors {
		if v.ID == id {
			return v
		}
	}
	t.Fatalf("vector %s not found", id)
	return presentationVector{}
}

func TestCredentialFailureInsideAPresentationIsReportedPerCredential(t *testing.T) {
	file := loadVectors(t)
	vec := presentationVectorByID(t, file, "p10-credential-expired")
	report, err := presentationVerifier(t, file, vec.EvaluationTime, NewMemoryReplayStore()).VerifyPresentation(Response{VP: vec.VP, State: vec.ResponseState}, Request(vec.Request))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range report.Checks {
		if c.Result != Pass {
			t.Fatalf("presentation-level checks must pass, got %+v", report.Checks)
		}
	}
	if len(report.Credentials) != 1 || report.Credentials[0].TechnicalResult != Invalid || report.TechnicalResult != Invalid {
		t.Fatalf("the expired credential must invalidate the presentation: %+v", report)
	}
}

func TestReplayedResponseIsRejected(t *testing.T) {
	file := loadVectors(t)
	vec := presentationVectorByID(t, file, "p01-valid")
	v := presentationVerifier(t, file, vec.EvaluationTime, NewMemoryReplayStore())
	resp, req := Response{VP: vec.VP, State: vec.ResponseState}, Request(vec.Request)

	first, err := v.VerifyPresentation(resp, req)
	if err != nil || first.TechnicalResult != Valid {
		t.Fatalf("first use must be valid, err=%v %+v", err, first)
	}
	second, err := v.VerifyPresentation(resp, req)
	if err != nil {
		t.Fatal(err)
	}
	failed, any := firstFailure(second)
	if !any || failed.Name != CheckRequestBinding || failed.Code != CodeRequestReplayed || second.TechnicalResult != Invalid {
		t.Fatalf("second use must be request.replayed, got %+v", second)
	}
	if len(second.Credentials) != 0 {
		t.Fatal("credentials of a replayed response must not be verified")
	}
}

type countingStore struct {
	consumed atomic.Int32
	inner    *MemoryReplayStore
}

func (c *countingStore) Consume(key string) (bool, error) {
	c.consumed.Add(1)
	return c.inner.Consume(key)
}

func TestRequestIsConsumedOnlyAfterAnAuthenticMatchingResponse(t *testing.T) {
	file := loadVectors(t)
	cases := []struct {
		id   string
		want int32
		why  string
	}{
		{"p08-vp-header-typ-wrong", 0, "malformed VP"},
		{"p06-vp-signature-tampered", 0, "unauthenticated sender must not burn a request"},
		{"p03-audience-mismatch", 0, "audience mismatch"},
		{"p04-nonce-mismatch", 0, "nonce mismatch"},
		{"p05-state-mismatch", 0, "state mismatch"},
		{"p01-valid", 1, "valid response"},
		{"p02-holder-key-mismatch", 1, "a matching, signed response is consumed even if binding then fails"},
		{"p10-credential-expired", 1, "a matching, signed response is consumed even if a credential then fails"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			vec := presentationVectorByID(t, file, tc.id)
			store := &countingStore{inner: NewMemoryReplayStore()}
			if _, err := presentationVerifier(t, file, vec.EvaluationTime, store).VerifyPresentation(Response{VP: vec.VP, State: vec.ResponseState}, Request(vec.Request)); err != nil {
				t.Fatal(err)
			}
			if got := store.consumed.Load(); got != tc.want {
				t.Fatalf("%s: consumed %d times, want %d", tc.why, got, tc.want)
			}
		})
	}
}

func TestMemoryReplayStoreConsumesExactlyOnceUnderConcurrency(t *testing.T) {
	store := NewMemoryReplayStore()
	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if first, err := store.Consume("same-key"); err != nil {
				t.Error(err)
			} else if first {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("exactly one caller must win, got %d", winners.Load())
	}
	if first, _ := store.Consume("another-key"); !first {
		t.Fatal("a different key must be consumable")
	}
}

type failingStore struct{}

func (failingStore) Consume(string) (bool, error) { return false, errors.New("store unavailable") }

func TestReplayStoreFailureAndMissingStoreAreErrorsNotFindings(t *testing.T) {
	file := loadVectors(t)
	vec := presentationVectorByID(t, file, "p01-valid")
	resp, req := Response{VP: vec.VP, State: vec.ResponseState}, Request(vec.Request)

	report, err := presentationVerifier(t, file, vec.EvaluationTime, failingStore{}).VerifyPresentation(resp, req)
	if !errors.Is(err, ErrReplayStore) || report.Digest != "" || len(report.Checks) != 0 {
		t.Fatalf("expected an error and an empty report, got err=%v %+v", err, report)
	}
	noStore := newTestVerifier(t, file, at(t, vec.EvaluationTime), 0)
	if _, err := noStore.VerifyPresentation(resp, req); !errors.Is(err, ErrConfig) {
		t.Fatalf("a verifier without a replay store must refuse presentations, got %v", err)
	}
}

func TestHolderBindingUsesTheVectorThumbprint(t *testing.T) {
	file := loadVectors(t)
	key := ecdsaFromJWK(t, file.HolderKey)
	got, err := JWKThumbprint(key)
	if err != nil {
		t.Fatal(err)
	}
	if got != file.HolderJKT || got != jwkThumbprint(file.HolderKey) {
		t.Fatalf("thumbprint %q does not match the independent computation %q", got, file.HolderJKT)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := JWKThumbprint(&p384.PublicKey); err == nil {
		t.Fatal("only P-256 keys are supported")
	}
}

func TestEmptyExpectationsNeverMatch(t *testing.T) {
	parsed := &parsedPresentation{}
	for name, req := range map[string]Request{
		"all empty":      {},
		"empty audience": {Nonce: "n", State: "s"},
	} {
		if got := matchRequest(parsed, "", req); got != CodeRequestAudience {
			t.Fatalf("%s: an empty expectation must not match an empty value, got %q", name, got)
		}
	}
	if got := matchRequest(&parsedPresentation{Audience: "a"}, "", Request{Audience: "a"}); got != CodeRequestNonce {
		t.Fatalf("empty nonce expectation must fail with the nonce code, got %q", got)
	}
	if got := matchRequest(&parsedPresentation{Audience: "a", Nonce: "n"}, "", Request{Audience: "a", Nonce: "n"}); got != CodeRequestState {
		t.Fatalf("empty state expectation must fail with the state code, got %q", got)
	}
}

func presentationFormatCode(t *testing.T, header, payload map[string]any, limits Limits) Code {
	t.Helper()
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, code := parsePresentation(compact(header, payload, signer), limits)
	return code
}

func TestPresentationFormatRules(t *testing.T) {
	file := loadVectors(t)
	holder := file.HolderKey
	vc := envelopedCredential(file.Vectors[0].JWS)
	good := func() map[string]any { return presentationPayload("aud", "n", vc) }
	with := func(mutate func(map[string]any)) map[string]any { p := good(); mutate(p); return p }
	headerWith := func(mutate func(map[string]any)) map[string]any { h := presentationHeader(holder); mutate(h); return h }

	cases := map[string]struct {
		header, payload map[string]any
		want            Code
	}{
		"accepted":   {presentationHeader(holder), good(), ""},
		"alg none":   {headerWith(func(h map[string]any) { h["alg"] = "none" }), good(), CodeFormatHeaderAlg},
		"typ vc+jwt": {headerWith(func(h map[string]any) { h["typ"] = "vc+jwt" }), good(), CodeFormatHeaderTyp},
		"no jwk":     {headerWith(func(h map[string]any) { delete(h, "jwk") }), good(), CodeFormatMalformed},
		"kid only":   {headerWith(func(h map[string]any) { delete(h, "jwk"); h["kid"] = "holder-1" }), good(), CodeFormatMalformed},
		"jwk with private d": {headerWith(func(h map[string]any) {
			h["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": holder.X, "y": holder.Y, "d": "AA"}
		}), good(), CodeFormatMalformed},
		"jwk wrong curve": {headerWith(func(h map[string]any) {
			h["jwk"] = map[string]any{"kty": "EC", "crv": "P-384", "x": holder.X, "y": holder.Y}
		}), good(), CodeFormatMalformed},
		"jwk point off curve": {headerWith(func(h map[string]any) {
			h["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": holder.X, "y": holder.X}
		}), good(), CodeFormatMalformed},
		"jwk short coordinate": {headerWith(func(h map[string]any) {
			h["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": "AQ", "y": holder.Y}
		}), good(), CodeFormatMalformed},
		"wrong first context": {presentationHeader(holder), with(func(p map[string]any) { p["@context"] = []any{"https://example.invalid/ctx"} }), CodeFormatMalformed},
		"type lacks VP":       {presentationHeader(holder), with(func(p map[string]any) { p["type"] = []any{"Other"} }), CodeFormatMalformed},
		"no credentials":      {presentationHeader(holder), with(func(p map[string]any) { p["verifiableCredential"] = []any{} }), CodeFormatMalformed},
		"credentials missing": {presentationHeader(holder), with(func(p map[string]any) { delete(p, "verifiableCredential") }), CodeFormatMalformed},
		"entry not enveloped": {presentationHeader(holder), with(func(p map[string]any) {
			p["verifiableCredential"] = []any{map[string]any{"type": "VerifiableCredential", "id": "x"}}
		}), CodeFormatMalformed},
		"empty data url": {presentationHeader(holder), with(func(p map[string]any) { p["verifiableCredential"] = []any{envelopedCredential("")} }), CodeFormatMalformed},
		"too many credentials": {presentationHeader(holder), with(func(p map[string]any) {
			many := make([]any, DefaultLimits.MaxCredentials+1)
			for i := range many {
				many[i] = vc
			}
			p["verifiableCredential"] = many
		}), CodeFormatMalformed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := presentationFormatCode(t, tc.header, tc.payload, DefaultLimits); got != tc.want {
				t.Fatalf("code = %q, want %q", got, tc.want)
			}
		})
	}
	t.Run("oversize presentation", func(t *testing.T) {
		small := DefaultLimits
		small.MaxPresentationBytes = 300
		if got := presentationFormatCode(t, presentationHeader(holder), good(), small); got != CodeFormatMalformed {
			t.Fatalf("oversize presentation must be malformed, got %q", got)
		}
	})
}

func TestPresentationReportNeverLeaksTheResponse(t *testing.T) {
	file := loadVectors(t)
	vec := presentationVectorByID(t, file, "p01-valid")
	report, err := presentationVerifier(t, file, vec.EvaluationTime, NewMemoryReplayStore()).VerifyPresentation(Response{VP: vec.VP, State: vec.ResponseState}, Request(vec.Request))
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(report)
	for _, secret := range []string{vec.VP, vec.Request.Nonce, vec.Request.State, vec.Request.Audience, file.Vectors[0].JWS, "eyJ"} {
		if strings.Contains(string(blob), secret) {
			t.Fatalf("report leaks %q: %s", secret, blob)
		}
	}
	if report.Digest != Digest([]byte(vec.VP)) {
		t.Fatal("digest must be the SHA-256 of the presentation")
	}
	trusted := report.WithTrust(Untrusted)
	if trusted.TechnicalResult != report.TechnicalResult || report.Trust != nil {
		t.Fatal("trust must not alter the technical result or mutate the receiver")
	}
}

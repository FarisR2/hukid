package verification

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// sensitiveMaterial returns every string that must never appear in an output
// of the module for the given inputs: the compact tokens, each of their
// segments, the decoded JOSE header and payload, and the values that bind a
// presentation to its request or its holder (VER-FR08).
func sensitiveMaterial(t *testing.T, file vectorFile, jws ...string) []string {
	t.Helper()
	material := []string{file.Issuer, "synthetic-lab-key-1", file.HolderJKT, file.HolderKey.X, file.HolderKey.Y, "synthetic-lab-subject", vectorAudience}
	for _, token := range jws {
		material = append(material, token)
		for _, segment := range strings.Split(token, ".") {
			if len(segment) < 8 {
				continue
			}
			material = append(material, segment)
			if decoded, err := base64.RawURLEncoding.DecodeString(segment); err == nil && len(decoded) > 8 {
				material = append(material, string(decoded))
			}
		}
	}
	return material
}

func assertNoMaterial(t *testing.T, where string, output string, material []string) {
	t.Helper()
	for _, secret := range material {
		if strings.Contains(output, secret) {
			t.Fatalf("%s leaks %q\n%s", where, secret, output)
		}
	}
}

func renderings(value any) []string {
	blob, _ := json.Marshal(value)
	return []string{string(blob), fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)}
}

func TestNoOutputOfACredentialVerificationContainsTheCredential(t *testing.T) {
	file := loadVectors(t)
	for _, vec := range file.Vectors {
		t.Run(vec.ID, func(t *testing.T) {
			v := newTestVerifier(t, file, at(t, vec.EvaluationTime), 0).WithTrustPolicy(NewAllowlistTrustPolicy(file.Issuer))
			report, err := v.Verify(vec.JWS)
			if err != nil {
				t.Fatal(err)
			}
			material := sensitiveMaterial(t, file, vec.JWS)
			for i, rendered := range renderings(report) {
				assertNoMaterial(t, fmt.Sprintf("report rendering %d", i), rendered, material)
			}
		})
	}
}

func TestNoOutputOfAPresentationVerificationContainsTheResponse(t *testing.T) {
	file := loadVectors(t)
	for _, vec := range file.PresentationVectors {
		t.Run(vec.ID, func(t *testing.T) {
			v := presentationVerifier(t, file, vec.EvaluationTime, NewMemoryReplayStore()).WithTrustPolicy(NewAllowlistTrustPolicy(file.Issuer))
			report, err := v.VerifyPresentation(Response{VP: vec.VP, State: vec.ResponseState}, Request(vec.Request))
			if err != nil {
				t.Fatal(err)
			}
			material := append(sensitiveMaterial(t, file, vec.VP, file.Vectors[0].JWS), vec.Request.Nonce, vec.Request.State, vec.ResponseState, "wrong-nonce", "altered-nonce")
			for i, rendered := range renderings(report) {
				assertNoMaterial(t, fmt.Sprintf("presentation report rendering %d", i), rendered, material)
			}
		})
	}
}

type leakyFailure struct{ message string }

func (l leakyFailure) Error() string { return l.message }

func TestErrorsFromDependenciesDoNotAddTheCredential(t *testing.T) {
	file := loadVectors(t)
	vec, pres := file.Vectors[0], file.PresentationVectors[0]
	material := sensitiveMaterial(t, file, vec.JWS, pres.VP)
	material = append(material, pres.Request.Nonce, pres.Request.State)
	const inner = "dependency unavailable"
	at := at(t, vec.EvaluationTime)

	resolverErr := func() error {
		v, _ := NewVerifier(failingResolver{leakyFailure{inner}}, fixedClock(at), DefaultLimits, 0)
		_, err := v.Verify(vec.JWS)
		return err
	}()
	trustErr := func() error {
		_, err := newTestVerifier(t, file, at, 0).WithTrustPolicy(&spyPolicy{err: leakyFailure{inner}}).Verify(vec.JWS)
		return err
	}()
	replayErr := func() error {
		v := presentationVerifier(t, file, pres.EvaluationTime, failingStoreWith{inner})
		_, err := v.VerifyPresentation(Response{VP: pres.VP, State: pres.ResponseState}, Request(pres.Request))
		return err
	}()
	for name, tc := range map[string]struct {
		err      error
		sentinel error
	}{
		"resolver": {resolverErr, ErrKeyResolution},
		"trust":    {trustErr, ErrTrustPolicy},
		"replay":   {replayErr, ErrReplayStore},
	} {
		if !errors.Is(tc.err, tc.sentinel) {
			t.Fatalf("%s: expected %v, got %v", name, tc.sentinel, tc.err)
		}
		if got := tc.err.Error(); !strings.HasSuffix(got, inner) {
			t.Fatalf("%s: the error must wrap only the dependency message, got %q", name, got)
		}
		assertNoMaterial(t, name+" error", tc.err.Error(), material)
	}
}

type failingStoreWith struct{ message string }

func (f failingStoreWith) Consume(string) (bool, error) { return false, leakyFailure{f.message} }

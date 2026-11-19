package verification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
)

// Pruebas de rama para los caminos alcanzables que la suite de vectores no
// ejercitaba. Nomenclatura: Unidad_condicion_resultado.

func TestParseCredential_TypeIsNotAStringNorAnArrayOfStrings_ReturnsMalformed(t *testing.T) {
	payloads := map[string]string{
		"number":              `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":5,"issuer":"https://issuer.hukid.pe/lab"}`,
		"array with a number": `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential",1],"issuer":"https://issuer.hukid.pe/lab"}`,
	}
	for name, payload := range payloads {
		t.Run(name, func(t *testing.T) {
			// Arrange
			jws := token(goodHeader, payload)

			// Act
			parsed, check := ParseCredential(jws, DefaultLimits)

			// Assert
			if parsed != nil || check.Result != Fail || check.Code != CodeFormatMalformed {
				t.Fatalf("want format.malformed and no parsed credential, got parsed=%v check=%+v", parsed != nil, check)
			}
		})
	}
}

func TestParsePresentation_EnvelopeContextIsNotTheBaseContext_ReturnsContextNotAllowed(t *testing.T) {
	file := loadVectors(t)
	contexts := map[string]any{"another string": "https://example.invalid/ctx", "a number": 5}
	for name, envelopeContext := range contexts {
		t.Run(name, func(t *testing.T) {
			// Arrange
			entry := envelopedCredential(file.Vectors[0].JWS)
			entry["@context"] = envelopeContext
			payload := presentationPayload("aud", "n", entry)

			// Act
			got := presentationFormatCode(t, presentationHeader(file.HolderKey), payload, DefaultLimits)

			// Assert
			if got != CodeFormatContextNotAllowed {
				t.Fatalf("code = %q, want %q", got, CodeFormatContextNotAllowed)
			}
		})
	}
}

func TestParsePresentation_HolderJWKIsNotAnObject_ReturnsMalformed(t *testing.T) {
	file := loadVectors(t)
	jwks := map[string]any{"a string": "not-an-object", "an array": []any{"x"}}
	for name, jwkValue := range jwks {
		t.Run(name, func(t *testing.T) {
			// Arrange
			header := presentationHeader(file.HolderKey)
			header["jwk"] = jwkValue
			payload := presentationPayload("aud", "n", envelopedCredential(file.Vectors[0].JWS))

			// Act
			got := presentationFormatCode(t, header, payload, DefaultLimits)

			// Assert
			if got != CodeFormatMalformed {
				t.Fatalf("code = %q, want %q", got, CodeFormatMalformed)
			}
		})
	}
}

func TestVerifyPresentation_ResolverFailsWhileVerifyingACredential_ReturnsKeyResolutionError(t *testing.T) {
	// Arrange
	file := loadVectors(t)
	vec := presentationVectorByID(t, file, "p01-valid")
	unavailable := failingResolver{errors.New("jwks fetch timed out")}
	verifier, err := NewVerifier(unavailable, fixedClock(at(t, vec.EvaluationTime)), DefaultLimits, 0)
	if err != nil {
		t.Fatal(err)
	}
	verifier = verifier.WithReplayStore(NewMemoryReplayStore())

	// Act
	report, err := verifier.VerifyPresentation(Response{VP: vec.VP, State: vec.ResponseState}, Request(vec.Request))

	// Assert
	if !errors.Is(err, ErrKeyResolution) {
		t.Fatalf("err = %v, want ErrKeyResolution", err)
	}
	if report.Digest != "" || len(report.Checks) != 0 {
		t.Fatalf("an infrastructure failure must return an empty report, got %+v", report)
	}
}

func TestVerifyPresentation_EnvelopedCredentialIsMalformed_ReportsItAndSkipsHolderBinding(t *testing.T) {
	// Arrange
	file := loadVectors(t)
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	malformed := token(goodHeader, `{"not":"a credential"}`)
	vp := compact(
		presentationHeader(publicJWK(&holderKey.PublicKey, "")),
		presentationPayload("aud-1", "nonce-1", envelopedCredential(malformed)),
		holderKey,
	)
	verifier := presentationVerifier(t, file, insideWindow, NewMemoryReplayStore())

	// Act
	report, err := verifier.VerifyPresentation(Response{VP: vp, State: "state-1"}, Request{Audience: "aud-1", Nonce: "nonce-1", State: "state-1"})
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	credentialFormat := checkByName(report.Credentials[0].Checks, CheckFormat)
	holder := checkByName(report.Checks, CheckHolderBinding)
	request := checkByName(report.Checks, CheckRequestBinding)
	if credentialFormat.Code != CodeFormatMalformed || credentialFormat.Result != Fail {
		t.Fatalf("the credential must report format.malformed, got %+v", credentialFormat)
	}
	if request.Result != Pass {
		t.Fatalf("the request matched and must pass, got %+v", request)
	}
	if holder.Result != Skipped || holder.Code != CodeSkippedPrecondition {
		t.Fatalf("holder binding must be skipped, got %+v", holder)
	}
	if report.TechnicalResult != Invalid {
		t.Fatalf("technicalResult = %q, want invalid", report.TechnicalResult)
	}
}

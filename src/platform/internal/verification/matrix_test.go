package verification

import (
	"strings"
	"testing"
)

// matrixRow ties one scenario of the FEAT-004 negative matrix to the vector
// that exercises it and the failure it must produce.
type matrixRow struct {
	scenario string
	vectorID string
	check    CheckName
	code     Code
}

// negativeMatrix is the minimum matrix of the plan. Scenarios without a signed
// vector (oversize inputs and replay) are exercised inline below. Adding a
// vector without adding a row here fails TestEveryVectorIsInTheMatrix.
var negativeMatrix = []matrixRow{
	{"header incorrecto", "v02-header-typ-wrong", CheckFormat, CodeFormatHeaderTyp},
	{"alg alterado", "v03-header-alg-none", CheckFormat, CodeFormatHeaderAlg},
	{"contenedor vc", "v04-payload-vc-container", CheckFormat, CodeFormatVCContainer},
	{"contexto no listado en la credencial", "v10-context-not-listed", CheckFormat, CodeFormatContextNotAllowed},
	{"jku o jwk en la credencial", "v05-header-jku", CheckIssuerKey, CodeKeyUntrustedHeader},
	{"kid desconocido", "v07-unknown-kid", CheckIssuerKey, CodeKeyUnknownKID},
	{"issuer distinto", "v11-issuer-mismatch", CheckIssuerKey, CodeKeyIssuerMismatch},
	{"firma alterada", "v06-signature-tampered", CheckSignature, CodeSignatureInvalid},
	{"credencial futura", "v09-not-yet-valid", CheckValidity, CodeValidityNotYetValid},
	{"credencial vencida", "v08-expired", CheckValidity, CodeValidityExpired},
	{"VP con header incorrecto", "p08-vp-header-typ-wrong", CheckFormat, CodeFormatHeaderTyp},
	{"VP con credencial no envuelta como data URL", "p09-envelope-not-data-url", CheckFormat, CodeFormatMalformed},
	{"contexto no listado en la VP", "p11-presentation-context-not-listed", CheckFormat, CodeFormatContextNotAllowed},
	{"firma de la VP alterada", "p06-vp-signature-tampered", CheckSignature, CodeSignatureInvalid},
	{"audience equivocada", "p03-audience-mismatch", CheckRequestBinding, CodeRequestAudience},
	{"nonce equivocado", "p04-nonce-mismatch", CheckRequestBinding, CodeRequestNonce},
	{"state equivocado", "p05-state-mismatch", CheckRequestBinding, CodeRequestState},
	{"cnf.jkt distinto de la clave de la VP", "p02-holder-key-mismatch", CheckHolderBinding, CodeBindingMismatch},
	{"credencial sin cnf", "p07-credential-without-cnf", CheckHolderBinding, CodeBindingMissingCNF},
	{"credencial vencida dentro de una VP", "p10-credential-expired", CheckValidity, CodeValidityExpired},
}

func TestNegativeMatrix(t *testing.T) {
	file := loadVectors(t)
	for _, row := range negativeMatrix {
		t.Run(row.scenario, func(t *testing.T) {
			var failed Check
			var any bool
			var result TechnicalResult
			if strings.HasPrefix(row.vectorID, "p") {
				vec := presentationVectorByID(t, file, row.vectorID)
				report, err := presentationVerifier(t, file, vec.EvaluationTime, NewMemoryReplayStore()).VerifyPresentation(Response{VP: vec.VP, State: vec.ResponseState}, Request(vec.Request))
				if err != nil {
					t.Fatal(err)
				}
				failed, any = firstFailure(report)
				result = report.TechnicalResult
			} else {
				var vec vector
				for _, candidate := range file.Vectors {
					if candidate.ID == row.vectorID {
						vec = candidate
					}
				}
				if vec.ID == "" {
					t.Fatalf("vector %s not found", row.vectorID)
				}
				report, err := newTestVerifier(t, file, at(t, vec.EvaluationTime), 0).Verify(vec.JWS)
				if err != nil {
					t.Fatal(err)
				}
				failed, any = failedCheck(report)
				result = report.TechnicalResult
			}
			if result != Invalid || !any || failed.Name != row.check || failed.Code != row.code {
				t.Fatalf("expected invalid with %s/%s, got result=%q failed=%+v", row.check, row.code, result, failed)
			}
		})
	}
}

func TestEveryVectorIsInTheMatrix(t *testing.T) {
	file := loadVectors(t)
	inMatrix := map[string]bool{}
	for _, row := range negativeMatrix {
		inMatrix[row.vectorID] = true
	}
	for _, vec := range file.Vectors {
		if vec.Expected.TechnicalResult == Invalid && !inMatrix[vec.ID] {
			t.Fatalf("negative vector %s has no row in the negative matrix", vec.ID)
		}
	}
	for _, vec := range file.PresentationVectors {
		if vec.Expected.TechnicalResult == Invalid && !inMatrix[vec.ID] {
			t.Fatalf("negative presentation vector %s has no row in the negative matrix", vec.ID)
		}
	}
	// And the matrix names only vectors that exist.
	known := map[string]bool{}
	for _, vec := range file.Vectors {
		known[vec.ID] = true
	}
	for _, vec := range file.PresentationVectors {
		known[vec.ID] = true
	}
	for _, row := range negativeMatrix {
		if !known[row.vectorID] {
			t.Fatalf("matrix row %q names a vector that does not exist: %s", row.scenario, row.vectorID)
		}
	}
}

func TestNegativeMatrixInlineScenarios(t *testing.T) {
	file := loadVectors(t)

	t.Run("credencial sobredimensionada", func(t *testing.T) {
		v := newTestVerifier(t, file, at(t, insideWindow), 0)
		report, err := v.Verify(strings.Repeat("a", DefaultLimits.MaxJWSBytes+1))
		if err != nil {
			t.Fatal(err)
		}
		if failed, any := failedCheck(report); !any || failed.Name != CheckFormat || failed.Code != CodeFormatMalformed || report.TechnicalResult != Invalid {
			t.Fatalf("expected format.malformed, got %+v", report)
		}
	})
	t.Run("presentacion sobredimensionada", func(t *testing.T) {
		v := presentationVerifier(t, file, insideWindow, NewMemoryReplayStore())
		report, err := v.VerifyPresentation(Response{VP: strings.Repeat("a", DefaultLimits.MaxPresentationBytes+1), State: "s"}, Request{Audience: "a", Nonce: "n", State: "s"})
		if err != nil {
			t.Fatal(err)
		}
		if failed, any := firstFailure(report); !any || failed.Name != CheckFormat || failed.Code != CodeFormatMalformed || report.TechnicalResult != Invalid {
			t.Fatalf("expected format.malformed, got %+v", report)
		}
	})
	t.Run("nonce y state reutilizados", func(t *testing.T) {
		vec := presentationVectorByID(t, file, "p01-valid")
		v := presentationVerifier(t, file, vec.EvaluationTime, NewMemoryReplayStore())
		resp, req := Response{VP: vec.VP, State: vec.ResponseState}, Request(vec.Request)
		if first, err := v.VerifyPresentation(resp, req); err != nil || first.TechnicalResult != Valid {
			t.Fatalf("first use must be valid, err=%v", err)
		}
		second, err := v.VerifyPresentation(resp, req)
		if err != nil {
			t.Fatal(err)
		}
		if failed, any := firstFailure(second); !any || failed.Name != CheckRequestBinding || failed.Code != CodeRequestReplayed || second.TechnicalResult != Invalid {
			t.Fatalf("expected request.replayed, got %+v", second)
		}
	})
	t.Run("contexto remoto no listado no sale a la red", func(t *testing.T) {
		// The package cannot reach the network (see TestPackageStaysPureAndSilent),
		// so an unlisted context can only be rejected by the allowlist.
		vec := file.Vectors[9]
		if vec.ID != "v10-context-not-listed" {
			t.Fatalf("unexpected vector order: %s", vec.ID)
		}
		_, check := ParseCredential(vec.JWS, DefaultLimits)
		if check.Code != CodeFormatContextNotAllowed {
			t.Fatalf("expected format.context_not_allowed, got %+v", check)
		}
	})
}

func TestAnExtraContextIsAcceptedOnlyWhenTheVerifierIsConfiguredForIt(t *testing.T) {
	file := loadVectors(t)
	vec := file.Vectors[9]
	base := newTestVerifier(t, file, at(t, vec.EvaluationTime), 0)

	rejected, err := base.Verify(vec.JWS)
	if err != nil {
		t.Fatal(err)
	}
	if failed, any := failedCheck(rejected); !any || failed.Code != CodeFormatContextNotAllowed {
		t.Fatalf("the default allowlist must reject the extra context, got %+v", rejected)
	}
	accepted, err := base.WithCredentialContexts("https://attacker.invalid/context").Verify(vec.JWS)
	if err != nil {
		t.Fatal(err)
	}
	if _, any := failedCheck(accepted); any || accepted.TechnicalResult != Valid {
		t.Fatalf("an explicitly allowed context must pass, got %+v", accepted)
	}
	if again, _ := base.Verify(vec.JWS); again.TechnicalResult != Invalid {
		t.Fatal("WithCredentialContexts must not mutate the receiver")
	}
}

func TestInlineContextObjectsAreNeverAllowed(t *testing.T) {
	ctx := `{"@context":["https://www.w3.org/ns/credentials/v2",{"x":"https://attacker.invalid/x"}],"type":["VerifiableCredential"],"issuer":"i"}`
	wantFormat(t, token(goodHeader, ctx), CodeFormatContextNotAllowed)
}

package verification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const vectorsPath = "testdata/vectors.json"

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid,omitempty"`
}

type vectorExpectation struct {
	TechnicalResult TechnicalResult `json:"technicalResult"`
	FailedCheck     CheckName       `json:"failedCheck,omitempty"`
	Code            Code            `json:"code,omitempty"`
}

type vector struct {
	ID             string            `json:"id"`
	Description    string            `json:"description"`
	JWS            string            `json:"jws"`
	EvaluationTime string            `json:"evaluationTime"`
	Expected       vectorExpectation `json:"expected"`
}

type vectorFile struct {
	Synthetic   bool              `json:"synthetic"`
	Notice      string            `json:"notice"`
	CodesVer    int               `json:"codesVersion"`
	Issuer      string            `json:"issuer"`
	IssuerKeys  map[string]jwk    `json:"issuerPublicKeys"`
	HolderKey   jwk               `json:"holderPublicKey"`
	HolderJKT   string            `json:"holderJkt"`
	Vectors     []vector          `json:"vectors"`
	Limitations []string          `json:"limitations"`
	Meta        map[string]string `json:"meta"`
}

const (
	vectorIssuer = "https://issuer.hukid.pe/synthetic-lab"
	validFrom    = "2026-01-01T00:00:00Z"
	validUntil   = "2027-01-01T00:00:00Z"
	insideWindow = "2026-06-01T00:00:00Z"
)

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func publicJWK(key *ecdsa.PublicKey, kid string) jwk {
	raw, err := key.Bytes()
	if err != nil {
		panic(err)
	}
	return jwk{Kty: "EC", Crv: "P-256", X: b64(raw[1:33]), Y: b64(raw[33:65]), Kid: kid}
}

// jwkThumbprint is the RFC 7638 thumbprint of an EC public key.
func jwkThumbprint(k jwk) string {
	canonical := `{"crv":"` + k.Crv + `","kty":"` + k.Kty + `","x":"` + k.X + `","y":"` + k.Y + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return b64(sum[:])
}

func signES256(key *ecdsa.PrivateKey, signingInput string) string {
	digest := sha256.Sum256([]byte(signingInput))
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		panic(err)
	}
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		panic(err)
	}
	raw := make([]byte, 64)
	sig.R.FillBytes(raw[:32])
	sig.S.FillBytes(raw[32:])
	return b64(raw)
}

// verifyES256 is an independent oracle built only on the standard library.
func verifyES256(k jwk, signingInput, signature string) bool {
	x, err1 := base64.RawURLEncoding.DecodeString(k.X)
	y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
	sig, err3 := base64.RawURLEncoding.DecodeString(signature)
	if err1 != nil || err2 != nil || err3 != nil || len(sig) != 64 {
		return false
	}
	pub := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])})
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(signingInput))
	return ecdsa.VerifyASN1(&pub, digest[:], der)
}

func compact(header, payload map[string]any, key *ecdsa.PrivateKey) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	input := b64(h) + "." + b64(p)
	return input + "." + signES256(key, input)
}

func credentialPayload(jkt string) map[string]any {
	return map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential", "SyntheticLabCredential"},
		"issuer":            vectorIssuer,
		"validFrom":         validFrom,
		"validUntil":        validUntil,
		"credentialSubject": map[string]any{"label": "synthetic-lab-subject"},
		"cnf":               map[string]any{"jkt": jkt},
	}
}

func baseHeader(kid string) map[string]any {
	return map[string]any{"alg": "ES256", "typ": "vc+jwt", "cty": "vc", "kid": kid}
}

func generateVectors(t *testing.T) vectorFile {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "synthetic-lab-key-1"
	issuerPub := publicJWK(&issuerKey.PublicKey, kid)
	holderPub := publicJWK(&holderKey.PublicKey, "")
	jkt := jwkThumbprint(holderPub)

	valid := func() map[string]any { return credentialPayload(jkt) }
	mutate := func(h map[string]any, fn func(map[string]any)) map[string]any {
		fn(h)
		return h
	}

	validJWS := compact(baseHeader(kid), valid(), issuerKey)
	parts := strings.Split(validJWS, ".")
	tamperedPayload, _ := json.Marshal(mutate(valid(), func(p map[string]any) { p["credentialSubject"] = map[string]any{"label": "tampered"} }))
	noneHeader, _ := json.Marshal(map[string]any{"alg": "none", "typ": "vc+jwt", "kid": kid})
	validPayloadJSON, _ := json.Marshal(valid())

	fail := func(check CheckName, code Code) vectorExpectation {
		return vectorExpectation{TechnicalResult: Invalid, FailedCheck: check, Code: code}
	}
	return vectorFile{
		Synthetic: true,
		Notice:    "SYNTHETIC lab vectors. Generated with ephemeral P-256 keys whose private halves were discarded. They are not evidence of interoperability with any external verifier, wallet or issuer.",
		CodesVer:  CodesVersion,
		Issuer:    vectorIssuer,
		IssuerKeys: map[string]jwk{
			kid: issuerPub,
		},
		HolderKey: holderPub,
		HolderJKT: jkt,
		Vectors: []vector{
			{"v01-valid", "Well-formed vc+jwt signed by the issuer key, inside its validity window.", validJWS, insideWindow, vectorExpectation{TechnicalResult: Valid}},
			{"v02-header-typ-wrong", "Header typ is JWT instead of vc+jwt; signature is otherwise valid.", compact(mutate(baseHeader(kid), func(h map[string]any) { h["typ"] = "JWT" }), valid(), issuerKey), insideWindow, fail(CheckFormat, CodeFormatHeaderTyp)},
			{"v03-header-alg-none", "Header alg is none with an empty signature.", b64(noneHeader) + "." + b64(validPayloadJSON) + ".", insideWindow, fail(CheckFormat, CodeFormatHeaderAlg)},
			{"v04-payload-vc-container", "Payload wraps the credential in a vc claim, which the profile forbids.", compact(baseHeader(kid), map[string]any{"vc": valid()}, issuerKey), insideWindow, fail(CheckFormat, CodeFormatVCContainer)},
			{"v05-header-jku", "Header carries a jku supplied by the credential.", compact(mutate(baseHeader(kid), func(h map[string]any) { h["jku"] = "https://attacker.invalid/jwks.json" }), valid(), issuerKey), insideWindow, fail(CheckIssuerKey, CodeKeyUntrustedHeader)},
			{"v06-signature-tampered", "Payload altered after signing; the signature no longer matches.", parts[0] + "." + b64(tamperedPayload) + "." + parts[2], insideWindow, fail(CheckSignature, CodeSignatureInvalid)},
			{"v07-unknown-kid", "kid is not published by the issuer; signed with the issuer key.", compact(baseHeader("unknown-key"), valid(), issuerKey), insideWindow, fail(CheckIssuerKey, CodeKeyUnknownKID)},
			{"v08-expired", "Valid credential evaluated after validUntil.", validJWS, "2027-06-01T00:00:00Z", fail(CheckValidity, CodeValidityExpired)},
			{"v09-not-yet-valid", "Valid credential evaluated before validFrom.", validJWS, "2025-06-01T00:00:00Z", fail(CheckValidity, CodeValidityNotYetValid)},
		},
		Limitations: []string{
			"The credential uses only the VCDM 2.0 base context. The profile defines cnf through a HukID context that does not exist for this lab type.",
			"No verifiable presentation, status list or schema vectors yet: holder-binding and request-binding vectors arrive with VER-T05.",
			"The issuer URL follows the profile pattern but is not a published issuer.",
		},
		Meta: map[string]string{"generator": "vectors_test.go TestGenerateVectors", "feature": "FEAT-004 VER-T01"},
	}
}

func TestGenerateVectors(t *testing.T) {
	if os.Getenv("HUKID_UPDATE_VECTORS") != "1" {
		t.Skip("set HUKID_UPDATE_VECTORS=1 to regenerate testdata/vectors.json")
	}
	blob, err := json.MarshalIndent(generateVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(vectorsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorsPath, append(blob, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	blob, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with HUKID_UPDATE_VECTORS=1): %v", err)
	}
	var file vectorFile
	if err := json.Unmarshal(blob, &file); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestVectorsAreSyntheticAndCarryNoPrivateMaterial(t *testing.T) {
	blob, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	file := loadVectors(t)
	if !file.Synthetic || !strings.Contains(file.Notice, "SYNTHETIC") || !strings.Contains(file.Notice, "not evidence of interoperability") {
		t.Fatal("vector file must declare itself synthetic and not interoperability evidence")
	}
	var generic any
	if err := json.Unmarshal(blob, &generic); err != nil {
		t.Fatal(err)
	}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if k == "d" || k == "p" || k == "q" {
					t.Fatalf("private JWK member %q present", k)
				}
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(generic)
	if strings.Contains(string(blob), "PRIVATE KEY") {
		t.Fatal("PEM private key material present")
	}
	if file.CodesVer != CodesVersion {
		t.Fatalf("vectors target codesVersion %d, package is %d: regenerate", file.CodesVer, CodesVersion)
	}
}

func TestVectorExpectationsUseTheClosedCodeSet(t *testing.T) {
	file := loadVectors(t)
	if len(file.Vectors) < 9 {
		t.Fatalf("expected the base vector set, got %d", len(file.Vectors))
	}
	ids := map[string]bool{}
	for _, v := range file.Vectors {
		if ids[v.ID] || v.ID == "" || v.Description == "" {
			t.Fatalf("vector %q has a duplicate or missing id/description", v.ID)
		}
		ids[v.ID] = true
		if _, err := time.Parse(time.RFC3339, v.EvaluationTime); err != nil {
			t.Fatalf("%s: evaluationTime: %v", v.ID, err)
		}
		switch v.Expected.TechnicalResult {
		case Valid:
			if v.Expected.Code != "" || v.Expected.FailedCheck != "" {
				t.Fatalf("%s: a valid vector must not name a failure", v.ID)
			}
		case Invalid:
			if !IsKnown(v.Expected.Code) {
				t.Fatalf("%s: code %q is outside the closed set", v.ID, v.Expected.Code)
			}
			// The expected code must belong to the expected failed check.
			func() {
				defer func() {
					if recover() != nil {
						t.Fatalf("%s: code %q does not belong to check %q", v.ID, v.Expected.Code, v.Expected.FailedCheck)
					}
				}()
				Failed(v.Expected.FailedCheck, v.Expected.Code)
			}()
		default:
			t.Fatalf("%s: unknown technicalResult %q", v.ID, v.Expected.TechnicalResult)
		}
	}
}

// TestVectorSignaturesMatchTheirExpectations checks, with an oracle that does
// not use this package's verifier, that signature outcomes are what the
// vector set declares. Format and validity checks arrive with VER-T02/T04.
func TestVectorSignaturesMatchTheirExpectations(t *testing.T) {
	file := loadVectors(t)
	key := file.IssuerKeys["synthetic-lab-key-1"]
	if file.HolderJKT != jwkThumbprint(file.HolderKey) {
		t.Fatal("holder thumbprint does not match the holder public key")
	}
	for _, v := range file.Vectors {
		parts := strings.Split(v.JWS, ".")
		if len(parts) != 3 {
			t.Fatalf("%s: not a compact JWS", v.ID)
		}
		signatureHolds := verifyES256(key, parts[0]+"."+parts[1], parts[2])
		switch v.ID {
		case "v03-header-alg-none":
			if signatureHolds {
				t.Fatalf("%s: an empty signature must not verify", v.ID)
			}
		case "v06-signature-tampered":
			if signatureHolds {
				t.Fatalf("%s: tampered payload must not verify", v.ID)
			}
		default:
			if !signatureHolds {
				t.Fatalf("%s: signature should verify so the declared failure is the only defect", v.ID)
			}
		}
	}
}

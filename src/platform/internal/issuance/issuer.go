package issuance

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"time"
)

const (
	// VCDMBaseContext is the mandatory first @context entry for W3C VCDM 2.0.
	VCDMBaseContext = "https://www.w3.org/ns/credentials/v2"
	// ReceiptContext is the schema context for electronic receipts (profile §4).
	ReceiptContext = "https://schemas.hukid.pe/contexts/cpe/v1"
	// CertificateContext is the schema context for academic/event certificates.
	CertificateContext = "https://schemas.hukid.pe/contexts/certificate/v1"

	// CredentialFormat is the HukID v0 credential format identifier (profile §1).
	CredentialFormat = "application/vc+jwt"

	// ReceiptConfigID and CertificateConfigID identify Phase 0 credential types.
	ReceiptConfigID     = "pe.cpe.receipt.vc-jwt.v1"
	CertificateConfigID = "pe.edu.certificate.vc-jwt.v1"

	// ReceiptType and CertificateType are the specialized VC type names.
	ReceiptType     = "ElectronicReceiptCredential"
	CertificateType = "AttendanceCertificateCredential"
)

var (
	// ErrInvalidCredentialInput indicates malformed or incomplete credential input.
	ErrInvalidCredentialInput = errors.New("invalid credential input")
)

// CredentialInput contains the domain payload used to mint a vc+jwt credential.
type CredentialInput struct {
	ID                string
	Contexts          []string
	Types             []string
	ValidFrom         time.Time
	ValidUntil        *time.Time
	CredentialSubject map[string]any
}

// NewReceiptInput builds a Phase 0 electronic receipt credential input.
func NewReceiptInput(id string, validFrom time.Time, validUntil *time.Time, claims map[string]any) (CredentialInput, error) {
	return newTypedInput(id, ReceiptContext, ReceiptType, validFrom, validUntil, claims)
}

// NewCertificateInput builds a Phase 0 event/academic certificate credential input.
func NewCertificateInput(id string, validFrom time.Time, validUntil *time.Time, claims map[string]any) (CredentialInput, error) {
	return newTypedInput(id, CertificateContext, CertificateType, validFrom, validUntil, claims)
}

func newTypedInput(id, extraContext, specificType string, validFrom time.Time, validUntil *time.Time, claims map[string]any) (CredentialInput, error) {
	if validFrom.IsZero() || len(claims) == 0 {
		return CredentialInput{}, ErrInvalidCredentialInput
	}
	if validUntil != nil && !validFrom.UTC().Before(validUntil.UTC()) {
		return CredentialInput{}, ErrInvalidCredentialInput
	}
	claimsCopy := make(map[string]any, len(claims))
	maps.Copy(claimsCopy, claims)
	var untilCopy *time.Time
	if validUntil != nil {
		u := validUntil.UTC()
		untilCopy = &u
	}
	return CredentialInput{
		ID:                id,
		Contexts:          []string{VCDMBaseContext, extraContext},
		Types:             []string{"VerifiableCredential", specificType},
		ValidFrom:         validFrom.UTC(),
		ValidUntil:        untilCopy,
		CredentialSubject: claimsCopy,
	}, nil
}

// IssueVCJWT constructs a VCDM 2.0 direct JSON payload (no "vc" wrapper, no
// duplicate JWT claims), binds holderJKT into cnf.jkt, and signs it as a
// compact ES256 vc+jwt using signer (profile §2 and §4.1).
func IssueVCJWT(signer Signer, input CredentialInput, holderJKT string) (string, error) {
	if signer == nil || strings.TrimSpace(holderJKT) == "" {
		return "", ErrInvalidCredentialInput
	}
	if err := validateCredentialInput(input); err != nil {
		return "", err
	}

	header := map[string]any{
		"alg": "ES256",
		"typ": "vc+jwt",
		"cty": "vc",
		"kid": signer.KeyID(),
	}

	subjectCopy := make(map[string]any, len(input.CredentialSubject))
	maps.Copy(subjectCopy, input.CredentialSubject)

	payload := map[string]any{
		"@context":          append([]string(nil), input.Contexts...),
		"type":              append([]string(nil), input.Types...),
		"issuer":            signer.Issuer(),
		"validFrom":         input.ValidFrom.UTC().Format(time.RFC3339),
		"credentialSubject": subjectCopy,
		"cnf": map[string]any{
			"jkt": holderJKT,
		},
	}
	if strings.TrimSpace(input.ID) != "" {
		payload["id"] = input.ID
	}
	if input.ValidUntil != nil {
		payload["validUntil"] = input.ValidUntil.UTC().Format(time.RFC3339)
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", ErrInvalidCredentialInput
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", ErrInvalidCredentialInput
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig, err := signer.Sign(signingInput)
	if err != nil {
		return "", err
	}
	if len(sig) != 64 {
		return "", ErrSigningFailed
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func validateCredentialInput(input CredentialInput) error {
	if input.ValidFrom.IsZero() || len(input.CredentialSubject) == 0 {
		return ErrInvalidCredentialInput
	}
	if input.ValidUntil != nil && !input.ValidFrom.UTC().Before(input.ValidUntil.UTC()) {
		return ErrInvalidCredentialInput
	}
	if len(input.Contexts) == 0 || input.Contexts[0] != VCDMBaseContext {
		return ErrInvalidCredentialInput
	}
	for _, ctx := range input.Contexts {
		if strings.TrimSpace(ctx) == "" {
			return ErrInvalidCredentialInput
		}
	}
	hasBaseType := false
	specificTypes := 0
	for _, t := range input.Types {
		if strings.TrimSpace(t) == "" {
			return ErrInvalidCredentialInput
		}
		if t == "VerifiableCredential" {
			hasBaseType = true
		} else {
			specificTypes++
		}
	}
	if !hasBaseType || specificTypes == 0 {
		return ErrInvalidCredentialInput
	}
	return nil
}

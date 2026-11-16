package issuance

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func sampleCertificateDefinition(tenantID, issuerID string) Definition {
	return Definition{
		TenantID:        tenantID,
		IssuerID:        issuerID,
		ID:              "unas-certificate",
		Version:         "1.0.0",
		ConfigurationID: CertificateConfigID,
		DisplayName:     "Certificado de Asistencia UNAS",
		Locale:          "es-PE",
		Contexts:        []string{CertificateContext},
		Types:           []string{CertificateType},
		DefaultValidity: 180 * 24 * time.Hour,
		Fields: map[string]FieldSpec{
			"participantName": {Type: "string", Required: true, MaxLength: 120},
			"eventName":       {Type: "string", Required: true, MaxLength: 160},
			"hours":           {Type: "number", Required: false},
			"passed":          {Type: "boolean", Required: false},
			"metadata": {
				Type: "object",
				Fields: map[string]FieldSpec{
					"campus": {Type: "string", Required: true, MaxLength: 60},
				},
			},
		},
	}
}

func TestDefinitionLifecycleAndImmutability(t *testing.T) {
	now := time.Date(2026, 11, 16, 18, 30, 0, 0, time.UTC)
	audit := NewAuditLog(nil)
	reg := NewDefinitionRegistry(audit)

	def := sampleCertificateDefinition("tenant-unas", "iss_unas")
	if err := reg.CreateDraft(def, "admin-1", "cor-1", now); err != nil {
		t.Fatalf("create draft: %v", err)
	}

	// Draft cannot issue credentials yet.
	if _, err := reg.GetIssuable("tenant-unas", "iss_unas", "unas-certificate", "1.0.0"); !errors.Is(err, ErrDefinitionUnavailable) {
		t.Fatalf("expected ErrDefinitionUnavailable for draft, got %v", err)
	}

	// Duplicate draft or duplicate configurationId within same issuer is rejected.
	if err := reg.CreateDraft(def, "admin-1", "cor-2", now); !errors.Is(err, ErrDefinitionConflict) {
		t.Fatalf("expected ErrDefinitionConflict for duplicate id/version, got %v", err)
	}
	otherID := def
	otherID.ID = "other-cert"
	if err := reg.CreateDraft(otherID, "admin-1", "cor-3", now); !errors.Is(err, ErrDefinitionConflict) {
		t.Fatalf("expected ErrDefinitionConflict for duplicate configurationId, got %v", err)
	}

	// Draft can be replaced before publishing.
	def.DisplayName = "Certificado Oficial IncubaUNAS"
	if err := reg.ReplaceDraft(def, "admin-1", "cor-4", now.Add(time.Minute)); err != nil {
		t.Fatalf("replace draft: %v", err)
	}

	// Publish freezes the definition and computes its deterministic hash.
	pub, err := reg.Publish("tenant-unas", "iss_unas", "unas-certificate", "1.0.0", "admin-1", "cor-5", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if pub.State != DefinitionPublished || len(pub.Hash) != 64 || pub.PublishedAt == nil {
		t.Fatalf("unexpected published definition: %+v", pub)
	}

	// Once published, ReplaceDraft and re-Publish are rejected as immutable.
	def.DisplayName = "Mutated After Publish"
	if err := reg.ReplaceDraft(def, "admin-1", "cor-6", now.Add(3*time.Minute)); !errors.Is(err, ErrDefinitionImmutable) {
		t.Fatalf("expected ErrDefinitionImmutable on ReplaceDraft, got %v", err)
	}
	if _, err := reg.Publish("tenant-unas", "iss_unas", "unas-certificate", "1.0.0", "admin-1", "cor-7", now.Add(3*time.Minute)); !errors.Is(err, ErrDefinitionImmutable) {
		t.Fatalf("expected ErrDefinitionImmutable on double Publish, got %v", err)
	}

	// Fix or evolution requires a new SemVer version + distinct configurationId.
	v2 := sampleCertificateDefinition("tenant-unas", "iss_unas")
	v2.Version = "1.1.0"
	v2.ConfigurationID = "pe.edu.certificate.vc-jwt.v2"
	if err := reg.CreateDraft(v2, "admin-1", "cor-8", now.Add(4*time.Minute)); err != nil {
		t.Fatalf("create v2 draft: %v", err)
	}
	if _, err := reg.Publish("tenant-unas", "iss_unas", "unas-certificate", "1.1.0", "admin-1", "cor-9", now.Add(5*time.Minute)); err != nil {
		t.Fatalf("publish v2: %v", err)
	}
	list := reg.ListPublished("tenant-unas", "iss_unas")
	if len(list) != 2 || list[0].Ref() != "unas-certificate@1.0.0" || list[1].Ref() != "unas-certificate@1.1.0" {
		t.Fatalf("unexpected published list: %+v", list)
	}

	// Cross-tenant isolation: another tenant cannot see or modify this definition.
	if _, err := reg.Get("tenant-other", "iss_unas", "unas-certificate", "1.0.0"); !errors.Is(err, ErrDefinitionNotFound) {
		t.Fatalf("expected ErrDefinitionNotFound cross-tenant, got %v", err)
	}

	// Retiring v1.0.0 stops new issuance from v1.0.0 and cannot be mutated back.
	if err := reg.Retire("tenant-unas", "iss_unas", "unas-certificate", "1.0.0", "admin-1", "cor-10", now.Add(6*time.Minute)); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if _, err := reg.GetIssuable("tenant-unas", "iss_unas", "unas-certificate", "1.0.0"); !errors.Is(err, ErrDefinitionUnavailable) {
		t.Fatalf("expected ErrDefinitionUnavailable after retire, got %v", err)
	}
	if err := reg.Retire("tenant-unas", "iss_unas", "unas-certificate", "1.0.0", "admin-1", "cor-11", now.Add(7*time.Minute)); !errors.Is(err, ErrDefinitionImmutable) {
		t.Fatalf("expected ErrDefinitionImmutable on double retire, got %v", err)
	}
}

func TestDefinitionClaimValidationAndRefs(t *testing.T) {
	def := sampleCertificateDefinition("tenant-unas", "iss_unas")

	valid := map[string]any{
		"participantName": "Juan Perez",
		"eventName":       "Demo Day 2026",
		"hours":           8,
		"passed":          true,
		"metadata":        map[string]any{"campus": "Tingo Maria"},
	}
	if err := def.ValidateClaims(valid); err != nil {
		t.Fatalf("expected valid claims to pass, got %v", err)
	}

	bad := map[string]any{
		"participantName": "   ",
		"eventName":       strings.Repeat("x", 200),
		"hours":           "eight",
		"passed":          "yes",
		"extra":           "forbidden",
		"metadata":        map[string]any{},
	}
	err := def.ValidateClaims(bad)
	var claimErr *ClaimValidationError
	if !errors.As(err, &claimErr) || len(claimErr.Errors) < 5 {
		t.Fatalf("expected ClaimValidationError with multiple field errors, got %v", err)
	}
	// Ensure no claim values leak into error structs.
	for _, fe := range claimErr.Errors {
		if strings.Contains(fe.Path+fe.Code, "eight") || strings.Contains(fe.Path+fe.Code, "forbidden") {
			t.Fatalf("error leaked claim value: %+v", fe)
		}
	}

	id, ver, err := ParseDefinitionRef("unas-certificate@1.0.0")
	if err != nil || id != "unas-certificate" || ver != "1.0.0" {
		t.Fatalf("unexpected ParseDefinitionRef result: %q %q %v", id, ver, err)
	}
	for _, invalid := range []string{"", "unas-certificate", "unas@1.0", "UNAS@1.0.0", "unas@v1.0.0"} {
		if _, _, err := ParseDefinitionRef(invalid); !errors.Is(err, ErrDefinitionNotFound) {
			t.Errorf("expected ErrDefinitionNotFound for %q, got %v", invalid, err)
		}
	}
}

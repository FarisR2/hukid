package issuance

import (
	"strings"
	"time"
)

const (
	// CanonicalEventParticipationDefID identifies the product Event Participation Certificate definition (ISS-T07).
	CanonicalEventParticipationDefID = "event-participation-certificate"
	// CanonicalEventParticipationVersion is the initial immutable semantic version of the canonical certificate.
	CanonicalEventParticipationVersion = "1.0.0"
	// CanonicalEventParticipationConfigID is the OID4VCI credential_configuration_id advertised by issuers.
	CanonicalEventParticipationConfigID = "pe.hukid.events.participation-certificate.v1"
	// CanonicalEventParticipationType is the W3C VC type for event participation certificates.
	CanonicalEventParticipationType = "EventParticipationCertificate"
)

// CanonicalEventParticipationDefinition builds the canonical Event Participation
// Certificate definition (ISS-T07) aligned with VER-T09 validity/status rules and
// VER-T13 JSON Schema publication for a given tenant issuer.
func CanonicalEventParticipationDefinition(tenantID, issuerID, issuerURI string) Definition {
	base := strings.TrimRight(issuerURI, "/")
	contextURL := base + "/contexts/" + CanonicalEventParticipationDefID + "/" + CanonicalEventParticipationVersion + ".jsonld"
	return Definition{
		TenantID:        tenantID,
		IssuerID:        issuerID,
		ID:              CanonicalEventParticipationDefID,
		Version:         CanonicalEventParticipationVersion,
		ConfigurationID: CanonicalEventParticipationConfigID,
		DisplayName:     "Certificado de Participación en Evento",
		Locale:          "es-PE",
		Contexts:        []string{contextURL},
		Types:           []string{CanonicalEventParticipationType},
		DefaultValidity: DefaultCredentialValidity,
		StatusPurposes:  []string{PurposeRevocation, PurposeSuspension},
		PublishSchema:   true,
		Fields: map[string]FieldSpec{
			"participantName":   {Type: "string", Required: true, MaxLength: 160},
			"eventTitle":        {Type: "string", Required: true, MaxLength: 200},
			"organizerName":     {Type: "string", Required: true, MaxLength: 160},
			"eventDate":         {Type: "string", Required: true, MaxLength: 32},
			"participationRole": {Type: "string", Required: true, MaxLength: 64},
			"certificateNumber": {Type: "string", Required: true, MaxLength: 64},
		},
	}
}

// CanonicalEventParticipationRef returns the "id@version" reference used in issuance requests.
func CanonicalEventParticipationRef() string {
	return CanonicalEventParticipationDefID + "@" + CanonicalEventParticipationVersion
}

// CanonicalDefaultValiditySeconds returns the default validity in seconds used by canonical definitions.
func CanonicalDefaultValiditySeconds() int64 {
	return int64(DefaultCredentialValidity / time.Second)
}

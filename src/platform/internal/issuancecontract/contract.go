// Package issuancecontract defines only the synthetic wallet laboratory data model.
// Validation is not signature, trust, time-window, proof or revocation verification.
package issuancecontract

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const ConfigurationID = "lab.workshop.vc-jwt.v1"

var (
	ErrOrigin     = errors.New("issuancecontract: invalid laboratory origin")
	ErrCredential = errors.New("issuancecontract: invalid laboratory credential")
	identifier    = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	//go:embed fixtures/subject-schema-v1.json
	schemaTemplate string
	//go:embed fixtures/context-v1.json
	contextTemplate string
)

// Definition is configured by the operator, never derived from an offered VC.
type Definition struct{ origin string }

type Subject struct {
	Demo          bool   `json:"demo"`
	Workshop      string `json:"workshop"`
	Participation string `json:"participation"`
}

type Confirmation struct {
	JKT string `json:"jkt"`
}

// Credential is a direct VCDM payload, not a JWT wrapper or an issuance proof.
// Fixed arrays and value-only fields prevent shared mutable caller state.
type Credential struct {
	Context   [2]string    `json:"@context"`
	ID        string       `json:"id"`
	Type      [2]string    `json:"type"`
	Issuer    string       `json:"issuer"`
	ValidFrom string       `json:"validFrom"`
	CNF       Confirmation `json:"cnf"`
	Subject   Subject      `json:"credentialSubject"`
}

// New accepts a bare HTTPS origin; it performs no DNS or certificate validation.
func New(origin string) (Definition, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" ||
		u.String() != origin || strings.HasSuffix(u.Host, ":") || strings.ContainsAny(origin, `"<>\`) {
		return Definition{}, ErrOrigin
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return Definition{}, ErrOrigin
		}
	}
	return Definition{origin: origin}, nil
}

func (d Definition) Issuer() string { return d.origin + "/wallet-lab" }

// Schema describes ONLY credentialSubject, not the full VC JSON Schema profile.
func (d Definition) Schema() []byte {
	return []byte(strings.ReplaceAll(schemaTemplate, "{issuer}", d.Issuer()))
}

// Context returns the pinned local vocabulary; no remote context is fetched.
func (d Definition) Context() []byte {
	return []byte(strings.ReplaceAll(contextTemplate, "{issuer}", d.Issuer()))
}

func (d Definition) subject() Subject {
	var schema struct {
		Const Subject `json:"const"`
	}
	// Embedded release artifact, exercised by TestOfflineArtifacts.
	if err := json.Unmarshal(d.Schema(), &schema); err != nil {
		panic("issuancecontract: invalid embedded subject schema")
	}
	return schema.Const
}

// Example is unsigned synthetic data, not a credential for storage or a real key.
// T3 must replace ID, validFrom and cnf.jkt after validating the holder proof.
func (d Definition) Example() Credential {
	return Credential{
		Context:   [2]string{"https://www.w3.org/ns/credentials/v2", d.Issuer() + "/contexts/workshop/v1"},
		ID:        d.Issuer() + "/credentials/demo-1",
		Type:      [2]string{"VerifiableCredential", "DemoWorkshopCredential"},
		Issuer:    d.Issuer(),
		ValidFrom: "2026-01-01T00:00:00Z",
		CNF:       Confirmation{JKT: base64.RawURLEncoding.EncodeToString(make([]byte, 32))},
		Subject:   d.subject(),
	}
}

// Validate checks the closed typed shape and the registered subject-schema const.
// It neither decodes untrusted JSON nor establishes who controls cnf.jkt.
func (d Definition) Validate(c Credential) error {
	if d.origin == "" {
		return ErrCredential
	}
	expected := d.Example()
	suffix, ok := strings.CutPrefix(c.ID, d.Issuer()+"/credentials/")
	at, timeErr := time.Parse(time.RFC3339, c.ValidFrom)
	jkt, keyErr := base64.RawURLEncoding.Strict().DecodeString(c.CNF.JKT)
	if !ok || !identifier.MatchString(suffix) || c.Issuer != expected.Issuer ||
		c.Context != expected.Context || c.Type != expected.Type || c.Subject != expected.Subject ||
		timeErr != nil || at.Format(time.RFC3339) != c.ValidFrom || !strings.HasSuffix(c.ValidFrom, "Z") ||
		keyErr != nil || len(jkt) != 32 {
		return ErrCredential
	}
	return nil
}

package issuancecontract_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"hukid.local/platform/internal/issuancecontract"
)

const origin = "https://wallet-lab.example:8443"

func TestOrigins(t *testing.T) {
	for _, input := range []string{"http://lab.example", "https://", "https://user@lab.example", "https://lab.example/", "https://lab.example/path", "https://lab.example?x=1", "https://lab.example#x", "https://lab.example:0", "https://lab.example:65536", "https://lab.example:"} {
		t.Run(input, func(t *testing.T) {
			_, err := issuancecontract.New(input)
			if !errors.Is(err, issuancecontract.ErrOrigin) {
				t.Fatalf("got %v, want ErrOrigin", err)
			}
		})
	}
	for _, input := range []string{"https://lab.example", "https://lab.example:1", "https://lab.example:65535"} {
		d, err := issuancecontract.New(input)
		if err != nil || d.Issuer() != input+"/wallet-lab" {
			t.Fatalf("valid origin rejected: %v", err)
		}
	}
}

func TestCredentialContract(t *testing.T) {
	d, err := issuancecontract.New(origin)
	if err != nil {
		t.Fatal(err)
	}
	valid := d.Example()
	if err := d.Validate(valid); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		edit func(*issuancecontract.Credential)
	}{
		{"context", func(c *issuancecontract.Credential) { c.Context[1] = "https://untrusted.example/context" }},
		{"base context", func(c *issuancecontract.Credential) { c.Context[0] = "https://www.w3.org/2018/credentials/v1" }},
		{"type", func(c *issuancecontract.Credential) { c.Type[1] = "AcademicCredential" }},
		{"issuer", func(c *issuancecontract.Credential) { c.Issuer = "https://other.example/wallet-lab" }},
		{"id origin", func(c *issuancecontract.Credential) { c.ID = "https://other.example/credentials/1" }},
		{"id empty", func(c *issuancecontract.Credential) { c.ID = d.Issuer() + "/credentials/" }},
		{"id traversal", func(c *issuancecontract.Credential) { c.ID = d.Issuer() + "/credentials/../key" }},
		{"id too long", func(c *issuancecontract.Credential) { c.ID = d.Issuer() + "/credentials/" + strings.Repeat("a", 65) }},
		{"time", func(c *issuancecontract.Credential) { c.ValidFrom = "yesterday" }},
		{"time zone", func(c *issuancecontract.Credential) { c.ValidFrom = "2026-01-01T00:00:00+01:00" }},
		{"binding absent", func(c *issuancecontract.Credential) { c.CNF.JKT = "" }},
		{"binding short", func(c *issuancecontract.Credential) { c.CNF.JKT = "AA" }},
		{"binding encoding", func(c *issuancecontract.Credential) { c.CNF.JKT = strings.Repeat("/", 43) }},
		{"not demo", func(c *issuancecontract.Credential) { c.Subject.Demo = false }},
		{"workshop", func(c *issuancecontract.Credential) { c.Subject.Workshop = "Real qualification" }},
		{"participation", func(c *issuancecontract.Credential) { c.Subject.Participation = "certified" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := valid
			tc.edit(&input)
			before := input
			if err := d.Validate(input); !errors.Is(err, issuancecontract.ErrCredential) {
				t.Fatalf("got %v, want ErrCredential", err)
			}
			if !reflect.DeepEqual(input, before) {
				t.Fatal("rejection mutated caller input")
			}
		})
	}
	for _, suffix := range []string{"a", strings.Repeat("a", 64)} {
		c := valid
		c.ID = d.Issuer() + "/credentials/" + suffix
		c.ValidFrom = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
		if err := d.Validate(c); err != nil {
			t.Fatalf("shape validation must not claim current validity: %v", err)
		}
	}
	if err := (issuancecontract.Definition{}).Validate(valid); !errors.Is(err, issuancecontract.ErrCredential) {
		t.Fatalf("zero definition accepted: %v", err)
	}
}

func TestOfflineArtifacts(t *testing.T) {
	d, _ := issuancecontract.New(origin)
	var schema struct {
		ID    string                   `json:"$id"`
		Const issuancecontract.Subject `json:"const"`
	}
	if err := json.Unmarshal(d.Schema(), &schema); err != nil {
		t.Fatal(err)
	}
	if schema.ID != d.Issuer()+"/schemas/workshop/v1" || schema.Const != (issuancecontract.Subject{Demo: true, Workshop: "Taller ficticio de wallet", Participation: "simulated"}) {
		t.Fatal("schema fixture and typed validation disagree")
	}
	var context map[string]map[string]any
	if err := json.Unmarshal(d.Context(), &context); err != nil {
		t.Fatal(err)
	}
	for _, term := range []string{"DemoWorkshopCredential", "demo", "workshop", "participation", "cnf", "jkt"} {
		if context["@context"][term] != d.Issuer()+"/vocabulary/v1#"+term {
			t.Fatalf("context mapping missing for %s", term)
		}
	}
	encoded, _ := json.Marshal(d.Example())
	for _, forbidden := range []string{"credentialStatus", "credentialSchema", "\"vc\"", "\"sub\"", "\"iss\"", "\"nbf\""} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("unexpected claim %s", forbidden)
		}
	}
	d.Schema()[0] = '!'
	if !json.Valid(d.Schema()) {
		t.Fatal("artifact returned shared mutable bytes")
	}
}

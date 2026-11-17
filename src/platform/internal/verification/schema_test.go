package verification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
)

type mapSchemaResolver struct {
	docs map[string][]byte
	err  error
}

func (m mapSchemaResolver) ResolveSchema(url string) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	doc, ok := m.docs[url]
	if !ok {
		return nil, errors.New("schema not found")
	}
	return doc, nil
}

func TestVerifierChecksCredentialSchema(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://issuer.example/unas"
	kid := "unas-k1"
	schemaURL := issuer + "/schemas/unas-certificate/1.0.0.json"
	now := at(t, insideWindow)
	keys := NewMemoryKeyResolver()
	if err := keys.Add(issuer, kid, &key.PublicKey); err != nil {
		t.Fatal(err)
	}

	schemaDoc := []byte(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["participantName", "hours"],
	  "properties": {
	    "participantName": {"type": "string", "minLength": 2, "maxLength": 120},
	    "hours": {"type": "integer", "minimum": 1, "maximum": 200},
	    "passed": {"type": "boolean"},
	    "metadata": {
	      "type": "object",
	      "additionalProperties": false,
	      "required": ["campus"],
	      "properties": {
	        "campus": {"type": "string", "minLength": 2, "maxLength": 60}
	      }
	    }
	  }
	}`)

	signCred := func(subject map[string]any, credSchema any) string {
		p := credentialPayload("holder-jkt-123")
		p["issuer"] = issuer
		p["credentialSubject"] = subject
		if credSchema != nil {
			p["credentialSchema"] = credSchema
		}
		return compact(baseHeader(kid), p, key)
	}

	validVC := signCred(map[string]any{
		"participantName": "Ana Gomez",
		"hours":           12,
		"passed":          true,
		"metadata":        map[string]any{"campus": "Tingo Maria"},
	}, map[string]any{"id": schemaURL, "type": "JsonSchema"})

	v := func(r SchemaResolver) *Verifier {
		base, err := NewVerifier(keys, fixedClock(now), DefaultLimits, 0)
		if err != nil {
			t.Fatal(err)
		}
		if r != nil {
			base = base.WithSchemaResolver(r)
		}
		return base
	}

	// Valid subject against valid JsonSchema passes.
	okReport, err := v(mapSchemaResolver{docs: map[string][]byte{schemaURL: schemaDoc}}).Verify(validVC)
	if err != nil || okReport.TechnicalResult != Valid {
		t.Fatalf("expected Valid with matching schema, got %+v err=%v", okReport, err)
	}

	// Missing SchemaResolver still fails closed with skipped.not_implemented.
	noResolverReport, err := v(nil).Verify(validVC)
	if err != nil || noResolverReport.TechnicalResult != Invalid {
		t.Fatalf("expected Invalid without SchemaResolver, got %+v err=%v", noResolverReport, err)
	}

	// Resolver failure returns ErrSchemaResolution without a report.
	if _, err := v(mapSchemaResolver{err: errors.New("network")}).Verify(validVC); !errors.Is(err, ErrSchemaResolution) {
		t.Fatalf("expected ErrSchemaResolution, got %v", err)
	}

	cases := []struct {
		name     string
		vc       string
		doc      []byte
		wantCode Code
	}{
		{
			name:     "missing required field",
			vc:       signCred(map[string]any{"hours": 12}, map[string]any{"id": schemaURL, "type": "JsonSchema"}),
			doc:      schemaDoc,
			wantCode: CodeSchemaMismatch,
		},
		{
			name:     "unknown additional property rejected",
			vc:       signCred(map[string]any{"participantName": "Ana", "hours": 12, "extra": "x"}, map[string]any{"id": schemaURL, "type": "JsonSchema"}),
			doc:      schemaDoc,
			wantCode: CodeSchemaMismatch,
		},
		{
			name:     "non-integer hours rejected",
			vc:       signCred(map[string]any{"participantName": "Ana", "hours": 12.5}, map[string]any{"id": schemaURL, "type": "JsonSchema"}),
			doc:      schemaDoc,
			wantCode: CodeSchemaMismatch,
		},
		{
			name:     "nested object constraint violated",
			vc:       signCred(map[string]any{"participantName": "Ana", "hours": 12, "metadata": map[string]any{}}, map[string]any{"id": schemaURL, "type": "JsonSchema"}),
			doc:      schemaDoc,
			wantCode: CodeSchemaMismatch,
		},
		{
			name:     "unsupported schema type rejected as schema.invalid",
			vc:       signCred(map[string]any{"participantName": "Ana", "hours": 12}, map[string]any{"id": schemaURL, "type": "ShaclValidator"}),
			doc:      schemaDoc,
			wantCode: CodeSchemaInvalid,
		},
		{
			name:     "malformed fetched schema rejected as schema.invalid",
			vc:       validVC,
			doc:      []byte(`{"type":"string"}`),
			wantCode: CodeSchemaInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := v(mapSchemaResolver{docs: map[string][]byte{schemaURL: tc.doc}}).Verify(tc.vc)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if report.TechnicalResult != Invalid {
				t.Fatalf("expected Invalid, got %+v", report)
			}
			failed, ok := failedCheck(report)
			if !ok || failed.Name != CheckSchema || failed.Code != tc.wantCode {
				t.Fatalf("expected %s failure, got failed=%+v ok=%v", tc.wantCode, failed, ok)
			}
		})
	}
}

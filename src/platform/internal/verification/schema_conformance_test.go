package verification

import (
	"testing"
)

func TestVER_T13JSONSchemaDraftConformance(t *testing.T) {
	const draft2020Schema = `{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$id": "https://unas.example/schemas/certificate/1.0.0.json",
		"type": "object",
		"additionalProperties": false,
		"required": ["id", "email", "issuedDate", "issuedAt", "portal", "code", "hours", "tags", "version"],
		"properties": {
			"id": {"type": "string", "format": "uuid"},
			"email": {"type": "string", "format": "email"},
			"issuedDate": {"type": "string", "format": "date"},
			"issuedAt": {"type": "string", "format": "date-time"},
			"portal": {"type": "string", "format": "uri"},
			"code": {"type": "string", "pattern": "^UNAS-[0-9]{4}$"},
			"hours": {"type": "integer", "exclusiveMinimum": 0, "exclusiveMaximum": 500},
			"tags": {"type": "array", "minItems": 1, "maxItems": 3, "uniqueItems": true, "items": {"type": "string"}},
			"version": {"const": "v1"},
			"badge": {
				"oneOf": [
					{"type": "string", "minLength": 2},
					{"type": "integer", "minimum": 1}
				]
			}
		}
	}`

	doc, ok := parseJSONSchemaDoc([]byte(draft2020Schema))
	if !ok {
		t.Fatal("expected Draft 2020-12 conformance schema to parse")
	}

	validSubject, ok := decodeJSONSubject([]byte(`{
		"id": "550e8400-e29b-41d4-a716-446655440000",
		"email": "alumno@unas.edu.pe",
		"issuedDate": "2026-11-17",
		"issuedAt": "2026-11-17T21:30:00Z",
		"portal": "https://eventos.unas.edu.pe/cert/123",
		"code": "UNAS-2026",
		"hours": 12,
		"tags": ["cloud", "ssi"],
		"version": "v1",
		"badge": "gold"
	}`))
	if !ok || !validateAgainstSchema(doc, validSubject) {
		t.Fatal("expected valid Draft 2020-12 subject to pass")
	}

	invalidCases := []struct {
		name string
		json string
	}{
		{"bad_uuid", `{"id":"not-uuid","email":"a@b.pe","issuedDate":"2026-11-17","issuedAt":"2026-11-17T21:30:00Z","portal":"https://e.pe/1","code":"UNAS-2026","hours":1,"tags":["a"],"version":"v1"}`},
		{"bad_email", `{"id":"550e8400-e29b-41d4-a716-446655440000","email":"Alumno <a@b.pe>","issuedDate":"2026-11-17","issuedAt":"2026-11-17T21:30:00Z","portal":"https://e.pe/1","code":"UNAS-2026","hours":1,"tags":["a"],"version":"v1"}`},
		{"bad_date", `{"id":"550e8400-e29b-41d4-a716-446655440000","email":"a@b.pe","issuedDate":"17-11-2026","issuedAt":"2026-11-17T21:30:00Z","portal":"https://e.pe/1","code":"UNAS-2026","hours":1,"tags":["a"],"version":"v1"}`},
		{"bad_datetime", `{"id":"550e8400-e29b-41d4-a716-446655440000","email":"a@b.pe","issuedDate":"2026-11-17","issuedAt":"2026-11-17","portal":"https://e.pe/1","code":"UNAS-2026","hours":1,"tags":["a"],"version":"v1"}`},
		{"bad_uri", `{"id":"550e8400-e29b-41d4-a716-446655440000","email":"a@b.pe","issuedDate":"2026-11-17","issuedAt":"2026-11-17T21:30:00Z","portal":"/relative","code":"UNAS-2026","hours":1,"tags":["a"],"version":"v1"}`},
		{"bad_pattern", `{"id":"550e8400-e29b-41d4-a716-446655440000","email":"a@b.pe","issuedDate":"2026-11-17","issuedAt":"2026-11-17T21:30:00Z","portal":"https://e.pe/1","code":"BAD-2026","hours":1,"tags":["a"],"version":"v1"}`},
		{"exclusive_min_fail", `{"id":"550e8400-e29b-41d4-a716-446655440000","email":"a@b.pe","issuedDate":"2026-11-17","issuedAt":"2026-11-17T21:30:00Z","portal":"https://e.pe/1","code":"UNAS-2026","hours":0,"tags":["a"],"version":"v1"}`},
		{"non_unique_items", `{"id":"550e8400-e29b-41d4-a716-446655440000","email":"a@b.pe","issuedDate":"2026-11-17","issuedAt":"2026-11-17T21:30:00Z","portal":"https://e.pe/1","code":"UNAS-2026","hours":1,"tags":["a","a"],"version":"v1"}`},
		{"const_mismatch", `{"id":"550e8400-e29b-41d4-a716-446655440000","email":"a@b.pe","issuedDate":"2026-11-17","issuedAt":"2026-11-17T21:30:00Z","portal":"https://e.pe/1","code":"UNAS-2026","hours":1,"tags":["a"],"version":"v2"}`},
		{"oneof_fail", `{"id":"550e8400-e29b-41d4-a716-446655440000","email":"a@b.pe","issuedDate":"2026-11-17","issuedAt":"2026-11-17T21:30:00Z","portal":"https://e.pe/1","code":"UNAS-2026","hours":1,"tags":["a"],"version":"v1","badge":true}`},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			subj, ok := decodeJSONSubject([]byte(tc.json))
			if !ok {
				t.Fatalf("failed to decode test subject %s", tc.name)
			}
			if validateAgainstSchema(doc, subj) {
				t.Fatalf("expected %s to fail schema conformance", tc.name)
			}
		})
	}

	if _, ok := parseJSONSchemaDoc([]byte(`{"$schema":"https://evil.example/unknown-draft","type":"object"}`)); ok {
		t.Fatal("unsupported $schema dialect must be rejected")
	}
	if _, ok := parseJSONSchemaDoc([]byte(`{"type":"object","properties":{"x":{"type":"string","pattern":"[invalid"}}}`)); ok {
		t.Fatal("invalid regex pattern must be rejected")
	}
}

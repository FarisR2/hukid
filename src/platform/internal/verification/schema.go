package verification

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ErrSchemaResolution wraps a failure of the SchemaResolver port without
// exposing credential claims or payload values.
var ErrSchemaResolution = errors.New("schema resolution failed")

// SchemaResolver fetches a JSON Schema document bytes by credentialSchema.id URL.
// It is a pure port; HTTP(S) transport and host rules live in the adapter.
type SchemaResolver interface {
	ResolveSchema(schemaURL string) ([]byte, error)
}

// CredentialSchemaType is the W3C VCDM 2.0 JsonSchema validator identifier.
const CredentialSchemaType = "JsonSchema"

type rawSchemaEntry struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

func parseCredentialSchemaEntries(raw json.RawMessage) ([]rawSchemaEntry, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, false
	}
	if trimmed[0] == '[' {
		var entries []rawSchemaEntry
		if json.Unmarshal(trimmed, &entries) != nil || len(entries) == 0 {
			return nil, false
		}
		return entries, true
	}
	if trimmed[0] == '{' {
		var single rawSchemaEntry
		if json.Unmarshal(trimmed, &single) != nil {
			return nil, false
		}
		return []rawSchemaEntry{single}, true
	}
	return nil, false
}

type jsonSchemaNode struct {
	Type                 string                     `json:"type"`
	Properties           map[string]*jsonSchemaNode `json:"properties"`
	Required             []string                   `json:"required"`
	AdditionalProperties *bool                      `json:"additionalProperties"`
	MinLength            *int                       `json:"minLength"`
	MaxLength            *int                       `json:"maxLength"`
	Minimum              *float64                   `json:"minimum"`
	Maximum              *float64                   `json:"maximum"`
	Enum                 []any                      `json:"enum"`
	Items                *jsonSchemaNode            `json:"items"`
}

func parseJSONSchemaDoc(raw []byte) (*jsonSchemaNode, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var doc jsonSchemaNode
	if dec.Decode(&doc) != nil {
		return nil, false
	}
	var trailing any
	if dec.Decode(&trailing) == nil {
		return nil, false
	}
	if !validateSchemaNodeShape(&doc) || doc.Type != "object" {
		return nil, false
	}
	return &doc, true
}

func validateSchemaNodeShape(node *jsonSchemaNode) bool {
	if node == nil {
		return false
	}
	switch node.Type {
	case "string", "number", "integer", "boolean", "object", "array":
	default:
		return false
	}
	if node.MinLength != nil && *node.MinLength < 0 {
		return false
	}
	if node.MaxLength != nil && *node.MaxLength < 0 {
		return false
	}
	if node.MinLength != nil && node.MaxLength != nil && *node.MinLength > *node.MaxLength {
		return false
	}
	if node.Minimum != nil && node.Maximum != nil && *node.Minimum > *node.Maximum {
		return false
	}
	for _, prop := range node.Properties {
		if !validateSchemaNodeShape(prop) {
			return false
		}
	}
	if node.Items != nil && !validateSchemaNodeShape(node.Items) {
		return false
	}
	return true
}

func (v *Verifier) evaluateSchema(parsed *ParsedCredential) (Check, error) {
	if !parsed.DeclaresSchema {
		return optionalSkip(CheckSchema, false), nil
	}
	if v.schema == nil {
		return optionalSkip(CheckSchema, true), nil
	}
	entries, ok := parseCredentialSchemaEntries(parsed.RawSchema)
	if !ok {
		return Failed(CheckSchema, CodeSchemaInvalid), nil
	}

	subject, ok := decodeJSONSubject(parsed.RawSubject)
	if !ok {
		return Failed(CheckSchema, CodeSchemaMismatch), nil
	}

	for _, entry := range entries {
		if strings.TrimSpace(entry.ID) == "" || entry.Type != CredentialSchemaType {
			return Failed(CheckSchema, CodeSchemaInvalid), nil
		}
		schemaBytes, err := v.schema.ResolveSchema(entry.ID)
		if err != nil {
			return Check{}, ErrSchemaResolution
		}
		doc, ok := parseJSONSchemaDoc(schemaBytes)
		if !ok {
			return Failed(CheckSchema, CodeSchemaInvalid), nil
		}
		if !validateAgainstSchema(doc, subject) {
			return Failed(CheckSchema, CodeSchemaMismatch), nil
		}
	}
	return Passed(CheckSchema, true), nil
}

func decodeJSONSubject(raw json.RawMessage) (map[string]any, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var obj map[string]any
	if dec.Decode(&obj) != nil || obj == nil {
		return nil, false
	}
	return obj, true
}

func validateAgainstSchema(node *jsonSchemaNode, val any) bool {
	if node == nil {
		return true
	}
	switch node.Type {
	case "string":
		s, ok := val.(string)
		if !ok {
			return false
		}
		runes := utf8.RuneCountInString(s)
		if node.MinLength != nil && runes < *node.MinLength {
			return false
		}
		if node.MaxLength != nil && runes > *node.MaxLength {
			return false
		}
		return matchesEnum(s, node.Enum)
	case "number":
		f, ok := toFloat64(val)
		if !ok {
			return false
		}
		if node.Minimum != nil && f < *node.Minimum {
			return false
		}
		if node.Maximum != nil && f > *node.Maximum {
			return false
		}
		return matchesNumberEnum(f, node.Enum)
	case "integer":
		num, ok := val.(json.Number)
		if !ok || strings.ContainsAny(num.String(), ".eE") {
			return false
		}
		i, err := strconv.ParseInt(num.String(), 10, 64)
		if err != nil {
			return false
		}
		f := float64(i)
		if node.Minimum != nil && f < *node.Minimum {
			return false
		}
		if node.Maximum != nil && f > *node.Maximum {
			return false
		}
		return matchesNumberEnum(f, node.Enum)
	case "boolean":
		b, ok := val.(bool)
		if !ok {
			return false
		}
		return matchesEnum(b, node.Enum)
	case "array":
		arr, ok := val.([]any)
		if !ok {
			return false
		}
		if node.Items != nil {
			for _, elem := range arr {
				if !validateAgainstSchema(node.Items, elem) {
					return false
				}
			}
		}
		return true
	case "object":
		obj, ok := val.(map[string]any)
		if !ok || obj == nil {
			return false
		}
		for _, reqKey := range node.Required {
			if v, exists := obj[reqKey]; !exists || v == nil {
				return false
			}
		}
		for key, elem := range obj {
			propSchema, declared := node.Properties[key]
			if !declared {
				if node.AdditionalProperties != nil && !*node.AdditionalProperties {
					return false
				}
				continue
			}
			if !validateAgainstSchema(propSchema, elem) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func toFloat64(val any) (float64, bool) {
	switch v := val.(type) {
	case json.Number:
		f, err := v.Float64()
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	case float64:
		return v, !math.IsNaN(v) && !math.IsInf(v, 0)
	default:
		return 0, false
	}
}

func matchesEnum(val any, enum []any) bool {
	if len(enum) == 0 {
		return true
	}
	for _, candidate := range enum {
		if candidate == val {
			return true
		}
	}
	return false
}

func matchesNumberEnum(val float64, enum []any) bool {
	if len(enum) == 0 {
		return true
	}
	for _, candidate := range enum {
		if f, ok := toFloat64(candidate); ok && f == val {
			return true
		}
	}
	return false
}

package verification

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
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
	Schema               string                     `json:"$schema"`
	ID                   string                     `json:"$id"`
	Type                 string                     `json:"type"`
	Properties           map[string]*jsonSchemaNode `json:"properties"`
	Required             []string                   `json:"required"`
	AdditionalProperties *bool                      `json:"additionalProperties"`
	MinLength            *int                       `json:"minLength"`
	MaxLength            *int                       `json:"maxLength"`
	Pattern              string                     `json:"pattern"`
	Format               string                     `json:"format"`
	Minimum              *float64                   `json:"minimum"`
	Maximum              *float64                   `json:"maximum"`
	ExclusiveMinimum     *float64                   `json:"exclusiveMinimum"`
	ExclusiveMaximum     *float64                   `json:"exclusiveMaximum"`
	Enum                 []any                      `json:"enum"`
	Const                json.RawMessage            `json:"const"`
	Items                *jsonSchemaNode            `json:"items"`
	MinItems             *int                       `json:"minItems"`
	MaxItems             *int                       `json:"maxItems"`
	UniqueItems          bool                       `json:"uniqueItems"`
	AllOf                []*jsonSchemaNode          `json:"allOf"`
	AnyOf                []*jsonSchemaNode          `json:"anyOf"`
	OneOf                []*jsonSchemaNode          `json:"oneOf"`
	compiledPattern      *regexp.Regexp
	constValue           any
	hasConst             bool
}

var (
	uuidPattern  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	emailPattern = regexp.MustCompile(`^[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+$`)
	uriPattern   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:(//[^\s/$.?#].[^\s]*|[^\s/][^\s]*)$`)
)

func isSupportedSchemaDialect(dialect string) bool {
	switch dialect {
	case "",
		"https://json-schema.org/draft/2020-12/schema",
		"https://json-schema.org/draft/2020-12/schema#",
		"https://json-schema.org/draft/2019-09/schema",
		"https://json-schema.org/draft/2019-09/schema#",
		"http://json-schema.org/draft-07/schema#",
		"https://json-schema.org/draft-07/schema#":
		return true
	default:
		return false
	}
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
	if !isSupportedSchemaDialect(doc.Schema) || !validateSchemaNodeShape(&doc) || (doc.Type != "object" && len(doc.AllOf) == 0 && len(doc.AnyOf) == 0 && len(doc.OneOf) == 0) {
		return nil, false
	}
	return &doc, true
}

func validateSchemaNodeShape(node *jsonSchemaNode) bool {
	if node == nil {
		return false
	}
	hasCombinators := len(node.AllOf) > 0 || len(node.AnyOf) > 0 || len(node.OneOf) > 0
	if len(bytes.TrimSpace(node.Const)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(node.Const))
		dec.UseNumber()
		if err := dec.Decode(&node.constValue); err != nil {
			return false
		}
		node.hasConst = true
	}
	switch node.Type {
	case "string", "number", "integer", "boolean", "object", "array":
	case "":
		if !hasCombinators && !node.hasConst && len(node.Enum) == 0 {
			return false
		}
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
	if node.Pattern != "" {
		if len(node.Pattern) > 256 {
			return false
		}
		re, err := regexp.Compile(node.Pattern)
		if err != nil {
			return false
		}
		node.compiledPattern = re
	}
	if node.Minimum != nil && node.Maximum != nil && *node.Minimum > *node.Maximum {
		return false
	}
	if node.MinItems != nil && *node.MinItems < 0 {
		return false
	}
	if node.MaxItems != nil && *node.MaxItems < 0 {
		return false
	}
	if node.MinItems != nil && node.MaxItems != nil && *node.MinItems > *node.MaxItems {
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
	for _, sub := range node.AllOf {
		if !validateSchemaNodeShape(sub) {
			return false
		}
	}
	for _, sub := range node.AnyOf {
		if !validateSchemaNodeShape(sub) {
			return false
		}
	}
	for _, sub := range node.OneOf {
		if !validateSchemaNodeShape(sub) {
			return false
		}
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
	if node.hasConst && !jsonValuesEqual(val, node.constValue) {
		return false
	}
	for _, sub := range node.AllOf {
		if !validateAgainstSchema(sub, val) {
			return false
		}
	}
	if len(node.AnyOf) > 0 {
		matched := false
		for _, sub := range node.AnyOf {
			if validateAgainstSchema(sub, val) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(node.OneOf) > 0 {
		matches := 0
		for _, sub := range node.OneOf {
			if validateAgainstSchema(sub, val) {
				matches++
			}
		}
		if matches != 1 {
			return false
		}
	}
	switch node.Type {
	case "":
		return matchesEnumAny(val, node.Enum)
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
		if node.compiledPattern != nil && !node.compiledPattern.MatchString(s) {
			return false
		}
		if !matchesStringFormat(s, node.Format) {
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
		if node.ExclusiveMinimum != nil && f <= *node.ExclusiveMinimum {
			return false
		}
		if node.ExclusiveMaximum != nil && f >= *node.ExclusiveMaximum {
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
		if node.ExclusiveMinimum != nil && f <= *node.ExclusiveMinimum {
			return false
		}
		if node.ExclusiveMaximum != nil && f >= *node.ExclusiveMaximum {
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
		if node.MinItems != nil && len(arr) < *node.MinItems {
			return false
		}
		if node.MaxItems != nil && len(arr) > *node.MaxItems {
			return false
		}
		if node.UniqueItems {
			for i := 0; i < len(arr); i++ {
				for j := i + 1; j < len(arr); j++ {
					if jsonValuesEqual(arr[i], arr[j]) {
						return false
					}
				}
			}
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

func matchesEnumAny(val any, enum []any) bool {
	if len(enum) == 0 {
		return true
	}
	for _, candidate := range enum {
		if jsonValuesEqual(val, candidate) {
			return true
		}
	}
	return false
}

func jsonValuesEqual(a, b any) bool {
	if fa, oka := toFloat64(a); oka {
		if fb, okb := toFloat64(b); okb {
			return fa == fb
		}
		return false
	}
	return reflect.DeepEqual(a, b)
}

func matchesStringFormat(s, format string) bool {
	switch format {
	case "":
		return true
	case "date-time":
		if _, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return true
		}
		_, err := time.Parse(time.RFC3339, s)
		return err == nil
	case "date":
		_, err := time.Parse("2006-01-02", s)
		return err == nil
	case "email":
		return emailPattern.MatchString(s)
	case "uri":
		return uriPattern.MatchString(s)
	case "uuid":
		return uuidPattern.MatchString(s)
	default:
		return true
	}
}

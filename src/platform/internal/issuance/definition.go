package issuance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefinitionState is the lifecycle of a credential definition version (HK-003).
type DefinitionState string

const (
	DefinitionDraft     DefinitionState = "draft"
	DefinitionPublished DefinitionState = "published"
	DefinitionRetired   DefinitionState = "retired"

	// DefaultCredentialValidity applies when a definition does not set one.
	DefaultCredentialValidity = 365 * 24 * time.Hour

	maxClaimsBytes     = 8 * 1024
	defaultMaxFieldLen = 256
	maxFieldDepth      = 4
)

var (
	// ErrDefinitionImmutable rejects any change to a published or retired version.
	ErrDefinitionImmutable = errors.New("definition version is immutable")
	// ErrDefinitionConflict rejects a duplicate id/version or configuration id.
	ErrDefinitionConflict = errors.New("definition version already exists")
	// ErrDefinitionNotFound reports an unknown definition version in the tenant/issuer.
	ErrDefinitionNotFound = errors.New("definition not found")
	// ErrDefinitionUnavailable reports a definition that cannot issue (draft or retired).
	ErrDefinitionUnavailable = errors.New("definition is not published")
	// ErrClaimValidation reports claims that do not satisfy the definition.
	ErrClaimValidation = errors.New("claims do not satisfy the definition")

	semverPattern   = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	definitionIDRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)
	configIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,127}$`)
	fieldNamePatern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
)

// FieldSpec declares one claim. Type is string, number, boolean or object.
type FieldSpec struct {
	Type      string               `json:"type"`
	Required  bool                 `json:"required,omitempty"`
	MaxLength int                  `json:"maxLength,omitempty"`
	Fields    map[string]FieldSpec `json:"fields,omitempty"`
}

// FieldError points at one invalid claim without echoing its value.
type FieldError struct {
	Path string `json:"path"`
	Code string `json:"code"`
}

// ClaimValidationError carries every field problem found.
type ClaimValidationError struct{ Errors []FieldError }

func (e *ClaimValidationError) Error() string { return ErrClaimValidation.Error() }
func (e *ClaimValidationError) Unwrap() error { return ErrClaimValidation }

// Definition is one immutable-once-published credential template version.
type Definition struct {
	TenantID        string
	IssuerID        string
	ID              string
	Version         string
	ConfigurationID string
	DisplayName     string
	Locale          string
	// Contexts are the JSON-LD contexts beyond the VCDM base context.
	Contexts []string
	// Types are the specific VC types beyond "VerifiableCredential".
	Types           []string
	Fields          map[string]FieldSpec
	DefaultValidity time.Duration

	State       DefinitionState
	Hash        string
	CreatedAt   time.Time
	PublishedAt *time.Time
	RetiredAt   *time.Time
}

// Ref is the canonical "id@version" reference used by the Integration API.
func (d Definition) Ref() string { return d.ID + "@" + d.Version }

// ParseDefinitionRef splits "id@version".
func ParseDefinitionRef(ref string) (id, version string, err error) {
	id, version, ok := strings.Cut(ref, "@")
	if !ok || !definitionIDRe.MatchString(id) || !semverPattern.MatchString(version) {
		return "", "", ErrDefinitionNotFound
	}
	return id, version, nil
}

type definitionKey struct{ tenant, issuer, id, version string }

// DefinitionRegistry stores credential definitions per tenant and issuer.
type DefinitionRegistry struct {
	mu    sync.RWMutex
	audit *AuditLog
	items map[definitionKey]*Definition
}

// NewDefinitionRegistry builds an empty registry.
func NewDefinitionRegistry(audit *AuditLog) *DefinitionRegistry {
	return &DefinitionRegistry{audit: audit, items: map[definitionKey]*Definition{}}
}

func cloneDefinition(d *Definition) Definition {
	c := *d
	c.Contexts = slices.Clone(d.Contexts)
	c.Types = slices.Clone(d.Types)
	c.Fields = cloneFields(d.Fields)
	return c
}

func cloneFields(in map[string]FieldSpec) map[string]FieldSpec {
	out := make(map[string]FieldSpec, len(in))
	for name, spec := range in {
		spec.Fields = cloneFields(spec.Fields)
		if len(spec.Fields) == 0 {
			spec.Fields = nil
		}
		out[name] = spec
	}
	return out
}

func validateFields(fields map[string]FieldSpec, depth int) error {
	if len(fields) == 0 || len(fields) > 64 || depth > maxFieldDepth {
		return ErrInvalidFoundationInput
	}
	for name, spec := range fields {
		if !fieldNamePatern.MatchString(name) {
			return ErrInvalidFoundationInput
		}
		switch spec.Type {
		case "string":
			if spec.MaxLength < 0 || spec.MaxLength > defaultMaxFieldLen*4 || len(spec.Fields) != 0 {
				return ErrInvalidFoundationInput
			}
		case "number", "boolean":
			if spec.MaxLength != 0 || len(spec.Fields) != 0 {
				return ErrInvalidFoundationInput
			}
		case "object":
			if err := validateFields(spec.Fields, depth+1); err != nil {
				return err
			}
		default:
			return ErrInvalidFoundationInput
		}
	}
	return nil
}

func validateDefinitionShape(d Definition) error {
	if strings.TrimSpace(d.TenantID) == "" || strings.TrimSpace(d.IssuerID) == "" ||
		!definitionIDRe.MatchString(d.ID) || !semverPattern.MatchString(d.Version) ||
		!configIDPattern.MatchString(d.ConfigurationID) ||
		strings.TrimSpace(d.DisplayName) == "" || len(d.DisplayName) > 200 ||
		len(d.Types) == 0 || len(d.Types) > 8 || len(d.Contexts) > 8 ||
		d.DefaultValidity < 0 {
		return ErrInvalidFoundationInput
	}
	for _, t := range d.Types {
		if strings.TrimSpace(t) == "" || t == "VerifiableCredential" {
			return ErrInvalidFoundationInput
		}
	}
	for _, c := range d.Contexts {
		u, err := url.Parse(c)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Fragment != "" || u.User != nil || c == VCDMBaseContext {
			return ErrInvalidFoundationInput
		}
	}
	return validateFields(d.Fields, 1)
}

// ValidateDefinition verifies a Definition's identifiers, types, contexts and field schema.
func ValidateDefinition(d Definition) error {
	return validateDefinitionShape(d)
}

// ComputeDefinitionHash computes the canonical SHA-256 content hash fixed upon publishing.
func ComputeDefinitionHash(d Definition) (string, error) {
	if err := validateDefinitionShape(d); err != nil {
		return "", err
	}
	return definitionHash(&d)
}

func definitionHash(d *Definition) (string, error) {
	canonical := struct {
		ID              string               `json:"id"`
		Version         string               `json:"version"`
		ConfigurationID string               `json:"configurationId"`
		Contexts        []string             `json:"contexts"`
		Types           []string             `json:"types"`
		Fields          map[string]FieldSpec `json:"fields"`
		DefaultValidity int64                `json:"defaultValiditySeconds"`
	}{d.ID, d.Version, d.ConfigurationID, d.Contexts, d.Types, d.Fields, int64(d.DefaultValidity / time.Second)}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// CreateDraft registers a new draft. A duplicate id/version or configuration id
// within the issuer is a conflict.
func (r *DefinitionRegistry) CreateDraft(def Definition, actorID, correlationID string, now time.Time) error {
	if err := validateDefinitionShape(def); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := definitionKey{def.TenantID, def.IssuerID, def.ID, def.Version}
	if _, exists := r.items[key]; exists {
		return ErrDefinitionConflict
	}
	for k, other := range r.items {
		if k.tenant == def.TenantID && k.issuer == def.IssuerID && other.ConfigurationID == def.ConfigurationID {
			return ErrDefinitionConflict
		}
	}
	stored := cloneDefinition(&def)
	stored.State = DefinitionDraft
	stored.Hash = ""
	stored.CreatedAt = now.UTC()
	stored.PublishedAt, stored.RetiredAt = nil, nil
	r.items[key] = &stored
	r.audit.Record(def.TenantID, actorID, "definition.draft_created", def.Ref(), "succeeded", correlationID, now)
	return nil
}

// ReplaceDraft rewrites a draft. Published and retired versions are immutable:
// a change requires a new version.
func (r *DefinitionRegistry) ReplaceDraft(def Definition, actorID, correlationID string, now time.Time) error {
	if err := validateDefinitionShape(def); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := definitionKey{def.TenantID, def.IssuerID, def.ID, def.Version}
	current, ok := r.items[key]
	if !ok {
		return ErrDefinitionNotFound
	}
	if current.State != DefinitionDraft {
		return ErrDefinitionImmutable
	}
	for k, other := range r.items {
		if k != key && k.tenant == def.TenantID && k.issuer == def.IssuerID && other.ConfigurationID == def.ConfigurationID {
			return ErrDefinitionConflict
		}
	}
	replaced := cloneDefinition(&def)
	replaced.State, replaced.CreatedAt = DefinitionDraft, current.CreatedAt
	replaced.Hash, replaced.PublishedAt, replaced.RetiredAt = "", nil, nil
	r.items[key] = &replaced
	r.audit.Record(def.TenantID, actorID, "definition.draft_replaced", def.Ref(), "succeeded", correlationID, now)
	return nil
}

// Publish freezes a draft and fixes its content hash.
func (r *DefinitionRegistry) Publish(tenantID, issuerID, id, version, actorID, correlationID string, now time.Time) (Definition, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.items[definitionKey{tenantID, issuerID, id, version}]
	if !ok {
		return Definition{}, ErrDefinitionNotFound
	}
	if d.State != DefinitionDraft {
		return Definition{}, ErrDefinitionImmutable
	}
	hash, err := definitionHash(d)
	if err != nil {
		return Definition{}, ErrInvalidFoundationInput
	}
	ts := now.UTC()
	d.State, d.Hash, d.PublishedAt = DefinitionPublished, hash, &ts
	r.audit.Record(tenantID, actorID, "definition.published", d.Ref(), "succeeded", correlationID, now)
	return cloneDefinition(d), nil
}

// Retire stops new issuance from a published version. It is terminal; the fix for
// an error is a successor version, never a mutation.
func (r *DefinitionRegistry) Retire(tenantID, issuerID, id, version, actorID, correlationID string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.items[definitionKey{tenantID, issuerID, id, version}]
	if !ok {
		return ErrDefinitionNotFound
	}
	if d.State != DefinitionPublished {
		return ErrDefinitionImmutable
	}
	ts := now.UTC()
	d.State, d.RetiredAt = DefinitionRetired, &ts
	r.audit.Record(tenantID, actorID, "definition.retired", d.Ref(), "succeeded", correlationID, now)
	return nil
}

// Get returns a copy of a definition in any state.
func (r *DefinitionRegistry) Get(tenantID, issuerID, id, version string) (Definition, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.items[definitionKey{tenantID, issuerID, id, version}]
	if !ok {
		return Definition{}, ErrDefinitionNotFound
	}
	return cloneDefinition(d), nil
}

// GetIssuable returns a published definition or ErrDefinitionUnavailable.
func (r *DefinitionRegistry) GetIssuable(tenantID, issuerID, id, version string) (Definition, error) {
	d, err := r.Get(tenantID, issuerID, id, version)
	if err != nil {
		return Definition{}, err
	}
	if d.State != DefinitionPublished {
		return Definition{}, ErrDefinitionUnavailable
	}
	return d, nil
}

// ListPublished returns the published versions of an issuer, ordered by ref.
func (r *DefinitionRegistry) ListPublished(tenantID, issuerID string) []Definition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Definition
	for k, d := range r.items {
		if k.tenant == tenantID && k.issuer == issuerID && d.State == DefinitionPublished {
			out = append(out, cloneDefinition(d))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref() < out[j].Ref() })
	return out
}

// ValidateClaims checks claims against the definition: unknown fields, missing
// required fields, wrong types and over-long strings are rejected. The result
// names paths only, never values.
func (d Definition) ValidateClaims(claims map[string]any) error {
	if raw, err := json.Marshal(claims); err != nil || len(raw) > maxClaimsBytes {
		return &ClaimValidationError{Errors: []FieldError{{Path: "/claims", Code: "invalid_size"}}}
	}
	var problems []FieldError
	validateObject("/claims", d.Fields, claims, &problems)
	if len(problems) == 0 {
		return nil
	}
	sort.Slice(problems, func(i, j int) bool { return problems[i].Path < problems[j].Path })
	return &ClaimValidationError{Errors: problems}
}

func validateObject(path string, specs map[string]FieldSpec, values map[string]any, problems *[]FieldError) {
	for name := range values {
		if _, known := specs[name]; !known {
			*problems = append(*problems, FieldError{Path: path + "/" + name, Code: "unknown_field"})
		}
	}
	for _, name := range slices.Sorted(maps.Keys(specs)) {
		spec := specs[name]
		fieldPath := path + "/" + name
		value, present := values[name]
		if !present || value == nil {
			if spec.Required {
				*problems = append(*problems, FieldError{Path: fieldPath, Code: "required"})
			}
			continue
		}
		switch spec.Type {
		case "string":
			s, ok := value.(string)
			limit := spec.MaxLength
			if limit == 0 {
				limit = defaultMaxFieldLen
			}
			switch {
			case !ok:
				*problems = append(*problems, FieldError{Path: fieldPath, Code: "invalid_type"})
			case strings.TrimSpace(s) == "" && spec.Required:
				*problems = append(*problems, FieldError{Path: fieldPath, Code: "required"})
			case len(s) > limit:
				*problems = append(*problems, FieldError{Path: fieldPath, Code: "too_long"})
			}
		case "number":
			switch value.(type) {
			case float64, int, int64, json.Number:
			default:
				*problems = append(*problems, FieldError{Path: fieldPath, Code: "invalid_type"})
			}
		case "boolean":
			if _, ok := value.(bool); !ok {
				*problems = append(*problems, FieldError{Path: fieldPath, Code: "invalid_type"})
			}
		case "object":
			nested, ok := value.(map[string]any)
			if !ok {
				*problems = append(*problems, FieldError{Path: fieldPath, Code: "invalid_type"})
				continue
			}
			validateObject(fieldPath, spec.Fields, nested, problems)
		default:
			*problems = append(*problems, FieldError{Path: fieldPath, Code: fmt.Sprintf("unsupported_%s", spec.Type)})
		}
	}
}

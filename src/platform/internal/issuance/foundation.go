package issuance

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"hukid.local/platform/internal/verification"
)

// IssuerState tracks the operational lifecycle of a logical issuer (HK-001).
type IssuerState string

const (
	IssuerActive    IssuerState = "active"
	IssuerSuspended IssuerState = "suspended"
)

// KeyState tracks the lifecycle of an ES256 issuer key (HK-002).
type KeyState string

const (
	KeyActive      KeyState = "active"
	KeyRetired     KeyState = "retired"
	KeyCompromised KeyState = "compromised"
)

// ClientState tracks the lifecycle of an M2M integration client (HK-004).
type ClientState string

const (
	ClientActive  ClientState = "active"
	ClientRevoked ClientState = "revoked"
)

const (
	// ScopeIssuanceCreate allows calling POST /v1/issuance-requests.
	ScopeIssuanceCreate = "issuance:create"
	// ScopeIssuanceRead allows reading issuance request status.
	ScopeIssuanceRead = "issuance:read"

	// IntegrationTokenClass and IntegrationAudience bind M2M tokens (profile §6).
	IntegrationTokenClass      = "integration"
	IntegrationAudience        = "https://api.hukid.pe/integration"
	DefaultIntegrationTokenTTL = 5 * time.Minute

	minClientSecretBytes = 16
)

var (
	// ErrInvalidFoundationInput indicates invalid tenant, issuer, key or client config.
	ErrInvalidFoundationInput = errors.New("invalid foundation input")
	// ErrNoActiveKey indicates the issuer has no active signing key (e.g. compromised).
	ErrNoActiveKey = errors.New("no active signing key")
	// ErrKeyConflict indicates duplicate kid or invalid key state transition.
	ErrKeyConflict = errors.New("issuer key conflict")
	// ErrClientUnauthorized indicates invalid credentials, revoked/expired client or wrong token class/scope.
	ErrClientUnauthorized = errors.New("integration client unauthorized")
	// ErrResourceNotFound indicates a missing or cross-tenant/cross-client resource (maps to HTTP 404).
	ErrResourceNotFound = errors.New("resource not found")
)

// reservedSlugs cannot be issuer slugs: they are fixed first path segments of the
// HukID HTTP surface ("/v1/..." and "/oauth2/...").
var reservedSlugs = map[string]bool{"v1": true, "oauth2": true}

// IssuerRecord models a logical issuer bound to one tenant (HK-001).
type IssuerRecord struct {
	TenantID    string
	IssuerID    string
	Slug        string
	IssuerURI   string
	DisplayName string
	State       IssuerState
	CreatedAt   time.Time
}

// NewIssuerRecord validates inputs and constructs a logical issuer for tenantID.
func NewIssuerRecord(tenantID, issuerID, slug, displayName string, now time.Time) (IssuerRecord, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(issuerID) == "" ||
		strings.TrimSpace(displayName) == "" || !isValidSlug(slug) || reservedSlugs[slug] {
		return IssuerRecord{}, ErrInvalidFoundationInput
	}
	uri := IssuerPrefix + slug
	if err := ValidateIssuerIdentifier(uri); err != nil {
		return IssuerRecord{}, ErrInvalidFoundationInput
	}
	return IssuerRecord{
		TenantID:    tenantID,
		IssuerID:    issuerID,
		Slug:        slug,
		IssuerURI:   uri,
		DisplayName: displayName,
		State:       IssuerActive,
		CreatedAt:   now.UTC(),
	}, nil
}

// AuditRecord captures a tamper-evident, secret-free audit entry (HK-005).
type AuditRecord struct {
	EventID       string
	TenantID      string
	ActorID       string
	Action        string
	TargetID      string
	Outcome       string
	CorrelationID string
	OccurredAt    time.Time
}

// AuditLog is an append-only store of foundation security and lifecycle events.
type AuditLog struct {
	mu      sync.Mutex
	random  io.Reader
	records []AuditRecord
}

// NewAuditLog builds a clean append-only AuditLog.
func NewAuditLog(random io.Reader) *AuditLog {
	if random == nil {
		random = rand.Reader
	}
	return &AuditLog{random: random}
}

// Record appends an immutable audit event without storing secrets or claims.
func (a *AuditLog) Record(tenantID, actorID, action, targetID, outcome, correlationID string, occurredAt time.Time) {
	if a == nil {
		return
	}
	buf := make([]byte, 16)
	_, _ = io.ReadFull(a.random, buf)
	eventID := "evt_" + base64.RawURLEncoding.EncodeToString(buf)

	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, AuditRecord{
		EventID:       eventID,
		TenantID:      tenantID,
		ActorID:       actorID,
		Action:        action,
		TargetID:      targetID,
		Outcome:       outcome,
		CorrelationID: correlationID,
		OccurredAt:    occurredAt.UTC(),
	})
}

// ListByTenant returns a copy of audit records belonging exclusively to tenantID,
// optionally filtered by action when actionFilter != "".
func (a *AuditLog) ListByTenant(tenantID, actionFilter string) []AuditRecord {
	if a == nil || strings.TrimSpace(tenantID) == "" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []AuditRecord
	for _, r := range a.records {
		if r.TenantID != tenantID {
			continue
		}
		if actionFilter != "" && r.Action != actionFilter {
			continue
		}
		out = append(out, r)
	}
	return out
}

// KeyMetadata describes one key entry inside an issuer's KeyRing without exposing private material.
type KeyMetadata struct {
	KID           string
	IssuerURI     string
	State         KeyState
	CreatedAt     time.Time
	RetiredAt     *time.Time
	CompromisedAt *time.Time
}

type ringEntry struct {
	meta   KeyMetadata
	signer *MemorySigner
}

// KeyRing manages ES256 signing keys, rotation and compromise handling for one
// tenant-scoped issuer (HK-002, HK-052).
type KeyRing struct {
	mu       sync.RWMutex
	tenantID string
	issuer   string
	audit    *AuditLog
	order    []string
	keys     map[string]*ringEntry
}

// NewKeyRing creates a key ring bound to one tenant and logical issuer URI.
func NewKeyRing(tenantID, issuerURI string, audit *AuditLog) (*KeyRing, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, ErrInvalidFoundationInput
	}
	if err := ValidateIssuerIdentifier(issuerURI); err != nil {
		return nil, err
	}
	return &KeyRing{
		tenantID: tenantID,
		issuer:   issuerURI,
		audit:    audit,
		keys:     map[string]*ringEntry{},
	}, nil
}

// RegisterKey registers an initial active signing key when no active key exists yet.
func (r *KeyRing) RegisterKey(kid string, key *ecdsa.PrivateKey, actorID, correlationID string, now time.Time) error {
	signer, err := NewMemorySigner(r.issuer, kid, key, nil)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.keys[kid]; exists {
		return ErrKeyConflict
	}
	for _, existing := range r.keys {
		if existing.meta.State == KeyActive {
			return ErrKeyConflict
		}
	}
	r.order = append(r.order, kid)
	r.keys[kid] = &ringEntry{
		meta: KeyMetadata{
			KID:       kid,
			IssuerURI: r.issuer,
			State:     KeyActive,
			CreatedAt: now.UTC(),
		},
		signer: signer,
	}
	r.audit.Record(r.tenantID, actorID, "issuer_key.registered", kid, "succeeded", correlationID, now)
	return nil
}

// RotateKey retires any currently active key (keeping it in JWKS so existing
// credentials remain verifiable) and activates newKey under newKID (HK-002).
func (r *KeyRing) RotateKey(newKID string, newKey *ecdsa.PrivateKey, actorID, correlationID string, now time.Time) error {
	signer, err := NewMemorySigner(r.issuer, newKID, newKey, nil)
	if err != nil {
		return err
	}
	ts := now.UTC()

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.keys[newKID]; exists {
		return ErrKeyConflict
	}
	for _, entry := range r.keys {
		if entry.meta.State == KeyActive {
			entry.meta.State = KeyRetired
			retired := ts
			entry.meta.RetiredAt = &retired
		}
	}
	r.order = append(r.order, newKID)
	r.keys[newKID] = &ringEntry{
		meta: KeyMetadata{
			KID:       newKID,
			IssuerURI: r.issuer,
			State:     KeyActive,
			CreatedAt: ts,
		},
		signer: signer,
	}
	r.audit.Record(r.tenantID, actorID, "issuer_key.rotated", newKID, "succeeded", correlationID, now)
	return nil
}

// CompromiseKey marks kid as compromised, stopping all future signing with it and
// removing it from PublicJWKS (HK-002, HK-052).
func (r *KeyRing) CompromiseKey(kid, actorID, correlationID string, now time.Time) error {
	ts := now.UTC()

	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.keys[kid]
	if !ok {
		return ErrResourceNotFound
	}
	if entry.meta.State == KeyCompromised {
		return nil
	}
	entry.meta.State = KeyCompromised
	entry.meta.CompromisedAt = &ts
	r.audit.Record(r.tenantID, actorID, "issuer_key.compromised", kid, "succeeded", correlationID, now)
	return nil
}

// ActiveSigner returns the currently active Signer or ErrNoActiveKey if none is active.
func (r *KeyRing) ActiveSigner() (Signer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, kid := range r.order {
		if entry := r.keys[kid]; entry.meta.State == KeyActive {
			return entry.signer, nil
		}
	}
	return nil, ErrNoActiveKey
}

// PublicJWKS returns all active and retired keys for this issuer; compromised keys are omitted.
func (r *KeyRing) PublicJWKS() (JWKS, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	keys := make([]PublicJWK, 0, len(r.order))
	for _, kid := range r.order {
		entry := r.keys[kid]
		if entry.meta.State == KeyCompromised {
			continue
		}
		jwk, err := entry.signer.JWK()
		if err != nil {
			return JWKS{}, err
		}
		keys = append(keys, jwk)
	}
	return JWKS{Keys: keys}, nil
}

// BuildResolver constructs a fresh verification.MemoryKeyResolver containing only
// non-compromised (active and retired) keys of this KeyRing.
func (r *KeyRing) BuildResolver() (*verification.MemoryKeyResolver, error) {
	res := verification.NewMemoryKeyResolver()
	if err := r.SyncToResolver(res); err != nil {
		return nil, err
	}
	return res, nil
}

// SyncToResolver populates resolver with all active and retired keys of this KeyRing.
func (r *KeyRing) SyncToResolver(resolver *verification.MemoryKeyResolver) error {
	if resolver == nil {
		return ErrInvalidFoundationInput
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, kid := range r.order {
		entry := r.keys[kid]
		if entry.meta.State == KeyCompromised {
			continue
		}
		if err := resolver.Add(r.issuer, entry.meta.KID, entry.signer.PublicKey()); err != nil {
			return err
		}
	}
	return nil
}

// KeyHistory returns metadata copies for all keys in creation order.
func (r *KeyRing) KeyHistory() []KeyMetadata {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]KeyMetadata, 0, len(r.order))
	for _, kid := range r.order {
		out = append(out, r.keys[kid].meta)
	}
	return out
}

// IntegrationToken represents a validated OAuth2 M2M token for /v1 integration endpoints.
type IntegrationToken struct {
	TokenClass     string
	Audience       string
	TenantID       string
	ClientID       string
	AllowedIssuers []string
	Scopes         []string
	IssuedAt       time.Time
	ExpiresAt      time.Time
}

type clientRecord struct {
	clientID       string
	tenantID       string
	clientName     string
	secretHash     [32]byte
	allowedIssuers map[string]bool
	scopes         map[string]bool
	state          ClientState
	createdAt      time.Time
	expiresAt      *time.Time
	revokedAt      *time.Time
}

// ClientRegistry stores tenant-scoped OAuth2 M2M clients and per-issuer grants (HK-004).
type ClientRegistry struct {
	mu      sync.RWMutex
	audit   *AuditLog
	clients map[string]*clientRecord
}

// NewClientRegistry constructs a clean ClientRegistry.
func NewClientRegistry(audit *AuditLog) *ClientRegistry {
	return &ClientRegistry{
		audit:   audit,
		clients: map[string]*clientRecord{},
	}
}

func allowedIntegrationScope(s string) bool {
	return s == ScopeIssuanceCreate || s == ScopeIssuanceRead
}

// RegisterClient creates a client storing only the SHA-256 hash of rawSecret.
func (r *ClientRegistry) RegisterClient(
	tenantID, clientID, clientName, rawSecret string,
	allowedIssuers, scopes []string,
	expiresAt *time.Time,
	actorID, correlationID string,
	now time.Time,
) error {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(clientID) == "" ||
		strings.TrimSpace(clientName) == "" || len(rawSecret) < minClientSecretBytes ||
		len(allowedIssuers) == 0 || len(scopes) == 0 {
		return ErrInvalidFoundationInput
	}
	if expiresAt != nil && !expiresAt.UTC().After(now.UTC()) {
		return ErrInvalidFoundationInput
	}
	issuerSet := make(map[string]bool, len(allowedIssuers))
	for _, id := range allowedIssuers {
		if strings.TrimSpace(id) == "" {
			return ErrInvalidFoundationInput
		}
		issuerSet[id] = true
	}
	scopeSet := make(map[string]bool, len(scopes))
	for _, sc := range scopes {
		if !allowedIntegrationScope(sc) {
			return ErrInvalidFoundationInput
		}
		scopeSet[sc] = true
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.clients[clientID]; exists {
		return ErrInvalidFoundationInput
	}
	var expCopy *time.Time
	if expiresAt != nil {
		t := expiresAt.UTC()
		expCopy = &t
	}
	r.clients[clientID] = &clientRecord{
		clientID:       clientID,
		tenantID:       tenantID,
		clientName:     clientName,
		secretHash:     sha256.Sum256([]byte(rawSecret)),
		allowedIssuers: issuerSet,
		scopes:         scopeSet,
		state:          ClientActive,
		createdAt:      now.UTC(),
		expiresAt:      expCopy,
	}
	r.audit.Record(tenantID, actorID, "integration_client.registered", clientID, "succeeded", correlationID, now)
	return nil
}

// AuthenticateClient validates clientID + clientSecret in constant time and issues
// an IntegrationToken bounded to the requested subset of granted scopes.
func (r *ClientRegistry) AuthenticateClient(clientID, clientSecret string, requestedScopes []string, now time.Time) (IntegrationToken, error) {
	if clientID == "" || clientSecret == "" {
		return IntegrationToken{}, ErrClientUnauthorized
	}
	providedHash := sha256.Sum256([]byte(clientSecret))
	nowUTC := now.UTC()

	r.mu.RLock()
	rec, ok := r.clients[clientID]
	if !ok {
		r.mu.RUnlock()
		return IntegrationToken{}, ErrClientUnauthorized
	}
	hashMatch := subtle.ConstantTimeCompare(rec.secretHash[:], providedHash[:]) == 1
	active := rec.state == ClientActive && (rec.expiresAt == nil || nowUTC.Before(*rec.expiresAt))
	grantedScopes := maps.Clone(rec.scopes)
	issuers := make([]string, 0, len(rec.allowedIssuers))
	for id := range rec.allowedIssuers {
		issuers = append(issuers, id)
	}
	tenantID := rec.tenantID
	r.mu.RUnlock()

	if !hashMatch || !active {
		r.audit.Record(tenantID, clientID, "integration_client.authenticate", clientID, "denied", "", now)
		return IntegrationToken{}, ErrClientUnauthorized
	}

	var effectiveScopes []string
	if len(requestedScopes) == 0 {
		for sc := range grantedScopes {
			effectiveScopes = append(effectiveScopes, sc)
		}
	} else {
		for _, sc := range requestedScopes {
			if !grantedScopes[sc] {
				r.audit.Record(tenantID, clientID, "integration_client.authenticate", clientID, "denied", "", now)
				return IntegrationToken{}, ErrClientUnauthorized
			}
			effectiveScopes = append(effectiveScopes, sc)
		}
	}
	slices.Sort(effectiveScopes)
	slices.Sort(issuers)

	r.audit.Record(tenantID, clientID, "integration_client.authenticate", clientID, "succeeded", "", now)
	return IntegrationToken{
		TokenClass:     IntegrationTokenClass,
		Audience:       IntegrationAudience,
		TenantID:       tenantID,
		ClientID:       clientID,
		AllowedIssuers: issuers,
		Scopes:         effectiveScopes,
		IssuedAt:       nowUTC,
		ExpiresAt:      nowUTC.Add(DefaultIntegrationTokenTTL),
	}, nil
}

// AuthorizeIssuerAccess enforces token class, audience, expiry, tenant ownership,
// scope and explicit issuer grant. Cross-tenant or ungranted issuer access returns
// ErrResourceNotFound (HTTP 404 per HK-004).
func (r *ClientRegistry) AuthorizeIssuerAccess(token IntegrationToken, tenantID, issuerID, requiredScope string, now time.Time) error {
	nowUTC := now.UTC()
	if token.TokenClass != IntegrationTokenClass || token.Audience != IntegrationAudience ||
		token.ClientID == "" || !nowUTC.Before(token.ExpiresAt) || nowUTC.Before(token.IssuedAt) {
		return ErrClientUnauthorized
	}
	if token.TenantID == "" || token.TenantID != tenantID {
		return ErrResourceNotFound
	}
	if !slices.Contains(token.AllowedIssuers, issuerID) {
		return ErrResourceNotFound
	}
	if requiredScope != "" && !slices.Contains(token.Scopes, requiredScope) {
		return ErrClientUnauthorized
	}
	r.mu.RLock()
	rec, ok := r.clients[token.ClientID]
	stillValid := ok && rec.tenantID == tenantID && rec.state == ClientActive &&
		(rec.expiresAt == nil || nowUTC.Before(*rec.expiresAt)) && rec.allowedIssuers[issuerID]
	r.mu.RUnlock()
	if !stillValid {
		return ErrClientUnauthorized
	}
	return nil
}

// RotateSecret replaces a client's secret hash within its owning tenant (404 cross-tenant).
func (r *ClientRegistry) RotateSecret(tenantID, clientID, newSecret, actorID, correlationID string, now time.Time) error {
	if len(newSecret) < minClientSecretBytes {
		return ErrInvalidFoundationInput
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.clients[clientID]
	if !ok || rec.tenantID != tenantID {
		return ErrResourceNotFound
	}
	if rec.state != ClientActive {
		return ErrClientUnauthorized
	}
	rec.secretHash = sha256.Sum256([]byte(newSecret))
	r.audit.Record(tenantID, actorID, "integration_client.secret_rotated", clientID, "succeeded", correlationID, now)
	return nil
}

// RevokeClient marks a client revoked within its owning tenant (404 cross-tenant).
func (r *ClientRegistry) RevokeClient(tenantID, clientID, actorID, correlationID string, now time.Time) error {
	ts := now.UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.clients[clientID]
	if !ok || rec.tenantID != tenantID {
		return ErrResourceNotFound
	}
	rec.state = ClientRevoked
	rec.revokedAt = &ts
	r.audit.Record(tenantID, actorID, "integration_client.revoked", clientID, "succeeded", correlationID, now)
	return nil
}

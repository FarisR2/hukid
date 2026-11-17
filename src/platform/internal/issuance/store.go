package issuance

import (
	"crypto/sha256"
	"crypto/subtle"
	"maps"
	"slices"
	"sync"
	"time"
)

// StoredKey is the public signing key metadata persisted for an active issuer key.
type StoredKey struct {
	KID       string
	KMSKeyRef string
	IssuerURI string
	JWK       PublicJWK
}

// StoredClient is the persisted M2M integration client state and grants.
type StoredClient struct {
	ClientID       string
	TenantID       string
	SecretHash     [32]byte
	AllowedIssuers map[string]bool
	Scopes         map[string]bool
	State          ClientState
	ExpiresAt      *time.Time
}

// StoredRequest is the tenant-scoped encrypted issuance request record.
type StoredRequest struct {
	ID              string
	TenantID        string
	IssuerID        string
	ClientID        string
	DefID           string
	DefVersion      string
	ConfigID        string
	ClaimsCipher    []byte
	ClaimsNonce     []byte
	ClaimsKeyVer    string
	OfferRef        string
	OfferCipher     []byte
	OfferNonce      []byte
	OfferKeyVer     string
	OfferState      string
	IssuanceState   string
	SourceSystem    string
	SourceReference string
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

// StoredOffer carries the minimal request linkage returned when redeeming an offer.
type StoredOffer struct {
	TenantID  string
	IssuerID  string
	IssuerURI string
	RequestID string
	ConfigID  string
	ExpiresAt time.Time
}

// StoredToken represents a persisted integration or OID4VCI access token record.
type StoredToken struct {
	Class       string
	Audience    string
	IssuedAt    time.Time
	ExpiresAt   time.Time
	Integration IntegrationToken
	RequestID   string
	CredID      string
	Used        bool
}

// IdempotencyRecord snapshots an Idempotency-Key response for safe replay detection.
type IdempotencyRecord struct {
	ClientID    string
	KeyHash     [32]byte
	RequestHash [32]byte
	Result      IssuanceRequestResult
}

// Backend abstracts tenant-scoped issuance persistence. Implementations run Tx
// callbacks with row locking (Postgres FOR UPDATE / FORCE RLS) or mutex isolation.
type Backend interface {
	ResolveTenantBySlug(slug string) (string, bool, error)
	ResolveTenantByClient(clientID string) (string, bool, error)
	ResolveTenantByOfferCode(codeHash [32]byte) (string, bool, error)
	ResolveTenantByToken(tokenHash [32]byte) (string, bool, error)
	WithTenantTx(tenantID string, fn func(Tx) error) error
}

// Tx represents one tenant-isolated atomic transaction.
type Tx interface {
	GetIssuerByID(issuerID string) (IssuerRecord, bool, error)
	GetIssuerBySlug(slug string) (IssuerRecord, bool, error)
	GetActiveKey(issuerID string) (StoredKey, error)
	ListPublicKeys(issuerID string) ([]PublicJWK, error)
	GetClient(clientID string) (StoredClient, bool, error)
	GetIssuableDefinition(issuerID, id, version string) (Definition, error)
	ListPublishedDefinitions(issuerID string) ([]Definition, error)
	LockIdempotency(clientID string, keyHash [32]byte) (IdempotencyRecord, bool, error)
	SaveIdempotency(rec IdempotencyRecord) error
	SaveRequestAndOffer(req StoredRequest, codeHash [32]byte) error
	GetRequestForClient(requestID, clientID string) (StoredRequest, bool, error)
	GetRequestByOfferRef(issuerID, ref string) (StoredRequest, bool, error)
	RedeemOfferByCodeHash(codeHash [32]byte, now time.Time) (StoredOffer, error)
	SaveNonce(issuerID string, nonceHash [32]byte, createdAt, expiresAt time.Time) error
	ConsumeNonce(issuerID string, nonceHash [32]byte, now time.Time) error
	SaveToken(tokenHash [32]byte, rec StoredToken) error
	LookupToken(tokenHash [32]byte) (StoredToken, bool, error)
	LockTokenForCredential(tokenHash [32]byte) (StoredToken, bool, error)
	LockRequest(requestID string) (StoredRequest, bool, error)
	MarkIssued(requestID string, tokenHash [32]byte, now time.Time) error
	AppendAudit(rec AuditRecord) error
}

type activeSignerProvider interface {
	ActiveSigner(issuerID string) (Signer, error)
}

// AuthenticateStoredClient verifies clientSecret in constant time and derives the
// effective scope subset of an integration client.
func AuthenticateStoredClient(rec StoredClient, clientSecret string, requestedScopes []string, now time.Time) (IntegrationToken, error) {
	if clientSecret == "" {
		return IntegrationToken{}, ErrClientUnauthorized
	}
	providedHash := sha256.Sum256([]byte(clientSecret))
	nowUTC := now.UTC()
	hashMatch := subtle.ConstantTimeCompare(rec.SecretHash[:], providedHash[:]) == 1
	active := rec.State == ClientActive && (rec.ExpiresAt == nil || nowUTC.Before(*rec.ExpiresAt))
	if !hashMatch || !active {
		return IntegrationToken{}, ErrClientUnauthorized
	}

	var effectiveScopes []string
	if len(requestedScopes) == 0 {
		for sc := range rec.Scopes {
			effectiveScopes = append(effectiveScopes, sc)
		}
	} else {
		for _, sc := range requestedScopes {
			if !rec.Scopes[sc] {
				return IntegrationToken{}, ErrClientUnauthorized
			}
			effectiveScopes = append(effectiveScopes, sc)
		}
	}
	issuers := make([]string, 0, len(rec.AllowedIssuers))
	for id := range rec.AllowedIssuers {
		issuers = append(issuers, id)
	}
	slices.Sort(effectiveScopes)
	slices.Sort(issuers)

	return IntegrationToken{
		TokenClass:     IntegrationTokenClass,
		Audience:       IntegrationAudience,
		TenantID:       rec.TenantID,
		ClientID:       rec.ClientID,
		AllowedIssuers: issuers,
		Scopes:         effectiveScopes,
		IssuedAt:       nowUTC,
		ExpiresAt:      nowUTC.Add(DefaultIntegrationTokenTTL),
	}, nil
}

// AuthorizeStoredIssuerAccess enforces token claims and live client status.
func AuthorizeStoredIssuerAccess(rec *StoredClient, token IntegrationToken, tenantID, issuerID, requiredScope string, now time.Time) error {
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
	if rec == nil || rec.TenantID != tenantID || rec.State != ClientActive ||
		(rec.ExpiresAt != nil && !nowUTC.Before(*rec.ExpiresAt)) || !rec.AllowedIssuers[issuerID] {
		return ErrClientUnauthorized
	}
	return nil
}

type memoryIdemKey struct {
	tenantID string
	clientID string
	keyHash  [32]byte
}

type memoryTokenEntry struct {
	tenantID string
	record   StoredToken
}

type memoryBackend struct {
	mu      sync.Mutex
	clients *ClientRegistry
	defs    *DefinitionRegistry
	audit   *AuditLog
	offers  *OfferStore
	nonces  *NonceStore
	byID    map[string]*issuerEntry
	bySlug  map[string]*issuerEntry
	reqs    map[string]*StoredRequest
	byRef   map[string]*StoredRequest
	idem    map[memoryIdemKey]IdempotencyRecord
	tokens  map[[32]byte]*memoryTokenEntry
}

func newMemoryBackend(cfg ServiceConfig) *memoryBackend {
	return &memoryBackend{
		clients: cfg.Clients,
		defs:    cfg.Definitions,
		audit:   cfg.Audit,
		offers:  NewOfferStore(cfg.Random),
		nonces:  NewNonceStore(DefaultNonceTTL, cfg.Random),
		byID:    map[string]*issuerEntry{},
		bySlug:  map[string]*issuerEntry{},
		reqs:    map[string]*StoredRequest{},
		byRef:   map[string]*StoredRequest{},
		idem:    map[memoryIdemKey]IdempotencyRecord{},
		tokens:  map[[32]byte]*memoryTokenEntry{},
	}
}

func (m *memoryBackend) registerIssuer(record IssuerRecord, ring *KeyRing) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.byID[record.IssuerID]; dup {
		return ErrInvalidFoundationInput
	}
	if _, dup := m.bySlug[record.Slug]; dup {
		return ErrInvalidFoundationInput
	}
	entry := &issuerEntry{record: record, ring: ring}
	m.byID[record.IssuerID] = entry
	m.bySlug[record.Slug] = entry
	return nil
}

func (m *memoryBackend) ResolveTenantBySlug(slug string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.bySlug[slug]
	if !ok {
		return "", false, nil
	}
	return entry.record.TenantID, true, nil
}

func (m *memoryBackend) ResolveTenantByClient(clientID string) (string, bool, error) {
	if clientID == "" || m.clients == nil {
		return "", false, nil
	}
	m.clients.mu.RLock()
	rec, ok := m.clients.clients[clientID]
	m.clients.mu.RUnlock()
	if !ok {
		return "", false, nil
	}
	return rec.tenantID, true, nil
}

func (m *memoryBackend) ResolveTenantByOfferCode(codeHash [32]byte) (string, bool, error) {
	reqID, ok := m.offers.lookupRequestID(codeHash)
	if !ok {
		return "", false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.reqs[reqID]
	if !ok {
		return "", false, nil
	}
	return rec.TenantID, true, nil
}

func (m *memoryBackend) ResolveTenantByToken(tokenHash [32]byte) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.tokens[tokenHash]
	if !ok {
		return "", false, nil
	}
	return entry.tenantID, true, nil
}

func (m *memoryBackend) WithTenantTx(tenantID string, fn func(Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fn(&memoryTx{m: m, tenantID: tenantID})
}

type memoryTx struct {
	m        *memoryBackend
	tenantID string
}

func (t *memoryTx) GetIssuerByID(issuerID string) (IssuerRecord, bool, error) {
	entry, ok := t.m.byID[issuerID]
	if !ok || entry.record.TenantID != t.tenantID {
		return IssuerRecord{}, false, nil
	}
	return entry.record, true, nil
}

func (t *memoryTx) GetIssuerBySlug(slug string) (IssuerRecord, bool, error) {
	entry, ok := t.m.bySlug[slug]
	if !ok || entry.record.TenantID != t.tenantID {
		return IssuerRecord{}, false, nil
	}
	return entry.record, true, nil
}

func (t *memoryTx) ActiveSigner(issuerID string) (Signer, error) {
	entry, ok := t.m.byID[issuerID]
	if !ok || entry.record.TenantID != t.tenantID {
		return nil, ErrResourceNotFound
	}
	return entry.ring.ActiveSigner()
}

func (t *memoryTx) GetActiveKey(issuerID string) (StoredKey, error) {
	signer, err := t.ActiveSigner(issuerID)
	if err != nil {
		return StoredKey{}, err
	}
	jwk, err := ExportPublicJWK(signer.PublicKey(), signer.KeyID())
	if err != nil {
		return StoredKey{}, err
	}
	return StoredKey{
		KID:       signer.KeyID(),
		KMSKeyRef: "memory://" + signer.KeyID(),
		IssuerURI: signer.Issuer(),
		JWK:       jwk,
	}, nil
}

func (t *memoryTx) ListPublicKeys(issuerID string) ([]PublicJWK, error) {
	entry, ok := t.m.byID[issuerID]
	if !ok || entry.record.TenantID != t.tenantID {
		return nil, ErrResourceNotFound
	}
	doc, err := entry.ring.PublicJWKS()
	if err != nil {
		return nil, err
	}
	return doc.Keys, nil
}

func (t *memoryTx) GetClient(clientID string) (StoredClient, bool, error) {
	if t.m.clients == nil {
		return StoredClient{}, false, nil
	}
	t.m.clients.mu.RLock()
	rec, ok := t.m.clients.clients[clientID]
	if !ok || rec.tenantID != t.tenantID {
		t.m.clients.mu.RUnlock()
		return StoredClient{}, false, nil
	}
	out := StoredClient{
		ClientID:       rec.clientID,
		TenantID:       rec.tenantID,
		SecretHash:     rec.secretHash,
		AllowedIssuers: maps.Clone(rec.allowedIssuers),
		Scopes:         maps.Clone(rec.scopes),
		State:          rec.state,
	}
	if rec.expiresAt != nil {
		exp := *rec.expiresAt
		out.ExpiresAt = &exp
	}
	t.m.clients.mu.RUnlock()
	return out, true, nil
}

func (t *memoryTx) GetIssuableDefinition(issuerID, id, version string) (Definition, error) {
	return t.m.defs.GetIssuable(t.tenantID, issuerID, id, version)
}

func (t *memoryTx) ListPublishedDefinitions(issuerID string) ([]Definition, error) {
	return t.m.defs.ListPublished(t.tenantID, issuerID), nil
}

func (t *memoryTx) LockIdempotency(clientID string, keyHash [32]byte) (IdempotencyRecord, bool, error) {
	rec, ok := t.m.idem[memoryIdemKey{t.tenantID, clientID, keyHash}]
	return rec, ok, nil
}

func (t *memoryTx) SaveIdempotency(rec IdempotencyRecord) error {
	t.m.idem[memoryIdemKey{t.tenantID, rec.ClientID, rec.KeyHash}] = rec
	return nil
}

func (t *memoryTx) SaveRequestAndOffer(req StoredRequest, codeHash [32]byte) error {
	entry, ok := t.m.byID[req.IssuerID]
	if !ok || entry.record.TenantID != t.tenantID {
		return ErrResourceNotFound
	}
	copyReq := req
	t.m.reqs[req.ID] = &copyReq
	t.m.byRef[req.OfferRef] = &copyReq
	t.m.offers.putHashed(codeHash, entry.record.IssuerURI, req.ConfigID, map[string]any{"request_id": req.ID}, req.ExpiresAt)
	return nil
}

func (t *memoryTx) GetRequestForClient(requestID, clientID string) (StoredRequest, bool, error) {
	rec, ok := t.m.reqs[requestID]
	if !ok || rec.TenantID != t.tenantID || rec.ClientID != clientID {
		return StoredRequest{}, false, nil
	}
	return *rec, true, nil
}

func (t *memoryTx) GetRequestByOfferRef(issuerID, ref string) (StoredRequest, bool, error) {
	rec, ok := t.m.byRef[ref]
	if !ok || rec.TenantID != t.tenantID || rec.IssuerID != issuerID {
		return StoredRequest{}, false, nil
	}
	return *rec, true, nil
}

func (t *memoryTx) RedeemOfferByCodeHash(codeHash [32]byte, now time.Time) (StoredOffer, error) {
	offer, err := t.m.offers.redeemHashed(codeHash, now)
	if err != nil {
		return StoredOffer{}, err
	}
	requestID, _ := offer.SubjectClaims["request_id"].(string)
	rec, ok := t.m.reqs[requestID]
	if !ok || rec.TenantID != t.tenantID || rec.OfferState != offerReady {
		return StoredOffer{}, ErrOfferInvalid
	}
	rec.OfferState = offerRedeemed
	rec.OfferCipher, rec.OfferNonce, rec.OfferKeyVer = nil, nil, ""
	return StoredOffer{
		TenantID:  rec.TenantID,
		IssuerID:  rec.IssuerID,
		IssuerURI: offer.Issuer,
		RequestID: rec.ID,
		ConfigID:  rec.ConfigID,
		ExpiresAt: rec.ExpiresAt,
	}, nil
}

func (t *memoryTx) SaveNonce(_ string, nonceHash [32]byte, _, expiresAt time.Time) error {
	t.m.nonces.putHash(nonceHash, expiresAt)
	return nil
}

func (t *memoryTx) ConsumeNonce(_ string, nonceHash [32]byte, now time.Time) error {
	return t.m.nonces.consumeHash(nonceHash, now)
}

func (t *memoryTx) SaveToken(tokenHash [32]byte, rec StoredToken) error {
	t.m.tokens[tokenHash] = &memoryTokenEntry{tenantID: t.tenantID, record: rec}
	return nil
}

func (t *memoryTx) LookupToken(tokenHash [32]byte) (StoredToken, bool, error) {
	entry, ok := t.m.tokens[tokenHash]
	if !ok || entry.tenantID != t.tenantID {
		return StoredToken{}, false, nil
	}
	return entry.record, true, nil
}

func (t *memoryTx) LockTokenForCredential(tokenHash [32]byte) (StoredToken, bool, error) {
	return t.LookupToken(tokenHash)
}

func (t *memoryTx) LockRequest(requestID string) (StoredRequest, bool, error) {
	rec, ok := t.m.reqs[requestID]
	if !ok || rec.TenantID != t.tenantID {
		return StoredRequest{}, false, nil
	}
	return *rec, true, nil
}

func (t *memoryTx) MarkIssued(requestID string, tokenHash [32]byte, _ time.Time) error {
	rec, ok := t.m.reqs[requestID]
	if !ok || rec.TenantID != t.tenantID {
		return ErrInvalidToken
	}
	tok, ok := t.m.tokens[tokenHash]
	if !ok || tok.tenantID != t.tenantID {
		return ErrInvalidToken
	}
	rec.IssuanceState = issuanceIssued
	tok.record.Used = true
	return nil
}

func (t *memoryTx) AppendAudit(rec AuditRecord) error {
	t.m.audit.appendRecord(rec)
	return nil
}

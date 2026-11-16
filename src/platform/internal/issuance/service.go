package issuance

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultAccessTokenTTL bounds both integration and OID4VCI access tokens.
	DefaultAccessTokenTTL = 5 * time.Minute

	minIdempotencyKeyLen = 16
	maxIdempotencyKeyLen = 128

	tokenClassOID4VCI = "oid4vci"

	offerReady    = "ready"
	offerRedeemed = "redeemed"
	offerExpired  = "expired"

	issuancePrepared = "prepared"
	issuanceIssued   = "issued"
)

var (
	// ErrInvalidRequest reports a structurally invalid request.
	ErrInvalidRequest = errors.New("malformed request")
	// ErrIdempotencyConflict reports an Idempotency-Key reused with a different body.
	ErrIdempotencyConflict = errors.New("idempotency key reused with a different request")
	// ErrUnsupportedDelivery reports a delivery option outside the v0 profile.
	ErrUnsupportedDelivery = errors.New("delivery option not supported")
	// ErrInvalidGrant reports an unknown, expired or already-redeemed grant.
	ErrInvalidGrant = errors.New("invalid or expired grant")
	// ErrInvalidToken reports a missing, expired, wrong-class or already-used token.
	ErrInvalidToken = errors.New("invalid access token")
	// ErrInvalidNonce reports a c_nonce that is unknown, expired or already used.
	ErrInvalidNonce = errors.New("invalid c_nonce")
	// ErrUnknownCredentialIdentifier reports a credential identifier the token does not grant.
	ErrUnknownCredentialIdentifier = errors.New("unknown credential identifier")
)

// ServiceConfig wires the Phase 3 issuance service. Everything with a side
// effect (clock, entropy) is injected so expiry and replay can be tested.
type ServiceConfig struct {
	// ClaimsKey is the 32-byte AES-256-GCM key that protects claims and stored
	// offers at rest. A KMS-managed key replaces it in production.
	ClaimsKey        []byte
	ClaimsKeyVersion string
	Clients          *ClientRegistry
	Definitions      *DefinitionRegistry
	Audit            *AuditLog
	// AuthorizationServer is the public base URL of the token endpoint host.
	AuthorizationServer string
	Now                 func() time.Time
	Random              io.Reader
	OfferTTL            time.Duration
	AccessTokenTTL      time.Duration
}

type issuerEntry struct {
	record IssuerRecord
	ring   *KeyRing
}

type requestRecord struct {
	id            string
	tenantID      string
	issuerID      string
	clientID      string
	defID         string
	defVersion    string
	configID      string
	claimsCipher  []byte
	claimsNonce   []byte
	keyVersion    string
	offerRef      string
	offerState    string
	issuanceState string
	createdAt     time.Time
	expiresAt     time.Time
}

type offerDelivery struct {
	requestID string
	slug      string
	cipher    []byte
	nonce     []byte
}

type idempotencyEntry struct {
	hash   [32]byte
	result IssuanceRequestResult
}

type accessRecord struct {
	class       string
	audience    string
	expiresAt   time.Time
	integration IntegrationToken
	requestID   string
	credID      string
	used        bool
}

// Service is the Phase 3 issuance orchestrator. It is in-memory by design: the
// ports it needs (stores for requests, offers, idempotency and tokens) map one
// to one to the PostgreSQL tables of the data model.
type Service struct {
	cfg     ServiceConfig
	aead    cipher.AEAD
	offers  *OfferStore
	nonces  *NonceStore
	mu      sync.Mutex
	byID    map[string]*issuerEntry
	bySlug  map[string]*issuerEntry
	reqs    map[string]*requestRecord
	idem    map[string]idempotencyEntry
	deliver map[string]*offerDelivery
	tokens  map[[32]byte]*accessRecord
}

// NewService validates the configuration and builds the service.
func NewService(cfg ServiceConfig) (*Service, error) {
	if len(cfg.ClaimsKey) != 32 || strings.TrimSpace(cfg.ClaimsKeyVersion) == "" ||
		cfg.Clients == nil || cfg.Definitions == nil {
		return nil, ErrInvalidFoundationInput
	}
	block, err := aes.NewCipher(cfg.ClaimsKey)
	if err != nil {
		return nil, ErrInvalidFoundationInput
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidFoundationInput
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}
	if cfg.OfferTTL <= 0 || cfg.OfferTTL > MaxOfferTTL {
		cfg.OfferTTL = MaxOfferTTL
	}
	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = DefaultAccessTokenTTL
	}
	if cfg.AuthorizationServer == "" {
		cfg.AuthorizationServer = AuthorizationServerURL
	}
	cfg.ClaimsKey = append([]byte(nil), cfg.ClaimsKey...)
	return &Service{
		cfg:     cfg,
		aead:    aead,
		offers:  NewOfferStore(cfg.Random),
		nonces:  NewNonceStore(DefaultNonceTTL, cfg.Random),
		byID:    map[string]*issuerEntry{},
		bySlug:  map[string]*issuerEntry{},
		reqs:    map[string]*requestRecord{},
		idem:    map[string]idempotencyEntry{},
		deliver: map[string]*offerDelivery{},
		tokens:  map[[32]byte]*accessRecord{},
	}, nil
}

// RegisterIssuer makes an issuer and its key ring reachable by the service.
func (s *Service) RegisterIssuer(record IssuerRecord, ring *KeyRing) error {
	if ring == nil || record.TenantID == "" || record.IssuerID == "" ||
		ring.tenantID != record.TenantID || ring.issuer != record.IssuerURI ||
		ValidateIssuerIdentifier(record.IssuerURI) != nil || reservedSlugs[record.Slug] {
		return ErrInvalidFoundationInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.byID[record.IssuerID]; dup {
		return ErrInvalidFoundationInput
	}
	if _, dup := s.bySlug[record.Slug]; dup {
		return ErrInvalidFoundationInput
	}
	entry := &issuerEntry{record: record, ring: ring}
	s.byID[record.IssuerID] = entry
	s.bySlug[record.Slug] = entry
	return nil
}

func (s *Service) now() time.Time { return s.cfg.Now().UTC() }

func (s *Service) randomID(prefix string) (string, error) {
	buf := make([]byte, 16)
	if _, err := io.ReadFull(s.cfg.Random, buf); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

func newUUID(random io.Reader) (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(random, b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func (s *Service) seal(plaintext []byte, aad string) (ciphertext, nonce []byte, err error) {
	nonce = make([]byte, s.aead.NonceSize())
	if _, err = io.ReadFull(s.cfg.Random, nonce); err != nil {
		return nil, nil, err
	}
	return s.aead.Seal(nil, nonce, plaintext, []byte(aad)), nonce, nil
}

func (s *Service) open(ciphertext, nonce []byte, aad string) ([]byte, error) {
	return s.aead.Open(nil, nonce, ciphertext, []byte(aad))
}

func claimsAAD(tenantID, issuerID, requestID string) string {
	return "hukid/claims/v1|" + tenantID + "|" + issuerID + "|" + requestID
}

func offerAAD(tenantID, issuerID, ref string) string {
	return "hukid/offer/v1|" + tenantID + "|" + issuerID + "|" + ref
}

// DeliveryInput selects how the offer reaches the holder. Only the low-risk
// pre-authorized flow without tx_code exists in v0.
type DeliveryInput struct {
	Flow             string `json:"flow,omitempty"`
	ExpiresInSeconds int    `json:"expiresInSeconds,omitempty"`
	TxCodeRequired   bool   `json:"txCodeRequired,omitempty"`
}

// SourceInput identifies the originating record in the caller's system.
type SourceInput struct {
	System    string `json:"system,omitempty"`
	Reference string `json:"reference,omitempty"`
}

// IssuanceRequestInput is the body of POST /v1/issuance-requests.
type IssuanceRequestInput struct {
	IssuerID             string         `json:"issuerId"`
	CredentialDefinition string         `json:"credentialDefinition"`
	Claims               map[string]any `json:"claims"`
	Delivery             *DeliveryInput `json:"delivery,omitempty"`
	Source               *SourceInput   `json:"source,omitempty"`
}

// IssuanceRequestResult is the Integration API view of an issuance request.
type IssuanceRequestResult struct {
	ID                        string    `json:"id"`
	OfferState                string    `json:"offerState"`
	IssuanceState             string    `json:"issuanceState"`
	IssuerID                  string    `json:"issuerId"`
	CredentialConfigurationID string    `json:"credentialConfigurationId"`
	CredentialOfferURI        string    `json:"credentialOfferUri,omitempty"`
	ExpiresAt                 time.Time `json:"expiresAt"`
	CreatedAt                 time.Time `json:"createdAt"`
}

// CreateIssuanceRequest implements HK-010/HK-011: authorize, deduplicate by
// Idempotency-Key, validate claims against a published definition, store the
// claims encrypted and return a one-use offer reference. replay is true when the
// key already produced this exact request.
func (s *Service) CreateIssuanceRequest(token IntegrationToken, idempotencyKey string, in IssuanceRequestInput) (IssuanceRequestResult, bool, error) {
	if len(idempotencyKey) < minIdempotencyKeyLen || len(idempotencyKey) > maxIdempotencyKeyLen ||
		strings.TrimSpace(in.IssuerID) == "" || len(in.Claims) == 0 {
		return IssuanceRequestResult{}, false, ErrInvalidRequest
	}
	delivery := DeliveryInput{Flow: "pre-authorized_code"}
	if in.Delivery != nil {
		delivery = *in.Delivery
	}
	if delivery.Flow == "" {
		delivery.Flow = "pre-authorized_code"
	}
	if delivery.Flow != "pre-authorized_code" || delivery.TxCodeRequired {
		return IssuanceRequestResult{}, false, ErrUnsupportedDelivery
	}
	offerTTL := s.cfg.OfferTTL
	if delivery.ExpiresInSeconds < 0 || time.Duration(delivery.ExpiresInSeconds)*time.Second > MaxOfferTTL {
		return IssuanceRequestResult{}, false, ErrInvalidRequest
	}
	if delivery.ExpiresInSeconds > 0 {
		offerTTL = time.Duration(delivery.ExpiresInSeconds) * time.Second
	}
	if in.Source != nil && (len(in.Source.System) > 128 || len(in.Source.Reference) > 128) {
		return IssuanceRequestResult{}, false, ErrInvalidRequest
	}
	hashInput, err := json.Marshal(in)
	if err != nil {
		return IssuanceRequestResult{}, false, ErrInvalidRequest
	}
	requestHash := sha256.Sum256(hashInput)
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.byID[in.IssuerID]
	if !ok {
		return IssuanceRequestResult{}, false, ErrResourceNotFound
	}
	tenantID := entry.record.TenantID
	if err := s.cfg.Clients.AuthorizeIssuerAccess(token, tenantID, in.IssuerID, ScopeIssuanceCreate, now); err != nil {
		return IssuanceRequestResult{}, false, err
	}
	idemKey := token.ClientID + "\x00" + idempotencyKey
	if prior, seen := s.idem[idemKey]; seen {
		if prior.hash != requestHash {
			return IssuanceRequestResult{}, false, ErrIdempotencyConflict
		}
		return prior.result, true, nil
	}
	if entry.record.State != IssuerActive {
		return IssuanceRequestResult{}, false, ErrDefinitionUnavailable
	}
	defID, defVersion, err := ParseDefinitionRef(in.CredentialDefinition)
	if err != nil {
		return IssuanceRequestResult{}, false, ErrDefinitionNotFound
	}
	def, err := s.cfg.Definitions.GetIssuable(tenantID, in.IssuerID, defID, defVersion)
	if err != nil {
		return IssuanceRequestResult{}, false, err
	}
	if err := def.ValidateClaims(in.Claims); err != nil {
		return IssuanceRequestResult{}, false, err
	}

	requestID, err := s.randomID("ir_")
	if err != nil {
		return IssuanceRequestResult{}, false, ErrInvalidRequest
	}
	ref, err := s.randomID("ofr_")
	if err != nil {
		return IssuanceRequestResult{}, false, ErrInvalidRequest
	}
	claimsJSON, err := json.Marshal(in.Claims)
	if err != nil {
		return IssuanceRequestResult{}, false, ErrInvalidRequest
	}
	claimsCipher, claimsNonce, err := s.seal(claimsJSON, claimsAAD(tenantID, in.IssuerID, requestID))
	if err != nil {
		return IssuanceRequestResult{}, false, ErrInvalidRequest
	}
	// The offer store only learns an opaque request id: no claim ever reaches it.
	offer, err := s.offers.CreateOffer(entry.record.IssuerURI, def.ConfigurationID, map[string]any{"request_id": requestID}, now, offerTTL)
	if err != nil {
		return IssuanceRequestResult{}, false, ErrInvalidRequest
	}
	offerJSON, err := json.Marshal(offer)
	if err != nil {
		return IssuanceRequestResult{}, false, ErrInvalidRequest
	}
	offerCipher, offerNonce, err := s.seal(offerJSON, offerAAD(tenantID, in.IssuerID, ref))
	if err != nil {
		return IssuanceRequestResult{}, false, ErrInvalidRequest
	}

	record := &requestRecord{
		id: requestID, tenantID: tenantID, issuerID: in.IssuerID, clientID: token.ClientID,
		defID: defID, defVersion: defVersion, configID: def.ConfigurationID,
		claimsCipher: claimsCipher, claimsNonce: claimsNonce, keyVersion: s.cfg.ClaimsKeyVersion,
		offerRef: ref, offerState: offerReady, issuanceState: issuancePrepared,
		createdAt: now, expiresAt: now.Add(offerTTL),
	}
	s.reqs[requestID] = record
	s.deliver[ref] = &offerDelivery{requestID: requestID, slug: entry.record.Slug, cipher: offerCipher, nonce: offerNonce}

	result := IssuanceRequestResult{
		ID: requestID, OfferState: offerReady, IssuanceState: issuancePrepared,
		IssuerID: in.IssuerID, CredentialConfigurationID: def.ConfigurationID,
		CredentialOfferURI: "openid-credential-offer://?credential_offer_uri=" +
			url.QueryEscape(entry.record.IssuerURI+"/offers/"+ref),
		ExpiresAt: record.expiresAt, CreatedAt: now,
	}
	s.idem[idemKey] = idempotencyEntry{hash: requestHash, result: result}
	s.cfg.Audit.Record(tenantID, token.ClientID, "issuance_request.created", requestID, "succeeded", "", now)
	return result, false, nil
}

// GetRequest implements the read side of HK-012. A request that belongs to
// another tenant or client is indistinguishable from a missing one.
func (s *Service) GetRequest(token IntegrationToken, requestID string) (IssuanceRequestResult, error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.reqs[requestID]
	if !ok || rec.tenantID != token.TenantID || rec.clientID != token.ClientID {
		return IssuanceRequestResult{}, ErrResourceNotFound
	}
	if err := s.cfg.Clients.AuthorizeIssuerAccess(token, rec.tenantID, rec.issuerID, ScopeIssuanceRead, now); err != nil {
		return IssuanceRequestResult{}, err
	}
	offerState := rec.offerState
	if offerState == offerReady && !now.Before(rec.expiresAt) {
		offerState = offerExpired
	}
	return IssuanceRequestResult{
		ID: rec.id, OfferState: offerState, IssuanceState: rec.issuanceState,
		IssuerID: rec.issuerID, CredentialConfigurationID: rec.configID,
		ExpiresAt: rec.expiresAt, CreatedAt: rec.createdAt,
	}, nil
}

// TokenResponse is the body of a successful token endpoint response.
type TokenResponse struct {
	AccessToken          string                `json:"access_token"`
	TokenType            string                `json:"token_type"`
	ExpiresIn            int                   `json:"expires_in"`
	Scope                string                `json:"scope,omitempty"`
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details,omitempty"`
}

// AuthorizationDetail is the OID4VCI authorization_details entry returned with
// the token so the wallet can ask for a specific credential identifier.
type AuthorizationDetail struct {
	Type                      string   `json:"type"`
	CredentialConfigurationID string   `json:"credential_configuration_id"`
	CredentialIdentifiers     []string `json:"credential_identifiers"`
}

func (s *Service) storeToken(rec *accessRecord) (string, error) {
	raw, err := generateOpaqueToken(s.cfg.Random)
	if err != nil {
		return "", err
	}
	s.tokens[sha256.Sum256([]byte(raw))] = rec
	return raw, nil
}

// ClientCredentialsToken authenticates an integration client (HK-004/HK-013) and
// returns an opaque access token of class "integration".
func (s *Service) ClientCredentialsToken(clientID, clientSecret string, scopes []string) (TokenResponse, error) {
	now := s.now()
	integration, err := s.cfg.Clients.AuthenticateClient(clientID, clientSecret, scopes, now)
	if err != nil {
		return TokenResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := s.storeToken(&accessRecord{
		class: IntegrationTokenClass, audience: IntegrationAudience,
		expiresAt: integration.ExpiresAt, integration: integration,
	})
	if err != nil {
		return TokenResponse{}, ErrInvalidRequest
	}
	return TokenResponse{
		AccessToken: raw, TokenType: "Bearer",
		ExpiresIn: int(integration.ExpiresAt.Sub(now) / time.Second),
		Scope:     strings.Join(integration.Scopes, " "),
	}, nil
}

// PreAuthorizedToken redeems a pre-authorized code exactly once (HK-011/HK-021)
// and returns an opaque access token of class "oid4vci" whose audience is the
// issuer identifier.
func (s *Service) PreAuthorizedToken(code string) (TokenResponse, error) {
	now := s.now()
	offer, err := s.offers.RedeemOffer(code, now)
	if err != nil {
		return TokenResponse{}, ErrInvalidGrant
	}
	requestID, _ := offer.SubjectClaims["request_id"].(string)

	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.reqs[requestID]
	if !ok || rec.offerState != offerReady {
		return TokenResponse{}, ErrInvalidGrant
	}
	rec.offerState = offerRedeemed
	credID, err := s.randomID("cred_")
	if err != nil {
		return TokenResponse{}, ErrInvalidRequest
	}
	expires := now.Add(s.cfg.AccessTokenTTL)
	raw, err := s.storeToken(&accessRecord{
		class: tokenClassOID4VCI, audience: offer.Issuer, expiresAt: expires,
		requestID: requestID, credID: credID,
	})
	if err != nil {
		return TokenResponse{}, ErrInvalidRequest
	}
	s.cfg.Audit.Record(rec.tenantID, "wallet", "offer.redeemed", requestID, "succeeded", "", now)
	return TokenResponse{
		AccessToken: raw, TokenType: "Bearer", ExpiresIn: int(s.cfg.AccessTokenTTL / time.Second),
		AuthorizationDetails: []AuthorizationDetail{{
			Type: "openid_credential", CredentialConfigurationID: rec.configID,
			CredentialIdentifiers: []string{credID},
		}},
	}, nil
}

func (s *Service) lookupTokenLocked(raw, class, audience string, now time.Time) (*accessRecord, error) {
	if raw == "" {
		return nil, ErrInvalidToken
	}
	rec, ok := s.tokens[sha256.Sum256([]byte(raw))]
	if !ok || rec.class != class || rec.audience != audience || rec.used || !now.Before(rec.expiresAt) {
		return nil, ErrInvalidToken
	}
	return rec, nil
}

// AuthenticateIntegration resolves a bearer token of class "integration".
func (s *Service) AuthenticateIntegration(bearer string) (IntegrationToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.lookupTokenLocked(bearer, IntegrationTokenClass, IntegrationAudience, s.now())
	if err != nil {
		return IntegrationToken{}, err
	}
	return rec.integration, nil
}

// ResolveOffer returns the credential offer a QR points to. It disappears once
// the offer is redeemed or expired.
func (s *Service) ResolveOffer(slug, ref string) (CredentialOffer, error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	delivery, ok := s.deliver[ref]
	if !ok || delivery.slug != slug {
		return CredentialOffer{}, ErrResourceNotFound
	}
	rec := s.reqs[delivery.requestID]
	if rec == nil || rec.offerState != offerReady || !now.Before(rec.expiresAt) {
		return CredentialOffer{}, ErrResourceNotFound
	}
	plain, err := s.open(delivery.cipher, delivery.nonce, offerAAD(rec.tenantID, rec.issuerID, ref))
	if err != nil {
		return CredentialOffer{}, ErrResourceNotFound
	}
	var offer CredentialOffer
	if err := json.Unmarshal(plain, &offer); err != nil {
		return CredentialOffer{}, ErrResourceNotFound
	}
	return offer, nil
}

// IssueNonce returns a fresh single-use c_nonce for the issuer (HK-022).
func (s *Service) IssueNonce(slug string) (string, error) {
	s.mu.Lock()
	_, ok := s.bySlug[slug]
	s.mu.Unlock()
	if !ok {
		return "", ErrResourceNotFound
	}
	return s.nonces.IssueNonce(s.now())
}

// CredentialRequest is the body of POST /{slug}/credential.
type CredentialRequest struct {
	CredentialIdentifier string `json:"credential_identifier"`
	Proofs               struct {
		JWT []string `json:"jwt"`
	} `json:"proofs"`
}

// IssueCredential implements HK-022..HK-024: it authenticates the token, proves
// holder possession, binds the credential to the holder key and signs exactly
// once. The token and the request are burned only after a credential exists.
func (s *Service) IssueCredential(slug, bearer string, req CredentialRequest) (string, error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.bySlug[slug]
	if !ok {
		return "", ErrResourceNotFound
	}
	issuerURI := entry.record.IssuerURI
	acc, err := s.lookupTokenLocked(bearer, tokenClassOID4VCI, issuerURI, now)
	if err != nil {
		return "", err
	}
	if req.CredentialIdentifier == "" || req.CredentialIdentifier != acc.credID {
		return "", ErrUnknownCredentialIdentifier
	}
	if len(req.Proofs.JWT) != 1 {
		return "", ErrInvalidRequest
	}
	proof := req.Proofs.JWT[0]
	nonce, err := PeekProofNonce(proof)
	if err != nil {
		return "", ErrProofInvalid
	}
	jkt, _, err := VerifyHolderProof(proof, issuerURI, nonce, now, DefaultProofSkew)
	if err != nil {
		return "", ErrProofInvalid
	}
	if err := s.nonces.ConsumeNonce(nonce, now); err != nil {
		return "", ErrInvalidNonce
	}

	rec := s.reqs[acc.requestID]
	if rec == nil || rec.issuanceState != issuancePrepared {
		return "", ErrInvalidToken
	}
	def, err := s.cfg.Definitions.GetIssuable(rec.tenantID, rec.issuerID, rec.defID, rec.defVersion)
	if err != nil {
		return "", err
	}
	plain, err := s.open(rec.claimsCipher, rec.claimsNonce, claimsAAD(rec.tenantID, rec.issuerID, rec.id))
	if err != nil {
		return "", ErrInvalidToken
	}
	var claims map[string]any
	if err := json.Unmarshal(plain, &claims); err != nil {
		return "", ErrInvalidToken
	}
	signer, err := entry.ring.ActiveSigner()
	if err != nil {
		return "", err
	}
	credentialID, err := newUUID(s.cfg.Random)
	if err != nil {
		return "", ErrInvalidRequest
	}
	validity := def.DefaultValidity
	if validity <= 0 {
		validity = DefaultCredentialValidity
	}
	until := now.Add(validity)
	input := CredentialInput{
		ID:                "urn:uuid:" + credentialID,
		Contexts:          append([]string{VCDMBaseContext}, def.Contexts...),
		Types:             append([]string{"VerifiableCredential"}, def.Types...),
		ValidFrom:         now,
		ValidUntil:        &until,
		CredentialSubject: claims,
	}
	jws, err := IssueVCJWT(signer, input, jkt)
	if err != nil {
		return "", err
	}
	rec.issuanceState = issuanceIssued
	acc.used = true
	s.cfg.Audit.Record(rec.tenantID, "wallet", "credential.issued", rec.id, "succeeded", "", now)
	return jws, nil
}

// IssuerJWKS implements the public JWKS lookup of the HTTP catalog.
func (s *Service) IssuerJWKS(slug string) (JWKS, bool) {
	s.mu.Lock()
	entry, ok := s.bySlug[slug]
	s.mu.Unlock()
	if !ok {
		return JWKS{}, false
	}
	doc, err := entry.ring.PublicJWKS()
	if err != nil {
		return JWKS{}, false
	}
	return doc, true
}

// IssuerMetadata builds the OID4VCI issuer metadata from the published
// definitions of the issuer.
func (s *Service) IssuerMetadata(slug string) (IssuerMetadata, bool) {
	s.mu.Lock()
	entry, ok := s.bySlug[slug]
	s.mu.Unlock()
	if !ok {
		return IssuerMetadata{}, false
	}
	configs := map[string]CredentialConfigurationMetadata{}
	for _, def := range s.cfg.Definitions.ListPublished(entry.record.TenantID, entry.record.IssuerID) {
		meta := CredentialConfigurationMetadata{
			Format:                               CredentialFormat,
			Scope:                                def.ConfigurationID,
			CryptographicBindingMethodsSupported: []string{"jwk"},
			CredentialSigningAlgValuesSupported:  []string{"ES256"},
			CredentialDefinition:                 CredentialDefinitionMeta{Type: slices.Concat([]string{"VerifiableCredential"}, def.Types)},
			ProofTypesSupported:                  map[string]ProofTypeMetadata{"jwt": {ProofSigningAlgValuesSupported: []string{"ES256"}}},
		}
		if def.Locale != "" {
			meta.CredentialMetadata = &CredentialDisplayMetadata{Display: []DisplayEntry{{Name: def.DisplayName, Locale: def.Locale}}}
		}
		configs[def.ConfigurationID] = meta
	}
	doc := BuildIssuerMetadata(entry.record.IssuerURI, configs)
	doc.AuthorizationServers = []string{s.cfg.AuthorizationServer}
	return doc, true
}

// AuthorizationServerMetadata describes the token endpoint (RFC 8414 subset).
type AuthorizationServerMetadata struct {
	Issuer                                string   `json:"issuer"`
	TokenEndpoint                         string   `json:"token_endpoint"`
	GrantTypesSupported                   []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported     []string `json:"token_endpoint_auth_methods_supported"`
	PreAuthorizedGrantAnonymousAccessSupp bool     `json:"pre-authorized_grant_anonymous_access_supported"`
}

// AuthorizationServer returns the metadata of the single authorization server.
func (s *Service) AuthorizationServer() AuthorizationServerMetadata {
	return AuthorizationServerMetadata{
		Issuer:        s.cfg.AuthorizationServer,
		TokenEndpoint: s.cfg.AuthorizationServer + "/oauth2/token",
		GrantTypesSupported: []string{
			PreAuthorizedGrantType, "client_credentials",
		},
		TokenEndpointAuthMethodsSupported:     []string{"client_secret_post", "none"},
		PreAuthorizedGrantAnonymousAccessSupp: true,
	}
}

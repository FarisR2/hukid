package issuance

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"time"

	"hukid.local/platform/internal/verification"
)

const (
	// DefaultAccessTokenTTL bounds both integration and OID4VCI access tokens.
	DefaultAccessTokenTTL = 5 * time.Minute
	// DefaultDeferredInterval is the recommended wallet polling interval for HK-025.
	DefaultDeferredInterval = 5 * time.Second
	// DefaultDeferredTTL bounds how long a deferred transaction stays pollable.
	DefaultDeferredTTL = 1 * time.Hour

	minIdempotencyKeyLen = 16
	maxIdempotencyKeyLen = 128

	tokenClassOID4VCI = "oid4vci"

	offerReady     = "ready"
	offerRedeemed  = "redeemed"
	offerExpired   = "expired"
	offerCancelled = "cancelled"

	issuancePrepared  = "prepared"
	issuanceDeferred  = "deferred"
	issuanceIssued    = "issued"
	issuanceCancelled = "cancelled"
	issuanceFailed    = "failed"

	// Deferred transaction lifecycle states.
	DeferredStatusPending   = "pending"
	DeferredStatusIssued    = "issued"
	DeferredStatusFailed    = "failed"
	DeferredStatusCancelled = "cancelled"
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
	// ErrIssuancePending tells a polling wallet to retry deferred issuance later.
	ErrIssuancePending = errors.New("issuance pending")
	// ErrInvalidTransactionID rejects unknown, expired or cross-client deferred transaction IDs.
	ErrInvalidTransactionID = errors.New("invalid transaction_id")
	// ErrDeferredDenied reports a deferred issuance that failed or was cancelled.
	ErrDeferredDenied = errors.New("deferred credential request denied")
)

// ServiceConfig wires the Phase 3 issuance service. When Backend is nil, an
// in-memory Backend is built from Clients, Definitions and Audit; when Backend is
// set (for example backed by PostgreSQL), Signers must also be provided.
type ServiceConfig struct {
	// ClaimsKey is the 32-byte AES-256-GCM key that protects claims and stored
	// offers at rest. A KMS-managed key replaces it in production.
	ClaimsKey        []byte
	ClaimsKeyVersion string
	Clients          *ClientRegistry
	Definitions      *DefinitionRegistry
	Audit            *AuditLog
	Backend          Backend
	Signers          SignerResolver
	KeyProvisioner   KeyProvisioner
	// AuthorizationServer is the public base URL of the token endpoint host.
	AuthorizationServer string
	Now                 func() time.Time
	Random              io.Reader
	OfferTTL            time.Duration
	AccessTokenTTL      time.Duration
	StatusListTTL       time.Duration
	DeferredInterval    time.Duration
	DeferredTTL         time.Duration
}

type issuerEntry struct {
	record IssuerRecord
	ring   *KeyRing
}

// Service is the Phase 3 issuance orchestrator. It delegates persistence to a
// tenant-isolated Backend port (in-memory or PostgreSQL) while keeping protocol,
// validation and AES-256-GCM handling in one pure domain unit.
type Service struct {
	cfg     ServiceConfig
	aead    cipher.AEAD
	backend Backend
	mem     *memoryBackend
}

// NewService validates the configuration and builds the service.
func NewService(cfg ServiceConfig) (*Service, error) {
	if len(cfg.ClaimsKey) != 32 || strings.TrimSpace(cfg.ClaimsKeyVersion) == "" {
		return nil, ErrInvalidFoundationInput
	}
	if cfg.Backend == nil && (cfg.Clients == nil || cfg.Definitions == nil) {
		return nil, ErrInvalidFoundationInput
	}
	if cfg.Backend != nil && cfg.Signers == nil {
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
	if cfg.StatusListTTL <= 0 {
		cfg.StatusListTTL = DefaultStatusListTTL
	}
	if cfg.DeferredInterval <= 0 {
		cfg.DeferredInterval = DefaultDeferredInterval
	}
	if cfg.DeferredTTL <= 0 {
		cfg.DeferredTTL = DefaultDeferredTTL
	}
	if cfg.AuthorizationServer == "" {
		cfg.AuthorizationServer = AuthorizationServerURL
	}
	cfg.ClaimsKey = append([]byte(nil), cfg.ClaimsKey...)

	svc := &Service{cfg: cfg, aead: aead}
	if cfg.Backend != nil {
		svc.backend = cfg.Backend
	} else {
		if cfg.Audit == nil {
			cfg.Audit = NewAuditLog(cfg.Random)
			svc.cfg.Audit = cfg.Audit
		}
		svc.mem = newMemoryBackend(cfg)
		svc.backend = svc.mem
	}
	return svc, nil
}

// RegisterIssuer makes an issuer and its key ring reachable in the in-memory backend.
func (s *Service) RegisterIssuer(record IssuerRecord, ring *KeyRing) error {
	if s.mem == nil || ring == nil || record.TenantID == "" || record.IssuerID == "" ||
		ring.tenantID != record.TenantID || ring.issuer != record.IssuerURI ||
		ValidateIssuerIdentifier(record.IssuerURI) != nil || reservedSlugs[record.Slug] {
		return ErrInvalidFoundationInput
	}
	return s.mem.registerIssuer(record, ring)
}

func (s *Service) now() time.Time { return s.cfg.Now().UTC() }

func (s *Service) randomID(prefix string) (string, error) {
	buf := make([]byte, 16)
	if _, err := io.ReadFull(s.cfg.Random, buf); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

func (s *Service) newAudit(tenantID, actorID, action, targetID, outcome, correlationID string, now time.Time) AuditRecord {
	buf := make([]byte, 16)
	_, _ = io.ReadFull(s.cfg.Random, buf)
	return AuditRecord{
		EventID:       "evt_" + base64.RawURLEncoding.EncodeToString(buf),
		TenantID:      tenantID,
		ActorID:       actorID,
		Action:        action,
		TargetID:      targetID,
		Outcome:       outcome,
		CorrelationID: correlationID,
		OccurredAt:    now.UTC(),
	}
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

func deferredVCAAD(tenantID, issuerID, requestID string) string {
	return "hukid/deferred-vc/v1|" + tenantID + "|" + issuerID + "|" + requestID
}

// DeliveryInput selects how the offer reaches the holder. Only the low-risk
// pre-authorized flow without tx_code exists in v0.
type DeliveryInput struct {
	Flow             string `json:"flow,omitempty"`
	ExpiresInSeconds int    `json:"expiresInSeconds,omitempty"`
	TxCodeRequired   bool   `json:"txCodeRequired,omitempty"`
	Deferred         bool   `json:"deferred,omitempty"`
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
	CredentialID              string    `json:"credentialId,omitempty"`
	ExpiresAt                 time.Time `json:"expiresAt"`
	CreatedAt                 time.Time `json:"createdAt"`
}

// OperatorRequestSummary is the minimal operator list view; it deliberately
// has no claims, source reference, offer URI/code, or encrypted fields.
type OperatorRequestSummary struct {
	ID                   string    `json:"id"`
	IssuerID             string    `json:"issuerId"`
	ClientID             string    `json:"clientId"`
	CredentialDefinition string    `json:"credentialDefinition"`
	ConfigurationID      string    `json:"configurationId"`
	OfferState           string    `json:"offerState"`
	IssuanceState        string    `json:"issuanceState"`
	CredentialID         string    `json:"credentialId,omitempty"`
	CreatedAt            time.Time `json:"createdAt"`
	ExpiresAt            time.Time `json:"expiresAt"`
}

// OperatorCredentialSummary contains status and operational references only.
type OperatorCredentialSummary struct {
	CredentialID    string    `json:"credentialId"`
	IssuerID        string    `json:"issuerId"`
	RequestID       string    `json:"requestId"`
	ClientID        string    `json:"clientId"`
	DesiredStatus   string    `json:"desiredStatus"`
	PublishedStatus string    `json:"publishedStatus"`
	StatusVersion   int64     `json:"statusVersion"`
	IssuedAt        time.Time `json:"issuedAt"`
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
	var sourceSystem, sourceReference string
	if in.Source != nil {
		if len(in.Source.System) > 128 || len(in.Source.Reference) > 128 {
			return IssuanceRequestResult{}, false, ErrInvalidRequest
		}
		sourceSystem, sourceReference = in.Source.System, in.Source.Reference
	}
	hashInput, err := json.Marshal(in)
	if err != nil {
		return IssuanceRequestResult{}, false, ErrInvalidRequest
	}
	requestHash := sha256.Sum256(hashInput)
	idempotencyKeyHash := sha256.Sum256([]byte(idempotencyKey))
	now := s.now()

	if strings.TrimSpace(token.TenantID) == "" || token.ClientID == "" {
		return IssuanceRequestResult{}, false, ErrResourceNotFound
	}

	var result IssuanceRequestResult
	var replay bool
	err = s.backend.WithTenantTx(token.TenantID, func(tx Tx) error {
		issuerRec, ok, err := tx.GetIssuerByID(in.IssuerID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrResourceNotFound
		}
		client, clientOK, err := tx.GetClient(token.ClientID)
		if err != nil {
			return err
		}
		var clientPtr *StoredClient
		if clientOK {
			clientPtr = &client
		}
		if err := AuthorizeStoredIssuerAccess(clientPtr, token, issuerRec.TenantID, in.IssuerID, ScopeIssuanceCreate, now); err != nil {
			return err
		}

		prior, seen, err := tx.LockIdempotency(token.ClientID, idempotencyKeyHash)
		if err != nil {
			return err
		}
		if seen {
			if prior.RequestHash != requestHash {
				return ErrIdempotencyConflict
			}
			result, replay = prior.Result, true
			return nil
		}

		if issuerRec.State != IssuerActive {
			return ErrDefinitionUnavailable
		}
		defID, defVersion, err := ParseDefinitionRef(in.CredentialDefinition)
		if err != nil {
			return ErrDefinitionNotFound
		}
		def, err := tx.GetIssuableDefinition(in.IssuerID, defID, defVersion)
		if err != nil {
			return err
		}
		if err := def.ValidateClaims(in.Claims); err != nil {
			return err
		}

		requestID, err := s.randomID("ir_")
		if err != nil {
			return ErrInvalidRequest
		}
		ref, err := s.randomID("ofr_")
		if err != nil {
			return ErrInvalidRequest
		}
		claimsJSON, err := json.Marshal(in.Claims)
		if err != nil {
			return ErrInvalidRequest
		}
		claimsCipher, claimsNonce, err := s.seal(claimsJSON, claimsAAD(issuerRec.TenantID, in.IssuerID, requestID))
		if err != nil {
			return ErrInvalidRequest
		}
		code, err := generateOpaqueToken(s.cfg.Random)
		if err != nil {
			return ErrInvalidRequest
		}
		codeHash := sha256.Sum256([]byte(code))
		offer := CredentialOffer{
			CredentialIssuer:           issuerRec.IssuerURI,
			CredentialConfigurationIDs: []string{def.ConfigurationID},
			Grants: map[string]PreAuthorizedGrant{
				PreAuthorizedGrantType: {PreAuthorizedCode: code},
			},
		}
		offerJSON, err := json.Marshal(offer)
		if err != nil {
			return ErrInvalidRequest
		}
		offerCipher, offerNonce, err := s.seal(offerJSON, offerAAD(issuerRec.TenantID, in.IssuerID, ref))
		if err != nil {
			return ErrInvalidRequest
		}

		expiresAt := now.Add(offerTTL)
		record := StoredRequest{
			ID: requestID, TenantID: issuerRec.TenantID, IssuerID: in.IssuerID, ClientID: token.ClientID,
			DefID: defID, DefVersion: defVersion, ConfigID: def.ConfigurationID,
			ClaimsCipher: claimsCipher, ClaimsNonce: claimsNonce, ClaimsKeyVer: s.cfg.ClaimsKeyVersion,
			OfferRef: ref, OfferCipher: offerCipher, OfferNonce: offerNonce, OfferKeyVer: s.cfg.ClaimsKeyVersion,
			OfferState: offerReady, IssuanceState: issuancePrepared,
			Deferred:     delivery.Deferred,
			SourceSystem: sourceSystem, SourceReference: sourceReference,
			CreatedAt: now, ExpiresAt: expiresAt,
		}
		if err := tx.SaveRequestAndOffer(record, codeHash); err != nil {
			return err
		}

		result = IssuanceRequestResult{
			ID: requestID, OfferState: offerReady, IssuanceState: issuancePrepared,
			IssuerID: in.IssuerID, CredentialConfigurationID: def.ConfigurationID,
			CredentialOfferURI: "openid-credential-offer://?credential_offer_uri=" +
				url.QueryEscape(issuerRec.IssuerURI+"/offers/"+ref),
			ExpiresAt: expiresAt, CreatedAt: now,
		}
		if err := tx.SaveIdempotency(IdempotencyRecord{
			ClientID: token.ClientID, KeyHash: idempotencyKeyHash,
			RequestHash: requestHash, Result: result,
		}); err != nil {
			return err
		}
		return tx.AppendAudit(s.newAudit(issuerRec.TenantID, token.ClientID, "issuance_request.created", requestID, "succeeded", "", now))
	})
	if err != nil {
		return IssuanceRequestResult{}, false, err
	}
	return result, replay, nil
}

// GetRequest implements the read side of HK-012. A request that belongs to
// another tenant or client is indistinguishable from a missing one.
func (s *Service) GetRequest(token IntegrationToken, requestID string) (IssuanceRequestResult, error) {
	if strings.TrimSpace(token.TenantID) == "" || token.ClientID == "" || requestID == "" {
		return IssuanceRequestResult{}, ErrResourceNotFound
	}
	now := s.now()
	var result IssuanceRequestResult
	err := s.backend.WithTenantTx(token.TenantID, func(tx Tx) error {
		rec, ok, err := tx.GetRequestForClient(requestID, token.ClientID)
		if err != nil {
			return err
		}
		if !ok || rec.TenantID != token.TenantID || rec.ClientID != token.ClientID {
			return ErrResourceNotFound
		}
		client, clientOK, err := tx.GetClient(token.ClientID)
		if err != nil {
			return err
		}
		var clientPtr *StoredClient
		if clientOK {
			clientPtr = &client
		}
		if err := AuthorizeStoredIssuerAccess(clientPtr, token, rec.TenantID, rec.IssuerID, ScopeIssuanceRead, now); err != nil {
			return err
		}
		offerState := rec.OfferState
		if offerState == offerReady && !now.Before(rec.ExpiresAt) {
			offerState = offerExpired
		}
		result = IssuanceRequestResult{
			ID: rec.ID, OfferState: offerState, IssuanceState: rec.IssuanceState,
			IssuerID: rec.IssuerID, CredentialConfigurationID: rec.ConfigID,
			CredentialID: rec.IssuedCredentialID,
			ExpiresAt:    rec.ExpiresAt, CreatedAt: rec.CreatedAt,
		}
		return nil
	})
	if err != nil {
		return IssuanceRequestResult{}, err
	}
	return result, nil
}

// CancelRequest implements the owner-scoped cancellation side of HK-012.
// Already-issued requests return ErrInvalidStatusTransition; already-cancelled
// requests are idempotent.
func (s *Service) CancelRequest(token IntegrationToken, requestID string) (IssuanceRequestResult, error) {
	if strings.TrimSpace(token.TenantID) == "" || token.ClientID == "" || requestID == "" {
		return IssuanceRequestResult{}, ErrResourceNotFound
	}
	now := s.now()
	var result IssuanceRequestResult
	err := s.backend.WithTenantTx(token.TenantID, func(tx Tx) error {
		rec, ok, err := tx.LockRequest(requestID)
		if err != nil {
			return err
		}
		if !ok || rec.TenantID != token.TenantID || rec.ClientID != token.ClientID {
			return ErrResourceNotFound
		}
		client, clientOK, err := tx.GetClient(token.ClientID)
		if err != nil {
			return err
		}
		var clientPtr *StoredClient
		if clientOK {
			clientPtr = &client
		}
		if err := AuthorizeStoredIssuerAccess(clientPtr, token, rec.TenantID, rec.IssuerID, ScopeIssuanceCreate, now); err != nil {
			return err
		}
		switch rec.IssuanceState {
		case issuanceIssued:
			return ErrInvalidStatusTransition
		case issuanceCancelled:
			result = IssuanceRequestResult{
				ID: rec.ID, OfferState: rec.OfferState, IssuanceState: rec.IssuanceState,
				IssuerID: rec.IssuerID, CredentialConfigurationID: rec.ConfigID,
				ExpiresAt: rec.ExpiresAt, CreatedAt: rec.CreatedAt,
			}
			return nil
		}
		if err := tx.CancelIssuanceRequest(rec.ID, now); err != nil {
			return err
		}
		if err := tx.AppendAudit(s.newAudit(rec.TenantID, token.ClientID, "issuance_request.cancelled", rec.ID, "succeeded", "", now)); err != nil {
			return err
		}
		offerState := rec.OfferState
		if offerState == offerReady {
			offerState = offerCancelled
		}
		result = IssuanceRequestResult{
			ID: rec.ID, OfferState: offerState, IssuanceState: issuanceCancelled,
			IssuerID: rec.IssuerID, CredentialConfigurationID: rec.ConfigID,
			ExpiresAt: rec.ExpiresAt, CreatedAt: rec.CreatedAt,
		}
		return nil
	})
	if err != nil {
		return IssuanceRequestResult{}, err
	}
	return result, nil
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

// ClientCredentialsToken authenticates an integration client (HK-004/HK-013) and
// returns an opaque access token of class "integration".
func (s *Service) ClientCredentialsToken(clientID, clientSecret string, scopes []string) (TokenResponse, error) {
	if clientID == "" || clientSecret == "" {
		return TokenResponse{}, ErrClientUnauthorized
	}
	now := s.now()
	tenantID, ok, err := s.backend.ResolveTenantByClient(clientID)
	if err != nil || !ok {
		return TokenResponse{}, ErrClientUnauthorized
	}

	var resp TokenResponse
	var deniedAudit *AuditRecord
	err = s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		client, found, err := tx.GetClient(clientID)
		if err != nil {
			return err
		}
		if !found {
			return ErrClientUnauthorized
		}
		integration, authErr := AuthenticateStoredClient(client, clientSecret, scopes, now)
		if authErr != nil {
			rec := s.newAudit(tenantID, clientID, "integration_client.authenticate", clientID, "denied", "", now)
			deniedAudit = &rec
			return ErrClientUnauthorized
		}
		raw, err := generateOpaqueToken(s.cfg.Random)
		if err != nil {
			return ErrInvalidRequest
		}
		tokenHash := sha256.Sum256([]byte(raw))
		if err := tx.SaveToken(tokenHash, StoredToken{
			Class: IntegrationTokenClass, Audience: IntegrationAudience,
			IssuedAt: integration.IssuedAt, ExpiresAt: integration.ExpiresAt,
			Integration: integration,
		}); err != nil {
			return err
		}
		if err := tx.AppendAudit(s.newAudit(tenantID, clientID, "integration_client.authenticate", clientID, "succeeded", "", now)); err != nil {
			return err
		}
		resp = TokenResponse{
			AccessToken: raw, TokenType: "Bearer",
			ExpiresIn: int(integration.ExpiresAt.Sub(now) / time.Second),
			Scope:     strings.Join(integration.Scopes, " "),
		}
		return nil
	})
	if err != nil {
		if deniedAudit != nil {
			_ = s.backend.WithTenantTx(tenantID, func(tx Tx) error {
				return tx.AppendAudit(*deniedAudit)
			})
		}
		return TokenResponse{}, err
	}
	return resp, nil
}

// PreAuthorizedToken redeems a pre-authorized code exactly once (HK-011/HK-021)
// and returns an opaque access token of class "oid4vci" whose audience is the
// issuer identifier.
func (s *Service) PreAuthorizedToken(code string) (TokenResponse, error) {
	if code == "" {
		return TokenResponse{}, ErrInvalidGrant
	}
	now := s.now()
	codeHash := sha256.Sum256([]byte(code))
	tenantID, ok, err := s.backend.ResolveTenantByOfferCode(codeHash)
	if err != nil || !ok {
		return TokenResponse{}, ErrInvalidGrant
	}

	var resp TokenResponse
	err = s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		offer, err := tx.RedeemOfferByCodeHash(codeHash, now)
		if err != nil {
			return ErrInvalidGrant
		}
		credID, err := s.randomID("cred_")
		if err != nil {
			return ErrInvalidRequest
		}
		raw, err := generateOpaqueToken(s.cfg.Random)
		if err != nil {
			return ErrInvalidRequest
		}
		expires := now.Add(s.cfg.AccessTokenTTL)
		if err := tx.SaveToken(sha256.Sum256([]byte(raw)), StoredToken{
			Class: tokenClassOID4VCI, Audience: offer.IssuerURI,
			IssuedAt: now, ExpiresAt: expires,
			RequestID: offer.RequestID, CredID: credID,
		}); err != nil {
			return err
		}
		if err := tx.AppendAudit(s.newAudit(tenantID, "wallet", "offer.redeemed", offer.RequestID, "succeeded", "", now)); err != nil {
			return err
		}
		resp = TokenResponse{
			AccessToken: raw, TokenType: "Bearer", ExpiresIn: int(s.cfg.AccessTokenTTL / time.Second),
			AuthorizationDetails: []AuthorizationDetail{{
				Type: "openid_credential", CredentialConfigurationID: offer.ConfigID,
				CredentialIdentifiers: []string{credID},
			}},
		}
		return nil
	})
	if err != nil {
		return TokenResponse{}, err
	}
	return resp, nil
}

// AuthenticateIntegration resolves a bearer token of class "integration".
func (s *Service) AuthenticateIntegration(bearer string) (IntegrationToken, error) {
	if bearer == "" {
		return IntegrationToken{}, ErrInvalidToken
	}
	now := s.now()
	tokenHash := sha256.Sum256([]byte(bearer))
	tenantID, ok, err := s.backend.ResolveTenantByToken(tokenHash)
	if err != nil || !ok {
		return IntegrationToken{}, ErrInvalidToken
	}
	var out IntegrationToken
	err = s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		rec, found, err := tx.LookupToken(tokenHash)
		if err != nil || !found || rec.Class != IntegrationTokenClass || rec.Audience != IntegrationAudience ||
			rec.Used || !now.Before(rec.ExpiresAt) {
			return ErrInvalidToken
		}
		out = rec.Integration
		return nil
	})
	if err != nil {
		return IntegrationToken{}, err
	}
	return out, nil
}

// ResolveOffer returns the credential offer a QR points to. It disappears once
// the offer is redeemed or expired.
func (s *Service) ResolveOffer(slug, ref string) (CredentialOffer, error) {
	if slug == "" || ref == "" {
		return CredentialOffer{}, ErrResourceNotFound
	}
	now := s.now()
	tenantID, ok, err := s.backend.ResolveTenantBySlug(slug)
	if err != nil || !ok {
		return CredentialOffer{}, ErrResourceNotFound
	}
	var offer CredentialOffer
	err = s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		issuerRec, found, err := tx.GetIssuerBySlug(slug)
		if err != nil || !found {
			return ErrResourceNotFound
		}
		rec, found, err := tx.GetRequestByOfferRef(issuerRec.IssuerID, ref)
		if err != nil || !found || rec.OfferState != offerReady || !now.Before(rec.ExpiresAt) {
			return ErrResourceNotFound
		}
		if rec.OfferKeyVer != s.cfg.ClaimsKeyVersion {
			return ErrResourceNotFound
		}
		plain, err := s.open(rec.OfferCipher, rec.OfferNonce, offerAAD(rec.TenantID, rec.IssuerID, ref))
		if err != nil {
			return ErrResourceNotFound
		}
		if err := json.Unmarshal(plain, &offer); err != nil {
			return ErrResourceNotFound
		}
		return nil
	})
	if err != nil {
		return CredentialOffer{}, ErrResourceNotFound
	}
	return offer, nil
}

// IssueNonce returns a fresh single-use c_nonce for the issuer (HK-022).
func (s *Service) IssueNonce(slug string) (string, error) {
	tenantID, ok, err := s.backend.ResolveTenantBySlug(slug)
	if err != nil || !ok {
		return "", ErrResourceNotFound
	}
	now := s.now()
	nonce, err := generateOpaqueToken(s.cfg.Random)
	if err != nil {
		return "", ErrNonceInvalid
	}
	nonceHash := sha256.Sum256([]byte(nonce))
	err = s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		issuerRec, found, err := tx.GetIssuerBySlug(slug)
		if err != nil || !found {
			return ErrResourceNotFound
		}
		return tx.SaveNonce(issuerRec.IssuerID, nonceHash, now, now.Add(DefaultNonceTTL))
	})
	if err != nil {
		return "", err
	}
	return nonce, nil
}

// CredentialRequest is the body of POST /{slug}/credential.
type CredentialRequest struct {
	CredentialIdentifier string `json:"credential_identifier"`
	Proofs               struct {
		JWT []string `json:"jwt"`
	} `json:"proofs"`
}

func (s *Service) resolveActiveSigner(tx Tx, issuerRec IssuerRecord) (Signer, error) {
	activeKey, err := tx.GetActiveKey(issuerRec.IssuerID)
	if err != nil {
		return nil, err
	}
	if s.cfg.Signers == nil {
		if provider, ok := tx.(activeSignerProvider); ok {
			return provider.ActiveSigner(issuerRec.IssuerID)
		}
		return nil, ErrNoActiveKey
	}
	expectedPub, err := DecodePublicJWK(activeKey.JWK)
	if err != nil {
		return nil, ErrNoActiveKey
	}
	signer, err := s.cfg.Signers(issuerRec.TenantID, issuerRec.IssuerID, issuerRec.IssuerURI, activeKey.KID, activeKey.KMSKeyRef, expectedPub)
	if err != nil || signer == nil {
		return nil, ErrNoActiveKey
	}
	pub := signer.PublicKey()
	if signer.Issuer() != issuerRec.IssuerURI || signer.KeyID() != activeKey.KID || pub == nil || !pub.Equal(expectedPub) {
		return nil, ErrNoActiveKey
	}
	return signer, nil
}

// CredentialOutcome represents either an immediately issued vc+jwt or an
// OID4VCI 1.0 deferred transaction_id + polling interval (HK-025).
type CredentialOutcome struct {
	Credential    string `json:"credential,omitempty"`
	TransactionID string `json:"transaction_id,omitempty"`
	Interval      int    `json:"interval,omitempty"`
}

// IssueCredential implements HK-022..HK-024 for immediate issuance. Requests
// configured for deferred delivery return ErrIssuancePending; callers supporting
// HK-025 should call RequestCredential instead.
func (s *Service) IssueCredential(slug, bearer string, req CredentialRequest) (string, error) {
	out, err := s.RequestCredential(slug, bearer, req)
	if err != nil {
		return "", err
	}
	if out.TransactionID != "" {
		return "", ErrIssuancePending
	}
	return out.Credential, nil
}

// RequestCredential implements HK-022..HK-025 for POST /{slug}/credential.
func (s *Service) RequestCredential(slug, bearer string, req CredentialRequest) (CredentialOutcome, error) {
	if bearer == "" {
		return CredentialOutcome{}, ErrInvalidToken
	}
	now := s.now()
	tenantID, ok, err := s.backend.ResolveTenantBySlug(slug)
	if err != nil || !ok {
		return CredentialOutcome{}, ErrResourceNotFound
	}
	tokenHash := sha256.Sum256([]byte(bearer))

	var out CredentialOutcome
	err = s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		issuerRec, found, err := tx.GetIssuerBySlug(slug)
		if err != nil {
			return err
		}
		if !found {
			return ErrResourceNotFound
		}
		issuerURI := issuerRec.IssuerURI
		acc, found, err := tx.LockTokenForCredential(tokenHash)
		if err != nil || !found || acc.Class != tokenClassOID4VCI || acc.Audience != issuerURI ||
			acc.Used || !now.Before(acc.ExpiresAt) {
			return ErrInvalidToken
		}
		if req.CredentialIdentifier == "" || req.CredentialIdentifier != acc.CredID {
			return ErrUnknownCredentialIdentifier
		}
		if len(req.Proofs.JWT) != 1 {
			return ErrInvalidRequest
		}
		proof := req.Proofs.JWT[0]
		nonce, err := PeekProofNonce(proof)
		if err != nil {
			return ErrProofInvalid
		}
		jkt, _, err := VerifyHolderProof(proof, issuerURI, nonce, now, DefaultProofSkew)
		if err != nil {
			return ErrProofInvalid
		}
		if err := tx.ConsumeNonce(issuerRec.IssuerID, sha256.Sum256([]byte(nonce)), now); err != nil {
			return ErrInvalidNonce
		}

		rec, found, err := tx.LockRequest(acc.RequestID)
		if err != nil || !found || rec.IssuanceState != issuancePrepared {
			return ErrInvalidToken
		}
		def, err := tx.GetIssuableDefinition(rec.IssuerID, rec.DefID, rec.DefVersion)
		if err != nil {
			return err
		}
		if rec.ClaimsKeyVer != s.cfg.ClaimsKeyVersion {
			return ErrInvalidToken
		}
		if rec.Deferred {
			txID, err := s.randomID("tx_")
			if err != nil {
				return ErrInvalidRequest
			}
			intervalSec := int(s.cfg.DeferredInterval / time.Second)
			if intervalSec < 1 {
				intervalSec = 1
			}
			dtx := DeferredTxRecord{
				TxHash:          sha256.Sum256([]byte(txID)),
				TenantID:        rec.TenantID,
				IssuerID:        rec.IssuerID,
				RequestID:       rec.ID,
				TokenHash:       tokenHash,
				Status:          DeferredStatusPending,
				IntervalSeconds: intervalSec,
				CreatedAt:       now,
				ExpiresAt:       now.Add(s.cfg.DeferredTTL),
			}
			if err := tx.CreateDeferredTransaction(dtx, jkt, now); err != nil {
				return err
			}
			if err := tx.AppendAudit(s.newAudit(rec.TenantID, "wallet", "credential.deferred_requested", rec.ID, "succeeded", "", now)); err != nil {
				return err
			}
			out = CredentialOutcome{TransactionID: txID, Interval: intervalSec}
			return nil
		}

		signed, credHandle, err := s.mintAndSaveCredential(tx, issuerRec, rec, def, jkt, now)
		if err != nil {
			return err
		}
		if err := tx.MarkIssued(rec.ID, tokenHash, credHandle, now); err != nil {
			return err
		}
		if err := tx.AppendAudit(s.newAudit(rec.TenantID, "wallet", "credential.issued", rec.ID, "succeeded", "", now)); err != nil {
			return err
		}
		out = CredentialOutcome{Credential: signed}
		return nil
	})
	if err != nil {
		return CredentialOutcome{}, err
	}
	return out, nil
}

func (s *Service) mintAndSaveCredential(tx Tx, issuerRec IssuerRecord, rec StoredRequest, def Definition, holderJKT string, now time.Time) (string, string, error) {
	plain, err := s.open(rec.ClaimsCipher, rec.ClaimsNonce, claimsAAD(rec.TenantID, rec.IssuerID, rec.ID))
	if err != nil {
		return "", "", ErrInvalidToken
	}
	var claims map[string]any
	if err := json.Unmarshal(plain, &claims); err != nil {
		return "", "", ErrInvalidToken
	}
	signer, err := s.resolveActiveSigner(tx, issuerRec)
	if err != nil {
		return "", "", err
	}
	credentialID, err := newUUID(s.cfg.Random)
	if err != nil {
		return "", "", ErrInvalidRequest
	}
	validity := def.DefaultValidity
	if validity <= 0 {
		validity = DefaultCredentialValidity
	}
	until := now.Add(validity)

	credHandle, err := s.randomID("vc_")
	if err != nil {
		return "", "", ErrInvalidRequest
	}
	var statusEntries []CredentialStatusEntry
	var revListID, suspListID string
	var revIdx, suspIdx *int
	for _, purpose := range sortStatusPurposes(def.StatusPurposes) {
		listID, slotIdx, allocErr := tx.AllocateStatusSlot(
			issuerRec.IssuerID,
			purpose,
			DefaultStatusListSize,
			func() (string, error) { return s.randomID("sl_") },
			func(id string, rawBits []byte) (string, time.Time, time.Time, error) {
				vf := now
				vu := now.Add(s.cfg.StatusListTTL)
				signedList, signErr := IssueStatusListVC(signer, id, purpose, rawBits, vf, vu)
				return signedList, vf, vu, signErr
			},
			now,
		)
		if allocErr != nil {
			return "", "", allocErr
		}
		statusEntries = append(statusEntries, BuildCredentialStatusEntry(issuerRec.IssuerURI, purpose, listID, slotIdx))
		idxVal := slotIdx
		if purpose == PurposeRevocation {
			revListID = listID
			revIdx = &idxVal
		} else if purpose == PurposeSuspension {
			suspListID = listID
			suspIdx = &idxVal
		}
	}

	var schemas []CredentialSchemaRef
	if def.PublishSchema {
		schemas = []CredentialSchemaRef{{
			ID:   def.SchemaURL(issuerRec.IssuerURI),
			Type: verification.CredentialSchemaType,
		}}
	}

	input := CredentialInput{
		ID:                "urn:uuid:" + credentialID,
		Contexts:          append([]string{VCDMBaseContext}, def.Contexts...),
		Types:             append([]string{"VerifiableCredential"}, def.Types...),
		ValidFrom:         now,
		ValidUntil:        &until,
		CredentialSubject: claims,
		CredentialStatus:  statusEntries,
		CredentialSchema:  schemas,
	}
	signed, err := IssueVCJWT(signer, input, holderJKT)
	if err != nil {
		return "", "", err
	}
	digestSum := sha256.Sum256([]byte(signed))
	if err := tx.SaveIssuedCredential(IssuedCredentialRecord{
		CredentialID:     credHandle,
		TenantID:         rec.TenantID,
		IssuerID:         rec.IssuerID,
		RequestID:        rec.ID,
		ClientID:         rec.ClientID,
		SigningKID:       signer.KeyID(),
		Digest:           "sha256:" + hex.EncodeToString(digestSum[:]),
		RevocationListID: revListID,
		RevocationIndex:  revIdx,
		SuspensionListID: suspListID,
		SuspensionIndex:  suspIdx,
		DesiredStatus:    CredentialStatusActive,
		PublishedStatus:  CredentialStatusActive,
		StatusVersion:    1,
		IssuedAt:         now,
	}); err != nil {
		return "", "", err
	}
	return signed, credHandle, nil
}

// FulfillDeferredRequest completes asynchronous signing for a pending deferred
// request (HK-025) and stores the resulting vc+jwt encrypted until retrieved.
func (s *Service) FulfillDeferredRequest(tenantID, requestID string) error {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(requestID) == "" {
		return ErrResourceNotFound
	}
	now := s.now()
	return s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		rec, found, err := tx.LockRequest(requestID)
		if err != nil || !found {
			return ErrResourceNotFound
		}
		if rec.IssuanceState != issuanceDeferred || rec.HolderJKT == "" {
			return ErrInvalidStatusTransition
		}
		dtx, found, err := tx.LockDeferredByRequestID(requestID)
		if err != nil || !found || dtx.Status != DeferredStatusPending {
			return ErrInvalidStatusTransition
		}
		issuerRec, found, err := tx.GetIssuerByID(rec.IssuerID)
		if err != nil || !found {
			return ErrResourceNotFound
		}
		def, err := tx.GetIssuableDefinition(rec.IssuerID, rec.DefID, rec.DefVersion)
		if err != nil {
			return err
		}
		signed, credHandle, err := s.mintAndSaveCredential(tx, issuerRec, rec, def, rec.HolderJKT, now)
		if err != nil {
			return err
		}
		vcCipher, vcNonce, err := s.seal([]byte(signed), deferredVCAAD(rec.TenantID, rec.IssuerID, rec.ID))
		if err != nil {
			return ErrInvalidRequest
		}
		if err := tx.CompleteDeferredTransaction(rec.ID, credHandle, vcCipher, vcNonce, s.cfg.ClaimsKeyVersion, now); err != nil {
			return err
		}
		return tx.AppendAudit(s.newAudit(rec.TenantID, "worker", "credential.issued", rec.ID, "succeeded", "", now))
	})
}

// FulfillPendingDeferredRequests drains one bounded, tenant-scoped batch of
// deferred transactions. The worker is expected to be invoked periodically;
// persisted state transitions make repeated invocations safe.
func (s *Service) FulfillPendingDeferredRequests(tenantID string, limit int) (int, error) {
	if strings.TrimSpace(tenantID) == "" || limit < 1 || limit > 500 {
		return 0, ErrInvalidRequest
	}
	var requestIDs []string
	if err := s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		var err error
		requestIDs, err = tx.ListPendingDeferredRequestIDs(limit, s.now())
		return err
	}); err != nil {
		return 0, err
	}
	fulfilled := 0
	for _, requestID := range requestIDs {
		if err := s.FulfillDeferredRequest(tenantID, requestID); err != nil {
			return fulfilled, err
		}
		fulfilled++
	}
	return fulfilled, nil
}

// FailDeferredRequest transitions a pending deferred request to terminal failure.
func (s *Service) FailDeferredRequest(tenantID, requestID, errorCode string) error {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(requestID) == "" || len(errorCode) > 64 {
		return ErrInvalidRequest
	}
	now := s.now()
	return s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		if err := tx.FailDeferredTransaction(requestID, errorCode, now); err != nil {
			return err
		}
		return tx.AppendAudit(s.newAudit(tenantID, "worker", "credential.deferred_failed", requestID, "denied", "", now))
	})
}

// DeferredCredential implements POST /{slug}/deferred_credential (OID4VCI 1.0 §9).
func (s *Service) DeferredCredential(slug, bearer, transactionID string) (string, int, error) {
	if bearer == "" {
		return "", 0, ErrInvalidToken
	}
	if strings.TrimSpace(transactionID) == "" {
		return "", 0, ErrInvalidTransactionID
	}
	now := s.now()
	tenantID, ok, err := s.backend.ResolveTenantBySlug(slug)
	if err != nil || !ok {
		return "", 0, ErrResourceNotFound
	}
	tokenHash := sha256.Sum256([]byte(bearer))
	txHash := sha256.Sum256([]byte(transactionID))

	var vcJWT string
	var retryInterval int
	err = s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		issuerRec, found, err := tx.GetIssuerBySlug(slug)
		if err != nil || !found {
			return ErrResourceNotFound
		}
		acc, found, err := tx.LockTokenForCredential(tokenHash)
		if err != nil || !found || acc.Class != tokenClassOID4VCI || acc.Audience != issuerRec.IssuerURI ||
			acc.Used || !now.Before(acc.ExpiresAt) {
			return ErrInvalidToken
		}
		dtx, found, err := tx.LockDeferredByTxHash(txHash)
		if err != nil || !found || dtx.IssuerID != issuerRec.IssuerID || dtx.RequestID != acc.RequestID || !now.Before(dtx.ExpiresAt) {
			return ErrInvalidTransactionID
		}
		retryInterval = dtx.IntervalSeconds
		switch dtx.Status {
		case DeferredStatusPending:
			return ErrIssuancePending
		case DeferredStatusFailed, DeferredStatusCancelled:
			_ = tx.MarkDeferredDelivered(txHash, tokenHash, now)
			return ErrDeferredDenied
		case DeferredStatusIssued:
			if dtx.VCKeyVer != s.cfg.ClaimsKeyVersion || len(dtx.VCCipher) == 0 {
				return ErrDeferredDenied
			}
			plain, openErr := s.open(dtx.VCCipher, dtx.VCNonce, deferredVCAAD(dtx.TenantID, dtx.IssuerID, dtx.RequestID))
			if openErr != nil {
				return ErrDeferredDenied
			}
			if err := tx.MarkDeferredDelivered(txHash, tokenHash, now); err != nil {
				return err
			}
			vcJWT = string(plain)
			return nil
		default:
			return ErrDeferredDenied
		}
	})
	if err != nil {
		return "", retryInterval, err
	}
	return vcJWT, 0, nil
}

// IssuerJWKS implements the public JWKS lookup of the HTTP catalog.
func (s *Service) IssuerJWKS(slug string) (JWKS, bool) {
	tenantID, ok, err := s.backend.ResolveTenantBySlug(slug)
	if err != nil || !ok {
		return JWKS{}, false
	}
	var doc JWKS
	err = s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		issuerRec, found, err := tx.GetIssuerBySlug(slug)
		if err != nil || !found {
			return ErrResourceNotFound
		}
		keys, err := tx.ListPublicKeys(issuerRec.IssuerID)
		if err != nil {
			return err
		}
		doc = JWKS{Keys: keys}
		return nil
	})
	if err != nil {
		return JWKS{}, false
	}
	return doc, true
}

// IssuerMetadata builds the OID4VCI issuer metadata from the published
// definitions of the issuer.
func (s *Service) IssuerMetadata(slug string) (IssuerMetadata, bool) {
	tenantID, ok, err := s.backend.ResolveTenantBySlug(slug)
	if err != nil || !ok {
		return IssuerMetadata{}, false
	}
	var doc IssuerMetadata
	err = s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		issuerRec, found, err := tx.GetIssuerBySlug(slug)
		if err != nil || !found {
			return ErrResourceNotFound
		}
		defs, err := tx.ListPublishedDefinitions(issuerRec.IssuerID)
		if err != nil {
			return err
		}
		configs := map[string]CredentialConfigurationMetadata{}
		for _, def := range defs {
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
		doc = BuildIssuerMetadata(issuerRec.IssuerURI, configs)
		doc.AuthorizationServers = []string{s.cfg.AuthorizationServer}
		return nil
	})
	if err != nil {
		return IssuerMetadata{}, false
	}
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

// SuspendCredential suspends an active issued credential and republishes the
// issuer's BitstringStatusListCredential (HK-050).
func (s *Service) SuspendCredential(token IntegrationToken, idempotencyKey, credentialID string, in StatusChangeInput) (StatusChangeResult, bool, error) {
	return s.changeCredentialStatus(token, idempotencyKey, credentialID, "suspend", in)
}

// ReactivateCredential clears a reversible suspension on a non-revoked credential.
func (s *Service) ReactivateCredential(token IntegrationToken, idempotencyKey, credentialID string) (StatusChangeResult, bool, error) {
	return s.changeCredentialStatus(token, idempotencyKey, credentialID, "reactivate", StatusChangeInput{})
}

// RevokeCredential permanently revokes an issued credential; revoked credentials
// cannot transition back to active (HK-050).
func (s *Service) RevokeCredential(token IntegrationToken, idempotencyKey, credentialID string, in StatusChangeInput) (StatusChangeResult, bool, error) {
	return s.changeCredentialStatus(token, idempotencyKey, credentialID, "revoke", in)
}

func (s *Service) changeCredentialStatus(token IntegrationToken, idempotencyKey, credentialID, op string, in StatusChangeInput) (StatusChangeResult, bool, error) {
	if len(idempotencyKey) < minIdempotencyKeyLen || len(idempotencyKey) > maxIdempotencyKeyLen ||
		strings.TrimSpace(credentialID) == "" || len(in.ReasonCode) > 64 || len(in.Comment) > 512 ||
		strings.ContainsAny(in.ReasonCode, " \t\r\n") {
		return StatusChangeResult{}, false, ErrInvalidRequest
	}
	if strings.TrimSpace(token.TenantID) == "" || token.ClientID == "" {
		return StatusChangeResult{}, false, ErrResourceNotFound
	}
	rawReq, err := json.Marshal(struct {
		Op         string `json:"op"`
		CredID     string `json:"credentialId"`
		ReasonCode string `json:"reasonCode,omitempty"`
		Comment    string `json:"comment,omitempty"`
	}{op, credentialID, in.ReasonCode, in.Comment})
	if err != nil {
		return StatusChangeResult{}, false, ErrInvalidRequest
	}
	requestHash := sha256.Sum256(rawReq)
	keyHash := sha256.Sum256([]byte(idempotencyKey))
	now := s.now()

	var result StatusChangeResult
	var replay bool
	err = s.backend.WithTenantTx(token.TenantID, func(tx Tx) error {
		prior, seen, err := tx.LockStatusIdempotency(token.ClientID, keyHash)
		if err != nil {
			return err
		}
		if seen {
			if prior.RequestHash != requestHash {
				return ErrIdempotencyConflict
			}
			result, replay = prior.Result, true
			return nil
		}

		cred, found, err := tx.LockIssuedCredential(credentialID)
		if err != nil {
			return err
		}
		if !found {
			return ErrResourceNotFound
		}
		client, clientOK, err := tx.GetClient(token.ClientID)
		if err != nil {
			return err
		}
		var clientPtr *StoredClient
		if clientOK {
			clientPtr = &client
		}
		if err := AuthorizeStoredIssuerAccess(clientPtr, token, cred.TenantID, cred.IssuerID, ScopeStatusWrite, now); err != nil {
			return err
		}
		issuerRec, found, err := tx.GetIssuerByID(cred.IssuerID)
		if err != nil || !found {
			return ErrResourceNotFound
		}

		var targetListID string
		var targetIndex *int
		var bitVal bool
		var nextStatus, auditAction string
		switch op {
		case "suspend":
			if cred.DesiredStatus != CredentialStatusActive || cred.SuspensionListID == "" || cred.SuspensionIndex == nil {
				return ErrInvalidStatusTransition
			}
			targetListID, targetIndex, bitVal = cred.SuspensionListID, cred.SuspensionIndex, true
			nextStatus, auditAction = CredentialStatusSuspended, "credential.suspended"
			ts := now
			cred.SuspendedAt = &ts
		case "reactivate":
			if cred.DesiredStatus != CredentialStatusSuspended || cred.SuspensionListID == "" || cred.SuspensionIndex == nil {
				return ErrInvalidStatusTransition
			}
			targetListID, targetIndex, bitVal = cred.SuspensionListID, cred.SuspensionIndex, false
			nextStatus, auditAction = CredentialStatusActive, "credential.reactivated"
			cred.SuspendedAt = nil
		case "revoke":
			if cred.DesiredStatus == CredentialStatusRevoked || cred.RevocationListID == "" || cred.RevocationIndex == nil {
				return ErrInvalidStatusTransition
			}
			targetListID, targetIndex, bitVal = cred.RevocationListID, cred.RevocationIndex, true
			nextStatus, auditAction = CredentialStatusRevoked, "credential.revoked"
			ts := now
			cred.RevokedAt = &ts
		default:
			return ErrInvalidRequest
		}

		list, found, err := tx.LockStatusList(cred.IssuerID, targetListID)
		if err != nil || !found {
			return ErrResourceNotFound
		}
		if err := SetBitstringBit(list.RawBits, *targetIndex, bitVal); err != nil {
			return err
		}
		signer, err := s.resolveActiveSigner(tx, issuerRec)
		if err != nil {
			return err
		}
		list.Version++
		list.ValidFrom = now
		list.ValidUntil = now.Add(s.cfg.StatusListTTL)
		list.UpdatedAt = now
		signedList, err := IssueStatusListVC(signer, list.ListID, list.Purpose, list.RawBits, list.ValidFrom, list.ValidUntil)
		if err != nil {
			return err
		}
		list.PublishedVersion = list.Version
		list.PublishedJWT = signedList

		cred.DesiredStatus = nextStatus
		cred.PublishedStatus = nextStatus
		cred.StatusVersion++
		if in.ReasonCode != "" {
			cred.ReasonCode = in.ReasonCode
		}
		if err := tx.SaveStatusListAndCredential(list, cred); err != nil {
			return err
		}
		result = StatusChangeResult{
			CredentialID:      cred.CredentialID,
			State:             "accepted",
			DesiredStatus:     cred.DesiredStatus,
			PublishedStatus:   cred.PublishedStatus,
			StatusListVersion: list.PublishedVersion,
			PropagationState:  "published",
			EffectiveAt:       now,
		}
		if err := tx.SaveStatusIdempotency(StatusIdempotencyRecord{
			ClientID: token.ClientID, KeyHash: keyHash, RequestHash: requestHash, Result: result,
		}); err != nil {
			return err
		}
		return tx.AppendAudit(s.newAudit(cred.TenantID, token.ClientID, auditAction, cred.CredentialID, "succeeded", "", now))
	})
	if err != nil {
		return StatusChangeResult{}, false, err
	}
	return result, replay, nil
}

// ResolveStatusList returns the signed BitstringStatusListCredential JWT for
// public verification (HK-051).
func (s *Service) ResolveStatusList(slug, purpose, listID string) (string, error) {
	if slug == "" || !isValidStatusPurpose(purpose) || strings.TrimSpace(listID) == "" {
		return "", ErrResourceNotFound
	}
	tenantID, ok, err := s.backend.ResolveTenantBySlug(slug)
	if err != nil || !ok {
		return "", ErrResourceNotFound
	}
	var jwt string
	err = s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		issuerRec, found, err := tx.GetIssuerBySlug(slug)
		if err != nil || !found {
			return ErrResourceNotFound
		}
		list, found, err := tx.GetPublishedStatusList(issuerRec.IssuerID, purpose, listID)
		if err != nil || !found || list.PublishedJWT == "" {
			return ErrResourceNotFound
		}
		jwt = list.PublishedJWT
		return nil
	})
	if err != nil {
		return "", ErrResourceNotFound
	}
	return jwt, nil
}

// RotateIssuerKey retires any current active key and activates newKID (HK-002).
func (s *Service) RotateIssuerKey(tenantID, issuerID, newKID, kmsKeyRef string, jwk PublicJWK, actorID, correlationID string) error {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(issuerID) == "" {
		return ErrInvalidFoundationInput
	}
	now := s.now()
	return s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		return tx.RotateKey(issuerID, newKID, kmsKeyRef, jwk, actorID, correlationID, now)
	})
}

// CompromiseIssuerKey transitions kid to compromised, immediately halting
// signing with it, removing it from JWKS and listing impacted credentialIds (HK-052).
func (s *Service) CompromiseIssuerKey(tenantID, issuerID, kid, actorID, correlationID string) (CompromiseKeyReport, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(issuerID) == "" || strings.TrimSpace(kid) == "" {
		return CompromiseKeyReport{}, ErrResourceNotFound
	}
	now := s.now()
	var report CompromiseKeyReport
	err := s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		if err := tx.CompromiseKey(issuerID, kid, actorID, correlationID, now); err != nil {
			return err
		}
		impacted, err := tx.ListIssuedCredentialsByKID(issuerID, kid)
		if err != nil {
			return err
		}
		if impacted == nil {
			impacted = []string{}
		}
		report = CompromiseKeyReport{
			IssuerID:              issuerID,
			KID:                   kid,
			State:                 KeyCompromised,
			ImpactedCredentialIDs: impacted,
		}
		return nil
	})
	if err != nil {
		return CompromiseKeyReport{}, err
	}
	return report, nil
}

// ResolveCredentialSchema renders the immutable JSON Schema for a published or
// retired definition version (VER-T13).
func (s *Service) ResolveCredentialSchema(slug, id, version string) ([]byte, error) {
	return s.resolveDefinitionArtifact(slug, id, version, func(def Definition, issuerURI string) ([]byte, error) {
		return def.BuildJSONSchema(issuerURI)
	})
}

// ResolveDefinitionContext renders the immutable versioned JSON-LD @context
// for a published or retired definition version (Profile §2.6).
func (s *Service) ResolveDefinitionContext(slug, id, version string) ([]byte, error) {
	return s.resolveDefinitionArtifact(slug, id, version, func(def Definition, issuerURI string) ([]byte, error) {
		return def.BuildJSONLDContext(issuerURI)
	})
}

func (s *Service) resolveDefinitionArtifact(slug, id, version string, build func(Definition, string) ([]byte, error)) ([]byte, error) {
	if slug == "" || !definitionIDRe.MatchString(id) || !semverPattern.MatchString(version) {
		return nil, ErrResourceNotFound
	}
	tenantID, ok, err := s.backend.ResolveTenantBySlug(slug)
	if err != nil || !ok {
		return nil, ErrResourceNotFound
	}
	var out []byte
	err = s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		issuerRec, found, err := tx.GetIssuerBySlug(slug)
		if err != nil || !found {
			return ErrResourceNotFound
		}
		def, err := tx.GetPublicDefinition(issuerRec.IssuerID, id, version)
		if err != nil {
			return ErrResourceNotFound
		}
		data, err := build(def, issuerRec.IssuerURI)
		if err != nil {
			return ErrResourceNotFound
		}
		out = data
		return nil
	})
	if err != nil {
		return nil, ErrResourceNotFound
	}
	return out, nil
}

// CreateIssuer creates a new tenant-scoped logical issuer and optionally provisions
// an initial active KMS signing key when initialKID is provided (HK-001, HK-002).
func (s *Service) CreateIssuer(tenantID, issuerID, slug, displayName, initialKID, actorID, correlationID string) (IssuerRecord, PublicJWK, error) {
	if strings.TrimSpace(tenantID) == "" {
		return IssuerRecord{}, PublicJWK{}, ErrInvalidFoundationInput
	}
	if strings.TrimSpace(issuerID) == "" {
		var err error
		issuerID, err = newUUID(s.cfg.Random)
		if err != nil {
			return IssuerRecord{}, PublicJWK{}, ErrInvalidFoundationInput
		}
	}
	now := s.now()
	rec, err := NewIssuerRecord(tenantID, issuerID, slug, displayName, now)
	if err != nil {
		return IssuerRecord{}, PublicJWK{}, err
	}
	var kmsKeyRef string
	var jwk PublicJWK
	if initialKID != "" {
		if len(initialKID) > 128 || strings.TrimSpace(initialKID) != initialKID || strings.ContainsAny(initialKID, " \t\r\n") {
			return IssuerRecord{}, PublicJWK{}, ErrInvalidFoundationInput
		}
		if s.cfg.KeyProvisioner == nil {
			return IssuerRecord{}, PublicJWK{}, ErrNoActiveKey
		}
		kmsKeyRef, jwk, err = s.cfg.KeyProvisioner(tenantID, issuerID, initialKID)
		if err != nil {
			return IssuerRecord{}, PublicJWK{}, err
		}
	}
	if err := s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		return tx.CreateIssuer(rec, initialKID, kmsKeyRef, jwk, actorID, correlationID, now)
	}); err != nil {
		return IssuerRecord{}, PublicJWK{}, err
	}
	return rec, jwk, nil
}

// ListIssuers returns all logical issuers owned by tenantID (HK-001).
func (s *Service) ListIssuers(tenantID string) ([]IssuerRecord, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, ErrInvalidFoundationInput
	}
	var out []IssuerRecord
	err := s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		items, err := tx.ListIssuers()
		if err != nil {
			return err
		}
		out = items
		return nil
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []IssuerRecord{}
	}
	return out, nil
}

// ProvisionAndRotateIssuerKey creates a new P-256 KMS key for newKID and rotates it into active state (HK-002).
func (s *Service) ProvisionAndRotateIssuerKey(tenantID, issuerID, newKID, actorID, correlationID string) (PublicJWK, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(issuerID) == "" {
		return PublicJWK{}, ErrResourceNotFound
	}
	if newKID == "" || len(newKID) > 128 || strings.TrimSpace(newKID) != newKID || strings.ContainsAny(newKID, " \t\r\n") {
		return PublicJWK{}, ErrInvalidFoundationInput
	}
	if s.cfg.KeyProvisioner == nil {
		return PublicJWK{}, ErrNoActiveKey
	}
	if err := s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		if _, found, err := tx.GetIssuerByID(issuerID); err != nil {
			return err
		} else if !found {
			return ErrResourceNotFound
		}
		return nil
	}); err != nil {
		return PublicJWK{}, err
	}
	kmsKeyRef, jwk, err := s.cfg.KeyProvisioner(tenantID, issuerID, newKID)
	if err != nil {
		return PublicJWK{}, err
	}
	now := s.now()
	if err := s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		return tx.RotateKey(issuerID, newKID, kmsKeyRef, jwk, actorID, correlationID, now)
	}); err != nil {
		return PublicJWK{}, err
	}
	return jwk, nil
}

// CreateDraftDefinition registers a new draft credential definition version (HK-003).
func (s *Service) CreateDraftDefinition(def Definition, actorID, correlationID string) (Definition, error) {
	if strings.TrimSpace(def.TenantID) == "" || strings.TrimSpace(def.IssuerID) == "" {
		return Definition{}, ErrInvalidFoundationInput
	}
	if err := ValidateDefinition(def); err != nil {
		return Definition{}, err
	}
	now := s.now()
	var created Definition
	err := s.backend.WithTenantTx(def.TenantID, func(tx Tx) error {
		if err := tx.CreateDraftDefinition(def, actorID, correlationID, now); err != nil {
			return err
		}
		d, err := tx.GetDefinition(def.IssuerID, def.ID, def.Version)
		if err != nil {
			return err
		}
		created = d
		return nil
	})
	if err != nil {
		return Definition{}, err
	}
	return created, nil
}

// ReplaceDraftDefinition updates an existing draft version when expectedETag matches (HK-003).
func (s *Service) ReplaceDraftDefinition(def Definition, expectedETag, actorID, correlationID string) (Definition, error) {
	if strings.TrimSpace(def.TenantID) == "" || strings.TrimSpace(def.IssuerID) == "" {
		return Definition{}, ErrInvalidFoundationInput
	}
	if strings.TrimSpace(expectedETag) == "" {
		return Definition{}, ErrETagMismatch
	}
	if err := ValidateDefinition(def); err != nil {
		return Definition{}, err
	}
	now := s.now()
	var updated Definition
	err := s.backend.WithTenantTx(def.TenantID, func(tx Tx) error {
		current, err := tx.GetDefinition(def.IssuerID, def.ID, def.Version)
		if err != nil {
			return err
		}
		if current.State != DefinitionDraft {
			return ErrDefinitionImmutable
		}
		if DefinitionETag(current) != expectedETag {
			return ErrETagMismatch
		}
		if err := tx.ReplaceDraftDefinition(def, actorID, correlationID, now); err != nil {
			return err
		}
		d, err := tx.GetDefinition(def.IssuerID, def.ID, def.Version)
		if err != nil {
			return err
		}
		updated = d
		return nil
	})
	if err != nil {
		return Definition{}, err
	}
	return updated, nil
}

// PublishDefinition freezes a draft definition version with its SHA-256 content hash (HK-003).
func (s *Service) PublishDefinition(tenantID, issuerID, id, version, actorID, correlationID string) (Definition, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(issuerID) == "" {
		return Definition{}, ErrDefinitionNotFound
	}
	now := s.now()
	var out Definition
	err := s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		d, err := tx.PublishDefinition(issuerID, id, version, actorID, correlationID, now)
		if err != nil {
			return err
		}
		out = d
		return nil
	})
	if err != nil {
		return Definition{}, err
	}
	return out, nil
}

// RetireDefinition marks a published definition version retired (HK-003).
func (s *Service) RetireDefinition(tenantID, issuerID, id, version, actorID, correlationID string) (Definition, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(issuerID) == "" {
		return Definition{}, ErrDefinitionNotFound
	}
	now := s.now()
	var out Definition
	err := s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		d, err := tx.RetireDefinition(issuerID, id, version, actorID, correlationID, now)
		if err != nil {
			return err
		}
		out = d
		return nil
	})
	if err != nil {
		return Definition{}, err
	}
	return out, nil
}

// GetDefinition reads any definition version owned by tenantID/issuerID.
func (s *Service) GetDefinition(tenantID, issuerID, id, version string) (Definition, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(issuerID) == "" {
		return Definition{}, ErrDefinitionNotFound
	}
	var out Definition
	err := s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		d, err := tx.GetDefinition(issuerID, id, version)
		if err != nil {
			return err
		}
		out = d
		return nil
	})
	if err != nil {
		return Definition{}, err
	}
	return out, nil
}

// ListDefinitions returns all definition versions for an issuer in tenantID.
func (s *Service) ListDefinitions(tenantID, issuerID string) ([]Definition, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(issuerID) == "" {
		return nil, ErrResourceNotFound
	}
	var out []Definition
	err := s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		items, err := tx.ListDefinitions(issuerID)
		if err != nil {
			return err
		}
		out = items
		return nil
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []Definition{}
	}
	return out, nil
}

func (s *Service) newClientSecret() (string, error) {
	buf := make([]byte, 24)
	if _, err := io.ReadFull(s.cfg.Random, buf); err != nil {
		return "", err
	}
	return "hks_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// RegisterIntegrationClient registers a tenant-scoped M2M client and returns its secret once (HK-004).
func (s *Service) RegisterIntegrationClient(
	tenantID, clientID, clientName, rawSecret string,
	allowedIssuers, scopes []string,
	expiresAt *time.Time,
	actorID, correlationID string,
) (ClientSummary, string, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(clientName) == "" || len(allowedIssuers) == 0 || len(scopes) == 0 {
		return ClientSummary{}, "", ErrInvalidFoundationInput
	}
	if strings.TrimSpace(clientID) == "" {
		var err error
		clientID, err = newUUID(s.cfg.Random)
		if err != nil {
			return ClientSummary{}, "", ErrInvalidFoundationInput
		}
	}
	if rawSecret == "" {
		var err error
		rawSecret, err = s.newClientSecret()
		if err != nil {
			return ClientSummary{}, "", ErrInvalidFoundationInput
		}
	}
	secretHash, err := HashClientSecret(rawSecret)
	if err != nil {
		return ClientSummary{}, "", err
	}
	now := s.now()
	if expiresAt != nil && !expiresAt.UTC().After(now) {
		return ClientSummary{}, "", ErrInvalidFoundationInput
	}
	issuersCopy := slices.Clone(allowedIssuers)
	slices.Sort(issuersCopy)
	scopesCopy := slices.Clone(scopes)
	slices.Sort(scopesCopy)
	var expCopy *time.Time
	if expiresAt != nil {
		t := expiresAt.UTC()
		expCopy = &t
	}
	summary := ClientSummary{
		ClientID:       clientID,
		TenantID:       tenantID,
		ClientName:     clientName,
		AllowedIssuers: issuersCopy,
		Scopes:         scopesCopy,
		State:          ClientActive,
		CreatedAt:      now,
		ExpiresAt:      expCopy,
	}
	if err := s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		return tx.RegisterClient(summary, secretHash, actorID, correlationID, now)
	}); err != nil {
		return ClientSummary{}, "", err
	}
	return summary, rawSecret, nil
}

// ListIntegrationClients returns secret-free M2M client summaries for tenantID (HK-004).
func (s *Service) ListIntegrationClients(tenantID string) ([]ClientSummary, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, ErrInvalidFoundationInput
	}
	var out []ClientSummary
	err := s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		items, err := tx.ListClients()
		if err != nil {
			return err
		}
		out = items
		return nil
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []ClientSummary{}
	}
	return out, nil
}

// RotateIntegrationClientSecret replaces an active client's secret within tenantID and returns it once (HK-004).
func (s *Service) RotateIntegrationClientSecret(tenantID, clientID, newSecret, actorID, correlationID string) (string, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(clientID) == "" {
		return "", ErrResourceNotFound
	}
	if newSecret == "" {
		var err error
		newSecret, err = s.newClientSecret()
		if err != nil {
			return "", ErrInvalidFoundationInput
		}
	}
	secretHash, err := HashClientSecret(newSecret)
	if err != nil {
		return "", err
	}
	now := s.now()
	if err := s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		return tx.RotateClientSecret(clientID, secretHash, actorID, correlationID, now)
	}); err != nil {
		return "", err
	}
	return newSecret, nil
}

// RevokeIntegrationClient marks an M2M integration client revoked inside tenantID (HK-004).
func (s *Service) RevokeIntegrationClient(tenantID, clientID, actorID, correlationID string) error {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(clientID) == "" {
		return ErrResourceNotFound
	}
	now := s.now()
	return s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		return tx.RevokeClient(clientID, actorID, correlationID, now)
	})
}

// ListAuditEvents lists immutable secret-free issuance audit entries for tenantID (HK-005).
func (s *Service) ListAuditEvents(tenantID, actionFilter string) ([]AuditRecord, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, ErrInvalidFoundationInput
	}
	var out []AuditRecord
	err := s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		items, err := tx.ListAuditEvents(actionFilter)
		if err != nil {
			return err
		}
		out = items
		return nil
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []AuditRecord{}
	}
	return out, nil
}

// ListOperatorRequests returns a metadata-only, tenant-scoped page for the
// operator console. It never decrypts or returns claims or offer material.
func (s *Service) ListOperatorRequests(tenantID string, filter AdminListFilter) ([]OperatorRequestSummary, error) {
	if strings.TrimSpace(tenantID) == "" || filter.Limit < 1 || filter.Limit > 100 || filter.Offset < 0 || filter.Offset > 1_000_000 {
		return nil, ErrInvalidRequest
	}
	var out []OperatorRequestSummary
	err := s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		items, err := tx.ListAdminRequests(filter)
		if err != nil {
			return err
		}
		out = make([]OperatorRequestSummary, 0, len(items))
		for _, item := range items {
			out = append(out, OperatorRequestSummary{ID: item.ID, IssuerID: item.IssuerID, ClientID: item.ClientID,
				CredentialDefinition: item.DefID + "@" + item.DefVersion, ConfigurationID: item.ConfigID,
				OfferState: item.OfferState, IssuanceState: item.IssuanceState,
				CredentialID: item.IssuedCredentialID, CreatedAt: item.CreatedAt, ExpiresAt: item.ExpiresAt})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []OperatorRequestSummary{}
	}
	return out, nil
}

// ListOperatorCredentials returns a metadata-only, tenant-scoped page for the
// operator console. It deliberately excludes credential digests and claims.
func (s *Service) ListOperatorCredentials(tenantID string, filter AdminListFilter) ([]OperatorCredentialSummary, error) {
	if strings.TrimSpace(tenantID) == "" || filter.Limit < 1 || filter.Limit > 100 || filter.Offset < 0 || filter.Offset > 1_000_000 {
		return nil, ErrInvalidRequest
	}
	var out []OperatorCredentialSummary
	err := s.backend.WithTenantTx(tenantID, func(tx Tx) error {
		items, err := tx.ListAdminCredentials(filter)
		if err != nil {
			return err
		}
		out = make([]OperatorCredentialSummary, 0, len(items))
		for _, item := range items {
			out = append(out, OperatorCredentialSummary{CredentialID: item.CredentialID, IssuerID: item.IssuerID,
				RequestID: item.RequestID, ClientID: item.ClientID, DesiredStatus: item.DesiredStatus,
				PublishedStatus: item.PublishedStatus, StatusVersion: item.StatusVersion, IssuedAt: item.IssuedAt})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []OperatorCredentialSummary{}
	}
	return out, nil
}

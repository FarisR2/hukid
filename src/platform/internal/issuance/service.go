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
	// AuthorizationServer is the public base URL of the token endpoint host.
	AuthorizationServer string
	Now                 func() time.Time
	Random              io.Reader
	OfferTTL            time.Duration
	AccessTokenTTL      time.Duration
	StatusListTTL       time.Duration
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
	if cfg.AuthorizationServer == "" {
		cfg.AuthorizationServer = AuthorizationServerURL
	}
	cfg.ClaimsKey = append([]byte(nil), cfg.ClaimsKey...)

	svc := &Service{cfg: cfg, aead: aead}
	if cfg.Backend != nil {
		svc.backend = cfg.Backend
	} else {
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
	CredentialID              string    `json:"credentialId,omitempty"`
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

// IssueCredential implements HK-022..HK-024: it authenticates the token, proves
// holder possession, binds the credential to the holder key and signs exactly
// once. The token and the request are burned only after a credential exists.
func (s *Service) IssueCredential(slug, bearer string, req CredentialRequest) (string, error) {
	if bearer == "" {
		return "", ErrInvalidToken
	}
	now := s.now()
	tenantID, ok, err := s.backend.ResolveTenantBySlug(slug)
	if err != nil || !ok {
		return "", ErrResourceNotFound
	}
	tokenHash := sha256.Sum256([]byte(bearer))

	var jws string
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
		plain, err := s.open(rec.ClaimsCipher, rec.ClaimsNonce, claimsAAD(rec.TenantID, rec.IssuerID, rec.ID))
		if err != nil {
			return ErrInvalidToken
		}
		var claims map[string]any
		if err := json.Unmarshal(plain, &claims); err != nil {
			return ErrInvalidToken
		}
		signer, err := s.resolveActiveSigner(tx, issuerRec)
		if err != nil {
			return err
		}
		credentialID, err := newUUID(s.cfg.Random)
		if err != nil {
			return ErrInvalidRequest
		}
		validity := def.DefaultValidity
		if validity <= 0 {
			validity = DefaultCredentialValidity
		}
		until := now.Add(validity)

		var statusEntries []CredentialStatusEntry
		var revListID, suspListID string
		var revIdx, suspIdx *int
		var credHandle string
		if len(def.StatusPurposes) > 0 {
			credHandle, err = s.randomID("vc_")
			if err != nil {
				return ErrInvalidRequest
			}
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
					return allocErr
				}
				statusEntries = append(statusEntries, BuildCredentialStatusEntry(issuerURI, purpose, listID, slotIdx))
				idxVal := slotIdx
				if purpose == PurposeRevocation {
					revListID = listID
					revIdx = &idxVal
				} else if purpose == PurposeSuspension {
					suspListID = listID
					suspIdx = &idxVal
				}
			}
		}

		input := CredentialInput{
			ID:                "urn:uuid:" + credentialID,
			Contexts:          append([]string{VCDMBaseContext}, def.Contexts...),
			Types:             append([]string{"VerifiableCredential"}, def.Types...),
			ValidFrom:         now,
			ValidUntil:        &until,
			CredentialSubject: claims,
			CredentialStatus:  statusEntries,
		}
		signed, err := IssueVCJWT(signer, input, jkt)
		if err != nil {
			return err
		}
		if credHandle != "" {
			digestSum := sha256.Sum256([]byte(signed))
			if err := tx.SaveIssuedCredential(IssuedCredentialRecord{
				CredentialID:     credHandle,
				TenantID:         rec.TenantID,
				IssuerID:         rec.IssuerID,
				RequestID:        rec.ID,
				ClientID:         rec.ClientID,
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
				return err
			}
		}
		if err := tx.MarkIssued(rec.ID, tokenHash, credHandle, now); err != nil {
			return err
		}
		if err := tx.AppendAudit(s.newAudit(rec.TenantID, "wallet", "credential.issued", rec.ID, "succeeded", "", now)); err != nil {
			return err
		}
		jws = signed
		return nil
	})
	if err != nil {
		return "", err
	}
	return jws, nil
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

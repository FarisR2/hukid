package issuance

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"maps"
	"strings"
	"sync"
	"time"
)

const (
	// MaxOfferTTL enforces the profile section 7.1 ceiling (<= 5 minutes) for
	// anonymous pre-authorized credential offers.
	MaxOfferTTL = 5 * time.Minute

	// DefaultNonceTTL bounds how long a c_nonce stays redeemable.
	DefaultNonceTTL = 5 * time.Minute

	// PreAuthorizedGrantType is the OID4VCI 1.0 pre-authorized code grant URI.
	PreAuthorizedGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

	// AuthorizationServerURL is the default AS identifier for profile section 8.
	AuthorizationServerURL = "https://auth.hukid.pe"

	tokenEntropyBytes = 32
)

var (
	// ErrOfferInvalid indicates a missing, expired, malformed or already-redeemed offer.
	ErrOfferInvalid = errors.New("credential offer invalid or expired")
	// ErrNonceInvalid indicates a missing, expired or already-consumed c_nonce.
	ErrNonceInvalid = errors.New("c_nonce invalid or expired")
)

// CredentialOffer models the OID4VCI Credential Offer JSON payload (profile §7).
type CredentialOffer struct {
	CredentialIssuer           string                        `json:"credential_issuer"`
	CredentialConfigurationIDs []string                      `json:"credential_configuration_ids"`
	Grants                     map[string]PreAuthorizedGrant `json:"grants"`
}

// PreAuthorizedGrant carries the one-time pre-authorized code in a CredentialOffer.
type PreAuthorizedGrant struct {
	PreAuthorizedCode string `json:"pre-authorized_code"`
}

// IssuerMetadata models the static OID4VCI discovery document (profile §8).
type IssuerMetadata struct {
	CredentialIssuer                  string                                     `json:"credential_issuer"`
	AuthorizationServers              []string                                   `json:"authorization_servers"`
	CredentialEndpoint                string                                     `json:"credential_endpoint"`
	DeferredCredentialEndpoint        string                                     `json:"deferred_credential_endpoint,omitempty"`
	NonceEndpoint                     string                                     `json:"nonce_endpoint"`
	CredentialConfigurationsSupported map[string]CredentialConfigurationMetadata `json:"credential_configurations_supported"`
}

// CredentialConfigurationMetadata describes one credential type in IssuerMetadata.
type CredentialConfigurationMetadata struct {
	Format                               string                       `json:"format"`
	Scope                                string                       `json:"scope,omitempty"`
	CryptographicBindingMethodsSupported []string                     `json:"cryptographic_binding_methods_supported"`
	CredentialSigningAlgValuesSupported  []string                     `json:"credential_signing_alg_values_supported"`
	CredentialDefinition                 CredentialDefinitionMeta     `json:"credential_definition"`
	ProofTypesSupported                  map[string]ProofTypeMetadata `json:"proof_types_supported"`
	CredentialMetadata                   *CredentialDisplayMetadata   `json:"credential_metadata,omitempty"`
}

// CredentialDefinitionMeta declares the W3C VC types of a configuration.
type CredentialDefinitionMeta struct {
	Type []string `json:"type"`
}

// ProofTypeMetadata declares accepted proof signing algorithms.
type ProofTypeMetadata struct {
	ProofSigningAlgValuesSupported []string `json:"proof_signing_alg_values_supported"`
}

// CredentialDisplayMetadata groups localized display entries for wallets.
type CredentialDisplayMetadata struct {
	Display []DisplayEntry `json:"display"`
}

// DisplayEntry models one localized visual representation of a credential.
type DisplayEntry struct {
	Name            string `json:"name"`
	Locale          string `json:"locale"`
	BackgroundColor string `json:"background_color,omitempty"`
	TextColor       string `json:"text_color,omitempty"`
}

// BuildIssuerMetadata builds the static OID4VCI discovery payload for issuer.
func BuildIssuerMetadata(issuer string, configs map[string]CredentialConfigurationMetadata) IssuerMetadata {
	base := strings.TrimRight(issuer, "/")
	copied := make(map[string]CredentialConfigurationMetadata, len(configs))
	maps.Copy(copied, configs)
	return IssuerMetadata{
		CredentialIssuer:                  issuer,
		AuthorizationServers:              []string{AuthorizationServerURL},
		CredentialEndpoint:                base + "/credential",
		DeferredCredentialEndpoint:        base + "/deferred_credential",
		NonceEndpoint:                     base + "/nonce",
		CredentialConfigurationsSupported: copied,
	}
}

// OfferRecord stores a hashed pre-authorized offer without retaining the raw code.
type OfferRecord struct {
	codeHash        [32]byte
	Issuer          string
	ConfigurationID string
	SubjectClaims   map[string]any
	ExpiresAt       time.Time
	Redeemed        bool
}

// OfferStore manages in-memory one-time pre-authorized offers for Phase 0 tests.
type OfferStore struct {
	mu     sync.Mutex
	random io.Reader
	offers map[[32]byte]*OfferRecord
}

// NewOfferStore constructs a clean OfferStore; random defaults to crypto/rand.Reader.
func NewOfferStore(random io.Reader) *OfferStore {
	if random == nil {
		random = rand.Reader
	}
	return &OfferStore{
		random: random,
		offers: map[[32]byte]*OfferRecord{},
	}
}

// CreateOffer registers a hashed one-time offer and returns the public OID4VCI
// CredentialOffer containing the raw pre-authorized code once.
func (s *OfferStore) CreateOffer(issuer, configurationID string, claims map[string]any, now time.Time, ttl time.Duration) (CredentialOffer, error) {
	if err := ValidateIssuerIdentifier(issuer); err != nil {
		return CredentialOffer{}, ErrOfferInvalid
	}
	if strings.TrimSpace(configurationID) == "" || len(claims) == 0 {
		return CredentialOffer{}, ErrOfferInvalid
	}
	if ttl <= 0 {
		ttl = MaxOfferTTL
	}
	if ttl > MaxOfferTTL {
		return CredentialOffer{}, ErrOfferInvalid
	}
	code, err := generateOpaqueToken(s.random)
	if err != nil {
		return CredentialOffer{}, ErrOfferInvalid
	}
	hash := sha256.Sum256([]byte(code))

	claimsCopy := make(map[string]any, len(claims))
	maps.Copy(claimsCopy, claims)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.offers[hash] = &OfferRecord{
		codeHash:        hash,
		Issuer:          issuer,
		ConfigurationID: configurationID,
		SubjectClaims:   claimsCopy,
		ExpiresAt:       now.UTC().Add(ttl),
	}
	return CredentialOffer{
		CredentialIssuer:           issuer,
		CredentialConfigurationIDs: []string{configurationID},
		Grants: map[string]PreAuthorizedGrant{
			PreAuthorizedGrantType: {PreAuthorizedCode: code},
		},
	}, nil
}

// RedeemOffer atomically consumes a valid pre-authorized code once.
// A missing, expired or already-redeemed code returns ErrOfferInvalid.
func (s *OfferStore) RedeemOffer(code string, now time.Time) (OfferRecord, error) {
	if code == "" {
		return OfferRecord{}, ErrOfferInvalid
	}
	return s.redeemHashed(sha256.Sum256([]byte(code)), now)
}

func (s *OfferStore) putHashed(hash [32]byte, issuer, configurationID string, claims map[string]any, expiresAt time.Time) {
	claimsCopy := make(map[string]any, len(claims))
	maps.Copy(claimsCopy, claims)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offers[hash] = &OfferRecord{
		codeHash:        hash,
		Issuer:          issuer,
		ConfigurationID: configurationID,
		SubjectClaims:   claimsCopy,
		ExpiresAt:       expiresAt.UTC(),
	}
}

func (s *OfferStore) lookupRequestID(hash [32]byte) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.offers[hash]
	if !ok {
		return "", false
	}
	reqID, _ := rec.SubjectClaims["request_id"].(string)
	return reqID, reqID != ""
}

func (s *OfferStore) cancelByRequestID(requestID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, rec := range s.offers {
		if id, _ := rec.SubjectClaims["request_id"].(string); id == requestID {
			delete(s.offers, hash)
		}
	}
}

func (s *OfferStore) redeemHashed(hash [32]byte, now time.Time) (OfferRecord, error) {
	nowUTC := now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.offers[hash]
	if !ok || subtle.ConstantTimeCompare(rec.codeHash[:], hash[:]) != 1 {
		return OfferRecord{}, ErrOfferInvalid
	}
	if rec.Redeemed || !nowUTC.Before(rec.ExpiresAt) {
		return OfferRecord{}, ErrOfferInvalid
	}
	rec.Redeemed = true
	claimsCopy := make(map[string]any, len(rec.SubjectClaims))
	maps.Copy(claimsCopy, rec.SubjectClaims)
	return OfferRecord{
		codeHash:        rec.codeHash,
		Issuer:          rec.Issuer,
		ConfigurationID: rec.ConfigurationID,
		SubjectClaims:   claimsCopy,
		ExpiresAt:       rec.ExpiresAt,
		Redeemed:        true,
	}, nil
}

type nonceEntry struct {
	hash      [32]byte
	expiresAt time.Time
	used      bool
}

// NonceStore issues and consumes single-use c_nonce tokens for OID4VCI proofs.
type NonceStore struct {
	mu     sync.Mutex
	random io.Reader
	ttl    time.Duration
	nonces map[[32]byte]*nonceEntry
}

// NewNonceStore constructs an in-memory NonceStore. Zero ttl uses DefaultNonceTTL.
func NewNonceStore(ttl time.Duration, random io.Reader) *NonceStore {
	if ttl <= 0 {
		ttl = DefaultNonceTTL
	}
	if random == nil {
		random = rand.Reader
	}
	return &NonceStore{
		random: random,
		ttl:    ttl,
		nonces: map[[32]byte]*nonceEntry{},
	}
}

// IssueNonce creates a fresh high-entropy c_nonce and stores only its SHA-256 hash.
func (s *NonceStore) IssueNonce(now time.Time) (string, error) {
	token, err := generateOpaqueToken(s.random)
	if err != nil {
		return "", ErrNonceInvalid
	}
	hash := sha256.Sum256([]byte(token))

	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces[hash] = &nonceEntry{
		hash:      hash,
		expiresAt: now.UTC().Add(s.ttl),
	}
	return token, nil
}

// ConsumeNonce atomically verifies and burns a c_nonce once.
func (s *NonceStore) ConsumeNonce(nonce string, now time.Time) error {
	if nonce == "" {
		return ErrNonceInvalid
	}
	return s.consumeHash(sha256.Sum256([]byte(nonce)), now)
}

func (s *NonceStore) putHash(hash [32]byte, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces[hash] = &nonceEntry{
		hash:      hash,
		expiresAt: expiresAt.UTC(),
	}
}

func (s *NonceStore) consumeHash(hash [32]byte, now time.Time) error {
	nowUTC := now.UTC()

	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.nonces[hash]
	if !ok || subtle.ConstantTimeCompare(entry.hash[:], hash[:]) != 1 {
		return ErrNonceInvalid
	}
	if entry.used || !nowUTC.Before(entry.expiresAt) {
		return ErrNonceInvalid
	}
	entry.used = true
	return nil
}

func generateOpaqueToken(random io.Reader) (string, error) {
	buf := make([]byte, tokenEntropyBytes)
	if _, err := io.ReadFull(random, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

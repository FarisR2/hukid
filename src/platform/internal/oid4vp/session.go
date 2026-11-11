// Package oid4vp is the OpenID4VP adapter over the verification core (FEAT-004,
// VER-T10, increment a). It builds the signed authorization request for a
// presentation session and turns the encrypted direct_post.jwt response into a
// verification.PresentationReport.
//
// This increment is pure: no HTTP, database or logging. Endpoints and a
// persistent replay store come in later increments. The package consumes
// internal/verification without modifying it and must not import
// internal/authentication (profile section 6: token classes stay separate).
package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	// RequestObjectType is the typ header of the signed request object (RFC 9101).
	RequestObjectType = "oauth-authz-req+jwt"
	// ResponseModeDirectPostJWT is the only response mode of the MVP (profile 9.3).
	ResponseModeDirectPostJWT = "direct_post.jwt"
	// CredentialFormat is the HukID credential format identifier (profile 2).
	CredentialFormat = "application/vc+jwt"

	// DefaultTTL and MaxTTL bound how long a request can be answered. They are
	// proposed values, not owner-approved ones.
	DefaultTTL = 5 * time.Minute
	MaxTTL     = 15 * time.Minute

	selfIssuedAudience = "https://self-issued.me/v2"
	secretBytes        = 32
)

var (
	// ErrConfig reports an invalid session configuration.
	ErrConfig = errors.New("invalid oid4vp configuration")
	// ErrSessionExpired reports a response that arrived after the request expired.
	ErrSessionExpired = errors.New("presentation request expired")
	// ErrResponseInvalid reports a response that could not be authenticated as
	// an answer to this request. It deliberately carries no detail: the cause
	// (wrong key, wrong algorithm, malformed payload) must not guide an attacker.
	ErrResponseInvalid = errors.New("presentation response invalid")
)

// Config describes one verifier. ClientID and ResponseURI belong to the
// verifier or tenant that hires the service (profile section 10).
type Config struct {
	// ClientID is the verifier client identifier, for example
	// "x509_san_dns:verifier.example". It is also the expected VP audience.
	ClientID string
	// ResponseURI is the exact https URI that receives the direct_post.jwt response.
	ResponseURI string
	// CredentialQueryID names the DCQL credential query. Default "credential".
	CredentialQueryID string
	// TTL bounds the session. Zero means DefaultTTL; above MaxTTL is rejected.
	TTL time.Duration
}

func (c Config) normalized() (Config, error) {
	if c.CredentialQueryID == "" {
		c.CredentialQueryID = "credential"
	}
	if c.TTL == 0 {
		c.TTL = DefaultTTL
	}
	parsed, err := url.Parse(c.ResponseURI)
	switch {
	case c.ClientID == "" || strings.TrimSpace(c.ClientID) != c.ClientID,
		err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Fragment != "" || parsed.User != nil,
		c.TTL < 0 || c.TTL > MaxTTL,
		strings.ContainsAny(c.CredentialQueryID, " \t\r\n\""):
		return Config{}, ErrConfig
	}
	return c, nil
}

// Session is one presentation request. It owns the nonce, the state and the
// private key that decrypts the response, so it has no String or JSON form and
// must never be logged or persisted outside a store that protects the key.
type Session struct {
	cfg       Config
	nonce     string
	state     string
	kid       string
	encKey    *ecdsa.PrivateKey
	issuedAt  time.Time
	expiresAt time.Time
}

func randomToken(random io.Reader) (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := io.ReadFull(random, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// NewSession creates a request with an unpredictable nonce and state and a
// fresh response-encryption key. random may be nil to use crypto/rand.
func NewSession(cfg Config, now time.Time, random io.Reader) (*Session, error) {
	cfg, err := cfg.normalized()
	if err != nil {
		return nil, err
	}
	if random == nil {
		random = rand.Reader
	}
	nonce, err := randomToken(random)
	if err != nil {
		return nil, ErrConfig
	}
	state, err := randomToken(random)
	if err != nil {
		return nil, ErrConfig
	}
	kid, err := randomToken(random)
	if err != nil {
		return nil, ErrConfig
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return nil, ErrConfig
	}
	now = now.UTC()
	return &Session{cfg: cfg, nonce: nonce, state: state, kid: kid, encKey: key, issuedAt: now, expiresAt: now.Add(cfg.TTL)}, nil
}

// ExpiresAt is when the request stops accepting responses.
func (s *Session) ExpiresAt() time.Time { return s.expiresAt }

// State is the value the wallet must echo; the verifier binds it to the
// browser or caller session that started the request.
func (s *Session) State() string { return s.state }

// RequestObjectClaims returns the claims of the authorization request object
// (profile section 9, items 1, 3 and 4): vp_token, direct_post.jwt, nonce,
// state, exact response URI, DCQL and the encryption JWK in client_metadata.
func (s *Session) RequestObjectClaims() (map[string]any, error) {
	enc := jose.JSONWebKey{Key: &s.encKey.PublicKey, KeyID: s.kid, Use: "enc", Algorithm: string(jose.ECDH_ES)}
	rawKey, err := enc.MarshalJSON()
	if err != nil {
		return nil, ErrConfig
	}
	return map[string]any{
		"iss":           s.cfg.ClientID,
		"aud":           selfIssuedAudience,
		"client_id":     s.cfg.ClientID,
		"response_type": "vp_token",
		"response_mode": ResponseModeDirectPostJWT,
		"response_uri":  s.cfg.ResponseURI,
		"nonce":         s.nonce,
		"state":         s.state,
		"iat":           s.issuedAt.Unix(),
		"exp":           s.expiresAt.Unix(),
		"dcql_query": map[string]any{
			"credentials": []any{map[string]any{
				"id":     s.cfg.CredentialQueryID,
				"format": CredentialFormat,
				"meta":   map[string]any{},
			}},
		},
		"client_metadata": map[string]any{
			"jwks": map[string]any{"keys": []json.RawMessage{rawKey}},
			"encrypted_response_enc_values_supported": []string{string(jose.A256GCM)},
		},
	}, nil
}

// SignRequestObject signs the request object with ES256. chain is the verifier
// certificate chain (leaf first, DER) placed in x5c for the x509_san_dns
// client identifier prefix; it may be empty in the laboratory.
func (s *Session) SignRequestObject(key *ecdsa.PrivateKey, chain [][]byte) (string, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return "", ErrConfig
	}
	claims, err := s.RequestObjectClaims()
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", ErrConfig
	}
	options := (&jose.SignerOptions{}).WithType(RequestObjectType)
	if len(chain) > 0 {
		encoded := make([]string, len(chain))
		for i, der := range chain {
			encoded[i] = base64.StdEncoding.EncodeToString(der)
		}
		options = options.WithHeader("x5c", encoded)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, options)
	if err != nil {
		return "", ErrConfig
	}
	object, err := signer.Sign(payload)
	if err != nil {
		return "", ErrConfig
	}
	return object.CompactSerialize()
}

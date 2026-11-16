// Package issuance implements the Phase 0 cryptographic laboratory of the
// HukID credential issuer (roadmap phase 0, interoperability profile v0.1-draft).
//
// This package is pure: no HTTP handlers, database access, environment lookups
// or logging. It stays strictly decoupled from internal/authentication and
// produces ES256 vc+jwt credentials validated against internal/verification.
package issuance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net/url"
	"strings"
)

const (
	// IssuerPrefix is the canonical base URL for HukID v0 logical issuers (profile 3.2).
	IssuerPrefix = "https://issuer.hukid.pe/"
)

var (
	// ErrInvalidIssuerConfig reports invalid issuer URI, kid or P-256 key configuration.
	ErrInvalidIssuerConfig = errors.New("invalid issuer configuration")
	// ErrSigningFailed reports a failure while signing a credential payload.
	ErrSigningFailed = errors.New("credential signing failed")
)

// Signer abstracts asymmetric ES256 signing for an issuer key ring.
// Production adapters delegate to KMS/HSM without exporting private keys.
type Signer interface {
	Issuer() string
	KeyID() string
	PublicKey() *ecdsa.PublicKey
	Sign(signingInput string) ([]byte, error)
}

// PublicJWK represents a public P-256 JSON Web Key published in JWKS.
type PublicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

// JWKS represents a JSON Web Key Set exposed at /.well-known/jwks.json.
type JWKS struct {
	Keys []PublicJWK `json:"keys"`
}

// MemorySigner is an in-memory ES256 signer for Phase 0 interoperability tests.
type MemorySigner struct {
	issuer string
	kid    string
	key    *ecdsa.PrivateKey
	random io.Reader
}

// ValidateIssuerIdentifier enforces https://issuer.hukid.pe/{slug} with a single
// lowercase slug segment and no query, fragment or userinfo (profile section 3.2).
func ValidateIssuerIdentifier(issuer string) error {
	if !strings.HasPrefix(issuer, IssuerPrefix) {
		return ErrInvalidIssuerConfig
	}
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "issuer.hukid.pe" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ErrInvalidIssuerConfig
	}
	slug := strings.TrimPrefix(issuer, IssuerPrefix)
	if !isValidSlug(slug) {
		return ErrInvalidIssuerConfig
	}
	return nil
}

func isValidSlug(slug string) bool {
	if len(slug) == 0 || len(slug) > 64 || strings.Contains(slug, "/") {
		return false
	}
	for i := 0; i < len(slug); i++ {
		c := slug[i]
		isLower := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		isDash := c == '-' || c == '_'
		if !isLower && !isDigit && !isDash {
			return false
		}
	}
	return slug[0] != '-' && slug[len(slug)-1] != '-'
}

// NewMemorySigner validates issuer, kid and P-256 private key and builds a laboratory Signer.
func NewMemorySigner(issuer, kid string, key *ecdsa.PrivateKey, random io.Reader) (*MemorySigner, error) {
	if err := ValidateIssuerIdentifier(issuer); err != nil {
		return nil, err
	}
	if kid == "" || strings.TrimSpace(kid) != kid || strings.ContainsAny(kid, " \t\r\n") {
		return nil, ErrInvalidIssuerConfig
	}
	if key == nil || key.Curve != elliptic.P256() || !key.Curve.IsOnCurve(key.X, key.Y) || key.D == nil || key.D.Sign() <= 0 {
		return nil, ErrInvalidIssuerConfig
	}
	if random == nil {
		random = rand.Reader
	}
	return &MemorySigner{
		issuer: issuer,
		kid:    kid,
		key:    key,
		random: random,
	}, nil
}

func (s *MemorySigner) Issuer() string { return s.issuer }
func (s *MemorySigner) KeyID() string  { return s.kid }
func (s *MemorySigner) PublicKey() *ecdsa.PublicKey {
	pub := s.key.PublicKey
	return &pub
}

// Sign computes the raw 64-byte ES256 (R || S) signature over signingInput.
func (s *MemorySigner) Sign(signingInput string) ([]byte, error) {
	if signingInput == "" {
		return nil, ErrSigningFailed
	}
	digest := sha256.Sum256([]byte(signingInput))
	der, err := ecdsa.SignASN1(s.random, s.key, digest[:])
	if err != nil {
		return nil, ErrSigningFailed
	}
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &sig); err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil {
		return nil, ErrSigningFailed
	}
	raw := make([]byte, 64)
	sig.R.FillBytes(raw[:32])
	sig.S.FillBytes(raw[32:])
	return raw, nil
}

// JWK exports the public key as a P-256 JWK suitable for JWKS publication.
func (s *MemorySigner) JWK() (PublicJWK, error) {
	return ExportPublicJWK(&s.key.PublicKey, s.kid)
}

// JWKS exports the single-key JWKS document for this laboratory signer.
func (s *MemorySigner) JWKS() (JWKS, error) {
	jwk, err := s.JWK()
	if err != nil {
		return JWKS{}, err
	}
	return JWKS{Keys: []PublicJWK{jwk}}, nil
}

// ExportPublicJWK converts a P-256 public key into a PublicJWK with optional kid.
func ExportPublicJWK(key *ecdsa.PublicKey, kid string) (PublicJWK, error) {
	if key == nil || key.Curve != elliptic.P256() || !key.Curve.IsOnCurve(key.X, key.Y) {
		return PublicJWK{}, ErrInvalidIssuerConfig
	}
	raw, err := key.Bytes()
	if err != nil || len(raw) != 65 {
		return PublicJWK{}, ErrInvalidIssuerConfig
	}
	out := PublicJWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(raw[1:33]),
		Y:   base64.RawURLEncoding.EncodeToString(raw[33:65]),
	}
	if kid != "" {
		out.Kid = kid
		out.Alg = "ES256"
		out.Use = "sig"
	}
	return out, nil
}

// Package issuance implements the Phase 0 cryptographic laboratory of the
// HukID credential issuer (roadmap phase 0, interoperability profile v0.1-draft).
//
// This package is pure: no HTTP handlers, database access, environment lookups
// or logging. It stays strictly decoupled from internal/authentication and
// produces ES256 vc+jwt credentials validated against internal/verification.
package issuance

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
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

// SignerResolver obtains a Signer for an active issuer key persisted in metadata
// storage without storing raw private keys in SQL.
type SignerResolver func(tenantID, issuerID, issuerURI, kid, kmsKeyRef string, expectedPub *ecdsa.PublicKey) (Signer, error)

// KeyProvisioner provisions a non-exportable P-256 key pair inside KMS/HSM for
// an issuer kid and returns its KMS reference and public JWK.
type KeyProvisioner func(tenantID, issuerID, kid string) (kmsKeyRef string, jwk PublicJWK, err error)

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
	return ParseASN1OrRawES256Signature(der)
}

// ParseASN1OrRawES256Signature normalizes either a 64-byte raw (R || S) or
// ASN.1 DER-encoded ECDSA P-256 signature into the 64-byte JWS R || S form.
func ParseASN1OrRawES256Signature(sigBytes []byte) ([]byte, error) {
	order := elliptic.P256().Params().N
	if len(sigBytes) == 64 {
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(order) >= 0 || s.Cmp(order) >= 0 {
			return nil, ErrSigningFailed
		}
		out := make([]byte, 64)
		copy(out, sigBytes)
		return out, nil
	}
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(sigBytes, &sig); err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil {
		return nil, ErrSigningFailed
	}
	if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.Cmp(order) >= 0 || sig.S.Cmp(order) >= 0 {
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

// DecodePublicJWK reconstructs and validates a P-256 public key from a PublicJWK.
func DecodePublicJWK(jwk PublicJWK) (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, ErrInvalidIssuerConfig
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || len(xBytes) != 32 {
		return nil, ErrInvalidIssuerConfig
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil || len(yBytes) != 32 {
		return nil, ErrInvalidIssuerConfig
	}
	raw := make([]byte, 65)
	raw[0] = 0x04
	copy(raw[1:33], xBytes)
	copy(raw[33:65], yBytes)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return nil, ErrInvalidIssuerConfig
	}
	return pub, nil
}

// MarshalP256PrivateKeyPKCS8PEM encodes an ECDSA P-256 private key as PKCS#8 PEM
// for persistent local key files.
func MarshalP256PrivateKeyPKCS8PEM(key *ecdsa.PrivateKey) ([]byte, error) {
	if key == nil || key.Curve != elliptic.P256() || key.D == nil || key.D.Sign() <= 0 || !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, ErrInvalidIssuerConfig
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, ErrInvalidIssuerConfig
	}
	defer clear(der)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseP256PrivateKeyPKCS8PEM parses a PKCS#8 or SEC1 PEM block containing a P-256 private key.
func ParseP256PrivateKeyPKCS8PEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil || len(rest) != 0 {
		return nil, ErrInvalidIssuerConfig
	}
	defer clear(block.Bytes)
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrInvalidIssuerConfig
		}
		ecKey, ok := parsed.(*ecdsa.PrivateKey)
		if !ok || ecKey.Curve != elliptic.P256() || !ecKey.Curve.IsOnCurve(ecKey.X, ecKey.Y) {
			return nil, ErrInvalidIssuerConfig
		}
		return ecKey, nil
	case "EC PRIVATE KEY":
		ecKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil || ecKey.Curve != elliptic.P256() || !ecKey.Curve.IsOnCurve(ecKey.X, ecKey.Y) {
			return nil, ErrInvalidIssuerConfig
		}
		return ecKey, nil
	default:
		return nil, ErrInvalidIssuerConfig
	}
}

// NewMemorySignerFromPEM builds an ES256 Signer from a persistent PEM private key.
func NewMemorySignerFromPEM(issuer, kid string, pemBytes []byte, random io.Reader) (*MemorySigner, error) {
	key, err := ParseP256PrivateKeyPKCS8PEM(pemBytes)
	if err != nil {
		return nil, err
	}
	return NewMemorySigner(issuer, kid, key, random)
}

// SealP256PrivateKey encrypts a PKCS#8 P-256 private key with AES-256-GCM under a 32-byte KEK.
func SealP256PrivateKey(key *ecdsa.PrivateKey, kek []byte, aad string, random io.Reader) (ciphertext, nonce []byte, err error) {
	if len(kek) != 32 || key == nil || key.Curve != elliptic.P256() {
		return nil, nil, ErrInvalidIssuerConfig
	}
	if random == nil {
		random = rand.Reader
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, ErrInvalidIssuerConfig
	}
	defer clear(der)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, nil, ErrInvalidIssuerConfig
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, ErrInvalidIssuerConfig
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(random, nonce); err != nil {
		return nil, nil, ErrInvalidIssuerConfig
	}
	return aead.Seal(nil, nonce, der, []byte(aad)), nonce, nil
}

// OpenP256PrivateKey decrypts a sealed PKCS#8 P-256 private key using AES-256-GCM.
func OpenP256PrivateKey(ciphertext, nonce, kek []byte, aad string) (*ecdsa.PrivateKey, error) {
	if len(kek) != 32 || len(ciphertext) < 16 {
		return nil, ErrInvalidIssuerConfig
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, ErrInvalidIssuerConfig
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidIssuerConfig
	}
	if len(nonce) != aead.NonceSize() {
		return nil, ErrInvalidIssuerConfig
	}
	der, err := aead.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		return nil, ErrInvalidIssuerConfig
	}
	defer clear(der)
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, ErrInvalidIssuerConfig
	}
	ecKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || ecKey.Curve != elliptic.P256() || !ecKey.Curve.IsOnCurve(ecKey.X, ecKey.Y) {
		return nil, ErrInvalidIssuerConfig
	}
	return ecKey, nil
}

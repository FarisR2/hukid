package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/oid4vp"
)

// Per-tenant verifier signing keys (ADR-0034, VER-T11-d1). The private key is
// PKCS#8 DER sealed with an authentication.Cipher whose purpose binds tenant
// and kid, so a ciphertext copied to another tenant or key id does not open.

var (
	// ErrVerifierKey reports an invalid key, chain or custody request.
	ErrVerifierKey = errors.New("invalid verifier key")
	// ErrNoSigningKey reports a session that is unknown, finished, expired or
	// whose tenant has no key. The causes are deliberately not distinguished.
	ErrNoSigningKey = oid4vp.ErrNoSigningKey
)

const maxChainCertificates = 8

// VerifierKeyAAD is the purpose string that binds a sealed key to its owner.
func VerifierKeyAAD(tenant, kid string) string { return "verifier-key:" + tenant + ":" + kid }

// VerifierKeyProvisioner installs and rotates tenant signing keys. Pool must
// belong to a role allowed to run verification.rotate_verifier_key (owner or a
// provisioning login), never hukid_verification_runtime.
type VerifierKeyProvisioner struct {
	Pool   *pgxpool.Pool
	Cipher authentication.Cipher
	Now    func() time.Time
}

func (p *VerifierKeyProvisioner) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Provision seals key and makes it the tenant's active key, retiring the
// previous one. chain is the tenant's certificate chain (leaf first, DER) for
// x509_san_dns, or nil. When given, the leaf must carry key's public key and
// be valid now; HukID does not issue certificates. It returns the new kid.
func (p *VerifierKeyProvisioner) Provision(ctx context.Context, tenant string, key *ecdsa.PrivateKey, chain [][]byte) (string, error) {
	if p == nil || p.Pool == nil || p.Cipher == nil || !validID(tenant) || key == nil || key.Curve != elliptic.P256() || len(chain) > maxChainCertificates {
		return "", ErrVerifierKey
	}
	if len(chain) > 0 {
		leaf, err := x509.ParseCertificate(chain[0])
		if err != nil {
			return "", ErrVerifierKey
		}
		public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		now := p.now()
		if !ok || !public.Equal(&key.PublicKey) || now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			return "", ErrVerifierKey
		}
	}
	kid, err := newKeyID()
	if err != nil {
		return "", ErrVerifierKey
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", ErrVerifierKey
	}
	envelope, err := p.Cipher.Seal(der, VerifierKeyAAD(tenant, kid))
	clear(der)
	if err != nil {
		return "", ErrVerifierKey
	}
	if chain == nil {
		chain = [][]byte{}
	}
	if _, err := p.Pool.Exec(ctx, `SELECT verification.rotate_verifier_key($1::uuid,$2,$3,$4,$5,$6)`,
		tenant, kid, envelope.Ciphertext, envelope.Nonce, envelope.KeyVersion, chain); err != nil {
		return "", err
	}
	return kid, nil
}

func newKeyID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 32)
	for _, b := range buf {
		out = append(out, hex[b>>4], hex[b&15])
	}
	return string(out), nil
}

// VerifierKeyStore gives the wallet-facing request handler the signing key of
// a session's tenant. Pool must belong to hukid_verification_runtime, which can
// only execute verification.session_signing_key.
type VerifierKeyStore struct {
	Pool   *pgxpool.Pool
	Cipher authentication.Cipher
}

// SigningKey returns the key that signs the request object of sessionID, its
// kid and its certificate chain (leaf first, DER; nil without a certificate).
// The first call pins the active kid on the session, so a later rotation does
// not change the key of a session already answered. The caller must not
// retain or log the private key.
func (s *VerifierKeyStore) SigningKey(ctx context.Context, sessionID string) (*ecdsa.PrivateKey, string, [][]byte, error) {
	if s == nil || s.Pool == nil || s.Cipher == nil || !validID(sessionID) {
		return nil, "", nil, ErrNoSigningKey
	}
	var (
		tenant, kid, version string
		envelope             authentication.Envelope
		chain                [][]byte
	)
	err := s.Pool.QueryRow(ctx, `SELECT tenant_id::text,kid,ciphertext,nonce,key_version,chain FROM verification.session_signing_key($1::uuid)`, sessionID).
		Scan(&tenant, &kid, &envelope.Ciphertext, &envelope.Nonce, &version, &chain)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", nil, ErrNoSigningKey
	}
	if err != nil {
		return nil, "", nil, err
	}
	envelope.KeyVersion = version
	der, err := s.Cipher.Open(envelope, VerifierKeyAAD(tenant, kid))
	if err != nil {
		return nil, "", nil, ErrNoSigningKey
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	clear(der)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return nil, "", nil, ErrNoSigningKey
	}
	if len(chain) == 0 {
		chain = nil
	}
	return key, kid, chain, nil
}

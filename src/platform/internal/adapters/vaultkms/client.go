// Package vaultkms implements a HashiCorp Vault Transit HTTP KMS adapter for
// ES256 credential signing and AES-256/Transit envelope KEK operations.
package vaultkms

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"hukid.local/platform/internal/issuance"
)

const (
	defaultMountPath = "transit"
	defaultTimeout   = 5 * time.Second
	maxResponseBytes = 64 << 10
)

var (
	// ErrConfig reports invalid Vault URL, token or mount configuration.
	ErrConfig = errors.New("invalid vault kms configuration")
	// ErrVaultUnavailable reports Vault API unavailability or protocol error.
	ErrVaultUnavailable = errors.New("vault kms unavailable")

	safeSegmentRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	safeKeyCharRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
)

// Config configures the HashiCorp Vault Transit client.
type Config struct {
	BaseURL    string
	Token      string
	MountPath  string
	Namespace  string
	HTTPClient *http.Client
	Timeout    time.Duration
}

// Client talks to Vault Transit v1 endpoints without exporting private keys.
type Client struct {
	baseURL   string
	token     string
	mountPath string
	namespace string
	http      *http.Client
	timeout   time.Duration
}

// NewClient validates Config fail-closed and constructs a Transit KMS client.
func NewClient(cfg Config) (*Client, error) {
	rawURL := strings.TrimSpace(cfg.BaseURL)
	if rawURL == "" {
		return nil, ErrConfig
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrConfig
	}
	if parsed.Scheme != "https" && !isLoopbackHTTP(parsed) {
		return nil, ErrConfig
	}
	if strings.TrimSpace(cfg.Token) == "" || strings.ContainsAny(cfg.Token, " \t\r\n") {
		return nil, ErrConfig
	}
	mount := strings.Trim(cfg.MountPath, "/")
	if mount == "" {
		mount = defaultMountPath
	}
	if !safeSegmentRe.MatchString(mount) {
		return nil, ErrConfig
	}
	if strings.ContainsAny(cfg.Namespace, "\r\n") {
		return nil, ErrConfig
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("redirects disabled")
			},
		}
	}
	return &Client{
		baseURL:   strings.TrimRight(parsed.String(), "/"),
		token:     cfg.Token,
		mountPath: mount,
		namespace: strings.TrimSpace(cfg.Namespace),
		http:      httpClient,
		timeout:   timeout,
	}, nil
}

func isLoopbackHTTP(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// FormatKeyRef encodes a Vault Transit key reference as vault://{mount}/{keyName}#v{version}.
func FormatKeyRef(mount, keyName string, version int) string {
	return fmt.Sprintf("vault://%s/%s#v%d", mount, keyName, version)
}

// ParseKeyRef parses and validates a vault://{mount}/{keyName}#v{version} key reference.
func ParseKeyRef(ref string) (mount, keyName string, version int, err error) {
	u, err := url.Parse(strings.TrimSpace(ref))
	if err != nil || u.Scheme != "vault" || u.User != nil || u.RawQuery != "" || u.Host == "" {
		return "", "", 0, issuance.ErrInvalidFoundationInput
	}
	mount = u.Host
	keyName = strings.TrimPrefix(u.Path, "/")
	if !safeSegmentRe.MatchString(mount) || !safeSegmentRe.MatchString(keyName) {
		return "", "", 0, issuance.ErrInvalidFoundationInput
	}
	if !strings.HasPrefix(u.Fragment, "v") {
		return "", "", 0, issuance.ErrInvalidFoundationInput
	}
	version, err = strconv.Atoi(strings.TrimPrefix(u.Fragment, "v"))
	if err != nil || version < 1 {
		return "", "", 0, issuance.ErrInvalidFoundationInput
	}
	return mount, keyName, version, nil
}

func transitKeyName(issuerID, kid string) string {
	joined := "hukid-" + issuerID + "-" + kid
	sanitized := safeKeyCharRe.ReplaceAllString(joined, "-")
	sanitized = strings.Trim(sanitized, ".-")
	if len(sanitized) > 120 {
		sanitized = sanitized[:120]
	}
	return sanitized
}

// ProvisionKey creates/ensures an exportable=false ecdsa-p256 Transit key and
// returns its KMS reference and exported P-256 public JWK.
func (c *Client) ProvisionKey(ctx context.Context, _, issuerID, kid string) (string, issuance.PublicJWK, error) {
	if strings.TrimSpace(issuerID) == "" || strings.TrimSpace(kid) == "" || strings.ContainsAny(kid, " \t\r\n") {
		return "", issuance.PublicJWK{}, issuance.ErrInvalidFoundationInput
	}
	keyName := transitKeyName(issuerID, kid)
	if !safeSegmentRe.MatchString(keyName) {
		return "", issuance.PublicJWK{}, issuance.ErrInvalidFoundationInput
	}
	createPath := fmt.Sprintf("/v1/%s/keys/%s", c.mountPath, url.PathEscape(keyName))
	if status, _, err := c.doJSON(ctx, http.MethodPost, createPath, map[string]any{
		"type":       "ecdsa-p256",
		"exportable": false,
	}); err != nil || (status != http.StatusOK && status != http.StatusNoContent) {
		return "", issuance.PublicJWK{}, ErrVaultUnavailable
	}

	status, raw, err := c.doJSON(ctx, http.MethodGet, createPath, nil)
	if err != nil || status != http.StatusOK {
		return "", issuance.PublicJWK{}, ErrVaultUnavailable
	}
	var resp struct {
		Data struct {
			LatestVersion int `json:"latest_version"`
			Keys          map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &resp) != nil || resp.Data.LatestVersion < 1 {
		return "", issuance.PublicJWK{}, ErrVaultUnavailable
	}
	entry, ok := resp.Data.Keys[strconv.Itoa(resp.Data.LatestVersion)]
	if !ok || strings.TrimSpace(entry.PublicKey) == "" {
		return "", issuance.PublicJWK{}, ErrVaultUnavailable
	}
	pub, err := parseP256PublicPEM(entry.PublicKey)
	if err != nil {
		return "", issuance.PublicJWK{}, ErrVaultUnavailable
	}
	jwk, err := issuance.ExportPublicJWK(pub, kid)
	if err != nil {
		return "", issuance.PublicJWK{}, err
	}
	return FormatKeyRef(c.mountPath, keyName, resp.Data.LatestVersion), jwk, nil
}

// KeyProvisioner adapts ProvisionKey to issuance.KeyProvisioner.
func (c *Client) KeyProvisioner() issuance.KeyProvisioner {
	return func(tenantID, issuerID, kid string) (string, issuance.PublicJWK, error) {
		ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
		defer cancel()
		return c.ProvisionKey(ctx, tenantID, issuerID, kid)
	}
}

// Resolver returns an issuance.SignerResolver backed by Vault Transit.
func (c *Client) Resolver() issuance.SignerResolver {
	return func(_, _, issuerURI, kid, kmsKeyRef string, expectedPub *ecdsa.PublicKey) (issuance.Signer, error) {
		return c.Signer(issuerURI, kid, kmsKeyRef, expectedPub)
	}
}

// Signer validates issuerURI, kid, kmsKeyRef and expectedPub and returns a VaultSigner.
func (c *Client) Signer(issuerURI, kid, kmsKeyRef string, expectedPub *ecdsa.PublicKey) (issuance.Signer, error) {
	if err := issuance.ValidateIssuerIdentifier(issuerURI); err != nil {
		return nil, err
	}
	if strings.TrimSpace(kid) == "" || strings.ContainsAny(kid, " \t\r\n") {
		return nil, issuance.ErrInvalidIssuerConfig
	}
	if expectedPub == nil || expectedPub.Curve != elliptic.P256() || !expectedPub.Curve.IsOnCurve(expectedPub.X, expectedPub.Y) {
		return nil, issuance.ErrNoActiveKey
	}
	mount, keyName, version, err := ParseKeyRef(kmsKeyRef)
	if err != nil {
		return nil, err
	}
	pubCopy := *expectedPub
	return &VaultSigner{
		client:    c,
		issuerURI: issuerURI,
		kid:       kid,
		mount:     mount,
		keyName:   keyName,
		version:   version,
		pub:       &pubCopy,
	}, nil
}

// VaultSigner implements issuance.Signer by delegating ES256 signing to Vault Transit.
type VaultSigner struct {
	client    *Client
	issuerURI string
	kid       string
	mount     string
	keyName   string
	version   int
	pub       *ecdsa.PublicKey
}

func (s *VaultSigner) Issuer() string              { return s.issuerURI }
func (s *VaultSigner) KeyID() string               { return s.kid }
func (s *VaultSigner) PublicKey() *ecdsa.PublicKey { p := *s.pub; return &p }

// Sign hashes signingInput with SHA-256, asks Vault Transit to sign the digest
// with ES256, verifies the signature against expectedPub and returns 64-byte R || S.
func (s *VaultSigner) Sign(signingInput string) ([]byte, error) {
	if signingInput == "" {
		return nil, issuance.ErrSigningFailed
	}
	digest := sha256.Sum256([]byte(signingInput))
	ctx, cancel := context.WithTimeout(context.Background(), s.client.timeout)
	defer cancel()

	signPath := fmt.Sprintf("/v1/%s/sign/%s/sha2-256", s.mount, url.PathEscape(s.keyName))
	status, raw, err := s.client.doJSON(ctx, http.MethodPost, signPath, map[string]any{
		"input":                base64.StdEncoding.EncodeToString(digest[:]),
		"prehashed":            true,
		"key_version":          s.version,
		"marshaling_algorithm": "jws",
	})
	if err != nil || status != http.StatusOK {
		return nil, issuance.ErrSigningFailed
	}
	var resp struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &resp) != nil {
		return nil, issuance.ErrSigningFailed
	}
	sigBytes, err := decodeVaultSignature(resp.Data.Signature)
	if err != nil {
		return nil, issuance.ErrSigningFailed
	}
	rawSig, err := issuance.ParseASN1OrRawES256Signature(sigBytes)
	if err != nil {
		return nil, issuance.ErrSigningFailed
	}
	r := new(big.Int).SetBytes(rawSig[:32])
	sv := new(big.Int).SetBytes(rawSig[32:])
	if !ecdsa.Verify(s.pub, digest[:], r, sv) {
		return nil, issuance.ErrSigningFailed
	}
	return rawSig, nil
}

// WrapDEK encrypts a 32-byte DEK under a Vault Transit KEK using optional AAD context (HK-024).
func (c *Client) WrapDEK(ctx context.Context, kekName string, dek []byte, aad string) (string, error) {
	if !safeSegmentRe.MatchString(kekName) || len(dek) != 32 {
		return "", issuance.ErrInvalidFoundationInput
	}
	body := map[string]any{
		"plaintext": base64.StdEncoding.EncodeToString(dek),
	}
	if aad != "" {
		body["context"] = base64.StdEncoding.EncodeToString([]byte(aad))
	}
	path := fmt.Sprintf("/v1/%s/encrypt/%s", c.mountPath, url.PathEscape(kekName))
	status, raw, err := c.doJSON(ctx, http.MethodPost, path, body)
	if err != nil || status != http.StatusOK {
		return "", ErrVaultUnavailable
	}
	var resp struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &resp) != nil || !strings.HasPrefix(resp.Data.Ciphertext, "vault:v") {
		return "", ErrVaultUnavailable
	}
	return resp.Data.Ciphertext, nil
}

// UnwrapDEK decrypts a Vault Transit-wrapped 32-byte DEK using optional AAD context (HK-024).
func (c *Client) UnwrapDEK(ctx context.Context, kekName, ciphertext, aad string) ([]byte, error) {
	if !safeSegmentRe.MatchString(kekName) || !strings.HasPrefix(ciphertext, "vault:v") {
		return nil, issuance.ErrInvalidFoundationInput
	}
	body := map[string]any{
		"ciphertext": ciphertext,
	}
	if aad != "" {
		body["context"] = base64.StdEncoding.EncodeToString([]byte(aad))
	}
	path := fmt.Sprintf("/v1/%s/decrypt/%s", c.mountPath, url.PathEscape(kekName))
	status, raw, err := c.doJSON(ctx, http.MethodPost, path, body)
	if err != nil || status != http.StatusOK {
		return nil, ErrVaultUnavailable
	}
	var resp struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &resp) != nil || resp.Data.Plaintext == "" {
		return nil, ErrVaultUnavailable
	}
	dek, err := base64.StdEncoding.DecodeString(resp.Data.Plaintext)
	if err != nil || len(dek) != 32 {
		if len(dek) > 0 {
			clear(dek)
		}
		return nil, ErrVaultUnavailable
	}
	return dek, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, payload any) (int, []byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		buf, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, err
		}
		bodyReader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(raw) > maxResponseBytes {
		return resp.StatusCode, nil, ErrVaultUnavailable
	}
	return resp.StatusCode, raw, nil
}

func parseP256PublicPEM(pemStr string) (*ecdsa.PublicKey, error) {
	block, rest := pem.Decode([]byte(pemStr))
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrVaultUnavailable
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, ErrVaultUnavailable
	}
	ecPub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || ecPub.Curve != elliptic.P256() || !ecPub.Curve.IsOnCurve(ecPub.X, ecPub.Y) {
		return nil, ErrVaultUnavailable
	}
	return ecPub, nil
}

func decodeVaultSignature(sig string) ([]byte, error) {
	if !strings.HasPrefix(sig, "vault:v") {
		return nil, ErrVaultUnavailable
	}
	parts := strings.SplitN(sig, ":", 3)
	if len(parts) != 3 || len(parts[1]) < 2 || parts[2] == "" {
		return nil, ErrVaultUnavailable
	}
	if v, err := strconv.Atoi(strings.TrimPrefix(parts[1], "v")); err != nil || v < 1 {
		return nil, ErrVaultUnavailable
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.RawURLEncoding, base64.URLEncoding} {
		if decoded, err := enc.DecodeString(parts[2]); err == nil {
			return decoded, nil
		}
	}
	return nil, ErrVaultUnavailable
}

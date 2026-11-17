// Package verifierhttp implements the outbound HTTPS adapters (VER-T12) for
// resolving issuer JWKS and Bitstring Status Lists according to HukID Profile §3.
package verifierhttp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"hukid.local/platform/internal/verification"
)

const (
	maxResponseBytes = 1 << 20
	maxRedirects     = 2
	defaultTimeout   = 5 * time.Second
)

// Resolver fetches JWKS and BitstringStatusListCredentials over HTTPS/HTTP
// while enforcing single-host isolation and rejecting cross-origin redirects.
type Resolver struct {
	client *http.Client
	// TransportBase optionally maps canonical https://issuer.hukid.pe/{slug}
	// origins to an explicit local/test HTTP(S) base URL (loopback only for HTTP).
	TransportBase string
}

// Config configures the VER-T12 HTTPS resolver adapter.
type Config struct {
	Timeout       time.Duration
	Transport     http.RoundTripper
	TransportBase string
}

// NewResolver constructs a Resolver enforcing Profile §3.5 origin rules.
func NewResolver(cfg Config) (*Resolver, error) {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if cfg.TransportBase != "" {
		parsed, err := url.Parse(cfg.TransportBase)
		if err != nil || (parsed.Scheme != "https" && !isLoopbackHTTP(parsed)) || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, errors.New("invalid verifier transport base")
		}
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: cfg.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return errors.New("too many redirects")
			}
			orig := via[0].URL
			if req.URL.Scheme != orig.Scheme || req.URL.Host != orig.Host {
				return errors.New("cross-origin redirect forbidden")
			}
			return nil
		},
	}
	return &Resolver{client: client, TransportBase: strings.TrimRight(cfg.TransportBase, "/")}, nil
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

func (r *Resolver) resolveEndpoint(canonicalURL string) (string, error) {
	parsed, err := url.Parse(canonicalURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("invalid issuer URL")
	}
	if parsed.Scheme == "https" {
		if r.TransportBase != "" {
			return r.TransportBase + parsed.EscapedPath(), nil
		}
		return canonicalURL, nil
	}
	if isLoopbackHTTP(parsed) {
		return canonicalURL, nil
	}
	return "", errors.New("non-https issuer URL rejected")
}

// ResolveKey fetches {issuer}/.well-known/jwks.json and extracts the P-256 key matching kid.
func (r *Resolver) ResolveKey(issuer, kid string) (verification.ResolvedKey, error) {
	if issuer == "" || kid == "" {
		return verification.ResolvedKey{}, verification.ErrKeyNotFound
	}
	endpoint, err := r.resolveEndpoint(strings.TrimRight(issuer, "/") + "/.well-known/jwks.json")
	if err != nil {
		return verification.ResolvedKey{}, fmt.Errorf("%w: %v", verification.ErrKeyResolution, err)
	}
	body, err := r.fetch(endpoint, "application/json")
	if err != nil {
		return verification.ResolvedKey{}, fmt.Errorf("%w: %v", verification.ErrKeyResolution, err)
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return verification.ResolvedKey{}, fmt.Errorf("%w: invalid jwks", verification.ErrKeyResolution)
	}
	for _, k := range doc.Keys {
		if k.Kid != kid {
			continue
		}
		if k.Kty != "EC" || k.Crv != "P-256" || (k.Alg != "" && k.Alg != "ES256") {
			return verification.ResolvedKey{}, verification.ErrKeyNotFound
		}
		xb, errX := base64.RawURLEncoding.DecodeString(k.X)
		yb, errY := base64.RawURLEncoding.DecodeString(k.Y)
		if errX != nil || errY != nil || len(xb) != 32 || len(yb) != 32 {
			return verification.ResolvedKey{}, fmt.Errorf("%w: invalid jwk coordinates", verification.ErrKeyResolution)
		}
		raw := make([]byte, 65)
		raw[0] = 0x04
		copy(raw[1:33], xb)
		copy(raw[33:65], yb)
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
		if err != nil {
			return verification.ResolvedKey{}, fmt.Errorf("%w: invalid curve point", verification.ErrKeyResolution)
		}
		return verification.ResolvedKey{Key: pub, Issuer: issuer}, nil
	}
	return verification.ResolvedKey{}, verification.ErrKeyNotFound
}

// ResolveStatusList fetches a signed BitstringStatusListCredential JWT from credentialURL.
func (r *Resolver) ResolveStatusList(credentialURL string) (string, error) {
	endpoint, err := r.resolveEndpoint(credentialURL)
	if err != nil {
		return "", verification.ErrStatusResolution
	}
	body, err := r.fetch(endpoint, "application/vc+jwt")
	if err != nil {
		return "", verification.ErrStatusResolution
	}
	return strings.TrimSpace(string(body)), nil
}

// ResolveSchema fetches a JSON Schema document bytes from schemaURL (VER-T13).
func (r *Resolver) ResolveSchema(schemaURL string) ([]byte, error) {
	endpoint, err := r.resolveEndpoint(schemaURL)
	if err != nil {
		return nil, verification.ErrSchemaResolution
	}
	body, err := r.fetch(endpoint, "application/schema+json, application/json")
	if err != nil {
		return nil, verification.ErrSchemaResolution
	}
	return body, nil
}

func (r *Resolver) fetch(endpoint, accept string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(data) > maxResponseBytes {
		return nil, errors.New("response unreadable or too large")
	}
	return data, nil
}

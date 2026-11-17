// Package jwksresolver is the HTTPS adapter of verification.IssuerKeyResolver
// (FEAT-004, VER-T12, VER-FR11/AC11). It applies the HukID profile section 3:
// a kid resolves only against
// https://issuer.hukid.pe/{issuerSlug}/.well-known/jwks.json, keys from any
// other host are never read, redirects are not followed and the credential
// cannot supply a jku (the core already rejects key headers before any lookup).
//
// The URL is built from a fixed host and a validated slug, never from the
// credential, so there is nothing to redirect an attacker-chosen request to.
// The package never logs; failures are generic.
package jwksresolver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"hukid.local/platform/internal/verification"
)

const (
	// DefaultHost is the only host JWKS are read from (profile section 3).
	DefaultHost = "issuer.hukid.pe"

	// DefaultTTL is how long a fetched key set is served without refetching.
	// DefaultMinRefresh bounds refetches triggered by an unknown kid so a
	// stream of forged credentials cannot turn into a stream of requests.
	// DefaultTimeout and MaxBodyBytes bound one fetch. All are proposed values,
	// not owner-approved ones.
	DefaultTTL        = 5 * time.Minute
	DefaultMinRefresh = 30 * time.Second
	DefaultTimeout    = 5 * time.Second
	MaxBodyBytes      = 64 << 10

	maxCachedIssuers = 256
	maxKeysPerSet    = 64
)

var (
	// ErrConfig reports an invalid resolver configuration.
	ErrConfig = errors.New("invalid jwks resolver configuration")
	// ErrFetch reports that the key set could not be obtained or trusted. It
	// carries no detail from the remote side.
	ErrFetch = errors.New("issuer key set unavailable")

	slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Config configures a Resolver. The zero value of every optional field takes
// the documented default.
type Config struct {
	// Host is the only host contacted. Default DefaultHost. A port is allowed
	// only so tests can target a local server.
	Host string
	// Client performs the requests. Default: a client with Timeout, TLS from
	// the system roots and redirects disabled. A supplied client keeps its
	// transport, but redirects are always disabled on a copy.
	Client *http.Client
	// TTL, MinRefresh, Timeout bound caching and fetching; zero means default.
	TTL, MinRefresh, Timeout time.Duration
	// Now is the clock; default time.Now.
	Now func() time.Time
}

type entry struct {
	keys    map[string]*ecdsa.PublicKey
	fetched time.Time
}

// Resolver implements verification.IssuerKeyResolver over HTTPS.
type Resolver struct {
	host       string
	client     *http.Client
	ttl        time.Duration
	minRefresh time.Duration
	timeout    time.Duration
	now        func() time.Time

	mu    sync.Mutex
	cache map[string]entry
}

var _ verification.IssuerKeyResolver = (*Resolver)(nil)

// New validates cfg and returns a Resolver.
func New(cfg Config) (*Resolver, error) {
	if cfg.Host == "" {
		cfg.Host = DefaultHost
	}
	if u, err := url.Parse("https://" + cfg.Host); err != nil || u.Host != cfg.Host || u.User != nil || u.Path != "" || cfg.Host == "" {
		return nil, ErrConfig
	}
	if cfg.TTL == 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.MinRefresh == 0 {
		cfg.MinRefresh = DefaultMinRefresh
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.TTL < 0 || cfg.MinRefresh < 0 || cfg.Timeout < 0 || cfg.MinRefresh > cfg.TTL {
		return nil, ErrConfig
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	client := &http.Client{}
	if cfg.Client != nil {
		copied := *cfg.Client
		client = &copied
	}
	// No redirect is followed, same-origin or not: the profile asks for no
	// cross-origin redirect and the published JWKS has no reason to move.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = cfg.Timeout
	return &Resolver{host: cfg.Host, client: client, ttl: cfg.TTL, minRefresh: cfg.MinRefresh, timeout: cfg.Timeout, now: cfg.Now, cache: map[string]entry{}}, nil
}

// slugOf returns the issuer slug when issuer is exactly
// https://{host}/{slug}; anything else (other host, port, query, fragment,
// user info, trailing slash, extra path, odd slug) is not an HukID issuer.
func (r *Resolver) slugOf(issuer string) (string, bool) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host != r.host || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery {
		return "", false
	}
	slug := u.Path
	if len(slug) < 2 || slug[0] != '/' {
		return "", false
	}
	slug = slug[1:]
	if !slugPattern.MatchString(slug) || u.EscapedPath() != u.Path {
		return "", false
	}
	return slug, true
}

// ResolveKey implements verification.IssuerKeyResolver. An issuer outside the
// HukID host and a kid the issuer does not publish are both
// verification.ErrKeyNotFound, with no network access for the former. Any
// fetch or trust failure is ErrFetch, which the core reports as a resolver
// failure rather than as a finding about the credential.
func (r *Resolver) ResolveKey(issuer, kid string) (verification.ResolvedKey, error) {
	slug, ok := r.slugOf(issuer)
	if !ok || kid == "" {
		return verification.ResolvedKey{}, verification.ErrKeyNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	held, cached := r.cache[slug]
	if cached {
		age := now.Sub(held.fetched)
		if key, found := held.keys[kid]; found && age < r.ttl {
			return verification.ResolvedKey{Key: key, Issuer: issuer}, nil
		}
		// A kid that is not in a recent set stays unknown until the throttle
		// passes; an expired set is refetched below.
		if _, found := held.keys[kid]; !found && age < r.minRefresh {
			return verification.ResolvedKey{}, verification.ErrKeyNotFound
		}
	}
	keys, err := r.fetch(slug)
	if err != nil {
		// Keep serving a stale set for a kid it already holds: a retired key
		// must keep verifying old credentials through an outage.
		if cached {
			if key, found := held.keys[kid]; found {
				return verification.ResolvedKey{Key: key, Issuer: issuer}, nil
			}
		}
		return verification.ResolvedKey{}, err
	}
	if len(r.cache) >= maxCachedIssuers {
		r.evictLocked()
	}
	r.cache[slug] = entry{keys: keys, fetched: now}
	if key, found := keys[kid]; found {
		return verification.ResolvedKey{Key: key, Issuer: issuer}, nil
	}
	return verification.ResolvedKey{}, verification.ErrKeyNotFound
}

func (r *Resolver) evictLocked() {
	var oldest string
	var oldestAt time.Time
	for slug, held := range r.cache {
		if oldest == "" || held.fetched.Before(oldestAt) {
			oldest, oldestAt = slug, held.fetched
		}
	}
	delete(r.cache, oldest)
}

func (r *Resolver) fetch(slug string) (map[string]*ecdsa.PublicKey, error) {
	target := (&url.URL{Scheme: "https", Host: r.host, Path: "/" + slug + "/.well-known/jwks.json"}).String()
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, ErrFetch
	}
	request.Header.Set("Accept", "application/json, application/jwk-set+json")
	response, err := r.client.Do(request)
	if err != nil {
		return nil, ErrFetch
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrFetch
	}
	if media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type")); err != nil || (media != "application/json" && media != "application/jwk-set+json") {
		return nil, ErrFetch
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxBodyBytes+1))
	if err != nil || len(body) > MaxBodyBytes {
		return nil, ErrFetch
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil || len(set.Keys) > maxKeysPerSet {
		return nil, ErrFetch
	}
	keys := make(map[string]*ecdsa.PublicKey, len(set.Keys))
	for _, jwk := range set.Keys {
		// Only public ES256 signing keys on P-256 with a kid are usable; a
		// private key, another curve or another use is skipped, never trusted.
		public, ok := jwk.Key.(*ecdsa.PublicKey)
		if !ok || !jwk.IsPublic() || jwk.KeyID == "" || public.Curve != elliptic.P256() || !public.Curve.IsOnCurve(public.X, public.Y) {
			continue
		}
		if (jwk.Use != "" && jwk.Use != "sig") || (jwk.Algorithm != "" && jwk.Algorithm != string(jose.ES256)) {
			continue
		}
		if _, duplicate := keys[jwk.KeyID]; duplicate {
			// A set that publishes one kid twice is ambiguous: drop both.
			keys[jwk.KeyID] = nil
			continue
		}
		keys[jwk.KeyID] = public
	}
	for kid, key := range keys {
		if key == nil {
			delete(keys, kid)
		}
	}
	return keys, nil
}

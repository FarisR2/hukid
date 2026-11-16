package jwksresolver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"hukid.local/platform/internal/verification"
)

var epoch = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func jwkOf(t *testing.T, key any, kid, use, alg string) jose.JSONWebKey {
	t.Helper()
	return jose.JSONWebKey{Key: key, KeyID: kid, Use: use, Algorithm: alg}
}

func setJSON(t *testing.T, keys ...jose.JSONWebKey) []byte {
	t.Helper()
	body, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// rig is one TLS "issuer.hukid.pe": it serves whatever body, status and
// content type the test sets and counts the requests it receives.
type rig struct {
	server      *httptest.Server
	hits        atomic.Int32
	mu          sync.Mutex
	body        []byte
	status      int
	contentType string
	handler     http.HandlerFunc
	clock       *clock
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{status: http.StatusOK, contentType: "application/json", clock: &clock{now: epoch}}
	r.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		r.mu.Lock()
		handler, body, status, contentType := r.handler, r.body, r.status, r.contentType
		r.mu.Unlock()
		if handler != nil {
			handler(w, req)
			return
		}
		if req.Method != http.MethodGet || req.URL.Path != "/acme/.well-known/jwks.json" {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *rig) serve(body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.body = body
}

func (r *rig) host() string { return strings.TrimPrefix(r.server.URL, "https://") }

func (r *rig) issuer(slug string) string { return "https://" + r.host() + "/" + slug }

func (r *rig) resolver(t *testing.T, mutate ...func(*Config)) *Resolver {
	t.Helper()
	cfg := Config{Host: r.host(), Client: r.server.Client(), Now: r.clock.Now}
	for _, m := range mutate {
		m(&cfg)
	}
	resolver, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func TestResolvesAPublishedKeyIncludingRetiredOnes(t *testing.T) {
	r := newRig(t)
	current, retired := newKey(t, elliptic.P256()), newKey(t, elliptic.P256())
	r.serve(setJSON(t, jwkOf(t, &current.PublicKey, "2026-b", "sig", "ES256"), jwkOf(t, &retired.PublicKey, "2025-a", "", "")))
	resolver := r.resolver(t)
	for kid, want := range map[string]*ecdsa.PublicKey{"2026-b": &current.PublicKey, "2025-a": &retired.PublicKey} {
		got, err := resolver.ResolveKey(r.issuer("acme"), kid)
		if err != nil || !got.Key.Equal(want) || got.Issuer != r.issuer("acme") {
			t.Fatalf("%s: %v %+v", kid, err, got)
		}
	}
}

func TestUnknownKidIsNotFound(t *testing.T) {
	r := newRig(t)
	key := newKey(t, elliptic.P256())
	r.serve(setJSON(t, jwkOf(t, &key.PublicKey, "k1", "sig", "ES256")))
	if _, err := r.resolver(t).ResolveKey(r.issuer("acme"), "nope"); !errors.Is(err, verification.ErrKeyNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestOnlyTheExactHukIDIssuerShapeIsContactedAndNothingElse(t *testing.T) {
	r := newRig(t)
	key := newKey(t, elliptic.P256())
	r.serve(setJSON(t, jwkOf(t, &key.PublicKey, "k1", "sig", "ES256")))
	resolver := r.resolver(t)
	host := r.host()
	cases := map[string]string{
		"other host":        "https://evil.example/acme",
		"http scheme":       "http://" + host + "/acme",
		"host with prefix":  "https://x." + host + "/acme",
		"host as userinfo":  "https://" + host + "@evil.example/acme",
		"userinfo":          "https://user@" + host + "/acme",
		"trailing slash":    "https://" + host + "/acme/",
		"extra path":        "https://" + host + "/acme/extra",
		"nested slug":       "https://" + host + "/a/b",
		"query":             "https://" + host + "/acme?x=1",
		"empty query":       "https://" + host + "/acme?",
		"fragment":          "https://" + host + "/acme#f",
		"empty slug":        "https://" + host + "/",
		"no path":           "https://" + host,
		"uppercase slug":    "https://" + host + "/ACME",
		"encoded slug":      "https://" + host + "/ac%6De",
		"dot segment":       "https://" + host + "/..",
		"leading dash":      "https://" + host + "/-acme",
		"underscore":        "https://" + host + "/ac_me",
		"slug too long":     "https://" + host + "/" + strings.Repeat("a", 64),
		"not a url":         "::::",
		"empty":             "",
		"credential claims": "https://" + host + "/acme/.well-known/jwks.json",
	}
	for name, issuer := range cases {
		if _, err := resolver.ResolveKey(issuer, "k1"); !errors.Is(err, verification.ErrKeyNotFound) {
			t.Fatalf("%s: accepted or wrong error: %v", name, err)
		}
	}
	if _, err := resolver.ResolveKey(r.issuer("acme"), ""); !errors.Is(err, verification.ErrKeyNotFound) {
		t.Fatalf("empty kid: %v", err)
	}
	if got := r.hits.Load(); got != 0 {
		t.Fatalf("a rejected issuer reached the network: %d requests", got)
	}
}

func TestRedirectsAreNeverFollowed(t *testing.T) {
	foreign := newRig(t)
	key := newKey(t, elliptic.P256())
	foreign.serve(setJSON(t, jwkOf(t, &key.PublicKey, "k1", "sig", "ES256")))
	foreign.handler = func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(foreign.body)
	}
	cases := map[string]func(*rig) string{
		"cross-origin": func(*rig) string { return foreign.server.URL + "/acme/.well-known/jwks.json" },
		"same-origin":  func(r *rig) string { return r.server.URL + "/elsewhere" },
	}
	for name, location := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.handler = func(w http.ResponseWriter, req *http.Request) {
				http.Redirect(w, req, location(r), http.StatusFound)
			}
			before := foreign.hits.Load()
			_, err := r.resolver(t).ResolveKey(r.issuer("acme"), "k1")
			if !errors.Is(err, ErrFetch) || errors.Is(err, verification.ErrKeyNotFound) {
				t.Fatalf("redirect was followed or misreported: %v", err)
			}
			if foreign.hits.Load() != before {
				t.Fatal("the redirect target received a request")
			}
		})
	}
}

func TestFetchFailuresAreResolverFailuresNotFindings(t *testing.T) {
	good := newKey(t, elliptic.P256())
	body := setJSON(t, jwkOf(t, &good.PublicKey, "k1", "sig", "ES256"))
	cases := map[string]func(*rig){
		"server error":    func(r *rig) { r.status = http.StatusInternalServerError },
		"not found":       func(r *rig) { r.status = http.StatusNotFound },
		"no content":      func(r *rig) { r.status = http.StatusNoContent },
		"html":            func(r *rig) { r.contentType = "text/html" },
		"no content type": func(r *rig) { r.contentType = "" },
		"malformed json":  func(r *rig) { r.body = []byte("{") },
		"not a key set":   func(r *rig) { r.body = []byte(`{"keys":"x"}`) },
		"oversize":        func(r *rig) { r.body = []byte(`{"keys":[],"pad":"` + strings.Repeat("a", MaxBodyBytes) + `"}`) },
		"too many keys":   func(r *rig) { r.body = manyKeys(t, maxKeysPerSet+1) },
		"timeout": func(r *rig) {
			r.handler = func(http.ResponseWriter, *http.Request) { time.Sleep(400 * time.Millisecond) }
		},
		"unreachable": func(r *rig) {
			r.server.Close()
		},
	}
	for name, apply := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.body = body
			apply(r)
			resolver := r.resolver(t, func(c *Config) { c.Timeout = 150 * time.Millisecond })
			_, err := resolver.ResolveKey(r.issuer("acme"), "k1")
			if !errors.Is(err, ErrFetch) || errors.Is(err, verification.ErrKeyNotFound) {
				t.Fatalf("%v", err)
			}
		})
	}
}

func manyKeys(t *testing.T, n int) []byte {
	t.Helper()
	keys := make([]jose.JSONWebKey, n)
	for i := range keys {
		key := newKey(t, elliptic.P256())
		keys[i] = jwkOf(t, &key.PublicKey, "k"+string(rune('a'+i%26))+strings.Repeat("x", i/26), "sig", "ES256")
	}
	return setJSON(t, keys...)
}

func TestOnlyUsablePublicES256KeysAreTrusted(t *testing.T) {
	r := newRig(t)
	good := newKey(t, elliptic.P256())
	other := newKey(t, elliptic.P256())
	p384 := newKey(t, elliptic.P384())
	dupA, dupB := newKey(t, elliptic.P256()), newKey(t, elliptic.P256())
	r.serve(setJSON(t,
		jwkOf(t, &good.PublicKey, "good", "sig", "ES256"),
		jwkOf(t, other, "private", "sig", "ES256"),
		jwkOf(t, &p384.PublicKey, "p384", "sig", "ES384"),
		jwkOf(t, &other.PublicKey, "encryption", "enc", "ES256"),
		jwkOf(t, &other.PublicKey, "wrong-alg", "sig", "ES384"),
		jwkOf(t, &other.PublicKey, "", "sig", "ES256"),
		jwkOf(t, &dupA.PublicKey, "dup", "sig", "ES256"),
		jwkOf(t, &dupB.PublicKey, "dup", "sig", "ES256"),
	))
	resolver := r.resolver(t)
	if got, err := resolver.ResolveKey(r.issuer("acme"), "good"); err != nil || !got.Key.Equal(&good.PublicKey) {
		t.Fatalf("good: %v", err)
	}
	for _, kid := range []string{"private", "p384", "encryption", "wrong-alg", "", "dup"} {
		if _, err := resolver.ResolveKey(r.issuer("acme"), kid); !errors.Is(err, verification.ErrKeyNotFound) {
			t.Fatalf("%q was trusted or misreported: %v", kid, err)
		}
	}
}

func TestKeySetsAreCachedForTheTTL(t *testing.T) {
	r := newRig(t)
	key := newKey(t, elliptic.P256())
	r.serve(setJSON(t, jwkOf(t, &key.PublicKey, "k1", "sig", "ES256")))
	resolver := r.resolver(t)
	for range 5 {
		if _, err := resolver.ResolveKey(r.issuer("acme"), "k1"); err != nil {
			t.Fatal(err)
		}
	}
	if r.hits.Load() != 1 {
		t.Fatalf("not cached: %d requests", r.hits.Load())
	}
	r.clock.Advance(DefaultTTL)
	if _, err := resolver.ResolveKey(r.issuer("acme"), "k1"); err != nil || r.hits.Load() != 2 {
		t.Fatalf("not refreshed after the TTL: %v %d", err, r.hits.Load())
	}
}

func TestUnknownKidsDoNotTurnIntoRequestFloods(t *testing.T) {
	r := newRig(t)
	old, rotated := newKey(t, elliptic.P256()), newKey(t, elliptic.P256())
	r.serve(setJSON(t, jwkOf(t, &old.PublicKey, "old", "sig", "ES256")))
	resolver := r.resolver(t)
	for range 20 {
		if _, err := resolver.ResolveKey(r.issuer("acme"), "forged"); !errors.Is(err, verification.ErrKeyNotFound) {
			t.Fatal(err)
		}
	}
	if r.hits.Load() != 1 {
		t.Fatalf("forged kids caused %d requests", r.hits.Load())
	}
	// The issuer rotates; a legitimate new kid is found once the throttle passes.
	r.serve(setJSON(t, jwkOf(t, &old.PublicKey, "old", "sig", "ES256"), jwkOf(t, &rotated.PublicKey, "new", "sig", "ES256")))
	if _, err := resolver.ResolveKey(r.issuer("acme"), "new"); !errors.Is(err, verification.ErrKeyNotFound) {
		t.Fatalf("throttle not applied: %v", err)
	}
	r.clock.Advance(DefaultMinRefresh)
	if got, err := resolver.ResolveKey(r.issuer("acme"), "new"); err != nil || !got.Key.Equal(&rotated.PublicKey) {
		t.Fatalf("rotated key not picked up: %v", err)
	}
}

func TestAKnownKeyKeepsVerifyingThroughAnOutage(t *testing.T) {
	r := newRig(t)
	key := newKey(t, elliptic.P256())
	r.serve(setJSON(t, jwkOf(t, &key.PublicKey, "k1", "sig", "ES256")))
	resolver := r.resolver(t)
	if _, err := resolver.ResolveKey(r.issuer("acme"), "k1"); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.status = http.StatusServiceUnavailable
	r.mu.Unlock()
	r.clock.Advance(2 * DefaultTTL)
	if got, err := resolver.ResolveKey(r.issuer("acme"), "k1"); err != nil || !got.Key.Equal(&key.PublicKey) {
		t.Fatalf("stale key not served during the outage: %v", err)
	}
	if _, err := resolver.ResolveKey(r.issuer("acme"), "never-seen"); !errors.Is(err, ErrFetch) {
		t.Fatalf("an unseen kid must not be answered from nothing: %v", err)
	}
}

func TestIssuersAreCachedIndependentlyAndTheCacheIsBounded(t *testing.T) {
	r := newRig(t)
	r.handler = func(w http.ResponseWriter, req *http.Request) {
		key := newKey(t, elliptic.P256())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(setJSON(t, jwkOf(t, &key.PublicKey, "k1", "sig", "ES256")))
	}
	resolver := r.resolver(t)
	for i := range maxCachedIssuers + 20 {
		r.clock.Advance(time.Millisecond)
		slug := "org" + url.PathEscape(strings.Repeat("a", 1+i%40)) + strings.Repeat("b", i/40)
		if _, err := resolver.ResolveKey(r.issuer(slug), "k1"); err != nil {
			t.Fatalf("%s: %v", slug, err)
		}
	}
	resolver.mu.Lock()
	size := len(resolver.cache)
	resolver.mu.Unlock()
	if size > maxCachedIssuers {
		t.Fatalf("cache grew to %d", size)
	}
}

func TestConfigurationIsValidated(t *testing.T) {
	bad := []Config{
		{Host: "https://issuer.hukid.pe"},
		{Host: "issuer.hukid.pe/path"},
		{Host: "user@issuer.hukid.pe"},
		{Host: "issuer.hukid.pe", TTL: -time.Second},
		{Host: "issuer.hukid.pe", Timeout: -time.Second},
		{Host: "issuer.hukid.pe", TTL: time.Minute, MinRefresh: time.Hour},
	}
	for i, cfg := range bad {
		if _, err := New(cfg); !errors.Is(err, ErrConfig) {
			t.Fatalf("%d: accepted: %v", i, err)
		}
	}
	resolver, err := New(Config{})
	if err != nil || resolver.host != DefaultHost {
		t.Fatalf("defaults: %v", err)
	}
	// The caller's client is never mutated: redirects stay off on a copy only.
	client := &http.Client{Timeout: time.Hour}
	if _, err := New(Config{Client: client}); err != nil || client.CheckRedirect != nil || client.Timeout != time.Hour {
		t.Fatalf("the supplied client was modified: %v", err)
	}
}

func TestResolverFailuresCarryNoRemoteDetail(t *testing.T) {
	r := newRig(t)
	r.body = []byte("secret-remote-detail")
	_, err := r.resolver(t).ResolveKey(r.issuer("acme"), "k1")
	if err == nil || strings.Contains(err.Error(), "secret-remote-detail") {
		t.Fatalf("%v", err)
	}
}

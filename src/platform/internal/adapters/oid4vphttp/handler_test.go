package oid4vphttp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"hukid.local/platform/internal/oid4vp"
	"hukid.local/platform/internal/verification"
)

const clientID = "x509_san_dns:verifier.example"

var now = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

type sink struct {
	mu      sync.Mutex
	states  []string
	reports []verification.PresentationReport
	err     error
}

func (s *sink) Deliver(state string, report verification.PresentationReport) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states = append(s.states, state)
	s.reports = append(s.reports, report)
	return s.err
}

type rig struct {
	handler  *Handler
	sessions *oid4vp.SessionStore
	results  *sink
	session  *oid4vp.Session
	signing  *ecdsa.PrivateKey
	mux      *http.ServeMux
	clock    *time.Time
}

func newRig(t *testing.T) *rig {
	t.Helper()
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := now
	at := func() time.Time { return clock }
	verifier, err := verification.NewVerifier(verification.NewMemoryKeyResolver(), verification.ClockFunc(at), verification.DefaultLimits, 0)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := oid4vp.NewScopedReplayStore("tenant-a", oid4vp.MaxTTL, 10, at)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := oid4vp.NewSessionStore(10, at)
	if err != nil {
		t.Fatal(err)
	}
	session, err := oid4vp.NewSession(oid4vp.Config{ClientID: clientID, ResponseURI: "https://verifier.example/oid4vp/response"}, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.Put(session); err != nil {
		t.Fatal(err)
	}
	results := &sink{}
	r := &rig{sessions: sessions, results: results, session: session, signing: signing, clock: &clock}
	r.handler = &Handler{Sessions: sessions, Verifier: verifier.WithReplayStore(replay), Results: results, SigningKey: signing, Now: at}
	r.mux = http.NewServeMux()
	r.handler.Routes(r.mux)
	return r
}

func (r *rig) do(method, target, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	r.mux.ServeHTTP(rec, req)
	return rec
}

func (r *rig) post(form url.Values) *httptest.ResponseRecorder {
	return r.do(http.MethodPost, ResponsePath, "application/x-www-form-urlencoded", form.Encode())
}

// wallet fetches the request object and encrypts a response to the JWK in it,
// as a real wallet does. vp is the presentation it claims to hold.
func (r *rig) wallet(t *testing.T, vp string) string {
	t.Helper()
	rec := r.do(http.MethodGet, RequestPathPrefix+r.session.State(), "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("request object: %d %s", rec.Code, rec.Body)
	}
	object, err := jose.ParseSigned(rec.Body.String(), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := object.Verify(&r.signing.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		ClientMetadata struct {
			JWKS jose.JSONWebKeySet `json:"jwks"`
		} `json:"client_metadata"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || len(claims.ClientMetadata.JWKS.Keys) != 1 {
		t.Fatalf("client_metadata: %v", err)
	}
	key := claims.ClientMetadata.JWKS.Keys[0]
	plaintext, _ := json.Marshal(map[string]any{"vp_token": map[string][]string{"credential": {vp}}, "state": r.session.State()})
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: key.Key, KeyID: key.KeyID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jwe, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jwe.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func kidOf(t *testing.T, response string) string {
	t.Helper()
	kid, err := oid4vp.ResponseKeyID(response)
	if err != nil {
		t.Fatal(err)
	}
	return kid
}

func TestRequestObjectIsServedSignedAndUncached(t *testing.T) {
	r := newRig(t)
	rec := r.do(http.MethodGet, RequestPathPrefix+r.session.State(), "", "")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/oauth-authz-req+jwt" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	object, err := jose.ParseSigned(rec.Body.String(), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if object.Signatures[0].Protected.ExtraHeaders[jose.HeaderType] != oid4vp.RequestObjectType {
		t.Fatalf("typ: %v", object.Signatures[0].Protected.ExtraHeaders)
	}
	if _, err := object.Verify(&r.signing.PublicKey); err != nil {
		t.Fatalf("signature: %v", err)
	}
}

func TestRequestObjectLookupFailuresAreIndistinguishable(t *testing.T) {
	r := newRig(t)
	cases := map[string]string{
		"unknown state":  RequestPathPrefix + "unknown",
		"empty state":    RequestPathPrefix,
		"nested path":    RequestPathPrefix + r.session.State() + "/x",
		"query string":   RequestPathPrefix + r.session.State() + "?x=1",
		"oversize state": RequestPathPrefix + strings.Repeat("a", 129),
	}
	var first string
	for name, target := range cases {
		rec := r.do(http.MethodGet, target, "", "")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: %d", name, rec.Code)
		}
		if first == "" {
			first = rec.Body.String()
		} else if rec.Body.String() != first {
			t.Fatalf("%s: body differs", name)
		}
	}
	*r.clock = now.Add(oid4vp.DefaultTTL)
	if rec := r.do(http.MethodGet, RequestPathPrefix+r.session.State(), "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("expired: %d", rec.Code)
	}
}

func TestMethodsAreRestricted(t *testing.T) {
	r := newRig(t)
	if rec := r.do(http.MethodPost, RequestPathPrefix+r.session.State(), "", ""); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	if rec := r.do(http.MethodGet, ResponsePath, "", ""); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
}

func TestAWalletResponseIsVerifiedDeliveredAndConsumed(t *testing.T) {
	r := newRig(t)
	rec := r.post(url.Values{"response": {r.wallet(t, "not-a-presentation")}})
	if rec.Code != http.StatusOK || rec.Body.String() != "{}" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %q %v", rec.Code, rec.Body, rec.Header())
	}
	if len(r.results.reports) != 1 || r.results.states[0] != r.session.State() || r.results.reports[0].TechnicalResult != verification.Invalid {
		t.Fatalf("delivery: %+v", r.results)
	}
	if _, err := r.sessions.Get(r.session.State()); !errors.Is(err, oid4vp.ErrSessionNotFound) {
		t.Fatalf("session still open after a processed response: %v", err)
	}
	// The same session cannot be answered twice.
	if rec := r.do(http.MethodGet, RequestPathPrefix+r.session.State(), "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("request object after consumption: %d", rec.Code)
	}
}

func TestResponsesThatCannotBeAuthenticatedAreRejectedAndKeepTheSessionOpen(t *testing.T) {
	r := newRig(t)
	good := r.wallet(t, "x")
	cases := map[string]url.Values{
		"missing response": {},
		"empty response":   {"response": {""}},
		"not a jwe":        {"response": {"garbage"}},
		"extra parameter":  {"response": {good}, "state": {"s"}},
		"repeated":         {"response": {good, good}},
	}
	for name, form := range cases {
		rec := r.post(form)
		if rec.Code != http.StatusBadRequest || rec.Body.String() != `{"error":"invalid_request"}` {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, kid := range map[string]string{"unknown kid": "nobody", "right kid, wrong key": kidOf(t, good)} {
		enc, _ := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: &stranger.PublicKey, KeyID: kid}, nil)
		jwe, _ := enc.Encrypt([]byte("{}"))
		compact, _ := jwe.CompactSerialize()
		if rec := r.post(url.Values{"response": {compact}}); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", name, rec.Code)
		}
	}
	if len(r.results.reports) != 0 {
		t.Fatal("a rejected response reached the result sink")
	}
	if _, err := r.sessions.Get(r.session.State()); err != nil {
		t.Fatalf("unauthenticated garbage burned the session: %v", err)
	}
	if rec := r.post(url.Values{"response": {good}}); rec.Code != http.StatusOK {
		t.Fatalf("the genuine wallet can no longer answer: %d", rec.Code)
	}
}

func TestExpiredSessionsRejectTheResponse(t *testing.T) {
	r := newRig(t)
	response := r.wallet(t, "x")
	*r.clock = now.Add(oid4vp.DefaultTTL)
	if rec := r.post(url.Values{"response": {response}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("%d", rec.Code)
	}
}

func TestContentTypeAndSizeAreEnforced(t *testing.T) {
	r := newRig(t)
	if rec := r.do(http.MethodPost, ResponsePath, "application/json", `{"response":"x"}`); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("json: %d", rec.Code)
	}
	huge := "response=" + strings.Repeat("a", oid4vp.MaxResponseBytes+formOverhead+1)
	if rec := r.do(http.MethodPost, ResponsePath, "application/x-www-form-urlencoded", huge); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversize: %d", rec.Code)
	}
}

func TestSinkFailureIsAGenericServerError(t *testing.T) {
	r := newRig(t)
	r.results.err = errors.New("secret detail")
	rec := r.post(url.Values{"response": {r.wallet(t, "x")}})
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestAnUnconfiguredHandlerFailsClosed(t *testing.T) {
	r := newRig(t)
	r.handler.Results = nil
	if rec := r.do(http.MethodGet, RequestPathPrefix+r.session.State(), "", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("request: %d", rec.Code)
	}
	if rec := r.post(url.Values{"response": {"x"}}); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("response: %d", rec.Code)
	}
}

func TestResponsesNeverEchoTheInput(t *testing.T) {
	r := newRig(t)
	rec := r.post(url.Values{"response": {"secret-vp-token"}})
	body, _ := io.ReadAll(rec.Body)
	if strings.Contains(string(body), "secret-vp-token") {
		t.Fatal("the response echoed the input")
	}
}

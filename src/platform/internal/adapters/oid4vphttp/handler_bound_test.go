package oid4vphttp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"hukid.local/platform/internal/oid4vp"
	"hukid.local/platform/internal/verification"
)

const (
	boundSession = "11111111-1111-4111-8111-111111111111"
	boundTenant  = "22222222-2222-4222-8222-222222222222"
)

type fakeKeys struct {
	key      *ecdsa.PrivateKey
	err      error
	sessions []string
}

func (f *fakeKeys) SigningKey(_ context.Context, sessionID string) (*ecdsa.PrivateKey, string, [][]byte, error) {
	f.sessions = append(f.sessions, sessionID)
	return f.key, "kid", nil, f.err
}

// sessionSink implements both Results and SessionResults.
type sessionSink struct {
	sink
	ids []string
	err error
}

func (s *sessionSink) DeliverSession(id string, report verification.PresentationReport) error {
	s.ids = append(s.ids, id)
	s.reports = append(s.reports, report)
	return s.err
}

// boundRig replaces the rig's session with one bound to a persisted session
// and tenant, and its signing key with a custodied one.
func boundRig(t *testing.T) (*rig, *fakeKeys, *sessionSink) {
	t.Helper()
	r := newRig(t)
	session, err := oid4vp.NewSession(oid4vp.Config{ClientID: clientID, ResponseURI: "https://verifier.example/oid4vp/response", SessionID: boundSession, TenantID: boundTenant}, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.sessions.Put(session); err != nil {
		t.Fatal(err)
	}
	r.session = session
	tenantKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := &fakeKeys{key: tenantKey}
	results := &sessionSink{}
	r.handler.Keys = keys
	r.handler.Results = results
	// The wallet helper verifies the request object with r.signing.
	r.signing = tenantKey
	return r, keys, results
}

func TestBoundSessionIsSignedWithTheTenantsKey(t *testing.T) {
	r, keys, _ := boundRig(t)
	rec := r.do(http.MethodGet, RequestPathPrefix+r.session.State(), "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	object, err := jose.ParseSigned(rec.Body.String(), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := object.Verify(&keys.key.PublicKey); err != nil {
		t.Fatalf("not signed with the tenant key: %v", err)
	}
	if _, err := object.Verify(&r.handler.SigningKey.PublicKey); err == nil {
		t.Fatal("signed with the process-wide key")
	}
	if len(keys.sessions) != 1 || keys.sessions[0] != boundSession {
		t.Fatalf("key requested for %v, want the bound session", keys.sessions)
	}
}

func TestAMissingTenantKeyLooksLikeAnUnknownRequest(t *testing.T) {
	r, keys, _ := boundRig(t)
	keys.err = oid4vp.ErrNoSigningKey
	unknown := r.do(http.MethodGet, RequestPathPrefix+"unknown", "", "")
	missing := r.do(http.MethodGet, RequestPathPrefix+r.session.State(), "", "")
	if missing.Code != http.StatusNotFound || missing.Body.String() != unknown.Body.String() {
		t.Fatalf("%d %q vs %q", missing.Code, missing.Body, unknown.Body)
	}
	keys.err = errors.New("secret detail")
	rec := r.do(http.MethodGet, RequestPathPrefix+r.session.State(), "", "")
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestCustodiedKeysRefuseASessionWithoutAPersistedID(t *testing.T) {
	r := newRig(t)
	keys := &fakeKeys{key: r.signing}
	r.handler.Keys = keys
	if rec := r.do(http.MethodGet, RequestPathPrefix+r.session.State(), "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("%d", rec.Code)
	}
	if len(keys.sessions) != 0 {
		t.Fatal("asked for a key without a persisted session")
	}
}

func TestBoundResponsesGoToTheirSessionAndTenantVerifier(t *testing.T) {
	r, _, results := boundRig(t)
	base := r.handler.Verifier
	var tenants []string
	r.handler.Verifier = nil
	r.handler.VerifierFor = func(tenant string) (*verification.Verifier, error) {
		tenants = append(tenants, tenant)
		return base, nil
	}
	rec := r.post(url.Values{"response": {r.wallet(t, "not-a-presentation")}})
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(tenants) != 1 || tenants[0] != boundTenant {
		t.Fatalf("verifier for %v, want the session's tenant", tenants)
	}
	if len(results.ids) != 1 || results.ids[0] != boundSession || len(results.states) != 0 {
		t.Fatalf("delivery by id %v, by state %v", results.ids, results.states)
	}
}

func TestAFailingTenantVerifierOrSinkIsAGenericServerError(t *testing.T) {
	r, _, results := boundRig(t)
	response := r.wallet(t, "x")
	results.err = errors.New("secret detail")
	rec := r.post(url.Values{"response": {response}})
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("sink: %d %s", rec.Code, rec.Body)
	}
	r, _, _ = boundRig(t)
	r.handler.Verifier = nil
	r.handler.VerifierFor = func(string) (*verification.Verifier, error) { return nil, errors.New("secret detail") }
	rec = r.post(url.Values{"response": {r.wallet(t, "x")}})
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("verifier: %d %s", rec.Code, rec.Body)
	}
}

func TestABoundSessionNeedsASinkThatCanStoreIt(t *testing.T) {
	r, _, _ := boundRig(t)
	r.handler.Results = &sink{}
	rec := r.post(url.Values{"response": {r.wallet(t, "x")}})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("%d", rec.Code)
	}
}

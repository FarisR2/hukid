//go:build integration

package postgres

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"hukid.local/platform/internal/adapters/oid4vphttp"
	"hukid.local/platform/internal/oid4vp"
	"hukid.local/platform/internal/verification"
)

// expiryMargin mirrors privateapi.verificationExpiryMargin: the in-memory
// session expires this long before its persisted row (VER-T11-d5).
const expiryMargin = 2 * time.Second

// A response that arrives in the last moments of a session must be refused by
// the in-memory session while the row is still pending, instead of being
// accepted and then lost because complete_session refuses an expired row.
// The wallet-facing handler runs on a controlled clock; the row is real.
func TestVerificationResponseInTheExpiryMarginIsRefusedBeforeCompletion(t *testing.T) {
	db := newTestDatabase(t)
	provisioner, keys, _ := keyFixtures(t, db)
	if _, err := provisioner.Provision(testContext, vsTenantA, newP256(t), nil); err != nil {
		t.Fatal(err)
	}
	pool := db.pool(t, "hukid_verification_runtime")
	sessionID, clientID, responseURI, rowExpiry, err := (&VerificationStartStore{Pool: pool}).Start(testContext, vsOperator, vsTenantA, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := oid4vp.NewSessionStore(oid4vp.DefaultStoreCapacity, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	session, err := oid4vp.NewSession(oid4vp.Config{ClientID: clientID, ResponseURI: responseURI, TTL: time.Minute, SessionID: sessionID, TenantID: vsTenantA, NotAfter: rowExpiry.Add(-expiryMargin)}, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.Put(session); err != nil {
		t.Fatal(err)
	}
	base, err := verification.NewVerifier(verification.NewMemoryKeyResolver(), verification.ClockFunc(time.Now), verification.DefaultLimits, 0)
	if err != nil {
		t.Fatal(err)
	}
	clock := rowExpiry.Add(-10 * time.Second)
	handler := &oid4vphttp.Handler{
		Sessions: sessions,
		VerifierFor: func(tenant string) (*verification.Verifier, error) {
			store, err := NewReplayStore(pool, tenant, oid4vp.MaxTTL, oid4vp.DefaultStoreCapacity)
			if err != nil {
				return nil, err
			}
			return base.WithReplayStore(store), nil
		},
		Results: &VerificationResultStore{Pool: pool},
		Keys:    keys,
		Now:     func() time.Time { return clock },
	}
	mux := http.NewServeMux()
	handler.Routes(mux)
	do := func(method, target, contentType, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	rec := do(http.MethodGet, oid4vphttp.RequestPathPrefix+session.State(), "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("request object: %d %s", rec.Code, rec.Body)
	}
	object, err := jose.ParseSigned(rec.Body.String(), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		ClientMetadata struct {
			JWKS jose.JSONWebKeySet `json:"jwks"`
		} `json:"client_metadata"`
	}
	if err := json.Unmarshal(object.UnsafePayloadWithoutVerification(), &claims); err != nil || len(claims.ClientMetadata.JWKS.Keys) != 1 {
		t.Fatalf("client_metadata: %v", err)
	}
	encryptionKey := claims.ClientMetadata.JWKS.Keys[0]
	plaintext, _ := json.Marshal(map[string]any{"vp_token": map[string][]string{"credential": {"not-a-presentation"}}, "state": session.State()})
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: encryptionKey.Key, KeyID: encryptionKey.KeyID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jwe, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	response, err := jwe.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"response": {response}}.Encode()
	status := func() string {
		var s string
		if err := db.admin.QueryRow(testContext, `SELECT status FROM verification.sessions WHERE session_id=$1`, sessionID).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	// One second before the row expires, inside the margin: refused, and the
	// row is left pending (nothing was consumed or half-written).
	clock = rowExpiry.Add(-time.Second)
	if rec := do(http.MethodPost, oid4vphttp.ResponsePath, "application/x-www-form-urlencoded", form); rec.Code == http.StatusOK {
		t.Fatalf("a response inside the expiry margin was accepted: %s", rec.Body)
	}
	if got := status(); got != "pending" {
		t.Fatalf("row status after the refused response: %q, want pending", got)
	}

	// Before the margin the same response is accepted and the row completes,
	// which shows the refusal above came from the margin and not from the response.
	clock = rowExpiry.Add(-expiryMargin - time.Second)
	if rec := do(http.MethodPost, oid4vphttp.ResponsePath, "application/x-www-form-urlencoded", form); rec.Code != http.StatusOK || rec.Body.String() != "{}" {
		t.Fatalf("a response before the margin: %d %s", rec.Code, rec.Body)
	}
	if got := status(); got != "completed" {
		t.Fatalf("row status after the accepted response: %q, want completed", got)
	}
}

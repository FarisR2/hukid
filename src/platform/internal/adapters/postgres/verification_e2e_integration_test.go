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

// The whole tenant verification thread with real PostgreSQL and the real
// handler, as cmd/api mounts it (VER-T11-d3): start a session for a tenant,
// fetch the request object signed with that tenant's custodied key, answer it
// as a wallet would, and find the session completed with only the closed-set
// outcome stored. Each piece has its own test; this is the one that proves
// they fit together.
func TestVerificationThreadFromStartToCompletedRow(t *testing.T) {
	db := newTestDatabase(t)
	provisioner, keys, _ := keyFixtures(t, db)
	tenantKey := newP256(t)
	kid, err := provisioner.Provision(testContext, vsTenantA, tenantKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	otherKey := newP256(t)
	if _, err := provisioner.Provision(testContext, vsTenantB, otherKey, nil); err != nil {
		t.Fatal(err)
	}

	pool := db.pool(t, "hukid_verification_runtime")
	sessionID, clientID, responseURI, _, err := (&VerificationStartStore{Pool: pool}).Start(testContext, vsOperator, vsTenantA, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := oid4vp.NewSessionStore(oid4vp.DefaultStoreCapacity, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	session, err := oid4vp.NewSession(oid4vp.Config{ClientID: clientID, ResponseURI: responseURI, TTL: 5 * time.Minute, SessionID: sessionID, TenantID: vsTenantA}, time.Now(), nil)
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
	var verifiedFor []string
	handler := &oid4vphttp.Handler{
		Sessions: sessions,
		VerifierFor: func(tenant string) (*verification.Verifier, error) {
			verifiedFor = append(verifiedFor, tenant)
			store, err := NewReplayStore(pool, tenant, oid4vp.MaxTTL, oid4vp.DefaultStoreCapacity)
			if err != nil {
				return nil, err
			}
			return base.WithReplayStore(store), nil
		},
		Results: &VerificationResultStore{Pool: pool},
		Keys:    keys,
		Now:     time.Now,
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

	// 1. The wallet fetches the request object: ES256, signed with the key
	// custodied for the session's tenant and not with another tenant's.
	rec := do(http.MethodGet, oid4vphttp.RequestPathPrefix+session.State(), "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("request object: %d %s", rec.Code, rec.Body)
	}
	object, err := jose.ParseSigned(rec.Body.String(), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := object.Verify(&otherKey.PublicKey); err == nil {
		t.Fatal("the request object verifies with another tenant's key")
	}
	payload, err := object.Verify(&tenantKey.PublicKey)
	if err != nil {
		t.Fatalf("the request object does not verify with the tenant's key: %v", err)
	}
	if object.Signatures[0].Header.KeyID != kid {
		t.Fatalf("request object kid %q, want the custodied %q", object.Signatures[0].Header.KeyID, kid)
	}
	var claims struct {
		ClientMetadata struct {
			JWKS jose.JSONWebKeySet `json:"jwks"`
		} `json:"client_metadata"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || len(claims.ClientMetadata.JWKS.Keys) != 1 {
		t.Fatalf("client_metadata: %v", err)
	}
	var pinned string
	if err := db.admin.QueryRow(testContext, `SELECT signing_kid FROM verification.sessions WHERE session_id=$1`, sessionID).Scan(&pinned); err != nil || pinned != kid {
		t.Fatalf("the session did not pin the signing kid: %q %v", pinned, err)
	}

	// 2. The wallet answers with a response encrypted to the key in the request
	// object. The presentation is not valid, so the outcome must be a failure.
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
	if rec := do(http.MethodPost, oid4vphttp.ResponsePath, "application/x-www-form-urlencoded", form); rec.Code != http.StatusOK || rec.Body.String() != "{}" {
		t.Fatalf("wallet response: %d %s", rec.Code, rec.Body)
	}
	if len(verifiedFor) != 1 || verifiedFor[0] != vsTenantA {
		t.Fatalf("the response was verified for %v, want only the session's tenant", verifiedFor)
	}

	// 3. The session row is completed, with the closed-set outcome and nothing
	// of the presentation.
	var status, result string
	var codes []string
	var digest []byte
	if err := db.admin.QueryRow(testContext, `SELECT status,result,codes,report_digest FROM verification.sessions WHERE session_id=$1`, sessionID).Scan(&status, &result, &codes, &digest); err != nil {
		t.Fatal(err)
	}
	if status != "completed" || result != "fail" || len(codes) == 0 || len(digest) != 32 {
		t.Fatalf("stored outcome: status=%q result=%q codes=%v digest=%d bytes", status, result, codes, len(digest))
	}
	for _, code := range codes {
		if !verification.IsKnown(verification.Code(code)) {
			t.Fatalf("stored code %q is outside the closed set", code)
		}
	}
	var leaked bool
	if err := db.admin.QueryRow(testContext, `SELECT row_to_json(s)::text LIKE '%not-a-presentation%' OR row_to_json(s)::text LIKE '%'||$2||'%' FROM verification.sessions s WHERE session_id=$1`, sessionID, session.State()).Scan(&leaked); err != nil || leaked {
		t.Fatalf("the session row holds the presentation or the state: leaked=%v err=%v", leaked, err)
	}

	// 4. Nothing can answer it again: the response is refused, the request
	// object is gone, and the stored row does not change.
	if rec := do(http.MethodPost, oid4vphttp.ResponsePath, "application/x-www-form-urlencoded", form); rec.Code == http.StatusOK {
		t.Fatal("a completed session accepted a second response")
	}
	if rec := do(http.MethodGet, oid4vphttp.RequestPathPrefix+session.State(), "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("request object after completion: %d", rec.Code)
	}
	var completions int
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM verification.sessions WHERE tenant_id=$1 AND status='completed'`, vsTenantA).Scan(&completions); err != nil || completions != 1 {
		t.Fatalf("completed sessions: %d %v", completions, err)
	}
}

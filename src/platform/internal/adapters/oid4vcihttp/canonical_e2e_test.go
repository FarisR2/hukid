package oid4vcihttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"hukid.local/platform/internal/issuance"
	"hukid.local/platform/internal/verification"
)

type muxArtifactResolver struct {
	mux *http.ServeMux
}

func (r muxArtifactResolver) ResolveStatusList(credentialURL string) (string, error) {
	u, err := url.Parse(credentialURL)
	if err != nil {
		return "", err
	}
	rec := httptest.NewRecorder()
	r.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, u.Path, nil))
	if rec.Code != http.StatusOK {
		return "", fmt.Errorf("status list %d", rec.Code)
	}
	return rec.Body.String(), nil
}

func (r muxArtifactResolver) ResolveSchema(schemaURL string) ([]byte, error) {
	u, err := url.Parse(schemaURL)
	if err != nil {
		return nil, err
	}
	rec := httptest.NewRecorder()
	r.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, u.Path, nil))
	if rec.Code != http.StatusOK {
		return nil, fmt.Errorf("schema %d", rec.Code)
	}
	return rec.Body.Bytes(), nil
}

func redeemCanonicalOfferForVC(t *testing.T, mux *http.ServeMux, issuerSlug, offerURI string, now time.Time) (string, string, int) {
	t.Helper()
	u, err := url.Parse(offerURI)
	if err != nil || u.Scheme != "openid-credential-offer" {
		t.Fatalf("invalid credentialOfferUri %q: %v", offerURI, err)
	}
	offerTarget, err := url.Parse(u.Query().Get("credential_offer_uri"))
	if err != nil {
		t.Fatalf("invalid inner offer URL: %v", err)
	}
	offerRec := httptest.NewRecorder()
	mux.ServeHTTP(offerRec, httptest.NewRequest(http.MethodGet, offerTarget.Path, nil))
	if offerRec.Code != http.StatusOK {
		t.Fatalf("GET offer failed: %d %s", offerRec.Code, offerRec.Body.String())
	}
	var offer issuance.CredentialOffer
	if err := json.Unmarshal(offerRec.Body.Bytes(), &offer); err != nil {
		t.Fatalf("decode offer: %v", err)
	}
	preCode := offer.Grants[issuance.PreAuthorizedGrantType].PreAuthorizedCode

	form := url.Values{
		"grant_type":          {issuance.PreAuthorizedGrantType},
		"pre-authorized_code": {preCode},
	}
	tokReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRec := httptest.NewRecorder()
	mux.ServeHTTP(tokRec, tokReq)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("pre-authorized token failed: %d %s", tokRec.Code, tokRec.Body.String())
	}
	var tok issuance.TokenResponse
	if err := json.Unmarshal(tokRec.Body.Bytes(), &tok); err != nil || len(tok.AuthorizationDetails) != 1 {
		t.Fatalf("decode wallet token: %v %+v", err, tok)
	}

	nonceRec := httptest.NewRecorder()
	mux.ServeHTTP(nonceRec, httptest.NewRequest(http.MethodPost, "/"+issuerSlug+"/nonce", nil))
	if nonceRec.Code != http.StatusOK {
		t.Fatalf("nonce failed: %d %s", nonceRec.Code, nonceRec.Body.String())
	}
	var nonceBody struct {
		CNonce string `json:"c_nonce"`
	}
	if err := json.Unmarshal(nonceRec.Body.Bytes(), &nonceBody); err != nil || nonceBody.CNonce == "" {
		t.Fatalf("decode nonce: %v", err)
	}

	proofJWT, err := issuance.BuildHolderProof(mustKey(t), issuance.IssuerPrefix+issuerSlug, nonceBody.CNonce, now, nil)
	if err != nil {
		t.Fatalf("build holder proof: %v", err)
	}
	credBody, _ := json.Marshal(map[string]any{
		"credential_identifier": tok.AuthorizationDetails[0].CredentialIdentifiers[0],
		"proofs":                map[string]any{"jwt": []string{proofJWT}},
	})
	credReq := httptest.NewRequest(http.MethodPost, "/"+issuerSlug+"/credential", strings.NewReader(string(credBody)))
	credReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	credReq.Header.Set("Content-Type", "application/json")
	credRec := httptest.NewRecorder()
	mux.ServeHTTP(credRec, credReq)
	if credRec.Code == http.StatusAccepted {
		var asyncResp struct {
			TransactionID string `json:"transaction_id"`
		}
		if err := json.Unmarshal(credRec.Body.Bytes(), &asyncResp); err != nil {
			t.Fatalf("decode deferred response: %v", err)
		}
		return asyncResp.TransactionID, tok.AccessToken, http.StatusAccepted
	}
	if credRec.Code != http.StatusOK {
		t.Fatalf("credential failed: %d %s", credRec.Code, credRec.Body.String())
	}
	var syncResp struct {
		Credentials []struct {
			Credential string `json:"credential"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(credRec.Body.Bytes(), &syncResp); err != nil || len(syncResp.Credentials) != 1 {
		t.Fatalf("decode credential: %v %+v", err, syncResp)
	}
	return syncResp.Credentials[0].Credential, tok.AccessToken, http.StatusOK
}

func TestCanonicalEventParticipationEndToEndFlow(t *testing.T) {
	env := setupHTTPTestEnv(t)

	// 1. Publish canonical Event Participation Certificate definition on UNAS issuer.
	canonDef := issuance.CanonicalEventParticipationDefinition("tenant-unas", "iss_unas", issuance.IssuerPrefix+"unas")
	if err := issuance.ValidateDefinition(canonDef); err != nil {
		t.Fatalf("canonical definition invalid: %v", err)
	}
	if err := env.defs.CreateDraft(canonDef, "admin-1", "cor-canon-1", env.now); err != nil {
		t.Fatalf("create canonical draft: %v", err)
	}
	if _, err := env.defs.Publish("tenant-unas", "iss_unas", canonDef.ID, canonDef.Version, "admin-1", "cor-canon-2", env.now); err != nil {
		t.Fatalf("publish canonical definition: %v", err)
	}

	metaRec := httptest.NewRecorder()
	env.mux.ServeHTTP(metaRec, httptest.NewRequest(http.MethodGet, "/unas/.well-known/openid-credential-issuer", nil))
	if metaRec.Code != http.StatusOK || !strings.Contains(metaRec.Body.String(), issuance.CanonicalEventParticipationConfigID) {
		t.Fatalf("expected canonical configuration in issuer metadata: %d %s", metaRec.Code, metaRec.Body.String())
	}

	// Register M2M client with create + read + status:write scopes (adapter Team 4).
	if err := env.clients.RegisterClient(
		"tenant-unas",
		"cli_events_canonical",
		"Events Canonical Adapter",
		"canonical-client-secret-0123456789ab",
		[]string{"iss_unas"},
		[]string{issuance.ScopeIssuanceCreate, issuance.ScopeIssuanceRead, issuance.ScopeStatusWrite},
		nil,
		"admin-1",
		"cor-canon-3",
		env.now,
	); err != nil {
		t.Fatalf("register canonical client: %v", err)
	}

	tokForm := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"cli_events_canonical"},
		"client_secret": {"canonical-client-secret-0123456789ab"},
		"scope":         {"issuance:create issuance:read status:write"},
	}
	tokReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(tokForm.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRec := httptest.NewRecorder()
	env.mux.ServeHTTP(tokRec, tokReq)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("token failed: %d %s", tokRec.Code, tokRec.Body.String())
	}
	var m2mTok issuance.TokenResponse
	_ = json.Unmarshal(tokRec.Body.Bytes(), &m2mTok)

	postReq := func(key, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/issuance-requests", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+m2mTok.AccessToken)
		req.Header.Set("Idempotency-Key", key)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		env.mux.ServeHTTP(rec, req)
		return rec
	}

	// 2. Negative validations: PII leak guard (extra email rejected without echo), tx_code v0 unsupported, TTL > 300s.
	piiRec := postReq("canon-neg-pii-0001", `{
		"issuerId": "iss_unas",
		"credentialDefinition": "event-participation-certificate@1.0.0",
		"claims": {
			"participantName": "Ana María Quispe",
			"eventTitle": "Congreso Cloud UNAS",
			"organizerName": "IncubaUNAS",
			"eventDate": "2026-11-18",
			"participationRole": "attendee",
			"certificateNumber": "CERT-2026-0001",
			"email": "sensitive-canary@example.invalid"
		}
	}`)
	if piiRec.Code != http.StatusUnprocessableEntity || strings.Contains(piiRec.Body.String(), "sensitive-canary@example.invalid") {
		t.Fatalf("expected 422 without echoing rejected email claim, got %d %s", piiRec.Code, piiRec.Body.String())
	}

	txCodeRec := postReq("canon-neg-tx-0001", `{
		"issuerId": "iss_unas",
		"credentialDefinition": "event-participation-certificate@1.0.0",
		"claims": {
			"participantName": "Ana María Quispe",
			"eventTitle": "Congreso Cloud UNAS",
			"organizerName": "IncubaUNAS",
			"eventDate": "2026-11-18",
			"participationRole": "attendee",
			"certificateNumber": "CERT-2026-0001"
		},
		"delivery": {"flow": "pre-authorized_code", "txCodeRequired": true}
	}`)
	if txCodeRec.Code != http.StatusUnprocessableEntity || !strings.Contains(txCodeRec.Body.String(), `"code":"delivery_not_supported"`) {
		t.Fatalf("expected 422 delivery_not_supported for txCodeRequired v0, got %d %s", txCodeRec.Code, txCodeRec.Body.String())
	}

	ttlRec := postReq("canon-neg-ttl-0001", `{
		"issuerId": "iss_unas",
		"credentialDefinition": "event-participation-certificate@1.0.0",
		"claims": {
			"participantName": "Ana María Quispe",
			"eventTitle": "Congreso Cloud UNAS",
			"organizerName": "IncubaUNAS",
			"eventDate": "2026-11-18",
			"participationRole": "attendee",
			"certificateNumber": "CERT-2026-0001"
		},
		"delivery": {"flow": "pre-authorized_code", "expiresInSeconds": 301}
	}`)
	if ttlRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for TTL > MaxOfferTTL (300s), got %d %s", ttlRec.Code, ttlRec.Body.String())
	}

	// 3. Immediate canonical flow: create (201) -> replay (200) -> Wallet OID4VCI -> Verify VC + schema + status -> Revoke -> Verify fails.
	validBody := `{
		"issuerId": "iss_unas",
		"credentialDefinition": "event-participation-certificate@1.0.0",
		"claims": {
			"participantName": "Ana María Quispe",
			"eventTitle": "Congreso Cloud UNAS",
			"organizerName": "IncubaUNAS",
			"eventDate": "2026-11-18",
			"participationRole": "attendee",
			"certificateNumber": "CERT-2026-0001"
		},
		"delivery": {"flow": "pre-authorized_code", "expiresInSeconds": 300},
		"source": {"system": "events", "reference": "cert-2026-0001"}
	}`
	createRec := postReq("canon-ok-req-0001", validBody)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create canonical request failed: %d %s", createRec.Code, createRec.Body.String())
	}
	var created issuance.IssuanceRequestResult
	_ = json.Unmarshal(createRec.Body.Bytes(), &created)

	replayRec := postReq("canon-ok-req-0001", validBody)
	if replayRec.Code != http.StatusOK {
		t.Fatalf("idempotent replay failed: %d %s", replayRec.Code, replayRec.Body.String())
	}

	vcJWT, _, status := redeemCanonicalOfferForVC(t, env.mux, "unas", created.CredentialOfferURI, env.now)
	if status != http.StatusOK {
		t.Fatalf("expected immediate 200 VC, got status=%d", status)
	}

	// Build verifier with JWKS, StatusResolver (VER-T09 DefaultStatusPolicy) and SchemaResolver (VER-T13).
	jwksRec := httptest.NewRecorder()
	env.mux.ServeHTTP(jwksRec, httptest.NewRequest(http.MethodGet, "/unas/.well-known/jwks.json", nil))
	var jwksDoc issuance.JWKS
	_ = json.Unmarshal(jwksRec.Body.Bytes(), &jwksDoc)

	muxRes := muxArtifactResolver{mux: env.mux}
	verifier, err := verification.NewVerifier(
		resolverFromHTTPJWKS(t, issuance.IssuerPrefix+"unas", jwksDoc),
		verification.ClockFunc(func() time.Time { return env.now }),
		verification.DefaultLimits,
		verification.DefaultClockSkew,
	)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	verifier = verifier.
		WithCredentialContexts(canonDef.Contexts[0]).
		WithStatusResolver(muxRes, verification.DefaultStatusPolicy()).
		WithSchemaResolver(muxRes)

	rep, err := verifier.Verify(vcJWT)
	if err != nil || rep.TechnicalResult != verification.Valid {
		t.Fatalf("canonical VC verification (with schema + status) failed: rep=%+v err=%v", rep, err)
	}

	// Confirm polling sees issued + credentialId.
	pollReq := httptest.NewRequest(http.MethodGet, "/v1/issuance-requests/"+created.ID, nil)
	pollReq.Header.Set("Authorization", "Bearer "+m2mTok.AccessToken)
	pollRec := httptest.NewRecorder()
	env.mux.ServeHTTP(pollRec, pollReq)
	var polled issuance.IssuanceRequestResult
	_ = json.Unmarshal(pollRec.Body.Bytes(), &polled)
	if pollRec.Code != http.StatusOK || polled.IssuanceState != "issued" || polled.CredentialID == "" {
		t.Fatalf("expected polled request issued with credentialId, got %d %+v", pollRec.Code, polled)
	}

	// Confirm ADR-0035 metadata-only operator views exclude PII/secrets.
	opReqs, err := env.service.ListOperatorRequests("tenant-unas", issuance.AdminListFilter{IssuerID: "iss_unas", Limit: 20})
	if err != nil || len(opReqs) == 0 {
		t.Fatalf("ListOperatorRequests failed: len=%d err=%v", len(opReqs), err)
	}
	opCreds, err := env.service.ListOperatorCredentials("tenant-unas", issuance.AdminListFilter{IssuerID: "iss_unas", Limit: 20})
	if err != nil || len(opCreds) == 0 {
		t.Fatalf("ListOperatorCredentials failed: len=%d err=%v", len(opCreds), err)
	}
	opReqsRaw, _ := json.Marshal(opReqs)
	opCredsRaw, _ := json.Marshal(opCreds)
	for _, secret := range []string{"Ana María Quispe", "CERT-2026-0001", "cert-2026-0001", "ofr_", vcJWT} {
		if strings.Contains(string(opReqsRaw), secret) || strings.Contains(string(opCredsRaw), secret) {
			t.Fatalf("operator summary leaked restricted field %q", secret)
		}
	}

	// Revoke via M2M status:write and verify Bitstring Status List detects revocation.
	revReq := httptest.NewRequest(http.MethodPost, "/v1/credentials/"+polled.CredentialID+"/revocations", strings.NewReader(`{"reasonCode":"events_certificate_annulled"}`))
	revReq.Header.Set("Authorization", "Bearer "+m2mTok.AccessToken)
	revReq.Header.Set("Idempotency-Key", "canon-revoke-req-0001")
	revReq.Header.Set("Content-Type", "application/json")
	revRec := httptest.NewRecorder()
	env.mux.ServeHTTP(revRec, revReq)
	if revRec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted on revocation, got %d %s", revRec.Code, revRec.Body.String())
	}
	revokedRep, err := verifier.Verify(vcJWT)
	if err != nil || revokedRep.TechnicalResult != verification.Invalid {
		t.Fatalf("expected revoked VC to fail verification, got %+v err=%v", revokedRep, err)
	}

	// 4. Deferred issuance canonical path: 202 transaction_id -> 400 issuance_pending -> fulfill -> 200 vc+jwt.
	defReqRec := postReq("canon-def-req-0001", `{
		"issuerId": "iss_unas",
		"credentialDefinition": "event-participation-certificate@1.0.0",
		"claims": {
			"participantName": "Carlos Mendoza",
			"eventTitle": "Congreso Cloud UNAS",
			"organizerName": "IncubaUNAS",
			"eventDate": "2026-11-18",
			"participationRole": "speaker",
			"certificateNumber": "CERT-2026-0002"
		},
		"delivery": {"flow": "pre-authorized_code", "deferred": true}
	}`)
	if defReqRec.Code != http.StatusCreated {
		t.Fatalf("create deferred canonical request failed: %d %s", defReqRec.Code, defReqRec.Body.String())
	}
	var defCreated issuance.IssuanceRequestResult
	_ = json.Unmarshal(defReqRec.Body.Bytes(), &defCreated)

	txID, walletAccessTok, asyncStatus := redeemCanonicalOfferForVC(t, env.mux, "unas", defCreated.CredentialOfferURI, env.now)
	if asyncStatus != http.StatusAccepted || txID == "" {
		t.Fatalf("expected 202 transaction_id on deferred canonical claim, got status=%d tx=%q", asyncStatus, txID)
	}

	pollDeferred := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/unas/deferred_credential", strings.NewReader(`{"transaction_id":"`+txID+`"}`))
		req.Header.Set("Authorization", "Bearer "+walletAccessTok)
		req.Header.Set("Content-Type", "application/json")
		env.mux.ServeHTTP(rec, req)
		return rec
	}

	if pending := pollDeferred(); pending.Code != http.StatusBadRequest || !strings.Contains(pending.Body.String(), `"error":"issuance_pending"`) {
		t.Fatalf("expected 400 issuance_pending, got %d %s", pending.Code, pending.Body.String())
	}
	if err := env.service.FulfillDeferredRequest("tenant-unas", defCreated.ID); err != nil {
		t.Fatalf("fulfill deferred request: %v", err)
	}
	done := pollDeferred()
	if done.Code != http.StatusOK || !strings.Contains(done.Body.String(), `"credential":"eyJ`) {
		t.Fatalf("expected 200 vc+jwt after fulfill, got %d %s", done.Code, done.Body.String())
	}
}

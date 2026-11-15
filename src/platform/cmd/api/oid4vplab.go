package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"

	"hukid.local/platform/internal/adapters/oid4vphttp"
	"hukid.local/platform/internal/oid4vp"
	"hukid.local/platform/internal/verification"
)

// The OpenID4VP laboratory mount (FEAT-004, VER-T10 increment e) exposes the
// wallet-facing endpoints so an external wallet or verifier can be tried
// against them. It is NOT the production mount: it is off unless
// HUKID_OID4VP_LAB=1, refuses any environment other than test or local, seeds
// exactly one session at startup (there is no authenticated way to start
// sessions until VER-T11), reads issuer keys from a file (there is no JWKS
// resolver until VER-T12), keeps replay and sessions in memory, and uses an
// ephemeral request-signing key without a certificate chain.
//
// Variables (all required once HUKID_OID4VP_LAB is set):
//
//	HUKID_OID4VP_LAB_CLIENT_ID    verifier client identifier, also the VP audience
//	HUKID_OID4VP_LAB_RESPONSE_URI exact https URI whose path is /oid4vp/response
//	HUKID_OID4VP_LAB_ISSUER_KEYS  JSON file: [{"issuer","kid","jwk"}] with P-256 public keys
const (
	labFlag       = "HUKID_OID4VP_LAB"
	labClientID   = "HUKID_OID4VP_LAB_CLIENT_ID"
	labResponse   = "HUKID_OID4VP_LAB_RESPONSE_URI"
	labIssuerKeys = "HUKID_OID4VP_LAB_ISSUER_KEYS"

	labMaxKeysFile = 64 << 10
	labMaxKeys     = 32
)

var errLabConfig = errors.New("complete oid4vp laboratory configuration is required (test or local only)")

type labIssuerKey struct {
	Issuer string          `json:"issuer"`
	Kid    string          `json:"kid"`
	JWK    json.RawMessage `json:"jwk"`
}

// labResults prints each report as one JSON line. Reports hold codes, a digest
// and per-credential checks, never the JWS or the claims, and never the state.
type labResults struct{ out io.Writer }

func (r labResults) Deliver(_ string, report verification.PresentationReport) error {
	line, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(r.out, "oid4vp-lab report %s\n", line)
	return err
}

func loadLabIssuerKeys(path string) (*verification.MemoryKeyResolver, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errLabConfig
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, labMaxKeysFile+1))
	if err != nil || len(data) > labMaxKeysFile {
		return nil, errLabConfig
	}
	var entries []labIssuerKey
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&entries) != nil || decoder.Decode(new(any)) != io.EOF || len(entries) == 0 || len(entries) > labMaxKeys {
		return nil, errLabConfig
	}
	keys := verification.NewMemoryKeyResolver()
	for _, entry := range entries {
		var jwk jose.JSONWebKey
		if jwk.UnmarshalJSON(entry.JWK) != nil || !jwk.IsPublic() {
			return nil, errLabConfig
		}
		public, ok := jwk.Key.(*ecdsa.PublicKey)
		if !ok || keys.Add(entry.Issuer, entry.Kid, public) != nil {
			return nil, errLabConfig
		}
	}
	return keys, nil
}

// configureOID4VPLab returns the routes of the laboratory mount, or nil when
// it is not enabled. out receives the launch URI and the reports. now may be
// nil to use time.Now.
func configureOID4VPLab(out io.Writer, now func() time.Time) (func(*http.ServeMux), error) {
	enabled, clientID, response, keysPath := os.Getenv(labFlag), os.Getenv(labClientID), os.Getenv(labResponse), os.Getenv(labIssuerKeys)
	if enabled == "" && clientID == "" && response == "" && keysPath == "" {
		return nil, nil
	}
	if enabled != "1" || clientID == "" || response == "" || keysPath == "" {
		return nil, errLabConfig
	}
	if environment := os.Getenv("HUKID_ENV"); environment != "test" && environment != "local" {
		return nil, errLabConfig
	}
	parsed, err := url.Parse(response)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != oid4vphttp.ResponsePath || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return nil, errLabConfig
	}
	if now == nil {
		now = time.Now
	}
	keys, err := loadLabIssuerKeys(keysPath)
	if err != nil {
		return nil, err
	}
	verifier, err := verification.NewVerifier(keys, verification.ClockFunc(now), verification.DefaultLimits, 0)
	if err != nil {
		return nil, errLabConfig
	}
	replay, err := oid4vp.NewScopedReplayStore("oid4vp-lab", oid4vp.MaxTTL, 64, now)
	if err != nil {
		return nil, errLabConfig
	}
	sessions, err := oid4vp.NewSessionStore(1, now)
	if err != nil {
		return nil, errLabConfig
	}
	session, err := oid4vp.NewSession(oid4vp.Config{ClientID: clientID, ResponseURI: response}, now(), nil)
	if err != nil || sessions.Put(session) != nil {
		return nil, errLabConfig
	}
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errLabConfig
	}
	pinned, err := (&jose.JSONWebKey{Key: &signing.PublicKey, Use: "sig", Algorithm: string(jose.ES256)}).MarshalJSON()
	if err != nil {
		return nil, errLabConfig
	}
	requestURI := (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: oid4vphttp.RequestPathPrefix + session.State()}).String()
	launch := url.Values{"client_id": {clientID}, "request_uri": {requestURI}, "request_uri_method": {"get"}}
	// The launch URI carries the session handle, so it goes to the operator's
	// terminal only; the process logger never sees it.
	fmt.Fprintf(out, "oid4vp-lab launch openid4vp://authorize?%s\n", launch.Encode())
	fmt.Fprintf(out, "oid4vp-lab request-signing-key %s\n", pinned)
	fmt.Fprintf(out, "oid4vp-lab session-expires %s\n", session.ExpiresAt().UTC().Format(time.RFC3339))
	handler := &oid4vphttp.Handler{Sessions: sessions, Verifier: verifier.WithReplayStore(replay), Results: labResults{out: out}, SigningKey: signing, Now: now}
	return handler.Routes, nil
}

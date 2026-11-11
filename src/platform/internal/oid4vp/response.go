package oid4vp

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/go-jose/go-jose/v4"

	"hukid.local/platform/internal/verification"
)

// MaxResponseBytes bounds the encrypted response before it is parsed. It sits
// above the proposed 64 KiB presentation limit plus JWE overhead.
const MaxResponseBytes = 192 * 1024

type responsePayload struct {
	VPToken map[string][]string `json:"vp_token"`
	State   string              `json:"state"`
}

// HandleResponse decrypts the direct_post.jwt response and verifies the
// presentation through the core. response is the value of the form parameter
// "response" (a compact JWE).
//
// Order: expiry, JWE parsing restricted to ECDH-ES/A256GCM, decryption with the
// session key, payload shape, then verification.Verifier.VerifyPresentation,
// which consumes the request only after the holder signature is valid, so an
// unauthenticated sender cannot burn it. Anything that fails before the core
// returns ErrResponseInvalid with no detail; a verification outcome (valid or
// invalid) is a report; the error is otherwise only a core infrastructure
// failure (resolver or replay store).
func (s *Session) HandleResponse(v *verification.Verifier, now time.Time, response string) (verification.PresentationReport, error) {
	if v == nil {
		return verification.PresentationReport{}, ErrConfig
	}
	if !now.UTC().Before(s.expiresAt) {
		return verification.PresentationReport{}, ErrSessionExpired
	}
	if len(response) == 0 || len(response) > MaxResponseBytes {
		return verification.PresentationReport{}, ErrResponseInvalid
	}
	// Restricting the accepted algorithms rejects a plain JWS/JWT or an
	// unencrypted payload and any other key-management or content algorithm.
	object, err := jose.ParseEncrypted(response, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return verification.PresentationReport{}, ErrResponseInvalid
	}
	if object.Header.KeyID != s.kid {
		return verification.PresentationReport{}, ErrResponseInvalid
	}
	if _, compressed := object.Header.ExtraHeaders[jose.HeaderKey("zip")]; compressed {
		return verification.PresentationReport{}, ErrResponseInvalid
	}
	plaintext, err := object.Decrypt(s.encKey)
	if err != nil {
		return verification.PresentationReport{}, ErrResponseInvalid
	}

	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	var payload responsePayload
	if err := decoder.Decode(&payload); err != nil || decoder.More() {
		return verification.PresentationReport{}, ErrResponseInvalid
	}
	presentations := payload.VPToken[s.cfg.CredentialQueryID]
	if len(payload.VPToken) != 1 || len(presentations) != 1 || presentations[0] == "" {
		return verification.PresentationReport{}, ErrResponseInvalid
	}

	return v.VerifyPresentation(
		verification.Response{VP: presentations[0], State: payload.State},
		verification.Request{Audience: s.cfg.ClientID, Nonce: s.nonce, State: s.state},
	)
}

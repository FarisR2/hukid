package authentication

import "encoding/json"

// SessionSecrets stays server-side; it is never an HTTP response model.
type SessionSecrets struct {
	Recipient     *RecipientEvidence `json:"recipient,omitempty"`
	AccessToken   string             `json:"accessToken"`
	RefreshToken  string             `json:"refreshToken"`
	CSRF          string             `json:"csrf"`
	OIDCNonceHash []byte             `json:"oidcNonceHash,omitempty"`
}

func encodeRecipientSecrets(access, refresh, csrf string, nonce []byte, recipient *RecipientEvidence) ([]byte, error) {
	return json.Marshal(SessionSecrets{AccessToken: access, RefreshToken: refresh, CSRF: csrf, OIDCNonceHash: nonce, Recipient: recipient})
}

func encodeSecrets(access, refresh, csrf string, nonceHash ...[]byte) ([]byte, error) {
	v := SessionSecrets{AccessToken: access, RefreshToken: refresh, CSRF: csrf}
	if len(nonceHash) > 0 {
		v.OIDCNonceHash = nonceHash[0]
	}
	return json.Marshal(v)
}

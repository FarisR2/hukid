package authentication

import "encoding/json"

// SessionSecrets stays server-side; it is never an HTTP response model.
type SessionSecrets struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	CSRF         string `json:"csrf"`
}

func encodeSecrets(access, refresh, csrf string) ([]byte, error) {
	return json.Marshal(SessionSecrets{access, refresh, csrf})
}

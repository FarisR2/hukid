// Package memberconfig loads separate laboratory invitation secrets.
package memberconfig

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
)

type Secrets struct {
	Key, HMAC []byte
	Version   string
}

func Load() (*Secrets, error) {
	raw, mac, version := os.Getenv("HUKID_INVITATION_KEY"), os.Getenv("HUKID_INVITATION_HMAC_KEY"), os.Getenv("HUKID_INVITATION_KEY_VERSION")
	if raw == "" && mac == "" && version == "" {
		return nil, nil
	}
	invalid := errors.New("complete isolated invitation secrets required")
	if (os.Getenv("HUKID_ENV") != "test" && os.Getenv("HUKID_ENV") != "local" && os.Getenv("HUKID_ENV") != "staging") || version == "" || len(version) > 128 {
		return nil, invalid
	}
	key, e := base64.StdEncoding.Strict().DecodeString(raw)
	hmac, e2 := base64.StdEncoding.Strict().DecodeString(mac)
	if e != nil || e2 != nil || len(key) != 32 || len(hmac) != 32 || bytes.Equal(key, hmac) {
		return nil, invalid
	}
	for _, name := range []string{"HUKID_AUTH_KEY", "HUKID_MEMBERS_CURSOR_KEY"} {
		other, _ := base64.StdEncoding.Strict().DecodeString(os.Getenv(name))
		if bytes.Equal(key, other) || bytes.Equal(hmac, other) {
			return nil, invalid
		}
	}
	return &Secrets{key, hmac, version}, nil
}
func (s *Secrets) Clear() {
	if s != nil {
		clear(s.Key)
		clear(s.HMAC)
	}
}

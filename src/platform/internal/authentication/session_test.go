package authentication

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

type readStore struct {
	value ReadSession
	err   error
	calls int
}

func (s *readStore) ReadSession(context.Context, []byte, time.Time) (ReadSession, error) {
	s.calls++
	return s.value, s.err
}
func (s *readStore) TouchSession(context.Context, []byte, time.Time, time.Duration) error {
	return s.err
}

type readCipher struct {
	data []byte
	err  error
}

func (c readCipher) Seal([]byte, string) (Envelope, error) { return Envelope{}, nil }
func (c readCipher) Open(Envelope, string) ([]byte, error) { return append([]byte{}, c.data...), c.err }
func TestSessionReadStrictBoundariesAndIntegrity(t *testing.T) {
	now := time.Unix(2000000000, 0)
	csrf := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	cookie := csrf
	for _, name := range []string{"valid", "malformed", "unknown", "idle_deadline", "absolute_deadline", "future", "wrong_generation", "wrong_policy", "cipher", "csrf"} {
		t.Run(name, func(t *testing.T) {
			p := Policy{SessionAbsoluteSeconds: 3600, SessionIdleSeconds: 1800}
			store := &readStore{value: ReadSession{FamilyID: "family", ActorID: "actor", PolicyVersion: "auth-test-v1", Generation: 1, CSRFHash: Digest(csrf), CreatedAt: now.Add(-time.Minute), FamilyCreatedAt: now.Add(-time.Minute), LastSeenAt: now.Add(-time.Minute), IdleExpiresAt: now.Add(time.Minute), AbsoluteExpiresAt: now.Add(time.Hour)}}
			data, _ := encodeSecrets("access", "refresh", csrf)
			cipher := readCipher{data: data}
			value := cookie
			switch name {
			case "malformed":
				value = "invalid"
			case "unknown":
				store.err = ErrSession
			case "idle_deadline":
				store.value.IdleExpiresAt = now
			case "absolute_deadline":
				store.value.AbsoluteExpiresAt = now
			case "future":
				store.value.LastSeenAt = now.Add(time.Second)
			case "wrong_generation":
				store.value.Generation = 0
			case "wrong_policy":
				store.value.PolicyVersion = "other"
			case "cipher":
				cipher.err = errors.New("unavailable key")
			case "csrf":
				store.value.CSRFHash = Digest("wrong")
			}
			s := SessionService{Store: store, Cipher: cipher, Policy: p, Now: func() time.Time { return now }}
			result, err := s.Read(context.Background(), value)
			if (err == nil) != (name == "valid") {
				t.Fatal("unexpected session authorization")
			}
			if err == nil && (result.AccessToken != "access" || result.CSRF != csrf) {
				t.Fatal("wrong secrets")
			}
			if name == "malformed" && store.calls != 0 {
				t.Fatal("malformed cookie queried storage")
			}
		})
	}
}

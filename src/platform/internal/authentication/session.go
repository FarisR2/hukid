package authentication

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"
)

// ReadSession carries only server-side data, never an HTTP response model.
type ReadSession struct {
	FamilyID, ActorID, ActiveTenantID, PolicyVersion                         string
	Generation                                                               int64
	CSRFHash                                                                 []byte
	RefreshDigest                                                            []byte
	Secrets                                                                  Envelope
	CreatedAt, LastSeenAt, IdleExpiresAt, AbsoluteExpiresAt, FamilyCreatedAt time.Time
}
type SessionReader interface {
	ReadSession(context.Context, []byte, time.Time) (ReadSession, error)
	TouchSession(context.Context, []byte, time.Time, time.Duration) error
}
type SessionView struct{ ActorID, ActiveTenantID, AccessToken, CSRF string }
type SessionService struct {
	Store  SessionReader
	Cipher Cipher
	Policy Policy
	Now    func() time.Time
}

func (s *SessionService) Read(ctx context.Context, cookie string) (SessionView, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(cookie)
	if err != nil || len(b) != 32 {
		return SessionView{}, ErrSession
	}
	now := s.Now()
	v, err := s.Store.ReadSession(ctx, Digest(cookie), now)
	if err != nil {
		return SessionView{}, err
	}
	if !s.valid(v, now) {
		return SessionView{}, ErrSession
	}
	secrets, err := s.open(v)
	if err != nil {
		return SessionView{}, err
	}
	return SessionView{v.ActorID, v.ActiveTenantID, secrets.AccessToken, secrets.CSRF}, nil
}

func (s *SessionService) valid(v ReadSession, now time.Time) bool {
	return v.Generation > 0 && v.PolicyVersion == "auth-test-v1" && !now.Before(v.FamilyCreatedAt) && !s.Policy.SessionExpired(v.FamilyCreatedAt, v.LastSeenAt, now) && !now.Before(v.CreatedAt) && now.Before(v.IdleExpiresAt) && now.Before(v.AbsoluteExpiresAt)
}

func (s *SessionService) Touch(ctx context.Context, cookie string) error {
	return s.Store.TouchSession(ctx, Digest(cookie), s.Now(), time.Duration(s.Policy.SessionIdleSeconds)*time.Second)
}

func (s *SessionService) open(v ReadSession) (SessionSecrets, error) {
	plain, err := s.Cipher.Open(v.Secrets, SessionGenerationAAD(v.FamilyID, v.Generation))
	if err != nil {
		return SessionSecrets{}, ErrDependency
	}
	defer clear(plain)
	var secrets SessionSecrets
	if json.Unmarshal(plain, &secrets) != nil || secrets.AccessToken == "" || !EqualDigest(Digest(secrets.CSRF), v.CSRFHash) {
		return SessionSecrets{}, ErrDependency
	}
	csrf, err := base64.RawURLEncoding.Strict().DecodeString(secrets.CSRF)
	if err != nil || len(csrf) != 32 {
		return SessionSecrets{}, ErrDependency
	}
	return secrets, nil
}

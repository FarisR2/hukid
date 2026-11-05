package authentication

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"
)

// ReadSession is intentionally read-only; refresh/rotation remain AUTH-T06.
type ReadSession struct {
	FamilyID, ActorID, ActiveTenantID, PolicyVersion                         string
	Generation                                                               int64
	CSRFHash                                                                 []byte
	Secrets                                                                  Envelope
	CreatedAt, LastSeenAt, IdleExpiresAt, AbsoluteExpiresAt, FamilyCreatedAt time.Time
}
type SessionReader interface {
	ReadSession(context.Context, []byte, time.Time) (ReadSession, error)
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
	if v.Generation != 1 || v.PolicyVersion != "auth-test-v1" || now.Before(v.FamilyCreatedAt) || s.Policy.SessionExpired(v.FamilyCreatedAt, v.LastSeenAt, now) || now.Before(v.CreatedAt) || !now.Before(v.IdleExpiresAt) || !now.Before(v.AbsoluteExpiresAt) {
		return SessionView{}, ErrSession
	}
	plain, err := s.Cipher.Open(v.Secrets, SessionAAD(v.FamilyID))
	if err != nil {
		return SessionView{}, ErrDependency
	}
	defer clear(plain)
	var secrets SessionSecrets
	if json.Unmarshal(plain, &secrets) != nil || secrets.AccessToken == "" || !EqualDigest(Digest(secrets.CSRF), v.CSRFHash) {
		return SessionView{}, ErrDependency
	}
	csrf, err := base64.RawURLEncoding.Strict().DecodeString(secrets.CSRF)
	if err != nil || len(csrf) != 32 {
		return SessionView{}, ErrDependency
	}
	return SessionView{v.ActorID, v.ActiveTenantID, secrets.AccessToken, secrets.CSRF}, nil
}

package authentication

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"time"
)

var (
	ErrOrigin      = errors.New("invalid session command origin")
	ErrCSRF        = errors.New("invalid session command proof")
	ErrRefreshBusy = errors.New("refresh in progress")
)

// A durable claim outlives request cancellation and process death. It is never
// stolen to retry an uncertain refresh token exchange.
const RefreshLease = 10 * time.Second

type SessionRotation struct {
	SessionID                           string
	CookieHash, CSRFHash, RefreshDigest []byte
	Secrets                             Envelope
	IdleExpiresAt                       time.Time
}

type SessionCommands interface {
	ClaimRefresh(context.Context, []byte, []byte, string, time.Time, time.Time) (ReadSession, error)
	FinishRefresh(context.Context, ReadSession, string, SessionRotation, time.Time) error
	InvalidateFamily(context.Context, string) error
	Logout(context.Context, []byte, []byte, time.Time) (ReadSession, error)
}

type SessionOIDC interface {
	Refresh(context.Context, string, string, []byte) (VerifiedLogin, error)
	Revoke(context.Context, string) error
}

type SessionLifecycle struct {
	Sessions *SessionService
	Store    SessionCommands
	OIDC     SessionOIDC
	Random   io.Reader
}

type RefreshedSession struct {
	Cookie    string
	ExpiresAt time.Time
}

func opaque(value string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(b) == 32
}

func (s *SessionLifecycle) Refresh(ctx context.Context, cookie, csrf string) (RefreshedSession, error) {
	if !opaque(csrf) {
		return RefreshedSession{}, ErrCSRF
	}
	if !opaque(cookie) {
		return RefreshedSession{}, ErrSession
	}
	// Generate all browser credentials before consuming a provider token.
	random := LoginService{Random: s.Random}
	lease, err := random.id()
	if err != nil {
		return RefreshedSession{}, err
	}
	id, err := random.id()
	if err != nil {
		return RefreshedSession{}, err
	}
	nextCookie, err := random.random(32)
	if err != nil {
		return RefreshedSession{}, err
	}
	nextCSRF, err := random.random(32)
	if err != nil {
		return RefreshedSession{}, err
	}
	now := s.Sessions.Now()
	v, err := s.Store.ClaimRefresh(ctx, Digest(cookie), Digest(csrf), lease, now, now.Add(RefreshLease))
	if err != nil {
		return RefreshedSession{}, err
	}
	completed := false
	defer func() {
		if !completed {
			// Cleanup must survive a disconnected browser. A persistent lease also
			// keeps the family unusable if the database is unavailable here.
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.Store.InvalidateFamily(cleanup, v.FamilyID)
		}
	}()
	if !s.Sessions.valid(v, now) {
		return RefreshedSession{}, ErrSession
	}
	secrets, err := s.Sessions.open(v)
	if err != nil {
		return RefreshedSession{}, err
	}
	if secrets.RefreshToken == "" || !EqualDigest(Digest(secrets.RefreshToken), v.RefreshDigest) {
		return RefreshedSession{}, ErrDependency
	}
	if !now.Before(v.FamilyCreatedAt.Add(time.Duration(s.Sessions.Policy.RefreshTokenSeconds) * time.Second)) {
		return RefreshedSession{}, ErrSession
	}
	identity, err := s.OIDC.Refresh(ctx, secrets.AccessToken, secrets.RefreshToken, secrets.OIDCNonceHash)
	if err != nil {
		return RefreshedSession{}, err
	}
	if identity.AccessToken == "" || identity.RefreshToken == "" || identity.RefreshToken == secrets.RefreshToken || EqualDigest(Digest(identity.RefreshToken), v.RefreshDigest) {
		return RefreshedSession{}, ErrSession
	}
	now = s.Sessions.Now()
	if !s.Sessions.valid(v, now) || s.Sessions.Policy.CheckMFA(identity.AuthTime, now, identity.AMR, identity.ACR, false) != nil {
		return RefreshedSession{}, ErrSession
	}
	plain, err := encodeSecrets(identity.AccessToken, identity.RefreshToken, nextCSRF, secrets.OIDCNonceHash)
	if err != nil {
		return RefreshedSession{}, ErrDependency
	}
	defer clear(plain)
	envelope, err := s.Sessions.Cipher.Seal(plain, SessionGenerationAAD(v.FamilyID, v.Generation+1))
	if err != nil {
		return RefreshedSession{}, ErrDependency
	}
	idle := now.Add(time.Duration(s.Sessions.Policy.SessionIdleSeconds) * time.Second)
	if v.AbsoluteExpiresAt.Before(idle) {
		idle = v.AbsoluteExpiresAt
	}
	next := SessionRotation{SessionID: id, CookieHash: Digest(nextCookie), CSRFHash: Digest(nextCSRF), RefreshDigest: Digest(identity.RefreshToken), Secrets: envelope, IdleExpiresAt: idle}
	if err := s.Store.FinishRefresh(ctx, v, lease, next, now); err != nil {
		return RefreshedSession{}, err
	}
	completed = true
	return RefreshedSession{nextCookie, v.AbsoluteExpiresAt}, nil
}

func (s *SessionLifecycle) Logout(ctx context.Context, cookie, csrf string) error {
	if !opaque(cookie) || !opaque(csrf) {
		return ErrCSRF
	}
	v, err := s.Store.Logout(ctx, Digest(cookie), Digest(csrf), s.Sessions.Now())
	if err != nil {
		return err
	}
	// Local invalidation has committed. No provider or cipher failure can undo it.
	if len(v.Secrets.Ciphertext) != 0 {
		if secrets, err := s.Sessions.open(v); err == nil && secrets.RefreshToken != "" {
			_ = s.OIDC.Revoke(ctx, secrets.RefreshToken)
		}
	}
	return nil
}

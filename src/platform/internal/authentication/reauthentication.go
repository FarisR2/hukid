package authentication

import (
	"context"
	"time"
)

type ReauthenticationOIDC interface {
	ReauthenticationURL(state, nonce, challenge string) string
	SessionIdentity(context.Context, string) (Operator, error)
}

type ContextSelection struct {
	TenantID string
	Revision int64
}

type ReauthenticationStore interface {
	RotateSession(context.Context, ReadSession, SessionRotation, *VerifiedLogin, *ContextSelection, time.Time) error
}

// proof authenticates the opaque generation before any command side effect.
func (s *SessionService) proof(ctx context.Context, cookie, csrf string, requireCSRF bool) (ReadSession, error) {
	if !opaque(cookie) {
		return ReadSession{}, ErrSession
	}
	v, err := s.Store.ReadSession(ctx, Digest(cookie), s.Now())
	if err != nil {
		return ReadSession{}, err
	}
	if !s.valid(v, s.Now()) {
		return ReadSession{}, ErrSession
	}
	if requireCSRF && (!opaque(csrf) || !EqualDigest(Digest(csrf), v.CSRFHash)) {
		return ReadSession{}, ErrCSRF
	}
	return v, nil
}

func (s *LoginService) StartStepUp(ctx context.Context, cookie, csrf, returnTo string) (LoginStart, error) {
	if s.Sessions == nil {
		return LoginStart{}, ErrDependency
	}
	v, err := s.Sessions.proof(ctx, cookie, csrf, true)
	if err != nil {
		return LoginStart{}, err
	}
	return s.start(ctx, returnTo, &v)
}

func (s *LoginService) completeStepUp(ctx context.Context, tx LoginTransaction, old ReadSession, identity VerifiedLogin, now time.Time) (LoginComplete, error) {
	// OIDC auth_time has second resolution. No past clock skew is added here.
	if identity.AuthTime.Unix() < tx.CreatedAt.Unix() || s.Policy.CheckMFA(identity.AuthTime, now, identity.AMR, identity.ACR, true) != nil {
		return LoginComplete{}, ErrMFA
	}
	secrets, err := s.Sessions.open(old)
	if err != nil {
		return LoginComplete{}, err
	}
	provider, ok := s.OIDC.(ReauthenticationOIDC)
	if !ok {
		return LoginComplete{}, ErrDependency
	}
	operator, err := provider.SessionIdentity(ctx, secrets.AccessToken)
	if err != nil {
		return LoginComplete{}, err
	}
	if operator.Issuer != identity.Issuer || operator.Subject != identity.Subject {
		return LoginComplete{}, ErrCallback
	}
	now = s.Now()
	if !now.Before(tx.ExpiresAt) || !s.Sessions.valid(old, now) {
		return LoginComplete{}, ErrSession
	}
	if s.Policy.CheckMFA(identity.AuthTime, now, identity.AMR, identity.ACR, true) != nil {
		return LoginComplete{}, ErrMFA
	}
	rotation, cookie, err := s.rotation(old, identity.AccessToken, identity.RefreshToken, identity.NonceHash, now)
	if err != nil {
		return LoginComplete{}, err
	}
	if err := s.Reauthentication.RotateSession(ctx, old, rotation, &identity, nil, s.Now()); err != nil {
		return LoginComplete{}, err
	}
	return LoginComplete{tx.ReturnTo, cookie, old.AbsoluteExpiresAt}, nil
}

// rotation also changes CSRF and the authenticated encryption AAD on context switches.
func (s *LoginService) rotation(old ReadSession, access, refresh string, nonce []byte, now time.Time) (SessionRotation, string, error) {
	if access == "" || refresh == "" {
		return SessionRotation{}, "", ErrCallback
	}
	id, err := s.id()
	if err != nil {
		return SessionRotation{}, "", err
	}
	cookie, err := s.random(32)
	if err != nil {
		return SessionRotation{}, "", err
	}
	csrf, err := s.random(32)
	if err != nil {
		return SessionRotation{}, "", err
	}
	plain, err := encodeSecrets(access, refresh, csrf, nonce)
	if err != nil {
		return SessionRotation{}, "", ErrDependency
	}
	defer clear(plain)
	envelope, err := s.Cipher.Seal(plain, SessionGenerationAAD(old.FamilyID, old.Generation+1))
	if err != nil {
		return SessionRotation{}, "", ErrDependency
	}
	idle := now.Add(time.Duration(s.Policy.SessionIdleSeconds) * time.Second)
	if old.AbsoluteExpiresAt.Before(idle) {
		idle = old.AbsoluteExpiresAt
	}
	return SessionRotation{SessionID: id, CookieHash: Digest(cookie), CSRFHash: Digest(csrf), RefreshDigest: Digest(refresh), Secrets: envelope, IdleExpiresAt: idle}, cookie, nil
}

// SelectContext accepts an already resolved server-side membership. The next
// protected request revalidates it; the snapshot is never durable authority.
func (s *LoginService) SelectContext(ctx context.Context, cookie, csrf string, selection ContextSelection) (RefreshedSession, error) {
	old, err := s.Sessions.proof(ctx, cookie, csrf, true)
	if err != nil {
		return RefreshedSession{}, err
	}
	secrets, err := s.Sessions.open(old)
	if err != nil {
		return RefreshedSession{}, err
	}
	next, nextCookie, err := s.rotation(old, secrets.AccessToken, secrets.RefreshToken, secrets.OIDCNonceHash, s.Now())
	if err != nil {
		return RefreshedSession{}, err
	}
	if err := s.Reauthentication.RotateSession(ctx, old, next, nil, &selection, s.Now()); err != nil {
		return RefreshedSession{}, err
	}
	return RefreshedSession{nextCookie, old.AbsoluteExpiresAt}, nil
}

func (s *SessionService) CheckCommand(ctx context.Context, cookie, csrf string) (SessionView, error) {
	if _, err := s.proof(ctx, cookie, csrf, true); err != nil {
		return SessionView{}, err
	}
	return s.Read(ctx, cookie)
}

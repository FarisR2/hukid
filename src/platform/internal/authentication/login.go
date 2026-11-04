package authentication

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"time"
)

var (
	ErrRequest    = errors.New("invalid request")
	ErrCallback   = errors.New("invalid callback")
	ErrMFA        = errors.New("MFA required")
	ErrDependency = errors.New("authentication dependency unavailable")
)

type Envelope struct {
	Ciphertext, Nonce []byte
	KeyVersion        string
}

type Cipher interface {
	Seal(plaintext []byte, purpose string) (Envelope, error)
	Open(Envelope, string) ([]byte, error)
}

type LoginTransaction struct {
	ID, Issuer, ClientID, RedirectURI, ReturnTo string
	StateHash, NonceHash, BindingHash           []byte
	Verifier                                    Envelope
	CreatedAt, ExpiresAt                        time.Time
}

// VerifiedLogin contains evidence verified by the OIDC adapter, never HTTP DTOs.
type VerifiedLogin struct {
	Issuer, Subject, AccessToken, RefreshToken, ACR string
	AMR                                             []string
	AuthTime                                        time.Time
}

type OIDC interface {
	AuthorizationURL(state, nonce, challenge string) string
	Exchange(context.Context, string, string, []byte) (VerifiedLogin, error)
}

type InitialSession struct {
	FamilyID, SessionID, PolicyVersion          string
	CookieHash, CSRFHash, RefreshDigest         []byte
	Secrets                                     Envelope
	CreatedAt, IdleExpiresAt, AbsoluteExpiresAt time.Time
	Identity                                    VerifiedLogin
}

type LoginStore interface {
	CreateTransaction(context.Context, LoginTransaction) error
	// Consume commits consumption and purges the stored verifier before returning it.
	Consume(context.Context, []byte, []byte, string, string, string, time.Time) (LoginTransaction, error)
	CreateInitialSession(context.Context, InitialSession) error
}

type LoginService struct {
	Policy Policy
	OIDC   OIDC
	Store  LoginStore
	Cipher Cipher
	Now    func() time.Time
	Random io.Reader
}

type LoginStart struct {
	Location, Binding string
	ExpiresAt         time.Time
}
type LoginComplete struct {
	ReturnTo, Cookie string
	ExpiresAt        time.Time
}

func Digest(value string) []byte      { h := sha256.Sum256([]byte(value)); return h[:] }
func TransactionAAD(id string) string { return "hukid:oidc:" + id }
func SessionAAD(family string) string { return "hukid:session:" + family + ":1" }

func (s *LoginService) random(size int) (string, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(s.Random, b); err != nil {
		return "", ErrDependency
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *LoginService) id() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(s.Random, b); err != nil {
		return "", ErrDependency
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

func (s *LoginService) Start(ctx context.Context, returnTo string) (LoginStart, error) {
	if returnTo == "" {
		returnTo = "/"
	}
	if !slices.Contains(s.Policy.AllowedReturnTo, returnTo) {
		return LoginStart{}, ErrRequest
	}
	values := make([]string, 4)
	for i := range values {
		v, err := s.random(32)
		if err != nil {
			return LoginStart{}, err
		}
		values[i] = v
	}
	state, nonce, binding, verifier := values[0], values[1], values[2], values[3]
	id, err := s.id()
	if err != nil {
		return LoginStart{}, err
	}
	envelope, err := s.Cipher.Seal([]byte(verifier), TransactionAAD(id))
	if err != nil {
		return LoginStart{}, ErrDependency
	}
	now := s.Now().UTC()
	tx := LoginTransaction{ID: id, Issuer: s.Policy.Issuer, ClientID: s.Policy.ClientID, RedirectURI: s.Policy.RedirectURI, ReturnTo: returnTo, StateHash: Digest(state), NonceHash: Digest(nonce), BindingHash: Digest(binding), Verifier: envelope, CreatedAt: now, ExpiresAt: now.Add(time.Duration(s.Policy.TransactionSeconds) * time.Second)}
	if err := s.Store.CreateTransaction(ctx, tx); err != nil {
		return LoginStart{}, ErrDependency
	}
	challenge := base64.RawURLEncoding.EncodeToString(Digest(verifier))
	return LoginStart{s.OIDC.AuthorizationURL(state, nonce, challenge), binding, tx.ExpiresAt}, nil
}

func (s *LoginService) Complete(ctx context.Context, state, binding, issuer, code, oauthError string) (LoginComplete, error) {
	if state == "" || binding == "" || issuer != s.Policy.Issuer || (code == "") == (oauthError == "") {
		return LoginComplete{}, ErrCallback
	}
	now := s.Now().UTC()
	tx, err := s.Store.Consume(ctx, Digest(state), Digest(binding), issuer, s.Policy.ClientID, s.Policy.RedirectURI, now)
	if err != nil {
		if errors.Is(err, ErrCallback) {
			return LoginComplete{}, ErrCallback
		}
		return LoginComplete{}, ErrDependency
	}
	if oauthError != "" {
		return LoginComplete{}, ErrCallback
	}
	verifier, err := s.Cipher.Open(tx.Verifier, TransactionAAD(tx.ID))
	if err != nil {
		return LoginComplete{}, ErrDependency
	}
	defer clear(verifier)
	identity, err := s.OIDC.Exchange(ctx, code, string(verifier), tx.NonceHash)
	if err != nil {
		return LoginComplete{}, err
	}
	now = s.Now().UTC()
	// Recheck local expiry after the network request; skew never extends transactions.
	if !now.Before(tx.ExpiresAt) || !slices.Contains(s.Policy.AllowedReturnTo, tx.ReturnTo) || identity.Issuer != s.Policy.Issuer || identity.Subject == "" {
		return LoginComplete{}, ErrCallback
	}
	if s.Policy.CheckMFA(identity.AuthTime, now, identity.AMR, identity.ACR, false) != nil {
		return LoginComplete{}, ErrMFA
	}
	return s.createSession(ctx, tx.ReturnTo, identity, now)
}

func (s *LoginService) createSession(ctx context.Context, returnTo string, identity VerifiedLogin, now time.Time) (LoginComplete, error) {
	if identity.AccessToken == "" || identity.RefreshToken == "" {
		return LoginComplete{}, ErrCallback
	}
	family, err := s.id()
	if err != nil {
		return LoginComplete{}, err
	}
	id, err := s.id()
	if err != nil {
		return LoginComplete{}, err
	}
	cookie, err := s.random(32)
	if err != nil {
		return LoginComplete{}, err
	}
	csrf, err := s.random(32)
	if err != nil {
		return LoginComplete{}, err
	}
	secrets, err := encodeSecrets(identity.AccessToken, identity.RefreshToken, csrf)
	if err != nil {
		return LoginComplete{}, ErrDependency
	}
	defer clear(secrets)
	envelope, err := s.Cipher.Seal(secrets, SessionAAD(family))
	if err != nil {
		return LoginComplete{}, ErrDependency
	}
	absolute := now.Add(time.Duration(s.Policy.SessionAbsoluteSeconds) * time.Second)
	if authDeadline := identity.AuthTime.Add(time.Duration(s.Policy.SessionAbsoluteSeconds) * time.Second); authDeadline.Before(absolute) {
		absolute = authDeadline
	}
	idle := now.Add(time.Duration(s.Policy.SessionIdleSeconds) * time.Second)
	if absolute.Before(idle) {
		idle = absolute
	}
	session := InitialSession{FamilyID: family, SessionID: id, PolicyVersion: "auth-test-v1", CookieHash: Digest(cookie), CSRFHash: Digest(csrf), RefreshDigest: Digest(identity.RefreshToken), Secrets: envelope, CreatedAt: now, IdleExpiresAt: idle, AbsoluteExpiresAt: absolute, Identity: identity}
	if err := s.Store.CreateInitialSession(ctx, session); err != nil {
		return LoginComplete{}, ErrDependency
	}
	return LoginComplete{returnTo, cookie, absolute}, nil
}

func EqualDigest(a, b []byte) bool {
	return len(a) == sha256.Size && len(b) == sha256.Size && subtle.ConstantTimeCompare(a, b) == 1
}

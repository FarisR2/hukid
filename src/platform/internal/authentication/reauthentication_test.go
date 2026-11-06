package authentication_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	a "hukid.local/platform/internal/authentication"
	"net/url"
	"testing"
	"time"
)

type reauthOIDC struct {
	*testOIDC
	historical    a.Operator
	afterExchange func()
}

func (o *reauthOIDC) ReauthenticationURL(state, nonce, challenge string) string {
	return o.AuthorizationURL(state, nonce, challenge)
}
func (o *reauthOIDC) SessionIdentity(context.Context, string) (a.Operator, error) {
	return o.historical, nil
}
func (o *reauthOIDC) Exchange(ctx context.Context, code, verifier string, nonce []byte) (a.VerifiedLogin, error) {
	v, err := o.testOIDC.Exchange(ctx, code, verifier, nonce)
	if o.afterExchange != nil {
		o.afterExchange()
	}
	return v, err
}

type reauthStore struct {
	value     a.ReadSession
	err       error
	rotations int
	identity  *a.VerifiedLogin
}

func (m *reauthStore) ReadSession(context.Context, []byte, time.Time) (a.ReadSession, error) {
	return m.value, m.err
}
func (m *reauthStore) TouchSession(context.Context, []byte, time.Time, time.Duration) error {
	return nil
}
func (m *reauthStore) ReconcileSessionContext(context.Context, []byte, a.ReadSession, a.ContextSelection, time.Time) error {
	return m.err
}
func (m *reauthStore) RotateSession(_ context.Context, old a.ReadSession, next a.SessionRotation, identity *a.VerifiedLogin, _ *a.ContextSelection, now time.Time) error {
	if m.err != nil {
		return m.err
	}
	m.rotations++
	m.identity = identity
	m.value.Generation++
	m.value.CSRFHash = next.CSRFHash
	m.value.Secrets = next.Secrets
	m.value.CreatedAt = now
	m.value.LastSeenAt = now
	m.value.IdleExpiresAt = next.IdleExpiresAt
	return nil
}

func TestStepUpBindsFamilyIdentityAndNewAuthentication(t *testing.T) {
	for _, name := range []string{"valid", "before_freshness_deadline", "bad_csrf", "wrong_cookie", "different_family", "different_generation", "different_subject", "old_authentication", "at_freshness_deadline", "future_beyond_skew", "missing_otp", "wrong_acr", "expired_during_exchange", "revoked_during_exchange", "store_failure", "provider_failure"} {
		t.Run(name, func(t *testing.T) {
			s, transactions, provider, now := setup(t)
			if name == "at_freshness_deadline" || name == "before_freshness_deadline" {
				s.Policy.TransactionSeconds = s.Policy.StepUpSeconds + 60
			}
			cookieBytes := make([]byte, 32)
			rand.Read(cookieBytes)
			cookie := base64.RawURLEncoding.EncodeToString(cookieBytes)
			csrfBytes := make([]byte, 32)
			rand.Read(csrfBytes)
			csrf := base64.RawURLEncoding.EncodeToString(csrfBytes)
			plain, _ := json.Marshal(a.SessionSecrets{AccessToken: "old-access", RefreshToken: "old-refresh", CSRF: csrf, OIDCNonceHash: a.Digest("nonce")})
			envelope, _ := s.Cipher.Seal(plain, a.SessionGenerationAAD("family", 1))
			clear(plain)
			store := &reauthStore{value: a.ReadSession{FamilyID: "family", ActorID: "actor", Generation: 1, PolicyVersion: "auth-test-v1", CSRFHash: a.Digest(csrf), Secrets: envelope, FamilyCreatedAt: now.Add(-time.Minute), CreatedAt: now.Add(-time.Minute), LastSeenAt: now.Add(-time.Minute), IdleExpiresAt: now.Add(30 * time.Minute), AbsoluteExpiresAt: now.Add(time.Hour)}}
			s.Sessions = &a.SessionService{Store: store, Cipher: s.Cipher, Policy: s.Policy, Now: s.Now}
			s.Reauthentication = store
			oidc := &reauthOIDC{testOIDC: provider, historical: a.Operator{Issuer: s.Policy.Issuer, Subject: provider.identity.Subject}}
			s.OIDC = oidc
			if name == "bad_csrf" {
				if _, err := s.StartStepUp(context.Background(), cookie, cookie, "/"); !errors.Is(err, a.ErrCSRF) {
					t.Fatal("CSRF accepted")
				}
				if len(transactions.transactions) != 0 || provider.calls.Load() != 0 {
					t.Fatal("bad proof had effects")
				}
				return
			}
			start, err := s.StartStepUp(context.Background(), cookie, csrf, "/")
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(start.Location)
			state := u.Query().Get("state")
			want := a.ErrMFA
			callbackCookie := cookie
			switch name {
			case "wrong_cookie":
				callbackCookie = "bad"
				want = a.ErrSession
			case "different_family":
				store.value.FamilyID = "other"
				want = a.ErrSession
			case "different_generation":
				store.value.Generation++
				want = a.ErrSession
			case "different_subject":
				provider.identity.Subject = "another-operator"
				want = a.ErrCallback
			case "old_authentication":
				provider.identity.AuthTime = now.Add(-time.Second)
			case "at_freshness_deadline":
				*now = now.Add(time.Duration(s.Policy.StepUpSeconds) * time.Second)
			case "before_freshness_deadline":
				*now = now.Add(time.Duration(s.Policy.StepUpSeconds)*time.Second - time.Nanosecond)
			case "future_beyond_skew":
				provider.identity.AuthTime = now.Add(time.Duration(s.Policy.ClockSkewSeconds+1) * time.Second)
			case "missing_otp":
				provider.identity.AMR = []string{"pwd"}
			case "wrong_acr":
				provider.identity.ACR = "foreign"
			case "expired_during_exchange":
				oidc.afterExchange = func() { *now = now.Add(time.Duration(s.Policy.TransactionSeconds) * time.Second) }
				want = a.ErrCallback
			case "revoked_during_exchange":
				oidc.afterExchange = func() { store.err = a.ErrSession }
				want = a.ErrSession
			case "store_failure":
				oidc.afterExchange = func() { store.err = a.ErrDependency }
				want = a.ErrDependency
			case "provider_failure":
				provider.failure = a.ErrDependency
				want = a.ErrDependency
			}
			result, err := s.CompleteWithSession(context.Background(), state, start.Binding, s.Policy.Issuer, "code", "", callbackCookie)
			if name == "valid" || name == "before_freshness_deadline" {
				if err != nil || result.Cookie == cookie || store.rotations != 1 || store.identity == nil || !result.ExpiresAt.Equal(store.value.AbsoluteExpiresAt) {
					t.Fatalf("reauthentication failed: %v", err)
				}
				view, err := s.Sessions.Read(context.Background(), result.Cookie)
				if err != nil || view.CSRF == csrf || view.AccessToken != provider.identity.AccessToken {
					t.Fatal("rotated envelope invalid")
				}
			} else {
				if !errors.Is(err, want) || store.rotations != 0 {
					t.Fatalf("expected %v, got %v", want, err)
				}
			}
			if _, err := s.CompleteWithSession(context.Background(), state, start.Binding, s.Policy.Issuer, "code", "", cookie); !errors.Is(err, a.ErrCallback) {
				t.Fatal("step-up transaction replayed")
			}
		})
	}
}

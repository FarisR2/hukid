package authentication_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hukid.local/platform/internal/adapters/secretbox"
	a "hukid.local/platform/internal/authentication"
)

type memoryStore struct {
	mu                      sync.Mutex
	transactions            map[string]a.LoginTransaction
	sessions                []a.InitialSession
	failCreate, failSession bool
}

func (m *memoryStore) CreateTransaction(_ context.Context, t a.LoginTransaction) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failCreate {
		return errors.New("storage")
	}
	m.transactions[string(t.StateHash)] = t
	return nil
}
func (m *memoryStore) Consume(_ context.Context, state, binding []byte, issuer, client, redirect string, now time.Time) (a.LoginTransaction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.transactions[string(state)]
	if !ok || !a.EqualDigest(binding, t.BindingHash) || issuer != t.Issuer || client != t.ClientID || redirect != t.RedirectURI || now.Before(t.CreatedAt) || !now.Before(t.ExpiresAt) {
		return a.LoginTransaction{}, a.ErrCallback
	}
	delete(m.transactions, string(state))
	return t, nil
}
func (m *memoryStore) CreateInitialSession(_ context.Context, s a.InitialSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failSession {
		return errors.New("storage")
	}
	m.sessions = append(m.sessions, s)
	return nil
}

type testOIDC struct {
	identity a.VerifiedLogin
	failure  error
	calls    atomic.Int32
}

func (o *testOIDC) AuthorizationURL(state, nonce, challenge string) string {
	return "http://127.0.0.1:19090/auth?" + url.Values{"state": {state}, "nonce": {nonce}, "code_challenge": {challenge}}.Encode()
}
func (o *testOIDC) Exchange(context.Context, string, string, []byte) (a.VerifiedLogin, error) {
	o.calls.Add(1)
	return o.identity, o.failure
}

func setup(t *testing.T) (*a.LoginService, *memoryStore, *testOIDC, *time.Time) {
	t.Helper()
	f, err := os.Open("../../config/auth.test.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := a.LoadPolicy(f, "test")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2000000000, 0).UTC()
	key := make([]byte, 32)
	rand.Read(key)
	box, _ := secretbox.New(key, "unit-v1", rand.Reader)
	store := &memoryStore{transactions: map[string]a.LoginTransaction{}}
	oidc := &testOIDC{identity: a.VerifiedLogin{Issuer: p.Issuer, Subject: "operator", AccessToken: "ephemeral-access", RefreshToken: "ephemeral-refresh", ACR: p.AcceptedACR[0], AMR: p.RequiredAMR, AuthTime: now}}
	return &a.LoginService{Policy: p, Store: store, OIDC: oidc, Cipher: box, Now: func() time.Time { return now }, Random: rand.Reader}, store, oidc, &now
}
func begin(t *testing.T, s *a.LoginService) (a.LoginStart, string) {
	t.Helper()
	start, err := s.Start(context.Background(), "/")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(start.Location)
	return start, u.Query().Get("state")
}

func TestLoginBindsCallbackAndCreatesOnlyOpaqueSession(t *testing.T) {
	s, store, oidc, now := setup(t)
	start, state := begin(t, s)
	for _, bad := range []struct{ state, binding, issuer string }{{"wrong", start.Binding, s.Policy.Issuer}, {state, "other-browser", s.Policy.Issuer}, {state, start.Binding, "http://127.0.0.1:1"}} {
		if _, err := s.Complete(context.Background(), bad.state, bad.binding, bad.issuer, "code", ""); !errors.Is(err, a.ErrCallback) {
			t.Fatal("invalid callback accepted")
		}
	}
	if oidc.calls.Load() != 0 {
		t.Fatal("unbound callback reached provider")
	}
	complete, err := s.Complete(context.Background(), state, start.Binding, s.Policy.Issuer, "code", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(complete.Cookie) != 43 || complete.ReturnTo != "/" || len(store.sessions) != 1 {
		t.Fatal("session not created")
	}
	session := store.sessions[0]
	if !a.EqualDigest(session.CookieHash, a.Digest(complete.Cookie)) || session.Identity.Subject != "operator" || session.CreatedAt != *now {
		t.Fatal("incorrect session authority")
	}
	plaintext, err := s.Cipher.Open(session.Secrets, a.SessionAAD(session.FamilyID))
	if err != nil || !bytes.Contains(plaintext, []byte("ephemeral-refresh")) {
		t.Fatal("secrets envelope unavailable")
	}
	if bytes.Contains(session.Secrets.Ciphertext, []byte("ephemeral-refresh")) {
		t.Fatal("plaintext in persistence")
	}
	if _, err = s.Complete(context.Background(), state, start.Binding, s.Policy.Issuer, "code", ""); !errors.Is(err, a.ErrCallback) {
		t.Fatal("replay accepted")
	}
	if oidc.calls.Load() != 1 {
		t.Fatal("replay reached provider")
	}
}

func TestCallbackExpiryAndFailuresNeverCreateSession(t *testing.T) {
	for _, mode := range []string{"deadline", "oauth_error", "provider", "storage", "cipher", "mfa", "entropy", "return"} {
		t.Run(mode, func(t *testing.T) {
			s, store, oidc, now := setup(t)
			start, state := begin(t, s)
			oauthError, code := "", "code"
			switch mode {
			case "deadline":
				*now = start.ExpiresAt
			case "oauth_error":
				oauthError, code = "access_denied", ""
			case "provider":
				oidc.failure = a.ErrDependency
			case "storage":
				store.failSession = true
			case "cipher":
				tx := store.transactions[string(a.Digest(state))]
				tx.Verifier.Ciphertext[0] ^= 1
				store.transactions[string(a.Digest(state))] = tx
			case "mfa":
				oidc.identity.AMR = []string{"pwd"}
			case "entropy":
				s.Random = bytes.NewReader(nil)
			case "return":
				tx := store.transactions[string(a.Digest(state))]
				tx.ReturnTo = "https://invalid.example"
				store.transactions[string(a.Digest(state))] = tx
			}
			if _, err := s.Complete(context.Background(), state, start.Binding, s.Policy.Issuer, code, oauthError); err == nil {
				t.Fatal("failure accepted")
			}
			if len(store.sessions) != 0 {
				t.Fatal("failure created session")
			}
			if mode != "deadline" {
				if _, err := s.Complete(context.Background(), state, start.Binding, s.Policy.Issuer, "code", ""); !errors.Is(err, a.ErrCallback) {
					t.Fatal("failed consumed callback was reusable")
				}
			}
		})
	}
}

func TestConcurrentCallbacksExchangeExactlyOnce(t *testing.T) {
	s, store, oidc, _ := setup(t)
	start, state := begin(t, s)
	var wg sync.WaitGroup
	var successes atomic.Int32
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Complete(context.Background(), state, start.Binding, s.Policy.Issuer, "code", ""); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || oidc.calls.Load() != 1 || len(store.sessions) != 1 {
		t.Fatal("callback did not serialize")
	}
}

func TestStartRejectsUnsafeReturnAndInfrastructureFailure(t *testing.T) {
	for _, target := range []string{"https://evil.invalid", "//evil.invalid", "/%2f", "/?x=1", "/#x"} {
		s, store, _, _ := setup(t)
		if _, err := s.Start(context.Background(), target); !errors.Is(err, a.ErrRequest) || len(store.transactions) != 0 {
			t.Fatal("unsafe return persisted")
		}
	}
	s, store, _, _ := setup(t)
	store.failCreate = true
	if _, err := s.Start(context.Background(), "/"); !errors.Is(err, a.ErrDependency) {
		t.Fatal("storage failure ignored")
	}
	s.Random = bytes.NewReader(nil)
	if _, err := s.Start(context.Background(), "/"); !errors.Is(err, a.ErrDependency) {
		t.Fatal("entropy failure ignored")
	}
}

package console

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"hukid.local/platform/internal/adapters/secretbox"
	a "hukid.local/platform/internal/authentication"
)

type recordingStore struct{ created int }

func (s *recordingStore) CreateTransaction(context.Context, a.LoginTransaction) error {
	s.created++
	return nil
}
func (s *recordingStore) Consume(context.Context, []byte, []byte, string, string, string, time.Time) (a.LoginTransaction, error) {
	return a.LoginTransaction{}, a.ErrCallback
}
func (s *recordingStore) CreateInitialSession(context.Context, a.InitialSession) error { return nil }

type unusedOIDC struct{}

func (unusedOIDC) AuthorizationURL(string, string, string) string {
	return "http://127.0.0.1:19090/auth"
}
func (unusedOIDC) Exchange(context.Context, string, string, []byte) (a.VerifiedLogin, error) {
	return a.VerifiedLogin{}, a.ErrCallback
}
func handlerFixture(t *testing.T) (*LoginHandler, *recordingStore, *time.Time) {
	t.Helper()
	f, err := os.Open("../../../config/auth.test.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := a.LoadPolicy(f, "test")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2000000000, 0)
	box, _ := secretbox.New(make([]byte, 32), "http-test", rand.Reader)
	store := &recordingStore{}
	return New(&a.LoginService{Policy: p, Store: store, OIDC: unusedOIDC{}, Cipher: box, Now: func() time.Time { return now }, Random: rand.Reader}), store, &now
}
func perform(h *LoginHandler, method, path, cookie, forwarded string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = "127.0.0.1:50000"
	r.Header.Set("Cookie", cookie)
	r.Header.Set("X-Forwarded-For", forwarded)
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	h.Register(mux)
	mux.ServeHTTP(w, r)
	return w
}

func TestLoginRateLimitsIgnoreUntrustedForwardedIP(t *testing.T) {
	h, store, now := handlerFixture(t)
	h.Service.Policy.LoginRateLimit.MaxAttempts = 2
	for i := range 3 {
		r := perform(h, "GET", "/console/auth/login", "", strings.Repeat("x", i))
		want := 303
		if i == 2 {
			want = 429
		}
		if r.Code != want {
			t.Fatal("unexpected rate decision")
		}
		if r.Header().Get("Cache-Control") != "no-store" || r.Header().Get("Referrer-Policy") != "no-referrer" || r.Header().Get("X-Correlation-Id") == "" {
			t.Fatal("missing security headers")
		}
		if i == 2 {
			var problem map[string]any
			if json.Unmarshal(r.Body.Bytes(), &problem) != nil || problem["code"] != "rate_limited" || r.Header().Get("Retry-After") == "" {
				t.Fatal("unsafe rate error")
			}
		}
	}
	if store.created != 2 {
		t.Fatal("rate limit had side effects")
	}
	*now = now.Add(time.Duration(h.Service.Policy.LoginRateLimit.WindowSeconds) * time.Second)
	if perform(h, "GET", "/console/auth/login", "", "").Code != 303 {
		t.Fatal("window did not reset at deadline")
	}
}

func TestInvalidHTTPInputsHaveNoLoginEffects(t *testing.T) {
	for _, path := range []string{"/console/auth/login?returnTo=%2F", "/console/auth/login?returnTo=/&returnTo=/", "/console/auth/login?returnTo=//evil.invalid", "/console/auth/login?returnTo=/%23x", "/console/auth/login?x=1", "/console/auth/callback?state=a&state=b&iss=x&code=c", "/console/auth/callback?state=a&iss=x&code=c&error=denied", "/console/auth/callback?state=%xx"} {
		h, store, _ := handlerFixture(t)
		r := perform(h, "GET", path, TransactionCookie+"="+strings.Repeat("b", 43), "")
		if r.Code != 400 || store.created != 0 || r.Header().Get("Location") != "" {
			t.Fatal("invalid input accepted")
		}
	}
	h, store, _ := handlerFixture(t)
	if r := perform(h, "HEAD", "/console/auth/login", "", ""); r.Code != 405 || store.created != 0 {
		t.Fatal("HEAD created login")
	}
	duplicate := TransactionCookie + "=" + strings.Repeat("a", 43) + "; " + TransactionCookie + "=" + strings.Repeat("b", 43)
	if r := perform(h, "GET", "/console/auth/callback?state=a&iss=x&code=c", duplicate, ""); r.Code != 400 {
		t.Fatal("duplicate binding accepted")
	}
}

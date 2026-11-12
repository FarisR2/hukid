package audithttp

import (
	"bytes"
	"context"
	"errors"
	"hukid.local/platform/internal/audit"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type failureSink struct {
	mu   sync.Mutex
	ids  map[string]bool
	fail bool
}

func (s *failureSink) RecordFailure(ctx context.Context, failed bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	s.ids[audit.Correlation(ctx)] = failed
	if s.fail {
		return errors.New("secret-from-database")
	}
	return nil
}
func TestFailureCorrelationAndRedaction(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 405, 409, 422, 429, 503} {
		for _, unavailable := range []bool{false, true} {
			sink := &failureSink{ids: map[string]bool{}, fail: unavailable}
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			handler := Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if audit.Correlation(r.Context()) == "" {
					t.Error("no server correlation")
				}
				w.WriteHeader(status)
			}), sink, logger)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			req := httptest.NewRequest("GET", "http://example/console/auth/callback?code=secret-code&state=secret-state", nil).WithContext(ctx)
			req.Header.Set("X-Correlation-Id", "attacker-secret")
			req.Header.Set("Authorization", "Bearer secret-token")
			req.Header.Set("Cookie", "session=secret-cookie")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			id := response.Header().Get("X-Correlation-Id")
			if len(id) != 36 || response.Code != status || len(sink.ids) != 1 || sink.ids[id] != (status >= 500) {
				t.Fatal("invalid failure event")
			}
			for _, secret := range []string{"secret-code", "secret-state", "secret-token", "secret-cookie", "attacker-secret", "secret-from-database"} {
				if strings.Contains(logs.String(), secret) {
					t.Fatal("secret in log")
				}
			}
			if unavailable && !strings.Contains(logs.String(), "auth audit unavailable") {
				t.Fatal("missing audit loss alert")
			}
		}
	}
}
func TestConcurrentCorrelationAndSuccessExclusion(t *testing.T) {
	sink := &failureSink{ids: map[string]bool{}}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	h := Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }), sink, logger)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/console/auth/logout", nil))
		}()
	}
	wg.Wait()
	if len(sink.ids) != 32 {
		t.Fatal("requests shared correlation")
	}
	for _, path := range []string{"/healthz", "/console/api/me"} {
		Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }), sink, logger).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil))
	}
	if len(sink.ids) != 32 {
		t.Fatal("success produced denial")
	}
}

// Package audithttp records failures without inspecting credential-bearing inputs.
package audithttp

import (
	"context"
	"hukid.local/platform/internal/audit"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type FailureStore interface {
	RecordFailure(context.Context, bool) error
}
type responseStatus struct {
	http.ResponseWriter
	status int
}

func (w *responseStatus) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *responseStatus) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}
func (w *responseStatus) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func Wrap(next http.Handler, store FailureStore, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/console/") && !strings.HasPrefix(r.URL.Path, "/v1/operator/") {
			next.ServeHTTP(w, r)
			return
		}
		id, err := audit.NewID()
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		ctx := audit.WithCorrelation(r.Context(), id)
		w.Header().Set("X-Correlation-Id", id)
		response := &responseStatus{ResponseWriter: w}
		next.ServeHTTP(response, r.WithContext(ctx))
		if response.status < 400 {
			return
		}
		// Persist denial after client cancellation, with bounded work and no retries.
		record, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		if err := store.RecordFailure(record, response.status >= 500); err != nil {
			logger.Error("auth audit unavailable", "correlationId", id)
		}
		logger.Info("auth request rejected", "correlationId", id, "status", response.status)
	})
}

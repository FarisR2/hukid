package privateapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"hukid.local/platform/internal/audit"
	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/dashboard"
)

type DashboardHandler struct {
	Operators *Handler
	Overview  *dashboard.Service
	Activity  *dashboard.Activity
}

func (h *DashboardHandler) Register(mux *http.ServeMux) {
	for _, kind := range []string{"overview", "activity"} {
		mux.HandleFunc("/v1/operator/tenants/{tenantId}/"+kind, func(w http.ResponseWriter, r *http.Request) {
			if !PrepareDashboard(w, r) {
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			fail := func(err error) { DashboardProblem(w, err, true) }
			token, err := Bearer(r)
			if err != nil {
				fail(err)
				return
			}
			operator, err := h.Operators.Verifier.VerifyOperator(ctx, token)
			if err != nil {
				fail(err)
				return
			}
			identity, err := h.Operators.Tenancy.Me(ctx, operator)
			if err != nil {
				fail(err)
				return
			}
			h.Serve(w, r.WithContext(ctx), identity.ActorID, kind, true)
		})
	}
}

// Dashboard uses the UUID correlation and code/title shape fixed by its own
// contract. Do not change historical AUTH/USR error representations here.
func PrepareDashboard(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	id := audit.Correlation(r.Context())
	if id == "" {
		var err error
		id, err = audit.NewID()
		if err != nil {
			DashboardProblem(w, authentication.ErrDependency, false)
			return false
		}
	}
	w.Header().Set("X-Correlation-Id", id)
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeProblem(w, 405, "invalid_request", "invalid_request")
		return false
	}
	return true
}

func (h *DashboardHandler) Serve(w http.ResponseWriter, r *http.Request, actor, kind string, bearer bool) {
	start := time.Now()
	var result any
	var err error
	if kind == "overview" {
		result, err = h.Overview.Overview(r.Context(), actor, r.PathValue("tenantId"), r.URL.RawQuery)
	} else {
		result, err = h.Activity.List(r.Context(), actor, r.PathValue("tenantId"), r.URL.RawQuery)
	}
	// Bounded labels only: never URL, filters, identifiers, SQL or credentials.
	outcome := "success"
	if err != nil {
		outcome = "rejected"
	}
	slog.Info("dashboard read", "operation", kind, "outcome", outcome, "duration_ms", time.Since(start).Milliseconds(), "correlation_id", w.Header().Get("X-Correlation-Id"))
	if err != nil {
		DashboardProblem(w, err, bearer)
		return
	}
	JSON(w, result)
}

func DashboardProblem(w http.ResponseWriter, err error, bearer bool) {
	status, code := 503, "dependency_unavailable"
	switch {
	case errors.Is(err, dashboard.ErrRequest):
		status, code = 400, "invalid_request"
	case errors.Is(err, dashboard.ErrInput):
		status, code = 422, "invalid_input"
	case errors.Is(err, dashboard.ErrCursor):
		status, code = 422, "invalid_cursor"
	case errors.Is(err, dashboard.ErrForbidden), errors.Is(err, authentication.ErrMFA):
		status, code = 403, "forbidden"
	case errors.Is(err, authentication.ErrTenant):
		status, code = 404, "resource_not_found"
	case errors.Is(err, authentication.ErrSession), errors.Is(err, authentication.ErrCredential):
		status, code = 401, "invalid_credential"
		if bearer {
			w.Header().Set("WWW-Authenticate", "Bearer")
		}
	}
	if status == 503 {
		w.Header().Set("Retry-After", "1")
	}
	writeProblem(w, status, code, code)
}

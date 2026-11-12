package privateapi

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/dashboard"
)

func TestDashboardProblemContract(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{dashboard.ErrRequest, 400, "invalid_request"}, {dashboard.ErrInput, 422, "invalid_input"}, {dashboard.ErrCursor, 422, "invalid_cursor"}, {dashboard.ErrForbidden, 403, "forbidden"}, {authentication.ErrMFA, 403, "forbidden"}, {authentication.ErrTenant, 404, "resource_not_found"}, {authentication.ErrCredential, 401, "invalid_credential"}, {authentication.ErrSession, 401, "invalid_credential"}, {errors.New("private diagnostic"), 503, "dependency_unavailable"},
	} {
		for _, bearer := range []bool{false, true} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("X-Correlation-Id", "client-controlled")
			if !PrepareDashboard(w, r) {
				t.Fatal("prepare")
			}
			DashboardProblem(w, tc.err, bearer)
			var body map[string]any
			if json.Unmarshal(w.Body.Bytes(), &body) != nil || w.Code != tc.status || body["title"] != tc.code || body["code"] != tc.code || len(body) != 5 {
				t.Fatal(w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" || len(w.Header().Get("X-Correlation-Id")) != 36 || body["correlationId"] != w.Header().Get("X-Correlation-Id") {
				t.Fatal("headers")
			}
			if (w.Header().Get("WWW-Authenticate") != "") != (tc.status == 401 && bearer) {
				t.Fatal("challenge")
			}
		}
	}
	w := httptest.NewRecorder()
	if PrepareDashboard(w, httptest.NewRequest("POST", "/", nil)) || w.Code != 405 || w.Header().Get("Allow") != "GET" {
		t.Fatal("method accepted")
	}
}

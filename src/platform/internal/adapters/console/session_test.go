package console

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	a "hukid.local/platform/internal/authentication"
)

func TestSessionCommandsRejectInvalidRequestsBeforeStorage(t *testing.T) {
	f, err := os.Open("../../../config/auth.test.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.LoadPolicy(f, "test")
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	value := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, path := range []string{"/console/auth/refresh", "/console/auth/logout"} {
		for _, name := range []string{"method", "origin_missing", "origin_null", "origin_foreign", "origin_duplicate", "csrf_missing", "csrf_duplicate", "csrf_malformed", "cookie_missing", "cookie_duplicate", "query", "empty_query", "body", "transfer_encoding"} {
			t.Run(path+"/"+name, func(t *testing.T) {
				// No store/OIDC is installed: accepting any invalid request would panic.
				h := NewSessions(&a.SessionLifecycle{Sessions: &a.SessionService{Policy: p, Now: time.Now}})
				r := httptest.NewRequest("POST", p.ConsoleOrigin+path, nil)
				r.Header.Set("Origin", p.ConsoleOrigin)
				r.Header.Set("X-CSRF-Token", value)
				r.AddCookie(&http.Cookie{Name: p.CookieName, Value: value})
				status, code := 403, "csrf_invalid"
				switch name {
				case "method":
					r.Method = "GET"
					status = 405
					code = "invalid_request"
				case "origin_missing":
					r.Header.Del("Origin")
					code = "origin_invalid"
				case "origin_null":
					r.Header.Set("Origin", "null")
					code = "origin_invalid"
				case "origin_foreign":
					r.Header.Set("Origin", "http://127.0.0.1:1")
					code = "origin_invalid"
				case "origin_duplicate":
					r.Header.Add("Origin", p.ConsoleOrigin)
					code = "origin_invalid"
				case "csrf_missing":
					r.Header.Del("X-CSRF-Token")
				case "csrf_duplicate":
					r.Header.Add("X-CSRF-Token", value)
				case "csrf_malformed":
					r.Header.Set("X-CSRF-Token", strings.Repeat("!", 43))
				case "cookie_missing":
					r.Header.Del("Cookie")
				case "cookie_duplicate":
					r.AddCookie(&http.Cookie{Name: p.CookieName, Value: value})
				case "query":
					r.URL.RawQuery = "foo=bar"
					status = 422
					code = "invalid_request"
				case "empty_query":
					r.URL.ForceQuery = true
					status = 422
					code = "invalid_request"
				case "body":
					r.ContentLength = 1
					status = 422
					code = "invalid_request"
				case "transfer_encoding":
					r.TransferEncoding = []string{"chunked"}
					status = 422
					code = "invalid_request"
				}
				w := httptest.NewRecorder()
				h.serve(w, r)
				var problem struct {
					Code string `json:"code"`
				}
				if json.Unmarshal(w.Body.Bytes(), &problem) != nil || w.Code != status || problem.Code != code {
					t.Fatalf("unexpected safe rejection: %d %s", w.Code, problem.Code)
				}
				if len(w.Result().Cookies()) != 0 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Correlation-Id") == "" {
					t.Fatal("rejection changed cookie or lacked privacy headers")
				}
			})
		}
	}
}

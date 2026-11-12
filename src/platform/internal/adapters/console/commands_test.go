package console

import (
	a "hukid.local/platform/internal/authentication"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCommandJSONRejectsClaimsDuplicatesAndUnboundedInput(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `[]`, `{"returnTo":"/","returnTo":"/"}`, `{"returnTo":"/","amr":["pwd","otp"]}`, `{"returnTo":"/"} {}`, `{"returnTo":null}`, `{"returnTo":123}`, `{"returnTo":""}`, `{"returnTo":"` + strings.Repeat("a", 1100) + `"}`} {
		r := httptest.NewRequest("POST", "/console/auth/step-up", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if _, err := decodeCommand(httptest.NewRecorder(), r, "returnTo"); err == nil {
			t.Fatal("unsafe command JSON accepted")
		}
	}
	r := httptest.NewRequest("POST", "/console/auth/step-up", strings.NewReader(`{"returnTo":"/"}`))
	r.Header.Set("Content-Type", "application/json")
	if value, err := decodeCommand(httptest.NewRecorder(), r, "returnTo"); err != nil || value != "/" {
		t.Fatal("valid command rejected")
	}
}

func TestRemainingCommandsRejectOriginAndProofHeadersBeforeStorage(t *testing.T) {
	for _, path := range []string{"/console/auth/step-up", "/console/auth/tenant-context"} {
		for _, name := range []string{"method", "origin_missing", "origin_null", "origin_foreign", "origin_duplicate", "csrf_missing", "csrf_duplicate", "csrf_short", "cookie_missing", "cookie_duplicate"} {
			t.Run(path+"/"+name, func(t *testing.T) {
				p := a.Policy{ConsoleOrigin: "http://127.0.0.1:8080", CookieName: "hukid_test_session"}
				h := NewCommands(&a.LoginService{Policy: p, Now: time.Now}, nil, nil)
				r := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
				r.Header.Set("Origin", p.ConsoleOrigin)
				r.Header.Set("X-CSRF-Token", strings.Repeat("a", 43))
				r.AddCookie(&http.Cookie{Name: p.CookieName, Value: strings.Repeat("a", 43)})
				want := 403
				switch name {
				case "method":
					r.Method = "GET"
					want = 405
				case "origin_missing":
					r.Header.Del("Origin")
				case "origin_null":
					r.Header.Set("Origin", "null")
				case "origin_foreign":
					r.Header.Set("Origin", "http://127.0.0.1:1")
				case "origin_duplicate":
					r.Header.Add("Origin", p.ConsoleOrigin)
				case "csrf_missing":
					r.Header.Del("X-CSRF-Token")
				case "csrf_duplicate":
					r.Header.Add("X-CSRF-Token", strings.Repeat("a", 43))
				case "csrf_short":
					r.Header.Set("X-CSRF-Token", "invalid")
				case "cookie_missing":
					r.Header.Del("Cookie")
				case "cookie_duplicate":
					r.AddCookie(&http.Cookie{Name: p.CookieName, Value: strings.Repeat("a", 43)})
				}
				w := httptest.NewRecorder()
				h.serve(w, r)
				if w.Code != want || len(w.Result().Cookies()) != 0 || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("unsafe rejection")
				}
			})
		}
	}
}

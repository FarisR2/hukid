package console

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthorizationNegotiationKeepsRedirectCompatibility(t *testing.T) {
	for _, accept := range []string{"", "text/html", "application/json"} {
		h, store, _ := handlerFixture(t)
		r := httptest.NewRequest("GET", "/console/auth/login", nil)
		r.Header.Set("Accept", accept)
		w := httptest.NewRecorder()
		h.serve(w, r)
		want := 303
		if accept == "application/json" {
			want = 200
		}
		if w.Code != want || store.created != 1 || len(w.Result().Cookies()) != 1 || !w.Result().Cookies()[0].HttpOnly || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Vary") != "Accept" {
			t.Fatal("unsafe authorization response")
		}
		if want == 200 && (!strings.Contains(w.Body.String(), `"authorizationUrl":"http://127.0.0.1:19090/auth"`) || w.Header().Get("Location") != "") {
			t.Fatal("missing JSON navigation")
		}
	}
}

func TestBrowserCallbackErrorHasSafeRecovery(t *testing.T) {
	h, _, _ := handlerFixture(t)
	r := httptest.NewRequest("GET", "/console/auth/callback?code=private-code&state=private-state&error_description=private-detail", nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	w := httptest.NewRecorder()
	h.serve(w, r)
	if w.Code != 400 || w.Header().Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(w.Body.String(), `href="/"`) || w.Header().Get("Content-Security-Policy") == "" || strings.Contains(w.Body.String(), "private-") {
		t.Fatal("unsafe callback error page")
	}
}

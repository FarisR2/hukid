package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListenAddress(t *testing.T) {
	for _, value := range []string{"", "127.0.0.1:8080", "[::1]:8081"} {
		if _, err := ListenAddress(value); err != nil {
			t.Errorf("expected loopback address %q: %v", value, err)
		}
	}
	for _, value := range []string{"0.0.0.0:8080", ":8080", "192.168.1.2:8080", "localhost:8080", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:http", "bad"} {
		if _, err := ListenAddress(value); err == nil {
			t.Errorf("expected rejection of %q", value)
		}
	}
}

func TestBootstrapSurface(t *testing.T) {
	for _, tc := range []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/healthz", http.StatusNoContent},
		{http.MethodHead, "/healthz", http.StatusNoContent},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		{http.MethodGet, "/console/api/me", http.StatusNotFound},
		{http.MethodGet, "/v1/operator/me", http.StatusNotFound},
		{http.MethodGet, "/console/auth/login", http.StatusNotFound},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			Handler().ServeHTTP(response, httptest.NewRequest(tc.method, tc.path, nil))
			if response.Code != tc.status {
				t.Fatalf("status = %d, want %d", response.Code, tc.status)
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing response protections")
			}
			if tc.status == http.StatusNoContent && response.Body.Len() != 0 {
				t.Fatal("liveness must not return data")
			}
		})
	}
}

package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthcheckAnswersOnlyTo204OnTheLoopbackListener(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		valid  bool
	}{
		{"liveness_204", http.StatusNoContent, true},
		{"ok_is_not_the_contract", http.StatusOK, false},
		{"server_error", http.StatusInternalServerError, false},
		{"redirect_is_not_followed", http.StatusFound, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/healthz" {
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				w.Header().Set("Location", "/elsewhere")
				w.WriteHeader(tc.status)
			}))
			defer server.Close()
			getenv := func(string) string { return server.Listener.Addr().String() }
			if err := healthcheck(getenv, newHealthcheckClient()); (err == nil) != tc.valid {
				t.Fatalf("healthcheck error = %v, want valid=%v", err, tc.valid)
			}
		})
	}
}

func TestHealthcheckFailsWhenNothingListensOrTheAddressIsNotLoopback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := listener.Addr().String()
	listener.Close()
	for name, address := range map[string]string{
		"nothing_listening": closed,
		"non_loopback_ip":   "10.0.0.1:8080",
		"hostname":          "example.com:8080",
		"no_port":           "127.0.0.1",
	} {
		t.Run(name, func(t *testing.T) {
			if err := healthcheck(func(string) string { return address }, newHealthcheckClient()); err == nil {
				t.Fatal("healthcheck succeeded against an address that must fail")
			}
		})
	}
}

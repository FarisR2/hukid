// Package bootstrap contains only the local development entry point.
// Authentication and Management routes require the AUTH-T02 contracts first.
package bootstrap

import (
	"errors"
	"net"
	"net/http"
	"strconv"
)

// ListenAddress confines this unauthenticated bootstrap to a loopback IP.
func ListenAddress(value string) (string, error) {
	if value == "" {
		return "127.0.0.1:8080", nil
	}
	host, port, err := net.SplitHostPort(value)
	ip := net.ParseIP(host)
	number, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || number < 1 || number > 65535 {
		return "", errors.New("HUKID_LISTEN_ADDR must contain a loopback IP and port 1..65535")
	}
	return value, nil
}

// Handler exposes liveness only; it does not claim DB or IdP readiness.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

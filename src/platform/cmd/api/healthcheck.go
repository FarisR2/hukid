package main

import (
	"errors"
	"io"
	"net/http"
	"time"

	"hukid.local/platform/internal/bootstrap"
)

// The runtime image is distroless (no shell, wget or curl), so the container healthcheck is a
// subcommand of this binary: `hukid-api healthcheck`. It asks the liveness endpoint on the
// loopback listener the server itself would use and exits 0 only on the documented 204.
// It reads nothing but HUKID_LISTEN_ADDR, so it never needs secrets, the database or the IdP.
const healthcheckTimeout = 3 * time.Second

func healthcheck(getenv func(string) string, client *http.Client) error {
	address, err := bootstrap.ListenAddress(getenv("HUKID_LISTEN_ADDR"))
	if err != nil {
		return err
	}
	response, err := client.Get("http://" + address + "/healthz")
	if err != nil {
		return errors.New("liveness endpoint unreachable")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<10))
	if response.StatusCode != http.StatusNoContent {
		return errors.New("liveness endpoint did not answer 204")
	}
	return nil
}

// newHealthcheckClient never follows redirects: a redirect is not the liveness answer.
func newHealthcheckClient() *http.Client {
	return &http.Client{
		Timeout:       healthcheckTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

package main

import (
	"bytes"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPPanicDoesNotLogDependencySecrets(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	defer slog.SetDefault(previous)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("synthetic-private-token") }))
	server.Config.ErrorLog = log.New(redactedServerLog{}, "", 0)
	server.Start()
	defer server.Close()
	response, err := server.Client().Get(server.URL)
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("panic request succeeded")
	}
	if strings.Contains(output.String(), "synthetic-private-token") || !strings.Contains(output.String(), "http server failure") {
		t.Fatal("unsafe panic diagnostics")
	}
}

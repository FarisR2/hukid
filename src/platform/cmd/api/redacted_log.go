package main

import "log/slog"

// net/http diagnostics can contain panic values supplied by dependencies.
type redactedServerLog struct{}

func (redactedServerLog) Write(p []byte) (int, error) {
	slog.Error("http server failure")
	return len(p), nil
}

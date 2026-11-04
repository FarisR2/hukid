package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/bootstrap"
)

func main() {
	if err := run(); err != nil {
		slog.Error("platform stopped", "error", err)
		os.Exit(1)
	}
}

func validateAuthConfiguration() error {
	policyPath := os.Getenv("HUKID_AUTH_POLICY")
	environment := os.Getenv("HUKID_ENV")
	if policyPath == "" && environment == "" {
		return nil // Liveness-only bootstrap; no authentication routes exist.
	}
	if policyPath == "" {
		return errors.New("HUKID_AUTH_POLICY is required when HUKID_ENV is set")
	}
	file, err := os.Open(policyPath)
	if err != nil {
		return errors.New("cannot open auth policy")
	}
	defer file.Close()
	_, err = authentication.LoadPolicy(file, environment)
	return err
}

func run() error {
	if err := validateAuthConfiguration(); err != nil {
		return err
	}
	address, err := bootstrap.ListenAddress(os.Getenv("HUKID_LISTEN_ADDR"))
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              address,
		Handler:           bootstrap.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result := make(chan error, 1)
	go func() { result <- server.ListenAndServe() }()
	slog.Info("starting local bootstrap", "address", address)
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}

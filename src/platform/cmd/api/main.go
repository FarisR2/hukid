package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"hukid.local/platform/internal/bootstrap"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		if err := healthcheck(os.Getenv, newHealthcheckClient()); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		slog.Error("platform stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	if err := validateAuthConfiguration(); err != nil {
		return err
	}
	address, err := bootstrap.ListenAddress(os.Getenv("HUKID_LISTEN_ADDR"))
	if err != nil {
		return err
	}
	startup, cancelStartup := context.WithTimeout(context.Background(), 5*time.Second)
	handler, cleanup, err := configureHandler(startup, address)
	cancelStartup()
	if err != nil {
		return err
	}
	defer cleanup()
	server := &http.Server{
		ErrorLog:          log.New(redactedServerLog{}, "", 0),
		Addr:              address,
		Handler:           handler,
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

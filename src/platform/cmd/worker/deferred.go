package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"hukid.local/platform/internal/adapters/postgres"
	"hukid.local/platform/internal/adapters/vaultkms"
	"hukid.local/platform/internal/issuance"
)

const (
	defaultDeferredBatchSize = 50
	minDeferredInterval      = time.Second
	maxDeferredInterval      = time.Hour
	deferredLockNamespace    = "hukid/deferred-worker/v1"
)

var errDeferredWorkerConfig = errors.New("complete isolated deferred issuance worker configuration is required")

type deferredWorkerOptions struct {
	tenantID string
	limit    int
	interval time.Duration
}

func isDeferredRuntimeEnv(env string) bool {
	return env == "local" || env == "test" || env == "staging" || env == "production"
}

func isDeferredProdOrStaging(env string) bool {
	return env == "staging" || env == "production"
}

func isDeferredLoopbackHTTPURL(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	if u.Hostname() == "localhost" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback()
}

func parseDeferredWorkerArgs(args []string) (string, int, error) {
	opts, err := parseDeferredWorkerOptions(args)
	if err != nil {
		return "", 0, err
	}
	return opts.tenantID, opts.limit, nil
}

func parseDeferredWorkerOptions(args []string) (deferredWorkerOptions, error) {
	positional := make([]string, 0, len(args))
	var rawInterval string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "--interval="):
			if rawInterval != "" {
				return deferredWorkerOptions{}, errDeferredWorkerConfig
			}
			rawInterval = strings.TrimPrefix(arg, "--interval=")
		case arg == "--interval":
			if rawInterval != "" || i+1 >= len(args) {
				return deferredWorkerOptions{}, errDeferredWorkerConfig
			}
			i++
			rawInterval = args[i]
		case strings.HasPrefix(arg, "-"):
			return deferredWorkerOptions{}, errDeferredWorkerConfig
		default:
			positional = append(positional, arg)
		}
	}
	if len(positional) < 1 || len(positional) > 2 || strings.TrimSpace(positional[0]) == "" {
		return deferredWorkerOptions{}, errDeferredWorkerConfig
	}
	limit := defaultDeferredBatchSize
	if len(positional) == 2 {
		parsed, err := strconv.Atoi(positional[1])
		if err != nil || parsed < 1 || parsed > 500 {
			return deferredWorkerOptions{}, errDeferredWorkerConfig
		}
		limit = parsed
	}
	var interval time.Duration
	if rawInterval != "" {
		parsed, err := time.ParseDuration(strings.TrimSpace(rawInterval))
		if err != nil || parsed < minDeferredInterval || parsed > maxDeferredInterval {
			return deferredWorkerOptions{}, errDeferredWorkerConfig
		}
		interval = parsed
	}
	return deferredWorkerOptions{tenantID: positional[0], limit: limit, interval: interval}, nil
}

func runDeferredScheduler(ctx context.Context, interval time.Duration, step func(context.Context) error) error {
	if err := step(ctx); err != nil {
		return err
	}
	if interval <= 0 {
		return nil
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := step(ctx); err != nil {
				return err
			}
		}
	}
}

// runDeferredWorker is a bounded tenant-scoped batch intended for a scheduler or HA loop.
// Invoke once with `worker deferred <tenant-id> [limit]` or periodically with `--interval=<dur>`.
func runDeferredWorker(args []string) error {
	opts, err := parseDeferredWorkerOptions(args)
	if err != nil || !isDeferredRuntimeEnv(os.Getenv("HUKID_ENV")) {
		return errDeferredWorkerConfig
	}
	if opts.interval == 0 {
		if envInterval := strings.TrimSpace(os.Getenv("HUKID_WORKER_INTERVAL")); envInterval != "" {
			parsed, parseErr := time.ParseDuration(envInterval)
			if parseErr != nil || parsed < minDeferredInterval || parsed > maxDeferredInterval {
				return errDeferredWorkerConfig
			}
			opts.interval = parsed
		}
	}
	env := os.Getenv("HUKID_ENV")
	dsn := os.Getenv("HUKID_ISSUANCE_DATABASE_URL")
	if isDeferredProdOrStaging(env) {
		cfg, parseErr := pgxpool.ParseConfig(dsn)
		if parseErr != nil || cfg.ConnConfig.Host == "" || cfg.ConnConfig.Database == "" || cfg.ConnConfig.TLSConfig == nil {
			return errDeferredWorkerConfig
		}
	} else if postgres.ValidateLoginDatabase(dsn) != nil {
		return errDeferredWorkerConfig
	}

	authServer := strings.TrimRight(os.Getenv("HUKID_ISSUANCE_AUTH_SERVER"), "/")
	authURL, err := url.Parse(authServer)
	if err != nil || authURL.Host == "" || authURL.User != nil || authURL.RawQuery != "" || authURL.Fragment != "" || authURL.Scheme != "https" && (isDeferredProdOrStaging(env) || !isDeferredLoopbackHTTPURL(authURL)) {
		return errDeferredWorkerConfig
	}
	keyVersion := strings.TrimSpace(os.Getenv("HUKID_ISSUANCE_CLAIMS_KEY_VERSION"))
	if keyVersion == "" || len(keyVersion) > 128 || strings.ContainsAny(keyVersion, " \t\r\n") {
		return errDeferredWorkerConfig
	}
	var claimsKey []byte
	if raw := os.Getenv("HUKID_ISSUANCE_CLAIMS_KEY"); raw != "" {
		if os.Getenv("HUKID_ISSUANCE_CLAIMS_KEY_CIPHERTEXT") != "" {
			return errDeferredWorkerConfig
		}
		claimsKey, err = base64.StdEncoding.Strict().DecodeString(raw)
		if err != nil || len(claimsKey) != 32 {
			clear(claimsKey)
			return errDeferredWorkerConfig
		}
	} else if os.Getenv("HUKID_ISSUANCE_CLAIMS_KEY_CIPHERTEXT") == "" {
		return errDeferredWorkerConfig
	}
	defer clear(claimsKey)

	vaultCfg := vaultkms.Config{
		BaseURL:   os.Getenv("HUKID_VAULT_ADDR"),
		Token:     os.Getenv("HUKID_VAULT_TOKEN"),
		MountPath: os.Getenv("HUKID_VAULT_MOUNT"),
		Namespace: os.Getenv("HUKID_VAULT_NAMESPACE"),
	}
	if isDeferredProdOrStaging(env) {
		vaultURL, parseErr := url.Parse(vaultCfg.BaseURL)
		if parseErr != nil || vaultURL.Scheme != "https" || vaultURL.Host == "" || vaultURL.User != nil {
			return errDeferredWorkerConfig
		}
	}
	vault, err := vaultkms.NewClient(vaultCfg)
	if err != nil {
		return errDeferredWorkerConfig
	}
	if len(claimsKey) == 0 {
		kek := strings.TrimSpace(os.Getenv("HUKID_VAULT_KEK_NAME"))
		ciphertext := os.Getenv("HUKID_ISSUANCE_CLAIMS_KEY_CIPHERTEXT")
		if kek == "" || !strings.HasPrefix(ciphertext, "vault:v") {
			return errDeferredWorkerConfig
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		claimsKey, err = vault.UnwrapDEK(ctx, kek, ciphertext, "hukid/claims-dek/v1|"+keyVersion)
		cancel()
		if err != nil || len(claimsKey) != 32 {
			clear(claimsKey)
			return errDeferredWorkerConfig
		}
		defer clear(claimsKey)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	poolCtx, poolCancel := context.WithTimeout(ctx, 15*time.Second)
	pool, err := postgres.OpenRuntimePool(poolCtx, dsn, "hukid_issuance_runtime", 4)
	poolCancel()
	if err != nil {
		return errDeferredWorkerConfig
	}
	defer pool.Close()
	backend, err := postgres.NewIssuanceBackend(pool)
	if err != nil {
		return errDeferredWorkerConfig
	}
	service, err := issuance.NewService(issuance.ServiceConfig{
		ClaimsKey: claimsKey, ClaimsKeyVersion: keyVersion, Backend: backend,
		Signers: vault.Resolver(), KeyProvisioner: vault.KeyProvisioner(),
		AuthorizationServer: authServer,
	})
	if err != nil {
		return errDeferredWorkerConfig
	}
	return runDeferredScheduler(ctx, opts.interval, func(tickCtx context.Context) error {
		batchCtx, batchCancel := context.WithTimeout(tickCtx, 2*time.Minute)
		defer batchCancel()
		var fulfilled int
		acquired, lockErr := postgres.TryWithTenantAdvisoryLock(batchCtx, pool, deferredLockNamespace, opts.tenantID, func() error {
			var batchErr error
			fulfilled, batchErr = service.FulfillPendingDeferredRequests(opts.tenantID, opts.limit)
			return batchErr
		})
		if lockErr != nil {
			return fmt.Errorf("deferred issuance batch failed after %d credentials: %w", fulfilled, lockErr)
		}
		if !acquired {
			fmt.Printf("deferred issuance batch: tenant=%s skipped=lock_held\n", opts.tenantID)
			return nil
		}
		fmt.Printf("deferred issuance batch: tenant=%s fulfilled=%d limit=%d\n", opts.tenantID, fulfilled, opts.limit)
		return nil
	})
}

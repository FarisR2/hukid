package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"hukid.local/platform/internal/adapters/postgres"
	"hukid.local/platform/internal/adapters/vaultkms"
	"hukid.local/platform/internal/issuance"
)

const defaultDeferredBatchSize = 50

var errDeferredWorkerConfig = errors.New("complete isolated deferred issuance worker configuration is required")

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
	if len(args) < 1 || len(args) > 2 || strings.TrimSpace(args[0]) == "" {
		return "", 0, errDeferredWorkerConfig
	}
	limit := defaultDeferredBatchSize
	if len(args) == 2 {
		parsed, err := strconv.Atoi(args[1])
		if err != nil || parsed < 1 || parsed > 500 {
			return "", 0, errDeferredWorkerConfig
		}
		limit = parsed
	}
	return args[0], limit, nil
}

// runDeferredWorker is a bounded tenant-scoped batch intended for a scheduler.
// Invoke it periodically with `worker deferred <tenant-id> [limit]`.
func runDeferredWorker(args []string) error {
	tenantID, limit, err := parseDeferredWorkerArgs(args)
	if err != nil || !isDeferredRuntimeEnv(os.Getenv("HUKID_ENV")) {
		return errDeferredWorkerConfig
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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := postgres.OpenRuntimePool(ctx, dsn, "hukid_issuance_runtime", 4)
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
	fulfilled, err := service.FulfillPendingDeferredRequests(tenantID, limit)
	if err != nil {
		return fmt.Errorf("deferred issuance batch failed after %d credentials: %w", fulfilled, err)
	}
	fmt.Printf("deferred issuance batch: tenant=%s fulfilled=%d limit=%d\n", tenantID, fulfilled, limit)
	return nil
}

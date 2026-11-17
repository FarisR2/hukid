package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"hukid.local/platform/internal/adapters/oid4vcihttp"
	"hukid.local/platform/internal/adapters/oid4vphttp"
	"hukid.local/platform/internal/adapters/postgres"
	"hukid.local/platform/internal/adapters/privateapi"
	"hukid.local/platform/internal/adapters/vaultkms"
	"hukid.local/platform/internal/adapters/verifierhttp"
	"hukid.local/platform/internal/issuance"
	"hukid.local/platform/internal/oid4vp"
	"hukid.local/platform/internal/verification"
)

const (
	envIssuanceDatabaseURL         = "HUKID_ISSUANCE_DATABASE_URL"
	envIssuanceAuthServer          = "HUKID_ISSUANCE_AUTH_SERVER"
	envIssuanceClaimsKey           = "HUKID_ISSUANCE_CLAIMS_KEY"
	envIssuanceClaimsKeyCiphertext = "HUKID_ISSUANCE_CLAIMS_KEY_CIPHERTEXT"
	envIssuanceClaimsKeyVersion    = "HUKID_ISSUANCE_CLAIMS_KEY_VERSION"
	envVaultAddr                   = "HUKID_VAULT_ADDR"
	envVaultToken                  = "HUKID_VAULT_TOKEN"
	envVaultMount                  = "HUKID_VAULT_MOUNT"
	envVaultNamespace              = "HUKID_VAULT_NAMESPACE"
	envVaultKEKName                = "HUKID_VAULT_KEK_NAME"
	envOID4VPClientID              = "HUKID_OID4VP_CLIENT_ID"
	envOID4VPResponseURI           = "HUKID_OID4VP_RESPONSE_URI"
	envOID4VPSigningKey            = "HUKID_OID4VP_SIGNING_KEY"
	envOID4VPSigningCertPEM        = "HUKID_OID4VP_SIGNING_CERT_PEM"
	envOID4VPTransportBase         = "HUKID_OID4VP_TRANSPORT_BASE"
)

var (
	errIssuanceRuntimeConfig = errors.New("complete isolated issuance runtime and vault configuration is required")
	errOID4VPRuntimeConfig   = errors.New("complete oid4vp runtime configuration is required")
)

type issuanceRuntimeConfig struct {
	Environment         string
	DatabaseURL         string
	AuthServer          string
	ClaimsKey           []byte
	ClaimsKeyCiphertext string
	ClaimsKeyVersion    string
	Vault               vaultkms.Config
	VaultKEKName        string
}

type oid4vpRuntimeConfig struct {
	Environment   string
	ClientID      string
	ResponseURI   string
	SigningKey    string
	CertPEM       string
	TransportBase string
}

func isRuntimeEnvSupported(env string) bool {
	return env == "local" || env == "test" || env == "staging" || env == "production"
}

func isProdOrStaging(env string) bool {
	return env == "staging" || env == "production"
}

func anyIssuanceRuntimeEnvSet() bool {
	for _, k := range []string{
		envIssuanceDatabaseURL, envIssuanceAuthServer, envIssuanceClaimsKey,
		envIssuanceClaimsKeyCiphertext, envIssuanceClaimsKeyVersion,
		envVaultAddr, envVaultToken, envVaultMount, envVaultNamespace, envVaultKEKName,
	} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

func anyOID4VPRuntimeEnvSet() bool {
	for _, k := range []string{
		envOID4VPClientID, envOID4VPResponseURI, envOID4VPSigningKey,
		envOID4VPSigningCertPEM, envOID4VPTransportBase,
	} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

func validateRuntimeDatabaseURL(env, dsn string) error {
	if !isProdOrStaging(env) {
		return postgres.ValidateLoginDatabase(dsn)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil || cfg.ConnConfig.Host == "" || cfg.ConnConfig.Database == "" || cfg.ConnConfig.TLSConfig == nil {
		return errIssuanceRuntimeConfig
	}
	return nil
}

func isLoopbackHTTPURL(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func loadIssuanceRuntimeConfig() (*issuanceRuntimeConfig, error) {
	if !anyIssuanceRuntimeEnvSet() {
		return nil, nil
	}
	if anyVCILabEnvSet() {
		return nil, errors.New("cannot enable both oid4vci lab and issuance runtime")
	}
	env := os.Getenv("HUKID_ENV")
	if !isRuntimeEnvSupported(env) {
		return nil, errIssuanceRuntimeConfig
	}
	dsn := os.Getenv(envIssuanceDatabaseURL)
	if dsn == "" || validateRuntimeDatabaseURL(env, dsn) != nil {
		return nil, errIssuanceRuntimeConfig
	}
	authServer := os.Getenv(envIssuanceAuthServer)
	u, err := url.Parse(authServer)
	if err != nil || authServer == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errIssuanceRuntimeConfig
	}
	if u.Scheme != "https" && (isProdOrStaging(env) || !isLoopbackHTTPURL(u)) {
		return nil, errIssuanceRuntimeConfig
	}

	keyVer := strings.TrimSpace(os.Getenv(envIssuanceClaimsKeyVersion))
	if keyVer == "" || len(keyVer) > 128 || strings.ContainsAny(keyVer, " \t\r\n") {
		return nil, errIssuanceRuntimeConfig
	}
	rawKey := os.Getenv(envIssuanceClaimsKey)
	wrappedKey := os.Getenv(envIssuanceClaimsKeyCiphertext)
	kekName := strings.TrimSpace(os.Getenv(envVaultKEKName))
	if (rawKey == "" && wrappedKey == "") || (rawKey != "" && wrappedKey != "") {
		return nil, errIssuanceRuntimeConfig
	}
	var plainKey []byte
	if rawKey != "" {
		decoded, decErr := base64.StdEncoding.Strict().DecodeString(rawKey)
		if decErr != nil || len(decoded) != 32 {
			if len(decoded) > 0 {
				clear(decoded)
			}
			return nil, errIssuanceRuntimeConfig
		}
		plainKey = decoded
	} else {
		if kekName == "" || !strings.HasPrefix(wrappedKey, "vault:v") {
			return nil, errIssuanceRuntimeConfig
		}
	}

	vaultAddr := os.Getenv(envVaultAddr)
	vaultToken := os.Getenv(envVaultToken)
	if isProdOrStaging(env) {
		vu, vErr := url.Parse(vaultAddr)
		if vErr != nil || vu.Scheme != "https" {
			clear(plainKey)
			return nil, errIssuanceRuntimeConfig
		}
	}
	vCfg := vaultkms.Config{
		BaseURL:   vaultAddr,
		Token:     vaultToken,
		MountPath: os.Getenv(envVaultMount),
		Namespace: os.Getenv(envVaultNamespace),
	}
	if _, err := vaultkms.NewClient(vCfg); err != nil {
		clear(plainKey)
		return nil, errIssuanceRuntimeConfig
	}

	return &issuanceRuntimeConfig{
		Environment:         env,
		DatabaseURL:         dsn,
		AuthServer:          strings.TrimRight(authServer, "/"),
		ClaimsKey:           plainKey,
		ClaimsKeyCiphertext: wrappedKey,
		ClaimsKeyVersion:    keyVer,
		Vault:               vCfg,
		VaultKEKName:        kekName,
	}, nil
}

func validateIssuanceRuntimeConfiguration() error {
	cfg, err := loadIssuanceRuntimeConfig()
	if cfg != nil {
		clear(cfg.ClaimsKey)
	}
	return err
}

func configureIssuanceRuntime(
	ctx context.Context,
	operators *privateapi.Handler,
	now func() time.Time,
	vaultOverride ...*vaultkms.Client,
) (func(*http.ServeMux), func(), error) {
	cfg, err := loadIssuanceRuntimeConfig()
	if err != nil || cfg == nil {
		return nil, nil, err
	}
	defer clear(cfg.ClaimsKey)
	if now == nil {
		now = time.Now
	}

	var vaultClient *vaultkms.Client
	if len(vaultOverride) > 0 && vaultOverride[0] != nil {
		vaultClient = vaultOverride[0]
	} else {
		vaultClient, err = vaultkms.NewClient(cfg.Vault)
		if err != nil {
			return nil, nil, err
		}
	}

	claimsKey := cfg.ClaimsKey
	if len(claimsKey) == 0 {
		claimsKey, err = vaultClient.UnwrapDEK(ctx, cfg.VaultKEKName, cfg.ClaimsKeyCiphertext, "hukid/claims-dek/v1|"+cfg.ClaimsKeyVersion)
		if err != nil {
			return nil, nil, err
		}
		defer clear(claimsKey)
	}

	pool, err := postgres.OpenRuntimePool(ctx, cfg.DatabaseURL, "hukid_issuance_runtime", 4)
	if err != nil {
		return nil, nil, err
	}
	backend, err := postgres.NewIssuanceBackend(pool)
	if err != nil {
		pool.Close()
		return nil, nil, err
	}
	svc, err := issuance.NewService(issuance.ServiceConfig{
		ClaimsKey:           claimsKey,
		ClaimsKeyVersion:    cfg.ClaimsKeyVersion,
		Backend:             backend,
		Signers:             vaultClient.Resolver(),
		KeyProvisioner:      vaultClient.KeyProvisioner(),
		AuthorizationServer: cfg.AuthServer,
		Now:                 now,
	})
	if err != nil {
		pool.Close()
		return nil, nil, err
	}

	discovery := &oid4vcihttp.Handler{Catalog: svc}
	endpoints := &oid4vcihttp.IssuanceHandler{Service: svc}
	var admin *privateapi.IssuanceAdminHandler
	if operators != nil {
		admin = &privateapi.IssuanceAdminHandler{Operators: operators, Service: svc, Now: now}
	}
	routes := func(mux *http.ServeMux) {
		discovery.Routes(mux)
		endpoints.Routes(mux)
		if admin != nil {
			admin.Register(mux)
		}
	}
	return routes, pool.Close, nil
}

func loadOID4VPRuntimeConfig() (*oid4vpRuntimeConfig, error) {
	if !anyOID4VPRuntimeEnvSet() {
		return nil, nil
	}
	if os.Getenv(labFlag) != "" || os.Getenv(labClientID) != "" || os.Getenv(labResponse) != "" || os.Getenv(labIssuerKeys) != "" {
		return nil, errors.New("cannot enable both oid4vp lab and oid4vp runtime")
	}
	env := os.Getenv("HUKID_ENV")
	if !isRuntimeEnvSupported(env) {
		return nil, errOID4VPRuntimeConfig
	}
	clientID := os.Getenv(envOID4VPClientID)
	if strings.TrimSpace(clientID) == "" || len(clientID) > 256 || strings.ContainsAny(clientID, " \t\r\n") {
		return nil, errOID4VPRuntimeConfig
	}
	respURI := os.Getenv(envOID4VPResponseURI)
	pu, err := url.Parse(respURI)
	if err != nil || pu.Scheme != "https" || pu.Host == "" || pu.Path != oid4vphttp.ResponsePath || pu.RawQuery != "" || pu.Fragment != "" || pu.User != nil {
		return nil, errOID4VPRuntimeConfig
	}
	signingKey := os.Getenv(envOID4VPSigningKey)
	if signingKey == "" {
		return nil, errOID4VPRuntimeConfig
	}
	transportBase := os.Getenv(envOID4VPTransportBase)
	if transportBase != "" {
		tu, tErr := url.Parse(transportBase)
		if tErr != nil || (tu.Scheme != "https" && (isProdOrStaging(env) || !isLoopbackHTTPURL(tu))) || tu.Host == "" || tu.User != nil || tu.RawQuery != "" || tu.Fragment != "" {
			return nil, errOID4VPRuntimeConfig
		}
	}
	return &oid4vpRuntimeConfig{
		Environment:   env,
		ClientID:      clientID,
		ResponseURI:   respURI,
		SigningKey:    signingKey,
		CertPEM:       os.Getenv(envOID4VPSigningCertPEM),
		TransportBase: strings.TrimRight(transportBase, "/"),
	}, nil
}

func validateOID4VPRuntimeConfiguration() error {
	_, err := loadOID4VPRuntimeConfig()
	return err
}

func loadCertChainPEM(path string) ([][]byte, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > vciLabMaxPEMFile {
		return nil, errOID4VPRuntimeConfig
	}
	var chain [][]byte
	rest := data
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, errOID4VPRuntimeConfig
		}
		if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
			return nil, errOID4VPRuntimeConfig
		}
		chain = append(chain, blk.Bytes)
	}
	if len(chain) == 0 || len(strings.TrimSpace(string(rest))) > 0 {
		return nil, errOID4VPRuntimeConfig
	}
	return chain, nil
}

func configureOID4VPRuntime(out io.Writer, now func() time.Time) (func(*http.ServeMux), error) {
	cfg, err := loadOID4VPRuntimeConfig()
	if err != nil || cfg == nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	signingKey, err := loadOrCreatePersistentP256Key(cfg.SigningKey, false)
	if err != nil {
		return nil, errOID4VPRuntimeConfig
	}
	chain, err := loadCertChainPEM(cfg.CertPEM)
	if err != nil {
		return nil, err
	}
	httpResolver, err := verifierhttp.NewResolver(verifierhttp.Config{
		TransportBase: cfg.TransportBase,
	})
	if err != nil {
		return nil, errOID4VPRuntimeConfig
	}
	verifier, err := verification.NewVerifier(httpResolver, verification.ClockFunc(now), verification.DefaultLimits, 0)
	if err != nil {
		return nil, errOID4VPRuntimeConfig
	}
	verifier = verifier.
		WithStatusResolver(httpResolver, verification.StatusPolicy{}).
		WithSchemaResolver(httpResolver)

	replay, err := oid4vp.NewScopedReplayStore("oid4vp-runtime", oid4vp.MaxTTL, 1024, now)
	if err != nil {
		return nil, errOID4VPRuntimeConfig
	}
	sessions, err := oid4vp.NewSessionStore(256, now)
	if err != nil {
		return nil, errOID4VPRuntimeConfig
	}
	handler := &oid4vphttp.Handler{
		Sessions:   sessions,
		Verifier:   verifier.WithReplayStore(replay),
		Results:    labResults{out: out},
		SigningKey: signingKey,
		Chain:      chain,
		Now:        now,
	}
	return handler.Routes, nil
}

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"time"

	consolehttp "hukid.local/platform/internal/adapters/console"
	"hukid.local/platform/internal/adapters/oidc"
	"hukid.local/platform/internal/adapters/postgres"
	"hukid.local/platform/internal/adapters/privateapi"
	"hukid.local/platform/internal/adapters/secretbox"
	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/bootstrap"
	"hukid.local/platform/internal/tenancy"
)

type authConfig struct {
	policy                        authentication.Policy
	dsn, clientSecret, keyVersion string
	key                           []byte
	contextDSN, tenantDSN         string
}

func loadAuthConfiguration() (*authConfig, error) {
	path, environment := os.Getenv("HUKID_AUTH_POLICY"), os.Getenv("HUKID_ENV")
	values := []string{os.Getenv("HUKID_SESSION_DATABASE_URL"), os.Getenv("HUKID_OIDC_CLIENT_SECRET"), os.Getenv("HUKID_AUTH_KEY"), os.Getenv("HUKID_AUTH_KEY_VERSION"), os.Getenv("HUKID_CONTEXT_DATABASE_URL"), os.Getenv("HUKID_TENANT_DATABASE_URL")}
	configured := path != "" || environment != ""
	for _, v := range values {
		configured = configured || v != ""
	}
	if !configured {
		return nil, nil
	}
	invalid := errors.New("complete isolated auth configuration is required")
	if path == "" || environment != "test" {
		return nil, invalid
	}
	for _, v := range values {
		if v == "" {
			return nil, invalid
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open auth policy")
	}
	defer file.Close()
	p, err := authentication.LoadPolicy(file, environment)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.Strict().DecodeString(values[2])
	if err != nil || len(key) != 32 || len(values[3]) > 128 {
		return nil, invalid
	}
	for _, dsn := range []string{values[0], values[4], values[5]} {
		if postgres.ValidateLoginDatabase(dsn) != nil {
			return nil, invalid
		}
	}
	return &authConfig{policy: p, dsn: values[0], clientSecret: values[1], keyVersion: values[3], key: key, contextDSN: values[4], tenantDSN: values[5]}, nil
}

func validateAuthConfiguration() error {
	config, err := loadAuthConfiguration()
	if config != nil {
		clear(config.key)
	}
	return err
}

func configureHandler(ctx context.Context, address string) (http.Handler, func(), error) {
	config, err := loadAuthConfiguration()
	if err != nil {
		return nil, nil, err
	}
	if config == nil {
		return bootstrap.Handler(), func() {}, nil
	}
	defer clear(config.key)
	// A local Vite proxy can own the browser origin. This is explicit config,
	// never a forwarded/request header; policy validation still confines it to loopback.
	if config.policy.ConsoleOrigin != "http://"+address && os.Getenv("HUKID_CONSOLE_PROXY_ORIGIN") != config.policy.ConsoleOrigin {
		return nil, nil, errors.New("auth origin must match the explicit listener")
	}
	box, err := secretbox.New(config.key, config.keyVersion, rand.Reader)
	if err != nil {
		return nil, nil, authentication.ErrDependency
	}
	pool, err := postgres.OpenRuntimePool(ctx, config.dsn, "hukid_session_runtime", 4)
	if err != nil {
		return nil, nil, authentication.ErrDependency
	}
	discovery, err := postgres.OpenRuntimePool(ctx, config.contextDSN, "hukid_context_runtime", 4)
	if err != nil {
		pool.Close()
		return nil, nil, authentication.ErrDependency
	}
	tenant, err := postgres.OpenRuntimePool(ctx, config.tenantDSN, "hukid_tenant_runtime", 4)
	if err != nil {
		discovery.Close()
		pool.Close()
		return nil, nil, authentication.ErrDependency
	}
	closePools := func() { tenant.Close(); discovery.Close(); pool.Close() }
	provider, err := oidc.New(ctx, config.policy, config.clientSecret, time.Now)
	if err != nil {
		closePools()
		return nil, nil, authentication.ErrDependency
	}
	service := &authentication.LoginService{Policy: config.policy, OIDC: provider, Store: &postgres.LoginStore{Pool: pool}, Cipher: box, Now: time.Now, Random: rand.Reader}
	contexts, err := tenancy.New(&postgres.OperatorStore{Discovery: discovery, Tenant: tenant})
	if err != nil {
		closePools()
		return nil, nil, authentication.ErrDependency
	}
	management := &privateapi.Handler{Verifier: provider, Tenancy: contexts}
	store := &postgres.LoginStore{Pool: pool}
	sessions := &authentication.SessionService{Store: store, Cipher: box, Policy: config.policy, Now: time.Now}
	service.Sessions = sessions
	service.Reauthentication = store
	protectedCommands := consolehttp.NewCommands(service, provider, contexts)
	me := &consolehttp.MeHandler{Verifier: provider, Tenancy: contexts, Sessions: sessions}
	commands := consolehttp.NewSessions(&authentication.SessionLifecycle{Sessions: sessions, Store: store, OIDC: provider, Random: rand.Reader})
	stopCleanup := store.StartSessionCleanup(context.Background())
	return bootstrap.Handler(consolehttp.New(service).Register, management.Register, me.Register, commands.Register, protectedCommands.Register), func() { stopCleanup(); closePools() }, nil
}

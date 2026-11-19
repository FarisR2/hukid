package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"hukid.local/platform/internal/adapters/audithttp"
	"log/slog"
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
	if err := validateIssuanceRuntimeConfiguration(); err != nil {
		return nil, err
	}
	if err := validateOID4VPRuntimeConfiguration(); err != nil {
		return nil, err
	}
	dashboardConfig, dashboardErr := loadDashboardConfiguration()
	if dashboardConfig != nil {
		clear(dashboardConfig.Key)
	}
	if dashboardErr != nil {
		return nil, dashboardErr
	}
	memberConfig, memberErr := loadDirectoryConfiguration()
	if memberConfig != nil {
		clear(memberConfig.Key)
	}
	if memberErr != nil {
		return nil, memberErr
	}
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
	if path == "" || !authentication.SupportedEnvironment(environment) {
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
	var cleanups []func()
	cleanupAll := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}
	var labRoutes []func(*http.ServeMux)
	lab, err := configureOID4VPLab(os.Stdout, time.Now)
	if err != nil {
		return nil, nil, err
	}
	if lab != nil {
		labRoutes = append(labRoutes, lab)
	}
	vciLab, vciCleanup, err := configureOID4VCILab(ctx, address, os.Stdout, time.Now)
	if err != nil {
		cleanupAll()
		return nil, nil, err
	}
	if vciCleanup != nil {
		cleanups = append(cleanups, vciCleanup)
	}
	if vciLab != nil {
		labRoutes = append(labRoutes, vciLab)
	}
	vpRuntime, err := configureOID4VPRuntime(os.Stdout, time.Now)
	if err != nil {
		cleanupAll()
		return nil, nil, err
	}
	if vpRuntime != nil {
		labRoutes = append(labRoutes, vpRuntime)
	}
	if config == nil {
		vciRuntime, vciRuntimeCleanup, err := configureIssuanceRuntime(ctx, nil, nil, time.Now)
		if err != nil {
			cleanupAll()
			return nil, nil, err
		}
		if vciRuntimeCleanup != nil {
			cleanups = append(cleanups, vciRuntimeCleanup)
		}
		if vciRuntime != nil {
			labRoutes = append(labRoutes, vciRuntime)
		}
		return bootstrap.Handler(labRoutes...), cleanupAll, nil
	}
	defer clear(config.key)
	// A local Vite proxy can own the browser origin. This is explicit config,
	// never a forwarded/request header; policy validation still confines it to loopback.
	if config.policy.ConsoleOrigin != "http://"+address && os.Getenv("HUKID_CONSOLE_PROXY_ORIGIN") != config.policy.ConsoleOrigin {
		cleanupAll()
		return nil, nil, errors.New("auth origin must match the explicit listener")
	}
	box, err := secretbox.New(config.key, config.keyVersion, rand.Reader)
	if err != nil {
		cleanupAll()
		return nil, nil, authentication.ErrDependency
	}
	pool, err := postgres.OpenRuntimePool(ctx, config.dsn, "hukid_session_runtime", 4)
	if err != nil {
		cleanupAll()
		return nil, nil, authentication.ErrDependency
	}
	discovery, err := postgres.OpenRuntimePool(ctx, config.contextDSN, "hukid_context_runtime", 4)
	if err != nil {
		pool.Close()
		cleanupAll()
		return nil, nil, authentication.ErrDependency
	}
	tenant, err := postgres.OpenRuntimePool(ctx, config.tenantDSN, "hukid_tenant_runtime", 4)
	if err != nil {
		discovery.Close()
		pool.Close()
		cleanupAll()
		return nil, nil, authentication.ErrDependency
	}
	closePools := func() { tenant.Close(); discovery.Close(); pool.Close(); cleanupAll() }
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
	sessions := &authentication.SessionService{Store: store, Contexts: contexts, Cipher: box, Policy: config.policy, Now: time.Now}
	service.Sessions = sessions
	service.Reauthentication = store
	protectedCommands := consolehttp.NewCommands(service, provider, contexts)
	me := &consolehttp.MeHandler{Verifier: provider, Tenancy: contexts, Sessions: sessions}
	registerDirectory, closeDirectory, err := configureDirectory(ctx, management, me)
	if err != nil {
		closePools()
		return nil, nil, err
	}
	registerDashboard, closeDashboard, err := configureDashboard(ctx, management, me)
	if err != nil {
		closeDirectory()
		closePools()
		return nil, nil, err
	}
	vciRuntime, vciRuntimeCleanup, err := configureIssuanceRuntime(ctx, management, me, time.Now)
	if err != nil {
		closeDashboard()
		closeDirectory()
		closePools()
		return nil, nil, err
	}
	if vciRuntimeCleanup != nil {
		cleanups = append(cleanups, vciRuntimeCleanup)
	}
	if vciRuntime != nil {
		labRoutes = append(labRoutes, vciRuntime)
	}
	settings := &consolehttp.SettingsHandler{Auth: me, IssuanceRuntimeEnabled: vciRuntime != nil}
	commands := consolehttp.NewSessions(&authentication.SessionLifecycle{Sessions: sessions, Store: store, OIDC: provider, Random: rand.Reader})
	stopCleanup := store.StartSessionCleanup(context.Background())
	return audithttp.Wrap(bootstrap.Handler(append([]func(*http.ServeMux){consolehttp.New(service).Register, management.Register, me.Register, settings.Register, commands.Register, protectedCommands.Register, registerDirectory, registerDashboard}, labRoutes...)...), store, slog.Default()), func() { stopCleanup(); closeDashboard(); closeDirectory(); closePools() }, nil
}

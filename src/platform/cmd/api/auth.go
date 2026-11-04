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
	"hukid.local/platform/internal/adapters/secretbox"
	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/bootstrap"
)

type authConfig struct {
	policy                        authentication.Policy
	dsn, clientSecret, keyVersion string
	key                           []byte
}

func loadAuthConfiguration() (*authConfig, error) {
	path, environment := os.Getenv("HUKID_AUTH_POLICY"), os.Getenv("HUKID_ENV")
	values := []string{os.Getenv("HUKID_SESSION_DATABASE_URL"), os.Getenv("HUKID_OIDC_CLIENT_SECRET"), os.Getenv("HUKID_AUTH_KEY"), os.Getenv("HUKID_AUTH_KEY_VERSION")}
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
	if postgres.ValidateLoginDatabase(values[0]) != nil {
		return nil, invalid
	}
	return &authConfig{p, values[0], values[1], values[3], key}, nil
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
	if config.policy.ConsoleOrigin != "http://"+address {
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
	provider, err := oidc.New(ctx, config.policy, config.clientSecret, time.Now)
	if err != nil {
		pool.Close()
		return nil, nil, authentication.ErrDependency
	}
	service := &authentication.LoginService{Policy: config.policy, OIDC: provider, Store: &postgres.LoginStore{Pool: pool}, Cipher: box, Now: time.Now, Random: rand.Reader}
	return bootstrap.Handler(consolehttp.New(service).Register), pool.Close, nil
}

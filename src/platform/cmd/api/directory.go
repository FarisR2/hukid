package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	consolehttp "hukid.local/platform/internal/adapters/console"
	"hukid.local/platform/internal/adapters/memberconfig"
	"hukid.local/platform/internal/adapters/postgres"
	"hukid.local/platform/internal/adapters/privateapi"
	"hukid.local/platform/internal/adapters/secretbox"
	"hukid.local/platform/internal/tenancy"
	"net/http"
	"os"
	"time"
)

type directoryConfig struct {
	DSN    string
	Key    []byte
	Policy tenancy.MembershipPolicy
}

func loadDirectoryConfiguration() (*directoryConfig, error) {
	secrets, secretErr := memberconfig.Load()
	defer secrets.Clear()
	if secretErr != nil {
		return nil, secretErr
	}
	dsn, path, raw := os.Getenv("HUKID_MEMBERS_DATABASE_URL"), os.Getenv("HUKID_MEMBERS_POLICY"), os.Getenv("HUKID_MEMBERS_CURSOR_KEY")
	if dsn == "" && path == "" && raw == "" {
		if secrets != nil {
			return nil, errors.New("members configuration required for invitations")
		}
		return nil, nil
	}
	invalid := errors.New("complete isolated members configuration required")
	if dsn == "" || path == "" || raw == "" || os.Getenv("HUKID_ENV") != "test" || os.Getenv("HUKID_AUTH_POLICY") == "" || postgres.ValidateLoginDatabase(dsn) != nil {
		return nil, invalid
	}
	key, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, invalid
	}
	file, err := os.Open(path)
	if err != nil {
		clear(key)
		return nil, invalid
	}
	defer file.Close()
	policy, err := tenancy.LoadMembershipPolicy(file, "test")
	if err != nil {
		clear(key)
		return nil, invalid
	}
	return &directoryConfig{DSN: dsn, Key: key, Policy: policy}, nil
}
func configureDirectory(ctx context.Context, operators *privateapi.Handler, me *consolehttp.MeHandler) (func(*http.ServeMux), func(), error) {
	config, err := loadDirectoryConfiguration()
	if err != nil {
		return nil, nil, err
	}
	if config == nil {
		return func(*http.ServeMux) {}, func() {}, nil
	}
	defer clear(config.Key)
	pool, err := postgres.OpenRuntimePool(ctx, config.DSN, "hukid_members_runtime", 4)
	if err != nil {
		return nil, nil, err
	}
	directory, err := tenancy.NewDirectory(&postgres.DirectoryStore{Pool: pool}, config.Key, config.Policy, time.Now)
	if err != nil {
		pool.Close()
		return nil, nil, err
	}
	management := &privateapi.DirectoryHandler{Operators: operators, Directory: directory}
	browser := &consolehttp.DirectoryHandler{Auth: me, Management: management}
	secrets, err := memberconfig.Load()
	if err != nil {
		pool.Close()
		return nil, nil, err
	}
	if secrets == nil {
		return func(mux *http.ServeMux) { management.Register(mux); browser.Register(mux) }, pool.Close, nil
	}
	defer secrets.Clear()
	box, err := secretbox.New(secrets.Key, secrets.Version, rand.Reader)
	if err != nil {
		pool.Close()
		return nil, nil, err
	}
	verifier, ok := operators.Verifier.(privateapi.InvitationVerifier)
	if !ok {
		pool.Close()
		return nil, nil, errors.New("invitation verifier unavailable")
	}
	store := &postgres.InvitationStore{Pool: pool, Now: time.Now, Policy: config.Policy}
	service := &tenancy.InvitationService{Store: store, Cipher: box, HMACKey: append([]byte(nil), secrets.HMAC...), Random: rand.Reader, Policy: config.Policy}
	acceptance := &tenancy.AcceptanceService{Store: store, Policy: config.Policy, HMACKey: service.HMACKey, Now: time.Now}
	writes := &privateapi.InvitationHandler{Operators: operators, Verifier: verifier, Service: service, Acceptance: acceptance, Recipients: me.Sessions}
	bff := &consolehttp.InvitationHandler{Auth: me, Management: writes}
	return func(mux *http.ServeMux) {
		management.Register(mux)
		browser.Register(mux)
		writes.Register(mux)
		bff.Register(mux)
	}, func() { clear(service.HMACKey); pool.Close() }, nil
}

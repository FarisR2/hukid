package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"hukid.local/platform/internal/adapters/oid4vphttp"
	"hukid.local/platform/internal/adapters/postgres"
	"hukid.local/platform/internal/adapters/privateapi"
	"hukid.local/platform/internal/adapters/secretbox"
	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/oid4vp"
	"hukid.local/platform/internal/verification"
)

// The per-tenant verification mount (FEAT-004, VER-T11-d3, ADR-0033 and
// ADR-0034). It is off unless every variable is set, and it needs the console
// authentication configuration because operators start sessions with their
// console token. It does not coexist with the OpenID4VP laboratory mount: both
// serve the same wallet-facing paths.
//
// Variables (all required once any is set):
//
//	HUKID_VERIFICATION_DATABASE_URL  login in the hukid_verification_runtime group
//	HUKID_VERIFICATION_KEY           base64, 32 bytes: master key that seals tenant signing keys
//	HUKID_VERIFICATION_KEY_VERSION   label of that master key (at most 128 characters)
//	HUKID_VERIFICATION_ISSUER_KEYS   JSON file [{"issuer","kid","jwk"}] with P-256 public keys;
//	                                 an interim source until the JWKS resolver (VER-T12) is mounted
const (
	verificationDatabase = "HUKID_VERIFICATION_DATABASE_URL"
	verificationKey      = "HUKID_VERIFICATION_KEY"
	verificationVersion  = "HUKID_VERIFICATION_KEY_VERSION"
	verificationIssuers  = "HUKID_VERIFICATION_ISSUER_KEYS"
)

var errVerificationConfig = errors.New("complete isolated verification configuration is required")

type verificationConfig struct {
	DSN, KeyVersion, IssuerKeysPath string
	Key                             []byte
}

func loadVerificationConfiguration() (*verificationConfig, error) {
	dsn, raw, version, issuers := os.Getenv(verificationDatabase), os.Getenv(verificationKey), os.Getenv(verificationVersion), os.Getenv(verificationIssuers)
	if dsn == "" && raw == "" && version == "" && issuers == "" {
		return nil, nil
	}
	if dsn == "" || raw == "" || version == "" || issuers == "" || len(version) > 128 ||
		!authentication.SupportedEnvironment(os.Getenv("HUKID_ENV")) || os.Getenv("HUKID_AUTH_POLICY") == "" ||
		postgres.ValidateLoginDatabase(dsn) != nil {
		return nil, errVerificationConfig
	}
	key, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, errVerificationConfig
	}
	return &verificationConfig{DSN: dsn, KeyVersion: version, IssuerKeysPath: issuers, Key: key}, nil
}

// tenantVerifiers hands out one verifier per tenant over a shared base, each
// with its own replay scope, so a presentation consumed for one tenant is
// unknown to the others (ADR-0033 #4). The tenant always comes from the
// persisted session, never from the wallet.
type tenantVerifiers struct {
	mu       sync.Mutex
	base     *verification.Verifier
	pool     *pgxpool.Pool
	byTenant map[string]*verification.Verifier
}

func (t *tenantVerifiers) For(tenant string) (*verification.Verifier, error) {
	if tenant == "" {
		return nil, oid4vp.ErrConfig
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if verifier, ok := t.byTenant[tenant]; ok {
		return verifier, nil
	}
	store, err := postgres.NewReplayStore(t.pool, tenant, oid4vp.MaxTTL, oid4vp.DefaultStoreCapacity)
	if err != nil {
		return nil, err
	}
	verifier := t.base.WithReplayStore(store)
	t.byTenant[tenant] = verifier
	return verifier, nil
}

// configureVerification returns the routes of the per-tenant verification
// mount, or a no-op when it is not configured.
func configureVerification(ctx context.Context, operators *privateapi.Handler, labEnabled bool) (func(*http.ServeMux), func(), error) {
	config, err := loadVerificationConfiguration()
	if err != nil {
		return nil, nil, err
	}
	if config == nil {
		return func(*http.ServeMux) {}, func() {}, nil
	}
	defer clear(config.Key)
	if labEnabled {
		return nil, nil, errors.New("the oid4vp laboratory mount and the tenant verification mount are mutually exclusive")
	}
	invitations, ok := operators.Verifier.(privateapi.InvitationVerifier)
	if !ok {
		return nil, nil, errors.New("step-up verifier unavailable")
	}
	box, err := secretbox.New(config.Key, config.KeyVersion, rand.Reader)
	if err != nil {
		return nil, nil, errVerificationConfig
	}
	issuerKeys, err := loadLabIssuerKeys(config.IssuerKeysPath)
	if err != nil {
		return nil, nil, errVerificationConfig
	}
	base, err := verification.NewVerifier(issuerKeys, verification.ClockFunc(time.Now), verification.DefaultLimits, 0)
	if err != nil {
		return nil, nil, errVerificationConfig
	}
	pool, err := postgres.OpenRuntimePool(ctx, config.DSN, "hukid_verification_runtime", 4)
	if err != nil {
		return nil, nil, authentication.ErrDependency
	}
	sessions, err := oid4vp.NewSessionStore(oid4vp.DefaultStoreCapacity, time.Now)
	if err != nil {
		pool.Close()
		return nil, nil, errVerificationConfig
	}
	starts := &privateapi.VerificationHandler{
		Operators: operators,
		Verifier:  invitations,
		Starter:   &postgres.VerificationStartStore{Pool: pool},
		Sessions:  sessions,
		Now:       time.Now,
	}
	verifiers := &tenantVerifiers{base: base, pool: pool, byTenant: map[string]*verification.Verifier{}}
	wallet := &oid4vphttp.Handler{
		Sessions:    sessions,
		VerifierFor: verifiers.For,
		Results:     &postgres.VerificationResultStore{Pool: pool},
		Keys:        &postgres.VerifierKeyStore{Pool: pool, Cipher: box},
		Now:         time.Now,
	}
	return func(mux *http.ServeMux) { starts.Register(mux); wallet.Routes(mux) }, pool.Close, nil
}

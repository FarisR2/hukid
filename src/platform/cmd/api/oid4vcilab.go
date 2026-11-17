package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"hukid.local/platform/internal/adapters/oid4vcihttp"
	"hukid.local/platform/internal/adapters/postgres"
	"hukid.local/platform/internal/issuance"
)

// The OpenID4VCI laboratory mount exposes the Phase 1–3 credential issuer
// endpoints in cmd/api so Events, curl, Postman or wallets can exercise real
// issuance flows. It is off unless explicitly enabled via HUKID_OID4VCI_LAB=local|test
// and refuses staging/production environments.
const (
	vciLabFlag         = "HUKID_OID4VCI_LAB"
	vciLabSlug         = "HUKID_OID4VCI_LAB_SLUG"
	vciLabDisplayName  = "HUKID_OID4VCI_LAB_DISPLAY_NAME"
	vciLabKID          = "HUKID_OID4VCI_LAB_KID"
	vciLabSigningKey   = "HUKID_OID4VCI_LAB_SIGNING_KEY"
	vciLabCreateKey    = "HUKID_OID4VCI_LAB_CREATE_KEY"
	vciLabClaimsKey    = "HUKID_OID4VCI_LAB_CLAIMS_KEY"
	vciLabAuthServer   = "HUKID_OID4VCI_LAB_AUTH_SERVER"
	vciLabClientID     = "HUKID_OID4VCI_LAB_CLIENT_ID"
	vciLabClientSecret = "HUKID_OID4VCI_LAB_CLIENT_SECRET"
	vciLabDatabaseURL  = "HUKID_OID4VCI_LAB_DATABASE_URL"

	vciLabMaxPEMFile       = 64 << 10
	vciLabDefaultIssuerID  = "11111111-1111-4111-8111-111111111111"
	vciLabDefaultTenantID  = "00000000-0000-4000-8000-000000000001"
	vciLabDefaultClientID  = "33333333-3333-4333-8333-333333333333"
	vciLabDefaultKID       = "unas-key-1"
	vciLabDefaultSlug      = "unas"
	vciLabDefaultDisplay   = "IncubaUNAS"
	vciLabClaimsKeyVersion = "vci-lab-1"
)

var errVCILabConfig = errors.New("complete oid4vci laboratory configuration is required (test or local only)")

func anyVCILabEnvSet() bool {
	for _, key := range []string{
		vciLabFlag, vciLabSlug, vciLabDisplayName, vciLabKID,
		vciLabSigningKey, vciLabCreateKey, vciLabClaimsKey,
		vciLabAuthServer, vciLabClientID, vciLabClientSecret, vciLabDatabaseURL,
	} {
		if os.Getenv(key) != "" {
			return true
		}
	}
	return false
}

func loadOrCreatePersistentP256Key(path string, allowCreate bool) (*ecdsa.PrivateKey, error) {
	if path == "" {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	f, err := os.Open(path)
	if err == nil {
		defer f.Close()
		data, readErr := io.ReadAll(io.LimitReader(f, vciLabMaxPEMFile+1))
		if len(data) > 0 {
			defer clear(data)
		}
		if readErr != nil || len(data) > vciLabMaxPEMFile {
			return nil, errVCILabConfig
		}
		key, parseErr := issuance.ParseP256PrivateKeyPKCS8PEM(data)
		if parseErr != nil {
			return nil, errVCILabConfig
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) || !allowCreate {
		return nil, errVCILabConfig
	}
	key, genErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if genErr != nil {
		return nil, errVCILabConfig
	}
	pemBytes, marshalErr := issuance.MarshalP256PrivateKeyPKCS8PEM(key)
	if marshalErr != nil {
		return nil, errVCILabConfig
	}
	defer clear(pemBytes)

	out, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if openErr != nil {
		return nil, errVCILabConfig
	}
	_, writeErr := out.Write(pemBytes)
	closeErr := out.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return nil, errVCILabConfig
	}
	return key, nil
}

func parseLabClaimsKey(raw string, required bool) ([]byte, error) {
	if raw == "" {
		if required {
			return nil, errVCILabConfig
		}
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, errVCILabConfig
		}
		return key, nil
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil || len(decoded) != 32 {
		if len(decoded) > 0 {
			clear(decoded)
		}
		return nil, errVCILabConfig
	}
	return decoded, nil
}

func resolveLabAuthServer(address, configured string) (string, error) {
	if configured == "" {
		if address != "" {
			return "http://" + address, nil
		}
		return issuance.AuthorizationServerURL, nil
	}
	u, err := url.Parse(configured)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", errVCILabConfig
	}
	return strings.TrimRight(configured, "/"), nil
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// configureOID4VCILab mounts the public JWKS, OID4VCI metadata, Integration API
// and OID4VCI wallet endpoints when HUKID_OID4VCI_LAB=local|test.
func configureOID4VCILab(ctx context.Context, address string, out io.Writer, now func() time.Time) (func(*http.ServeMux), func(), error) {
	if !anyVCILabEnvSet() {
		return nil, nil, nil
	}
	enabled := os.Getenv(vciLabFlag)
	if enabled != "local" && enabled != "test" {
		return nil, nil, errVCILabConfig
	}
	if environment := os.Getenv("HUKID_ENV"); environment != "" && environment != enabled {
		return nil, nil, errVCILabConfig
	}
	if now == nil {
		now = time.Now
	}

	slug := defaultString(os.Getenv(vciLabSlug), vciLabDefaultSlug)
	if issuance.ValidateIssuerIdentifier(issuance.IssuerPrefix+slug) != nil || issuance.ReservedSlug(slug) {
		return nil, nil, errVCILabConfig
	}
	displayName := defaultString(os.Getenv(vciLabDisplayName), vciLabDefaultDisplay)
	if strings.TrimSpace(displayName) == "" || len(displayName) > 200 {
		return nil, nil, errVCILabConfig
	}
	kid := defaultString(os.Getenv(vciLabKID), vciLabDefaultKID)
	if kid == "" || len(kid) > 128 || strings.ContainsAny(kid, " \t\r\n") {
		return nil, nil, errVCILabConfig
	}
	authServer, err := resolveLabAuthServer(address, os.Getenv(vciLabAuthServer))
	if err != nil {
		return nil, nil, err
	}

	dsn := os.Getenv(vciLabDatabaseURL)
	usePostgres := dsn != ""
	keyPath := os.Getenv(vciLabSigningKey)
	if usePostgres && keyPath == "" {
		return nil, nil, errVCILabConfig
	}
	allowCreateKey := os.Getenv(vciLabCreateKey) == "1"
	privKey, err := loadOrCreatePersistentP256Key(keyPath, allowCreateKey)
	if err != nil {
		return nil, nil, err
	}

	claimsKey, err := parseLabClaimsKey(os.Getenv(vciLabClaimsKey), usePostgres)
	if err != nil {
		return nil, nil, err
	}
	defer clear(claimsKey)

	issuerURI := issuance.IssuerPrefix + slug
	pubJWK, err := issuance.ExportPublicJWK(&privKey.PublicKey, kid)
	if err != nil {
		return nil, nil, errVCILabConfig
	}
	jwkBytes, err := json.Marshal(pubJWK)
	if err != nil {
		return nil, nil, errVCILabConfig
	}

	var svc *issuance.Service
	var pool *pgxpool.Pool
	cleanup := func() {
		if pool != nil {
			pool.Close()
		}
	}

	if usePostgres {
		if postgres.ValidateLoginDatabase(dsn) != nil {
			return nil, nil, errVCILabConfig
		}
		pool, err = postgres.OpenRuntimePool(ctx, dsn, "hukid_issuance_runtime", 4)
		if err != nil {
			return nil, nil, errVCILabConfig
		}
		backend, err := postgres.NewIssuanceBackend(pool)
		if err != nil {
			cleanup()
			return nil, nil, errVCILabConfig
		}
		signers := func(_, _, resolvedIssuerURI, resolvedKID, _ string, expectedPub *ecdsa.PublicKey) (issuance.Signer, error) {
			if resolvedIssuerURI != issuerURI || resolvedKID != kid || expectedPub == nil || !expectedPub.Equal(&privKey.PublicKey) {
				return nil, issuance.ErrNoActiveKey
			}
			return issuance.NewMemorySigner(resolvedIssuerURI, resolvedKID, privKey, rand.Reader)
		}
		svc, err = issuance.NewService(issuance.ServiceConfig{
			ClaimsKey:           claimsKey,
			ClaimsKeyVersion:    vciLabClaimsKeyVersion,
			Backend:             backend,
			Signers:             signers,
			AuthorizationServer: authServer,
			Now:                 now,
			Random:              rand.Reader,
		})
		if err != nil {
			cleanup()
			return nil, nil, errVCILabConfig
		}
		fmt.Fprintf(out, "oid4vci-lab mode postgres\n")
		fmt.Fprintf(out, "oid4vci-lab issuer-uri %s\n", issuerURI)
		fmt.Fprintf(out, "oid4vci-lab jwks-path /%s/.well-known/jwks.json\n", slug)
		fmt.Fprintf(out, "oid4vci-lab metadata-path /%s/.well-known/openid-credential-issuer\n", slug)
		fmt.Fprintf(out, "oid4vci-lab kid %s\n", kid)
		fmt.Fprintf(out, "oid4vci-lab public-jwk %s\n", jwkBytes)
	} else {
		clientID := defaultString(os.Getenv(vciLabClientID), vciLabDefaultClientID)
		clientSecret := os.Getenv(vciLabClientSecret)
		generatedSecret := false
		if clientSecret == "" {
			buf := make([]byte, 24)
			if _, err := io.ReadFull(rand.Reader, buf); err != nil {
				return nil, nil, errVCILabConfig
			}
			clientSecret = base64.RawURLEncoding.EncodeToString(buf)
			generatedSecret = true
		} else if len(clientSecret) < 16 {
			return nil, nil, errVCILabConfig
		}

		seedTime := now().UTC()
		audit := issuance.NewAuditLog(rand.Reader)
		clients := issuance.NewClientRegistry(audit)
		defs := issuance.NewDefinitionRegistry(audit)
		issuerRec, err := issuance.NewIssuerRecord(vciLabDefaultTenantID, vciLabDefaultIssuerID, slug, displayName, seedTime)
		if err != nil {
			return nil, nil, errVCILabConfig
		}
		ring, err := issuance.NewKeyRing(vciLabDefaultTenantID, issuerURI, audit)
		if err != nil {
			return nil, nil, errVCILabConfig
		}
		if err := ring.RegisterKey(kid, privKey, "vci-lab-seed", "cor-seed-k1", seedTime); err != nil {
			return nil, nil, errVCILabConfig
		}
		certDef := issuance.Definition{
			TenantID:        vciLabDefaultTenantID,
			IssuerID:        vciLabDefaultIssuerID,
			ID:              "unas-certificate",
			Version:         "1.0.0",
			ConfigurationID: issuance.CertificateConfigID,
			DisplayName:     "Certificado de Asistencia UNAS",
			Locale:          "es-PE",
			Contexts:        []string{issuance.CertificateContext},
			Types:           []string{issuance.CertificateType},
			DefaultValidity: 365 * 24 * time.Hour,
			StatusPurposes:  []string{issuance.PurposeRevocation, issuance.PurposeSuspension},
			PublishSchema:   true,
			Fields: map[string]issuance.FieldSpec{
				"participantName": {Type: "string", Required: true, MaxLength: 120},
				"eventName":       {Type: "string", Required: true, MaxLength: 160},
				"role":            {Type: "string", Required: false, MaxLength: 60},
			},
		}
		if err := defs.CreateDraft(certDef, "vci-lab-seed", "cor-seed-d1", seedTime); err != nil {
			return nil, nil, errVCILabConfig
		}
		if _, err := defs.Publish(vciLabDefaultTenantID, vciLabDefaultIssuerID, certDef.ID, certDef.Version, "vci-lab-seed", "cor-seed-d2", seedTime); err != nil {
			return nil, nil, errVCILabConfig
		}
		if err := clients.RegisterClient(
			vciLabDefaultTenantID,
			clientID,
			"Lab Events Client",
			clientSecret,
			[]string{vciLabDefaultIssuerID},
			[]string{issuance.ScopeIssuanceCreate, issuance.ScopeIssuanceRead, issuance.ScopeStatusWrite},
			nil,
			"vci-lab-seed",
			"cor-seed-c1",
			seedTime,
		); err != nil {
			return nil, nil, errVCILabConfig
		}
		svc, err = issuance.NewService(issuance.ServiceConfig{
			ClaimsKey:           claimsKey,
			ClaimsKeyVersion:    vciLabClaimsKeyVersion,
			Clients:             clients,
			Definitions:         defs,
			Audit:               audit,
			AuthorizationServer: authServer,
			Now:                 now,
			Random:              rand.Reader,
		})
		if err != nil {
			return nil, nil, errVCILabConfig
		}
		if err := svc.RegisterIssuer(issuerRec, ring); err != nil {
			return nil, nil, errVCILabConfig
		}

		fmt.Fprintf(out, "oid4vci-lab mode memory\n")
		fmt.Fprintf(out, "oid4vci-lab issuer-uri %s\n", issuerURI)
		fmt.Fprintf(out, "oid4vci-lab issuer-id %s\n", vciLabDefaultIssuerID)
		fmt.Fprintf(out, "oid4vci-lab jwks-path /%s/.well-known/jwks.json\n", slug)
		fmt.Fprintf(out, "oid4vci-lab metadata-path /%s/.well-known/openid-credential-issuer\n", slug)
		fmt.Fprintf(out, "oid4vci-lab kid %s\n", kid)
		fmt.Fprintf(out, "oid4vci-lab public-jwk %s\n", jwkBytes)
		fmt.Fprintf(out, "oid4vci-lab definition %s\n", certDef.Ref())
		fmt.Fprintf(out, "oid4vci-lab client-id %s\n", clientID)
		if generatedSecret {
			fmt.Fprintf(out, "oid4vci-lab client-secret %s\n", clientSecret)
		}
	}

	discovery := &oid4vcihttp.Handler{Catalog: svc}
	endpoints := &oid4vcihttp.IssuanceHandler{Service: svc}
	routes := func(mux *http.ServeMux) {
		discovery.Routes(mux)
		endpoints.Routes(mux)
	}
	return routes, cleanup, nil
}

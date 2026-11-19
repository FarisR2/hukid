package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"hukid.local/platform/internal/issuance"
)

const issuanceQueryTimeout = 5 * time.Second

// IssuanceBackend implements issuance.Backend on PostgreSQL 18.6 using
// hukid_issuance_runtime, FORCE RLS tenant isolation, row-level locks for
// single-use redemption and SECURITY DEFINER locator functions for public lookups.
type IssuanceBackend struct {
	pool *pgxpool.Pool
}

// NewIssuanceBackend constructs a PostgreSQL-backed issuance store. The pool
// must belong to hukid_issuance_runtime (opened via OpenRuntimePool).
func NewIssuanceBackend(pool *pgxpool.Pool) (*IssuanceBackend, error) {
	if pool == nil {
		return nil, issuance.ErrInvalidFoundationInput
	}
	return &IssuanceBackend{pool: pool}, nil
}

// TryWithTenantAdvisoryLock acquires a non-blocking session advisory lock scoped
// to namespace and tenantID, executes fn while holding it, and releases it before
// returning the connection to the pool.
func TryWithTenantAdvisoryLock(ctx context.Context, pool *pgxpool.Pool, namespace, tenantID string, fn func() error) (bool, error) {
	if pool == nil || strings.TrimSpace(namespace) == "" || strings.TrimSpace(tenantID) == "" || fn == nil {
		return false, errors.New("invalid advisory lock arguments")
	}
	sum := sha256.Sum256([]byte(namespace + "|" + tenantID))
	lockKey := int64(binary.BigEndian.Uint64(sum[:8]))

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Release()

	var acquired bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", lockKey).Scan(&acquired); err != nil {
		return false, err
	}
	if !acquired {
		return false, nil
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", lockKey)
	}()
	return true, fn()
}

func (b *IssuanceBackend) opCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), issuanceQueryTimeout)
}

func newPostgresAuditEvent(tenantID, actorID, action, targetID, outcome, correlationID string, occurredAt time.Time) issuance.AuditRecord {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	if strings.TrimSpace(actorID) == "" {
		actorID = "system"
	}
	return issuance.AuditRecord{
		EventID:       "evt_" + base64.RawURLEncoding.EncodeToString(buf),
		TenantID:      tenantID,
		ActorID:       actorID,
		Action:        action,
		TargetID:      targetID,
		Outcome:       outcome,
		CorrelationID: correlationID,
		OccurredAt:    occurredAt.UTC(),
	}
}

func appendPostgresAudit(ctx context.Context, tx pgx.Tx, rec issuance.AuditRecord) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO issuance.audit_events(event_id,tenant_id,actor_id,action,target_id,outcome,correlation_id,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		rec.EventID, rec.TenantID, rec.ActorID, rec.Action, rec.TargetID, rec.Outcome, rec.CorrelationID, rec.OccurredAt.UTC())
	return err
}

func (b *IssuanceBackend) locateUUID(query string, arg any) (string, bool, error) {
	ctx, cancel := b.opCtx()
	defer cancel()
	var id pgtype.UUID
	err := withUnscopedTx(ctx, b.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, arg).Scan(&id)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !id.Valid {
		return "", false, nil
	}
	return id.String(), true, nil
}

// ResolveTenantBySlug resolves owning tenant_id for a public issuer slug.
func (b *IssuanceBackend) ResolveTenantBySlug(slug string) (string, bool, error) {
	if slug == "" {
		return "", false, nil
	}
	return b.locateUUID(`SELECT issuance.locate_issuer_by_slug($1)`, slug)
}

// ResolveTenantByClient resolves owning tenant_id for an M2M client_id UUID.
func (b *IssuanceBackend) ResolveTenantByClient(clientID string) (string, bool, error) {
	if !validID(clientID) {
		return "", false, nil
	}
	return b.locateUUID(`SELECT issuance.locate_client($1)`, clientID)
}

// ResolveTenantByOfferCode resolves owning tenant_id from a hashed pre-authorized code.
func (b *IssuanceBackend) ResolveTenantByOfferCode(codeHash [32]byte) (string, bool, error) {
	return b.locateUUID(`SELECT issuance.locate_offer($1)`, codeHash[:])
}

// ResolveTenantByToken resolves owning tenant_id from a hashed bearer token.
func (b *IssuanceBackend) ResolveTenantByToken(tokenHash [32]byte) (string, bool, error) {
	return b.locateUUID(`SELECT issuance.locate_token($1)`, tokenHash[:])
}

// WithTenantTx opens a FORCE RLS transaction scoped to tenantID.
func (b *IssuanceBackend) WithTenantTx(tenantID string, fn func(issuance.Tx) error) error {
	ctx, cancel := b.opCtx()
	defer cancel()
	return WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
		return fn(&postgresIssuanceTx{ctx: ctx, tx: tx, tenantID: tenantID})
	})
}

type postgresIssuanceTx struct {
	ctx      context.Context
	tx       pgx.Tx
	tenantID string
}

func (t *postgresIssuanceTx) GetIssuerByID(issuerID string) (issuance.IssuerRecord, bool, error) {
	if !validID(issuerID) {
		return issuance.IssuerRecord{}, false, nil
	}
	return t.scanIssuer(`SELECT tenant_id::text,issuer_id::text,slug,issuer_uri,display_name,state,created_at FROM tenancy.issuers WHERE issuer_id=$1`, issuerID)
}

func (t *postgresIssuanceTx) GetIssuerBySlug(slug string) (issuance.IssuerRecord, bool, error) {
	if slug == "" {
		return issuance.IssuerRecord{}, false, nil
	}
	return t.scanIssuer(`SELECT tenant_id::text,issuer_id::text,slug,issuer_uri,display_name,state,created_at FROM tenancy.issuers WHERE slug=$1`, slug)
}

func (t *postgresIssuanceTx) CreateIssuer(rec issuance.IssuerRecord, kid, kmsKeyRef string, jwk issuance.PublicJWK, actorID, correlationID string, now time.Time) error {
	return createIssuerWithKeyTx(t.ctx, t.tx, t.tenantID, rec, kid, kmsKeyRef, jwk, actorID, correlationID, now)
}

func (t *postgresIssuanceTx) ListIssuers() ([]issuance.IssuerRecord, error) {
	rows, err := t.tx.Query(t.ctx,
		`SELECT tenant_id::text,issuer_id::text,slug,issuer_uri,display_name,state,created_at
		 FROM tenancy.issuers ORDER BY created_at,issuer_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []issuance.IssuerRecord
	for rows.Next() {
		var rec issuance.IssuerRecord
		var state string
		if err := rows.Scan(&rec.TenantID, &rec.IssuerID, &rec.Slug, &rec.IssuerURI, &rec.DisplayName, &state, &rec.CreatedAt); err != nil {
			return nil, err
		}
		rec.State = issuance.IssuerState(state)
		rec.CreatedAt = rec.CreatedAt.UTC()
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (t *postgresIssuanceTx) scanIssuer(query, arg string) (issuance.IssuerRecord, bool, error) {
	var rec issuance.IssuerRecord
	var state string
	err := t.tx.QueryRow(t.ctx, query, arg).Scan(&rec.TenantID, &rec.IssuerID, &rec.Slug, &rec.IssuerURI, &rec.DisplayName, &state, &rec.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.IssuerRecord{}, false, nil
	}
	if err != nil {
		return issuance.IssuerRecord{}, false, err
	}
	rec.State = issuance.IssuerState(state)
	rec.CreatedAt = rec.CreatedAt.UTC()
	return rec, true, nil
}

func (t *postgresIssuanceTx) GetActiveKey(issuerID string) (issuance.StoredKey, error) {
	if !validID(issuerID) {
		return issuance.StoredKey{}, issuance.ErrNoActiveKey
	}
	var out issuance.StoredKey
	var alg, crv, x, y string
	err := t.tx.QueryRow(t.ctx,
		`SELECT k.kid,k.kms_key_ref,i.issuer_uri,k.alg,k.crv,k.x_coord,k.y_coord
		 FROM tenancy.issuer_keys k
		 JOIN tenancy.issuers i ON i.tenant_id=k.tenant_id AND i.issuer_id=k.issuer_id
		 WHERE k.issuer_id=$1 AND k.state='active'`, issuerID).
		Scan(&out.KID, &out.KMSKeyRef, &out.IssuerURI, &alg, &crv, &x, &y)
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.StoredKey{}, issuance.ErrNoActiveKey
	}
	if err != nil {
		return issuance.StoredKey{}, err
	}
	out.JWK = issuance.PublicJWK{Kty: "EC", Crv: crv, X: x, Y: y, Kid: out.KID, Alg: alg, Use: "sig"}
	return out, nil
}

func (t *postgresIssuanceTx) ListPublicKeys(issuerID string) ([]issuance.PublicJWK, error) {
	if !validID(issuerID) {
		return nil, issuance.ErrResourceNotFound
	}
	rows, err := t.tx.Query(t.ctx,
		`SELECT kid,alg,crv,x_coord,y_coord FROM tenancy.issuer_keys
		 WHERE issuer_id=$1 AND state IN ('active','retired')
		 ORDER BY created_at,kid`, issuerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := make([]issuance.PublicJWK, 0, 4)
	for rows.Next() {
		var kid, alg, crv, x, y string
		if err := rows.Scan(&kid, &alg, &crv, &x, &y); err != nil {
			return nil, err
		}
		keys = append(keys, issuance.PublicJWK{Kty: "EC", Crv: crv, X: x, Y: y, Kid: kid, Alg: alg, Use: "sig"})
	}
	return keys, rows.Err()
}

func (t *postgresIssuanceTx) GetClient(clientID string) (issuance.StoredClient, bool, error) {
	if !validID(clientID) {
		return issuance.StoredClient{}, false, nil
	}
	var out issuance.StoredClient
	var secretHash []byte
	var scopes, issuers []string
	var state string
	var expiresAt *time.Time
	err := t.tx.QueryRow(t.ctx,
		`SELECT c.client_id::text,c.tenant_id::text,c.secret_hash,c.scopes,c.state,c.expires_at,
		        COALESCE(ARRAY(SELECT g.issuer_id::text FROM tenancy.integration_client_grants g WHERE g.tenant_id=c.tenant_id AND g.client_id=c.client_id),'{}'::text[])
		 FROM tenancy.integration_clients c WHERE c.client_id=$1`, clientID).
		Scan(&out.ClientID, &out.TenantID, &secretHash, &scopes, &state, &expiresAt, &issuers)
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.StoredClient{}, false, nil
	}
	if err != nil {
		return issuance.StoredClient{}, false, err
	}
	if len(secretHash) != 32 {
		return issuance.StoredClient{}, false, issuance.ErrClientUnauthorized
	}
	copy(out.SecretHash[:], secretHash)
	out.State = issuance.ClientState(state)
	if expiresAt != nil {
		exp := expiresAt.UTC()
		out.ExpiresAt = &exp
	}
	out.Scopes = make(map[string]bool, len(scopes))
	for _, sc := range scopes {
		out.Scopes[sc] = true
	}
	out.AllowedIssuers = make(map[string]bool, len(issuers))
	for _, id := range issuers {
		out.AllowedIssuers[id] = true
	}
	return out, true, nil
}

func (t *postgresIssuanceTx) RegisterClient(client issuance.ClientSummary, secretHash [32]byte, actorID, correlationID string, now time.Time) error {
	return registerHashedClientTx(t.ctx, t.tx, t.tenantID, client, secretHash, actorID, correlationID, now)
}

func (t *postgresIssuanceTx) ListClients() ([]issuance.ClientSummary, error) {
	rows, err := t.tx.Query(t.ctx,
		`SELECT c.client_id::text,c.tenant_id::text,c.client_name,c.scopes,c.state,c.created_at,c.expires_at,c.revoked_at,
		        COALESCE(ARRAY(SELECT g.issuer_id::text FROM tenancy.integration_client_grants g WHERE g.tenant_id=c.tenant_id AND g.client_id=c.client_id ORDER BY g.issuer_id),'{}'::text[])
		 FROM tenancy.integration_clients c ORDER BY c.created_at,c.client_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []issuance.ClientSummary
	for rows.Next() {
		var c issuance.ClientSummary
		var state string
		var expAt, revAt *time.Time
		if err := rows.Scan(&c.ClientID, &c.TenantID, &c.ClientName, &c.Scopes, &state, &c.CreatedAt, &expAt, &revAt, &c.AllowedIssuers); err != nil {
			return nil, err
		}
		c.State = issuance.ClientState(state)
		c.CreatedAt = c.CreatedAt.UTC()
		if expAt != nil {
			t := expAt.UTC()
			c.ExpiresAt = &t
		}
		if revAt != nil {
			t := revAt.UTC()
			c.RevokedAt = &t
		}
		slices.Sort(c.Scopes)
		if c.AllowedIssuers == nil {
			c.AllowedIssuers = []string{}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (t *postgresIssuanceTx) RotateClientSecret(clientID string, newSecretHash [32]byte, actorID, correlationID string, now time.Time) error {
	return rotateClientSecretTx(t.ctx, t.tx, t.tenantID, clientID, newSecretHash, actorID, correlationID, now)
}

func (t *postgresIssuanceTx) RevokeClient(clientID, actorID, correlationID string, now time.Time) error {
	return revokeClientTx(t.ctx, t.tx, t.tenantID, clientID, actorID, correlationID, now)
}

func (t *postgresIssuanceTx) CreateDraftDefinition(def issuance.Definition, actorID, correlationID string, now time.Time) error {
	return createDraftDefinitionTx(t.ctx, t.tx, t.tenantID, def, actorID, correlationID, now)
}

func (t *postgresIssuanceTx) ReplaceDraftDefinition(def issuance.Definition, actorID, correlationID string, now time.Time) error {
	return replaceDraftDefinitionTx(t.ctx, t.tx, t.tenantID, def, actorID, correlationID, now)
}

func (t *postgresIssuanceTx) PublishDefinition(issuerID, id, version, actorID, correlationID string, now time.Time) (issuance.Definition, error) {
	return publishDefinitionTx(t.ctx, t.tx, t.tenantID, issuerID, id, version, actorID, correlationID, now)
}

func (t *postgresIssuanceTx) RetireDefinition(issuerID, id, version, actorID, correlationID string, now time.Time) (issuance.Definition, error) {
	return retireDefinitionTx(t.ctx, t.tx, t.tenantID, issuerID, id, version, actorID, correlationID, now)
}

func (t *postgresIssuanceTx) GetDefinition(issuerID, id, version string) (issuance.Definition, error) {
	return getDefinitionTx(t.ctx, t.tx, issuerID, id, version)
}

func (t *postgresIssuanceTx) ListDefinitions(issuerID string) ([]issuance.Definition, error) {
	if !validID(issuerID) {
		return nil, issuance.ErrResourceNotFound
	}
	var exists int
	if err := t.tx.QueryRow(t.ctx, `SELECT 1 FROM tenancy.issuers WHERE issuer_id=$1`, issuerID).Scan(&exists); errors.Is(err, pgx.ErrNoRows) {
		return nil, issuance.ErrResourceNotFound
	} else if err != nil {
		return nil, err
	}
	rows, err := t.tx.Query(t.ctx,
		selectDefinitionCols+` WHERE issuer_id=$1 ORDER BY definition_id,version`, issuerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []issuance.Definition
	for rows.Next() {
		d, err := scanDefinitionRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func scanDefinitionRow(row pgx.Row) (issuance.Definition, error) {
	var d issuance.Definition
	var fieldsRaw []byte
	var validitySecs int64
	var state string
	var pubAt, retAt *time.Time
	err := row.Scan(&d.TenantID, &d.IssuerID, &d.ID, &d.Version, &d.ConfigurationID,
		&d.DisplayName, &d.Locale, &d.Contexts, &d.Types, &fieldsRaw, &validitySecs,
		&d.StatusPurposes, &d.PublishSchema, &state, &d.Hash, &d.CreatedAt, &pubAt, &retAt)
	if err != nil {
		return issuance.Definition{}, err
	}
	if err := json.Unmarshal(fieldsRaw, &d.Fields); err != nil {
		return issuance.Definition{}, err
	}
	d.DefaultValidity = time.Duration(validitySecs) * time.Second
	d.State = issuance.DefinitionState(state)
	d.CreatedAt = d.CreatedAt.UTC()
	if pubAt != nil {
		t := pubAt.UTC()
		d.PublishedAt = &t
	}
	if retAt != nil {
		t := retAt.UTC()
		d.RetiredAt = &t
	}
	return d, nil
}

const selectDefinitionCols = `SELECT tenant_id::text,issuer_id::text,definition_id,version,configuration_id,display_name,locale,contexts,types,fields_json,default_validity_seconds,status_purposes,publish_schema,state,content_hash,created_at,published_at,retired_at FROM definition.definition_versions`

func (t *postgresIssuanceTx) GetPublicDefinition(issuerID, id, version string) (issuance.Definition, error) {
	if !validID(issuerID) {
		return issuance.Definition{}, issuance.ErrDefinitionNotFound
	}
	d, err := scanDefinitionRow(t.tx.QueryRow(t.ctx,
		selectDefinitionCols+` WHERE issuer_id=$1 AND definition_id=$2 AND version=$3 AND state <> 'draft'`,
		issuerID, id, version))
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.Definition{}, issuance.ErrDefinitionNotFound
	}
	return d, err
}

func (t *postgresIssuanceTx) GetIssuableDefinition(issuerID, id, version string) (issuance.Definition, error) {
	if !validID(issuerID) {
		return issuance.Definition{}, issuance.ErrDefinitionNotFound
	}
	d, err := scanDefinitionRow(t.tx.QueryRow(t.ctx,
		selectDefinitionCols+` WHERE issuer_id=$1 AND definition_id=$2 AND version=$3`,
		issuerID, id, version))
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.Definition{}, issuance.ErrDefinitionNotFound
	}
	if err != nil {
		return issuance.Definition{}, err
	}
	if d.State != issuance.DefinitionPublished {
		return issuance.Definition{}, issuance.ErrDefinitionUnavailable
	}
	return d, nil
}

func (t *postgresIssuanceTx) ListPublishedDefinitions(issuerID string) ([]issuance.Definition, error) {
	if !validID(issuerID) {
		return nil, nil
	}
	rows, err := t.tx.Query(t.ctx,
		selectDefinitionCols+` WHERE issuer_id=$1 AND state='published' ORDER BY definition_id,version`, issuerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []issuance.Definition
	for rows.Next() {
		d, err := scanDefinitionRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (t *postgresIssuanceTx) LockIdempotency(clientID string, keyHash [32]byte) (issuance.IdempotencyRecord, bool, error) {
	if !validID(clientID) {
		return issuance.IdempotencyRecord{}, false, nil
	}
	if _, err := t.tx.Exec(t.ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1||'|'||$2||'|'||encode($3,'hex'),0))`, t.tenantID, clientID, keyHash[:]); err != nil {
		return issuance.IdempotencyRecord{}, false, err
	}
	var out issuance.IdempotencyRecord
	var reqHash []byte
	err := t.tx.QueryRow(t.ctx,
		`SELECT client_id::text,request_hash,request_id,issuer_id::text,configuration_id,offer_state,issuance_state,credential_offer_uri,expires_at,created_at
		 FROM issuance.idempotency WHERE client_id=$1 AND key_hash=$2`, clientID, keyHash[:]).
		Scan(&out.ClientID, &reqHash, &out.Result.ID, &out.Result.IssuerID, &out.Result.CredentialConfigurationID,
			&out.Result.OfferState, &out.Result.IssuanceState, &out.Result.CredentialOfferURI, &out.Result.ExpiresAt, &out.Result.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.IdempotencyRecord{}, false, nil
	}
	if err != nil {
		return issuance.IdempotencyRecord{}, false, err
	}
	if len(reqHash) != 32 {
		return issuance.IdempotencyRecord{}, false, issuance.ErrInvalidRequest
	}
	out.KeyHash = keyHash
	copy(out.RequestHash[:], reqHash)
	out.Result.ExpiresAt = out.Result.ExpiresAt.UTC()
	out.Result.CreatedAt = out.Result.CreatedAt.UTC()
	return out, true, nil
}

func (t *postgresIssuanceTx) SaveIdempotency(rec issuance.IdempotencyRecord) error {
	_, err := t.tx.Exec(t.ctx,
		`INSERT INTO issuance.idempotency(tenant_id,client_id,key_hash,request_hash,request_id,issuer_id,configuration_id,offer_state,issuance_state,credential_offer_uri,expires_at,created_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		t.tenantID, rec.ClientID, rec.KeyHash[:], rec.RequestHash[:], rec.Result.ID, rec.Result.IssuerID,
		rec.Result.CredentialConfigurationID, rec.Result.OfferState, rec.Result.IssuanceState,
		rec.Result.CredentialOfferURI, rec.Result.ExpiresAt.UTC(), rec.Result.CreatedAt.UTC())
	return err
}

func (t *postgresIssuanceTx) SaveRequestAndOffer(req issuance.StoredRequest, codeHash [32]byte) error {
	var issuerURI string
	if err := t.tx.QueryRow(t.ctx, `SELECT issuer_uri FROM tenancy.issuers WHERE issuer_id=$1`, req.IssuerID).Scan(&issuerURI); err != nil {
		return issuance.ErrResourceNotFound
	}
	_, err := t.tx.Exec(t.ctx,
		`INSERT INTO issuance.issuance_requests(request_id,tenant_id,issuer_id,client_id,definition_id,definition_version,configuration_id,claims_ciphertext,claims_nonce,claims_key_version,offer_ref,offer_ciphertext,offer_nonce,offer_key_version,offer_state,issuance_state,deferred,holder_jkt,source_system,source_reference,created_at,expires_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,
		req.ID, req.TenantID, req.IssuerID, req.ClientID, req.DefID, req.DefVersion, req.ConfigID,
		req.ClaimsCipher, req.ClaimsNonce, req.ClaimsKeyVer, req.OfferRef, req.OfferCipher, req.OfferNonce, req.OfferKeyVer,
		req.OfferState, req.IssuanceState, req.Deferred, req.HolderJKT, req.SourceSystem, req.SourceReference, req.CreatedAt.UTC(), req.ExpiresAt.UTC())
	if err != nil {
		return err
	}
	_, err = t.tx.Exec(t.ctx,
		`INSERT INTO issuance.credential_offers(code_hash,tenant_id,issuer_id,issuer_uri,request_id,configuration_id,created_at,expires_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		codeHash[:], req.TenantID, req.IssuerID, issuerURI, req.ID, req.ConfigID, req.CreatedAt.UTC(), req.ExpiresAt.UTC())
	return err
}

func scanStoredRequest(row pgx.Row) (issuance.StoredRequest, bool, error) {
	var r issuance.StoredRequest
	var offerVer pgtype.Text
	err := row.Scan(&r.ID, &r.TenantID, &r.IssuerID, &r.ClientID, &r.DefID, &r.DefVersion, &r.ConfigID,
		&r.ClaimsCipher, &r.ClaimsNonce, &r.ClaimsKeyVer, &r.OfferRef, &r.OfferCipher, &r.OfferNonce, &offerVer,
		&r.OfferState, &r.IssuanceState, &r.IssuedCredentialID, &r.Deferred, &r.HolderJKT, &r.SourceSystem, &r.SourceReference, &r.CreatedAt, &r.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.StoredRequest{}, false, nil
	}
	if err != nil {
		return issuance.StoredRequest{}, false, err
	}
	r.OfferKeyVer = offerVer.String
	r.CreatedAt = r.CreatedAt.UTC()
	r.ExpiresAt = r.ExpiresAt.UTC()
	return r, true, nil
}

const selectRequestCols = `SELECT request_id,tenant_id::text,issuer_id::text,client_id::text,definition_id,definition_version,configuration_id,claims_ciphertext,claims_nonce,claims_key_version,offer_ref,offer_ciphertext,offer_nonce,offer_key_version,offer_state,issuance_state,issued_credential_id,deferred,holder_jkt,source_system,source_reference,created_at,expires_at FROM issuance.issuance_requests`

func (t *postgresIssuanceTx) GetRequestForClient(requestID, clientID string) (issuance.StoredRequest, bool, error) {
	if !validID(clientID) || requestID == "" {
		return issuance.StoredRequest{}, false, nil
	}
	return scanStoredRequest(t.tx.QueryRow(t.ctx, selectRequestCols+` WHERE request_id=$1 AND client_id=$2`, requestID, clientID))
}

func (t *postgresIssuanceTx) ListAdminRequests(filter issuance.AdminListFilter) ([]issuance.StoredRequest, error) {
	query := `SELECT request_id,tenant_id::text,issuer_id::text,client_id::text,definition_id,definition_version,configuration_id,offer_state,issuance_state,issued_credential_id,created_at,expires_at
		FROM issuance.issuance_requests`
	args := []any{}
	if filter.IssuerID != "" {
		if !validID(filter.IssuerID) {
			return nil, issuance.ErrInvalidRequest
		}
		query += ` WHERE issuer_id=$1`
		args = append(args, filter.IssuerID)
	}
	query += ` ORDER BY created_at DESC,request_id DESC LIMIT $` + strconv.Itoa(len(args)+1) + ` OFFSET $` + strconv.Itoa(len(args)+2)
	args = append(args, filter.Limit, filter.Offset)
	rows, err := t.tx.Query(t.ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]issuance.StoredRequest, 0)
	for rows.Next() {
		var r issuance.StoredRequest
		if err := rows.Scan(&r.ID, &r.TenantID, &r.IssuerID, &r.ClientID, &r.DefID, &r.DefVersion, &r.ConfigID, &r.OfferState, &r.IssuanceState, &r.IssuedCredentialID, &r.CreatedAt, &r.ExpiresAt); err != nil {
			return nil, err
		}
		r.CreatedAt, r.ExpiresAt = r.CreatedAt.UTC(), r.ExpiresAt.UTC()
		items = append(items, r)
	}
	return items, rows.Err()
}

func (t *postgresIssuanceTx) ListPendingDeferredRequestIDs(limit int, now time.Time) ([]string, error) {
	if limit < 1 || limit > 500 {
		return nil, issuance.ErrInvalidRequest
	}
	rows, err := t.tx.Query(t.ctx,
		`SELECT request_id FROM issuance.deferred_transactions
		 WHERE status='pending' AND expires_at>$1
		 ORDER BY created_at,request_id LIMIT $2
		 FOR UPDATE SKIP LOCKED`, now.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (t *postgresIssuanceTx) GetRequestByOfferRef(issuerID, ref string) (issuance.StoredRequest, bool, error) {
	if !validID(issuerID) || ref == "" {
		return issuance.StoredRequest{}, false, nil
	}
	return scanStoredRequest(t.tx.QueryRow(t.ctx, selectRequestCols+` WHERE issuer_id=$1 AND offer_ref=$2`, issuerID, ref))
}

func (t *postgresIssuanceTx) LockRequest(requestID string) (issuance.StoredRequest, bool, error) {
	if requestID == "" {
		return issuance.StoredRequest{}, false, nil
	}
	return scanStoredRequest(t.tx.QueryRow(t.ctx, selectRequestCols+` WHERE request_id=$1 FOR UPDATE`, requestID))
}

func (t *postgresIssuanceTx) RedeemOfferByCodeHash(codeHash [32]byte, now time.Time) (issuance.StoredOffer, error) {
	var out issuance.StoredOffer
	var redeemedAt, cancelledAt *time.Time
	var offerState string
	err := t.tx.QueryRow(t.ctx,
		`SELECT o.tenant_id::text,o.issuer_id::text,o.issuer_uri,o.request_id,o.configuration_id,o.expires_at,o.redeemed_at,o.cancelled_at,r.offer_state
		 FROM issuance.credential_offers o
		 JOIN issuance.issuance_requests r ON r.tenant_id=o.tenant_id AND r.request_id=o.request_id
		 WHERE o.code_hash=$1
		 FOR UPDATE`, codeHash[:]).
		Scan(&out.TenantID, &out.IssuerID, &out.IssuerURI, &out.RequestID, &out.ConfigID, &out.ExpiresAt, &redeemedAt, &cancelledAt, &offerState)
	if errors.Is(err, pgx.ErrNoRows) || err != nil {
		return issuance.StoredOffer{}, issuance.ErrOfferInvalid
	}
	nowUTC := now.UTC()
	out.ExpiresAt = out.ExpiresAt.UTC()
	if redeemedAt != nil || cancelledAt != nil || !nowUTC.Before(out.ExpiresAt) || offerState != "ready" {
		return issuance.StoredOffer{}, issuance.ErrOfferInvalid
	}
	tag, err := t.tx.Exec(t.ctx, `UPDATE issuance.credential_offers SET redeemed_at=$2 WHERE code_hash=$1 AND redeemed_at IS NULL`, codeHash[:], nowUTC)
	if err != nil || tag.RowsAffected() != 1 {
		return issuance.StoredOffer{}, issuance.ErrOfferInvalid
	}
	tag, err = t.tx.Exec(t.ctx,
		`UPDATE issuance.issuance_requests SET offer_state='redeemed',offer_ciphertext=NULL,offer_nonce=NULL,offer_key_version=NULL
		 WHERE request_id=$1 AND offer_state='ready'`, out.RequestID)
	if err != nil || tag.RowsAffected() != 1 {
		return issuance.StoredOffer{}, issuance.ErrOfferInvalid
	}
	return out, nil
}

func (t *postgresIssuanceTx) SaveNonce(issuerID string, nonceHash [32]byte, createdAt, expiresAt time.Time) error {
	if !validID(issuerID) {
		return issuance.ErrResourceNotFound
	}
	_, err := t.tx.Exec(t.ctx,
		`INSERT INTO issuance.nonces(nonce_hash,tenant_id,issuer_id,created_at,expires_at) VALUES($1,$2,$3,$4,$5)`,
		nonceHash[:], t.tenantID, issuerID, createdAt.UTC(), expiresAt.UTC())
	return err
}

func (t *postgresIssuanceTx) ConsumeNonce(issuerID string, nonceHash [32]byte, now time.Time) error {
	if !validID(issuerID) {
		return issuance.ErrInvalidNonce
	}
	var expiresAt time.Time
	var consumedAt *time.Time
	err := t.tx.QueryRow(t.ctx,
		`SELECT expires_at,consumed_at FROM issuance.nonces WHERE issuer_id=$1 AND nonce_hash=$2 FOR UPDATE`,
		issuerID, nonceHash[:]).Scan(&expiresAt, &consumedAt)
	if err != nil {
		return issuance.ErrInvalidNonce
	}
	nowUTC := now.UTC()
	if consumedAt != nil || !nowUTC.Before(expiresAt.UTC()) {
		return issuance.ErrInvalidNonce
	}
	tag, err := t.tx.Exec(t.ctx, `UPDATE issuance.nonces SET consumed_at=$2 WHERE nonce_hash=$1 AND consumed_at IS NULL`, nonceHash[:], nowUTC)
	if err != nil || tag.RowsAffected() != 1 {
		return issuance.ErrInvalidNonce
	}
	return nil
}

func (t *postgresIssuanceTx) SaveToken(tokenHash [32]byte, rec issuance.StoredToken) error {
	var clientID, requestID any
	var scopes, allowedIssuers []string
	var credID string
	if rec.Class == issuance.IntegrationTokenClass {
		if !validID(rec.Integration.ClientID) || len(rec.Integration.Scopes) == 0 || len(rec.Integration.AllowedIssuers) == 0 {
			return issuance.ErrInvalidRequest
		}
		for _, id := range rec.Integration.AllowedIssuers {
			if !validID(id) {
				return issuance.ErrInvalidRequest
			}
		}
		clientID = rec.Integration.ClientID
		scopes = rec.Integration.Scopes
		allowedIssuers = rec.Integration.AllowedIssuers
	} else {
		requestID = rec.RequestID
		credID = rec.CredID
		scopes = []string{}
		allowedIssuers = []string{}
	}
	_, err := t.tx.Exec(t.ctx,
		`INSERT INTO issuance.access_tokens(token_hash,tenant_id,token_class,audience,client_id,scopes,allowed_issuers,request_id,credential_id,issued_at,expires_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7::uuid[],$8,$9,$10,$11)`,
		tokenHash[:], t.tenantID, rec.Class, rec.Audience, clientID, scopes, allowedIssuers, requestID, credID,
		rec.IssuedAt.UTC(), rec.ExpiresAt.UTC())
	return err
}

func (t *postgresIssuanceTx) queryToken(tokenHash [32]byte, forUpdate bool) (issuance.StoredToken, bool, error) {
	sql := `SELECT token_class,audience,client_id::text,scopes,ARRAY(SELECT x::text FROM unnest(allowed_issuers) x),request_id,credential_id,issued_at,expires_at,used_at
	        FROM issuance.access_tokens WHERE token_hash=$1`
	if forUpdate {
		sql += ` FOR UPDATE`
	}
	var out issuance.StoredToken
	var clientID, requestID pgtype.Text
	var scopes, allowed []string
	var usedAt *time.Time
	err := t.tx.QueryRow(t.ctx, sql, tokenHash[:]).
		Scan(&out.Class, &out.Audience, &clientID, &scopes, &allowed, &requestID, &out.CredID, &out.IssuedAt, &out.ExpiresAt, &usedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.StoredToken{}, false, nil
	}
	if err != nil {
		return issuance.StoredToken{}, false, err
	}
	out.IssuedAt = out.IssuedAt.UTC()
	out.ExpiresAt = out.ExpiresAt.UTC()
	out.Used = usedAt != nil
	if out.Class == issuance.IntegrationTokenClass {
		out.Integration = issuance.IntegrationToken{
			TokenClass:     issuance.IntegrationTokenClass,
			Audience:       issuance.IntegrationAudience,
			TenantID:       t.tenantID,
			ClientID:       clientID.String,
			AllowedIssuers: allowed,
			Scopes:         scopes,
			IssuedAt:       out.IssuedAt,
			ExpiresAt:      out.ExpiresAt,
		}
	} else {
		out.RequestID = requestID.String
	}
	return out, true, nil
}

func (t *postgresIssuanceTx) LookupToken(tokenHash [32]byte) (issuance.StoredToken, bool, error) {
	return t.queryToken(tokenHash, false)
}

func (t *postgresIssuanceTx) LockTokenForCredential(tokenHash [32]byte) (issuance.StoredToken, bool, error) {
	return t.queryToken(tokenHash, true)
}

func (t *postgresIssuanceTx) MarkIssued(requestID string, tokenHash [32]byte, issuedCredentialID string, now time.Time) error {
	nowUTC := now.UTC()
	tag, err := t.tx.Exec(t.ctx,
		`UPDATE issuance.issuance_requests SET issuance_state='issued',issued_credential_id=$3,issued_at=$2 WHERE request_id=$1 AND issuance_state='prepared'`,
		requestID, nowUTC, issuedCredentialID)
	if err != nil || tag.RowsAffected() != 1 {
		return issuance.ErrInvalidToken
	}
	tag, err = t.tx.Exec(t.ctx,
		`UPDATE issuance.access_tokens SET used_at=$2 WHERE token_hash=$1 AND used_at IS NULL`,
		tokenHash[:], nowUTC)
	if err != nil || tag.RowsAffected() != 1 {
		return issuance.ErrInvalidToken
	}
	return nil
}

func (t *postgresIssuanceTx) CancelIssuanceRequest(requestID string, now time.Time) error {
	nowUTC := now.UTC()
	var offerState, issState string
	err := t.tx.QueryRow(t.ctx,
		`SELECT offer_state,issuance_state FROM issuance.issuance_requests WHERE request_id=$1 FOR UPDATE`,
		requestID).Scan(&offerState, &issState)
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.ErrResourceNotFound
	}
	if err != nil {
		return err
	}
	if issState == "issued" {
		return issuance.ErrInvalidStatusTransition
	}
	nextOffer := offerState
	if offerState == "ready" {
		nextOffer = "cancelled"
		if _, err := t.tx.Exec(t.ctx,
			`UPDATE issuance.issuance_requests
			 SET offer_state='cancelled',offer_ciphertext=NULL,offer_nonce=NULL,offer_key_version=NULL,issuance_state='cancelled'
			 WHERE request_id=$1`, requestID); err != nil {
			return err
		}
		if _, err := t.tx.Exec(t.ctx,
			`UPDATE issuance.credential_offers SET cancelled_at=$2 WHERE request_id=$1 AND redeemed_at IS NULL AND cancelled_at IS NULL`,
			requestID, nowUTC); err != nil {
			return err
		}
	} else if _, err := t.tx.Exec(t.ctx,
		`UPDATE issuance.issuance_requests SET issuance_state='cancelled' WHERE request_id=$1`, requestID); err != nil {
		return err
	}
	_ = nextOffer
	if _, err := t.tx.Exec(t.ctx,
		`UPDATE issuance.access_tokens SET used_at=$2 WHERE request_id=$1 AND token_class='oid4vci' AND used_at IS NULL`,
		requestID, nowUTC); err != nil {
		return err
	}
	if _, err := t.tx.Exec(t.ctx,
		`UPDATE issuance.deferred_transactions SET status='cancelled',completed_at=$2 WHERE request_id=$1 AND status='pending'`,
		requestID, nowUTC); err != nil {
		return err
	}
	return nil
}

func (t *postgresIssuanceTx) CreateDeferredTransaction(rec issuance.DeferredTxRecord, holderJKT string, _ time.Time) error {
	tag, err := t.tx.Exec(t.ctx,
		`UPDATE issuance.issuance_requests SET issuance_state='deferred',holder_jkt=$2 WHERE request_id=$1 AND issuance_state='prepared'`,
		rec.RequestID, holderJKT)
	if err != nil || tag.RowsAffected() != 1 {
		return issuance.ErrInvalidToken
	}
	_, err = t.tx.Exec(t.ctx,
		`INSERT INTO issuance.deferred_transactions(tx_hash,tenant_id,issuer_id,request_id,token_hash,status,error_code,interval_seconds,created_at,expires_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		rec.TxHash[:], rec.TenantID, rec.IssuerID, rec.RequestID, rec.TokenHash[:],
		rec.Status, rec.ErrorCode, rec.IntervalSeconds, rec.CreatedAt.UTC(), rec.ExpiresAt.UTC())
	return err
}

func scanDeferredTx(row pgx.Row) (issuance.DeferredTxRecord, bool, error) {
	var d issuance.DeferredTxRecord
	var txHash, tokHash []byte
	var vcVer pgtype.Text
	var completedAt *time.Time
	err := row.Scan(&txHash, &d.TenantID, &d.IssuerID, &d.RequestID, &tokHash, &d.Status, &d.ErrorCode,
		&d.VCCipher, &d.VCNonce, &vcVer, &d.IntervalSeconds, &d.CreatedAt, &d.ExpiresAt, &completedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.DeferredTxRecord{}, false, nil
	}
	if err != nil {
		return issuance.DeferredTxRecord{}, false, err
	}
	if len(txHash) != 32 || len(tokHash) != 32 {
		return issuance.DeferredTxRecord{}, false, issuance.ErrInvalidRequest
	}
	copy(d.TxHash[:], txHash)
	copy(d.TokenHash[:], tokHash)
	d.VCKeyVer = vcVer.String
	d.CreatedAt = d.CreatedAt.UTC()
	d.ExpiresAt = d.ExpiresAt.UTC()
	if completedAt != nil {
		c := completedAt.UTC()
		d.CompletedAt = &c
	}
	return d, true, nil
}

const selectDeferredCols = `SELECT tx_hash,tenant_id::text,issuer_id::text,request_id,token_hash,status,error_code,vc_ciphertext,vc_nonce,vc_key_version,interval_seconds,created_at,expires_at,completed_at FROM issuance.deferred_transactions`

func (t *postgresIssuanceTx) LockDeferredByTxHash(txHash [32]byte) (issuance.DeferredTxRecord, bool, error) {
	return scanDeferredTx(t.tx.QueryRow(t.ctx, selectDeferredCols+` WHERE tx_hash=$1 FOR UPDATE`, txHash[:]))
}

func (t *postgresIssuanceTx) LockDeferredByRequestID(requestID string) (issuance.DeferredTxRecord, bool, error) {
	if requestID == "" {
		return issuance.DeferredTxRecord{}, false, nil
	}
	return scanDeferredTx(t.tx.QueryRow(t.ctx, selectDeferredCols+` WHERE request_id=$1 FOR UPDATE`, requestID))
}

func (t *postgresIssuanceTx) CompleteDeferredTransaction(requestID, issuedCredID string, vcCipher, vcNonce []byte, vcKeyVer string, now time.Time) error {
	nowUTC := now.UTC()
	tag, err := t.tx.Exec(t.ctx,
		`UPDATE issuance.issuance_requests SET issuance_state='issued',issued_credential_id=$3,issued_at=$2 WHERE request_id=$1 AND issuance_state='deferred'`,
		requestID, nowUTC, issuedCredID)
	if err != nil || tag.RowsAffected() != 1 {
		return issuance.ErrInvalidStatusTransition
	}
	tag, err = t.tx.Exec(t.ctx,
		`UPDATE issuance.deferred_transactions
		 SET status='issued',vc_ciphertext=$2,vc_nonce=$3,vc_key_version=$4,completed_at=$5
		 WHERE request_id=$1 AND status='pending'`,
		requestID, vcCipher, vcNonce, vcKeyVer, nowUTC)
	if err != nil || tag.RowsAffected() != 1 {
		return issuance.ErrInvalidStatusTransition
	}
	return nil
}

func (t *postgresIssuanceTx) FailDeferredTransaction(requestID, errorCode string, now time.Time) error {
	nowUTC := now.UTC()
	tag, err := t.tx.Exec(t.ctx,
		`UPDATE issuance.issuance_requests SET issuance_state='failed' WHERE request_id=$1 AND issuance_state='deferred'`,
		requestID)
	if err != nil || tag.RowsAffected() != 1 {
		return issuance.ErrInvalidStatusTransition
	}
	tag, err = t.tx.Exec(t.ctx,
		`UPDATE issuance.deferred_transactions SET status='failed',error_code=$2,completed_at=$3 WHERE request_id=$1 AND status='pending'`,
		requestID, errorCode, nowUTC)
	if err != nil || tag.RowsAffected() != 1 {
		return issuance.ErrInvalidStatusTransition
	}
	return nil
}

func (t *postgresIssuanceTx) MarkDeferredDelivered(txHash, tokenHash [32]byte, now time.Time) error {
	nowUTC := now.UTC()
	if _, err := t.tx.Exec(t.ctx,
		`UPDATE issuance.deferred_transactions SET vc_ciphertext=NULL,vc_nonce=NULL,vc_key_version=NULL WHERE tx_hash=$1`,
		txHash[:]); err != nil {
		return err
	}
	tag, err := t.tx.Exec(t.ctx,
		`UPDATE issuance.access_tokens SET used_at=$2 WHERE token_hash=$1 AND used_at IS NULL`,
		tokenHash[:], nowUTC)
	if err != nil || tag.RowsAffected() != 1 {
		return issuance.ErrInvalidToken
	}
	return nil
}

func (t *postgresIssuanceTx) RotateKey(issuerID, newKID, kmsKeyRef string, jwk issuance.PublicJWK, actorID, correlationID string, now time.Time) error {
	return rotateKeyTx(t.ctx, t.tx, t.tenantID, issuerID, newKID, kmsKeyRef, jwk, actorID, correlationID, now)
}

func (t *postgresIssuanceTx) CompromiseKey(issuerID, kid, actorID, correlationID string, now time.Time) error {
	return compromiseKeyTx(t.ctx, t.tx, t.tenantID, issuerID, kid, actorID, correlationID, now)
}

func (t *postgresIssuanceTx) ListIssuedCredentialsByKID(issuerID, kid string) ([]string, error) {
	if !validID(issuerID) || kid == "" {
		return nil, nil
	}
	rows, err := t.tx.Query(t.ctx,
		`SELECT credential_id FROM status.issued_credentials WHERE issuer_id=$1 AND signing_kid=$2 AND desired_status <> 'revoked' ORDER BY issued_at,credential_id`,
		issuerID, kid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (t *postgresIssuanceTx) AllocateStatusSlot(
	issuerID, purpose string,
	listSize int,
	newListID func() (string, error),
	signInitial func(listID string, rawBits []byte) (jwt string, validFrom, validUntil time.Time, err error),
	now time.Time,
) (string, int, error) {
	if !validID(issuerID) || listSize <= 0 || listSize%8 != 0 {
		return "", 0, issuance.ErrInvalidRequest
	}
	if _, err := t.tx.Exec(t.ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1||'|'||$2||'|'||$3,0))`, t.tenantID, issuerID, purpose); err != nil {
		return "", 0, err
	}
	nowUTC := now.UTC()
	var listID string
	var nextIdx int
	err := t.tx.QueryRow(t.ctx,
		`SELECT list_id,next_index FROM status.status_lists
		 WHERE issuer_id=$1 AND purpose=$2 AND next_index<bitstring_size
		 ORDER BY updated_at DESC LIMIT 1 FOR UPDATE`, issuerID, purpose).Scan(&listID, &nextIdx)
	if err == nil {
		tag, updErr := t.tx.Exec(t.ctx,
			`UPDATE status.status_lists SET next_index=next_index+1,updated_at=$3 WHERE issuer_id=$1 AND list_id=$2`,
			issuerID, listID, nowUTC)
		if updErr != nil || tag.RowsAffected() != 1 {
			return "", 0, issuance.ErrStatusListFull
		}
		return listID, nextIdx, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", 0, err
	}
	listID, err = newListID()
	if err != nil {
		return "", 0, issuance.ErrInvalidRequest
	}
	rawBits := make([]byte, listSize/8)
	jwt, validFrom, validUntil, err := signInitial(listID, rawBits)
	if err != nil {
		return "", 0, err
	}
	_, err = t.tx.Exec(t.ctx,
		`INSERT INTO status.status_lists(tenant_id,issuer_id,list_id,purpose,bitstring_size,next_index,raw_bits,version,published_version,published_jwt,valid_from,valid_until,updated_at)
		 VALUES($1,$2,$3,$4,$5,1,$6,1,1,$7,$8,$9,$10)`,
		t.tenantID, issuerID, listID, purpose, listSize, rawBits, jwt, validFrom.UTC(), validUntil.UTC(), nowUTC)
	if err != nil {
		return "", 0, err
	}
	return listID, 0, nil
}

func (t *postgresIssuanceTx) SaveIssuedCredential(rec issuance.IssuedCredentialRecord) error {
	_, err := t.tx.Exec(t.ctx,
		`INSERT INTO status.issued_credentials(credential_id,tenant_id,issuer_id,request_id,client_id,signing_kid,jws_digest,revocation_list_id,revocation_index,suspension_list_id,suspension_index,desired_status,published_status,status_version,reason_code,issued_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		rec.CredentialID, rec.TenantID, rec.IssuerID, rec.RequestID, rec.ClientID, rec.SigningKID, rec.Digest,
		rec.RevocationListID, rec.RevocationIndex, rec.SuspensionListID, rec.SuspensionIndex,
		rec.DesiredStatus, rec.PublishedStatus, rec.StatusVersion, rec.ReasonCode, rec.IssuedAt.UTC())
	return err
}

func (t *postgresIssuanceTx) LockIssuedCredential(credentialID string) (issuance.IssuedCredentialRecord, bool, error) {
	if credentialID == "" {
		return issuance.IssuedCredentialRecord{}, false, nil
	}
	var rec issuance.IssuedCredentialRecord
	var suspAt, revAt *time.Time
	err := t.tx.QueryRow(t.ctx,
		`SELECT credential_id,tenant_id::text,issuer_id::text,request_id,client_id::text,signing_kid,jws_digest,
		        revocation_list_id,revocation_index,suspension_list_id,suspension_index,
		        desired_status,published_status,status_version,reason_code,issued_at,suspended_at,revoked_at
		 FROM status.issued_credentials WHERE credential_id=$1 FOR UPDATE`, credentialID).
		Scan(&rec.CredentialID, &rec.TenantID, &rec.IssuerID, &rec.RequestID, &rec.ClientID, &rec.SigningKID, &rec.Digest,
			&rec.RevocationListID, &rec.RevocationIndex, &rec.SuspensionListID, &rec.SuspensionIndex,
			&rec.DesiredStatus, &rec.PublishedStatus, &rec.StatusVersion, &rec.ReasonCode, &rec.IssuedAt, &suspAt, &revAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.IssuedCredentialRecord{}, false, nil
	}
	if err != nil {
		return issuance.IssuedCredentialRecord{}, false, err
	}
	rec.IssuedAt = rec.IssuedAt.UTC()
	if suspAt != nil {
		s := suspAt.UTC()
		rec.SuspendedAt = &s
	}
	if revAt != nil {
		r := revAt.UTC()
		rec.RevokedAt = &r
	}
	return rec, true, nil
}

func (t *postgresIssuanceTx) ListAdminCredentials(filter issuance.AdminListFilter) ([]issuance.IssuedCredentialRecord, error) {
	query := `SELECT credential_id,tenant_id::text,issuer_id::text,request_id,client_id,desired_status,published_status,status_version,issued_at FROM status.issued_credentials`
	args := []any{}
	if filter.IssuerID != "" {
		if !validID(filter.IssuerID) {
			return nil, issuance.ErrInvalidRequest
		}
		query += ` WHERE issuer_id=$1`
		args = append(args, filter.IssuerID)
	}
	query += ` ORDER BY issued_at DESC,credential_id DESC LIMIT $` + strconv.Itoa(len(args)+1) + ` OFFSET $` + strconv.Itoa(len(args)+2)
	args = append(args, filter.Limit, filter.Offset)
	rows, err := t.tx.Query(t.ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]issuance.IssuedCredentialRecord, 0)
	for rows.Next() {
		var r issuance.IssuedCredentialRecord
		if err := rows.Scan(&r.CredentialID, &r.TenantID, &r.IssuerID, &r.RequestID, &r.ClientID, &r.DesiredStatus, &r.PublishedStatus, &r.StatusVersion, &r.IssuedAt); err != nil {
			return nil, err
		}
		r.IssuedAt = r.IssuedAt.UTC()
		items = append(items, r)
	}
	return items, rows.Err()
}

func scanStatusList(row pgx.Row) (issuance.StatusListRecord, bool, error) {
	var l issuance.StatusListRecord
	err := row.Scan(&l.TenantID, &l.IssuerID, &l.ListID, &l.Purpose, &l.BitstringSize, &l.NextIndex,
		&l.RawBits, &l.Version, &l.PublishedVersion, &l.PublishedJWT, &l.ValidFrom, &l.ValidUntil, &l.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.StatusListRecord{}, false, nil
	}
	if err != nil {
		return issuance.StatusListRecord{}, false, err
	}
	l.ValidFrom = l.ValidFrom.UTC()
	l.ValidUntil = l.ValidUntil.UTC()
	l.UpdatedAt = l.UpdatedAt.UTC()
	return l, true, nil
}

const selectStatusListCols = `SELECT tenant_id::text,issuer_id::text,list_id,purpose,bitstring_size,next_index,raw_bits,version,published_version,published_jwt,valid_from,valid_until,updated_at FROM status.status_lists`

func (t *postgresIssuanceTx) LockStatusList(issuerID, listID string) (issuance.StatusListRecord, bool, error) {
	if !validID(issuerID) || listID == "" {
		return issuance.StatusListRecord{}, false, nil
	}
	return scanStatusList(t.tx.QueryRow(t.ctx, selectStatusListCols+` WHERE issuer_id=$1 AND list_id=$2 FOR UPDATE`, issuerID, listID))
}

func (t *postgresIssuanceTx) GetPublishedStatusList(issuerID, purpose, listID string) (issuance.StatusListRecord, bool, error) {
	if !validID(issuerID) || purpose == "" || listID == "" {
		return issuance.StatusListRecord{}, false, nil
	}
	return scanStatusList(t.tx.QueryRow(t.ctx, selectStatusListCols+` WHERE issuer_id=$1 AND purpose=$2 AND list_id=$3`, issuerID, purpose, listID))
}

func (t *postgresIssuanceTx) SaveStatusListAndCredential(list issuance.StatusListRecord, cred issuance.IssuedCredentialRecord) error {
	tag, err := t.tx.Exec(t.ctx,
		`UPDATE status.status_lists SET raw_bits=$3,version=$4,published_version=$5,published_jwt=$6,valid_from=$7,valid_until=$8,updated_at=$9
		 WHERE issuer_id=$1 AND list_id=$2 AND version=$10`,
		list.IssuerID, list.ListID, list.RawBits, list.Version, list.PublishedVersion, list.PublishedJWT,
		list.ValidFrom.UTC(), list.ValidUntil.UTC(), list.UpdatedAt.UTC(), list.Version-1)
	if err != nil || tag.RowsAffected() != 1 {
		return issuance.ErrInvalidStatusTransition
	}
	tag, err = t.tx.Exec(t.ctx,
		`UPDATE status.issued_credentials SET desired_status=$2,published_status=$3,status_version=$4,reason_code=$5,suspended_at=$6,revoked_at=$7
		 WHERE credential_id=$1 AND status_version=$8`,
		cred.CredentialID, cred.DesiredStatus, cred.PublishedStatus, cred.StatusVersion, cred.ReasonCode,
		cred.SuspendedAt, cred.RevokedAt, cred.StatusVersion-1)
	if err != nil || tag.RowsAffected() != 1 {
		return issuance.ErrInvalidStatusTransition
	}
	return nil
}

func (t *postgresIssuanceTx) LockStatusIdempotency(clientID string, keyHash [32]byte) (issuance.StatusIdempotencyRecord, bool, error) {
	if !validID(clientID) {
		return issuance.StatusIdempotencyRecord{}, false, nil
	}
	if _, err := t.tx.Exec(t.ctx, `SELECT pg_advisory_xact_lock(hashtextextended('status|'||$1||'|'||$2||'|'||encode($3,'hex'),0))`, t.tenantID, clientID, keyHash[:]); err != nil {
		return issuance.StatusIdempotencyRecord{}, false, err
	}
	var out issuance.StatusIdempotencyRecord
	var reqHash, rawResult []byte
	err := t.tx.QueryRow(t.ctx,
		`SELECT request_hash,result_json FROM status.status_idempotency WHERE client_id=$1 AND key_hash=$2`,
		clientID, keyHash[:]).Scan(&reqHash, &rawResult)
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.StatusIdempotencyRecord{}, false, nil
	}
	if err != nil {
		return issuance.StatusIdempotencyRecord{}, false, err
	}
	if len(reqHash) != 32 || json.Unmarshal(rawResult, &out.Result) != nil {
		return issuance.StatusIdempotencyRecord{}, false, issuance.ErrInvalidRequest
	}
	out.ClientID = clientID
	out.KeyHash = keyHash
	copy(out.RequestHash[:], reqHash)
	return out, true, nil
}

func (t *postgresIssuanceTx) SaveStatusIdempotency(rec issuance.StatusIdempotencyRecord) error {
	rawResult, err := json.Marshal(rec.Result)
	if err != nil {
		return err
	}
	_, err = t.tx.Exec(t.ctx,
		`INSERT INTO status.status_idempotency(tenant_id,client_id,key_hash,request_hash,result_json,created_at)
		 VALUES($1,$2,$3,$4,$5,$6)`,
		t.tenantID, rec.ClientID, rec.KeyHash[:], rec.RequestHash[:], rawResult, rec.Result.EffectiveAt.UTC())
	return err
}

func (t *postgresIssuanceTx) AppendAudit(rec issuance.AuditRecord) error {
	return appendPostgresAudit(t.ctx, t.tx, rec)
}

func (t *postgresIssuanceTx) ListAuditEvents(actionFilter string) ([]issuance.AuditRecord, error) {
	return listAuditEventsTx(t.ctx, t.tx, actionFilter)
}

func createIssuerWithKeyTx(
	ctx context.Context, tx pgx.Tx, tenantID string,
	rec issuance.IssuerRecord, kid, kmsKeyRef string, jwk issuance.PublicJWK,
	actorID, correlationID string, now time.Time,
) error {
	if rec.TenantID != tenantID || !validID(rec.IssuerID) {
		return issuance.ErrInvalidFoundationInput
	}
	if err := issuance.ValidateIssuerIdentifier(rec.IssuerURI); err != nil {
		return issuance.ErrInvalidFoundationInput
	}
	ts := now.UTC()
	if _, err := tx.Exec(ctx,
		`INSERT INTO tenancy.issuers(issuer_id,tenant_id,slug,issuer_uri,display_name,state,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		rec.IssuerID, tenantID, rec.Slug, rec.IssuerURI, rec.DisplayName, string(rec.State), rec.CreatedAt); err != nil {
		return mapFoundationPGError(err)
	}
	if err := appendPostgresAudit(ctx, tx, newPostgresAuditEvent(tenantID, actorID, "issuer.created", rec.IssuerID, "succeeded", correlationID, ts)); err != nil {
		return mapFoundationPGError(err)
	}
	if kid != "" {
		return registerKeyTx(ctx, tx, tenantID, rec.IssuerID, kid, kmsKeyRef, jwk, actorID, correlationID, ts)
	}
	return nil
}

func registerKeyTx(ctx context.Context, tx pgx.Tx, tenantID, issuerID, kid, kmsKeyRef string, jwk issuance.PublicJWK, actorID, correlationID string, now time.Time) error {
	if !validID(issuerID) || kid == "" || strings.TrimSpace(kmsKeyRef) == "" {
		return issuance.ErrInvalidFoundationInput
	}
	if _, err := issuance.DecodePublicJWK(jwk); err != nil {
		return issuance.ErrInvalidFoundationInput
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO tenancy.issuer_keys(tenant_id,issuer_id,kid,kms_key_ref,alg,crv,x_coord,y_coord,state,created_at)
		 VALUES($1,$2,$3,$4,'ES256','P-256',$5,$6,'active',$7)`,
		tenantID, issuerID, kid, kmsKeyRef, jwk.X, jwk.Y, now.UTC()); err != nil {
		return mapKeyPGError(err)
	}
	return mapKeyPGError(appendPostgresAudit(ctx, tx, newPostgresAuditEvent(tenantID, actorID, "issuer_key.registered", kid, "succeeded", correlationID, now)))
}

// CreateIssuer persists a logical issuer within tenantID under FORCE RLS.
func (b *IssuanceBackend) CreateIssuer(ctx context.Context, tenantID, issuerID, slug, displayName string, now time.Time) (issuance.IssuerRecord, error) {
	if !validID(issuerID) {
		return issuance.IssuerRecord{}, issuance.ErrInvalidFoundationInput
	}
	rec, err := issuance.NewIssuerRecord(tenantID, issuerID, slug, displayName, now)
	if err != nil {
		return issuance.IssuerRecord{}, err
	}
	err = WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
		return createIssuerWithKeyTx(ctx, tx, tenantID, rec, "", "", issuance.PublicJWK{}, "system", "", now)
	})
	if err != nil {
		return issuance.IssuerRecord{}, err
	}
	return rec, nil
}

// RegisterKey persists an active ES256 public key metadata row (no private key in SQL).
func (b *IssuanceBackend) RegisterKey(ctx context.Context, tenantID, issuerID, kid, kmsKeyRef string, jwk issuance.PublicJWK, actorID, correlationID string, now time.Time) error {
	return WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
		return registerKeyTx(ctx, tx, tenantID, issuerID, kid, kmsKeyRef, jwk, actorID, correlationID, now)
	})
}

func rotateKeyTx(ctx context.Context, tx pgx.Tx, tenantID, issuerID, newKID, newKMSKeyRef string, newJWK issuance.PublicJWK, actorID, correlationID string, now time.Time) error {
	if !validID(issuerID) || newKID == "" || strings.TrimSpace(newKMSKeyRef) == "" {
		return issuance.ErrInvalidFoundationInput
	}
	if _, err := issuance.DecodePublicJWK(newJWK); err != nil {
		return issuance.ErrInvalidFoundationInput
	}
	ts := now.UTC()
	if _, err := tx.Exec(ctx,
		`UPDATE tenancy.issuer_keys SET state='retired',retired_at=$2 WHERE issuer_id=$1 AND state='active'`,
		issuerID, ts); err != nil {
		return mapKeyPGError(err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO tenancy.issuer_keys(tenant_id,issuer_id,kid,kms_key_ref,alg,crv,x_coord,y_coord,state,created_at)
		 VALUES($1,$2,$3,$4,'ES256','P-256',$5,$6,'active',$7)`,
		tenantID, issuerID, newKID, newKMSKeyRef, newJWK.X, newJWK.Y, ts); err != nil {
		return mapKeyPGError(err)
	}
	return mapKeyPGError(appendPostgresAudit(ctx, tx, newPostgresAuditEvent(tenantID, actorID, "issuer_key.rotated", newKID, "succeeded", correlationID, ts)))
}

func compromiseKeyTx(ctx context.Context, tx pgx.Tx, tenantID, issuerID, kid, actorID, correlationID string, now time.Time) error {
	if !validID(issuerID) || kid == "" {
		return issuance.ErrResourceNotFound
	}
	ts := now.UTC()
	var state string
	err := tx.QueryRow(ctx, `SELECT state FROM tenancy.issuer_keys WHERE issuer_id=$1 AND kid=$2 FOR UPDATE`, issuerID, kid).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.ErrResourceNotFound
	}
	if err != nil {
		return err
	}
	if state == string(issuance.KeyCompromised) {
		return nil
	}
	if _, err := tx.Exec(ctx,
		`UPDATE tenancy.issuer_keys SET state='compromised',compromised_at=$3 WHERE issuer_id=$1 AND kid=$2`,
		issuerID, kid, ts); err != nil {
		return err
	}
	return appendPostgresAudit(ctx, tx, newPostgresAuditEvent(tenantID, actorID, "issuer_key.compromised", kid, "succeeded", correlationID, ts))
}

// RotateKey atomically retires any current active key and activates newKID.
func (b *IssuanceBackend) RotateKey(ctx context.Context, tenantID, issuerID, newKID, newKMSKeyRef string, newJWK issuance.PublicJWK, actorID, correlationID string, now time.Time) error {
	return WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
		return rotateKeyTx(ctx, tx, tenantID, issuerID, newKID, newKMSKeyRef, newJWK, actorID, correlationID, now)
	})
}

// CompromiseKey marks kid as compromised, omitting it from JWKS and preventing signing.
func (b *IssuanceBackend) CompromiseKey(ctx context.Context, tenantID, issuerID, kid, actorID, correlationID string, now time.Time) error {
	if !validID(issuerID) || kid == "" {
		return issuance.ErrResourceNotFound
	}
	return WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
		return compromiseKeyTx(ctx, tx, tenantID, issuerID, kid, actorID, correlationID, now)
	})
}

func registerHashedClientTx(
	ctx context.Context, tx pgx.Tx, tenantID string,
	client issuance.ClientSummary, secretHash [32]byte,
	actorID, correlationID string, now time.Time,
) error {
	if client.TenantID != tenantID || !validID(client.ClientID) || strings.TrimSpace(client.ClientName) == "" ||
		len(client.AllowedIssuers) == 0 || len(client.Scopes) == 0 {
		return issuance.ErrInvalidFoundationInput
	}
	if client.ExpiresAt != nil && !client.ExpiresAt.UTC().After(now.UTC()) {
		return issuance.ErrInvalidFoundationInput
	}
	for _, sc := range client.Scopes {
		if !issuance.AllowedIntegrationScope(sc) {
			return issuance.ErrInvalidFoundationInput
		}
	}
	for _, id := range client.AllowedIssuers {
		if !validID(id) {
			return issuance.ErrInvalidFoundationInput
		}
	}
	ts := now.UTC()
	var expPtr *time.Time
	if client.ExpiresAt != nil {
		t := client.ExpiresAt.UTC()
		expPtr = &t
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO tenancy.integration_clients(client_id,tenant_id,client_name,secret_hash,scopes,state,created_at,expires_at)
		 VALUES($1,$2,$3,$4,$5,'active',$6,$7)`,
		client.ClientID, tenantID, client.ClientName, secretHash[:], client.Scopes, ts, expPtr); err != nil {
		return mapFoundationPGError(err)
	}
	for _, issuerID := range client.AllowedIssuers {
		if _, err := tx.Exec(ctx,
			`INSERT INTO tenancy.integration_client_grants(tenant_id,client_id,issuer_id,created_at) VALUES($1,$2,$3,$4)`,
			tenantID, client.ClientID, issuerID, ts); err != nil {
			return mapFoundationPGError(err)
		}
	}
	return mapFoundationPGError(appendPostgresAudit(ctx, tx, newPostgresAuditEvent(tenantID, actorID, "integration_client.registered", client.ClientID, "succeeded", correlationID, ts)))
}

func rotateClientSecretTx(
	ctx context.Context, tx pgx.Tx, tenantID, clientID string, newSecretHash [32]byte,
	actorID, correlationID string, now time.Time,
) error {
	if !validID(clientID) {
		return issuance.ErrResourceNotFound
	}
	var state string
	err := tx.QueryRow(ctx, `SELECT state FROM tenancy.integration_clients WHERE client_id=$1 FOR UPDATE`, clientID).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.ErrResourceNotFound
	}
	if err != nil {
		return err
	}
	if state != string(issuance.ClientActive) {
		return issuance.ErrClientUnauthorized
	}
	if _, err := tx.Exec(ctx, `UPDATE tenancy.integration_clients SET secret_hash=$2 WHERE client_id=$1`, clientID, newSecretHash[:]); err != nil {
		return mapFoundationPGError(err)
	}
	return appendPostgresAudit(ctx, tx, newPostgresAuditEvent(tenantID, actorID, "integration_client.secret_rotated", clientID, "succeeded", correlationID, now.UTC()))
}

func revokeClientTx(ctx context.Context, tx pgx.Tx, tenantID, clientID, actorID, correlationID string, now time.Time) error {
	if !validID(clientID) {
		return issuance.ErrResourceNotFound
	}
	ts := now.UTC()
	tag, err := tx.Exec(ctx,
		`UPDATE tenancy.integration_clients SET state='revoked',revoked_at=$2 WHERE client_id=$1`,
		clientID, ts)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return issuance.ErrResourceNotFound
	}
	return appendPostgresAudit(ctx, tx, newPostgresAuditEvent(tenantID, actorID, "integration_client.revoked", clientID, "succeeded", correlationID, ts))
}

func marshalDefinitionPayload(tenantID string, def issuance.Definition) ([]byte, []string, []string, error) {
	if def.TenantID != tenantID || !validID(def.IssuerID) || issuance.ValidateDefinition(def) != nil {
		return nil, nil, nil, issuance.ErrInvalidFoundationInput
	}
	fieldsJSON, err := json.Marshal(def.Fields)
	if err != nil {
		return nil, nil, nil, issuance.ErrInvalidFoundationInput
	}
	contexts := def.Contexts
	if contexts == nil {
		contexts = []string{}
	}
	purposes := def.StatusPurposes
	if purposes == nil {
		purposes = []string{}
	}
	return fieldsJSON, contexts, purposes, nil
}

func createDraftDefinitionTx(ctx context.Context, tx pgx.Tx, tenantID string, def issuance.Definition, actorID, correlationID string, now time.Time) error {
	fieldsJSON, contexts, purposes, err := marshalDefinitionPayload(tenantID, def)
	if err != nil {
		return err
	}
	ts := now.UTC()
	if _, err := tx.Exec(ctx,
		`INSERT INTO definition.credential_definitions(tenant_id,issuer_id,definition_id,created_at) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
		tenantID, def.IssuerID, def.ID, ts); err != nil {
		return mapDefinitionPGError(err)
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO definition.definition_versions(tenant_id,issuer_id,definition_id,version,configuration_id,display_name,locale,contexts,types,fields_json,default_validity_seconds,status_purposes,publish_schema,state,content_hash,created_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'draft','',$14)`,
		tenantID, def.IssuerID, def.ID, def.Version, def.ConfigurationID, def.DisplayName,
		def.Locale, contexts, def.Types, fieldsJSON, int64(def.DefaultValidity/time.Second), purposes, def.PublishSchema, ts)
	if err != nil {
		return mapDefinitionPGError(err)
	}
	return mapDefinitionPGError(appendPostgresAudit(ctx, tx, newPostgresAuditEvent(tenantID, actorID, "definition.draft_created", def.Ref(), "succeeded", correlationID, ts)))
}

func replaceDraftDefinitionTx(ctx context.Context, tx pgx.Tx, tenantID string, def issuance.Definition, actorID, correlationID string, now time.Time) error {
	fieldsJSON, contexts, purposes, err := marshalDefinitionPayload(tenantID, def)
	if err != nil {
		return err
	}
	ts := now.UTC()
	var state string
	err = tx.QueryRow(ctx,
		`SELECT state FROM definition.definition_versions WHERE issuer_id=$1 AND definition_id=$2 AND version=$3 FOR UPDATE`,
		def.IssuerID, def.ID, def.Version).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.ErrDefinitionNotFound
	}
	if err != nil {
		return mapDefinitionPGError(err)
	}
	if state != string(issuance.DefinitionDraft) {
		return issuance.ErrDefinitionImmutable
	}
	_, err = tx.Exec(ctx,
		`UPDATE definition.definition_versions
		 SET configuration_id=$4,display_name=$5,locale=$6,contexts=$7,types=$8,fields_json=$9,default_validity_seconds=$10,status_purposes=$11,publish_schema=$12
		 WHERE issuer_id=$1 AND definition_id=$2 AND version=$3`,
		def.IssuerID, def.ID, def.Version, def.ConfigurationID, def.DisplayName, def.Locale, contexts, def.Types, fieldsJSON, int64(def.DefaultValidity/time.Second), purposes, def.PublishSchema)
	if err != nil {
		return mapDefinitionPGError(err)
	}
	return mapDefinitionPGError(appendPostgresAudit(ctx, tx, newPostgresAuditEvent(tenantID, actorID, "definition.draft_replaced", def.Ref(), "succeeded", correlationID, ts)))
}

func publishDefinitionTx(ctx context.Context, tx pgx.Tx, tenantID, issuerID, id, version, actorID, correlationID string, now time.Time) (issuance.Definition, error) {
	if !validID(issuerID) {
		return issuance.Definition{}, issuance.ErrDefinitionNotFound
	}
	ts := now.UTC()
	d, err := scanDefinitionRow(tx.QueryRow(ctx,
		selectDefinitionCols+` WHERE issuer_id=$1 AND definition_id=$2 AND version=$3 FOR UPDATE`,
		issuerID, id, version))
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.Definition{}, issuance.ErrDefinitionNotFound
	}
	if err != nil {
		return issuance.Definition{}, mapDefinitionPGError(err)
	}
	if d.State != issuance.DefinitionDraft {
		return issuance.Definition{}, issuance.ErrDefinitionImmutable
	}
	hash, err := issuance.ComputeDefinitionHash(d)
	if err != nil {
		return issuance.Definition{}, issuance.ErrInvalidFoundationInput
	}
	if _, err := tx.Exec(ctx,
		`UPDATE definition.definition_versions SET state='published',content_hash=$4,published_at=$5
		 WHERE issuer_id=$1 AND definition_id=$2 AND version=$3`,
		issuerID, id, version, hash, ts); err != nil {
		return issuance.Definition{}, mapDefinitionPGError(err)
	}
	d.State = issuance.DefinitionPublished
	d.Hash = hash
	d.PublishedAt = &ts
	if err := appendPostgresAudit(ctx, tx, newPostgresAuditEvent(tenantID, actorID, "definition.published", d.Ref(), "succeeded", correlationID, ts)); err != nil {
		return issuance.Definition{}, mapDefinitionPGError(err)
	}
	return d, nil
}

func retireDefinitionTx(ctx context.Context, tx pgx.Tx, tenantID, issuerID, id, version, actorID, correlationID string, now time.Time) (issuance.Definition, error) {
	if !validID(issuerID) {
		return issuance.Definition{}, issuance.ErrDefinitionNotFound
	}
	ts := now.UTC()
	d, err := scanDefinitionRow(tx.QueryRow(ctx,
		selectDefinitionCols+` WHERE issuer_id=$1 AND definition_id=$2 AND version=$3 FOR UPDATE`,
		issuerID, id, version))
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.Definition{}, issuance.ErrDefinitionNotFound
	}
	if err != nil {
		return issuance.Definition{}, mapDefinitionPGError(err)
	}
	if d.State != issuance.DefinitionPublished {
		return issuance.Definition{}, issuance.ErrDefinitionImmutable
	}
	if _, err := tx.Exec(ctx,
		`UPDATE definition.definition_versions SET state='retired',retired_at=$4 WHERE issuer_id=$1 AND definition_id=$2 AND version=$3`,
		issuerID, id, version, ts); err != nil {
		return issuance.Definition{}, mapDefinitionPGError(err)
	}
	d.State = issuance.DefinitionRetired
	d.RetiredAt = &ts
	if err := appendPostgresAudit(ctx, tx, newPostgresAuditEvent(tenantID, actorID, "definition.retired", id+"@"+version, "succeeded", correlationID, ts)); err != nil {
		return issuance.Definition{}, mapDefinitionPGError(err)
	}
	return d, nil
}

func getDefinitionTx(ctx context.Context, tx pgx.Tx, issuerID, id, version string) (issuance.Definition, error) {
	if !validID(issuerID) {
		return issuance.Definition{}, issuance.ErrDefinitionNotFound
	}
	d, err := scanDefinitionRow(tx.QueryRow(ctx,
		selectDefinitionCols+` WHERE issuer_id=$1 AND definition_id=$2 AND version=$3`,
		issuerID, id, version))
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.Definition{}, issuance.ErrDefinitionNotFound
	}
	return d, err
}

func listAuditEventsTx(ctx context.Context, tx pgx.Tx, actionFilter string) ([]issuance.AuditRecord, error) {
	rows, err := tx.Query(ctx,
		`SELECT event_id,tenant_id::text,actor_id,action,target_id,outcome,correlation_id,occurred_at
		 FROM issuance.audit_events WHERE ($1='' OR action=$1) ORDER BY occurred_at,event_id`, actionFilter)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []issuance.AuditRecord
	for rows.Next() {
		var r issuance.AuditRecord
		if err := rows.Scan(&r.EventID, &r.TenantID, &r.ActorID, &r.Action, &r.TargetID, &r.Outcome, &r.CorrelationID, &r.OccurredAt); err != nil {
			return nil, err
		}
		r.OccurredAt = r.OccurredAt.UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// RegisterClient persists an M2M integration client with its SHA-256 secret hash and issuer grants.
func (b *IssuanceBackend) RegisterClient(
	ctx context.Context,
	tenantID, clientID, clientName, rawSecret string,
	allowedIssuers, scopes []string,
	expiresAt *time.Time,
	actorID, correlationID string,
	now time.Time,
) error {
	secretHash, err := issuance.HashClientSecret(rawSecret)
	if err != nil {
		return err
	}
	summary := issuance.ClientSummary{
		ClientID:       clientID,
		TenantID:       tenantID,
		ClientName:     clientName,
		AllowedIssuers: allowedIssuers,
		Scopes:         scopes,
		ExpiresAt:      expiresAt,
	}
	return WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
		return registerHashedClientTx(ctx, tx, tenantID, summary, secretHash, actorID, correlationID, now)
	})
}

// RevokeClient revokes an integration client inside tenantID (404 cross-tenant).
func (b *IssuanceBackend) RevokeClient(ctx context.Context, tenantID, clientID, actorID, correlationID string, now time.Time) error {
	return WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
		return revokeClientTx(ctx, tx, tenantID, clientID, actorID, correlationID, now)
	})
}

// CreateDraftDefinition inserts a new draft definition version inside Postgres.
func (b *IssuanceBackend) CreateDraftDefinition(ctx context.Context, def issuance.Definition, actorID, correlationID string, now time.Time) error {
	return WithIssuanceTenant(ctx, b.pool, def.TenantID, func(tx pgx.Tx) error {
		return createDraftDefinitionTx(ctx, tx, def.TenantID, def, actorID, correlationID, now)
	})
}

// ReplaceDraftDefinition updates a mutable draft version; published/retired versions are rejected.
func (b *IssuanceBackend) ReplaceDraftDefinition(ctx context.Context, def issuance.Definition, actorID, correlationID string, now time.Time) error {
	return WithIssuanceTenant(ctx, b.pool, def.TenantID, func(tx pgx.Tx) error {
		return replaceDraftDefinitionTx(ctx, tx, def.TenantID, def, actorID, correlationID, now)
	})
}

// PublishDefinition computes the canonical SHA-256 hash and freezes the version.
func (b *IssuanceBackend) PublishDefinition(ctx context.Context, tenantID, issuerID, id, version, actorID, correlationID string, now time.Time) (issuance.Definition, error) {
	var out issuance.Definition
	err := WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
		d, err := publishDefinitionTx(ctx, tx, tenantID, issuerID, id, version, actorID, correlationID, now)
		out = d
		return err
	})
	return out, err
}

// RetireDefinition marks a published definition version retired (terminal).
func (b *IssuanceBackend) RetireDefinition(ctx context.Context, tenantID, issuerID, id, version, actorID, correlationID string, now time.Time) error {
	return WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
		_, err := retireDefinitionTx(ctx, tx, tenantID, issuerID, id, version, actorID, correlationID, now)
		return err
	})
}

// GetDefinition reads a definition version in any state inside tenantID.
func (b *IssuanceBackend) GetDefinition(ctx context.Context, tenantID, issuerID, id, version string) (issuance.Definition, error) {
	var out issuance.Definition
	err := WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
		d, err := getDefinitionTx(ctx, tx, issuerID, id, version)
		out = d
		return err
	})
	return out, err
}

// ListAuditEvents returns secret-free audit events strictly within tenantID.
func (b *IssuanceBackend) ListAuditEvents(ctx context.Context, tenantID, actionFilter string) ([]issuance.AuditRecord, error) {
	var out []issuance.AuditRecord
	err := WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := listAuditEventsTx(ctx, tx, actionFilter)
		out = rows
		return err
	})
	return out, err
}

func mapFoundationPGError(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}
	switch pgErr.Code {
	case "23505", "23503", "23514":
		return issuance.ErrInvalidFoundationInput
	default:
		return err
	}
}

func mapKeyPGError(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}
	switch pgErr.Code {
	case "23505":
		return issuance.ErrKeyConflict
	case "23503", "23514":
		return issuance.ErrInvalidFoundationInput
	default:
		return err
	}
}

func mapDefinitionPGError(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}
	switch pgErr.Code {
	case "23505":
		return issuance.ErrDefinitionConflict
	case "22023":
		return issuance.ErrDefinitionImmutable
	case "23503", "23514":
		return issuance.ErrInvalidFoundationInput
	default:
		return err
	}
}

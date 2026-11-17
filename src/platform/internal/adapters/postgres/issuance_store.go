package postgres

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
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

func scanDefinitionRow(row pgx.Row) (issuance.Definition, error) {
	var d issuance.Definition
	var fieldsRaw []byte
	var validitySecs int64
	var state string
	var pubAt, retAt *time.Time
	err := row.Scan(&d.TenantID, &d.IssuerID, &d.ID, &d.Version, &d.ConfigurationID,
		&d.DisplayName, &d.Locale, &d.Contexts, &d.Types, &fieldsRaw, &validitySecs,
		&state, &d.Hash, &d.CreatedAt, &pubAt, &retAt)
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

func (t *postgresIssuanceTx) GetIssuableDefinition(issuerID, id, version string) (issuance.Definition, error) {
	if !validID(issuerID) {
		return issuance.Definition{}, issuance.ErrDefinitionNotFound
	}
	d, err := scanDefinitionRow(t.tx.QueryRow(t.ctx,
		`SELECT tenant_id::text,issuer_id::text,definition_id,version,configuration_id,display_name,locale,contexts,types,fields_json,default_validity_seconds,state,content_hash,created_at,published_at,retired_at
		 FROM definition.definition_versions WHERE issuer_id=$1 AND definition_id=$2 AND version=$3`,
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
		`SELECT tenant_id::text,issuer_id::text,definition_id,version,configuration_id,display_name,locale,contexts,types,fields_json,default_validity_seconds,state,content_hash,created_at,published_at,retired_at
		 FROM definition.definition_versions WHERE issuer_id=$1 AND state='published' ORDER BY definition_id,version`, issuerID)
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
		`INSERT INTO issuance.issuance_requests(request_id,tenant_id,issuer_id,client_id,definition_id,definition_version,configuration_id,claims_ciphertext,claims_nonce,claims_key_version,offer_ref,offer_ciphertext,offer_nonce,offer_key_version,offer_state,issuance_state,source_system,source_reference,created_at,expires_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
		req.ID, req.TenantID, req.IssuerID, req.ClientID, req.DefID, req.DefVersion, req.ConfigID,
		req.ClaimsCipher, req.ClaimsNonce, req.ClaimsKeyVer, req.OfferRef, req.OfferCipher, req.OfferNonce, req.OfferKeyVer,
		req.OfferState, req.IssuanceState, req.SourceSystem, req.SourceReference, req.CreatedAt.UTC(), req.ExpiresAt.UTC())
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
		&r.OfferState, &r.IssuanceState, &r.SourceSystem, &r.SourceReference, &r.CreatedAt, &r.ExpiresAt)
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

const selectRequestCols = `SELECT request_id,tenant_id::text,issuer_id::text,client_id::text,definition_id,definition_version,configuration_id,claims_ciphertext,claims_nonce,claims_key_version,offer_ref,offer_ciphertext,offer_nonce,offer_key_version,offer_state,issuance_state,source_system,source_reference,created_at,expires_at FROM issuance.issuance_requests`

func (t *postgresIssuanceTx) GetRequestForClient(requestID, clientID string) (issuance.StoredRequest, bool, error) {
	if !validID(clientID) || requestID == "" {
		return issuance.StoredRequest{}, false, nil
	}
	return scanStoredRequest(t.tx.QueryRow(t.ctx, selectRequestCols+` WHERE request_id=$1 AND client_id=$2`, requestID, clientID))
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
	var redeemedAt *time.Time
	var offerState string
	err := t.tx.QueryRow(t.ctx,
		`SELECT o.tenant_id::text,o.issuer_id::text,o.issuer_uri,o.request_id,o.configuration_id,o.expires_at,o.redeemed_at,r.offer_state
		 FROM issuance.credential_offers o
		 JOIN issuance.issuance_requests r ON r.tenant_id=o.tenant_id AND r.request_id=o.request_id
		 WHERE o.code_hash=$1
		 FOR UPDATE`, codeHash[:]).
		Scan(&out.TenantID, &out.IssuerID, &out.IssuerURI, &out.RequestID, &out.ConfigID, &out.ExpiresAt, &redeemedAt, &offerState)
	if errors.Is(err, pgx.ErrNoRows) || err != nil {
		return issuance.StoredOffer{}, issuance.ErrOfferInvalid
	}
	nowUTC := now.UTC()
	out.ExpiresAt = out.ExpiresAt.UTC()
	if redeemedAt != nil || !nowUTC.Before(out.ExpiresAt) || offerState != "ready" {
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

func (t *postgresIssuanceTx) MarkIssued(requestID string, tokenHash [32]byte, now time.Time) error {
	nowUTC := now.UTC()
	tag, err := t.tx.Exec(t.ctx,
		`UPDATE issuance.issuance_requests SET issuance_state='issued',issued_at=$2 WHERE request_id=$1 AND issuance_state='prepared'`,
		requestID, nowUTC)
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

func (t *postgresIssuanceTx) AppendAudit(rec issuance.AuditRecord) error {
	return appendPostgresAudit(t.ctx, t.tx, rec)
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
		_, err := tx.Exec(ctx,
			`INSERT INTO tenancy.issuers(issuer_id,tenant_id,slug,issuer_uri,display_name,state,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
			rec.IssuerID, rec.TenantID, rec.Slug, rec.IssuerURI, rec.DisplayName, string(rec.State), rec.CreatedAt)
		return err
	})
	if err != nil {
		return issuance.IssuerRecord{}, mapFoundationPGError(err)
	}
	return rec, nil
}

// RegisterKey persists an active ES256 public key metadata row (no private key in SQL).
func (b *IssuanceBackend) RegisterKey(ctx context.Context, tenantID, issuerID, kid, kmsKeyRef string, jwk issuance.PublicJWK, actorID, correlationID string, now time.Time) error {
	if !validID(issuerID) || kid == "" || strings.TrimSpace(kmsKeyRef) == "" {
		return issuance.ErrInvalidFoundationInput
	}
	if _, err := issuance.DecodePublicJWK(jwk); err != nil {
		return issuance.ErrInvalidFoundationInput
	}
	err := WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO tenancy.issuer_keys(tenant_id,issuer_id,kid,kms_key_ref,alg,crv,x_coord,y_coord,state,created_at)
			 VALUES($1,$2,$3,$4,'ES256','P-256',$5,$6,'active',$7)`,
			tenantID, issuerID, kid, kmsKeyRef, jwk.X, jwk.Y, now.UTC()); err != nil {
			return err
		}
		return appendPostgresAudit(ctx, tx, newPostgresAuditEvent(tenantID, actorID, "issuer_key.registered", kid, "succeeded", correlationID, now))
	})
	return mapKeyPGError(err)
}

// RotateKey atomically retires any current active key and activates newKID.
func (b *IssuanceBackend) RotateKey(ctx context.Context, tenantID, issuerID, newKID, newKMSKeyRef string, newJWK issuance.PublicJWK, actorID, correlationID string, now time.Time) error {
	if !validID(issuerID) || newKID == "" || strings.TrimSpace(newKMSKeyRef) == "" {
		return issuance.ErrInvalidFoundationInput
	}
	if _, err := issuance.DecodePublicJWK(newJWK); err != nil {
		return issuance.ErrInvalidFoundationInput
	}
	ts := now.UTC()
	err := WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`UPDATE tenancy.issuer_keys SET state='retired',retired_at=$2 WHERE issuer_id=$1 AND state='active'`,
			issuerID, ts); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO tenancy.issuer_keys(tenant_id,issuer_id,kid,kms_key_ref,alg,crv,x_coord,y_coord,state,created_at)
			 VALUES($1,$2,$3,$4,'ES256','P-256',$5,$6,'active',$7)`,
			tenantID, issuerID, newKID, newKMSKeyRef, newJWK.X, newJWK.Y, ts); err != nil {
			return err
		}
		return appendPostgresAudit(ctx, tx, newPostgresAuditEvent(tenantID, actorID, "issuer_key.rotated", newKID, "succeeded", correlationID, ts))
	})
	return mapKeyPGError(err)
}

// CompromiseKey marks kid as compromised, omitting it from JWKS and preventing signing.
func (b *IssuanceBackend) CompromiseKey(ctx context.Context, tenantID, issuerID, kid, actorID, correlationID string, now time.Time) error {
	if !validID(issuerID) || kid == "" {
		return issuance.ErrResourceNotFound
	}
	ts := now.UTC()
	return WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
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
	})
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
	if !validID(clientID) || strings.TrimSpace(clientName) == "" || len(allowedIssuers) == 0 || len(scopes) == 0 {
		return issuance.ErrInvalidFoundationInput
	}
	if expiresAt != nil && !expiresAt.UTC().After(now.UTC()) {
		return issuance.ErrInvalidFoundationInput
	}
	secretHash, err := issuance.HashClientSecret(rawSecret)
	if err != nil {
		return err
	}
	for _, sc := range scopes {
		if !issuance.AllowedIntegrationScope(sc) {
			return issuance.ErrInvalidFoundationInput
		}
	}
	for _, id := range allowedIssuers {
		if !validID(id) {
			return issuance.ErrInvalidFoundationInput
		}
	}
	ts := now.UTC()
	var expPtr *time.Time
	if expiresAt != nil {
		t := expiresAt.UTC()
		expPtr = &t
	}
	err = WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO tenancy.integration_clients(client_id,tenant_id,client_name,secret_hash,scopes,state,created_at,expires_at)
			 VALUES($1,$2,$3,$4,$5,'active',$6,$7)`,
			clientID, tenantID, clientName, secretHash[:], scopes, ts, expPtr); err != nil {
			return err
		}
		for _, issuerID := range allowedIssuers {
			if _, err := tx.Exec(ctx,
				`INSERT INTO tenancy.integration_client_grants(tenant_id,client_id,issuer_id,created_at) VALUES($1,$2,$3,$4)`,
				tenantID, clientID, issuerID, ts); err != nil {
				return err
			}
		}
		return appendPostgresAudit(ctx, tx, newPostgresAuditEvent(tenantID, actorID, "integration_client.registered", clientID, "succeeded", correlationID, ts))
	})
	return mapFoundationPGError(err)
}

// RevokeClient revokes an integration client inside tenantID (404 cross-tenant).
func (b *IssuanceBackend) RevokeClient(ctx context.Context, tenantID, clientID, actorID, correlationID string, now time.Time) error {
	if !validID(clientID) {
		return issuance.ErrResourceNotFound
	}
	ts := now.UTC()
	return WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
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
	})
}

// CreateDraftDefinition inserts a new draft definition version inside Postgres.
func (b *IssuanceBackend) CreateDraftDefinition(ctx context.Context, def issuance.Definition, actorID, correlationID string, now time.Time) error {
	if !validID(def.IssuerID) || issuance.ValidateDefinition(def) != nil {
		return issuance.ErrInvalidFoundationInput
	}
	fieldsJSON, err := json.Marshal(def.Fields)
	if err != nil {
		return issuance.ErrInvalidFoundationInput
	}
	contexts := def.Contexts
	if contexts == nil {
		contexts = []string{}
	}
	ts := now.UTC()
	err = WithIssuanceTenant(ctx, b.pool, def.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO definition.credential_definitions(tenant_id,issuer_id,definition_id,created_at) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
			def.TenantID, def.IssuerID, def.ID, ts); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO definition.definition_versions(tenant_id,issuer_id,definition_id,version,configuration_id,display_name,locale,contexts,types,fields_json,default_validity_seconds,state,content_hash,created_at)
			 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'draft','',$12)`,
			def.TenantID, def.IssuerID, def.ID, def.Version, def.ConfigurationID, def.DisplayName,
			def.Locale, contexts, def.Types, fieldsJSON, int64(def.DefaultValidity/time.Second), ts)
		if err != nil {
			return err
		}
		return appendPostgresAudit(ctx, tx, newPostgresAuditEvent(def.TenantID, actorID, "definition.draft_created", def.Ref(), "succeeded", correlationID, ts))
	})
	return mapDefinitionPGError(err)
}

// ReplaceDraftDefinition updates a mutable draft version; published/retired versions are rejected.
func (b *IssuanceBackend) ReplaceDraftDefinition(ctx context.Context, def issuance.Definition, actorID, correlationID string, now time.Time) error {
	if !validID(def.IssuerID) || issuance.ValidateDefinition(def) != nil {
		return issuance.ErrInvalidFoundationInput
	}
	fieldsJSON, err := json.Marshal(def.Fields)
	if err != nil {
		return issuance.ErrInvalidFoundationInput
	}
	contexts := def.Contexts
	if contexts == nil {
		contexts = []string{}
	}
	ts := now.UTC()
	err = WithIssuanceTenant(ctx, b.pool, def.TenantID, func(tx pgx.Tx) error {
		var state string
		err := tx.QueryRow(ctx,
			`SELECT state FROM definition.definition_versions WHERE issuer_id=$1 AND definition_id=$2 AND version=$3 FOR UPDATE`,
			def.IssuerID, def.ID, def.Version).Scan(&state)
		if errors.Is(err, pgx.ErrNoRows) {
			return issuance.ErrDefinitionNotFound
		}
		if err != nil {
			return err
		}
		if state != string(issuance.DefinitionDraft) {
			return issuance.ErrDefinitionImmutable
		}
		_, err = tx.Exec(ctx,
			`UPDATE definition.definition_versions
			 SET configuration_id=$4,display_name=$5,locale=$6,contexts=$7,types=$8,fields_json=$9,default_validity_seconds=$10
			 WHERE issuer_id=$1 AND definition_id=$2 AND version=$3`,
			def.IssuerID, def.ID, def.Version, def.ConfigurationID, def.DisplayName, def.Locale, contexts, def.Types, fieldsJSON, int64(def.DefaultValidity/time.Second))
		if err != nil {
			return err
		}
		return appendPostgresAudit(ctx, tx, newPostgresAuditEvent(def.TenantID, actorID, "definition.draft_replaced", def.Ref(), "succeeded", correlationID, ts))
	})
	return mapDefinitionPGError(err)
}

// PublishDefinition computes the canonical SHA-256 hash and freezes the version.
func (b *IssuanceBackend) PublishDefinition(ctx context.Context, tenantID, issuerID, id, version, actorID, correlationID string, now time.Time) (issuance.Definition, error) {
	if !validID(issuerID) {
		return issuance.Definition{}, issuance.ErrDefinitionNotFound
	}
	ts := now.UTC()
	var out issuance.Definition
	err := WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
		d, err := scanDefinitionRow(tx.QueryRow(ctx,
			`SELECT tenant_id::text,issuer_id::text,definition_id,version,configuration_id,display_name,locale,contexts,types,fields_json,default_validity_seconds,state,content_hash,created_at,published_at,retired_at
			 FROM definition.definition_versions WHERE issuer_id=$1 AND definition_id=$2 AND version=$3 FOR UPDATE`,
			issuerID, id, version))
		if errors.Is(err, pgx.ErrNoRows) {
			return issuance.ErrDefinitionNotFound
		}
		if err != nil {
			return err
		}
		if d.State != issuance.DefinitionDraft {
			return issuance.ErrDefinitionImmutable
		}
		hash, err := issuance.ComputeDefinitionHash(d)
		if err != nil {
			return issuance.ErrInvalidFoundationInput
		}
		if _, err := tx.Exec(ctx,
			`UPDATE definition.definition_versions SET state='published',content_hash=$4,published_at=$5
			 WHERE issuer_id=$1 AND definition_id=$2 AND version=$3`,
			issuerID, id, version, hash, ts); err != nil {
			return err
		}
		d.State = issuance.DefinitionPublished
		d.Hash = hash
		d.PublishedAt = &ts
		out = d
		return appendPostgresAudit(ctx, tx, newPostgresAuditEvent(tenantID, actorID, "definition.published", d.Ref(), "succeeded", correlationID, ts))
	})
	if err != nil {
		return issuance.Definition{}, mapDefinitionPGError(err)
	}
	return out, nil
}

// RetireDefinition marks a published definition version retired (terminal).
func (b *IssuanceBackend) RetireDefinition(ctx context.Context, tenantID, issuerID, id, version, actorID, correlationID string, now time.Time) error {
	if !validID(issuerID) {
		return issuance.ErrDefinitionNotFound
	}
	ts := now.UTC()
	err := WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
		var state string
		err := tx.QueryRow(ctx,
			`SELECT state FROM definition.definition_versions WHERE issuer_id=$1 AND definition_id=$2 AND version=$3 FOR UPDATE`,
			issuerID, id, version).Scan(&state)
		if errors.Is(err, pgx.ErrNoRows) {
			return issuance.ErrDefinitionNotFound
		}
		if err != nil {
			return err
		}
		if state != string(issuance.DefinitionPublished) {
			return issuance.ErrDefinitionImmutable
		}
		if _, err := tx.Exec(ctx,
			`UPDATE definition.definition_versions SET state='retired',retired_at=$4 WHERE issuer_id=$1 AND definition_id=$2 AND version=$3`,
			issuerID, id, version, ts); err != nil {
			return err
		}
		return appendPostgresAudit(ctx, tx, newPostgresAuditEvent(tenantID, actorID, "definition.retired", id+"@"+version, "succeeded", correlationID, ts))
	})
	return mapDefinitionPGError(err)
}

// GetDefinition reads a definition version in any state inside tenantID.
func (b *IssuanceBackend) GetDefinition(ctx context.Context, tenantID, issuerID, id, version string) (issuance.Definition, error) {
	if !validID(issuerID) {
		return issuance.Definition{}, issuance.ErrDefinitionNotFound
	}
	var out issuance.Definition
	err := WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
		d, err := scanDefinitionRow(tx.QueryRow(ctx,
			`SELECT tenant_id::text,issuer_id::text,definition_id,version,configuration_id,display_name,locale,contexts,types,fields_json,default_validity_seconds,state,content_hash,created_at,published_at,retired_at
			 FROM definition.definition_versions WHERE issuer_id=$1 AND definition_id=$2 AND version=$3`,
			issuerID, id, version))
		if errors.Is(err, pgx.ErrNoRows) {
			return issuance.ErrDefinitionNotFound
		}
		out = d
		return err
	})
	return out, err
}

// ListAuditEvents returns secret-free audit events strictly within tenantID.
func (b *IssuanceBackend) ListAuditEvents(ctx context.Context, tenantID, actionFilter string) ([]issuance.AuditRecord, error) {
	var out []issuance.AuditRecord
	err := WithIssuanceTenant(ctx, b.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT event_id,tenant_id::text,actor_id,action,target_id,outcome,correlation_id,occurred_at
			 FROM issuance.audit_events WHERE ($1='' OR action=$1) ORDER BY occurred_at,event_id`, actionFilter)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r issuance.AuditRecord
			if err := rows.Scan(&r.EventID, &r.TenantID, &r.ActorID, &r.Action, &r.TargetID, &r.Outcome, &r.CorrelationID, &r.OccurredAt); err != nil {
				return err
			}
			r.OccurredAt = r.OccurredAt.UTC()
			out = append(out, r)
		}
		return rows.Err()
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

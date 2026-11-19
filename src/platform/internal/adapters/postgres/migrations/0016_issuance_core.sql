-- Phase 2 & 3 issuance core persistence (definitions, encrypted requests, offers, nonces, tokens, audit).
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'hukid_issuance_locator') THEN
    CREATE ROLE hukid_issuance_locator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'hukid_issuance_locator'
    AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
    OR EXISTS (SELECT FROM pg_auth_members WHERE member = 'hukid_issuance_locator'::regrole) THEN
    RAISE EXCEPTION 'Unsafe pre-existing issuance locator role';
  END IF;
END $$;

CREATE SCHEMA definition AUTHORIZATION hukid_owner;
CREATE SCHEMA issuance AUTHORIZATION hukid_owner;
SET LOCAL ROLE hukid_owner;

CREATE TABLE definition.credential_definitions (
  tenant_id uuid NOT NULL,
  issuer_id uuid NOT NULL,
  definition_id text NOT NULL CHECK (definition_id ~ '^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, issuer_id, definition_id),
  FOREIGN KEY (tenant_id, issuer_id) REFERENCES tenancy.issuers(tenant_id, issuer_id)
);

CREATE TABLE definition.definition_versions (
  tenant_id uuid NOT NULL,
  issuer_id uuid NOT NULL,
  definition_id text NOT NULL,
  version text NOT NULL CHECK (version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'),
  configuration_id text NOT NULL CHECK (configuration_id ~ '^[a-z0-9][a-z0-9._-]{2,127}$'),
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
  locale text NOT NULL DEFAULT '' CHECK (length(locale) <= 35),
  contexts text[] NOT NULL DEFAULT '{}' CHECK (cardinality(contexts) <= 8),
  types text[] NOT NULL CHECK (cardinality(types) BETWEEN 1 AND 8 AND NOT ('VerifiableCredential' = ANY(types))),
  fields_json jsonb NOT NULL CHECK (jsonb_typeof(fields_json) = 'object'),
  default_validity_seconds bigint NOT NULL CHECK (default_validity_seconds >= 0),
  state text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'published', 'retired')),
  content_hash text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  retired_at timestamptz,
  PRIMARY KEY (tenant_id, issuer_id, definition_id, version),
  UNIQUE (tenant_id, issuer_id, configuration_id),
  FOREIGN KEY (tenant_id, issuer_id, definition_id)
    REFERENCES definition.credential_definitions(tenant_id, issuer_id, definition_id),
  CHECK (
    (state = 'draft' AND content_hash = '' AND published_at IS NULL AND retired_at IS NULL) OR
    (state = 'published' AND length(content_hash) = 64 AND published_at IS NOT NULL AND retired_at IS NULL) OR
    (state = 'retired' AND length(content_hash) = 64 AND published_at IS NOT NULL AND retired_at IS NOT NULL)
  ),
  CHECK (published_at IS NULL OR published_at >= created_at),
  CHECK (retired_at IS NULL OR retired_at >= published_at)
);
CREATE INDEX definition_versions_published_idx ON definition.definition_versions(tenant_id, issuer_id, state);

CREATE FUNCTION definition.enforce_immutability() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.state <> 'draft' THEN
      RAISE EXCEPTION 'published or retired definition version cannot be deleted' USING ERRCODE = '22023';
    END IF;
    RETURN OLD;
  END IF;
  IF OLD.state = 'retired' THEN
    RAISE EXCEPTION 'retired definition version is immutable' USING ERRCODE = '22023';
  END IF;
  IF OLD.state = 'published' THEN
    IF NEW.state <> 'retired'
       OR NEW.retired_at IS NULL
       OR NEW.configuration_id IS DISTINCT FROM OLD.configuration_id
       OR NEW.display_name IS DISTINCT FROM OLD.display_name
       OR NEW.locale IS DISTINCT FROM OLD.locale
       OR NEW.contexts IS DISTINCT FROM OLD.contexts
       OR NEW.types IS DISTINCT FROM OLD.types
       OR NEW.fields_json IS DISTINCT FROM OLD.fields_json
       OR NEW.default_validity_seconds IS DISTINCT FROM OLD.default_validity_seconds
       OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.published_at IS DISTINCT FROM OLD.published_at THEN
      RAISE EXCEPTION 'published definition version is immutable' USING ERRCODE = '22023';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER definition_versions_immutability
  BEFORE UPDATE OR DELETE ON definition.definition_versions
  FOR EACH ROW EXECUTE FUNCTION definition.enforce_immutability();

CREATE TABLE issuance.issuance_requests (
  request_id text PRIMARY KEY CHECK (length(request_id) BETWEEN 3 AND 128),
  tenant_id uuid NOT NULL,
  issuer_id uuid NOT NULL,
  client_id uuid NOT NULL,
  definition_id text NOT NULL,
  definition_version text NOT NULL,
  configuration_id text NOT NULL,
  claims_ciphertext bytea NOT NULL CHECK (octet_length(claims_ciphertext) >= 16),
  claims_nonce bytea NOT NULL CHECK (octet_length(claims_nonce) = 12),
  claims_key_version text NOT NULL CHECK (length(claims_key_version) BETWEEN 1 AND 128),
  offer_ref text NOT NULL UNIQUE CHECK (length(offer_ref) BETWEEN 3 AND 128),
  offer_ciphertext bytea,
  offer_nonce bytea,
  offer_key_version text,
  offer_state text NOT NULL DEFAULT 'ready' CHECK (offer_state IN ('ready', 'redeemed', 'expired')),
  issuance_state text NOT NULL DEFAULT 'prepared' CHECK (issuance_state IN ('prepared', 'issued')),
  source_system text NOT NULL DEFAULT '' CHECK (length(source_system) <= 128),
  source_reference text NOT NULL DEFAULT '' CHECK (length(source_reference) <= 128),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
  issued_at timestamptz,
  UNIQUE (tenant_id, request_id),
  FOREIGN KEY (tenant_id, issuer_id) REFERENCES tenancy.issuers(tenant_id, issuer_id),
  FOREIGN KEY (tenant_id, client_id) REFERENCES tenancy.integration_clients(tenant_id, client_id),
  FOREIGN KEY (tenant_id, issuer_id, definition_id, definition_version)
    REFERENCES definition.definition_versions(tenant_id, issuer_id, definition_id, version),
  CHECK ((issuance_state = 'issued') = (issued_at IS NOT NULL)),
  CHECK (
    (offer_state = 'ready' AND offer_ciphertext IS NOT NULL AND octet_length(offer_ciphertext) >= 16 AND offer_nonce IS NOT NULL AND octet_length(offer_nonce) = 12 AND offer_key_version IS NOT NULL AND length(offer_key_version) BETWEEN 1 AND 128) OR
    (offer_state <> 'ready' AND offer_ciphertext IS NULL AND offer_nonce IS NULL AND offer_key_version IS NULL)
  )
);
CREATE INDEX issuance_requests_tenant_client_idx ON issuance.issuance_requests(tenant_id, client_id, created_at);

CREATE TABLE issuance.idempotency (
  tenant_id uuid NOT NULL,
  client_id uuid NOT NULL,
  key_hash bytea NOT NULL CHECK (octet_length(key_hash) = 32),
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  request_id text NOT NULL,
  issuer_id uuid NOT NULL,
  configuration_id text NOT NULL,
  offer_state text NOT NULL CHECK (offer_state IN ('ready', 'redeemed', 'expired')),
  issuance_state text NOT NULL CHECK (issuance_state IN ('prepared', 'issued')),
  credential_offer_uri text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, client_id, key_hash),
  FOREIGN KEY (tenant_id, client_id) REFERENCES tenancy.integration_clients(tenant_id, client_id),
  FOREIGN KEY (tenant_id, request_id) REFERENCES issuance.issuance_requests(tenant_id, request_id)
);

CREATE TABLE issuance.credential_offers (
  code_hash bytea PRIMARY KEY CHECK (octet_length(code_hash) = 32),
  tenant_id uuid NOT NULL,
  issuer_id uuid NOT NULL,
  issuer_uri text NOT NULL,
  request_id text NOT NULL UNIQUE,
  configuration_id text NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
  redeemed_at timestamptz,
  FOREIGN KEY (tenant_id, request_id) REFERENCES issuance.issuance_requests(tenant_id, request_id),
  FOREIGN KEY (tenant_id, issuer_id) REFERENCES tenancy.issuers(tenant_id, issuer_id),
  CHECK (redeemed_at IS NULL OR redeemed_at >= created_at)
);
CREATE INDEX credential_offers_expiry_idx ON issuance.credential_offers(tenant_id, expires_at);

CREATE TABLE issuance.nonces (
  nonce_hash bytea PRIMARY KEY CHECK (octet_length(nonce_hash) = 32),
  tenant_id uuid NOT NULL,
  issuer_id uuid NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
  consumed_at timestamptz,
  FOREIGN KEY (tenant_id, issuer_id) REFERENCES tenancy.issuers(tenant_id, issuer_id),
  CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);
CREATE INDEX nonces_expiry_idx ON issuance.nonces(tenant_id, expires_at);

CREATE TABLE issuance.access_tokens (
  token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  tenant_id uuid NOT NULL REFERENCES tenancy.tenants(tenant_id),
  token_class text NOT NULL CHECK (token_class IN ('integration', 'oid4vci')),
  audience text NOT NULL CHECK (length(audience) BETWEEN 1 AND 256),
  client_id uuid,
  scopes text[] NOT NULL DEFAULT '{}',
  allowed_issuers uuid[] NOT NULL DEFAULT '{}',
  request_id text,
  credential_id text NOT NULL DEFAULT '',
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
  used_at timestamptz,
  FOREIGN KEY (tenant_id, client_id) REFERENCES tenancy.integration_clients(tenant_id, client_id),
  FOREIGN KEY (tenant_id, request_id) REFERENCES issuance.issuance_requests(tenant_id, request_id),
  CHECK (
    (token_class = 'integration' AND client_id IS NOT NULL AND cardinality(scopes) >= 1 AND cardinality(allowed_issuers) >= 1 AND request_id IS NULL AND credential_id = '') OR
    (token_class = 'oid4vci' AND client_id IS NULL AND request_id IS NOT NULL AND length(credential_id) >= 3)
  ),
  CHECK (used_at IS NULL OR used_at >= issued_at)
);
CREATE INDEX access_tokens_expiry_idx ON issuance.access_tokens(tenant_id, expires_at);

CREATE TABLE issuance.audit_events (
  event_id text PRIMARY KEY CHECK (length(event_id) BETWEEN 5 AND 128),
  tenant_id uuid NOT NULL REFERENCES tenancy.tenants(tenant_id),
  actor_id text NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
  action text NOT NULL CHECK (length(action) BETWEEN 3 AND 128),
  target_id text NOT NULL CHECK (length(target_id) BETWEEN 1 AND 128),
  outcome text NOT NULL CHECK (outcome IN ('succeeded', 'denied')),
  correlation_id text NOT NULL DEFAULT '' CHECK (length(correlation_id) <= 128),
  occurred_at timestamptz NOT NULL
);
CREATE INDEX issuance_audit_events_tenant_idx ON issuance.audit_events(tenant_id, occurred_at, event_id);

GRANT USAGE ON SCHEMA definition, issuance TO hukid_issuance_runtime;
GRANT SELECT, INSERT, UPDATE ON definition.credential_definitions, definition.definition_versions TO hukid_issuance_runtime;
GRANT SELECT, INSERT, UPDATE ON issuance.issuance_requests, issuance.credential_offers, issuance.nonces, issuance.access_tokens TO hukid_issuance_runtime;
GRANT SELECT, INSERT ON issuance.idempotency, issuance.audit_events TO hukid_issuance_runtime;

DO $$
DECLARE tbl text;
BEGIN
  FOREACH tbl IN ARRAY ARRAY['credential_definitions', 'definition_versions'] LOOP
    EXECUTE format('ALTER TABLE definition.%I ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format('ALTER TABLE definition.%I FORCE ROW LEVEL SECURITY', tbl);
    EXECUTE format('CREATE POLICY issuance_tenant_scope ON definition.%I TO hukid_issuance_runtime USING (tenant_id = tenancy.current_tenant()) WITH CHECK (tenant_id = tenancy.current_tenant())', tbl);
  END LOOP;
  FOREACH tbl IN ARRAY ARRAY['issuance_requests', 'idempotency', 'credential_offers', 'nonces', 'access_tokens', 'audit_events'] LOOP
    EXECUTE format('ALTER TABLE issuance.%I ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format('ALTER TABLE issuance.%I FORCE ROW LEVEL SECURITY', tbl);
    EXECUTE format('CREATE POLICY issuance_tenant_scope ON issuance.%I TO hukid_issuance_runtime USING (tenant_id = tenancy.current_tenant()) WITH CHECK (tenant_id = tenancy.current_tenant())', tbl);
  END LOOP;
END $$;

GRANT USAGE ON SCHEMA tenancy, issuance TO hukid_issuance_locator;
GRANT SELECT(tenant_id, slug) ON tenancy.issuers TO hukid_issuance_locator;
GRANT SELECT(tenant_id, client_id) ON tenancy.integration_clients TO hukid_issuance_locator;
GRANT SELECT(tenant_id, code_hash) ON issuance.credential_offers TO hukid_issuance_locator;
GRANT SELECT(tenant_id, token_hash) ON issuance.access_tokens TO hukid_issuance_locator;

CREATE POLICY issuance_locator_issuers ON tenancy.issuers FOR SELECT TO hukid_issuance_locator USING (true);
CREATE POLICY issuance_locator_clients ON tenancy.integration_clients FOR SELECT TO hukid_issuance_locator USING (true);
CREATE POLICY issuance_locator_offers ON issuance.credential_offers FOR SELECT TO hukid_issuance_locator USING (true);
CREATE POLICY issuance_locator_tokens ON issuance.access_tokens FOR SELECT TO hukid_issuance_locator USING (true);

CREATE FUNCTION issuance.locate_issuer_by_slug(p_slug text) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$ SELECT tenant_id FROM tenancy.issuers WHERE slug = p_slug $$;

CREATE FUNCTION issuance.locate_client(p_client_id uuid) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$ SELECT tenant_id FROM tenancy.integration_clients WHERE client_id = p_client_id $$;

CREATE FUNCTION issuance.locate_offer(p_code_hash bytea) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$ SELECT tenant_id FROM issuance.credential_offers WHERE code_hash = p_code_hash AND octet_length(p_code_hash) = 32 $$;

CREATE FUNCTION issuance.locate_token(p_token_hash bytea) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$ SELECT tenant_id FROM issuance.access_tokens WHERE token_hash = p_token_hash AND octet_length(p_token_hash) = 32 $$;

RESET ROLE;
GRANT CREATE ON SCHEMA issuance TO hukid_issuance_locator;
ALTER FUNCTION issuance.locate_issuer_by_slug(text) OWNER TO hukid_issuance_locator;
ALTER FUNCTION issuance.locate_client(uuid) OWNER TO hukid_issuance_locator;
ALTER FUNCTION issuance.locate_offer(bytea) OWNER TO hukid_issuance_locator;
ALTER FUNCTION issuance.locate_token(bytea) OWNER TO hukid_issuance_locator;
REVOKE CREATE ON SCHEMA issuance FROM hukid_issuance_locator;
REVOKE ALL ON FUNCTION issuance.locate_issuer_by_slug(text), issuance.locate_client(uuid), issuance.locate_offer(bytea), issuance.locate_token(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION issuance.locate_issuer_by_slug(text), issuance.locate_client(uuid), issuance.locate_offer(bytea), issuance.locate_token(bytea) TO hukid_issuance_runtime;

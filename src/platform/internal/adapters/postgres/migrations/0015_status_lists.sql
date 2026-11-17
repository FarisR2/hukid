-- Phase 4 Bitstring Status Lists and credential revocation/suspension (HK-023, HK-050, HK-051).
CREATE SCHEMA status AUTHORIZATION hukid_owner;
SET LOCAL ROLE hukid_owner;

DO $$
DECLARE c_name text;
BEGIN
  SELECT conname INTO c_name
  FROM pg_constraint
  WHERE conrelid = 'tenancy.integration_clients'::regclass
    AND contype = 'c'
    AND pg_get_constraintdef(oid) LIKE '%issuance:create%';
  IF c_name IS NOT NULL THEN
    EXECUTE format('ALTER TABLE tenancy.integration_clients DROP CONSTRAINT %I', c_name);
  END IF;
END $$;

ALTER TABLE tenancy.integration_clients
  ADD CONSTRAINT integration_clients_scopes_allowed
  CHECK (cardinality(scopes) BETWEEN 1 AND 8 AND scopes <@ ARRAY['issuance:create', 'issuance:read', 'status:write']::text[]);

ALTER TABLE definition.definition_versions
  ADD COLUMN status_purposes text[] NOT NULL DEFAULT '{}'
  CHECK (cardinality(status_purposes) <= 2 AND status_purposes <@ ARRAY['revocation', 'suspension']::text[]);

CREATE OR REPLACE FUNCTION definition.enforce_immutability() RETURNS trigger
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
       OR NEW.status_purposes IS DISTINCT FROM OLD.status_purposes
       OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.published_at IS DISTINCT FROM OLD.published_at THEN
      RAISE EXCEPTION 'published definition version is immutable' USING ERRCODE = '22023';
    END IF;
  END IF;
  RETURN NEW;
END $$;

ALTER TABLE issuance.issuance_requests
  ADD COLUMN issued_credential_id text NOT NULL DEFAULT '';

CREATE TABLE status.status_lists (
  tenant_id uuid NOT NULL,
  issuer_id uuid NOT NULL,
  list_id text NOT NULL CHECK (length(list_id) BETWEEN 3 AND 128),
  purpose text NOT NULL CHECK (purpose IN ('revocation', 'suspension')),
  bitstring_size integer NOT NULL CHECK (bitstring_size > 0 AND bitstring_size % 8 = 0),
  next_index integer NOT NULL DEFAULT 0 CHECK (next_index >= 0 AND next_index <= bitstring_size),
  raw_bits bytea NOT NULL CHECK (octet_length(raw_bits) = bitstring_size / 8),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  published_version bigint NOT NULL DEFAULT 1 CHECK (published_version > 0 AND published_version <= version),
  published_jwt text NOT NULL CHECK (length(published_jwt) > 0),
  valid_from timestamptz NOT NULL,
  valid_until timestamptz NOT NULL CHECK (valid_until > valid_from),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, issuer_id, list_id),
  UNIQUE (tenant_id, issuer_id, purpose, list_id),
  FOREIGN KEY (tenant_id, issuer_id) REFERENCES tenancy.issuers(tenant_id, issuer_id)
);
CREATE INDEX status_lists_alloc_idx ON status.status_lists(tenant_id, issuer_id, purpose, updated_at);

CREATE TABLE status.issued_credentials (
  credential_id text PRIMARY KEY CHECK (length(credential_id) BETWEEN 3 AND 128),
  tenant_id uuid NOT NULL,
  issuer_id uuid NOT NULL,
  request_id text NOT NULL,
  client_id uuid NOT NULL,
  jws_digest text NOT NULL CHECK (jws_digest ~ '^sha256:[0-9a-f]{64}$'),
  revocation_list_id text NOT NULL DEFAULT '',
  revocation_index integer,
  suspension_list_id text NOT NULL DEFAULT '',
  suspension_index integer,
  desired_status text NOT NULL DEFAULT 'active' CHECK (desired_status IN ('active', 'suspended', 'revoked')),
  published_status text NOT NULL DEFAULT 'active' CHECK (published_status IN ('active', 'suspended', 'revoked')),
  status_version bigint NOT NULL DEFAULT 1 CHECK (status_version > 0),
  reason_code text NOT NULL DEFAULT '' CHECK (length(reason_code) <= 64),
  issued_at timestamptz NOT NULL,
  suspended_at timestamptz,
  revoked_at timestamptz,
  UNIQUE (tenant_id, request_id),
  FOREIGN KEY (tenant_id, issuer_id) REFERENCES tenancy.issuers(tenant_id, issuer_id),
  FOREIGN KEY (tenant_id, request_id) REFERENCES issuance.issuance_requests(tenant_id, request_id),
  FOREIGN KEY (tenant_id, client_id) REFERENCES tenancy.integration_clients(tenant_id, client_id),
  CHECK (
    (revocation_list_id = '' AND revocation_index IS NULL) OR
    (revocation_list_id <> '' AND revocation_index IS NOT NULL AND revocation_index >= 0)
  ),
  CHECK (
    (suspension_list_id = '' AND suspension_index IS NULL) OR
    (suspension_list_id <> '' AND suspension_index IS NOT NULL AND suspension_index >= 0)
  ),
  CHECK ((desired_status = 'revoked') = (revoked_at IS NOT NULL))
);
CREATE INDEX issued_credentials_tenant_issuer_idx ON status.issued_credentials(tenant_id, issuer_id, issued_at);

CREATE TABLE status.status_idempotency (
  tenant_id uuid NOT NULL,
  client_id uuid NOT NULL,
  key_hash bytea NOT NULL CHECK (octet_length(key_hash) = 32),
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  result_json jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, client_id, key_hash),
  FOREIGN KEY (tenant_id, client_id) REFERENCES tenancy.integration_clients(tenant_id, client_id)
);

GRANT USAGE ON SCHEMA status TO hukid_issuance_runtime;
GRANT SELECT, INSERT, UPDATE ON status.status_lists, status.issued_credentials TO hukid_issuance_runtime;
GRANT SELECT, INSERT ON status.status_idempotency TO hukid_issuance_runtime;

DO $$
DECLARE tbl text;
BEGIN
  FOREACH tbl IN ARRAY ARRAY['status_lists', 'issued_credentials', 'status_idempotency'] LOOP
    EXECUTE format('ALTER TABLE status.%I ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format('ALTER TABLE status.%I FORCE ROW LEVEL SECURITY', tbl);
    EXECUTE format('CREATE POLICY issuance_tenant_scope ON status.%I TO hukid_issuance_runtime USING (tenant_id = tenancy.current_tenant()) WITH CHECK (tenant_id = tenancy.current_tenant())', tbl);
  END LOOP;
END $$;

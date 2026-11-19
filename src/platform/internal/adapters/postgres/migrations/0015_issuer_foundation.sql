-- Phase 1 multi-tenant issuer foundation (HK-001, HK-002, HK-004).
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'hukid_issuance_runtime') THEN
    CREATE ROLE hukid_issuance_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'hukid_issuance_runtime'
    AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
    RAISE EXCEPTION 'Unsafe pre-existing issuance role';
  END IF;
END $$;
SET LOCAL ROLE hukid_owner;

CREATE TABLE tenancy.issuers (
  issuer_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenancy.tenants(tenant_id),
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9_-]{0,62}[a-z0-9]$|^[a-z0-9]$'),
  issuer_uri text NOT NULL UNIQUE CHECK (issuer_uri = 'https://issuer.hukid.pe/' || slug),
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'suspended')),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, issuer_id)
);
CREATE INDEX issuers_tenant_idx ON tenancy.issuers(tenant_id, created_at, issuer_id);

CREATE TABLE tenancy.issuer_keys (
  tenant_id uuid NOT NULL,
  issuer_id uuid NOT NULL,
  kid text NOT NULL CHECK (length(kid) BETWEEN 1 AND 128 AND position(' ' in kid) = 0),
  kms_key_ref text NOT NULL CHECK (length(kms_key_ref) BETWEEN 1 AND 512),
  alg text NOT NULL DEFAULT 'ES256' CHECK (alg = 'ES256'),
  crv text NOT NULL DEFAULT 'P-256' CHECK (crv = 'P-256'),
  x_coord text NOT NULL CHECK (length(x_coord) = 43),
  y_coord text NOT NULL CHECK (length(y_coord) = 43),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'retired', 'compromised')),
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  compromised_at timestamptz,
  PRIMARY KEY (tenant_id, issuer_id, kid),
  FOREIGN KEY (tenant_id, issuer_id) REFERENCES tenancy.issuers(tenant_id, issuer_id),
  CHECK (retired_at IS NULL OR retired_at >= created_at),
  CHECK (compromised_at IS NULL OR compromised_at >= created_at),
  CHECK (
    (state = 'active' AND retired_at IS NULL AND compromised_at IS NULL) OR
    (state = 'retired' AND retired_at IS NOT NULL AND compromised_at IS NULL) OR
    (state = 'compromised' AND compromised_at IS NOT NULL)
  )
);
CREATE UNIQUE INDEX issuer_keys_one_active ON tenancy.issuer_keys(tenant_id, issuer_id) WHERE state = 'active';

CREATE TABLE tenancy.integration_clients (
  client_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenancy.tenants(tenant_id),
  client_name text NOT NULL CHECK (length(client_name) BETWEEN 1 AND 200),
  secret_hash bytea NOT NULL CHECK (octet_length(secret_hash) = 32),
  scopes text[] NOT NULL CHECK (cardinality(scopes) BETWEEN 1 AND 8 AND scopes <@ ARRAY['issuance:create', 'issuance:read']::text[]),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  UNIQUE (tenant_id, client_id),
  CHECK (expires_at IS NULL OR expires_at > created_at),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at),
  CHECK ((state = 'revoked') = (revoked_at IS NOT NULL))
);
CREATE INDEX integration_clients_tenant_idx ON tenancy.integration_clients(tenant_id, created_at, client_id);

CREATE TABLE tenancy.integration_client_grants (
  tenant_id uuid NOT NULL,
  client_id uuid NOT NULL,
  issuer_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, client_id, issuer_id),
  FOREIGN KEY (tenant_id, client_id) REFERENCES tenancy.integration_clients(tenant_id, client_id),
  FOREIGN KEY (tenant_id, issuer_id) REFERENCES tenancy.issuers(tenant_id, issuer_id)
);

GRANT USAGE ON SCHEMA tenancy TO hukid_issuance_runtime;
GRANT EXECUTE ON FUNCTION tenancy.current_tenant() TO hukid_issuance_runtime;
GRANT SELECT ON tenancy.tenants TO hukid_issuance_runtime;
GRANT SELECT, INSERT, UPDATE ON tenancy.issuers, tenancy.issuer_keys, tenancy.integration_clients TO hukid_issuance_runtime;
GRANT SELECT, INSERT, DELETE ON tenancy.integration_client_grants TO hukid_issuance_runtime;

CREATE POLICY issuance_tenant_read ON tenancy.tenants FOR SELECT TO hukid_issuance_runtime
  USING (tenant_id = tenancy.current_tenant());

DO $$
DECLARE name text;
BEGIN
  FOREACH name IN ARRAY ARRAY['issuers', 'issuer_keys', 'integration_clients', 'integration_client_grants'] LOOP
    EXECUTE format('ALTER TABLE tenancy.%I ENABLE ROW LEVEL SECURITY', name);
    EXECUTE format('ALTER TABLE tenancy.%I FORCE ROW LEVEL SECURITY', name);
    EXECUTE format('CREATE POLICY issuance_tenant_scope ON tenancy.%I TO hukid_issuance_runtime USING (tenant_id = tenancy.current_tenant()) WITH CHECK (tenant_id = tenancy.current_tenant())', name);
  END LOOP;
END $$;

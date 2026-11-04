-- New console-owned DDL, not the missing historical issuer migrations.
DO $$
DECLARE name text;
BEGIN
  FOREACH name IN ARRAY ARRAY['hukid_owner','hukid_tenant_runtime','hukid_session_runtime','hukid_context_runtime','hukid_context_reader'] LOOP
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = name) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', name);
    END IF;
    IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = name AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
      RAISE EXCEPTION 'Unsafe pre-existing console role';
    END IF;
  END LOOP;
END $$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA tenancy AUTHORIZATION hukid_owner;
CREATE SCHEMA console_auth AUTHORIZATION hukid_owner;
CREATE SCHEMA platform AUTHORIZATION hukid_owner;
SET LOCAL ROLE hukid_owner;

CREATE TABLE tenancy.operator_identities (
  operator_identity_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oidc_issuer text NOT NULL CHECK (length(oidc_issuer) BETWEEN 1 AND 2048),
  subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (oidc_issuer, subject)
);
CREATE TABLE tenancy.tenants (
  tenant_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','suspended')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE tenancy.memberships (
  membership_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenancy.tenants(tenant_id),
  operator_identity_id uuid NOT NULL REFERENCES tenancy.operator_identities(operator_identity_id),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','suspended','revoked')),
  authorization_revision bigint NOT NULL DEFAULT 1 CHECK (authorization_revision > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, operator_identity_id),
  UNIQUE (tenant_id, membership_id)
);
CREATE INDEX memberships_operator_idx ON tenancy.memberships(operator_identity_id, tenant_id);
CREATE TABLE tenancy.membership_roles (
  tenant_id uuid NOT NULL,
  membership_id uuid NOT NULL,
  role text NOT NULL CHECK (role IN ('tenant_admin','security_admin','issuer_operator','support_readonly')),
  PRIMARY KEY (tenant_id, membership_id, role),
  FOREIGN KEY (tenant_id, membership_id) REFERENCES tenancy.memberships(tenant_id, membership_id)
);

CREATE TABLE console_auth.session_families (
  family_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  operator_identity_id uuid NOT NULL REFERENCES tenancy.operator_identities(operator_identity_id),
  created_at timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  auth_time timestamptz NOT NULL,
  amr text[] NOT NULL CHECK (cardinality(amr) > 0),
  acr text NOT NULL CHECK (length(acr) BETWEEN 1 AND 255),
  original_grant text NOT NULL CHECK (original_grant = 'authorization_code'),
  policy_version text NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 128),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','revoked','expired')),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  UNIQUE (family_id, operator_identity_id),
  UNIQUE (family_id, operator_identity_id, absolute_expires_at),
  CHECK (absolute_expires_at > created_at)
);
CREATE TABLE console_auth.sessions (
  session_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  family_id uuid NOT NULL,
  operator_identity_id uuid NOT NULL,
  generation bigint NOT NULL CHECK (generation > 0),
  cookie_hash bytea NOT NULL UNIQUE CHECK (octet_length(cookie_hash) = 32),
  csrf_hash bytea NOT NULL CHECK (octet_length(csrf_hash) = 32),
  created_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  idle_expires_at timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  active_tenant_id uuid,
  authorization_revision bigint CHECK (authorization_revision > 0),
  secret_ciphertext bytea,
  secret_nonce bytea,
  secret_key_version text,
  refresh_digest bytea CHECK (octet_length(refresh_digest) = 32),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','rotated','revoked','expired')),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  UNIQUE (family_id, generation),
  FOREIGN KEY (family_id, operator_identity_id, absolute_expires_at) REFERENCES console_auth.session_families(family_id, operator_identity_id, absolute_expires_at),
  FOREIGN KEY (active_tenant_id, operator_identity_id) REFERENCES tenancy.memberships(tenant_id, operator_identity_id),
  CHECK ((active_tenant_id IS NULL) = (authorization_revision IS NULL)),
  CHECK (last_seen_at >= created_at AND idle_expires_at > last_seen_at AND idle_expires_at <= absolute_expires_at),
  CHECK ((secret_ciphertext IS NULL AND secret_nonce IS NULL AND secret_key_version IS NULL AND refresh_digest IS NULL AND state <> 'active') OR
         (state = 'active' AND secret_ciphertext IS NOT NULL AND octet_length(secret_ciphertext) >= 16 AND secret_nonce IS NOT NULL AND octet_length(secret_nonce) = 12 AND secret_key_version IS NOT NULL AND length(secret_key_version) > 0 AND refresh_digest IS NOT NULL))
);
CREATE INDEX sessions_expiry_idx ON console_auth.sessions(idle_expires_at);
CREATE TABLE console_auth.oidc_transactions (
  transaction_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  family_id uuid REFERENCES console_auth.session_families(family_id),
  purpose text NOT NULL CHECK (purpose IN ('login','step_up')),
  state_hash bytea NOT NULL UNIQUE CHECK (octet_length(state_hash) = 32),
  nonce_hash bytea NOT NULL CHECK (octet_length(nonce_hash) = 32),
  binding_hash bytea NOT NULL CHECK (octet_length(binding_hash) = 32),
  oidc_issuer text NOT NULL,
  client_id text NOT NULL,
  redirect_uri text NOT NULL,
  return_to text NOT NULL CHECK (return_to = '/'),
  verifier_ciphertext bytea,
  verifier_nonce bytea,
  verifier_key_version text,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  CHECK (expires_at > created_at),
  CHECK (consumed_at IS NULL OR consumed_at >= created_at),
  CHECK ((purpose = 'login' AND family_id IS NULL) OR (purpose = 'step_up' AND family_id IS NOT NULL)),
  CHECK ((consumed_at IS NOT NULL AND verifier_ciphertext IS NULL AND verifier_nonce IS NULL AND verifier_key_version IS NULL) OR
         (consumed_at IS NULL AND verifier_ciphertext IS NOT NULL AND octet_length(verifier_ciphertext) >= 16 AND verifier_nonce IS NOT NULL AND octet_length(verifier_nonce) = 12 AND verifier_key_version IS NOT NULL AND length(verifier_key_version) > 0))
);
CREATE INDEX oidc_transactions_expiry_idx ON console_auth.oidc_transactions(expires_at);

CREATE TABLE platform.audit_events (
  event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenancy.tenants(tenant_id),
  actor_operator_identity_id uuid REFERENCES tenancy.operator_identities(operator_identity_id),
  target_id uuid NOT NULL,
  action text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_.]{1,79}$'),
  outcome text NOT NULL CHECK (outcome IN ('success','denied')),
  correlation_id uuid NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id,event_id)
);
CREATE TABLE platform.outbox_events (
  event_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenancy.tenants(tenant_id),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  FOREIGN KEY (tenant_id,event_id) REFERENCES platform.audit_events(tenant_id,event_id)
);
-- Only minimal references, no arbitrary JSON/claims/codes/secrets in audit/outbox.

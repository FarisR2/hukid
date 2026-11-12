-- Expand only. AUTH credentials keep their existing privileges and behavior.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='hukid_members_runtime') THEN
    CREATE ROLE hukid_members_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='hukid_members_runtime'
    AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
    RAISE EXCEPTION 'Unsafe pre-existing members role';
  END IF;
END $$;
SET LOCAL ROLE hukid_owner;

ALTER TABLE tenancy.memberships
  ADD COLUMN lifecycle bigint NOT NULL DEFAULT 1 CHECK (lifecycle BETWEEN 1 AND 9007199254740991),
  ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN lifecycle_started_at timestamptz,
  ADD COLUMN revoked_at timestamptz;
RESET ROLE;
UPDATE tenancy.memberships SET lifecycle_started_at=created_at,
  revoked_at=CASE WHEN state='revoked' THEN now() END;
-- Legacy revocation time is unknown: migration time is a conservative reentry
-- cutoff, not a claim about when revocation occurred.
SET LOCAL ROLE hukid_owner;
ALTER TABLE tenancy.memberships ALTER COLUMN lifecycle_started_at SET NOT NULL;
ALTER TABLE tenancy.memberships ALTER COLUMN lifecycle_started_at SET DEFAULT now();
ALTER TABLE tenancy.memberships ADD CONSTRAINT member_time_order
  CHECK (updated_at>=created_at AND lifecycle_started_at>=created_at
    AND (revoked_at IS NULL OR revoked_at>=lifecycle_started_at));
CREATE INDEX memberships_tenant_page ON tenancy.memberships(tenant_id,created_at,membership_id);

-- Structural grant validation only. Ownership must come from a trusted issuer
-- port before granting nonempty issuer IDs; no issuer registry is invented here.
CREATE FUNCTION tenancy.valid_member_roles(p_roles text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT cardinality(p_roles) BETWEEN 1 AND 4
 AND array_position(p_roles,NULL) IS NULL
 AND p_roles <@ ARRAY['tenant_admin','security_admin','issuer_operator','support_readonly']::text[]
 AND cardinality(p_roles)=(SELECT count(DISTINCT r) FROM unnest(p_roles) r)
$$;
CREATE FUNCTION tenancy.valid_member_issuers(p_roles text[],p_issuers uuid[]) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT cardinality(p_issuers)<=100 AND array_position(p_issuers,NULL) IS NULL
 AND cardinality(p_issuers)=(SELECT count(DISTINCT i) FROM unnest(p_issuers) i)
 AND ('issuer_operator'=ANY(p_roles))=(cardinality(p_issuers)>0)
$$;
REVOKE ALL ON FUNCTION tenancy.valid_member_roles(text[]),tenancy.valid_member_issuers(text[],uuid[]) FROM PUBLIC;

CREATE TABLE tenancy.membership_issuer_scopes (
  tenant_id uuid NOT NULL,
  membership_id uuid NOT NULL,
  issuer_id uuid NOT NULL,
  PRIMARY KEY(tenant_id,membership_id,issuer_id),
  FOREIGN KEY(tenant_id,membership_id) REFERENCES tenancy.memberships(tenant_id,membership_id)
);
CREATE TABLE tenancy.membership_history (
  tenant_id uuid NOT NULL,
  membership_id uuid NOT NULL,
  lifecycle bigint NOT NULL CHECK(lifecycle BETWEEN 1 AND 9007199254740991),
  authorization_revision bigint NOT NULL CHECK(authorization_revision BETWEEN 1 AND 9007199254740991),
  roles text[] NOT NULL,
  issuer_ids uuid[] NOT NULL,
  started_at timestamptz NOT NULL,
  revoked_at timestamptz NOT NULL CHECK(revoked_at>=started_at),
  PRIMARY KEY(tenant_id,membership_id,lifecycle),
  FOREIGN KEY(tenant_id,membership_id) REFERENCES tenancy.memberships(tenant_id,membership_id)
);
-- Preserve even incomplete legacy grants; new writes validate grants in Go.
RESET ROLE;
INSERT INTO tenancy.membership_history
 SELECT m.tenant_id,m.membership_id,m.lifecycle,m.authorization_revision,
 ARRAY(SELECT r.role FROM tenancy.membership_roles r WHERE r.tenant_id=m.tenant_id AND r.membership_id=m.membership_id ORDER BY r.role),
 ARRAY[]::uuid[],m.lifecycle_started_at,m.revoked_at FROM tenancy.memberships m WHERE m.state='revoked';
SET LOCAL ROLE hukid_owner;

CREATE TABLE tenancy.invitations (
  invitation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenancy.tenants(tenant_id),
  created_by uuid NOT NULL REFERENCES tenancy.operator_identities(operator_identity_id),
  token_hash bytea NOT NULL UNIQUE CHECK(octet_length(token_hash)=32),
  recipient_hmac bytea CHECK(octet_length(recipient_hmac)=32),
  recipient_ciphertext bytea,
  recipient_nonce bytea,
  recipient_key_version text,
  roles text[] NOT NULL CHECK(tenancy.valid_member_roles(roles)),
  issuer_ids uuid[] NOT NULL CHECK(tenancy.valid_member_issuers(roles,issuer_ids)),
  state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','accepted','revoked','expired')),
  delivery_state text NOT NULL DEFAULT 'queued' CHECK(delivery_state IN ('queued','sent','failed')),
  revision bigint NOT NULL DEFAULT 1 CHECK(revision BETWEEN 1 AND 9007199254740991),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
  recipient_delete_after timestamptz NOT NULL CHECK(recipient_delete_after>=expires_at),
  accepted_at timestamptz,
  revoked_at timestamptz,
  accepted_membership_id uuid,
  accepted_lifecycle bigint,
  -- Optional binding only when target is already known from a trusted identity.
  target_membership_id uuid,
  target_lifecycle bigint,
  target_revoked_at timestamptz,
  UNIQUE(tenant_id,invitation_id),
  UNIQUE(tenant_id,invitation_id,token_hash),
  FOREIGN KEY(tenant_id,accepted_membership_id) REFERENCES tenancy.memberships(tenant_id,membership_id),
  FOREIGN KEY(tenant_id,target_membership_id) REFERENCES tenancy.memberships(tenant_id,membership_id),
  CHECK((state='accepted')=(accepted_at IS NOT NULL)),
  CHECK((state='revoked')=(revoked_at IS NOT NULL)),
  CHECK((state='accepted')=(accepted_membership_id IS NOT NULL)),
  CHECK((accepted_membership_id IS NULL)=(accepted_lifecycle IS NULL)),
  CHECK(accepted_lifecycle IS NULL OR accepted_lifecycle BETWEEN 1 AND 9007199254740991),
  CHECK(accepted_at IS NULL OR (accepted_at>=created_at AND accepted_at<expires_at)),
  CHECK(revoked_at IS NULL OR revoked_at>=created_at),
  CHECK((target_membership_id IS NULL)=(target_lifecycle IS NULL)),
  CHECK(target_lifecycle IS NULL OR target_lifecycle BETWEEN 1 AND 9007199254740991),
  CHECK(target_revoked_at IS NULL OR (target_membership_id IS NOT NULL AND created_at>target_revoked_at)),
  CHECK((recipient_hmac IS NULL AND recipient_ciphertext IS NULL AND recipient_nonce IS NULL AND recipient_key_version IS NULL)
    OR (recipient_hmac IS NOT NULL AND recipient_ciphertext IS NOT NULL AND octet_length(recipient_ciphertext)>=16
      AND recipient_nonce IS NOT NULL AND octet_length(recipient_nonce)=12 AND recipient_key_version IS NOT NULL AND length(recipient_key_version) BETWEEN 1 AND 128))
);
-- Expiration is materialized under the tenant lock before replacing a pending
-- invitation. A time-dependent partial predicate would be incorrect.
CREATE UNIQUE INDEX invitation_pending_recipient ON tenancy.invitations(tenant_id,recipient_hmac) WHERE state='pending';
CREATE INDEX invitations_tenant_page ON tenancy.invitations(tenant_id,created_at,invitation_id);
CREATE INDEX invitations_retention ON tenancy.invitations(tenant_id,recipient_delete_after) WHERE recipient_hmac IS NOT NULL;

CREATE TABLE tenancy.invitation_delivery_secrets (
  tenant_id uuid NOT NULL,
  invitation_id uuid NOT NULL,
  generation bigint NOT NULL DEFAULT 1 CHECK(generation BETWEEN 1 AND 9007199254740991),
  ciphertext bytea NOT NULL CHECK(octet_length(ciphertext)>=16),
  nonce bytea NOT NULL CHECK(octet_length(nonce)=12),
  key_version text NOT NULL CHECK(length(key_version) BETWEEN 1 AND 128),
  created_at timestamptz NOT NULL,
  delete_after timestamptz NOT NULL CHECK(delete_after>created_at),
  PRIMARY KEY(tenant_id,invitation_id),
  FOREIGN KEY(tenant_id,invitation_id) REFERENCES tenancy.invitations(tenant_id,invitation_id)
);
CREATE INDEX invitation_secrets_retention ON tenancy.invitation_delivery_secrets(tenant_id,delete_after);

CREATE TABLE tenancy.member_idempotency (
  tenant_id uuid NOT NULL REFERENCES tenancy.tenants(tenant_id),
  actor_id uuid NOT NULL REFERENCES tenancy.operator_identities(operator_identity_id),
  operation text NOT NULL CHECK(operation IN ('invitation.create','invitation.revoke','invitation.accept','membership.change')),
  key_hash bytea NOT NULL CHECK(octet_length(key_hash)=32),
  request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
  token_hash bytea CHECK(octet_length(token_hash)=32),
  invitation_id uuid,
  membership_id uuid,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
  FOREIGN KEY(tenant_id,invitation_id) REFERENCES tenancy.invitations(tenant_id,invitation_id),
  FOREIGN KEY(tenant_id,invitation_id,token_hash) REFERENCES tenancy.invitations(tenant_id,invitation_id,token_hash),
  FOREIGN KEY(tenant_id,membership_id) REFERENCES tenancy.memberships(tenant_id,membership_id),
  CHECK((operation='invitation.accept')=(token_hash IS NOT NULL)),
  CHECK((operation IN ('invitation.create','invitation.revoke','invitation.accept'))=(invitation_id IS NOT NULL)),
  CHECK((operation IN ('membership.change','invitation.accept'))=(membership_id IS NOT NULL))
);
CREATE UNIQUE INDEX member_command_key ON tenancy.member_idempotency(tenant_id,actor_id,operation,key_hash)
 WHERE operation<>'invitation.accept';
CREATE UNIQUE INDEX member_acceptance_key ON tenancy.member_idempotency(actor_id,operation,token_hash,key_hash)
 WHERE operation='invitation.accept';
CREATE INDEX member_idempotency_retention ON tenancy.member_idempotency(tenant_id,expires_at);

GRANT USAGE ON SCHEMA tenancy,platform TO hukid_members_runtime;
GRANT EXECUTE ON FUNCTION tenancy.current_operator(),tenancy.current_tenant(),
 tenancy.valid_member_roles(text[]),tenancy.valid_member_issuers(text[],uuid[]) TO hukid_members_runtime;
GRANT SELECT ON tenancy.tenants TO hukid_members_runtime;
GRANT SELECT,INSERT ON tenancy.memberships TO hukid_members_runtime;
GRANT UPDATE(state,authorization_revision,lifecycle,updated_at,lifecycle_started_at,revoked_at) ON tenancy.memberships TO hukid_members_runtime;
GRANT SELECT,INSERT,DELETE ON tenancy.membership_roles,tenancy.membership_issuer_scopes TO hukid_members_runtime;
GRANT SELECT,INSERT ON tenancy.membership_history TO hukid_members_runtime;
GRANT SELECT,INSERT ON tenancy.invitations TO hukid_members_runtime;
GRANT UPDATE(recipient_hmac,recipient_ciphertext,recipient_nonce,recipient_key_version,state,delivery_state,revision,accepted_at,revoked_at,accepted_membership_id,accepted_lifecycle)
 ON tenancy.invitations TO hukid_members_runtime;
GRANT SELECT,INSERT,DELETE ON tenancy.invitation_delivery_secrets,tenancy.member_idempotency TO hukid_members_runtime;

CREATE POLICY members_tenant_read ON tenancy.tenants FOR SELECT TO hukid_members_runtime
 USING(tenant_id=tenancy.current_tenant());
CREATE POLICY members_membership ON tenancy.memberships TO hukid_members_runtime
 USING(tenant_id=tenancy.current_tenant()) WITH CHECK(tenant_id=tenancy.current_tenant());
CREATE POLICY members_roles ON tenancy.membership_roles TO hukid_members_runtime
 USING(tenant_id=tenancy.current_tenant()) WITH CHECK(tenant_id=tenancy.current_tenant());
DO $$
DECLARE name text;
BEGIN
 FOREACH name IN ARRAY ARRAY['membership_issuer_scopes','membership_history','invitations','invitation_delivery_secrets','member_idempotency'] LOOP
  EXECUTE format('ALTER TABLE tenancy.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE tenancy.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY members_scope ON tenancy.%I TO hukid_members_runtime USING(tenant_id=tenancy.current_tenant()) WITH CHECK(tenant_id=tenancy.current_tenant())',name);
 END LOOP;
END $$;
GRANT INSERT(event_id,tenant_id,actor_operator_identity_id,target_id,action,outcome,correlation_id)
 ON platform.audit_events TO hukid_members_runtime;
GRANT INSERT(event_id,tenant_id) ON platform.outbox_events TO hukid_members_runtime;
CREATE POLICY members_audit_append ON platform.audit_events FOR INSERT TO hukid_members_runtime
 WITH CHECK(tenant_id=tenancy.current_tenant() AND actor_operator_identity_id=tenancy.current_operator()
 AND outcome='success' AND action IN ('members.invitation.created','members.invitation.revoked',
 'members.invitation.accepted','members.invitation.expired','members.delivery.sent','members.delivery.failed',
 'members.membership.changed','members.membership.revoked','members.membership.reentered','members.retention.purged'));
CREATE POLICY members_outbox_append ON platform.outbox_events FOR INSERT TO hukid_members_runtime
 WITH CHECK(tenant_id=tenancy.current_tenant());
-- No directory/secret access for AUTH roles; no identity or session access for
-- members runtime. GUCs are trusted backend inputs, not JWT authorization.

-- Etapa A (HK-012 request cancellation, HK-025 deferred issuance, HK-052 signing_kid tracking, VER-T13 schema publication).
SET LOCAL ROLE hukid_owner;

ALTER TABLE definition.definition_versions
  ADD COLUMN publish_schema boolean NOT NULL DEFAULT false;

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
       OR NEW.publish_schema IS DISTINCT FROM OLD.publish_schema
       OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.published_at IS DISTINCT FROM OLD.published_at THEN
      RAISE EXCEPTION 'published definition version is immutable' USING ERRCODE = '22023';
    END IF;
  END IF;
  RETURN NEW;
END $$;

DO $$
DECLARE c record;
BEGIN
  FOR c IN
    SELECT conrelid::regclass AS tbl, conname
    FROM pg_constraint
    WHERE conrelid IN ('issuance.issuance_requests'::regclass, 'issuance.idempotency'::regclass)
      AND contype = 'c'
      AND (pg_get_constraintdef(oid) LIKE '%offer_state%' OR pg_get_constraintdef(oid) LIKE '%issuance_state%')
      AND pg_get_constraintdef(oid) NOT LIKE '%offer_ciphertext%'
      AND pg_get_constraintdef(oid) NOT LIKE '%issued_at%'
  LOOP
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', c.tbl, c.conname);
  END LOOP;
END $$;

ALTER TABLE issuance.issuance_requests
  ADD COLUMN deferred boolean NOT NULL DEFAULT false,
  ADD COLUMN holder_jkt text NOT NULL DEFAULT '' CHECK (length(holder_jkt) <= 128),
  ADD CONSTRAINT issuance_requests_offer_state_allowed
    CHECK (offer_state IN ('ready', 'redeemed', 'expired', 'cancelled')),
  ADD CONSTRAINT issuance_requests_issuance_state_allowed
    CHECK (issuance_state IN ('prepared', 'deferred', 'issued', 'cancelled', 'failed'));

ALTER TABLE issuance.idempotency
  ADD CONSTRAINT issuance_idempotency_offer_state_allowed
    CHECK (offer_state IN ('ready', 'redeemed', 'expired', 'cancelled')),
  ADD CONSTRAINT issuance_idempotency_issuance_state_allowed
    CHECK (issuance_state IN ('prepared', 'deferred', 'issued', 'cancelled', 'failed'));

ALTER TABLE issuance.credential_offers
  ADD COLUMN cancelled_at timestamptz CHECK (cancelled_at IS NULL OR cancelled_at >= created_at);

CREATE TABLE issuance.deferred_transactions (
  tx_hash bytea PRIMARY KEY CHECK (octet_length(tx_hash) = 32),
  tenant_id uuid NOT NULL,
  issuer_id uuid NOT NULL,
  request_id text NOT NULL UNIQUE,
  token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'issued', 'failed', 'cancelled')),
  error_code text NOT NULL DEFAULT '' CHECK (length(error_code) <= 64),
  vc_ciphertext bytea,
  vc_nonce bytea,
  vc_key_version text,
  interval_seconds integer NOT NULL DEFAULT 5 CHECK (interval_seconds BETWEEN 1 AND 3600),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
  completed_at timestamptz,
  FOREIGN KEY (tenant_id, issuer_id) REFERENCES tenancy.issuers(tenant_id, issuer_id),
  FOREIGN KEY (tenant_id, request_id) REFERENCES issuance.issuance_requests(tenant_id, request_id),
  CHECK (
    (status = 'issued' AND completed_at IS NOT NULL AND (
      (vc_ciphertext IS NOT NULL AND octet_length(vc_ciphertext) >= 16 AND vc_nonce IS NOT NULL AND octet_length(vc_nonce) = 12 AND vc_key_version IS NOT NULL AND length(vc_key_version) BETWEEN 1 AND 128) OR
      (vc_ciphertext IS NULL AND vc_nonce IS NULL AND vc_key_version IS NULL)
    )) OR
    (status <> 'issued' AND vc_ciphertext IS NULL AND vc_nonce IS NULL AND vc_key_version IS NULL)
  )
);
CREATE INDEX deferred_transactions_pending_idx
  ON issuance.deferred_transactions(tenant_id, issuer_id, status, expires_at);

GRANT SELECT, INSERT, UPDATE ON issuance.deferred_transactions TO hukid_issuance_runtime;
ALTER TABLE issuance.deferred_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE issuance.deferred_transactions FORCE ROW LEVEL SECURITY;
CREATE POLICY issuance_tenant_scope ON issuance.deferred_transactions TO hukid_issuance_runtime
  USING (tenant_id = tenancy.current_tenant())
  WITH CHECK (tenant_id = tenancy.current_tenant());

ALTER TABLE status.issued_credentials
  ADD COLUMN signing_kid text NOT NULL DEFAULT '' CHECK (length(signing_kid) <= 128);
CREATE INDEX issued_credentials_signing_kid_idx
  ON status.issued_credentials(tenant_id, issuer_id, signing_kid)
  WHERE signing_kid <> '';

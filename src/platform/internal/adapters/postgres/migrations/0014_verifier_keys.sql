-- Per-tenant verifier signing keys, custodied encrypted by HukID (ADR-0034, VER-T11-d1).
-- The private key is stored only as an AEAD envelope (ciphertext, nonce, key_version) sealed by the
-- application with a master key supplied outside the database; the database never sees it in clear.
-- The runtime role has no table access: it obtains a key through one narrow function.
SET LOCAL ROLE hukid_owner;

CREATE TABLE verification.verifier_keys (
 key_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL REFERENCES tenancy.tenants(tenant_id),
 kid text NOT NULL CHECK (length(kid) BETWEEN 1 AND 128),
 status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','retiring')),
 ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 16 AND 4096),
 nonce bytea NOT NULL CHECK (octet_length(nonce)=12),
 key_version text NOT NULL CHECK (length(key_version) BETWEEN 1 AND 128),
 -- x5c chain, leaf first, DER; empty when the tenant has no certificate yet.
 chain bytea[] NOT NULL DEFAULT '{}' CHECK (cardinality(chain)<=8),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 retired_at timestamptz,
 UNIQUE (tenant_id,kid),
 CHECK ((status='active' AND retired_at IS NULL) OR (status='retiring' AND retired_at IS NOT NULL))
);
-- One signing key per tenant at a time.
CREATE UNIQUE INDEX verifier_keys_one_active ON verification.verifier_keys(tenant_id) WHERE status='active';

-- The kid a session was signed with (ADR-0034 item 4); set by session_signing_key on first use.
ALTER TABLE verification.sessions ADD COLUMN signing_kid text CHECK (signing_kid IS NULL OR length(signing_kid) BETWEEN 1 AND 128);

-- Deny by default: no policy for any runtime role. Access is through the functions below, which run as the owner.
ALTER TABLE verification.verifier_keys ENABLE ROW LEVEL SECURITY;

-- Installs a new active key for a tenant and retires the previous one. Not granted to the runtime role.
CREATE FUNCTION verification.rotate_verifier_key(p_tenant_id uuid,p_kid text,p_ciphertext bytea,p_nonce bytea,p_key_version text,p_chain bytea[]) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp
AS $$
BEGIN
 IF p_tenant_id IS NULL OR p_kid IS NULL OR length(p_kid) NOT BETWEEN 1 AND 128
  OR p_ciphertext IS NULL OR octet_length(p_ciphertext) NOT BETWEEN 16 AND 4096
  OR p_nonce IS NULL OR octet_length(p_nonce)<>12
  OR p_key_version IS NULL OR length(p_key_version) NOT BETWEEN 1 AND 128
  OR p_chain IS NULL OR cardinality(p_chain)>8 OR array_position(p_chain,NULL) IS NOT NULL THEN
  RAISE EXCEPTION 'Invalid verifier key' USING ERRCODE='22023';
 END IF;
 UPDATE verification.verifier_keys SET status='retiring',retired_at=clock_timestamp()
  WHERE tenant_id=p_tenant_id AND status='active';
 INSERT INTO verification.verifier_keys(tenant_id,kid,ciphertext,nonce,key_version,chain)
  VALUES(p_tenant_id,p_kid,p_ciphertext,p_nonce,p_key_version,p_chain);
END $$;

-- The wallet's request fetch carries no operator or tenant context, so the key is found through the session.
-- Returns nothing for an unknown, completed or expired session. The first call pins the active kid on the
-- session; later calls return that same key even after a rotation, so a retiring key still serves open sessions.
CREATE FUNCTION verification.session_signing_key(p_session_id uuid) RETURNS TABLE(tenant_id uuid,kid text,ciphertext bytea,nonce bytea,key_version text,chain bytea[])
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
 session_tenant uuid;
 session_kid text;
BEGIN
 IF p_session_id IS NULL THEN
  RAISE EXCEPTION 'Invalid session' USING ERRCODE='22023';
 END IF;
 SELECT s.tenant_id,s.signing_kid INTO session_tenant,session_kid FROM verification.sessions s
  WHERE s.session_id=p_session_id AND s.status='pending' AND s.expires_at>clock_timestamp() FOR UPDATE;
 IF NOT FOUND THEN
  RETURN;
 END IF;
 IF session_kid IS NULL THEN
  SELECT k.kid INTO session_kid FROM verification.verifier_keys k WHERE k.tenant_id=session_tenant AND k.status='active';
  IF NOT FOUND THEN
   RETURN;
  END IF;
  UPDATE verification.sessions s SET signing_kid=session_kid WHERE s.session_id=p_session_id;
 END IF;
 RETURN QUERY SELECT k.tenant_id,k.kid,k.ciphertext,k.nonce,k.key_version,k.chain FROM verification.verifier_keys k
  WHERE k.tenant_id=session_tenant AND k.kid=session_kid;
END $$;

-- Drops retiring keys that no pending, unexpired session still needs. For a maintenance login, not the runtime role.
CREATE FUNCTION verification.purge_retired_keys(p_limit integer) RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
 removed integer;
BEGIN
 IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN
  RAISE EXCEPTION 'Invalid limit' USING ERRCODE='22023';
 END IF;
 WITH doomed AS (
  SELECT k.key_id FROM verification.verifier_keys k
   WHERE k.status='retiring' AND NOT EXISTS (
    SELECT FROM verification.sessions s
     WHERE s.tenant_id=k.tenant_id AND s.status='pending' AND s.expires_at>clock_timestamp()
      AND (s.signing_kid IS NULL OR s.signing_kid=k.kid))
   ORDER BY k.retired_at LIMIT p_limit)
 DELETE FROM verification.verifier_keys k USING doomed WHERE k.key_id=doomed.key_id;
 GET DIAGNOSTICS removed=ROW_COUNT;
 RETURN removed;
END $$;

REVOKE ALL ON FUNCTION verification.rotate_verifier_key(uuid,text,bytea,bytea,text,bytea[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION verification.session_signing_key(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION verification.purge_retired_keys(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verification.session_signing_key(uuid) TO hukid_verification_runtime;

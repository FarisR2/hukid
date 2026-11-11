-- Persistent anti-replay for OpenID4VP presentation requests (ADR-0032).
-- Stores only a SHA-256 hash: never a vp_token, credential, claim, nonce or state.
DO $$
BEGIN
 IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='hukid_verification_runtime') THEN
  CREATE ROLE hukid_verification_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='hukid_verification_runtime'
  AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
  RAISE EXCEPTION 'Unsafe pre-existing verification role';
 END IF;
END $$;
CREATE SCHEMA verification AUTHORIZATION hukid_owner;
SET LOCAL ROLE hukid_owner;

CREATE TABLE verification.presentation_replay (
 scope text NOT NULL CHECK (length(scope) BETWEEN 1 AND 256),
 key_hash bytea NOT NULL CHECK (octet_length(key_hash)=32),
 expires_at timestamptz NOT NULL,
 PRIMARY KEY (scope,key_hash)
);
CREATE INDEX presentation_replay_expiry ON verification.presentation_replay(scope,expires_at);
-- Defense in depth: no policy, so only the owner (the SECURITY DEFINER function) reads or writes.
ALTER TABLE verification.presentation_replay ENABLE ROW LEVEL SECURITY;

-- Atomic per scope: true on first use within the TTL, false on a replay.
-- SQLSTATE 53400 means the scope is full of live records; nothing live is evicted.
CREATE FUNCTION verification.consume_presentation(p_scope text,p_key_hash bytea,p_ttl_seconds integer,p_capacity integer) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
 now_ts timestamptz;
 held timestamptz;
 live integer;
BEGIN
 IF p_scope IS NULL OR length(p_scope) NOT BETWEEN 1 AND 256
  OR p_key_hash IS NULL OR octet_length(p_key_hash)<>32
  OR p_ttl_seconds IS NULL OR p_ttl_seconds NOT BETWEEN 1 AND 86400
  OR p_capacity IS NULL OR p_capacity NOT BETWEEN 1 AND 1000000 THEN
  RAISE EXCEPTION 'Invalid replay record' USING ERRCODE='22023';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('verification.presentation_replay:'||p_scope,0));
 now_ts:=clock_timestamp();
 DELETE FROM verification.presentation_replay
  WHERE ctid IN (SELECT ctid FROM verification.presentation_replay
                  WHERE scope=p_scope AND expires_at<=now_ts LIMIT 1000);
 SELECT expires_at INTO held FROM verification.presentation_replay WHERE scope=p_scope AND key_hash=p_key_hash;
 IF FOUND THEN
  IF held>now_ts THEN
   RETURN false;
  END IF;
  UPDATE verification.presentation_replay SET expires_at=now_ts+make_interval(secs=>p_ttl_seconds)
   WHERE scope=p_scope AND key_hash=p_key_hash;
  RETURN true;
 END IF;
 SELECT count(*) INTO live FROM verification.presentation_replay WHERE scope=p_scope AND expires_at>now_ts;
 IF live>=p_capacity THEN
  RAISE EXCEPTION 'Replay store full' USING ERRCODE='53400';
 END IF;
 INSERT INTO verification.presentation_replay(scope,key_hash,expires_at)
  VALUES(p_scope,p_key_hash,now_ts+make_interval(secs=>p_ttl_seconds));
 RETURN true;
END $$;

REVOKE ALL ON FUNCTION verification.consume_presentation(text,bytea,integer,integer) FROM PUBLIC;
GRANT USAGE ON SCHEMA verification TO hukid_verification_runtime;
GRANT EXECUTE ON FUNCTION verification.consume_presentation(text,bytea,integer,integer) TO hukid_verification_runtime;

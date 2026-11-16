-- Per-tenant verification sessions and results (ADR-0033, VER-T11 b).
-- Stores no JWS, claim, vp_token, nonce, state or key material: only the public
-- session id, status, result, closed-set failure codes and a report digest.
SET LOCAL ROLE hukid_owner;

-- Per-tenant verifier identity. Written outside the runtime role; key custody is still open (ADR-0033 item 7).
CREATE TABLE verification.verifier_configs (
 tenant_id uuid PRIMARY KEY REFERENCES tenancy.tenants(tenant_id),
 client_id text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 256),
 response_uri text NOT NULL CHECK (length(response_uri) BETWEEN 9 AND 2048 AND response_uri ~ '^https://[^[:space:]]+$'),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE verification.sessions (
 session_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL REFERENCES tenancy.tenants(tenant_id),
 started_by uuid NOT NULL REFERENCES tenancy.operator_identities(operator_identity_id),
 status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','completed')),
 result text CHECK (result IN ('pass','fail')),
 codes text[] NOT NULL DEFAULT '{}' CHECK (cardinality(codes) <= 32),
 report_digest bytea CHECK (octet_length(report_digest)=32),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,
 completed_at timestamptz,
 CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes'),
 CHECK ((status='pending' AND result IS NULL AND report_digest IS NULL AND completed_at IS NULL AND cardinality(codes)=0)
     OR (status='completed' AND result IS NOT NULL AND report_digest IS NOT NULL AND completed_at IS NOT NULL))
);
-- Bounded keyset page per tenant; never a global listing.
CREATE INDEX sessions_by_tenant ON verification.sessions(tenant_id,created_at DESC,session_id DESC);
CREATE INDEX sessions_by_creation ON verification.sessions(created_at);

-- No FORCE: the SECURITY DEFINER functions below run as the owner and bypass these policies on purpose.
ALTER TABLE verification.verifier_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE verification.sessions ENABLE ROW LEVEL SECURITY;

CREATE POLICY verifier_config_tenant ON verification.verifier_configs FOR SELECT TO hukid_verification_runtime
 USING (tenant_id=tenancy.current_tenant());
CREATE POLICY sessions_read_tenant ON verification.sessions FOR SELECT TO hukid_verification_runtime
 USING (tenant_id=tenancy.current_tenant());
CREATE POLICY sessions_start_tenant ON verification.sessions FOR INSERT TO hukid_verification_runtime
 WITH CHECK (tenant_id=tenancy.current_tenant() AND started_by=tenancy.current_operator()
  AND status='pending' AND result IS NULL AND report_digest IS NULL AND completed_at IS NULL);

-- The wallet response carries no operator or tenant context, so completion goes through one narrow function.
-- True when a pending, unexpired session was completed; false for an unknown, completed or expired one.
CREATE FUNCTION verification.complete_session(p_session_id uuid,p_result text,p_codes text[],p_report_digest bytea) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
 now_ts timestamptz;
BEGIN
 IF p_session_id IS NULL OR p_result IS NULL OR p_result NOT IN ('pass','fail')
  OR p_codes IS NULL OR cardinality(p_codes)>32 OR array_position(p_codes,NULL) IS NOT NULL
  OR EXISTS (SELECT FROM unnest(p_codes) AS code WHERE length(code) NOT BETWEEN 1 AND 64)
  OR p_report_digest IS NULL OR octet_length(p_report_digest)<>32 THEN
  RAISE EXCEPTION 'Invalid verification result' USING ERRCODE='22023';
 END IF;
 now_ts:=clock_timestamp();
 UPDATE verification.sessions
  SET status='completed',result=p_result,codes=p_codes,report_digest=p_report_digest,completed_at=now_ts
  WHERE session_id=p_session_id AND status='pending' AND expires_at>now_ts;
 RETURN FOUND;
END $$;

-- Bounded retention purge for a maintenance login; deliberately not granted to the runtime role.
CREATE FUNCTION verification.purge_sessions(p_retention_days integer,p_limit integer) RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
 removed integer;
BEGIN
 IF p_retention_days IS NULL OR p_retention_days NOT BETWEEN 1 AND 3650
  OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 10000 THEN
  RAISE EXCEPTION 'Invalid retention' USING ERRCODE='22023';
 END IF;
 WITH doomed AS (
  SELECT session_id FROM verification.sessions
   WHERE created_at<clock_timestamp()-make_interval(days=>p_retention_days)
   ORDER BY created_at LIMIT p_limit)
 DELETE FROM verification.sessions s USING doomed WHERE s.session_id=doomed.session_id;
 GET DIAGNOSTICS removed=ROW_COUNT;
 RETURN removed;
END $$;

REVOKE ALL ON FUNCTION verification.complete_session(uuid,text,text[],bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION verification.purge_sessions(integer,integer) FROM PUBLIC;
GRANT USAGE ON SCHEMA tenancy TO hukid_verification_runtime;
GRANT EXECUTE ON FUNCTION tenancy.current_operator(),tenancy.current_tenant() TO hukid_verification_runtime;
GRANT SELECT ON verification.verifier_configs TO hukid_verification_runtime;
GRANT SELECT ON verification.sessions TO hukid_verification_runtime;
GRANT INSERT(tenant_id,started_by,expires_at) ON verification.sessions TO hukid_verification_runtime;
GRANT EXECUTE ON FUNCTION verification.complete_session(uuid,text,text[],bytea) TO hukid_verification_runtime;

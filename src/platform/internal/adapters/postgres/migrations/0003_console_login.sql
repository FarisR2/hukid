-- Minimum post-OIDC identity registration; no directory or membership writes.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='hukid_identity_writer') THEN
    CREATE ROLE hukid_identity_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='hukid_identity_writer' AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
    RAISE EXCEPTION 'Unsafe identity writer role';
  END IF;
END $$;
GRANT USAGE ON SCHEMA tenancy,console_auth TO hukid_identity_writer;
GRANT SELECT,INSERT ON tenancy.operator_identities TO hukid_identity_writer;
-- Resolve a concurrent insert without granting UPDATE on an existing identity.
CREATE FUNCTION console_auth.register_operator(p_issuer text,p_subject text) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp
AS $$
DECLARE actor uuid;
BEGIN
  IF p_issuer IS NULL OR length(p_issuer) NOT BETWEEN 1 AND 2048 OR p_subject IS NULL OR length(p_subject) NOT BETWEEN 1 AND 128 THEN
    RAISE EXCEPTION 'Invalid operator identity';
  END IF;
  INSERT INTO tenancy.operator_identities(oidc_issuer,subject) VALUES(p_issuer,p_subject)
    ON CONFLICT(oidc_issuer,subject) DO NOTHING;
  SELECT operator_identity_id INTO STRICT actor FROM tenancy.operator_identities WHERE oidc_issuer=p_issuer AND subject=p_subject;
  RETURN actor;
END $$;
GRANT CREATE ON SCHEMA console_auth TO hukid_identity_writer;
ALTER FUNCTION console_auth.register_operator(text,text) OWNER TO hukid_identity_writer;
REVOKE CREATE ON SCHEMA console_auth FROM hukid_identity_writer;
REVOKE ALL ON FUNCTION console_auth.register_operator(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION console_auth.register_operator(text,text) TO hukid_session_runtime;

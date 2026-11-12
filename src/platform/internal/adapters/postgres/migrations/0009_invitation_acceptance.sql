-- Evidence remains inside the existing encrypted session envelope.
SET LOCAL ROLE hukid_owner;
ALTER TABLE console_auth.sessions ADD COLUMN access_hash bytea CHECK(octet_length(access_hash)=32);
CREATE INDEX sessions_access_evidence ON console_auth.sessions(access_hash) WHERE state='active';
RESET ROLE;
DO $$ BEGIN
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='hukid_invitation_locator') THEN
  CREATE ROLE hukid_invitation_locator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 IF EXISTS (SELECT FROM pg_roles WHERE rolname='hukid_invitation_locator' AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
 OR EXISTS (SELECT FROM pg_auth_members WHERE member='hukid_invitation_locator'::regrole) THEN
  RAISE EXCEPTION 'Unsafe invitation locator role';
 END IF;
END $$;
GRANT USAGE ON SCHEMA tenancy TO hukid_invitation_locator;
GRANT SELECT(tenant_id,token_hash) ON tenancy.invitations TO hukid_invitation_locator;
SET LOCAL ROLE hukid_owner;
CREATE POLICY invitation_locator ON tenancy.invitations FOR SELECT TO hukid_invitation_locator USING(true);
CREATE FUNCTION tenancy.locate_invitation(p_hash bytea) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp
AS $$ SELECT tenant_id FROM tenancy.invitations WHERE token_hash=p_hash AND octet_length(p_hash)=32 $$;
RESET ROLE;
GRANT CREATE ON SCHEMA tenancy TO hukid_invitation_locator;
ALTER FUNCTION tenancy.locate_invitation(bytea) OWNER TO hukid_invitation_locator;
REVOKE CREATE ON SCHEMA tenancy FROM hukid_invitation_locator;
REVOKE ALL ON FUNCTION tenancy.locate_invitation(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenancy.locate_invitation(bytea) TO hukid_members_runtime;

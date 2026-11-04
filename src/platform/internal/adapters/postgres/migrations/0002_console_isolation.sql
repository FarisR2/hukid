SET LOCAL ROLE hukid_owner;

CREATE FUNCTION tenancy.current_operator() RETURNS uuid
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp
AS $$ SELECT NULLIF(pg_catalog.current_setting('app.operator_id', true), '')::uuid $$;
CREATE FUNCTION tenancy.current_tenant() RETURNS uuid
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp
AS $$ SELECT NULLIF(pg_catalog.current_setting('app.tenant_id', true), '')::uuid $$;
REVOKE ALL ON FUNCTION tenancy.current_operator(), tenancy.current_tenant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenancy.current_operator(), tenancy.current_tenant() TO hukid_tenant_runtime, hukid_context_reader;

ALTER TABLE tenancy.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy.tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE tenancy.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy.memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE tenancy.membership_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy.membership_roles FORCE ROW LEVEL SECURITY;
ALTER TABLE platform.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.audit_events FORCE ROW LEVEL SECURITY;
ALTER TABLE platform.outbox_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.outbox_events FORCE ROW LEVEL SECURITY;

CREATE POLICY own_membership ON tenancy.memberships FOR SELECT TO hukid_tenant_runtime
USING (tenant_id = tenancy.current_tenant() AND operator_identity_id = tenancy.current_operator() AND state = 'active');
CREATE POLICY discovered_membership ON tenancy.memberships FOR SELECT TO hukid_context_reader
USING (operator_identity_id = tenancy.current_operator() AND state = 'active');
CREATE POLICY own_tenant ON tenancy.tenants FOR SELECT TO hukid_tenant_runtime
USING (tenant_id = tenancy.current_tenant() AND state = 'active' AND EXISTS
  (SELECT FROM tenancy.memberships m WHERE m.tenant_id = tenants.tenant_id AND m.operator_identity_id = tenancy.current_operator() AND m.state = 'active'));
CREATE POLICY discovered_tenant ON tenancy.tenants FOR SELECT TO hukid_context_reader
USING (state = 'active' AND EXISTS
  (SELECT FROM tenancy.memberships m WHERE m.tenant_id = tenants.tenant_id AND m.operator_identity_id = tenancy.current_operator() AND m.state = 'active'));
CREATE POLICY own_roles ON tenancy.membership_roles FOR SELECT TO hukid_tenant_runtime
USING (tenant_id = tenancy.current_tenant() AND EXISTS
  (SELECT FROM tenancy.memberships m WHERE m.tenant_id = membership_roles.tenant_id AND m.membership_id = membership_roles.membership_id AND m.operator_identity_id = tenancy.current_operator() AND m.state = 'active'));
CREATE POLICY discovered_roles ON tenancy.membership_roles FOR SELECT TO hukid_context_reader
USING (EXISTS
  (SELECT FROM tenancy.memberships m WHERE m.tenant_id = membership_roles.tenant_id AND m.membership_id = membership_roles.membership_id AND m.operator_identity_id = tenancy.current_operator() AND m.state = 'active'));
-- No runtime audit/outbox grant or policy yet: AUTH-T09/USR extend these explicitly.
GRANT USAGE ON SCHEMA tenancy TO hukid_tenant_runtime, hukid_context_reader;
GRANT SELECT ON tenancy.tenants, tenancy.memberships, tenancy.membership_roles TO hukid_tenant_runtime, hukid_context_reader;
GRANT SELECT ON tenancy.operator_identities TO hukid_context_reader;

GRANT USAGE ON SCHEMA console_auth TO hukid_session_runtime, hukid_context_runtime, hukid_context_reader;
GRANT SELECT, INSERT, UPDATE, DELETE ON console_auth.oidc_transactions, console_auth.session_families, console_auth.sessions TO hukid_session_runtime;

CREATE FUNCTION console_auth.resolve_operator(p_issuer text, p_subject text) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$ SELECT operator_identity_id FROM tenancy.operator_identities WHERE oidc_issuer = p_issuer AND subject = p_subject $$;
CREATE FUNCTION console_auth.operator_tenants()
RETURNS TABLE (tenant_id uuid, display_name text, membership_id uuid, authorization_revision bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT t.tenant_id, t.display_name, m.membership_id, m.authorization_revision
  FROM tenancy.tenants t JOIN tenancy.memberships m ON m.tenant_id = t.tenant_id
  WHERE m.operator_identity_id = tenancy.current_operator() AND m.state = 'active' AND t.state = 'active'
  ORDER BY t.tenant_id
$$;
-- A non-owner, NOBYPASSRLS function owner is constrained by the actor policies.
-- Application roles never inherit this function owner's table privileges.
RESET ROLE;
GRANT CREATE ON SCHEMA console_auth TO hukid_context_reader;
ALTER FUNCTION console_auth.resolve_operator(text,text) OWNER TO hukid_context_reader;
ALTER FUNCTION console_auth.operator_tenants() OWNER TO hukid_context_reader;
REVOKE CREATE ON SCHEMA console_auth FROM hukid_context_reader;
REVOKE ALL ON FUNCTION console_auth.resolve_operator(text,text), console_auth.operator_tenants() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION console_auth.resolve_operator(text,text), console_auth.operator_tenants() TO hukid_context_runtime;

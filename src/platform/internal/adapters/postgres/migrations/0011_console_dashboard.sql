-- Additive, independent read credential. No identity/session/invitation secrets.
DO $$
BEGIN
 IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='hukid_dashboard_runtime') THEN
  CREATE ROLE hukid_dashboard_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='hukid_dashboard_runtime'
  AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
  RAISE EXCEPTION 'Unsafe pre-existing dashboard role';
 END IF;
END $$;
SET LOCAL ROLE hukid_owner;
GRANT USAGE ON SCHEMA tenancy,platform TO hukid_dashboard_runtime;
GRANT EXECUTE ON FUNCTION tenancy.current_operator(),tenancy.current_tenant() TO hukid_dashboard_runtime;
GRANT SELECT ON tenancy.tenants,tenancy.memberships,tenancy.membership_roles,tenancy.membership_issuer_scopes TO hukid_dashboard_runtime;
GRANT SELECT(event_id,tenant_id,actor_operator_identity_id,target_id,action,outcome,recorded_at)
 ON platform.audit_events TO hukid_dashboard_runtime;
CREATE POLICY dashboard_tenant ON tenancy.tenants FOR SELECT TO hukid_dashboard_runtime
 USING(tenant_id=tenancy.current_tenant());
CREATE POLICY dashboard_membership ON tenancy.memberships FOR SELECT TO hukid_dashboard_runtime
 USING(tenant_id=tenancy.current_tenant());
CREATE POLICY dashboard_roles ON tenancy.membership_roles FOR SELECT TO hukid_dashboard_runtime
 USING(tenant_id=tenancy.current_tenant());
CREATE POLICY dashboard_issuers ON tenancy.membership_issuer_scopes FOR SELECT TO hukid_dashboard_runtime
 USING(tenant_id=tenancy.current_tenant());
CREATE POLICY dashboard_activity ON platform.audit_events FOR SELECT TO hukid_dashboard_runtime
 USING(tenant_id=tenancy.current_tenant() AND outcome='success' AND action IN
 ('auth.step_up.completed','auth.context.changed','auth.refresh.completed','auth.logout.completed','auth.family.revoked',
 'members.invitation.created','members.invitation.revoked','members.invitation.accepted','members.invitation.expired',
 'members.delivery.sent','members.delivery.failed','members.membership.changed','members.membership.revoked',
 'members.membership.reentered','members.retention.purged'));
-- Bounded descending keyset after tenant/action restrictions; not a global feed.
CREATE INDEX dashboard_activity_page ON platform.audit_events(tenant_id,recorded_at DESC,event_id DESC)
 WHERE tenant_id IS NOT NULL AND outcome='success';

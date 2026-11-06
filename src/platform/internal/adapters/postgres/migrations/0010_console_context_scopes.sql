SET LOCAL ROLE hukid_owner;

-- AUTH may project only the current actor's active membership scopes. This
-- grants neither a directory nor the ability to assign/verify issuer ownership.
GRANT SELECT ON tenancy.membership_issuer_scopes TO hukid_tenant_runtime;
CREATE POLICY own_issuer_scopes ON tenancy.membership_issuer_scopes
 FOR SELECT TO hukid_tenant_runtime
 USING (tenant_id=tenancy.current_tenant() AND EXISTS (
  SELECT FROM tenancy.memberships m
   JOIN tenancy.tenants t ON t.tenant_id=m.tenant_id
  WHERE m.tenant_id=membership_issuer_scopes.tenant_id
   AND m.membership_id=membership_issuer_scopes.membership_id
   AND m.operator_identity_id=tenancy.current_operator() AND m.state='active'
   AND t.state='active'));

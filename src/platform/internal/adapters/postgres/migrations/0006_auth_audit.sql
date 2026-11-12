-- Auth can precede tenant selection. Preserve existing tenant-scoped history.
SET LOCAL ROLE hukid_owner;
ALTER TABLE platform.audit_events ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE platform.outbox_events ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE platform.outbox_events ADD CONSTRAINT outbox_event_fk
 FOREIGN KEY (event_id) REFERENCES platform.audit_events(event_id);
ALTER TABLE platform.audit_events ADD CONSTRAINT global_auth_only
 CHECK (tenant_id IS NOT NULL OR action IN
 ('auth.login.started','auth.step_up.started','auth.login.completed','auth.step_up.completed',
  'auth.context.changed','auth.refresh.completed','auth.logout.completed','auth.family.revoked',
  'auth.request.denied','auth.request.failed'));
GRANT USAGE ON SCHEMA platform TO hukid_session_runtime;
GRANT INSERT (event_id,tenant_id,actor_operator_identity_id,target_id,action,outcome,correlation_id)
 ON platform.audit_events TO hukid_session_runtime;
GRANT INSERT (event_id,tenant_id) ON platform.outbox_events TO hukid_session_runtime;
CREATE POLICY auth_audit_append ON platform.audit_events FOR INSERT TO hukid_session_runtime
 WITH CHECK (action IN ('auth.login.started','auth.step_up.started','auth.login.completed',
 'auth.step_up.completed','auth.context.changed','auth.refresh.completed','auth.logout.completed',
 'auth.family.revoked','auth.request.denied','auth.request.failed'));
CREATE POLICY auth_outbox_append ON platform.outbox_events FOR INSERT TO hukid_session_runtime
 WITH CHECK (true);
-- Composite scope enforces matching tenant even for global records.
ALTER TABLE platform.audit_events ADD COLUMN audit_scope text GENERATED ALWAYS AS
 (COALESCE(tenant_id::text,'global')) STORED;
ALTER TABLE platform.audit_events ADD CONSTRAINT audit_scope_event UNIQUE(audit_scope,event_id);
ALTER TABLE platform.outbox_events ADD COLUMN audit_scope text GENERATED ALWAYS AS
 (COALESCE(tenant_id::text,'global')) STORED;
ALTER TABLE platform.outbox_events ADD CONSTRAINT outbox_scope_event
 FOREIGN KEY(audit_scope,event_id) REFERENCES platform.audit_events(audit_scope,event_id);
-- No runtime read/update/delete or publication grant.

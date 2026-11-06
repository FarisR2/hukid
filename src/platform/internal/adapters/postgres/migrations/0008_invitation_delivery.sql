-- Laboratory provider receipt: no email, token, link or recoverable payload.
SET LOCAL ROLE hukid_owner;
CREATE TABLE tenancy.synthetic_notification_receipts (
 tenant_id uuid NOT NULL,
 invitation_id uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
 payload_hash bytea NOT NULL CHECK(octet_length(payload_hash)=32),
 accepted_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,invitation_id,generation),
 FOREIGN KEY(tenant_id,invitation_id) REFERENCES tenancy.invitations(tenant_id,invitation_id)
);
ALTER TABLE tenancy.synthetic_notification_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy.synthetic_notification_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY members_scope ON tenancy.synthetic_notification_receipts TO hukid_members_runtime
 USING(tenant_id=tenancy.current_tenant()) WITH CHECK(tenant_id=tenancy.current_tenant());
GRANT SELECT,INSERT ON tenancy.synthetic_notification_receipts TO hukid_members_runtime;
GRANT UPDATE(payload_hash) ON tenancy.synthetic_notification_receipts TO hukid_members_runtime;

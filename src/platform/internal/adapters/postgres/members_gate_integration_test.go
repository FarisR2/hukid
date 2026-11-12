//go:build integration

package postgres

import (
	"strings"
	"testing"
	"time"
)

// Snapshot only for comparison; never print ciphertext, hashes or evidence.
func retentionSnapshot(t *testing.T, db *testDatabase) string {
	t.Helper()
	var snapshot string
	err := db.admin.QueryRow(testContext, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(i) ORDER BY invitation_id) FROM tenancy.invitations i),
 (SELECT jsonb_agg(to_jsonb(d) ORDER BY invitation_id) FROM tenancy.invitation_delivery_secrets d),
 (SELECT jsonb_agg(to_jsonb(k) ORDER BY tenant_id,actor_id,operation,key_hash) FROM tenancy.member_idempotency k),
 (SELECT jsonb_agg(to_jsonb(a) ORDER BY event_id) FROM platform.audit_events a),
 (SELECT jsonb_agg(to_jsonb(o) ORDER BY event_id) FROM platform.outbox_events o)
 )::text`).Scan(&snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestMembersGateRetentionAtomicityIsolationAndEvidence(t *testing.T) {
	for _, scenario := range []struct{ table, stage string }{
		{"audit_events", "expiration"}, {"outbox_events", "expiration"},
		{"audit_events", "recipient"}, {"outbox_events", "recipient"},
	} {
		t.Run(scenario.table+"_"+scenario.stage, func(t *testing.T) {
			db, service, store, now := invitationFixture(t)
			command := inviteCommand(*now, "gate_retention_invite_001")
			invitation := mustInvite(t, service, command)
			token := acceptanceToken(t, db, service, invitation)
			other := command
			other.Actor, other.Tenant, other.Key = TestActorB, TestTenantB, "gate_retention_invite_002"
			mustInvite(t, service, other)
			if scenario.stage == "recipient" {
				if err := store.PurgeInvitations(testContext, command.Actor, command.Tenant, invitation.ExpiresAt); err != nil {
					t.Fatal(err)
				}
			}
			before := retentionSnapshot(t, db)
			deadline := invitation.CreatedAt.Add(time.Duration(service.Policy.RecipientRetentionSeconds) * time.Second)
			// Expiration, secret/key deletion and recipient redaction must roll
			// back together if either evidence channel refuses an INSERT.
			mustExec(t, db.admin, "ALTER TABLE platform."+scenario.table+" ADD CONSTRAINT gate_reject CHECK(false) NOT VALID")
			if err := store.PurgeInvitations(testContext, command.Actor, command.Tenant, deadline); err == nil {
				t.Fatal("purge reported success without evidence")
			}
			mustExec(t, db.admin, "ALTER TABLE platform."+scenario.table+" DROP CONSTRAINT gate_reject")
			if retentionSnapshot(t, db) != before {
				t.Fatal("failed purge left partial state or evidence")
			}
			// Before retention: expiry has happened, recipient remains encrypted.
			if err := store.PurgeInvitations(testContext, command.Actor, command.Tenant, deadline.Add(-time.Microsecond)); err != nil {
				t.Fatal(err)
			}
			var retained bool
			if err := db.admin.QueryRow(testContext, `SELECT recipient_ciphertext IS NOT NULL FROM tenancy.invitations WHERE invitation_id=$1`, invitation.InvitationID).Scan(&retained); err != nil || !retained {
				t.Fatal("recipient removed before deadline", err)
			}
			if err := store.PurgeInvitations(testContext, command.Actor, command.Tenant, deadline); err != nil {
				t.Fatal(err)
			}
			var purged, isolated bool
			err := db.admin.QueryRow(testContext, `SELECT
 (SELECT state='expired' AND octet_length(token_hash)=32 AND recipient_hmac IS NULL AND recipient_ciphertext IS NULL AND recipient_nonce IS NULL AND recipient_key_version IS NULL FROM tenancy.invitations WHERE invitation_id=$1)
 AND NOT EXISTS(SELECT FROM tenancy.invitation_delivery_secrets WHERE tenant_id=$2)
 AND NOT EXISTS(SELECT FROM tenancy.member_idempotency WHERE tenant_id=$2),
 (SELECT state='pending' AND recipient_ciphertext IS NOT NULL FROM tenancy.invitations WHERE tenant_id=$3)
 AND EXISTS(SELECT FROM tenancy.invitation_delivery_secrets WHERE tenant_id=$3)
 AND EXISTS(SELECT FROM tenancy.member_idempotency WHERE tenant_id=$3)`, invitation.InvitationID, command.Tenant, other.Tenant).Scan(&purged, &isolated)
			if err != nil || !purged || !isolated {
				t.Fatal("purge failed retention or tenant isolation", err)
			}
			after := retentionSnapshot(t, db)
			if err := store.PurgeInvitations(testContext, command.Actor, command.Tenant, deadline); err != nil || retentionSnapshot(t, db) != after {
				t.Fatal("repeated purge changed state or duplicated evidence", err)
			}
			var coherent bool
			var evidence string
			err = db.admin.QueryRow(testContext, `SELECT
 NOT EXISTS(SELECT FROM platform.audit_events a FULL JOIN platform.outbox_events o USING(event_id)
 WHERE a.event_id IS NULL OR o.event_id IS NULL OR a.tenant_id IS DISTINCT FROM o.tenant_id
 OR a.actor_operator_identity_id IS NULL OR a.target_id IS NULL OR a.correlation_id IS NULL OR a.outcome<>'success'),
 (SELECT jsonb_agg(to_jsonb(a))::text FROM platform.audit_events a)`).Scan(&coherent, &evidence)
			if err != nil || !coherent {
				t.Fatal("incoherent audit/outbox envelope", err)
			}
			for _, secret := range []string{token, command.Input.Email, "Lab+recipient@example.invalid"} {
				if strings.Contains(evidence, secret) {
					t.Fatal("sensitive material in evidence")
				}
			}
			assertCleared(t, store.Pool)
		})
	}
}

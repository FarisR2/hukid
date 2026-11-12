package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"hukid.local/platform/internal/tenancy"
)

func (s *InvitationStore) PendingDelivery(ctx context.Context, actor, tenant string, now time.Time) (result []tenancy.DeliveryWork, err error) {
	err = WithTenant(ctx, s.Pool, actor, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT d.invitation_id::text,d.generation,d.ciphertext,d.nonce,d.key_version,LEAST(d.delete_after,i.expires_at),i.token_hash
  FROM tenancy.invitation_delivery_secrets d JOIN tenancy.invitations i USING(tenant_id,invitation_id)
  JOIN tenancy.tenants t USING(tenant_id) WHERE d.tenant_id=$1 AND i.state='pending' AND i.delivery_state<>'sent'
  AND t.state='active' AND i.created_at<=$2 AND d.created_at<=$2 AND i.expires_at>$2 AND d.delete_after>$2 ORDER BY d.created_at,d.invitation_id LIMIT 100`, tenant, now)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			item := tenancy.DeliveryWork{Tenant: tenant}
			if e = rows.Scan(&item.ID, &item.Generation, &item.Envelope.Ciphertext, &item.Envelope.Nonce, &item.Envelope.KeyVersion, &item.Deadline, &item.TokenHash); e != nil {
				return e
			}
			result = append(result, item)
		}
		return rows.Err()
	})
	if err != nil {
		err = invitationError(err)
	}
	return
}

func (s *InvitationStore) FinishDelivery(ctx context.Context, actor string, item tenancy.DeliveryWork, sent bool, now time.Time) error {
	err := WithTenant(ctx, s.Pool, actor, item.Tenant, func(tx pgx.Tx) error {
		if e := lockInvitationTenant(ctx, tx, item.Tenant, false); e != nil {
			return e
		}
		var eligible bool
		e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM tenancy.invitations i JOIN tenancy.invitation_delivery_secrets d USING(tenant_id,invitation_id)
  WHERE i.tenant_id=$1 AND i.invitation_id=$2 AND d.generation=$3 AND i.state='pending' AND i.delivery_state<>'sent' AND i.expires_at>$4 AND d.delete_after>$4)`, item.Tenant, item.ID, item.Generation, now).Scan(&eligible)
		if e != nil {
			return e
		}
		// A revocation/replacement or expiry during the provider call wins locally.
		if !eligible {
			return nil
		}
		state := "failed"
		if sent {
			state = "sent"
		}
		_, e = tx.Exec(ctx, `UPDATE tenancy.invitations SET delivery_state=$3,revision=revision+1 WHERE tenant_id=$1 AND invitation_id=$2`, item.Tenant, item.ID, state)
		if e != nil {
			return e
		}
		if sent {
			if _, e = tx.Exec(ctx, `DELETE FROM tenancy.invitation_delivery_secrets WHERE tenant_id=$1 AND invitation_id=$2 AND generation=$3`, item.Tenant, item.ID, item.Generation); e != nil {
				return e
			}
		}
		return appendEvent(ctx, tx, "members.delivery."+state, "success", actor, item.Tenant, item.ID)
	})
	if err != nil {
		return invitationError(err)
	}
	return nil
}

func (s *InvitationStore) PurgeInvitations(ctx context.Context, actor, tenant string, now time.Time) error {
	err := WithTenant(ctx, s.Pool, actor, tenant, func(tx pgx.Tx) error {
		if e := lockInvitationTenant(ctx, tx, tenant, false); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `UPDATE tenancy.invitations SET state='expired',revision=revision+1 WHERE tenant_id=$1 AND state='pending' AND expires_at<=$2 RETURNING invitation_id::text`, tenant, now)
		if e != nil {
			return e
		}
		var ids []string
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				break
			}
			ids = append(ids, id)
		}
		rowErr := rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if rowErr != nil {
			return rowErr
		}
		for _, id := range ids {
			if e = appendEvent(ctx, tx, "members.invitation.expired", "success", actor, tenant, id); e != nil {
				return e
			}
		}
		tag, e := tx.Exec(ctx, `DELETE FROM tenancy.invitation_delivery_secrets d USING tenancy.invitations i WHERE d.tenant_id=$1 AND d.tenant_id=i.tenant_id AND d.invitation_id=i.invitation_id AND (d.delete_after<=$2 OR i.state<>'pending' OR i.delivery_state='sent')`, tenant, now)
		if e != nil {
			return e
		}
		changed := tag.RowsAffected() > 0
		tag, e = tx.Exec(ctx, `UPDATE tenancy.invitations SET recipient_hmac=NULL,recipient_ciphertext=NULL,recipient_nonce=NULL,recipient_key_version=NULL WHERE tenant_id=$1 AND recipient_hmac IS NOT NULL AND recipient_delete_after<=$2`, tenant, now)
		if e != nil {
			return e
		}
		changed = changed || tag.RowsAffected() > 0
		tag, e = tx.Exec(ctx, `DELETE FROM tenancy.member_idempotency WHERE tenant_id=$1 AND expires_at<=$2`, tenant, now)
		if e != nil {
			return e
		}
		changed = changed || tag.RowsAffected() > 0
		if changed {
			return appendEvent(ctx, tx, "members.retention.purged", "success", actor, tenant, tenant)
		}
		return nil
	})
	if err != nil {
		return invitationError(err)
	}
	return nil
}

// SyntheticNotifications simulates provider acceptance; it never sends email.
// Durable receipts contain only a digest, so a crash after acceptance but before
// FinishDelivery safely retries the same generation without a second delivery.
type SyntheticNotifications struct {
	Store *InvitationStore
	Actor string
}

func (p *SyntheticNotifications) Send(ctx context.Context, tenant, id string, generation int64, payload tenancy.DeliveryPayload) error {
	data, _ := json.Marshal(payload)
	hash := sha256.Sum256(data)
	clear(data)
	return WithTenant(ctx, p.Store.Pool, p.Actor, tenant, func(tx pgx.Tx) error {
		// Recheck at the provider boundary, including revocation and secret deadline.
		var accepted bool
		e := tx.QueryRow(ctx, `INSERT INTO tenancy.synthetic_notification_receipts(tenant_id,invitation_id,generation,payload_hash)
  SELECT i.tenant_id,i.invitation_id,d.generation,$4 FROM tenancy.invitations i
  JOIN tenancy.invitation_delivery_secrets d USING(tenant_id,invitation_id) JOIN tenancy.tenants t USING(tenant_id)
  WHERE i.tenant_id=$1 AND i.invitation_id=$2 AND d.generation=$3 AND i.state='pending' AND t.state='active'
  AND i.expires_at>$5 AND d.delete_after>$5
  ON CONFLICT(tenant_id,invitation_id,generation) DO UPDATE SET payload_hash=tenancy.synthetic_notification_receipts.payload_hash
  RETURNING payload_hash=$4`, tenant, id, generation, hash[:], p.Store.Now().UTC()).Scan(&accepted)
		if e != nil {
			return e
		}
		if !accepted {
			return errors.New("synthetic notification rejected")
		}
		return nil
	})
}

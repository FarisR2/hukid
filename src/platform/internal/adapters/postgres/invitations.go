package postgres

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	a "hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
)

type InvitationStore struct {
	Pool   *pgxpool.Pool
	Now    func() time.Time
	Policy tenancy.MembershipPolicy
}

func authorizeInvitation(ctx context.Context, tx pgx.Tx, actor, tenant, capability string) error {
	var roles []string
	err := tx.QueryRow(ctx, `SELECT ARRAY(SELECT role FROM tenancy.membership_roles r WHERE r.tenant_id=m.tenant_id AND r.membership_id=m.membership_id ORDER BY role)
 FROM tenancy.memberships m JOIN tenancy.tenants t ON t.tenant_id=m.tenant_id
 WHERE m.tenant_id=$1 AND m.operator_identity_id=$2 AND m.state='active' AND t.state='active'`, tenant, actor).Scan(&roles)
	if errors.Is(err, pgx.ErrNoRows) {
		return a.ErrTenant
	}
	if err != nil {
		return err
	}
	// Both write capabilities are exclusive to tenant_admin in the single matrix.
	if !tenancy.MemberCapabilityAllowed(roles, capability) {
		return tenancy.ErrDirectoryForbidden
	}
	return nil
}

func lockInvitationTenant(ctx context.Context, tx pgx.Tx, tenant string, try bool) error {
	if try {
		var locked bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1::uuid::text,6721587303))`, tenant).Scan(&locked); err != nil {
			return err
		}
		if !locked {
			return tenancy.ErrInvitationBusy
		}
		return nil
	}
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text,6721587303))`, tenant)
	return err
}

func invitationView(ctx context.Context, tx pgx.Tx, tenant, id string, now time.Time) (v tenancy.InvitationView, err error) {
	err = tx.QueryRow(ctx, `SELECT tenant_id::text,invitation_id::text,
 CASE WHEN recipient_ciphertext IS NULL OR recipient_delete_after<=$3 THEN 'redacted' ELSE '***' END,
 roles,ARRAY(SELECT i::text FROM unnest(issuer_ids) i ORDER BY i),
 CASE WHEN state='pending' AND expires_at<=$3 THEN 'expired' ELSE state END,
 delivery_state,revision,created_at,expires_at,accepted_at,revoked_at FROM tenancy.invitations WHERE tenant_id=$1 AND invitation_id=$2`, tenant, id, now).
		Scan(&v.TenantID, &v.InvitationID, &v.RecipientHint, &v.Roles, &v.IssuerIDs, &v.State, &v.DeliveryState, &v.Revision, &v.CreatedAt, &v.ExpiresAt, &v.AcceptedAt, &v.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = a.ErrTenant
	}
	return
}

func (s *InvitationStore) MutateInvitation(ctx context.Context, c tenancy.InvitationCommand, build func(time.Time) (tenancy.InvitationMaterial, error)) (v tenancy.InvitationView, err error) {
	err = WithTenant(ctx, s.Pool, c.Actor, c.Tenant, func(tx pgx.Tx) error {
		capability := "members:invite"
		if c.Operation == "invitation.revoke" {
			capability = "invitations:revoke"
		}
		// Reject foreign actors before revealing even tenant lock contention.
		// This probe does not authorize the mutation; repeat after the lock.
		if e := authorizeInvitation(ctx, tx, c.Actor, c.Tenant, capability); e != nil {
			return e
		}
		if !s.Now().Before(c.PrivilegeDeadline) {
			return a.ErrStepUp
		}
		if e := lockInvitationTenant(ctx, tx, c.Tenant, true); e != nil {
			return e
		}
		now := s.Now().UTC()
		if e := authorizeInvitation(ctx, tx, c.Actor, c.Tenant, capability); e != nil {
			return e
		}
		if !now.Before(c.PrivilegeDeadline) {
			return a.ErrStepUp
		}
		var request []byte
		var id string
		e := tx.QueryRow(ctx, `SELECT request_hash,invitation_id::text FROM tenancy.member_idempotency WHERE tenant_id=$1 AND actor_id=$2 AND operation=$3 AND key_hash=$4 AND expires_at>$5`, c.Tenant, c.Actor, c.Operation, c.KeyHash, now).Scan(&request, &id)
		if e == nil {
			if !bytes.Equal(request, c.RequestHash) {
				return tenancy.ErrInvitationConflict
			}
			v, e = invitationView(ctx, tx, c.Tenant, id, now)
			if !s.Now().Before(c.PrivilegeDeadline) {
				return a.ErrStepUp
			}
			return e
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if _, e = tx.Exec(ctx, `DELETE FROM tenancy.member_idempotency WHERE tenant_id=$1 AND actor_id=$2 AND operation=$3 AND key_hash=$4 AND expires_at<=$5`, c.Tenant, c.Actor, c.Operation, c.KeyHash, now); e != nil {
			return e
		}
		action := "members.invitation.created"
		if c.Operation == "invitation.create" {
			// No authoritative issuer ownership source exists yet: fail closed.
			if len(c.Input.IssuerIDs) > 0 {
				return a.ErrDependency
			}
			m, e := build(now)
			if e != nil {
				return e
			}
			id = m.ID
			rows, e := tx.Query(ctx, `SELECT invitation_id::text FROM tenancy.invitations WHERE tenant_id=$1 AND recipient_hmac=$2 AND state='pending' ORDER BY invitation_id`, c.Tenant, m.RecipientHMAC)
			if e != nil {
				return e
			}
			var old []string
			for rows.Next() {
				var id string
				if e = rows.Scan(&id); e != nil {
					break
				}
				old = append(old, id)
			}
			rowErr := rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
			if rowErr != nil {
				return rowErr
			}
			for _, prior := range old {
				var state string
				e = tx.QueryRow(ctx, `UPDATE tenancy.invitations SET state=CASE WHEN expires_at<=$3 THEN 'expired' ELSE 'revoked' END,
    revoked_at=CASE WHEN expires_at>$3 THEN $3 END,revision=revision+1 WHERE tenant_id=$1 AND invitation_id=$2 RETURNING state`, c.Tenant, prior, now).Scan(&state)
				if e != nil {
					return e
				}
				if _, e = tx.Exec(ctx, `DELETE FROM tenancy.invitation_delivery_secrets WHERE tenant_id=$1 AND invitation_id=$2`, c.Tenant, prior); e != nil {
					return e
				}
				verb := "members.invitation.revoked"
				if state == "expired" {
					verb = "members.invitation.expired"
				}
				if e = appendEvent(ctx, tx, verb, "success", c.Actor, c.Tenant, prior); e != nil {
					return e
				}
			}
			_, e = tx.Exec(ctx, `INSERT INTO tenancy.invitations(invitation_id,tenant_id,created_by,token_hash,recipient_hmac,recipient_ciphertext,recipient_nonce,recipient_key_version,roles,issuer_ids,created_at,expires_at,recipient_delete_after)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::uuid[],$11,$12,$13)`, m.ID, c.Tenant, c.Actor, m.TokenHash, m.RecipientHMAC, m.Recipient.Ciphertext, m.Recipient.Nonce, m.Recipient.KeyVersion, c.Input.Roles, c.Input.IssuerIDs, m.CreatedAt, m.ExpiresAt, m.RecipientDeleteAfter)
			if e != nil {
				return e
			}
			_, e = tx.Exec(ctx, `INSERT INTO tenancy.invitation_delivery_secrets(tenant_id,invitation_id,ciphertext,nonce,key_version,created_at,delete_after) VALUES($1,$2,$3,$4,$5,$6,$7)`, c.Tenant, m.ID, m.Delivery.Ciphertext, m.Delivery.Nonce, m.Delivery.KeyVersion, m.CreatedAt, m.DeliveryDeleteAfter)
			if e != nil {
				return e
			}
		} else {
			id = c.InvitationID
			action = "members.invitation.revoked"
			current, e := invitationView(ctx, tx, c.Tenant, id, now)
			if e != nil {
				return e
			}
			if current.Revision != c.Revision {
				return tenancy.ErrInvitationRevision
			}
			if current.State != "pending" {
				return tenancy.ErrInvitationState
			}
			if _, e = tx.Exec(ctx, `UPDATE tenancy.invitations SET state='revoked',revoked_at=$3,revision=revision+1 WHERE tenant_id=$1 AND invitation_id=$2`, c.Tenant, id, now); e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, `DELETE FROM tenancy.invitation_delivery_secrets WHERE tenant_id=$1 AND invitation_id=$2`, c.Tenant, id); e != nil {
				return e
			}
		}
		_, e = tx.Exec(ctx, `INSERT INTO tenancy.member_idempotency(tenant_id,actor_id,operation,key_hash,request_hash,invitation_id,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, c.Tenant, c.Actor, c.Operation, c.KeyHash, c.RequestHash, id, now, now.Add(time.Duration(s.Policy.IdempotencySeconds)*time.Second))
		if e != nil {
			return e
		}
		if !s.Now().Before(c.PrivilegeDeadline) {
			return a.ErrStepUp
		}
		if e = appendEvent(ctx, tx, action, "success", c.Actor, c.Tenant, id); e != nil {
			return e
		}
		v, e = invitationView(ctx, tx, c.Tenant, id, now)
		return e
	})
	if err != nil {
		v = tenancy.InvitationView{}
		err = invitationError(err)
	}
	return
}
func invitationError(err error) error {
	for _, known := range []error{a.ErrTenant, a.ErrStepUp, tenancy.ErrDirectoryForbidden, tenancy.ErrInvitationBusy, tenancy.ErrInvitationConflict, tenancy.ErrInvitationRevision, tenancy.ErrInvitationState} {
		if errors.Is(err, known) {
			return known
		}
	}
	return a.ErrDependency
}

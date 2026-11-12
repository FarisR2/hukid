package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	a "hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
	"time"
)

func memberView(ctx context.Context, tx pgx.Tx, tenant, actor string) (v tenancy.MemberView, err error) {
	err = tx.QueryRow(ctx, `SELECT tenant_id::text,membership_id::text,operator_identity_id::text,
 ARRAY(SELECT role FROM tenancy.membership_roles r WHERE r.tenant_id=m.tenant_id AND r.membership_id=m.membership_id ORDER BY role),
 ARRAY(SELECT issuer_id::text FROM tenancy.membership_issuer_scopes s WHERE s.tenant_id=m.tenant_id AND s.membership_id=m.membership_id ORDER BY issuer_id),
 state,authorization_revision,lifecycle,created_at,updated_at FROM tenancy.memberships m WHERE tenant_id=$1 AND operator_identity_id=$2`, tenant, actor).Scan(&v.TenantID, &v.MembershipID, &v.OperatorIdentityID, &v.Roles, &v.IssuerIDs, &v.State, &v.Revision, &v.Lifecycle, &v.CreatedAt, &v.UpdatedAt)
	return
}

func (s *InvitationStore) AcceptInvitation(ctx context.Context, c tenancy.AcceptanceCommand, recipient func(string) []byte) (v tenancy.Acceptance, err error) {
	// The locator can return only one tenant for one full token digest. Its role
	// is not inherited by runtime and cannot see email, secrets or memberships.
	var tenant pgtype.UUID
	err = s.Pool.QueryRow(ctx, `SELECT tenancy.locate_invitation($1)`, c.TokenHash).Scan(&tenant)
	if err != nil {
		return v, a.ErrDependency
	}
	if !tenant.Valid {
		return v, tenancy.ErrInvitationInvalid
	}
	err = WithTenant(ctx, s.Pool, c.Actor, tenant.String(), func(tx pgx.Tx) error {
		if e := lockInvitationTenant(ctx, tx, tenant.String(), true); e != nil {
			return e
		}
		now := s.Now().UTC()
		fresh := func() bool {
			return a.RecipientFresh(c.Proof, s.Now(), time.Duration(s.Policy.EmailEvidenceSeconds)*time.Second)
		}
		if !fresh() {
			return a.ErrRecipient
		}
		var active bool
		if e := tx.QueryRow(ctx, `SELECT state='active' FROM tenancy.tenants WHERE tenant_id=$1`, tenant).Scan(&active); e != nil {
			return e
		}
		if !active {
			return tenancy.ErrInvitationInvalid
		}
		var id, state string
		var mac []byte
		var roles, issuers []string
		var created, expires, retention time.Time
		var acceptedLife, targetLife *int64
		var targetMember *string
		var targetRevoked *time.Time
		e := tx.QueryRow(ctx, `SELECT invitation_id::text,state,recipient_hmac,roles,ARRAY(SELECT i::text FROM unnest(issuer_ids)i),created_at,expires_at,recipient_delete_after,accepted_lifecycle,target_membership_id::text,target_lifecycle,target_revoked_at FROM tenancy.invitations WHERE tenant_id=$1 AND token_hash=$2 FOR UPDATE`, tenant, c.TokenHash).Scan(&id, &state, &mac, &roles, &issuers, &created, &expires, &retention, &acceptedLife, &targetMember, &targetLife, &targetRevoked)
		if errors.Is(e, pgx.ErrNoRows) {
			return tenancy.ErrInvitationInvalid
		}
		if e != nil {
			return e
		}
		if !now.Before(retention) || !hmac.Equal(mac, recipient(tenant.String())) {
			return tenancy.ErrInvitationInvalid
		}
		m, e := memberView(ctx, tx, tenant.String(), c.Actor)
		exists := e == nil
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		var request []byte
		var resultMember string
		e = tx.QueryRow(ctx, `SELECT request_hash,membership_id::text FROM tenancy.member_idempotency WHERE tenant_id=$1 AND actor_id=$2 AND operation='invitation.accept' AND token_hash=$3 AND key_hash=$4 AND expires_at>$5`, tenant, c.Actor, c.TokenHash, c.KeyHash, now).Scan(&request, &resultMember)
		if e == nil {
			if !bytes.Equal(request, c.TokenHash) {
				return tenancy.ErrInvitationConflict
			}
			if !exists || m.MembershipID != resultMember || acceptedLife == nil || m.Lifecycle != *acceptedLife || m.State == "revoked" {
				return tenancy.ErrMemberRevoked
			}
			if m.State != "active" {
				return tenancy.ErrMembershipExists
			}
			if !tenancy.DirectoryGrantShape(m.Roles, m.IssuerIDs) {
				return a.ErrDependency
			}
			if !fresh() {
				return a.ErrRecipient
			}
			v = tenancy.Acceptance{TenantID: tenant.String(), Membership: m}
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if !tenancy.InvitationUsable(state, created, expires, now) {
			return tenancy.ErrInvitationInvalid
		}
		if !tenancy.DirectoryGrantShape(roles, issuers) || len(issuers) > 0 {
			return a.ErrDependency
		}
		if exists && m.State != "revoked" {
			return tenancy.ErrMembershipExists
		}
		if targetMember != nil && (!exists || *targetMember != m.MembershipID || targetLife == nil || *targetLife != m.Lifecycle) {
			return tenancy.ErrInvitationInvalid
		}
		if exists {
			var revoked time.Time
			var archived bool
			if e = tx.QueryRow(ctx, `SELECT revoked_at,EXISTS(SELECT FROM tenancy.membership_history h WHERE h.tenant_id=m.tenant_id AND h.membership_id=m.membership_id AND h.lifecycle=m.lifecycle AND h.authorization_revision=m.authorization_revision AND h.revoked_at=m.revoked_at) FROM tenancy.memberships m WHERE tenant_id=$1 AND membership_id=$2 FOR UPDATE`, tenant, m.MembershipID).Scan(&revoked, &archived); e != nil {
				return e
			}
			if !created.After(revoked) || targetRevoked != nil && !targetRevoked.Equal(revoked) {
				return tenancy.ErrInvitationInvalid
			}
			if !archived || m.Revision >= 9007199254740991 || m.Lifecycle >= 9007199254740991 {
				return a.ErrDependency
			}
			_, e = tx.Exec(ctx, `UPDATE tenancy.memberships SET state='active',lifecycle=lifecycle+1,authorization_revision=authorization_revision+1,lifecycle_started_at=$3,updated_at=$3,revoked_at=NULL WHERE tenant_id=$1 AND membership_id=$2`, tenant, m.MembershipID, now)
			if e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, `DELETE FROM tenancy.membership_roles WHERE tenant_id=$1 AND membership_id=$2`, tenant, m.MembershipID); e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, `DELETE FROM tenancy.membership_issuer_scopes WHERE tenant_id=$1 AND membership_id=$2`, tenant, m.MembershipID); e != nil {
				return e
			}
		} else {
			e = tx.QueryRow(ctx, `INSERT INTO tenancy.memberships(tenant_id,operator_identity_id,created_at,updated_at,lifecycle_started_at) VALUES($1,$2,$3,$3,$3) RETURNING membership_id::text`, tenant, c.Actor, now).Scan(&m.MembershipID)
			if e != nil {
				return e
			}
		}
		for _, role := range roles {
			if _, e = tx.Exec(ctx, `INSERT INTO tenancy.membership_roles(tenant_id,membership_id,role) VALUES($1,$2,$3)`, tenant, m.MembershipID, role); e != nil {
				return e
			}
		}
		m, e = memberView(ctx, tx, tenant.String(), c.Actor)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE tenancy.invitations SET state='accepted',accepted_at=$3,accepted_membership_id=$4,accepted_lifecycle=$5,revision=revision+1 WHERE tenant_id=$1 AND invitation_id=$2`, tenant, id, now, m.MembershipID, m.Lifecycle); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `DELETE FROM tenancy.invitation_delivery_secrets WHERE tenant_id=$1 AND invitation_id=$2`, tenant, id); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `DELETE FROM tenancy.member_idempotency WHERE tenant_id=$1 AND actor_id=$2 AND operation='invitation.accept' AND token_hash=$3 AND key_hash=$4 AND expires_at<=$5`, tenant, c.Actor, c.TokenHash, c.KeyHash, now); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO tenancy.member_idempotency(tenant_id,actor_id,operation,key_hash,request_hash,token_hash,invitation_id,membership_id,created_at,expires_at) VALUES($1,$2,'invitation.accept',$3,$4,$4,$5,$6,$7,$8)`, tenant, c.Actor, c.KeyHash, c.TokenHash, id, m.MembershipID, now, now.Add(time.Duration(s.Policy.IdempotencySeconds)*time.Second)); e != nil {
			return e
		}
		if exists {
			if e = appendEvent(ctx, tx, "members.membership.reentered", "success", c.Actor, tenant.String(), m.MembershipID); e != nil {
				return e
			}
		}
		if !fresh() {
			return a.ErrRecipient
		}
		if !s.Now().Before(expires) {
			return tenancy.ErrInvitationInvalid
		}
		if e = appendEvent(ctx, tx, "members.invitation.accepted", "success", c.Actor, tenant.String(), id); e != nil {
			return e
		}
		v = tenancy.Acceptance{TenantID: tenant.String(), Membership: m}
		return nil
	})
	if err != nil {
		v = tenancy.Acceptance{}
		for _, known := range []error{tenancy.ErrInvitationInvalid, tenancy.ErrMembershipExists, tenancy.ErrMemberRevoked, a.ErrRecipient} {
			if errors.Is(err, known) {
				return v, known
			}
		}
		err = invitationError(err)
	}
	return
}

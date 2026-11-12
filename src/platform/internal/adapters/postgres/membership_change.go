package postgres

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	a "hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
)

func membershipByID(ctx context.Context, tx pgx.Tx, tenant, id string) (tenancy.MemberView, error) {
	var actor string
	err := tx.QueryRow(ctx, `SELECT operator_identity_id::text FROM tenancy.memberships WHERE tenant_id=$1 AND membership_id=$2`, tenant, id).Scan(&actor)
	if errors.Is(err, pgx.ErrNoRows) {
		return tenancy.MemberView{}, a.ErrTenant
	}
	if err != nil {
		return tenancy.MemberView{}, err
	}
	return memberView(ctx, tx, tenant, actor)
}

func (s *InvitationStore) ChangeMembership(ctx context.Context, c tenancy.MembershipCommand) (v tenancy.MemberView, err error) {
	err = WithTenant(ctx, s.Pool, c.Actor, c.Tenant, func(tx pgx.Tx) error {
		authorize := func() error {
			if e := authorizeInvitation(ctx, tx, c.Actor, c.Tenant, "members:update"); e != nil {
				return e
			}
			if c.Input.State == "revoked" {
				if e := authorizeInvitation(ctx, tx, c.Actor, c.Tenant, "members:revoke"); e != nil {
					return e
				}
			}
			if !s.Now().Before(c.PrivilegeDeadline) {
				return a.ErrStepUp
			}
			return nil
		}
		if e := authorize(); e != nil {
			return e
		}
		if e := lockInvitationTenant(ctx, tx, c.Tenant, true); e != nil {
			return e
		}
		if e := authorize(); e != nil {
			return e
		}
		now := s.Now().UTC()
		var request []byte
		var id string
		e := tx.QueryRow(ctx, `SELECT request_hash,membership_id::text FROM tenancy.member_idempotency WHERE tenant_id=$1 AND actor_id=$2 AND operation='membership.change' AND key_hash=$3 AND expires_at>$4`, c.Tenant, c.Actor, c.KeyHash, now).Scan(&request, &id)
		if e == nil {
			if !bytes.Equal(request, c.RequestHash) {
				return tenancy.ErrInvitationConflict
			}
			v, e = membershipByID(ctx, tx, c.Tenant, id)
			if e == nil && !tenancy.DirectoryGrantShape(v.Roles, v.IssuerIDs) {
				return a.ErrDependency
			}
			if !s.Now().Before(c.PrivilegeDeadline) {
				return a.ErrStepUp
			}
			return e
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		current, e := membershipByID(ctx, tx, c.Tenant, c.MembershipID)
		if e != nil {
			return e
		}
		state, roles := current.State, current.Roles
		if c.Input.State != "" {
			state = c.Input.State
		}
		if c.Input.Roles != nil {
			roles = c.Input.Roles
		}
		var admins int
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM tenancy.memberships m WHERE tenant_id=$1 AND state='active' AND EXISTS(SELECT FROM tenancy.membership_roles r WHERE r.tenant_id=m.tenant_id AND r.membership_id=m.membership_id AND role='tenant_admin')`, c.Tenant).Scan(&admins); e != nil {
			return e
		}
		if e = tenancy.CheckMembershipChange(tenancy.MemberAccess{State: current.State, Roles: current.Roles, Revision: current.Revision}, state, roles, c.Revision, admins); e != nil {
			return e
		}
		// No authoritative issuer ownership adapter exists. Explicit issuer grants
		// fail closed; a state-only operation preserves the already stored grants.
		if len(c.Input.IssuerIDs) > 0 {
			return a.ErrDependency
		}
		if _, e = tx.Exec(ctx, `UPDATE tenancy.memberships SET state=$3,authorization_revision=authorization_revision+1,updated_at=$4::timestamptz,revoked_at=CASE WHEN $3='revoked' THEN $4::timestamptz ELSE NULL END WHERE tenant_id=$1 AND membership_id=$2`, c.Tenant, c.MembershipID, state, now); e != nil {
			return e
		}
		if c.Input.Roles != nil {
			if _, e = tx.Exec(ctx, `DELETE FROM tenancy.membership_roles WHERE tenant_id=$1 AND membership_id=$2`, c.Tenant, c.MembershipID); e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, `DELETE FROM tenancy.membership_issuer_scopes WHERE tenant_id=$1 AND membership_id=$2`, c.Tenant, c.MembershipID); e != nil {
				return e
			}
			for _, role := range roles {
				if _, e = tx.Exec(ctx, `INSERT INTO tenancy.membership_roles(tenant_id,membership_id,role) VALUES($1,$2,$3)`, c.Tenant, c.MembershipID, role); e != nil {
					return e
				}
			}
		}
		action := "members.membership.changed"
		if state == "revoked" {
			action = "members.membership.revoked"
			if e = ArchiveRevokedMembership(ctx, tx, c.Tenant, c.MembershipID); e != nil {
				return e
			}
		}
		if _, e = tx.Exec(ctx, `DELETE FROM tenancy.member_idempotency WHERE tenant_id=$1 AND actor_id=$2 AND operation='membership.change' AND key_hash=$3 AND expires_at<=$4`, c.Tenant, c.Actor, c.KeyHash, now); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO tenancy.member_idempotency(tenant_id,actor_id,operation,key_hash,request_hash,membership_id,created_at,expires_at) VALUES($1,$2,'membership.change',$3,$4,$5,$6,$7)`, c.Tenant, c.Actor, c.KeyHash, c.RequestHash, c.MembershipID, now, now.Add(time.Duration(s.Policy.IdempotencySeconds)*time.Second)); e != nil {
			return e
		}
		if !s.Now().Before(c.PrivilegeDeadline) {
			return a.ErrStepUp
		}
		if e = appendEvent(ctx, tx, action, "success", c.Actor, c.Tenant, c.MembershipID); e != nil {
			return e
		}
		v, e = membershipByID(ctx, tx, c.Tenant, c.MembershipID)
		if e == nil && !tenancy.DirectoryGrantShape(v.Roles, v.IssuerIDs) {
			return a.ErrDependency
		}
		return e
	})
	if err != nil {
		v = tenancy.MemberView{}
		for _, known := range []error{tenancy.ErrMemberInput, tenancy.ErrMemberRevision, tenancy.ErrMemberRevoked, tenancy.ErrLastAdmin} {
			if errors.Is(err, known) {
				return v, known
			}
		}
		err = invitationError(err)
	}
	return
}

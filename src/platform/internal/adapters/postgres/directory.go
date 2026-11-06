package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
	"time"
)

type DirectoryStore struct{ Pool *pgxpool.Pool }

// Authorization and directory projection share a read-only repeatable snapshot.
// Only safe columns are selected; recipient ciphertext is never retrieved.
func (s *DirectoryStore) ReadDirectory(ctx context.Context, actor, tenant, kind string, f tenancy.DirectoryFilter, pos tenancy.DirectoryPosition, now time.Time) (result tenancy.DirectoryRows, err error) {
	if !validID(actor) || !validID(tenant) {
		return result, authentication.ErrTenant
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, authentication.ErrDependency
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, `SELECT set_config('app.operator_id',$1,true),set_config('app.tenant_id',$2,true)`, actor, tenant); err != nil {
		return result, authentication.ErrDependency
	}
	var roles []string
	err = tx.QueryRow(ctx, `SELECT ARRAY(SELECT r.role FROM tenancy.membership_roles r WHERE r.tenant_id=m.tenant_id AND r.membership_id=m.membership_id ORDER BY r.role) FROM tenancy.memberships m JOIN tenancy.tenants t ON t.tenant_id=m.tenant_id WHERE m.tenant_id=$1 AND m.operator_identity_id=$2 AND m.state='active' AND t.state='active'`, tenant, actor).Scan(&roles)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, authentication.ErrTenant
	}
	if err != nil {
		return result, authentication.ErrDependency
	}
	if !tenancy.DirectoryAllowed(roles, kind) {
		return result, tenancy.ErrDirectoryForbidden
	}
	id := pos.ID
	if id == "" {
		id = "00000000-0000-0000-0000-000000000000"
	}
	if kind == "memberships" {
		rows, e := tx.Query(ctx, `SELECT m.tenant_id::text,m.membership_id::text,m.operator_identity_id::text,
   ARRAY(SELECT r.role FROM tenancy.membership_roles r WHERE r.tenant_id=m.tenant_id AND r.membership_id=m.membership_id ORDER BY r.role),
   ARRAY(SELECT i.issuer_id::text FROM tenancy.membership_issuer_scopes i WHERE i.tenant_id=m.tenant_id AND i.membership_id=m.membership_id ORDER BY i.issuer_id),
   m.state,m.authorization_revision,m.lifecycle,m.created_at,m.updated_at
   FROM tenancy.memberships m WHERE m.tenant_id=$1 AND ($2='' OR m.state=$2)
   AND ($3='' OR EXISTS(SELECT FROM tenancy.membership_roles r WHERE r.tenant_id=m.tenant_id AND r.membership_id=m.membership_id AND r.role=$3))
   AND ($4='' OR starts_with(m.membership_id::text,$4) OR starts_with(m.operator_identity_id::text,$4))
   AND ($5 OR (m.created_at,m.membership_id)>($6,$7::uuid)) ORDER BY m.created_at,m.membership_id LIMIT $8`, tenant, f.State, f.Role, f.Query, pos.ID == "", pos.CreatedAt, id, f.Limit+1)
		if e != nil {
			return result, authentication.ErrDependency
		}
		for rows.Next() {
			var m tenancy.MemberView
			if e = rows.Scan(&m.TenantID, &m.MembershipID, &m.OperatorIdentityID, &m.Roles, &m.IssuerIDs, &m.State, &m.Revision, &m.Lifecycle, &m.CreatedAt, &m.UpdatedAt); e != nil {
				break
			}
			if !tenancy.DirectoryGrantShape(m.Roles, m.IssuerIDs) {
				e = authentication.ErrDependency
				break
			}
			result.Members = append(result.Members, m)
		}
		err = rows.Err()
		rows.Close()
		if e != nil || err != nil {
			return tenancy.DirectoryRows{}, authentication.ErrDependency
		}
	} else {
		rows, e := tx.Query(ctx, `SELECT tenant_id::text,invitation_id::text,
   CASE WHEN recipient_ciphertext IS NULL OR recipient_delete_after<=$2 THEN 'redacted' ELSE '***' END,
   roles,ARRAY(SELECT i::text FROM unnest(issuer_ids) i ORDER BY i),
   CASE WHEN state='pending' AND expires_at<=$2 THEN 'expired' ELSE state END,
   delivery_state,revision,created_at,expires_at,accepted_at,revoked_at
   FROM tenancy.invitations WHERE tenant_id=$1
   AND ($3='' OR (CASE WHEN state='pending' AND expires_at<=$2 THEN 'expired' ELSE state END)=$3)
   AND ($4='' OR delivery_state=$4) AND ($5 OR (created_at,invitation_id)>($6,$7::uuid))
   ORDER BY created_at,invitation_id LIMIT $8`, tenant, now, f.State, f.DeliveryState, pos.ID == "", pos.CreatedAt, id, f.Limit+1)
		if e != nil {
			return result, authentication.ErrDependency
		}
		for rows.Next() {
			var i tenancy.InvitationView
			if e = rows.Scan(&i.TenantID, &i.InvitationID, &i.RecipientHint, &i.Roles, &i.IssuerIDs, &i.State, &i.DeliveryState, &i.Revision, &i.CreatedAt, &i.ExpiresAt, &i.AcceptedAt, &i.RevokedAt); e != nil {
				break
			}
			result.Invitations = append(result.Invitations, i)
		}
		err = rows.Err()
		rows.Close()
		if e != nil || err != nil {
			return tenancy.DirectoryRows{}, authentication.ErrDependency
		}
	}
	if tx.Commit(ctx) != nil {
		return tenancy.DirectoryRows{}, authentication.ErrDependency
	}
	return result, nil
}

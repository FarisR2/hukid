package postgres

import (
	"context"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrMemberTenant = errors.New("membership tenant unavailable")

// MemberEvent contains only closed vocabulary and an opaque target, never PII.
type MemberEvent struct {
	Action string
	Target string
}

var memberActions = []string{
	"members.invitation.created", "members.invitation.revoked", "members.invitation.accepted",
	"members.invitation.expired", "members.delivery.sent", "members.delivery.failed",
	"members.membership.changed", "members.membership.revoked", "members.membership.reentered",
	"members.retention.purged",
}

// WithMemberMutation is a persistence primitive, NOT an authorization boundary.
// IDs must come from verified server context. The callback must reauthorize the
// actor (or verified recipient for acceptance), revision and grants under this
// lock, before modifying any row. No OIDC or provider I/O inside the callback.
// All membership/invitation writers must use this lock, including reentry.
// A successful callback always commits its event/outbox with the mutation.
func WithMemberMutation(ctx context.Context, pool *pgxpool.Pool, actor, tenant string, fn func(pgx.Tx) (MemberEvent, error)) error {
	return WithTenant(ctx, pool, actor, tenant, func(tx pgx.Tx) error {
		// Hash collisions only serialize unrelated tenants; they cannot weaken
		// exclusion. Transaction-level locks are released on all exit paths.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text,6721587303))`, tenant); err != nil {
			return err
		}
		var active bool
		if err := tx.QueryRow(ctx, `SELECT state='active' FROM tenancy.tenants WHERE tenant_id=$1`, tenant).Scan(&active); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrMemberTenant
			}
			return err
		}
		if !active {
			return ErrMemberTenant
		}
		event, err := fn(tx)
		if err != nil {
			return err
		}
		if !slices.Contains(memberActions, event.Action) || !validID(event.Target) {
			return errors.New("invalid membership event")
		}
		return appendEvent(ctx, tx, event.Action, "success", actor, tenant, event.Target)
	})
}

// ArchiveRevokedMembership preserves the final grants of a lifecycle before
// reentry replaces them. Invoke in the same locked transaction as revocation.
// Runtime cannot update/delete the archive; conflicts fail instead of overwrite.
func ArchiveRevokedMembership(ctx context.Context, tx pgx.Tx, tenant, member string) error {
	result, err := tx.Exec(ctx, `INSERT INTO tenancy.membership_history
	 (tenant_id,membership_id,lifecycle,authorization_revision,roles,issuer_ids,started_at,revoked_at)
	 SELECT m.tenant_id,m.membership_id,m.lifecycle,m.authorization_revision,
	 ARRAY(SELECT r.role FROM tenancy.membership_roles r WHERE r.tenant_id=m.tenant_id AND r.membership_id=m.membership_id ORDER BY r.role),
	 ARRAY(SELECT s.issuer_id FROM tenancy.membership_issuer_scopes s WHERE s.tenant_id=m.tenant_id AND s.membership_id=m.membership_id ORDER BY s.issuer_id),
	 m.lifecycle_started_at,m.revoked_at FROM tenancy.memberships m
	 WHERE m.tenant_id=$1 AND m.membership_id=$2 AND m.state='revoked' AND m.revoked_at IS NOT NULL`, tenant, member)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return errors.New("revoked membership snapshot unavailable")
	}
	return nil
}

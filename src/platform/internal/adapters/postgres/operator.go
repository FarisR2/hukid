package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
)

type OperatorStore struct{ Discovery, Tenant *pgxpool.Pool }

func (s *OperatorStore) Identity(ctx context.Context, operator authentication.Operator) (tenancy.Identity, error) {
	actor, tenants, err := DiscoverTenants(ctx, s.Discovery, operator.Issuer, operator.Subject)
	result := tenancy.Identity{ActorID: actor, Tenants: []tenancy.Tenant{}}
	for _, t := range tenants {
		result.Tenants = append(result.Tenants, tenancy.Tenant{ID: t.TenantID, DisplayName: t.DisplayName})
	}
	return result, err
}
func (s *OperatorStore) Membership(ctx context.Context, actor, tenant string) (tenancy.Membership, error) {
	if !validID(actor) || !validID(tenant) {
		return tenancy.Membership{}, authentication.ErrTenant
	}
	var result tenancy.Membership
	err := WithTenant(ctx, s.Tenant, actor, tenant, func(tx pgx.Tx) error {
		// One statement/snapshot: no stale role snapshot survives a subsequent request.
		return tx.QueryRow(ctx, `SELECT m.authorization_revision, ARRAY(SELECT r.role FROM tenancy.membership_roles r WHERE r.tenant_id=m.tenant_id AND r.membership_id=m.membership_id ORDER BY r.role), ARRAY(SELECT s.issuer_id::text FROM tenancy.membership_issuer_scopes s WHERE s.tenant_id=m.tenant_id AND s.membership_id=m.membership_id ORDER BY s.issuer_id) FROM tenancy.memberships m JOIN tenancy.tenants t ON t.tenant_id=m.tenant_id WHERE m.operator_identity_id=$1 AND m.tenant_id=$2 AND m.state='active' AND t.state='active'`, actor, tenant).Scan(&result.Revision, &result.Roles, &result.IssuerIDs)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, authentication.ErrTenant
	}
	if err != nil {
		return result, authentication.ErrDependency
	}
	return result, nil
}

// Package tenancy resolves local operator authorization without trusting token roles.
package tenancy

import (
	"context"
	"encoding/json"
	"hukid.local/platform/contracts"
	"hukid.local/platform/internal/authentication"
	"slices"
)

type Tenant struct {
	ID          string
	DisplayName string
}
type Identity struct {
	ActorID string
	Tenants []Tenant
}
type Context struct {
	TenantID                       string
	Capabilities, IssuerIDs, Roles []string
	AuthorizationRevision          int64
}
type Membership struct {
	Roles     []string
	IssuerIDs []string
	Revision  int64
}
type Store interface {
	Identity(context.Context, authentication.Operator) (Identity, error)
	Membership(context.Context, string, string) (Membership, error)
}
type Service struct {
	Store Store
	roles map[string][]string
}

func New(store Store) (*Service, error) {
	var matrix struct {
		Roles map[string][]string `json:"roles"`
	}
	if err := json.Unmarshal(contracts.Capabilities, &matrix); err != nil {
		return nil, err
	}
	return &Service{Store: store, roles: matrix.Roles}, nil
}
func (s *Service) Me(ctx context.Context, actor authentication.Operator) (Identity, error) {
	i, err := s.Store.Identity(ctx, actor)
	if err != nil {
		return Identity{}, authentication.ErrDependency
	}
	if i.ActorID == "" {
		return Identity{}, authentication.ErrCredential
	}
	if i.Tenants == nil {
		i.Tenants = []Tenant{}
	}
	return i, nil
}
func (s *Service) Context(ctx context.Context, actorID, tenantID string) (Context, error) {
	m, err := s.Store.Membership(ctx, actorID, tenantID)
	if err != nil {
		return Context{}, err
	}
	c := Context{TenantID: tenantID, Capabilities: []string{}, IssuerIDs: append([]string{}, m.IssuerIDs...), Roles: append([]string{}, m.Roles...), AuthorizationRevision: m.Revision}
	for _, role := range m.Roles {
		permissions, ok := s.roles[role]
		if !ok {
			return Context{}, authentication.ErrDependency
		}
		for _, permission := range permissions {
			if !slices.Contains(c.Capabilities, permission) {
				c.Capabilities = append(c.Capabilities, permission)
			}
		}
	}
	slices.Sort(c.Capabilities)
	return c, nil
}

// SessionContext revalidates the selected tenant without treating the stored
// revision as authority. A missing membership returns the browser to selection.
func (s *Service) SessionContext(ctx context.Context, actor, tenant string) (authentication.ContextSelection, error) {
	c, err := s.Context(ctx, actor, tenant)
	if err != nil {
		return authentication.ContextSelection{}, err
	}
	return authentication.ContextSelection{TenantID: c.TenantID, Revision: c.AuthorizationRevision}, nil
}

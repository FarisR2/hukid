package tenancy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"

	a "hukid.local/platform/internal/authentication"
)

type ChangeMembershipInput struct {
	Roles      []string `json:"roles,omitempty"`
	IssuerIDs  []string `json:"issuerIds,omitempty"`
	State      string   `json:"state,omitempty"`
	ReasonCode string   `json:"reasonCode"`
}

type MembershipCommand struct {
	Actor, Tenant, MembershipID, Key string
	Revision                         int64
	PrivilegeDeadline                time.Time
	Input                            ChangeMembershipInput
	KeyHash, RequestHash             []byte
}

type MembershipStore interface {
	ChangeMembership(context.Context, MembershipCommand) (MemberView, error)
}

type MembershipService struct {
	Store  MembershipStore
	Policy MembershipPolicy
}

func (s *MembershipService) Execute(ctx context.Context, c MembershipCommand) (MemberView, error) {
	if !memberIssuerID.MatchString(c.Actor) || !memberIssuerID.MatchString(c.Tenant) || !memberIssuerID.MatchString(c.MembershipID) {
		return MemberView{}, a.ErrTenant
	}
	if !commandKey.MatchString(c.Key) || c.Revision < 1 || c.Revision > 9007199254740991 {
		return MemberView{}, ErrDirectoryRequest
	}
	in := c.Input
	if !slices.Contains([]string{"access_change", "security_response", "operator_request", "invitation_cancelled"}, in.ReasonCode) ||
		(in.State != "" && !slices.Contains([]string{"active", "suspended", "revoked"}, in.State)) ||
		(in.Roles == nil) != (in.IssuerIDs == nil) || (in.State == "" && in.Roles == nil) ||
		(in.Roles != nil && !DirectoryGrantShape(in.Roles, in.IssuerIDs)) {
		return MemberView{}, ErrMemberInput
	}
	if s.Store == nil || s.Policy.Validate("test") != nil {
		return MemberView{}, a.ErrDependency
	}
	c.Input.Roles = slices.Clone(in.Roles)
	c.Input.IssuerIDs = slices.Clone(in.IssuerIDs)
	slices.Sort(c.Input.Roles)
	slices.Sort(c.Input.IssuerIDs)
	// Include target, revision and presence of grants: an omitted grant differs
	// from an explicit replacement, even for an empty issuer set.
	data, _ := json.Marshal(struct {
		ID       string
		Revision int64
		Input    ChangeMembershipInput
	}{c.MembershipID, c.Revision, c.Input})
	request := sha256.Sum256(data)
	key := sha256.Sum256([]byte(c.Key))
	c.RequestHash, c.KeyHash = request[:], key[:]
	return s.Store.ChangeMembership(ctx, c)
}

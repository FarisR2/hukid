package tenancy

import (
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"hukid.local/platform/contracts"
)

var (
	ErrMemberInput    = errors.New("invalid membership input")
	ErrMemberScope    = errors.New("issuer outside authorized tenant scope")
	ErrMemberRevoked  = errors.New("membership lifecycle is revoked")
	ErrMemberRevision = errors.New("membership revision mismatch")
	ErrLastAdmin      = errors.New("active tenant administrator required")
)

// MembershipPolicy is an explicit laboratory policy, not runtime provisioning.
// USR-T04/T05 will connect it to delivery and verified recipient evidence.
type MembershipPolicy struct {
	Environment               string `json:"environment"`
	Version                   string `json:"version"`
	InvitationSeconds         int    `json:"invitationSeconds"`
	IdempotencySeconds        int    `json:"idempotencySeconds"`
	DeliverySecretSeconds     int    `json:"deliverySecretSeconds"`
	RecipientRetentionSeconds int    `json:"recipientRetentionSeconds"`
	CursorSeconds             int    `json:"cursorSeconds"`
	EmailEvidenceSeconds      int    `json:"emailEvidenceSeconds"`
	MaxPageSize               int    `json:"maxPageSize"`
	EmailProfile              string `json:"emailProfile"`
	Reentry                   string `json:"reentry"`
	Notification              string `json:"notification"`
}

func LoadMembershipPolicy(reader io.Reader, environment string) (MembershipPolicy, error) {
	var p MembershipPolicy
	data, err := io.ReadAll(io.LimitReader(reader, 65537))
	if err != nil || len(data) > 65536 {
		return p, ErrMemberInput
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil || decoder.Decode(new(any)) != io.EOF || p.Validate(environment) != nil {
		return MembershipPolicy{}, ErrMemberInput
	}
	return p, nil
}

func (p MembershipPolicy) Validate(environment string) error {
	if environment != "test" || p.Environment != environment || p.Version != "usr-t01-test-v1" ||
		p.EmailProfile != "ascii-case-sensitive-local-v1" || p.Reentry != "same-membership-new-lifecycle" || p.Notification != "synthetic-only" {
		return ErrMemberInput
	}
	for _, seconds := range []int{p.InvitationSeconds, p.IdempotencySeconds, p.DeliverySecretSeconds, p.RecipientRetentionSeconds, p.CursorSeconds, p.EmailEvidenceSeconds} {
		if seconds < 1 || seconds > 604800 {
			return ErrMemberInput
		}
	}
	if p.InvitationSeconds > 86400 || p.IdempotencySeconds < p.InvitationSeconds ||
		p.DeliverySecretSeconds > p.InvitationSeconds || p.RecipientRetentionSeconds < p.InvitationSeconds ||
		p.CursorSeconds > 900 || p.EmailEvidenceSeconds > 300 || p.MaxPageSize < 1 || p.MaxPageSize > 100 {
		return ErrMemberInput
	}
	return nil
}

var invitationEmail = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")

// NormalizeInvitationEmail preserves the local part exactly. It never infers an
// identity, verifies an address, strips aliases, or applies provider heuristics.
func NormalizeInvitationEmail(value string) (string, error) {
	local, domain, ok := strings.Cut(value, "@")
	if !ok || len(value) > 254 || len(local) > 64 || !invitationEmail.MatchString(value) {
		return "", ErrMemberInput
	}
	return local + "@" + strings.ToLower(domain), nil
}

// InvitationUsable uses local deadlines, without adding IdP clock skew.
func InvitationUsable(state string, createdAt, expiresAt, now time.Time) bool {
	return state == "pending" && !createdAt.IsZero() && expiresAt.After(createdAt) && !now.Before(createdAt) && now.Before(expiresAt)
}

var memberIssuerID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidateMemberGrant accepts only issuer ownership resolved by a trusted caller
// in the current tenant. Passing browser-supplied ownership would be unsafe.
func ValidateMemberGrant(roles, issuerIDs []string, ownedIssuerIDs map[string]bool) error {
	var matrix struct {
		Roles map[string][]string `json:"roles"`
	}
	if json.Unmarshal(contracts.Capabilities, &matrix) != nil || len(roles) < 1 || len(roles) > len(matrix.Roles) || len(issuerIDs) > 100 {
		return ErrMemberInput
	}
	seen := map[string]bool{}
	for _, role := range roles {
		if _, ok := matrix.Roles[role]; !ok || seen[role] {
			return ErrMemberInput
		}
		seen[role] = true
	}
	if slices.Contains(roles, "issuer_operator") != (len(issuerIDs) > 0) {
		return ErrMemberInput
	}
	seen = map[string]bool{}
	for _, id := range issuerIDs {
		if !memberIssuerID.MatchString(id) || seen[id] {
			return ErrMemberInput
		}
		if !ownedIssuerIDs[id] {
			return ErrMemberScope
		}
		seen[id] = true
	}
	return nil
}

// MemberAccess is a policy input, not an HTTP DTO or persistence snapshot.
type MemberAccess struct {
	State    string
	Roles    []string
	Revision int64
}

// CheckMembershipChange requires a current snapshot and administrator count
// obtained under the SAME tenant lock. This pure guard does not acquire locks,
// authorize the actor, validate issuer grants, or implement reentry.
func CheckMembershipChange(current MemberAccess, nextState string, nextRoles []string, expectedRevision int64, activeAdmins int) error {
	if current.Revision < 1 || current.Revision >= 9007199254740991 || activeAdmins < 0 ||
		!slices.Contains([]string{"active", "suspended", "revoked"}, current.State) ||
		!slices.Contains([]string{"active", "suspended", "revoked"}, nextState) {
		return ErrMemberInput
	}
	if current.Revision != expectedRevision {
		return ErrMemberRevision
	}
	if current.State == "revoked" {
		return ErrMemberRevoked
	}
	isAdmin := current.State == "active" && slices.Contains(current.Roles, "tenant_admin")
	remainsAdmin := nextState == "active" && slices.Contains(nextRoles, "tenant_admin")
	if isAdmin && (!remainsAdmin && activeAdmins <= 1 || activeAdmins == 0) {
		return ErrLastAdmin
	}
	return nil
}

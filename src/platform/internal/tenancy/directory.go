package tenancy

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"hukid.local/platform/contracts"
	"hukid.local/platform/internal/authentication"
)

var (
	ErrDirectoryRequest   = errors.New("invalid directory request")
	ErrDirectoryCursor    = errors.New("invalid directory cursor")
	ErrDirectoryForbidden = errors.New("directory access denied")
)

type DirectoryFilter struct {
	State         string
	Role          string
	Query         string
	DeliveryState string
	Limit         int
}
type DirectoryPosition struct {
	CreatedAt time.Time
	ID        string
}
type MemberView struct {
	TenantID           string    `json:"tenantId"`
	MembershipID       string    `json:"membershipId"`
	OperatorIdentityID string    `json:"operatorIdentityId"`
	Roles              []string  `json:"roles"`
	IssuerIDs          []string  `json:"issuerIds"`
	State              string    `json:"state"`
	Revision           int64     `json:"revision"`
	Lifecycle          int64     `json:"lifecycle"`
	CreatedAt          time.Time `json:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt"`
}
type InvitationView struct {
	TenantID      string     `json:"tenantId"`
	InvitationID  string     `json:"invitationId"`
	RecipientHint string     `json:"recipientHint"`
	Roles         []string   `json:"roles"`
	IssuerIDs     []string   `json:"issuerIds"`
	State         string     `json:"state"`
	DeliveryState string     `json:"deliveryState"`
	Revision      int64      `json:"revision"`
	CreatedAt     time.Time  `json:"createdAt"`
	ExpiresAt     time.Time  `json:"expiresAt"`
	AcceptedAt    *time.Time `json:"acceptedAt"`
	RevokedAt     *time.Time `json:"revokedAt"`
}
type DirectoryRows struct {
	Members     []MemberView
	Invitations []InvitationView
}
type DirectoryPage struct {
	Items      any     `json:"items"`
	NextCursor *string `json:"nextCursor"`
}
type DirectoryStore interface {
	ReadDirectory(context.Context, string, string, string, DirectoryFilter, DirectoryPosition, time.Time) (DirectoryRows, error)
}

// DirectoryGrantShape checks only the public representation, not issuer ownership
// or authority to write grants. Legacy incomplete grants must not be invented.
func DirectoryGrantShape(roles, issuers []string) bool {
	if len(roles) < 1 || len(roles) > 4 || len(issuers) > 100 || slices.Contains(roles, "issuer_operator") != (len(issuers) > 0) {
		return false
	}
	for index, role := range roles {
		if !slices.Contains([]string{"tenant_admin", "security_admin", "issuer_operator", "support_readonly"}, role) || slices.Contains(roles[:index], role) {
			return false
		}
	}
	for index, id := range issuers {
		if !memberIssuerID.MatchString(id) || slices.Contains(issuers[:index], id) {
			return false
		}
	}
	return true
}

type Directory struct {
	Store       DirectoryStore
	aead        cipher.AEAD
	ttl         time.Duration
	maxPageSize int
	Now         func() time.Time
}

func NewDirectory(store DirectoryStore, key []byte, policy MembershipPolicy, now func() time.Time) (*Directory, error) {
	if len(key) != 32 || policy.Validate("test") != nil || now == nil || store == nil {
		return nil, ErrMemberInput
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Directory{Store: store, aead: aead, ttl: time.Duration(policy.CursorSeconds) * time.Second, maxPageSize: policy.MaxPageSize, Now: now}, nil
}

// DirectoryAllowed uses the same capability source as AUTH; token roles never enter here.
func DirectoryAllowed(roles []string, kind string) bool {
	capability := "members:read"
	if kind == "invitations" {
		capability = "invitations:read"
	} else if kind != "memberships" {
		return false
	}
	var matrix struct {
		Roles map[string][]string `json:"roles"`
	}
	if json.Unmarshal(contracts.Capabilities, &matrix) != nil {
		return false
	}
	for _, role := range roles {
		if _, ok := matrix.Roles[role]; !ok {
			return false
		}
	}
	for _, role := range roles {
		if slices.Contains(matrix.Roles[role], capability) {
			return true
		}
	}
	return false
}

func ParseDirectoryFilter(raw, kind string) (DirectoryFilter, string, error) {
	f := DirectoryFilter{Limit: 25}
	if len(raw) > 4096 {
		return f, "", ErrDirectoryRequest
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return f, "", ErrDirectoryRequest
	}
	allowed := []string{"state", "cursor", "limit"}
	states := []string{"active", "suspended", "revoked"}
	if kind == "invitations" {
		allowed = append(allowed, "deliveryState")
		states = []string{"pending", "accepted", "revoked", "expired"}
	} else if kind == "memberships" {
		allowed = append(allowed, "role", "query")
	} else {
		return f, "", ErrDirectoryRequest
	}
	for key, v := range values {
		if !slices.Contains(allowed, key) || len(v) != 1 || v[0] == "" {
			return f, "", ErrDirectoryRequest
		}
	}
	f.State = values.Get("state")
	f.Role = values.Get("role")
	f.Query = values.Get("query")
	f.DeliveryState = values.Get("deliveryState")
	if f.State != "" && !slices.Contains(states, f.State) || f.Role != "" && !slices.Contains([]string{"tenant_admin", "security_admin", "issuer_operator", "support_readonly"}, f.Role) || f.DeliveryState != "" && !slices.Contains([]string{"queued", "sent", "failed"}, f.DeliveryState) {
		return f, "", ErrMemberInput
	}
	if f.Query != "" && !canonicalUUIDPrefix(f.Query) {
		return f, "", ErrMemberInput
	}
	if limit, ok := values["limit"]; ok {
		if !regexp.MustCompile(`^[0-9]+$`).MatchString(limit[0]) {
			return f, "", ErrMemberInput
		}
		f.Limit, err = strconv.Atoi(limit[0])
		if err != nil || f.Limit < 1 || f.Limit > 100 {
			return f, "", ErrMemberInput
		}
	}
	return f, values.Get("cursor"), nil
}
func canonicalUUIDPrefix(value string) bool {
	if len(value) < 8 || len(value) > 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

type directoryCursor struct {
	Version             int
	Actor, Tenant, Kind string
	Filter              DirectoryFilter
	Position            DirectoryPosition
	Deadline            time.Time
}

func (s *Directory) List(ctx context.Context, actor, tenant, kind, raw string) (DirectoryPage, error) {
	if !memberIssuerID.MatchString(tenant) {
		return DirectoryPage{}, authentication.ErrTenant
	}
	f, token, err := ParseDirectoryFilter(raw, kind)
	if err != nil {
		return DirectoryPage{}, err
	}
	if f.Limit > s.maxPageSize {
		return DirectoryPage{}, ErrMemberInput
	}
	now := s.Now().UTC()
	cursor := directoryCursor{Version: 1, Actor: actor, Tenant: tenant, Kind: kind, Filter: f, Deadline: now.Add(s.ttl)}
	if token != "" {
		if len(token) > 2048 {
			return DirectoryPage{}, ErrDirectoryCursor
		}
		data, e := base64.RawURLEncoding.Strict().DecodeString(token)
		if e != nil || len(data) < s.aead.NonceSize()+s.aead.Overhead() {
			return DirectoryPage{}, ErrDirectoryCursor
		}
		plain, e := s.aead.Open(nil, data[:s.aead.NonceSize()], data[s.aead.NonceSize():], []byte("hukid:directory:v1"))
		var decoded directoryCursor
		if e != nil || json.Unmarshal(plain, &decoded) != nil || decoded.Version != 1 || decoded.Actor != actor || decoded.Tenant != tenant || decoded.Kind != kind || decoded.Filter != f || !now.Before(decoded.Deadline) || decoded.Deadline.After(now.Add(s.ttl)) || !memberIssuerID.MatchString(decoded.Position.ID) || decoded.Position.CreatedAt.IsZero() {
			return DirectoryPage{}, ErrDirectoryCursor
		}
		cursor = decoded
	}
	rows, err := s.Store.ReadDirectory(ctx, actor, tenant, kind, f, cursor.Position, now)
	if err != nil {
		return DirectoryPage{}, err
	}
	page := DirectoryPage{}
	more := false
	if kind == "memberships" {
		if rows.Members == nil {
			rows.Members = []MemberView{}
		}
		more = len(rows.Members) > f.Limit
		if more {
			rows.Members = rows.Members[:f.Limit]
		}
		page.Items = rows.Members
		if more {
			last := rows.Members[len(rows.Members)-1]
			cursor.Position = DirectoryPosition{last.CreatedAt, last.MembershipID}
		}
	} else {
		if rows.Invitations == nil {
			rows.Invitations = []InvitationView{}
		}
		more = len(rows.Invitations) > f.Limit
		if more {
			rows.Invitations = rows.Invitations[:f.Limit]
		}
		page.Items = rows.Invitations
		if more {
			last := rows.Invitations[len(rows.Invitations)-1]
			cursor.Position = DirectoryPosition{last.CreatedAt, last.InvitationID}
		}
	}
	if more {
		plain, e := json.Marshal(cursor)
		if e != nil {
			return DirectoryPage{}, authentication.ErrDependency
		}
		nonce := make([]byte, s.aead.NonceSize())
		if _, e = rand.Read(nonce); e != nil {
			return DirectoryPage{}, authentication.ErrDependency
		}
		next := base64.RawURLEncoding.EncodeToString(s.aead.Seal(nonce, nonce, plain, []byte("hukid:directory:v1")))
		page.NextCursor = &next
	}
	return page, nil
}

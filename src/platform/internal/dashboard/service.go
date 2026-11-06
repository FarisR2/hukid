package dashboard

import (
	"context"
	"errors"
	"slices"
	"time"

	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
)

var ErrForbidden = errors.New("dashboard access denied")

// Access is loaded from live tenancy data inside the read snapshot. Callers
// supply only authenticated actor IDs, never roles or capabilities from a client.
type Access struct {
	Revision         int64
	Roles, IssuerIDs []string
}

type Position struct {
	At time.Time
	ID string
}

type Event struct {
	EventID    string    `json:"eventId"`
	Action     string    `json:"action"`
	Outcome    string    `json:"outcome"`
	OccurredAt time.Time `json:"occurredAt"`
	ActorID    *string   `json:"actorId"`
	TargetID   string    `json:"targetId"`
}

// Snapshot cannot escape Read. Authorization and all queries use one read-only
// repeatable snapshot; no source may be queried before the capability check.
type Snapshot interface {
	Access() Access
	ActiveMembers(context.Context) (int64, time.Time, error)
	Activity(context.Context, Filter, Position, time.Time) ([]Event, error)
}

type Store interface {
	Read(context.Context, string, string, func(Snapshot) error) error
}

type Window struct {
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
	TimeZone string    `json:"timeZone"`
	Bounds   string    `json:"bounds"`
}

type Section struct {
	State      string     `json:"state"`
	Value      *int64     `json:"value"`
	AsOf       *time.Time `json:"asOf"`
	ReasonCode *string    `json:"reasonCode"`
}

type Overview struct {
	TenantID    string             `json:"tenantId"`
	IssuerID    *string            `json:"issuerId"`
	GeneratedAt time.Time          `json:"generatedAt"`
	Window      Window             `json:"window"`
	Sections    map[string]Section `json:"sections"`
}

// Service is not connected to HTTP until DASH-T03. Its store is a separate
// read credential; it never resolves identities, decrypts sessions or emits audit.
type Service struct {
	store  Store
	policy Policy
	now    func() time.Time
}

func New(store Store, policy Policy, now func() time.Time) (*Service, error) {
	if store == nil || now == nil || policy.Validate() != nil {
		return nil, ErrRequest
	}
	return &Service{store: store, policy: policy, now: now}, nil
}

func authorize(a Access, f Filter, activity bool) error {
	if a.Revision < 1 || !tenancy.DirectoryGrantShape(a.Roles, a.IssuerIDs) {
		return authentication.ErrDependency
	}
	if !tenancy.MemberCapabilityAllowed(a.Roles, "dashboard:read") || activity && !tenancy.MemberCapabilityAllowed(a.Roles, "audit:read") {
		return ErrForbidden
	}
	// A generic role never widens issuer grants. There is no trusted issuer
	// ownership source yet, so neither explicit selectors nor assigned sets can
	// authorize an aggregate. Empty grants must never mean all issuers.
	restricted := slices.Contains(a.Roles, "issuer_operator")
	if f.IssuerID != "" && restricted && !slices.Contains(a.IssuerIDs, f.IssuerID) {
		return authentication.ErrTenant
	}
	if f.IssuerID != "" || restricted {
		return authentication.ErrDependency
	}
	return nil
}

func window(f Filter) Window { return Window{f.From, f.To, "UTC", "[from,to)"} }

func hidden(state, reason string) Section {
	return Section{State: state, ReasonCode: &reason}
}

// SourceSection distinguishes a successful zero from absent, failed or stale
// data. Permissions are evaluated first, including for future source adapters.
func SourceSection(allowed, connected bool, value int64, asOf, generated time.Time, sourceErr error, staleAfter time.Duration) Section {
	if !allowed {
		return hidden("notAuthorized", "capability_required")
	}
	if !connected {
		return hidden("unavailable", "source_not_connected")
	}
	if sourceErr != nil || value < 0 || value > 9007199254740991 || asOf.IsZero() || asOf.After(generated) {
		return hidden("error", "source_failed")
	}
	asOf = asOf.UTC()
	s := Section{State: "available", Value: &value, AsOf: &asOf}
	if generated.Sub(asOf) > staleAfter {
		s.State = "stale"
		reason := "source_stale"
		s.ReasonCode = &reason
	}
	return s
}

func (s *Service) Overview(ctx context.Context, actor, tenant, raw string) (Overview, error) {
	if !issuerID.MatchString(actor) || !issuerID.MatchString(tenant) {
		return Overview{}, authentication.ErrTenant
	}
	f, err := ParseQuery(raw, false, s.now().UTC(), s.policy)
	if err != nil {
		return Overview{}, err
	}
	result := Overview{TenantID: tenant, Window: window(f), Sections: map[string]Section{}}
	err = s.store.Read(ctx, actor, tenant, func(reader Snapshot) error {
		a := reader.Access()
		if err := authorize(a, f, false); err != nil {
			return err
		}
		var count int64
		var asOf time.Time
		var sourceErr error
		allowed := tenancy.MemberCapabilityAllowed(a.Roles, "members:read")
		if allowed {
			count, asOf, sourceErr = reader.ActiveMembers(ctx)
		}
		result.GeneratedAt = s.now().UTC()
		result.Sections["activeMembers"] = SourceSection(allowed, true, count, asOf, result.GeneratedAt, sourceErr, time.Duration(s.policy.StaleAfterSeconds)*time.Second)
		if result.Sections["activeMembers"].State == "error" {
			return authentication.ErrDependency
		}
		for name, capability := range map[string]string{"activeIssuers": "issuer:read", "publishedDefinitionVersions": "definition:read", "createdRequests": "issuance:read", "issuedCredentials": "issuance:read", "pendingStatusChanges": "status:read"} {
			result.Sections[name] = SourceSection(tenancy.MemberCapabilityAllowed(a.Roles, capability), false, 0, time.Time{}, result.GeneratedAt, nil, 0)
		}
		return nil
	})
	if err != nil {
		return Overview{}, err
	}
	return result, nil
}

// ReadActivity opens an authorized read snapshot. DASH-T03 must authenticate opaque
// cursor state (including Access revision/scopes) inside this snapshot, via the
// callback, before requesting rows. This port does not decode opaque cursors.
func (s *Service) ReadActivity(ctx context.Context, actor, tenant, raw string, read func(Snapshot, Filter) error) error {
	if read == nil {
		return ErrRequest
	}
	if !issuerID.MatchString(actor) || !issuerID.MatchString(tenant) {
		return authentication.ErrTenant
	}
	f, err := ParseQuery(raw, true, s.now().UTC(), s.policy)
	if err != nil {
		return err
	}
	return s.store.Read(ctx, actor, tenant, func(reader Snapshot) error {
		if err := authorize(reader.Access(), f, true); err != nil {
			return err
		}
		return read(reader, f)
	})
}

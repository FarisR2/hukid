package dashboard

import (
	"context"
	"errors"
	"testing"
	"time"

	"hukid.local/platform/internal/authentication"
)

func TestSourceAvailabilityAndFreshness(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name               string
		allowed, connected bool
		value              int64
		at                 time.Time
		err                error
		state, reason      string
	}{
		{"zero", true, true, 0, now, nil, "available", ""},
		{"permission first", false, false, 3, now, nil, "notAuthorized", "capability_required"},
		{"future source", true, false, 0, time.Time{}, nil, "unavailable", "source_not_connected"},
		{"failed", true, true, 0, now, errors.New("private database diagnostic"), "error", "source_failed"},
		{"no observation", true, true, 0, time.Time{}, nil, "error", "source_failed"},
		{"future observation", true, true, 1, now.Add(time.Second), nil, "error", "source_failed"},
		{"overflow", true, true, 9007199254740992, now, nil, "error", "source_failed"},
		{"negative", true, true, -1, now, nil, "error", "source_failed"},
		{"fresh boundary", true, true, 0, now.Add(-300 * time.Second), nil, "available", ""},
		{"stale zero", true, true, 0, now.Add(-301 * time.Second), nil, "stale", "source_stale"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := SourceSection(tc.allowed, tc.connected, tc.value, tc.at, now, tc.err, 300*time.Second)
			if s.State != tc.state || tc.reason != "" && (s.ReasonCode == nil || *s.ReasonCode != tc.reason) {
				t.Fatal(s)
			}
			if tc.state == "available" || tc.state == "stale" {
				if s.Value == nil || *s.Value != tc.value || s.AsOf == nil {
					t.Fatal("valid value lost")
				}
			} else if s.Value != nil || s.AsOf != nil {
				t.Fatal("protected/invalid value leaked")
			}
		})
	}
}

func TestAuthorizationFailsClosedBeforeSources(t *testing.T) {
	for _, tc := range []struct {
		access   Access
		filter   Filter
		activity bool
		want     error
	}{
		{Access{1, []string{"support_readonly"}, nil}, Filter{}, true, ErrForbidden},
		{Access{1, []string{"issuer_operator"}, nil}, Filter{}, false, authentication.ErrDependency},
		{Access{1, []string{"issuer_operator"}, []string{"70000000-0000-4000-8000-000000000001"}}, Filter{}, false, authentication.ErrDependency},
		{Access{1, []string{"tenant_admin", "issuer_operator"}, []string{"70000000-0000-4000-8000-000000000001"}}, Filter{}, false, authentication.ErrDependency},
		{Access{1, []string{"issuer_operator"}, []string{"70000000-0000-4000-8000-000000000001"}}, Filter{IssuerID: "70000000-0000-4000-8000-000000000002"}, false, authentication.ErrTenant},
		{Access{1, []string{"tenant_admin"}, nil}, Filter{IssuerID: "70000000-0000-4000-8000-000000000001"}, false, authentication.ErrDependency},
		{Access{1, []string{"unknown"}, nil}, Filter{}, false, authentication.ErrDependency},
	} {
		if err := authorize(tc.access, tc.filter, tc.activity); !errors.Is(err, tc.want) {
			t.Fatal("unexpected authorization", err)
		}
	}
	if err := authorize(Access{1, []string{"tenant_admin"}, nil}, Filter{}, true); err != nil {
		t.Fatal(err)
	}
}

type testSnapshot struct {
	access     Access
	countCalls int
	err        error
}

func (r *testSnapshot) Access() Access { return r.access }
func (r *testSnapshot) ActiveMembers(context.Context) (int64, time.Time, error) {
	r.countCalls++
	return 0, time.Now().UTC(), r.err
}
func (r *testSnapshot) Activity(context.Context, Filter, Position, time.Time) ([]Event, error) {
	panic("unauthorized source read")
}

type testStore struct{ reader *testSnapshot }

func (s testStore) Read(_ context.Context, _, _ string, fn func(Snapshot) error) error {
	return fn(s.reader)
}
func testPolicy() Policy { return Policy{"test", 86400, 2678400, 25, 100, 900, 300, 4096} }

func TestOverviewSkipsProtectedSourcesAndFailsOnOnlyConnectedSource(t *testing.T) {
	r := &testSnapshot{access: Access{1, []string{"support_readonly"}, nil}}
	s, _ := New(testStore{r}, testPolicy(), time.Now)
	o, err := s.Overview(context.Background(), "20000000-0000-4000-8000-000000000001", "10000000-0000-4000-8000-000000000001", "")
	if err != nil || r.countCalls != 0 || len(o.Sections) != 6 {
		t.Fatal("protected source queried", err)
	}
	for _, section := range o.Sections {
		if section.State != "notAuthorized" || section.Value != nil || section.AsOf != nil {
			t.Fatal(section)
		}
	}
	r.access.Roles = []string{"tenant_admin"}
	r.err = errors.New("private failure")
	if _, err = s.Overview(context.Background(), "20000000-0000-4000-8000-000000000001", "10000000-0000-4000-8000-000000000001", ""); !errors.Is(err, authentication.ErrDependency) {
		t.Fatal("failed source became zero", err)
	}
}

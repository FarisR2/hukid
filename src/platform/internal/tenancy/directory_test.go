package tenancy

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type directoryStub struct {
	calls    int
	position DirectoryPosition
	rows     DirectoryRows
}

func (s *directoryStub) ReadDirectory(_ context.Context, _, _, _ string, _ DirectoryFilter, p DirectoryPosition, _ time.Time) (DirectoryRows, error) {
	s.calls++
	s.position = p
	return s.rows, nil
}
func directoryPolicy(t *testing.T) MembershipPolicy {
	t.Helper()
	f, err := os.Open("../../config/user-management.test.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := LoadMembershipPolicy(f, "test")
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestDirectoryCursorBindingsAndDeadline(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	id := "30000000-0000-4000-8000-000000000001"
	store := &directoryStub{rows: DirectoryRows{Members: []MemberView{{MembershipID: id, CreatedAt: now.Add(-time.Hour)}, {MembershipID: id, CreatedAt: now}}}}
	key := []byte(strings.Repeat("k", 32))
	s, err := NewDirectory(store, key, directoryPolicy(t), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor, tenant := "20000000-0000-4000-8000-000000000001", "10000000-0000-4000-8000-000000000001"
	page, err := s.List(context.Background(), actor, tenant, "memberships", "limit=1")
	if err != nil || page.NextCursor == nil || len(page.Items.([]MemberView)) != 1 {
		t.Fatal("missing continuation", err)
	}
	token := *page.NextCursor
	tampered := "A" + token[1:]
	if tampered == token {
		tampered = "B" + token[1:]
	}
	for _, tc := range []struct{ actor, tenant, kind, query string }{
		{actor + "x", tenant, "memberships", "limit=1&cursor=" + token},
		{actor, "10000000-0000-4000-8000-000000000002", "memberships", "limit=1&cursor=" + token},
		{actor, tenant, "invitations", "limit=1&cursor=" + token},
		{actor, tenant, "memberships", "limit=2&cursor=" + token},
		{actor, tenant, "memberships", "limit=1&state=active&cursor=" + token},
		{actor, tenant, "memberships", "limit=1&cursor=" + tampered},
	} {
		before := store.calls
		if _, err := s.List(context.Background(), tc.actor, tc.tenant, tc.kind, tc.query); !errors.Is(err, ErrDirectoryCursor) || store.calls != before {
			t.Fatal("cursor binding accepted", err)
		}
	}
	if _, err = s.List(context.Background(), actor, tenant, "memberships", "cursor="+token+"&limit=1"); err != nil || store.position.ID != id {
		t.Fatal("valid continuation rejected", err)
	}
	other, _ := NewDirectory(store, []byte(strings.Repeat("z", 32)), directoryPolicy(t), func() time.Time { return now })
	if _, err = other.List(context.Background(), actor, tenant, "memberships", "limit=1&cursor="+token); !errors.Is(err, ErrDirectoryCursor) {
		t.Fatal("foreign key accepted")
	}
	now = now.Add(s.ttl)
	if _, err = s.List(context.Background(), actor, tenant, "memberships", "limit=1&cursor="+token); !errors.Is(err, ErrDirectoryCursor) {
		t.Fatal("deadline accepted")
	}
	store.rows = DirectoryRows{}
	empty, err := s.List(context.Background(), actor, tenant, "memberships", "")
	if err != nil || empty.NextCursor != nil || len(empty.Items.([]MemberView)) != 0 {
		t.Fatal("bad empty page")
	}
}
func TestDirectoryFiltersAndCapabilities(t *testing.T) {
	for _, tc := range []struct {
		raw, kind string
		want      error
	}{
		{"limit=0", "memberships", ErrMemberInput}, {"limit=101", "memberships", ErrMemberInput}, {"limit=+1", "memberships", ErrMemberInput},
		{"role=owner", "memberships", ErrMemberInput}, {"state=unknown", "invitations", ErrMemberInput}, {"query=a@example.invalid", "memberships", ErrMemberInput},
		{"query=aaaaaaaaa", "memberships", ErrMemberInput}, {"query=AAAAAAAA", "memberships", ErrMemberInput}, {"query=abc", "memberships", ErrMemberInput},
		{"deliveryState=queued", "memberships", ErrDirectoryRequest}, {"role=tenant_admin", "invitations", ErrDirectoryRequest},
		{"limit=1&limit=2", "memberships", ErrDirectoryRequest}, {"secret=a", "memberships", ErrDirectoryRequest}, {"cursor=", "memberships", ErrDirectoryRequest}, {"state=%xx", "memberships", ErrDirectoryRequest},
	} {
		if _, _, err := ParseDirectoryFilter(tc.raw, tc.kind); !errors.Is(err, tc.want) {
			t.Fatalf("%s: %v", tc.raw, err)
		}
	}
	for _, q := range []string{"12345678", "12345678-", "12345678-0000-4000-8000-000000000001"} {
		if _, _, err := ParseDirectoryFilter("query="+q, "memberships"); err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range []string{"tenant_admin", "security_admin", "issuer_operator", "support_readonly"} {
		if DirectoryAllowed([]string{role}, "memberships") != (role == "tenant_admin" || role == "security_admin") || DirectoryAllowed([]string{role}, "invitations") != (role == "tenant_admin") {
			t.Fatal("capability drift")
		}
	}
}

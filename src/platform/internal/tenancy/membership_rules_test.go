package tenancy

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func testMembershipPolicy(t *testing.T) MembershipPolicy {
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

func TestMembershipPolicyRejectsMissingUnknownProductionAndIncoherentValues(t *testing.T) {
	p := testMembershipPolicy(t)
	data, _ := json.Marshal(p)
	var fields map[string]any
	json.Unmarshal(data, &fields)
	for field := range fields {
		t.Run("missing_"+field, func(t *testing.T) {
			var incomplete map[string]any
			json.Unmarshal(data, &incomplete)
			delete(incomplete, field)
			body, _ := json.Marshal(incomplete)
			if _, err := LoadMembershipPolicy(strings.NewReader(string(body)), "test"); err == nil {
				t.Fatal("missing policy field accepted")
			}
		})
	}
	for _, body := range []string{string(data) + " {}", strings.Replace(string(data), "{", `{"extra":true,`, 1), strings.Repeat(" ", 65537) + string(data)} {
		if _, err := LoadMembershipPolicy(strings.NewReader(body), "test"); err == nil {
			t.Fatal("unknown/trailing/oversized input accepted")
		}
	}
	if _, err := LoadMembershipPolicy(strings.NewReader(string(data)), "production"); err == nil {
		t.Fatal("production policy accepted")
	}
	for _, mutate := range []func(*MembershipPolicy){
		func(p *MembershipPolicy) { p.InvitationSeconds = 86401 },
		func(p *MembershipPolicy) { p.IdempotencySeconds = p.InvitationSeconds - 1 },
		func(p *MembershipPolicy) { p.DeliverySecretSeconds = p.InvitationSeconds + 1 },
		func(p *MembershipPolicy) { p.RecipientRetentionSeconds = p.InvitationSeconds - 1 },
		func(p *MembershipPolicy) { p.CursorSeconds = 901 },
		func(p *MembershipPolicy) { p.EmailEvidenceSeconds = 301 },
		func(p *MembershipPolicy) { p.MaxPageSize = 101 },
	} {
		changed := p
		mutate(&changed)
		if changed.Validate("test") == nil {
			t.Fatal("incoherent policy accepted")
		}
	}
}

func TestInvitationEmailPreservesIdentitySensitiveLocalPart(t *testing.T) {
	for input, want := range map[string]string{"Admin+demo@EXAMPLE.invalid": "Admin+demo@example.invalid", "admin@example.invalid": "admin@example.invalid", strings.Repeat("a", 64) + "@example.invalid": strings.Repeat("a", 64) + "@example.invalid"} {
		got, err := NormalizeInvitationEmail(input)
		if got != want || err != nil {
			t.Fatalf("normalize %q: got %q, %v", input, got, err)
		}
	}
	for _, input := range []string{"", " admin@example.invalid", "admin@example.invalid ", "a..b@example.invalid", ".a@example.invalid", "a.@example.invalid", "A <a@example.invalid>", "a@localhost", "a@-example.invalid", "a@example..invalid", "a@[127.0.0.1]", "á@example.invalid", "a@例.invalid", "a@example.invalid\n", strings.Repeat("a", 65) + "@example.invalid", "a@" + strings.Repeat("b", 64) + ".invalid"} {
		if _, err := NormalizeInvitationEmail(input); !errors.Is(err, ErrMemberInput) {
			t.Fatalf("invalid email accepted: %q", input)
		}
	}
}

func TestInvitationDeadlineDoesNotGainSkewOrReviveTerminalStates(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	created, expires := now.Add(-time.Hour), now.Add(time.Second)
	if !InvitationUsable("pending", created, expires, now) || InvitationUsable("pending", created, now, now) || InvitationUsable("pending", now.Add(time.Second), expires.Add(time.Second), now) {
		t.Fatal("invalid invitation boundary")
	}
	for _, state := range []string{"accepted", "revoked", "expired", "unknown"} {
		if InvitationUsable(state, created, expires, now) {
			t.Fatal("terminal invitation revived")
		}
	}
}

func TestMemberGrantsRejectEscalationAndForeignIssuers(t *testing.T) {
	id := "60000000-0000-4000-8000-000000000001"
	owned := map[string]bool{id: true}
	for _, roles := range [][]string{{"tenant_admin"}, {"security_admin"}, {"support_readonly"}} {
		if err := ValidateMemberGrant(roles, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := ValidateMemberGrant([]string{"issuer_operator", "tenant_admin"}, []string{id}, owned); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		roles, issuers []string
		owned          map[string]bool
		want           error
	}{
		{nil, nil, nil, ErrMemberInput},
		{[]string{"global_admin"}, nil, nil, ErrMemberInput},
		{[]string{"tenant_admin", "tenant_admin"}, nil, nil, ErrMemberInput},
		{[]string{"issuer_operator"}, nil, nil, ErrMemberInput},
		{[]string{"tenant_admin"}, []string{id}, owned, ErrMemberInput},
		{[]string{"issuer_operator"}, []string{id}, nil, ErrMemberScope},
		{[]string{"issuer_operator"}, []string{id, id}, owned, ErrMemberInput},
		{[]string{"issuer_operator"}, []string{"not-an-id"}, nil, ErrMemberInput},
	} {
		if err := ValidateMemberGrant(tc.roles, tc.issuers, tc.owned); !errors.Is(err, tc.want) {
			t.Fatalf("grant %v %v: got %v, want %v", tc.roles, tc.issuers, err, tc.want)
		}
	}
}

func TestMembershipChangeProtectsLastAdminAndTerminalLifecycle(t *testing.T) {
	admin := MemberAccess{State: "active", Roles: []string{"tenant_admin"}, Revision: 7}
	for _, state := range []string{"suspended", "revoked"} {
		if err := CheckMembershipChange(admin, state, admin.Roles, 7, 1); !errors.Is(err, ErrLastAdmin) {
			t.Fatalf("last admin changed: %v", err)
		}
		if err := CheckMembershipChange(admin, state, admin.Roles, 7, 2); err != nil {
			t.Fatal(err)
		}
	}
	if !errors.Is(CheckMembershipChange(admin, "active", []string{"support_readonly"}, 7, 1), ErrLastAdmin) {
		t.Fatal("last admin demoted")
	}
	if !errors.Is(CheckMembershipChange(admin, "suspended", admin.Roles, 6, 2), ErrMemberRevision) {
		t.Fatal("stale revision accepted")
	}
	admin.State = "revoked"
	if !errors.Is(CheckMembershipChange(admin, "active", admin.Roles, 7, 2), ErrMemberRevoked) {
		t.Fatal("PATCH restored revoked membership")
	}
	admin.State = "suspended"
	if err := CheckMembershipChange(admin, "active", admin.Roles, 7, 1); err != nil {
		t.Fatal(err)
	}
}

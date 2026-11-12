package tenancy

import (
	"context"
	"errors"
	"testing"
	"time"
)

type memberCapture struct{ commands []MembershipCommand }

func (s *memberCapture) ChangeMembership(_ context.Context, c MembershipCommand) (MemberView, error) {
	s.commands = append(s.commands, c)
	return MemberView{}, nil
}

func TestMembershipCommandValidationAndFingerprint(t *testing.T) {
	store := &memberCapture{}
	// Reuse the strict checked-in test policy; no runtime defaults.
	policy := testMembershipPolicy(t)
	s := &MembershipService{Store: store, Policy: policy}
	c := MembershipCommand{Actor: "20000000-0000-4000-8000-000000000001", Tenant: "10000000-0000-4000-8000-000000000001", MembershipID: "30000000-0000-4000-8000-000000000001", Key: "membership_test_001", Revision: 1, PrivilegeDeadline: time.Now().Add(time.Minute), Input: ChangeMembershipInput{Roles: []string{"tenant_admin", "security_admin"}, IssuerIDs: []string{}, ReasonCode: "access_change"}}
	for _, input := range []ChangeMembershipInput{{}, {ReasonCode: "access_change"}, {Roles: []string{"tenant_admin"}, ReasonCode: "access_change"}, {State: "deleted", ReasonCode: "access_change"}, {State: "active", ReasonCode: "free text"}, {Roles: []string{"global_admin"}, IssuerIDs: []string{}, ReasonCode: "access_change"}} {
		invalid := c
		invalid.Input = input
		if _, e := s.Execute(context.Background(), invalid); !errors.Is(e, ErrMemberInput) {
			t.Fatal("invalid patch accepted", e)
		}
	}
	if _, e := s.Execute(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	c.Input.Roles = []string{"security_admin", "tenant_admin"}
	if _, e := s.Execute(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	if string(store.commands[0].RequestHash) != string(store.commands[1].RequestHash) {
		t.Fatal("set order affects fingerprint")
	}
	c.MembershipID = "30000000-0000-4000-8000-000000000002"
	s.Execute(context.Background(), c)
	if string(store.commands[0].RequestHash) == string(store.commands[2].RequestHash) {
		t.Fatal("target omitted from fingerprint")
	}
	c.Revision++
	s.Execute(context.Background(), c)
	if string(store.commands[2].RequestHash) == string(store.commands[3].RequestHash) {
		t.Fatal("revision omitted from fingerprint")
	}
}

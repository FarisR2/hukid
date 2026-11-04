//go:build integration

package postgres

import (
	"errors"
	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
	"slices"
	"testing"
)

func TestLiveOperatorAuthorizationAndPoolIsolation(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)
	discovery, tenant := db.pool(t, "hukid_context_runtime"), db.pool(t, "hukid_tenant_runtime")
	service, err := tenancy.New(&OperatorStore{Discovery: discovery, Tenant: tenant})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		subject, actor, tenant string
		n                      int
	}{
		{"operator-test-a", TestActorA, TestTenantA, 1}, {"operator-test-b", TestActorB, TestTenantB, 1}, {"operator-test-pending", TestActorPending, "", 0},
	} {
		i, err := service.Me(testContext, authentication.Operator{Issuer: "http://127.0.0.1:19090", Subject: tc.subject})
		if err != nil || i.ActorID != tc.actor || len(i.Tenants) != tc.n {
			t.Fatal("identity exposed wrong contexts")
		}
		if tc.n > 0 && i.Tenants[0].ID != tc.tenant {
			t.Fatal("foreign tenant discovered")
		}
		assertCleared(t, discovery)
		assertCleared(t, tenant)
	}
	if _, err := service.Context(testContext, TestActorA, TestTenantB); !errors.Is(err, authentication.ErrTenant) {
		t.Fatal("foreign context allowed")
	}
	for _, role := range []string{"tenant_admin", "security_admin", "issuer_operator", "support_readonly"} {
		mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role=$1 WHERE membership_id=$2`, role, TestMemberA)
		c, err := service.Context(testContext, TestActorA, TestTenantA)
		if err != nil || !slices.Contains(c.Capabilities, "dashboard:read") || len(c.IssuerIDs) != 0 {
			t.Fatal("incorrect role context")
		}
		if (role == "issuer_operator" || role == "support_readonly") && slices.Contains(c.Capabilities, "members:read") {
			t.Fatal("directory escalated")
		}
		assertCleared(t, tenant)
	}
	for _, state := range []string{"suspended", "revoked"} {
		mustExec(t, db.admin, `UPDATE tenancy.memberships SET state=$1,authorization_revision=authorization_revision+1 WHERE membership_id=$2`, state, TestMemberA)
		if _, err := service.Context(testContext, TestActorA, TestTenantA); !errors.Is(err, authentication.ErrTenant) {
			t.Fatal("stale membership authorized")
		}
		mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='active' WHERE membership_id=$1`, TestMemberA)
	}
	mustExec(t, db.admin, `UPDATE tenancy.tenants SET state='suspended' WHERE tenant_id=$1`, TestTenantA)
	if _, err := service.Context(testContext, TestActorA, TestTenantA); !errors.Is(err, authentication.ErrTenant) {
		t.Fatal("suspended tenant authorized")
	}
	i, err := service.Me(testContext, authentication.Operator{Issuer: "http://127.0.0.1:19090", Subject: "operator-test-a"})
	if err != nil || len(i.Tenants) != 0 {
		t.Fatal("suspended context enumerated")
	}
	assertCleared(t, discovery)
	assertCleared(t, tenant)
}

//go:build integration

package postgres

import (
	"encoding/json"
	"hukid.local/platform/internal/authentication"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Reuses the real API process, validated OIDC token and server-side session.
func testDashboardHTTP(t *testing.T, db *testDatabase, call func(string, string, *http.Cookie, int) map[string]any, token string, cookie *http.Cookie, actor string) {
	t.Helper()
	defer func() {
		mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='active',authorization_revision=1 WHERE membership_id=$1`, TestMemberA)
		mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role='security_admin' WHERE membership_id=$1`, TestMemberA)
		mustExec(t, db.admin, `UPDATE console_auth.sessions SET active_tenant_id=$1,authorization_revision=1 WHERE cookie_hash=$2`, TestTenantA, authentication.Digest(cookie.Value))
	}()
	from := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	to := from.Add(30 * time.Minute)
	ids := []string{"98000000-0000-4000-8000-000000000001", "98000000-0000-4000-8000-000000000002", "98000000-0000-4000-8000-000000000003"}
	for _, id := range ids {
		mustExec(t, db.admin, `INSERT INTO platform.audit_events(event_id,tenant_id,actor_operator_identity_id,target_id,action,outcome,correlation_id,recorded_at) VALUES($1,$2,$3,$1,'members.invitation.created','success',$1,$4)`, id, TestTenantA, actor, from)
		mustExec(t, db.admin, `INSERT INTO platform.outbox_events(event_id,tenant_id) VALUES($1,$2)`, id, TestTenantA)
	}
	// Upper boundary and foreign rows must never enter any page.
	mustExec(t, db.admin, `INSERT INTO platform.audit_events(event_id,tenant_id,target_id,action,outcome,correlation_id,recorded_at) VALUES('98000000-0000-4000-8000-000000000004',$1,$1,'members.invitation.created','success',$1,$2),('98000000-0000-4000-8000-000000000005',$3,$3,'members.invitation.created','success',$3,$4)`, TestTenantA, to, TestTenantB, from)
	mustExec(t, db.admin, `INSERT INTO platform.outbox_events(event_id,tenant_id) VALUES('98000000-0000-4000-8000-000000000004',$1),('98000000-0000-4000-8000-000000000005',$2)`, TestTenantA, TestTenantB)
	var runtimeCases []map[string]any
	for _, prefix := range []string{"/v1/operator", "/console/api"} {
		bearer, session := token, (*http.Cookie)(nil)
		if prefix == "/console/api" {
			bearer, session = "", cookie
		}
		base := prefix + "/tenants/" + TestTenantA
		o := call(base+"/overview", bearer, session, 200)
		runtimeCases = append(runtimeCases, map[string]any{"schema": "Overview", "value": o})
		sections := o["sections"].(map[string]any)
		if sections["activeMembers"].(map[string]any)["value"] != float64(1) || sections["activeIssuers"].(map[string]any)["state"] != "notAuthorized" {
			t.Fatal("wrong overview")
		}
		for query, status := range map[string]int{"unknown=x": 400, "limit=1": 400, "issuerId=": 400, "from=bad&to=bad": 422, "from=2020-01-01T00:00:00Z&to=2020-03-01T00:00:00Z": 422, "issuerId=70000000-0000-4000-8000-000000000001": 503} {
			problem := call(base+"/overview?"+query, bearer, session, status)
			runtimeCases = append(runtimeCases, map[string]any{"schema": "Problem", "value": problem})
		}
		// Fail the real audit query without disrupting the independent overview.
		// Restore grants before leaving this scope, including on assertion failure.
		func() {
			mustExec(t, db.admin, `REVOKE SELECT(event_id,tenant_id,actor_operator_identity_id,target_id,action,outcome,recorded_at) ON platform.audit_events FROM hukid_dashboard_runtime`)
			defer mustExec(t, db.admin, `GRANT SELECT(event_id,tenant_id,actor_operator_identity_id,target_id,action,outcome,recorded_at) ON platform.audit_events TO hukid_dashboard_runtime`)
			problem := call(base+"/activity", bearer, session, 503)
			if problem["code"] != "dependency_unavailable" || len(problem) != 5 {
				t.Fatal("failed feed became empty or leaked diagnostics")
			}
			runtimeCases = append(runtimeCases, map[string]any{"schema": "Problem", "value": problem})
			if call(base+"/overview", bearer, session, 200)["sections"].(map[string]any)["activeMembers"].(map[string]any)["value"] != float64(1) {
				t.Fatal("feed failure contaminated overview")
			}
			mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role='support_readonly' WHERE membership_id=$1`, TestMemberA)
			defer mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role='security_admin' WHERE membership_id=$1`, TestMemberA)
			call(base+"/activity", bearer, session, 403)
		}()
		// Authorization-source failure must close both reads, never return a
		// successful overview of zeros or a partially authorized feed.
		func() {
			mustExec(t, db.admin, `REVOKE SELECT ON tenancy.memberships FROM hukid_dashboard_runtime`)
			defer mustExec(t, db.admin, `GRANT SELECT ON tenancy.memberships TO hukid_dashboard_runtime`)
			problem := call(base+"/overview", bearer, session, 503)
			if problem["code"] != "dependency_unavailable" || len(problem) != 5 {
				t.Fatal("failed aggregate became zero or leaked diagnostics")
			}
			runtimeCases = append(runtimeCases, map[string]any{"schema": "Problem", "value": problem})
			call(base+"/activity", bearer, session, 503)
		}()
		q := url.Values{"from": {from.Format(time.RFC3339)}, "to": {to.Format(time.RFC3339)}, "limit": {"1"}}
		var first map[string]any
		for i := 2; i >= 0; i-- {
			page := call(base+"/activity?"+q.Encode(), bearer, session, 200)
			runtimeCases = append(runtimeCases, map[string]any{"schema": "Activity", "value": page})
			if first == nil {
				first = page
			}
			items := page["items"].([]any)
			if len(items) != 1 || items[0].(map[string]any)["eventId"] != ids[i] || page["asOf"] != first["asOf"] {
				t.Fatal("keyset or tenant/window isolation")
			}
			if i > 0 {
				q.Set("cursor", page["nextCursor"].(string))
			} else if page["nextCursor"] != nil {
				t.Fatal("unexpected continuation")
			}
		}
		q.Set("cursor", first["nextCursor"].(string))
		q.Set("limit", "2")
		if problem := call(base+"/activity?"+q.Encode(), bearer, session, 422); problem["code"] != "invalid_cursor" {
			t.Fatal("changed page size")
		}
		q.Set("limit", "1")
		mustExec(t, db.admin, `UPDATE tenancy.memberships SET authorization_revision=authorization_revision+1 WHERE membership_id=$1`, TestMemberA)
		call(base+"/activity?"+q.Encode(), bearer, session, 422)
		q.Set("cursor", strings.Repeat("A", 64))
		call(base+"/activity?"+q.Encode(), bearer, session, 422)
		call(base+"/activity?cursor=short", bearer, session, 422)
		call(base+"/activity?limit=101", bearer, session, 422)
		call(base+"/activity?limit=1&limit=2", bearer, session, 400)
		call(strings.Replace(base, TestTenantA, TestTenantB, 1)+"/overview", bearer, session, 404)
		call(base+"/overview", "", nil, 401)
		if session != nil {
			mustExec(t, db.admin, `UPDATE console_auth.sessions SET active_tenant_id=NULL,authorization_revision=NULL WHERE cookie_hash=$1`, authentication.Digest(cookie.Value))
			call(base+"/overview", bearer, session, 403)
			mustExec(t, db.admin, `UPDATE console_auth.sessions SET active_tenant_id=$1,authorization_revision=(SELECT authorization_revision FROM tenancy.memberships WHERE membership_id=$2) WHERE cookie_hash=$3`, TestTenantA, TestMemberA, authentication.Digest(cookie.Value))
		}
		call(base+"/activity?from=2020-01-01T00:00:00Z&to=2020-01-02T00:00:00Z", bearer, session, 200)
		mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role='support_readonly' WHERE membership_id=$1`, TestMemberA)
		call(base+"/activity?"+q.Encode(), bearer, session, 403)
		hidden := call(base+"/overview", bearer, session, 200)
		runtimeCases = append(runtimeCases, map[string]any{"schema": "Overview", "value": hidden})
		for _, section := range hidden["sections"].(map[string]any) {
			if section.(map[string]any)["value"] != nil {
				t.Fatal("hidden count leaked")
			}
		}
		mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role='security_admin' WHERE membership_id=$1`, TestMemberA)
		mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='suspended' WHERE membership_id=$1`, TestMemberA)
		call(base+"/overview", bearer, session, 404)
		mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='active' WHERE membership_id=$1`, TestMemberA)
	}
	// Real serialized HTTP responses must validate against the strict draft schema.
	data, _ := json.Marshal(runtimeCases)
	validate := exec.Command("node", "../../../../../tests/fixtures/dashboard/validate-runtime.mjs")
	validate.Stdin = strings.NewReader(string(data))
	if output, err := validate.CombinedOutput(); err != nil {
		t.Fatalf("runtime contract: %s", output)
	}
}

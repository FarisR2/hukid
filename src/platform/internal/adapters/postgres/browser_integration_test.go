//go:build integration && browser

package postgres

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	a "hukid.local/platform/internal/authentication"
)

// The browser suite owns every service and database. No existing app is used.
func TestConsoleBrowser(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	pool := db.pool(t, "hukid_session_runtime")
	discovery := db.pool(t, "hukid_context_runtime")
	tenantPool := db.pool(t, "hukid_tenant_runtime")
	f, err := os.Open("../../../config/auth.test.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.LoadPolicy(f, "test")
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	p.Issuer = "http://" + freeLoopback(t)
	listen, frontend := freeLoopback(t), freeLoopback(t)
	p.ConsoleOrigin = "http://" + frontend
	p.RedirectURI = p.ConsoleOrigin + "/console/auth/callback"
	p.LoginRateLimit.MaxAttempts = 100
	driver := startDriver(t, p)
	secrets := driver.call(t, map[string]any{"action": "start", "policy": p})
	root, _ := filepath.Abs("../../../../..")
	scratch := t.TempDir()
	policyBytes, _ := json.Marshal(p)
	policyPath := filepath.Join(scratch, "policy.json")
	if os.WriteFile(policyPath, policyBytes, 0600) != nil {
		t.Fatal("cannot write test policy")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, ".cache", "build", "hukid-api")
	if os.PathSeparator == '\\' {
		binary += ".exe"
	}
	api := exec.Command(binary)
	api.Env = append(os.Environ(), "HUKID_ENV=test", "HUKID_AUTH_POLICY="+policyPath, "HUKID_LISTEN_ADDR="+listen,
		"HUKID_CONSOLE_PROXY_ORIGIN="+p.ConsoleOrigin,
		"HUKID_SESSION_DATABASE_URL="+pool.Config().ConnString(), "HUKID_CONTEXT_DATABASE_URL="+discovery.Config().ConnString(),
		"HUKID_TENANT_DATABASE_URL="+tenantPool.Config().ConnString(), "HUKID_OIDC_CLIENT_SECRET="+secrets["clientSecret"],
		"HUKID_AUTH_KEY="+base64.StdEncoding.EncodeToString(key), "HUKID_AUTH_KEY_VERSION=browser-test")
	apiLogs := &capturedLogs{}
	api.Stdout, api.Stderr = apiLogs, apiLogs
	for _, proxyOrigin := range []string{"", "http://127.0.0.1:1"} {
		rejected := exec.Command(binary)
		rejected.Env = append(append([]string{}, api.Env...), "HUKID_CONSOLE_PROXY_ORIGIN="+proxyOrigin)
		if rejected.Run() == nil {
			t.Fatal("unconfigured or mismatched proxy origin accepted")
		}
	}
	if api.Start() != nil {
		t.Fatal("cannot start test API; run npm run build first")
	}
	t.Cleanup(func() { api.Process.Kill(); api.Wait() })
	vite := exec.Command("node", filepath.Join(root, "node_modules", "vite", "bin", "vite.js"), "preview", filepath.Join(root, "src", "console"), "--host", "127.0.0.1", "--port", strings.Split(frontend, ":")[1], "--strictPort")
	vite.Env = append(os.Environ(), "HUKID_CONSOLE_API_TARGET=http://"+listen)
	viteLogs := &capturedLogs{}
	vite.Stdout, vite.Stderr = viteLogs, viteLogs
	if vite.Start() != nil {
		t.Fatal("cannot start test console")
	}
	t.Cleanup(func() { vite.Process.Kill(); vite.Wait() })
	client := &http.Client{Timeout: time.Second}
	for _, address := range []string{"http://" + listen + "/healthz", p.ConsoleOrigin + "/"} {
		ready := false
		for range 100 {
			r, err := client.Get(address)
			if err == nil {
				r.Body.Close()
				if r.StatusCode < 400 {
					ready = true
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !ready {
			t.Fatalf("browser service did not start (%s): API: %s; console: %s", address, apiLogs.String(), viteLogs.String())
		}
	}
	python := os.Getenv("HUKID_BROWSER_PYTHON")
	if python == "" {
		python = filepath.Join(root, ".cache", "browser-venv", "bin", "python")
		if os.PathSeparator == '\\' {
			python = filepath.Join(root, ".cache", "browser-venv", "Scripts", "python.exe")
		}
	}
	cmd := exec.Command(python, filepath.Join(root, "tests", "browser", "authentication.py"))
	cmd.Dir = root
	input, _ := cmd.StdinPipe()
	output, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if cmd.Start() != nil {
		t.Fatal("install tests/browser/requirements.txt and Chromium; set HUKID_BROWSER_PYTHON if needed")
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	json.NewEncoder(input).Encode(map[string]string{"origin": p.ConsoleOrigin, "issuer": p.Issuer, "interactionKey": secrets["interactionKey"]})
	var actor string
	scanner := bufio.NewScanner(output)
	for scanner.Scan() {
		switch scanner.Text() {
		case "seed":
			mustBootstrap(t, db)
			if err := db.admin.QueryRow(testContext, `SELECT operator_identity_id::text FROM tenancy.operator_identities WHERE oidc_issuer=$1 AND subject='operator-test-a'`, p.Issuer).Scan(&actor); err != nil {
				t.Fatal(err)
			}
			mustExec(t, db.admin, `UPDATE tenancy.memberships SET operator_identity_id=$1 WHERE membership_id=$2`, actor, TestMemberA)
			mustExec(t, db.admin, `INSERT INTO tenancy.memberships(membership_id,tenant_id,operator_identity_id) VALUES ('30000000-0000-4000-8000-000000000003',$1,$2)`, TestTenantB, actor)
			mustExec(t, db.admin, `INSERT INTO tenancy.membership_roles(tenant_id,membership_id,role) VALUES ($1,'30000000-0000-4000-8000-000000000003','tenant_admin')`, TestTenantB)
		case "expire":
			mustExec(t, db.admin, `UPDATE console_auth.sessions SET created_at=created_at-interval '2 hours',last_seen_at=created_at-interval '2 hours',idle_expires_at=now()-interval '1 second'`)
		case "suspend":
			mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='suspended' WHERE operator_identity_id=$1`, actor)
		case "resume":
			mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='active' WHERE operator_identity_id=$1`, actor)
		default:
			t.Log(scanner.Text())
			continue
		}
		json.NewEncoder(input).Encode(map[string]bool{"ok": true})
	}
	input.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatal("browser acceptance failed")
	}
	assertAuthEvents(t, db)
	var stored string
	if err := db.admin.QueryRow(testContext, `SELECT COALESCE(string_agg(row_to_json(a)::text,''),'') FROM platform.audit_events a`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{secrets["clientSecret"], secrets["interactionKey"], base64.StdEncoding.EncodeToString(key)} {
		if secret != "" && (strings.Contains(apiLogs.String(), secret) || strings.Contains(stored, secret)) {
			t.Fatal("browser secret leaked to audit/logs")
		}
	}
}

//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"hukid.local/platform/internal/adapters/secretbox"
	a "hukid.local/platform/internal/authentication"
)

type capturedLogs struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (l *capturedLogs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.data.Write(p)
}
func (l *capturedLogs) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.data.String() }

func freeLoopback(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	l.Close()
	return address
}

type idpDriver struct {
	input   io.WriteCloser
	decoder *json.Decoder
	command *exec.Cmd
	stopped bool
}

func (d *idpDriver) call(t *testing.T, value any) map[string]string {
	t.Helper()
	if json.NewEncoder(d.input).Encode(value) != nil {
		t.Fatal("cannot send isolated IdP command")
	}
	var response map[string]string
	if err := d.decoder.Decode(&response); err != nil {
		t.Fatalf("isolated IdP protocol failed: %T %v", err, err)
	}
	if response["error"] != "" {
		t.Fatalf("isolated IdP command failed (phase=%s status=%s)", response["phase"], response["status"])
	}
	return response
}
func startDriver(t *testing.T, p a.Policy) *idpDriver {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, "node", "../../../../../tests/fixtures/oidc-login-driver.mjs")
	command.Env = append(os.Environ(), "NODE_ENV=test", "HUKID_TEST_IDP=1", "DEBUG=")
	input, _ := command.StdinPipe()
	output, _ := command.StdoutPipe()
	command.Stderr = io.Discard
	if command.Start() != nil {
		t.Fatal("cannot start isolated IdP")
	}
	d := &idpDriver{input: input, decoder: json.NewDecoder(output), command: command}
	t.Cleanup(func() {
		if !d.stopped {
			d.call(t, map[string]any{"action": "stop"})
			d.stopped = true
		}
		input.Close()
		if command.Wait() != nil {
			t.Error("isolated IdP did not exit cleanly")
		}
	})
	return d
}

func TestLoginHTTPWithRealOIDCAndPostgres(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	pool := db.pool(t, "hukid_session_runtime")
	discovery := db.pool(t, "hukid_context_runtime")
	tenantPool := db.pool(t, "hukid_tenant_runtime")
	membersPool := db.pool(t, "hukid_members_runtime")
	file, err := os.Open("../../../config/auth.test.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.LoadPolicy(file, "test")
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	p.Issuer = "http://" + freeLoopback(t)
	listen := freeLoopback(t)
	p.ConsoleOrigin = "http://" + listen
	p.RedirectURI = p.ConsoleOrigin + "/console/auth/callback"
	p.LoginRateLimit.MaxAttempts = 100
	driver := startDriver(t, p)
	secret := driver.call(t, map[string]any{"action": "start", "policy": p})["clientSecret"]
	scratch := t.TempDir()
	policyPath := filepath.Join(scratch, "policy.json")
	policyBytes, _ := json.Marshal(p)
	if os.WriteFile(policyPath, policyBytes, 0600) != nil {
		t.Fatal("cannot write ephemeral policy")
	}
	key := make([]byte, 32)
	rand.Read(key)
	box, _ := secretbox.New(key, "integration-v1", rand.Reader)
	binary := filepath.Join(scratch, "api")
	goName := "go"
	if runtime.GOOS == "windows" {
		binary += ".exe"
		goName += ".exe"
	}
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", goName), "build", "-o", binary, "../../../cmd/api")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cannot build API: %s", output)
	}
	command := exec.Command(binary)
	command.Env = append(os.Environ(), "HUKID_ENV=test", "HUKID_AUTH_POLICY="+policyPath, "HUKID_LISTEN_ADDR="+listen, "HUKID_SESSION_DATABASE_URL="+pool.Config().ConnString(), "HUKID_OIDC_CLIENT_SECRET="+secret, "HUKID_AUTH_KEY="+base64.StdEncoding.EncodeToString(key), "HUKID_AUTH_KEY_VERSION=integration-v1")
	command.Env = append(command.Env, "HUKID_CONTEXT_DATABASE_URL="+discovery.Config().ConnString(), "HUKID_TENANT_DATABASE_URL="+tenantPool.Config().ConnString())
	membersPolicy, _ := filepath.Abs("../../../config/user-management.test.json")
	command.Env = append(command.Env, "HUKID_MEMBERS_DATABASE_URL="+membersPool.Config().ConnString(), "HUKID_MEMBERS_POLICY="+membersPolicy, "HUKID_MEMBERS_CURSOR_KEY="+base64.StdEncoding.EncodeToString(key))
	logs := &capturedLogs{}
	command.Stdout = logs
	command.Stderr = logs
	if command.Start() != nil {
		t.Fatal("cannot start API")
	}
	t.Cleanup(func() { command.Process.Kill(); command.Wait() })
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ready := false
	for range 100 {
		response, err := client.Get(p.ConsoleOrigin + "/healthz")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 204 {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("configured API did not become live")
	}
	secretValues := []string{secret, base64.StdEncoding.EncodeToString(key)}
	var sessionCookie *http.Cookie
	request := func(t *testing.T, path string, cookie *http.Cookie) *http.Response {
		t.Helper()
		req, _ := http.NewRequest("GET", p.ConsoleOrigin+path, nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal("API request failed")
		}
		t.Cleanup(func() { response.Body.Close() })
		if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Referrer-Policy") != "no-referrer" || response.Header.Get("X-Correlation-Id") == "" {
			t.Fatal("missing private response headers")
		}
		return response
	}
	begin := func(t *testing.T) (*url.URL, *http.Cookie) {
		t.Helper()
		response := request(t, "/console/auth/login", nil)
		if response.StatusCode != 303 {
			t.Fatalf("login status %d", response.StatusCode)
		}
		u, err := url.Parse(response.Header.Get("Location"))
		if err != nil {
			t.Fatal("bad authorization redirect")
		}
		cookies := response.Cookies()
		if len(cookies) != 1 || cookies[0].Name != "hukid_test_transaction" || !cookies[0].HttpOnly || cookies[0].Path != "/console/auth" || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Domain != "" {
			t.Fatal("unsafe transaction cookie")
		}
		secretValues = append(secretValues, cookies[0].Value, u.Query().Get("state"), u.Query().Get("nonce"))
		return u, cookies[0]
	}
	authorize := func(t *testing.T, u *url.URL) string {
		t.Helper()
		callback := driver.call(t, map[string]any{"action": "authorize", "url": u.String()})["callback"]
		parsed, err := url.Parse(callback)
		if err != nil || parsed.Query().Get("code") == "" {
			t.Fatal("IdP did not authorize")
		}
		secretValues = append(secretValues, parsed.Query().Get("code"))
		return parsed.RequestURI()
	}
	countSessions := func(t *testing.T) int {
		t.Helper()
		var n int
		if db.admin.QueryRow(testContext, `SELECT count(*) FROM console_auth.sessions`).Scan(&n) != nil {
			t.Fatal("cannot count sessions")
		}
		return n
	}
	assertError := func(t *testing.T, response *http.Response, status int) {
		t.Helper()
		body, _ := io.ReadAll(response.Body)
		if response.StatusCode != status || response.Header.Get("Location") != "" {
			t.Fatalf("expected safe error %d, received %d", status, response.StatusCode)
		}

		var events int
		if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM platform.audit_events WHERE correlation_id=$1 AND action IN ('auth.request.denied','auth.request.failed') AND actor_operator_identity_id IS NULL AND tenant_id IS NULL`, response.Header.Get("X-Correlation-Id")).Scan(&events); err != nil || events != 1 {
			t.Fatal("HTTP denial missing matching audit correlation")
		}

		for _, cookie := range response.Cookies() {
			if cookie.Name == p.CookieName && cookie.Value != "" {
				t.Fatal("failed callback emitted session")
			}
		}
		if strings.Contains(string(body), "error_description") || strings.Contains(string(body), "access_token") {
			t.Fatal("secret in error response")
		}
	}

	t.Run("unsafe_return_and_duplicate_input", func(t *testing.T) {
		for _, query := range []string{"returnTo=https://evil.invalid", "returnTo=%2F", "returnTo=/&returnTo=/", "returnTo=//evil.invalid"} {
			assertError(t, request(t, "/console/auth/login?"+query, nil), 400)
		}
		if countSessions(t) != 0 {
			t.Fatal("unsafe input created session")
		}
	})
	t.Run("unbound_callbacks_do_not_consume", func(t *testing.T) {
		u, cookie := begin(t)
		path := authorize(t, u)
		assertError(t, request(t, path, nil), 400)
		bad := *cookie
		bad.Value = strings.Repeat("a", 43)
		assertError(t, request(t, path, &bad), 400)
		parsed, _ := url.Parse(path)
		q := parsed.Query()
		q.Set("iss", "http://127.0.0.1:1")
		parsed.RawQuery = q.Encode()
		assertError(t, request(t, parsed.String(), cookie), 400)
		q.Set("iss", p.Issuer)
		q.Set("state", "unrelated-state")
		parsed.RawQuery = q.Encode()
		assertError(t, request(t, parsed.String(), cookie), 400)
		assertError(t, request(t, path+"&state=duplicate", cookie), 400)
		response := request(t, path, cookie)
		if response.StatusCode != 303 || response.Header.Get("Location") != "/" {
			t.Fatalf("callback did not create session: %d", response.StatusCode)
		}
		found := false
		for _, c := range response.Cookies() {
			if c.Name == p.CookieName {
				sessionCookie = c
				found = true
				secretValues = append(secretValues, c.Value)
				if len(c.Value) != 43 || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
					t.Fatal("unsafe session cookie")
				}
			}
		}
		if !found {
			t.Fatal("no session cookie")
		}
		assertError(t, request(t, path, cookie), 400)
	})
	t.Run("nonce_and_pkce", func(t *testing.T) {
		for _, mode := range []string{"nonce", "pkce"} {
			u, cookie := begin(t)
			q := u.Query()
			if mode == "nonce" {
				q.Set("nonce", "unbound-nonce")
			} else {
				q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(a.Digest("wrong-verifier")))
			}
			u.RawQuery = q.Encode()
			path := authorize(t, u)
			assertError(t, request(t, path, cookie), 400)
			assertError(t, request(t, path, cookie), 400)
		}
	})
	t.Run("expired_transaction", func(t *testing.T) {
		u, cookie := begin(t)
		path := authorize(t, u)
		mustExec(t, db.admin, `UPDATE console_auth.oidc_transactions SET created_at=now()-interval '10 minutes',expires_at=now()-interval '1 minute' WHERE state_hash=$1`, a.Digest(u.Query().Get("state")))
		assertError(t, request(t, path, cookie), 400)
	})
	t.Run("oauth_denial_consumed_without_leak", func(t *testing.T) {
		u, cookie := begin(t)
		path := "/console/auth/callback?" + url.Values{"state": {u.Query().Get("state")}, "iss": {p.Issuer}, "error": {"access_denied"}, "error_description": {"sensitive-test-detail"}}.Encode()
		r := request(t, path, cookie)
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "sensitive-test-detail") || r.StatusCode != 400 {
			t.Fatal("unsafe OAuth denial")
		}
		assertError(t, request(t, path, cookie), 400)
	})
	t.Run("concurrent_callbacks", func(t *testing.T) {
		u, cookie := begin(t)
		path := authorize(t, u)
		before := countSessions(t)
		var wg sync.WaitGroup
		results := make(chan int, 2)
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req, _ := http.NewRequest("GET", p.ConsoleOrigin+path, nil)
				req.AddCookie(cookie)
				r, err := client.Do(req)
				if err != nil {
					results <- 0
					return
				}
				r.Body.Close()
				results <- r.StatusCode
			}()
		}
		wg.Wait()
		close(results)
		success, denied := 0, 0
		for status := range results {
			if status == 303 {
				success++
			}
			if status == 400 {
				denied++
			}
		}
		if success != 1 || denied != 1 || countSessions(t) != before+1 {
			t.Fatal("concurrent callback was not single use")
		}
	})
	t.Run("session_rollback_preserves_consumption", func(t *testing.T) {
		u, cookie := begin(t)
		path := authorize(t, u)
		before := countSessions(t)
		mustExec(t, db.admin, `ALTER TABLE console_auth.sessions ADD CONSTRAINT auth_test_fail CHECK(false) NOT VALID`)
		assertError(t, request(t, path, cookie), 503)
		mustExec(t, db.admin, `ALTER TABLE console_auth.sessions DROP CONSTRAINT auth_test_fail`)
		assertError(t, request(t, path, cookie), 400)
		if countSessions(t) != before {
			t.Fatal("failed commit created session")
		}
	})
	t.Run("identity_and_encrypted_storage", func(t *testing.T) {
		var identities, memberships, families int
		db.admin.QueryRow(testContext, `SELECT count(*) FROM tenancy.operator_identities`).Scan(&identities)
		db.admin.QueryRow(testContext, `SELECT count(*) FROM tenancy.memberships`).Scan(&memberships)
		db.admin.QueryRow(testContext, `SELECT count(*) FROM console_auth.session_families`).Scan(&families)
		if identities != 1 || memberships != 0 || families != countSessions(t) {
			t.Fatal("login granted membership or left partial family")
		}
		var family string
		var envelope a.Envelope
		var activeTenant *string
		if err := db.admin.QueryRow(testContext, `SELECT family_id::text,secret_ciphertext,secret_nonce,secret_key_version,active_tenant_id::text FROM console_auth.sessions LIMIT 1`).Scan(&family, &envelope.Ciphertext, &envelope.Nonce, &envelope.KeyVersion, &activeTenant); err != nil {
			t.Fatal(err)
		}
		plaintext, err := box.Open(envelope, a.SessionAAD(family))
		if err != nil || activeTenant != nil {
			t.Fatal("invalid initial context or encryption")
		}
		var secrets a.SessionSecrets
		if json.Unmarshal(plaintext, &secrets) != nil || secrets.AccessToken == "" || secrets.RefreshToken == "" || len(secrets.CSRF) != 43 {
			t.Fatal("session secrets not recoverable")
		}
		secretValues = append(secretValues, secrets.AccessToken, secrets.RefreshToken, secrets.CSRF)
		var leaked bool
		if db.admin.QueryRow(testContext, `SELECT EXISTS(SELECT FROM console_auth.oidc_transactions WHERE consumed_at IS NOT NULL AND verifier_ciphertext IS NOT NULL)`).Scan(&leaked) != nil || leaked {
			t.Fatal("consumed verifier not purged")
		}
	})
	t.Run("operator_and_console_me_live_authorization", func(t *testing.T) {
		if sessionCookie == nil {
			t.Fatal("login session missing")
		}
		var actor, family string
		var envelope a.Envelope
		if err := db.admin.QueryRow(testContext, `SELECT operator_identity_id::text,family_id::text,secret_ciphertext,secret_nonce,secret_key_version FROM console_auth.sessions WHERE cookie_hash=$1`, a.Digest(sessionCookie.Value)).Scan(&actor, &family, &envelope.Ciphertext, &envelope.Nonce, &envelope.KeyVersion); err != nil {
			t.Fatal(err)
		}
		plain, err := box.Open(envelope, a.SessionAAD(family))
		if err != nil {
			t.Fatal(err)
		}
		var secrets a.SessionSecrets
		if json.Unmarshal(plain, &secrets) != nil {
			t.Fatal("bad secrets")
		}
		clear(plain)
		call := func(path, token string, cookie *http.Cookie, status int) map[string]any {
			t.Helper()
			req, _ := http.NewRequest("GET", p.ConsoleOrigin+path, nil)
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			if cookie != nil {
				req.AddCookie(cookie)
			}
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			if response.StatusCode != status {
				t.Fatalf("%s: expected %d, got %d", path, status, response.StatusCode)
			}
			if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Referrer-Policy") != "no-referrer" || response.Header.Get("X-Correlation-Id") == "" {
				t.Fatal("missing headers")
			}
			for _, secret := range []string{secrets.AccessToken, secrets.RefreshToken, sessionCookie.Value} {
				if strings.Contains(string(body), secret) {
					t.Fatal("response exposed credential")
				}
			}
			if (response.Header.Get("WWW-Authenticate") != "") != (status == 401 && strings.HasPrefix(path, "/v1/")) {
				t.Fatal("wrong bearer challenge")
			}
			var result map[string]any
			if json.Unmarshal(body, &result) != nil {
				t.Fatal("invalid JSON")
			}
			return result
		}
		call("/v1/operator/me", "", sessionCookie, 401)
		call("/console/api/me", secrets.AccessToken, nil, 401)
		pending := call("/console/api/me", "", sessionCookie, 200)
		if pending["actorId"] != actor || len(pending["tenants"].([]any)) != 0 || pending["activeTenantId"] != nil || pending["context"] != nil || pending["csrfToken"] != secrets.CSRF {
			t.Fatal("wrong pending access")
		}
		mustExec(t, db.admin, `INSERT INTO tenancy.tenants(tenant_id,display_name) VALUES($1,'Own'),($2,'Foreign')`, TestTenantA, TestTenantB)
		mustExec(t, db.admin, `INSERT INTO tenancy.memberships(membership_id,tenant_id,operator_identity_id) VALUES($1,$2,$3)`, TestMemberA, TestTenantA, actor)
		mustExec(t, db.admin, `INSERT INTO tenancy.membership_roles(tenant_id,membership_id,role) VALUES($1,$2,'security_admin')`, TestTenantA, TestMemberA)
		me := call("/v1/operator/me", secrets.AccessToken, nil, 200)
		if me["actorId"] != actor || len(me["tenants"].([]any)) != 1 {
			t.Fatal("wrong operator contexts")
		}
		call("/v1/operator/tenants/"+TestTenantB+"/context", secrets.AccessToken, nil, 404)
		call("/v1/operator/tenants/invalid/context", secrets.AccessToken, nil, 404)
		own := "/v1/operator/tenants/" + TestTenantA + "/context"
		c := call(own, secrets.AccessToken, nil, 200)
		if c["authorizationRevision"] != float64(1) || len(c["issuerIds"].([]any)) != 0 {
			t.Fatal("wrong authorization revision")
		}
		mustExec(t, db.admin, `UPDATE console_auth.sessions SET active_tenant_id=$1,authorization_revision=1 WHERE cookie_hash=$2`, TestTenantA, a.Digest(sessionCookie.Value))
		directory := "/v1/operator/tenants/" + TestTenantA + "/memberships"
		browserDirectory := "/console/api/tenants/" + TestTenantA + "/memberships"
		for _, endpoint := range []string{directory, browserDirectory} {
			token, cookie := secrets.AccessToken, (*http.Cookie)(nil)
			if strings.HasPrefix(endpoint, "/console/") {
				token = ""
				cookie = sessionCookie
			}
			page := call(endpoint, token, cookie, 200)
			items := page["items"].([]any)
			if len(items) != 1 || len(items[0].(map[string]any)) != 10 || items[0].(map[string]any)["membershipId"] != TestMemberA || page["nextCursor"] != nil {
				t.Fatal("directory projection")
			}
			if call(endpoint+"?state=unknown", token, cookie, 422)["code"] != "invalid_input" {
				t.Fatal("wrong input error")
			}
			call(endpoint+"?limit=1&limit=2", token, cookie, 400)
			if call(endpoint+"?cursor=altered", token, cookie, 400)["code"] != "invalid_cursor" {
				t.Fatal("wrong cursor error")
			}
			call(strings.Replace(endpoint, TestTenantA, TestTenantB, 1), token, cookie, 404)
		}
		call(directory, "", sessionCookie, 401)
		call(browserDirectory, secrets.AccessToken, nil, 401)
		invites := strings.Replace(directory, "memberships", "invitations", 1)
		call(invites, secrets.AccessToken, nil, 403)
		mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role='tenant_admin' WHERE membership_id=$1`, TestMemberA)
		if len(call(invites, secrets.AccessToken, nil, 200)["items"].([]any)) != 0 {
			t.Fatal("unexpected invitation")
		}
		call(strings.Replace(browserDirectory, "memberships", "invitations", 1), "", sessionCookie, 200)
		for _, role := range []string{"issuer_operator", "support_readonly"} {
			mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role=$1 WHERE membership_id=$2`, role, TestMemberA)
			call(directory, secrets.AccessToken, nil, 403)
			call(browserDirectory, "", sessionCookie, 403)
		}
		mustExec(t, db.admin, `UPDATE tenancy.membership_roles SET role='security_admin' WHERE membership_id=$1`, TestMemberA)
		selected := call("/console/api/me", "", sessionCookie, 200)
		if selected["activeTenantId"] != TestTenantA || selected["context"].(map[string]any)["tenantId"] != TestTenantA {
			t.Fatal("context inconsistent")
		}
		mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='suspended',authorization_revision=2 WHERE membership_id=$1`, TestMemberA)
		call(directory, secrets.AccessToken, nil, 404)
		call(browserDirectory, "", sessionCookie, 404)
		call(own, secrets.AccessToken, nil, 404)
		call("/console/api/me", "", sessionCookie, 404)
		mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='active',authorization_revision=3 WHERE membership_id=$1`, TestMemberA)
		c = call(own, secrets.AccessToken, nil, 200)
		if c["authorizationRevision"] != float64(3) {
			t.Fatal("cached authorization")
		}
		mustExec(t, db.admin, `UPDATE tenancy.tenants SET state='suspended' WHERE tenant_id=$1`, TestTenantA)
		call(own, secrets.AccessToken, nil, 404)
		mustExec(t, db.admin, `UPDATE tenancy.tenants SET state='active' WHERE tenant_id=$1`, TestTenantA)
		mustExec(t, db.admin, `UPDATE console_auth.sessions SET created_at=created_at-interval '2 hours',last_seen_at=created_at-interval '2 hours',idle_expires_at=now()-interval '1 second' WHERE cookie_hash=$1`, a.Digest(sessionCookie.Value))
		call("/console/api/me", "", sessionCookie, 401)
	})
	commandSession := func(t *testing.T) (*http.Cookie, string) {
		t.Helper()
		u, binding := begin(t)
		response := request(t, authorize(t, u), binding)
		if response.StatusCode != 303 {
			t.Fatal("cannot create command session")
		}
		var cookie *http.Cookie
		for _, c := range response.Cookies() {
			if c.Name == p.CookieName {
				cookie = c
			}
		}
		if cookie == nil {
			t.Fatal("missing command cookie")
		}
		me := request(t, "/console/api/me", cookie)
		var body struct {
			CSRF string `json:"csrfToken"`
		}
		if me.StatusCode != 200 || json.NewDecoder(me.Body).Decode(&body) != nil || body.CSRF == "" {
			t.Fatal("cannot read CSRF")
		}
		secretValues = append(secretValues, cookie.Value, body.CSRF)
		return cookie, body.CSRF
	}
	postCommand := func(t *testing.T, path string, cookie *http.Cookie, csrf, origin string, status int) *http.Response {
		t.Helper()
		req, _ := http.NewRequest("POST", p.ConsoleOrigin+path, nil)
		req.AddCookie(cookie)
		req.Header.Set("Origin", origin)
		req.Header.Set("X-CSRF-Token", csrf)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal("session command transport failed")
		}
		t.Cleanup(func() { response.Body.Close() })
		if response.StatusCode != status {
			t.Fatalf("%s: expected %d got %d", path, status, response.StatusCode)
		}
		if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Correlation-Id") == "" || response.Header.Get("WWW-Authenticate") != "" {
			t.Fatal("unsafe command headers")
		}
		if status == 204 && response.ContentLength > 0 {
			t.Fatal("command returned private body")
		}
		return response
	}
	t.Run("step_up_and_tenant_commands_http", func(t *testing.T) {
		cookie, csrf := commandSession(t)
		old, err := (&LoginStore{Pool: pool}).ReadSession(testContext, a.Digest(cookie.Value), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		postJSON := func(path, body, proof, origin string, c *http.Cookie, status int) *http.Response {
			t.Helper()
			req, _ := http.NewRequest("POST", p.ConsoleOrigin+path, strings.NewReader(body))
			req.AddCookie(c)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", origin)
			req.Header.Set("X-CSRF-Token", proof)
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { response.Body.Close() })
			if response.StatusCode != status {
				t.Fatalf("%s expected %d got %d", path, status, response.StatusCode)
			}
			if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Referrer-Policy") != "no-referrer" || response.Header.Get("X-Correlation-Id") == "" {
				t.Fatal("missing command privacy headers")
			}
			return response
		}
		for _, path := range []string{"/console/auth/step-up", "/console/auth/tenant-context"} {
			before := countSessions(t)
			postJSON(path, `{}`, csrf, "null", cookie, 403)
			postJSON(path, `{}`, strings.Repeat("a", 43), p.ConsoleOrigin, cookie, 403)
			if countSessions(t) != before {
				t.Fatal("invalid proof changed generation")
			}
		}
		postJSON("/console/auth/step-up", `{"returnTo":"https://foreign.invalid"}`, csrf, p.ConsoleOrigin, cookie, 422)
		postJSON("/console/auth/step-up", `{"returnTo":"/","amr":["pwd","otp"]}`, csrf, p.ConsoleOrigin, cookie, 422)
		start := postJSON("/console/auth/step-up", `{"returnTo":"/"}`, csrf, p.ConsoleOrigin, cookie, 303)
		u, _ := url.Parse(start.Header.Get("Location"))
		if u.Query().Get("prompt") != "login consent" || u.Query().Get("max_age") != "0" {
			t.Fatal("step-up did not force reauthentication")
		}
		var binding *http.Cookie
		for _, c := range start.Cookies() {
			if c.Name == "hukid_test_transaction" {
				binding = c
			}
		}
		if binding == nil {
			t.Fatal("missing step-up transaction binding")
		}
		callback := authorize(t, u)
		req, _ := http.NewRequest("GET", p.ConsoleOrigin+callback, nil)
		req.AddCookie(cookie)
		req.AddCookie(binding)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 303 {
			t.Fatalf("step-up callback status %d", response.StatusCode)
		}
		var next *http.Cookie
		for _, c := range response.Cookies() {
			if c.Name == p.CookieName {
				next = c
			}
		}
		if next == nil || next.Value == cookie.Value {
			t.Fatal("step-up did not rotate cookie")
		}
		secretValues = append(secretValues, next.Value, binding.Value)
		if request(t, "/console/api/me", cookie).StatusCode != 401 {
			t.Fatal("step-up preserved old cookie")
		}
		assertError(t, request(t, callback, binding), 400)
		updated, err := (&LoginStore{Pool: pool}).ReadSession(testContext, a.Digest(next.Value), time.Now())
		if err != nil || updated.FamilyID != old.FamilyID || updated.Generation != old.Generation+1 || !updated.AbsoluteExpiresAt.Equal(old.AbsoluteExpiresAt) {
			t.Fatal("step-up changed family or absolute lifetime")
		}
		readMe := func(c *http.Cookie) map[string]any {
			t.Helper()
			r := request(t, "/console/api/me", c)
			var v map[string]any
			if r.StatusCode != 200 || json.NewDecoder(r.Body).Decode(&v) != nil {
				t.Fatal("cannot read rotated me")
			}
			return v
		}
		me := readMe(next)
		nextCSRF := me["csrfToken"].(string)
		if nextCSRF == csrf {
			t.Fatal("step-up did not rotate CSRF")
		}
		secretValues = append(secretValues, nextCSRF)
		postJSON("/console/auth/tenant-context", `{"tenantId":"`+TestTenantB+`"}`, nextCSRF, p.ConsoleOrigin, next, 404)
		postJSON("/console/auth/tenant-context", `{"tenantId":"invalid"}`, nextCSRF, p.ConsoleOrigin, next, 404)
		postJSON("/console/auth/tenant-context", `{"tenantId":"`+TestTenantA+`"}`, csrf, p.ConsoleOrigin, next, 403)
		selected := postJSON("/console/auth/tenant-context", `{"tenantId":"`+TestTenantA+`"}`, nextCSRF, p.ConsoleOrigin, next, 204)
		var selectedCookie *http.Cookie
		for _, c := range selected.Cookies() {
			if c.Name == p.CookieName {
				selectedCookie = c
			}
		}
		if selectedCookie == nil || selectedCookie.Value == next.Value {
			t.Fatal("context did not rotate cookie")
		}
		secretValues = append(secretValues, selectedCookie.Value)
		selection := readMe(selectedCookie)
		if selection["activeTenantId"] != TestTenantA || selection["context"].(map[string]any)["tenantId"] != TestTenantA || selection["csrfToken"] == nextCSRF {
			t.Fatal("inconsistent selected context")
		}
		if request(t, "/console/api/me", next).StatusCode != 401 {
			t.Fatal("old context cookie remained valid")
		}
		mustExec(t, db.admin, `INSERT INTO tenancy.memberships(membership_id,tenant_id,operator_identity_id) VALUES($1,$2,$3)`, TestMemberB, TestTenantB, old.ActorID)
		mustExec(t, db.admin, `INSERT INTO tenancy.membership_roles(tenant_id,membership_id,role) VALUES($1,$2,'support_readonly')`, TestTenantB, TestMemberB)
		// A -> B -> B -> A: repeated selection must also reauthorize and rotate.
		for _, id := range []string{TestTenantB, TestTenantB, TestTenantA} {
			previousCookie, previousProof := selectedCookie, selection["csrfToken"].(string)
			response := postJSON("/console/auth/tenant-context", `{"tenantId":"`+id+`"}`, previousProof, p.ConsoleOrigin, previousCookie, 204)
			for _, c := range response.Cookies() {
				if c.Name == p.CookieName {
					selectedCookie = c
				}
			}
			selection = readMe(selectedCookie)
			if selectedCookie.Value == previousCookie.Value || selection["activeTenantId"] != id || selection["context"].(map[string]any)["tenantId"] != id || selection["csrfToken"] == previousProof {
				t.Fatal("tenant switch preserved stale state/proof")
			}
			secretValues = append(secretValues, selectedCookie.Value, selection["csrfToken"].(string))
			if request(t, "/console/api/me", previousCookie).StatusCode != 401 {
				t.Fatal("previous tenant cookie accepted")
			}
		}
		mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='suspended',authorization_revision=authorization_revision+1 WHERE membership_id=$1`, TestMemberA)
		if request(t, "/console/api/me", selectedCookie).StatusCode != 404 {
			t.Fatal("suspended membership survived context rotation")
		}
		postJSON("/console/auth/tenant-context", `{"tenantId":"`+TestTenantA+`"}`, selection["csrfToken"].(string), p.ConsoleOrigin, selectedCookie, 404)
		mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='active',authorization_revision=authorization_revision+1 WHERE membership_id=$1`, TestMemberA)
	})
	t.Run("refresh_logout_http", func(t *testing.T) {
		cookie, csrf := commandSession(t)
		before := countSessions(t)
		for _, origin := range []string{"", "null", "http://127.0.0.1:1"} {
			response := postCommand(t, "/console/auth/refresh", cookie, csrf, origin, 403)
			var problem struct {
				Code string `json:"code"`
			}
			json.NewDecoder(response.Body).Decode(&problem)
			if problem.Code != "origin_invalid" {
				t.Fatal("wrong origin error")
			}
		}
		postCommand(t, "/console/auth/logout", cookie, "invalid", p.ConsoleOrigin, 403)
		response := postCommand(t, "/console/auth/refresh", cookie, csrf, p.ConsoleOrigin, 204)
		var next *http.Cookie
		for _, c := range response.Cookies() {
			if c.Name == p.CookieName {
				next = c
			}
		}
		if next == nil || next.Value == cookie.Value || !next.HttpOnly || next.Path != "/" || next.SameSite != http.SameSiteLaxMode {
			t.Fatal("bad rotated cookie")
		}
		if countSessions(t) != before+1 {
			t.Fatal("refresh did not create exactly one generation")
		}
		if request(t, "/console/api/me", cookie).StatusCode != 401 {
			t.Fatal("obsolete cookie accepted")
		}
		me := request(t, "/console/api/me", next)
		var body struct {
			CSRF string `json:"csrfToken"`
		}
		if me.StatusCode != 200 || json.NewDecoder(me.Body).Decode(&body) != nil || body.CSRF == csrf || body.CSRF == "" {
			t.Fatal("rotated session not usable")
		}
		for range 2 {
			secretValues = append(secretValues, next.Value, body.CSRF)
			response = postCommand(t, "/console/auth/logout", next, body.CSRF, p.ConsoleOrigin, 204)
			cookies := response.Cookies()
			if len(cookies) != 1 || cookies[0].MaxAge != -1 {
				t.Fatal("logout did not clear cookie")
			}
		}
		if request(t, "/console/api/me", next).StatusCode != 401 {
			t.Fatal("logout cookie reused")
		}
		postCommand(t, "/console/auth/refresh", next, body.CSRF, p.ConsoleOrigin, 401)
	})

	t.Run("operational_disable_invalidate_and_reenable", func(t *testing.T) {
		cookie, _ := commandSession(t)
		pending, binding := begin(t)
		callback := authorize(t, pending)
		enabledEnv := append([]string{}, command.Env...)
		command.Process.Kill()
		if err := command.Wait(); err == nil {
			t.Log("API exited before offline invalidation")
		}
		// The shutdown mechanism is process termination on Windows. This is not a
		// signal/graceful-drain or database disaster-recovery test.
		conn, err := pool.Acquire(testContext)
		if err != nil {
			t.Fatal(err)
		}
		if InvalidateAuthTest(testContext, conn.Conn()) == nil {
			t.Fatal("runtime invalidated lab")
		}
		conn.Release()
		t.Setenv("HUKID_TEST_DATABASE", "0")
		if InvalidateAuthTest(testContext, db.admin) == nil {
			t.Fatal("invalidation accepted missing test flag")
		}
		t.Setenv("HUKID_TEST_DATABASE", "1")
		cancelled, cancel := context.WithCancel(testContext)
		cancel()
		if InvalidateAuthTest(cancelled, db.admin) == nil {
			t.Fatal("cancelled invalidation succeeded")
		}
		cli := func(success bool) {
			t.Helper()
			c := exec.Command(filepath.Join(runtime.GOROOT(), "bin", goName), "run", "../../../cmd/testdb", "invalidate-auth")
			c.Env = append(os.Environ(), "HUKID_DATABASE_URL="+db.dsn, "HUKID_ENV=test", "HUKID_TEST_DATABASE=1")
			out, err := c.CombinedOutput()
			if (err == nil) != success {
				t.Fatal("unexpected lab invalidation result")
			}
			for _, value := range secretValues {
				if value != "" && strings.Contains(string(out), value) {
					t.Fatal("CLI leaked secret")
				}
			}
		}
		var before, after int
		if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM platform.audit_events`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		mustExec(t, db.admin, `ALTER TABLE platform.outbox_events ADD CONSTRAINT rollback_test_failure CHECK(false) NOT VALID`)
		cli(false)
		if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM platform.audit_events`).Scan(&after); err != nil || after != before {
			t.Fatal("partial invalidation audit survived rollback")
		}
		var usable bool
		if err := db.admin.QueryRow(testContext, `SELECT state='active' AND secret_ciphertext IS NOT NULL FROM console_auth.sessions WHERE cookie_hash=$1`, a.Digest(cookie.Value)).Scan(&usable); err != nil || !usable {
			t.Fatal("failed invalidation modified session")
		}
		if err := db.admin.QueryRow(testContext, `SELECT consumed_at IS NULL FROM console_auth.oidc_transactions WHERE state_hash=$1`, a.Digest(pending.Query().Get("state"))).Scan(&usable); err != nil || !usable {
			t.Fatal("failed invalidation consumed callback")
		}
		mustExec(t, db.admin, `ALTER TABLE platform.outbox_events DROP CONSTRAINT rollback_test_failure`)
		// A later failure while cancelling OIDC must also roll back revocation/audit.
		mustExec(t, db.admin, `ALTER TABLE console_auth.oidc_transactions ADD CONSTRAINT rollback_oidc_failure CHECK(consumed_at IS NULL) NOT VALID`)
		cli(false)
		if err := db.admin.QueryRow(testContext, `SELECT state='active' FROM console_auth.sessions WHERE cookie_hash=$1`, a.Digest(cookie.Value)).Scan(&usable); err != nil || !usable {
			t.Fatal("OIDC failure committed session invalidation")
		}
		if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM platform.audit_events`).Scan(&after); err != nil || after != before {
			t.Fatal("OIDC failure committed revocation events")
		}
		mustExec(t, db.admin, `ALTER TABLE console_auth.oidc_transactions DROP CONSTRAINT rollback_oidc_failure`)

		var members, history int
		if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM tenancy.memberships`).Scan(&members); err != nil {
			t.Fatal(err)
		}
		if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM public.hukid_schema_migrations`).Scan(&history); err != nil {
			t.Fatal(err)
		}
		cli(true)
		if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM platform.audit_events`).Scan(&after); err != nil || after <= before {
			t.Fatal("invalidation did not preserve/add audit")
		}
		cli(true)
		var repeat int
		if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM platform.audit_events`).Scan(&repeat); err != nil || repeat != after {
			t.Fatal("repeated invalidation duplicated events")
		}
		for _, sql := range []string{
			`SELECT count(*) FROM console_auth.session_families WHERE state='active' OR refresh_lease IS NOT NULL`,
			`SELECT count(*) FROM console_auth.sessions WHERE state='active' OR secret_ciphertext IS NOT NULL OR secret_nonce IS NOT NULL OR secret_key_version IS NOT NULL OR refresh_digest IS NOT NULL`,
			`SELECT count(*) FROM console_auth.oidc_transactions WHERE consumed_at IS NULL OR verifier_ciphertext IS NOT NULL OR verifier_nonce IS NOT NULL OR verifier_key_version IS NOT NULL`,
		} {
			var n int
			if err := db.admin.QueryRow(testContext, sql).Scan(&n); err != nil || n != 0 {
				t.Fatal("rollback retained authentication material")
			}
		}
		var n int
		if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM tenancy.memberships`).Scan(&n); err != nil || n != members {
			t.Fatal("rollback changed memberships")
		}
		if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM public.hukid_schema_migrations`).Scan(&n); err != nil || n != history {
			t.Fatal("rollback changed schema")
		}
		restart := func(enabled bool) {
			t.Helper()
			command = exec.Command(binary)
			if enabled {
				command.Env = enabledEnv
			} else {
				for _, entry := range os.Environ() {
					if !strings.HasPrefix(entry, "HUKID_") {
						command.Env = append(command.Env, entry)
					}
				}
				command.Env = append(command.Env, "HUKID_LISTEN_ADDR="+listen)
			}
			command.Stdout, command.Stderr = logs, logs
			if command.Start() != nil {
				t.Fatal("cannot restart lab API")
			}
			live := false
			for range 100 {
				r, err := client.Get(p.ConsoleOrigin + "/healthz")
				if err == nil {
					r.Body.Close()
					if r.StatusCode == 204 {
						live = true
						break
					}
				}
				time.Sleep(50 * time.Millisecond)
			}
			if !live {
				t.Fatal("restarted API not live")
			}
		}
		restart(false)
		for _, path := range []string{"/console/auth/login", "/console/api/me", "/v1/operator/me"} {
			req, _ := http.NewRequest("GET", p.ConsoleOrigin+path, nil)
			req.AddCookie(cookie)
			r, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			r.Body.Close()
			if r.StatusCode != 404 || r.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("auth remained available during disablement")
			}
		}
		command.Process.Kill()
		command.Wait()
		restart(true)
		assertError(t, request(t, "/console/api/me", cookie), 401)
		assertError(t, request(t, callback, binding), 400)
		fresh, _ := commandSession(t)
		if r := request(t, "/console/api/me", fresh); r.StatusCode != 200 {
			t.Fatal("new login failed after reenablement")
		}
	})

	t.Run("idp_outage_requires_new_login", func(t *testing.T) {
		logoutCookie, csrf := commandSession(t)
		u, cookie := begin(t)
		path := authorize(t, u)
		driver.call(t, map[string]any{"action": "stop"})
		driver.stopped = true
		assertError(t, request(t, path, cookie), 503)
		assertError(t, request(t, path, cookie), 400)
		postCommand(t, "/console/auth/logout", logoutCookie, csrf, p.ConsoleOrigin, 204)
		postCommand(t, "/console/auth/logout", logoutCookie, csrf, p.ConsoleOrigin, 204)
		if request(t, "/console/api/me", logoutCookie).StatusCode != 401 {
			t.Fatal("IdP outage prevented local logout")
		}
	})
	t.Run("runtime_logs_exclude_secrets", func(t *testing.T) {
		output := logs.String()
		var stored string
		if err := db.admin.QueryRow(testContext, `SELECT COALESCE(string_agg(row_to_json(a)::text,''),'') FROM platform.audit_events a`).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		output += stored
		assertAuthEvents(t, db)
		for _, secret := range secretValues {
			if secret != "" && strings.Contains(output, secret) {
				t.Fatal("authentication secret leaked into runtime logs")
			}
		}
	})
}

func TestLoginIdentityRegistrationPrivilegesAndRollback(t *testing.T) {
	db := newTestDatabase(t)
	if err := migrateThrough(testContext, db.admin, "0002_console_isolation.sql"); err != nil {
		t.Fatal(err)
	}
	mustBootstrap(t, db)
	mustMigrate(t, db)
	pool := db.pool(t, "hukid_session_runtime")
	store := &LoginStore{Pool: pool}
	now := time.Now().UTC()
	secret, nonce := testEnvelope(t, "test-only")
	session := a.InitialSession{FamilyID: "60000000-0000-4000-8000-000000000001", SessionID: "60000000-0000-4000-8000-000000000002", PolicyVersion: "unit", CookieHash: a.Digest("cookie"), CSRFHash: a.Digest("csrf"), RefreshDigest: a.Digest("refresh"), Secrets: a.Envelope{Ciphertext: secret, Nonce: nonce[:11], KeyVersion: "test-only"}, CreatedAt: now, IdleExpiresAt: now.Add(time.Minute), AbsoluteExpiresAt: now.Add(time.Hour), Identity: a.VerifiedLogin{Issuer: "http://127.0.0.1:19090", Subject: "new-rollback-identity", AuthTime: now, AMR: []string{"pwd", "otp"}, ACR: "urn:hukid:test:mfa"}}
	if store.CreateInitialSession(testContext, session) == nil {
		t.Fatal("invalid session accepted")
	}
	var exists bool
	if db.admin.QueryRow(testContext, `SELECT EXISTS(SELECT FROM tenancy.operator_identities WHERE subject='new-rollback-identity')`).Scan(&exists) != nil || exists {
		t.Fatal("identity survived rollback")
	}
	session.Secrets.Nonce = nonce
	if store.CreateInitialSession(testContext, session) != nil {
		t.Fatal("valid initial session rejected")
	}
	for _, sql := range []string{`SELECT * FROM tenancy.operator_identities`, `INSERT INTO tenancy.operator_identities(oidc_issuer,subject) VALUES('x','y')`, `INSERT INTO tenancy.memberships(tenant_id,operator_identity_id) VALUES(NULL,NULL)`, `SET ROLE hukid_identity_writer`} {
		_, err := pool.Exec(testContext, sql)
		expectCode(t, err, "42501")
	}
	tenant := db.pool(t, "hukid_tenant_runtime")
	_, err := tenant.Exec(testContext, `SELECT console_auth.register_operator('x','y')`)
	expectCode(t, err, "42501")
	var id string
	if err := pool.QueryRow(testContext, `SELECT console_auth.register_operator($1,$2)::text`, session.Identity.Issuer, session.Identity.Subject).Scan(&id); err != nil || id == "" {
		t.Fatal("identity not stable")
	}
	if _, err := store.Consume(testContext, a.Digest("absent"), a.Digest("absent"), "issuer", "client", "redirect", now); !errors.Is(err, a.ErrCallback) {
		t.Fatal("missing transaction accepted")
	}
	login := pgx.Identifier{pool.Config().ConnConfig.User}.Sanitize()
	mustExec(t, db.admin, "GRANT hukid_identity_writer TO "+login)
	defer mustExec(t, db.admin, "REVOKE hukid_identity_writer FROM "+login)
	if unsafe, err := OpenRuntimePool(testContext, pool.Config().ConnString(), "hukid_session_runtime", 1); err == nil {
		unsafe.Close()
		t.Fatal("runtime inherited identity writer")
	}
}

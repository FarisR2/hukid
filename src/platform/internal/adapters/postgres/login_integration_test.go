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
	if d.decoder.Decode(&response) != nil || response["error"] != "" {
		t.Fatal("isolated IdP command failed")
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
		selected := call("/console/api/me", "", sessionCookie, 200)
		if selected["activeTenantId"] != TestTenantA || selected["context"].(map[string]any)["tenantId"] != TestTenantA {
			t.Fatal("context inconsistent")
		}
		mustExec(t, db.admin, `UPDATE tenancy.memberships SET state='suspended',authorization_revision=2 WHERE membership_id=$1`, TestMemberA)
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
	t.Run("idp_outage_requires_new_login", func(t *testing.T) {
		u, cookie := begin(t)
		path := authorize(t, u)
		driver.call(t, map[string]any{"action": "stop"})
		driver.stopped = true
		assertError(t, request(t, path, cookie), 503)
		assertError(t, request(t, path, cookie), 400)
	})
	t.Run("runtime_logs_exclude_secrets", func(t *testing.T) {
		output := logs.String()
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

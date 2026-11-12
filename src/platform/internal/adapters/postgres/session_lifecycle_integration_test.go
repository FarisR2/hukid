//go:build integration

package postgres

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"hukid.local/platform/internal/adapters/secretbox"
	a "hukid.local/platform/internal/authentication"
)

type lifecycleOIDC struct {
	identity    a.VerifiedLogin
	refresh     func(context.Context) error
	calls       atomic.Int32
	revocations atomic.Int32
}

func TestSessionLifecycleMigrationPreservesInitialSession(t *testing.T) {
	db := newTestDatabase(t)
	if err := migrateThrough(testContext, db.admin, "0003_console_login.sql"); err != nil {
		t.Fatal(err)
	}
	store := &LoginStore{Pool: db.pool(t, "hukid_session_runtime")}
	now := time.Now().UTC().Truncate(time.Microsecond)
	family := "73000000-0000-4000-8000-000000000001"
	ciphertext, nonce := testEnvelope(t, a.SessionAAD(family))
	initial := a.InitialSession{FamilyID: family, SessionID: "73000000-0000-4000-8000-000000000002", PolicyVersion: "auth-test-v1", CookieHash: a.Digest("upgrade-cookie"), CSRFHash: a.Digest("upgrade-csrf"), RefreshDigest: a.Digest("upgrade-refresh"), Secrets: a.Envelope{Ciphertext: ciphertext, Nonce: nonce, KeyVersion: "test"}, CreatedAt: now, IdleExpiresAt: now.Add(time.Minute), AbsoluteExpiresAt: now.Add(time.Hour), Identity: a.VerifiedLogin{Issuer: "http://127.0.0.1:19090", Subject: "upgrade-session", AuthTime: now, AMR: []string{"pwd", "otp"}, ACR: "urn:hukid:test:mfa"}}
	seedLegacySession(t, db, initial)
	// Preserve an outstanding login transaction across the 0004 -> 0005 upgrade.
	if err := migrateThrough(testContext, db.admin, "0004_session_lifecycle.sql"); err != nil {
		t.Fatal(err)
	}
	pending := "73000000-0000-4000-8000-000000000003"
	mustExec(t, db.admin, `INSERT INTO console_auth.oidc_transactions(transaction_id,purpose,state_hash,nonce_hash,binding_hash,oidc_issuer,client_id,redirect_uri,return_to,verifier_ciphertext,verifier_nonce,verifier_key_version,created_at,expires_at) VALUES($1,'login',$2,$3,$4,'issuer','client','redirect','/',$5,$6,'test',$7,$8)`, pending, a.Digest("pending-state"), a.Digest("pending-nonce"), a.Digest("pending-binding"), ciphertext, nonce, now, now.Add(time.Minute))
	mustMigrate(t, db)
	consumed, err := store.Consume(testContext, a.Digest("pending-state"), a.Digest("pending-binding"), "issuer", "client", "redirect", now)
	if err != nil || consumed.ID != pending || consumed.FamilyID != "" || consumed.Generation != 0 {
		t.Fatal("upgrade changed outstanding login transaction")
	}
	step := a.LoginTransaction{ID: "73000000-0000-4000-8000-000000000004", FamilyID: family, Issuer: "issuer", ClientID: "client", RedirectURI: "redirect", ReturnTo: "/", StateHash: a.Digest("step-state"), NonceHash: a.Digest("step-nonce"), BindingHash: a.Digest("step-binding"), Verifier: initial.Secrets, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := store.CreateTransaction(testContext, step); err == nil {
		t.Fatal("step-up without generation accepted")
	}
	step.Generation = 2
	if err := store.CreateTransaction(testContext, step); err == nil {
		t.Fatal("step-up without referenced generation accepted")
	}
	step.Generation = 1
	if err := store.CreateTransaction(testContext, step); err != nil {
		t.Fatal(err)
	}
	consumed, err = store.Consume(testContext, step.StateHash, step.BindingHash, step.Issuer, step.ClientID, step.RedirectURI, now)
	if err != nil || consumed.FamilyID != family || consumed.Generation != 1 {
		t.Fatal("step-up lost family/generation binding")
	}
	if _, err := store.Consume(testContext, step.StateHash, step.BindingHash, step.Issuer, step.ClientID, step.RedirectURI, now); !errors.Is(err, a.ErrCallback) {
		t.Fatal("step-up consumed twice")
	}
	v, err := store.ReadSession(testContext, initial.CookieHash, now)
	if err != nil || v.Generation != 1 || !a.EqualDigest(v.RefreshDigest, initial.RefreshDigest) || !v.AbsoluteExpiresAt.Equal(initial.AbsoluteExpiresAt) {
		t.Fatal("migration changed initial session")
	}
	_, err = db.admin.Exec(testContext, `INSERT INTO console_auth.sessions(session_id,family_id,operator_identity_id,generation,cookie_hash,csrf_hash,created_at,last_seen_at,idle_expires_at,absolute_expires_at,secret_ciphertext,secret_nonce,secret_key_version,refresh_digest) SELECT gen_random_uuid(),family_id,operator_identity_id,2,$2,csrf_hash,created_at,last_seen_at,idle_expires_at,absolute_expires_at,secret_ciphertext,secret_nonce,secret_key_version,refresh_digest FROM console_auth.sessions WHERE family_id=$1`, family, a.Digest("second-active-cookie"))
	if err == nil {
		t.Fatal("migration allowed two active generations")
	}
}

func (o *lifecycleOIDC) Refresh(ctx context.Context, _, _ string, _ []byte) (a.VerifiedLogin, error) {
	o.calls.Add(1)
	if o.refresh != nil {
		if err := o.refresh(ctx); err != nil {
			return a.VerifiedLogin{}, err
		}
	}
	return o.identity, nil
}
func (o *lifecycleOIDC) Revoke(context.Context, string) error {
	o.revocations.Add(1)
	return a.ErrDependency
}

func TestSessionLifecycleConcurrencyLossAndLogout(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	store := &LoginStore{Pool: db.pool(t, "hukid_session_runtime")}
	f, err := os.Open("../../../config/auth.test.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.LoadPolicy(f, "test")
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	rand.Read(key)
	box, _ := secretbox.New(key, "lifecycle-test", rand.Reader)
	newID := func() string {
		h := randomHex(t, 16)
		return fmt.Sprintf("%s-%s-%s-%s-%s", h[:8], h[8:12], h[12:16], h[16:20], h[20:])
	}
	opaque := func() string { b := make([]byte, 32); rand.Read(b); return base64.RawURLEncoding.EncodeToString(b) }
	for _, name := range []string{"command_concurrent", "command_logout", "command_refresh", "command_rollback", "rotation_replay", "concurrent", "provider_response_lost", "bff_response_lost", "commit_failure", "logout_during_refresh", "cancelled_exchange", "abandoned_lease", "idle_and_absolute", "bad_csrf", "logout_idempotent"} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			cookie, csrf, family := opaque(), opaque(), newID()
			secret := a.SessionSecrets{AccessToken: "old-access", RefreshToken: "old-refresh", CSRF: csrf, OIDCNonceHash: a.Digest("nonce")}
			plain, _ := json.Marshal(secret)
			envelope, err := box.Seal(plain, a.SessionGenerationAAD(family, 1))
			clear(plain)
			if err != nil {
				t.Fatal(err)
			}
			identity := a.VerifiedLogin{Issuer: p.Issuer, Subject: "lifecycle-operator", AccessToken: "new-access", RefreshToken: "new-refresh", AuthTime: now, AMR: p.RequiredAMR, ACR: p.AcceptedACR[0]}
			initial := a.InitialSession{FamilyID: family, SessionID: newID(), PolicyVersion: "auth-test-v1", CookieHash: a.Digest(cookie), CSRFHash: a.Digest(csrf), RefreshDigest: a.Digest(secret.RefreshToken), Secrets: envelope, CreatedAt: now, IdleExpiresAt: now.Add(30 * time.Minute), AbsoluteExpiresAt: now.Add(8 * time.Hour), Identity: identity}
			if err := store.CreateInitialSession(testContext, initial); err != nil {
				t.Fatal(err)
			}
			sessions := &a.SessionService{Store: store, Cipher: box, Policy: p, Now: func() time.Time { return now }}
			provider := &lifecycleOIDC{identity: identity}
			service := &a.SessionLifecycle{Sessions: sessions, Store: store, OIDC: provider, Random: rand.Reader}
			assertRevoked := func() {
				t.Helper()
				if _, err := sessions.Read(testContext, cookie); !errors.Is(err, a.ErrSession) {
					t.Fatal("old cookie remained usable")
				}
				var state string
				var secrets int
				if err := db.admin.QueryRow(testContext, `SELECT state FROM console_auth.session_families WHERE family_id=$1`, family).Scan(&state); err != nil || state != "revoked" {
					t.Fatal("family not revoked")
				}
				if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM console_auth.sessions WHERE family_id=$1 AND (secret_ciphertext IS NOT NULL OR secret_nonce IS NOT NULL OR secret_key_version IS NOT NULL OR refresh_digest IS NOT NULL)`, family).Scan(&secrets); err != nil || secrets != 0 {
					t.Fatal("revocation retained secrets")
				}
			}
			switch name {
			case "command_concurrent", "command_logout", "command_refresh", "command_rollback":
				old, err := store.ReadSession(testContext, a.Digest(cookie), now)
				if err != nil {
					t.Fatal(err)
				}
				plain, _ := json.Marshal(secret)
				envelope, err := box.Seal(plain, a.SessionGenerationAAD(family, 2))
				clear(plain)
				if err != nil {
					t.Fatal(err)
				}
				next := a.SessionRotation{SessionID: newID(), CookieHash: a.Digest(opaque()), CSRFHash: a.Digest(csrf), RefreshDigest: a.Digest(secret.RefreshToken), Secrets: envelope, IdleExpiresAt: now.Add(time.Minute)}
				if name == "command_logout" {
					if err := service.Logout(testContext, cookie, csrf); err != nil {
						t.Fatal(err)
					}
					if err := store.RotateSession(testContext, old, next, &identity, nil, now); !errors.Is(err, a.ErrSession) {
						t.Fatal("step-up resurrected logout")
					}
					assertRevoked()
					return
				}
				if name == "command_refresh" {
					if _, err := store.ClaimRefresh(testContext, a.Digest(cookie), a.Digest(csrf), newID(), now, now.Add(a.RefreshLease)); err != nil {
						t.Fatal(err)
					}
					if err := store.RotateSession(testContext, old, next, &identity, nil, now); !errors.Is(err, a.ErrSession) {
						t.Fatal("step-up overlapped claimed refresh")
					}
					return
				}
				if name == "command_rollback" {
					// Fail after retiring the old generation; rollback must restore it.
					selection := &a.ContextSelection{TenantID: TestTenantB, Revision: 1}
					if err := store.RotateSession(testContext, old, next, &identity, selection, now); err == nil {
						t.Fatal("foreign selection committed")
					}
					if _, err := sessions.Read(testContext, cookie); err != nil {
						t.Fatal("failed rotation lost original generation")
					}
					return
				}
				results := make(chan error, 2)
				for range 2 {
					go func() { results <- store.RotateSession(testContext, old, next, &identity, nil, now) }()
				}
				success, stale := 0, 0
				for range 2 {
					err := <-results
					if err == nil {
						success++
					} else if errors.Is(err, a.ErrSession) {
						stale++
					} else {
						t.Fatal(err)
					}
				}
				if success != 1 || stale != 1 {
					t.Fatal("parallel callbacks committed multiple generations")
				}
				var generations int
				if db.admin.QueryRow(testContext, `SELECT count(*) FROM console_auth.sessions WHERE family_id=$1 AND state='active'`, family).Scan(&generations) != nil || generations != 1 {
					t.Fatal("more than one active successor")
				}
			case "bad_csrf":
				if _, err := service.Refresh(testContext, cookie, opaque()); !errors.Is(err, a.ErrCSRF) {
					t.Fatal("bad proof accepted")
				}
				if err := service.Logout(testContext, cookie, opaque()); !errors.Is(err, a.ErrCSRF) {
					t.Fatal("bad logout proof accepted")
				}
				if _, err := sessions.Read(testContext, cookie); err != nil || provider.calls.Load() != 0 {
					t.Fatal("bad proof changed session")
				}
			case "logout_idempotent":
				for range 2 {
					if err := service.Logout(testContext, cookie, csrf); err != nil {
						t.Fatal(err)
					}
				}
				assertRevoked()
				if provider.revocations.Load() != 1 {
					t.Fatal("repeated provider revocation")
				}
				now = now.Add(8 * time.Hour)
				if !errors.Is(service.Logout(testContext, cookie, csrf), a.ErrCSRF) {
					t.Fatal("expired tombstone accepted")
				}
				if err := store.PurgeSessions(testContext, now); err != nil {
					t.Fatal(err)
				}
				var n int
				if db.admin.QueryRow(testContext, `SELECT count(*) FROM console_auth.sessions WHERE family_id=$1`, family).Scan(&n) != nil || n != 0 {
					t.Fatal("tombstone not purged")
				}
			case "abandoned_lease":
				if _, err := store.ClaimRefresh(testContext, a.Digest(cookie), a.Digest(csrf), newID(), now, now.Add(a.RefreshLease)); err != nil {
					t.Fatal(err)
				}
				now = now.Add(a.RefreshLease)
				if _, err := service.Refresh(testContext, cookie, csrf); !errors.Is(err, a.ErrSession) {
					t.Fatal("abandoned lease retried")
				}
				assertRevoked()
				if provider.calls.Load() != 0 {
					t.Fatal("provider called after uncertain lease")
				}
			case "idle_and_absolute":
				now = now.Add(time.Minute)
				if err := sessions.Touch(testContext, cookie); err != nil {
					t.Fatal(err)
				}
				v, err := store.ReadSession(testContext, a.Digest(cookie), now)
				if err != nil || !v.IdleExpiresAt.Equal(now.Add(30*time.Minute)) || !v.AbsoluteExpiresAt.Equal(initial.AbsoluteExpiresAt) {
					t.Fatal("activity changed absolute cap")
				}
				now = v.IdleExpiresAt
				if _, err := sessions.Read(testContext, cookie); !errors.Is(err, a.ErrSession) {
					t.Fatal("idle deadline accepted")
				}
				if err := store.PurgeSessions(testContext, now); err != nil {
					t.Fatal(err)
				}
				assertRevoked()
			case "concurrent", "logout_during_refresh", "cancelled_exchange":
				entered, release := make(chan struct{}), make(chan struct{})
				provider.refresh = func(ctx context.Context) error {
					close(entered)
					select {
					case <-release:
						return nil
					case <-ctx.Done():
						return a.ErrDependency
					}
				}
				ctx, cancel := context.WithCancel(testContext)
				defer cancel()
				result := make(chan error, 1)
				go func() { _, err := service.Refresh(ctx, cookie, csrf); result <- err }()
				<-entered
				if _, err := service.Refresh(testContext, cookie, csrf); !errors.Is(err, a.ErrRefreshBusy) {
					t.Fatal("concurrent refresh not coordinated")
				}
				if name == "logout_during_refresh" {
					if err := service.Logout(testContext, cookie, csrf); err != nil {
						t.Fatal(err)
					}
				}
				if name == "cancelled_exchange" {
					cancel()
				} else {
					close(release)
				}
				err := <-result
				if (err == nil) != (name == "concurrent") {
					t.Fatal("unexpected in-flight result")
				}
				if provider.calls.Load() != 1 {
					t.Fatal("multiple exchanges for same generation")
				}
				if name != "concurrent" {
					assertRevoked()
				}
			case "provider_response_lost", "commit_failure":
				if name == "provider_response_lost" {
					provider.refresh = func(context.Context) error { return a.ErrDependency }
				} else {
					mustExec(t, db.admin, `ALTER TABLE console_auth.sessions ADD CONSTRAINT lifecycle_fail CHECK(generation=1) NOT VALID`)
					defer mustExec(t, db.admin, `ALTER TABLE console_auth.sessions DROP CONSTRAINT lifecycle_fail`)
				}
				if _, err := service.Refresh(testContext, cookie, csrf); err == nil {
					t.Fatal("uncertain refresh succeeded")
				}
				assertRevoked()
				if _, err := service.Refresh(testContext, cookie, csrf); err == nil || provider.calls.Load() != 1 {
					t.Fatal("uncertain exchange retried")
				}
			case "rotation_replay", "bff_response_lost":
				next, err := service.Refresh(testContext, cookie, csrf)
				if err != nil {
					t.Fatal(err)
				}
				if next.Cookie == cookie || !next.ExpiresAt.Equal(initial.AbsoluteExpiresAt) {
					t.Fatal("rotation failed or absolute lifetime extended")
				}
				view, err := sessions.Read(testContext, next.Cookie)
				if err != nil || view.CSRF == csrf || view.AccessToken != "new-access" {
					t.Fatal("successor not readable with generational AAD")
				}
				if _, err := sessions.Read(testContext, cookie); !errors.Is(err, a.ErrSession) {
					t.Fatal("obsolete cookie recovered successor")
				}
				if name == "bff_response_lost" {
					// Deliberately discard the successful response: only the old proof survives.
					if err := service.Logout(testContext, cookie, csrf); err != nil {
						t.Fatal(err)
					}
				} else if _, err := service.Refresh(testContext, cookie, csrf); !errors.Is(err, a.ErrSession) {
					t.Fatal("replayed generation accepted")
				}
				assertRevoked()
				if _, err := sessions.Read(testContext, next.Cookie); !errors.Is(err, a.ErrSession) {
					t.Fatal("replay did not invalidate successor")
				}
			}
		})
	}
}

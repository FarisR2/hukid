//go:build integration

package postgres

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"hukid.local/platform/internal/adapters/secretbox"
)

func keyFixtures(t *testing.T, db *testDatabase) (*VerifierKeyProvisioner, *VerifierKeyStore, *secretbox.Box) {
	t.Helper()
	seedVerificationTenants(t, db)
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	box, err := secretbox.New(master, "synthetic-master-v1", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgxpool.New(testContext, db.dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	return &VerifierKeyProvisioner{Pool: admin, Cipher: box}, &VerifierKeyStore{Pool: db.pool(t, "hukid_verification_runtime"), Cipher: box}, box
}

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestVerifierKeyIsSealedAndServedThroughTheSession(t *testing.T) {
	db := newTestDatabase(t)
	provisioner, store, _ := keyFixtures(t, db)
	key := newP256(t)
	kid, err := provisioner.Provision(testContext, vsTenantA, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	session, err := startSession(t, db, vsTenantA, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got, gotKid, chain, err := store.SigningKey(testContext, session)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(key) || gotKid != kid || chain != nil {
		t.Fatal("the session did not receive its tenant's key")
	}
	// The private scalar never reaches the table in clear.
	var ciphertext []byte
	if err := db.admin.QueryRow(testContext, `SELECT ciphertext FROM verification.verifier_keys WHERE kid=$1`, kid).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, key.D.Bytes()) {
		t.Fatal("the private key is stored in clear")
	}
}

func TestVerifierKeyDoesNotCrossTenantsOrSessions(t *testing.T) {
	db := newTestDatabase(t)
	provisioner, store, _ := keyFixtures(t, db)
	keyA, keyB := newP256(t), newP256(t)
	if _, err := provisioner.Provision(testContext, vsTenantA, keyA, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := provisioner.Provision(testContext, vsTenantB, keyB, nil); err != nil {
		t.Fatal(err)
	}
	sessionA, _ := startSession(t, db, vsTenantA, 5*time.Minute)
	sessionB, _ := startSession(t, db, vsTenantB, 5*time.Minute)
	gotA, _, _, errA := store.SigningKey(testContext, sessionA)
	gotB, _, _, errB := store.SigningKey(testContext, sessionB)
	if errA != nil || errB != nil || !gotA.Equal(keyA) || !gotB.Equal(keyB) || gotA.Equal(keyB) {
		t.Fatal("tenant keys crossed")
	}
	// Moving a sealed key to another tenant must not open: the AAD binds it.
	mustExec(t, db.admin, `UPDATE verification.verifier_keys SET ciphertext=(SELECT ciphertext FROM verification.verifier_keys WHERE tenant_id=$1),nonce=(SELECT nonce FROM verification.verifier_keys WHERE tenant_id=$1) WHERE tenant_id=$2`, vsTenantA, vsTenantB)
	fresh, _ := startSession(t, db, vsTenantB, 5*time.Minute)
	if _, _, _, err := store.SigningKey(testContext, fresh); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("a copied envelope opened: %v", err)
	}
	// Copying the key id as well must not open it either: only the tenant in the
	// AAD tells the two owners apart once the kid is the same.
	mustExec(t, db.admin, `UPDATE verification.verifier_keys SET kid=(SELECT kid FROM verification.verifier_keys WHERE tenant_id=$1) WHERE tenant_id=$2`, vsTenantA, vsTenantB)
	fresh, _ = startSession(t, db, vsTenantB, 5*time.Minute)
	if _, _, _, err := store.SigningKey(testContext, fresh); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("an envelope copied with its kid opened under another tenant: %v", err)
	}
}

func TestVerifierKeyRuntimeHasNoDirectAccess(t *testing.T) {
	db := newTestDatabase(t)
	provisioner, store, _ := keyFixtures(t, db)
	if _, err := provisioner.Provision(testContext, vsTenantA, newP256(t), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(testContext, `SELECT * FROM verification.verifier_keys`); err == nil {
		t.Fatal("the runtime role read the key table")
	}
	if _, err := store.Pool.Exec(testContext, `SELECT verification.rotate_verifier_key($1::uuid,'k','\x00'::bytea,'\x00'::bytea,'v',ARRAY[]::bytea[])`, vsTenantA); err == nil {
		t.Fatal("the runtime role rotated a key")
	}
	if _, err := store.Pool.Exec(testContext, `SELECT verification.purge_retired_keys(1)`); err == nil {
		t.Fatal("the runtime role purged keys")
	}
}

func TestVerifierKeyNeedsAPendingUnexpiredSession(t *testing.T) {
	db := newTestDatabase(t)
	provisioner, store, _ := keyFixtures(t, db)
	if _, err := provisioner.Provision(testContext, vsTenantA, newP256(t), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.SigningKey(testContext, "99999999-9999-4999-8999-999999999999"); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("unknown session: %v", err)
	}
	session, _ := startSession(t, db, vsTenantA, time.Minute)
	mustExec(t, db.admin, `UPDATE verification.sessions SET created_at=created_at-interval '10 minutes',expires_at=expires_at-interval '10 minutes' WHERE session_id=$1`, session)
	if _, _, _, err := store.SigningKey(testContext, session); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("expired session: %v", err)
	}
	// A session that already completed no longer yields a key.
	done := mustSession(t, db, vsTenantA)
	mustExec(t, db.admin, `UPDATE verification.sessions SET status='completed',result='pass',report_digest=decode(repeat('00',32),'hex'),completed_at=clock_timestamp() WHERE session_id=$1`, done)
	if _, _, _, err := store.SigningKey(testContext, done); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("completed session: %v", err)
	}
	// A tenant without a key yields the same generic error.
	if _, _, _, err := store.SigningKey(testContext, mustSession(t, db, vsTenantB)); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("tenant without key: %v", err)
	}
}

func mustSession(t *testing.T, db *testDatabase, tenant string) string {
	t.Helper()
	id, err := startSession(t, db, tenant, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestVerifierKeyRotationPinsOpenSessionsAndPurgesRetired(t *testing.T) {
	db := newTestDatabase(t)
	provisioner, store, _ := keyFixtures(t, db)
	oldKey, newKey := newP256(t), newP256(t)
	oldKid, err := provisioner.Provision(testContext, vsTenantA, oldKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	pinned := mustSession(t, db, vsTenantA)
	if got, kid, _, err := store.SigningKey(testContext, pinned); err != nil || kid != oldKid || !got.Equal(oldKey) {
		t.Fatalf("first fetch: %v", err)
	}
	newKid, err := provisioner.Provision(testContext, vsTenantA, newKey, nil)
	if err != nil || newKid == oldKid {
		t.Fatalf("rotation: %v", err)
	}
	// The open session keeps its pinned (now retiring) key; a new one gets the new key.
	if got, kid, _, err := store.SigningKey(testContext, pinned); err != nil || kid != oldKid || !got.Equal(oldKey) {
		t.Fatalf("pinned session lost its key after rotation: %v", err)
	}
	if got, kid, _, err := store.SigningKey(testContext, mustSession(t, db, vsTenantA)); err != nil || kid != newKid || !got.Equal(newKey) {
		t.Fatalf("new session did not get the new key: %v", err)
	}
	var active int
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM verification.verifier_keys WHERE tenant_id=$1 AND status='active'`, vsTenantA).Scan(&active); err != nil || active != 1 {
		t.Fatalf("active keys: %d (%v)", active, err)
	}
	// The retiring key stays while a session still needs it, and goes after.
	var removed int
	if err := db.admin.QueryRow(testContext, `SELECT verification.purge_retired_keys(10)`).Scan(&removed); err != nil || removed != 0 {
		t.Fatalf("purged a key still in use: %d (%v)", removed, err)
	}
	mustExec(t, db.admin, `UPDATE verification.sessions SET status='completed',result='pass',report_digest=decode(repeat('00',32),'hex'),completed_at=clock_timestamp() WHERE session_id=$1`, pinned)
	if err := db.admin.QueryRow(testContext, `SELECT verification.purge_retired_keys(10)`).Scan(&removed); err != nil || removed != 1 {
		t.Fatalf("purged %d retired keys, want 1 (%v)", removed, err)
	}
	var left int
	if err := db.admin.QueryRow(testContext, `SELECT count(*) FROM verification.verifier_keys WHERE kid=$1`, oldKid).Scan(&left); err != nil || left != 0 {
		t.Fatalf("retired key not purged: %d (%v)", left, err)
	}
}

func TestVerifierKeyRejectsAChainThatDoesNotMatch(t *testing.T) {
	db := newTestDatabase(t)
	provisioner, _, _ := keyFixtures(t, db)
	if _, err := provisioner.Provision(testContext, vsTenantA, newP256(t), [][]byte{[]byte("not a certificate")}); !errors.Is(err, ErrVerifierKey) {
		t.Fatalf("garbage chain accepted: %v", err)
	}
}

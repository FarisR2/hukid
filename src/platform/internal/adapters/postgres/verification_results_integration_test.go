//go:build integration

package postgres

import (
	"errors"
	"slices"
	"testing"
	"time"

	"hukid.local/platform/internal/verification"
)

func TestResultStoreCompletesAPendingSessionOnce(t *testing.T) {
	db := newTestDatabase(t)
	seedVerificationTenants(t, db)
	store := &VerificationResultStore{Pool: db.pool(t, "hukid_verification_runtime")}
	id := mustSession(t, db, vsTenantA)
	report := verification.PresentationReport{
		TechnicalResult: verification.Invalid,
		Digest:          verification.Digest([]byte("synthetic presentation")),
		Checks:          []verification.Check{{Name: verification.CheckRequestBinding, Result: verification.Fail, Code: verification.CodeRequestNonce, Required: true}},
	}
	if err := store.DeliverSession(id, report); err != nil {
		t.Fatal(err)
	}
	var status, result string
	var codes []string
	if err := db.admin.QueryRow(testContext, `SELECT status,result,codes FROM verification.sessions WHERE session_id=$1`, id).Scan(&status, &result, &codes); err != nil {
		t.Fatal(err)
	}
	if status != "completed" || result != "fail" || !slices.Equal(codes, []string{string(verification.CodeRequestNonce)}) {
		t.Fatalf("%s %s %v", status, result, codes)
	}
	// A second result for the same session is refused, so it cannot be overwritten.
	if err := store.DeliverSession(id, report); !errors.Is(err, ErrResultNotStored) {
		t.Fatalf("second delivery: %v", err)
	}
}

func TestResultStoreRefusesUnknownAndExpiredSessions(t *testing.T) {
	db := newTestDatabase(t)
	seedVerificationTenants(t, db)
	store := &VerificationResultStore{Pool: db.pool(t, "hukid_verification_runtime")}
	report := verification.PresentationReport{TechnicalResult: verification.Valid, Digest: verification.Digest([]byte("x"))}
	if err := store.DeliverSession("99999999-9999-4999-8999-999999999999", report); !errors.Is(err, ErrResultNotStored) {
		t.Fatalf("unknown: %v", err)
	}
	id, err := startSession(t, db, vsTenantA, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db.admin, `UPDATE verification.sessions SET created_at=created_at-interval '10 minutes',expires_at=expires_at-interval '10 minutes' WHERE session_id=$1`, id)
	if err := store.DeliverSession(id, report); !errors.Is(err, ErrResultNotStored) {
		t.Fatalf("expired: %v", err)
	}
}

package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"hukid.local/platform/internal/verification"
)

const resultQueryTimeout = 5 * time.Second

// ErrResultNotStored reports that a result was not recorded: the session is
// unknown, already completed or expired, or the report is malformed. The
// causes are deliberately not distinguished.
var ErrResultNotStored = errors.New("verification result not stored")

// maxResultCodes matches the cardinality limit of verification.sessions.codes.
const maxResultCodes = 32

// VerificationResultStore records the outcome of a tenant's verification
// session (ADR-0033 #3). It stores the result, the closed-set failure codes
// and the report digest, never the JWS, the claims or the vp_token. Pool must
// belong to hukid_verification_runtime, which can only complete a session
// through verification.complete_session.
type VerificationResultStore struct{ Pool *pgxpool.Pool }

// Deliver satisfies oid4vphttp.Results but always refuses: this store records
// results only for sessions bound to a persisted tenant session, which the
// handler routes to DeliverSession. A request without one has nowhere to go.
func (s *VerificationResultStore) Deliver(string, verification.PresentationReport) error {
	return ErrResultNotStored
}

// DeliverSession implements oid4vphttp.SessionResults.
func (s *VerificationResultStore) DeliverSession(sessionID string, report verification.PresentationReport) error {
	if s == nil || s.Pool == nil || !validID(sessionID) {
		return ErrResultNotStored
	}
	result, codes, digest, err := summarizeReport(report)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), resultQueryTimeout)
	defer cancel()
	var completed bool
	if err := s.Pool.QueryRow(ctx, `SELECT verification.complete_session($1::uuid,$2,$3,$4)`, sessionID, result, codes, digest).Scan(&completed); err != nil {
		return errors.New("verification result store unavailable")
	}
	if !completed {
		return ErrResultNotStored
	}
	return nil
}

// summarizeReport reduces a report to what the table keeps: pass or fail, the
// distinct failure codes in stable order, and the 32-byte digest.
func summarizeReport(report verification.PresentationReport) (string, []string, []byte, error) {
	var result string
	switch report.TechnicalResult {
	case verification.Valid:
		result = "pass"
	case verification.Invalid:
		result = "fail"
	default:
		return "", nil, nil, ErrResultNotStored
	}
	digest, ok := strings.CutPrefix(report.Digest, "sha256:")
	raw, decodeErr := hex.DecodeString(digest)
	if !ok || decodeErr != nil || len(raw) != 32 {
		return "", nil, nil, ErrResultNotStored
	}
	seen := map[string]bool{}
	collect := func(checks []verification.Check) {
		for _, check := range checks {
			if check.Result != verification.Pass && check.Code != "" && verification.IsKnown(check.Code) {
				seen[string(check.Code)] = true
			}
		}
	}
	collect(report.Checks)
	for _, credential := range report.Credentials {
		collect(credential.Checks)
	}
	codes := make([]string, 0, len(seen))
	for code := range seen {
		codes = append(codes, code)
	}
	slices.Sort(codes)
	if len(codes) > maxResultCodes {
		return "", nil, nil, ErrResultNotStored
	}
	return result, codes, raw, nil
}

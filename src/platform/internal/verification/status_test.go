package verification

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type mapStatusResolver struct {
	lists map[string]string
	err   error
}

func (m mapStatusResolver) ResolveStatusList(url string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	jwt, ok := m.lists[url]
	if !ok {
		return "", errors.New("not found")
	}
	return jwt, nil
}

func encodeTestBitstring(t *testing.T, byteLen int, activeBits ...int) string {
	t.Helper()
	bits := make([]byte, byteLen)
	for _, idx := range activeBits {
		bits[idx/8] |= byte(1 << (7 - uint(idx%8)))
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(bits); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return "u" + base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

func buildTestStatusListVC(t *testing.T, key *ecdsa.PrivateKey, issuer, kid, listURL, purpose string, validFrom, validUntil time.Time, encoded string) string {
	t.Helper()
	payload := map[string]any{
		"@context":   []string{vcdmBaseContext},
		"id":         listURL,
		"type":       []string{"VerifiableCredential", "BitstringStatusListCredential"},
		"issuer":     issuer,
		"validFrom":  validFrom.UTC().Format(time.RFC3339),
		"validUntil": validUntil.UTC().Format(time.RFC3339),
		"credentialSubject": map[string]any{
			"id":            listURL + "#list",
			"type":          "BitstringStatusList",
			"statusPurpose": purpose,
			"encodedList":   encoded,
		},
	}
	return compact(baseHeader(kid), payload, key)
}

func TestVerifierChecksBitstringStatusLists(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://issuer.example/unas"
	kid := "unas-k1"
	now := at(t, insideWindow)
	resolver := NewMemoryKeyResolver()
	if err := resolver.Add(issuer, kid, &key.PublicKey); err != nil {
		t.Fatal(err)
	}

	revURL := issuer + "/status/revocation/list-1"
	suspURL := issuer + "/status/suspension/list-2"
	credPayload := credentialPayload("holder-jkt-123")
	credPayload["issuer"] = issuer
	credPayload["credentialStatus"] = []map[string]any{
		{
			"id":                   revURL + "#12",
			"type":                 "BitstringStatusListEntry",
			"statusPurpose":        "revocation",
			"statusListIndex":      "12",
			"statusListCredential": revURL,
		},
		{
			"id":                   suspURL + "#5",
			"type":                 "BitstringStatusListEntry",
			"statusPurpose":        "suspension",
			"statusListIndex":      "5",
			"statusListCredential": suspURL,
		},
	}
	vc := compact(baseHeader(kid), credPayload, key)

	mkVerifier := func(revBits, suspBits []int, listValidFrom, listValidUntil time.Time, staleness time.Duration) *Verifier {
		lists := map[string]string{
			revURL:  buildTestStatusListVC(t, key, issuer, kid, revURL, "revocation", listValidFrom, listValidUntil, encodeTestBitstring(t, 64, revBits...)),
			suspURL: buildTestStatusListVC(t, key, issuer, kid, suspURL, "suspension", listValidFrom, listValidUntil, encodeTestBitstring(t, 64, suspBits...)),
		}
		v, err := NewVerifier(resolver, fixedClock(now), DefaultLimits, DefaultClockSkew)
		if err != nil {
			t.Fatal(err)
		}
		return v.WithStatusResolver(mapStatusResolver{lists: lists}, StatusPolicy{MaxStaleness: staleness})
	}

	// 1. Active credential passes.
	activeRep, err := mkVerifier(nil, nil, now.Add(-time.Minute), now.Add(time.Hour), 5*time.Minute).Verify(vc)
	if err != nil || activeRep.TechnicalResult != Valid {
		t.Fatalf("expected active valid credential, got rep=%+v err=%v", activeRep, err)
	}

	// 2. Suspended bit=1 fails with status.suspended.
	suspRep, err := mkVerifier(nil, []int{5}, now.Add(-time.Minute), now.Add(time.Hour), 0).Verify(vc)
	if err != nil || suspRep.TechnicalResult != Invalid {
		t.Fatalf("expected suspended failure, got %+v err=%v", suspRep, err)
	}
	failed, ok := failedCheck(suspRep)
	if !ok || failed.Name != CheckStatus || failed.Code != CodeStatusSuspended {
		t.Fatalf("expected status.suspended, got %+v", suspRep.Checks)
	}

	// 3. Revoked overrides suspended and fails with status.revoked.
	revRep, err := mkVerifier([]int{12}, []int{5}, now.Add(-time.Minute), now.Add(time.Hour), 0).Verify(vc)
	if err != nil || revRep.TechnicalResult != Invalid {
		t.Fatalf("expected revoked failure, got %+v err=%v", revRep, err)
	}
	failed, _ = failedCheck(revRep)
	if failed.Name != CheckStatus || failed.Code != CodeStatusRevoked {
		t.Fatalf("expected status.revoked, got %+v", revRep.Checks)
	}

	// 4. Stale / expired status list fails with status.invalid.
	staleRep, err := mkVerifier(nil, nil, now.Add(-20*time.Minute), now.Add(time.Hour), 5*time.Minute).Verify(vc)
	if err != nil || staleRep.TechnicalResult != Invalid {
		t.Fatalf("expected stale list rejection, got %+v err=%v", staleRep, err)
	}
	failed, _ = failedCheck(staleRep)
	if failed.Code != CodeStatusInvalid {
		t.Fatalf("expected status.invalid for stale list, got %+v", staleRep.Checks)
	}

	// 5. Cross-host status URL is rejected cleanly as status.invalid without calling resolver.
	evilPayload := credentialPayload("holder-jkt-123")
	evilPayload["issuer"] = issuer
	evilPayload["credentialStatus"] = []map[string]any{{
		"id": "https://evil.example/s#0", "type": "BitstringStatusListEntry",
		"statusPurpose": "revocation", "statusListIndex": "0", "statusListCredential": "https://evil.example/s",
	}}
	evilVC := compact(baseHeader(kid), evilPayload, key)
	v := mkVerifier(nil, nil, now.Add(-time.Minute), now.Add(time.Hour), 0)
	evilRep, err := v.Verify(evilVC)
	if err != nil || evilRep.TechnicalResult != Invalid {
		t.Fatalf("expected evil status host to fail, got %+v err=%v", evilRep, err)
	}
	if failed, _ := failedCheck(evilRep); failed.Code != CodeStatusInvalid {
		t.Fatalf("expected status.invalid, got %+v", evilRep.Checks)
	}

	// 6. Tampered status list signature fails with status.invalid.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	vTampered, _ := NewVerifier(resolver, fixedClock(now), DefaultLimits, 0)
	vTampered = vTampered.WithStatusResolver(mapStatusResolver{lists: map[string]string{
		revURL:  buildTestStatusListVC(t, otherKey, issuer, kid, revURL, "revocation", now.Add(-time.Minute), now.Add(time.Hour), encodeTestBitstring(t, 64)),
		suspURL: buildTestStatusListVC(t, key, issuer, kid, suspURL, "suspension", now.Add(-time.Minute), now.Add(time.Hour), encodeTestBitstring(t, 64)),
	}}, StatusPolicy{})
	tamperedRep, err := vTampered.Verify(vc)
	if err != nil || tamperedRep.TechnicalResult != Invalid {
		t.Fatalf("expected tampered list to fail, got %+v err=%v", tamperedRep, err)
	}
	if failed, _ := failedCheck(tamperedRep); failed.Code != CodeStatusInvalid {
		t.Fatalf("expected status.invalid, got %+v", tamperedRep.Checks)
	}

	// 7. Resolver failure returns ErrStatusResolution with empty report and zero leaks.
	vErr, _ := NewVerifier(resolver, fixedClock(now), DefaultLimits, 0)
	vErr = vErr.WithStatusResolver(mapStatusResolver{err: errors.New("connection refused to secret url " + revURL)}, StatusPolicy{})
	errRep, err := vErr.Verify(vc)
	if !errors.Is(err, ErrStatusResolution) || errRep.Digest != "" || strings.Contains(err.Error(), "secret url") {
		t.Fatalf("expected clean ErrStatusResolution without leaks, got rep=%+v err=%v", errRep, err)
	}

	// 8. Index out of bounds fails cleanly as status.invalid.
	outOfBoundsRep, err := mkVerifier([]int{}, []int{}, now.Add(-time.Minute), now.Add(time.Hour), 0).WithStatusResolver(mapStatusResolver{lists: map[string]string{
		revURL:  buildTestStatusListVC(t, key, issuer, kid, revURL, "revocation", now.Add(-time.Minute), now.Add(time.Hour), encodeTestBitstring(t, 1)),
		suspURL: buildTestStatusListVC(t, key, issuer, kid, suspURL, "suspension", now.Add(-time.Minute), now.Add(time.Hour), encodeTestBitstring(t, 64)),
	}}, StatusPolicy{}).Verify(vc)
	if err != nil || outOfBoundsRep.TechnicalResult != Invalid {
		t.Fatalf("expected out-of-bounds index to fail, got %+v err=%v", outOfBoundsRep, err)
	}
	if blob, _ := json.Marshal(outOfBoundsRep); strings.Contains(string(blob), "holder-jkt-123") {
		t.Fatalf("status failure report leaked holder material: %s", blob)
	}
}

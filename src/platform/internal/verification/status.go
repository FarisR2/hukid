package verification

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
)

// ErrStatusResolution wraps a failure of the StatusResolver port (network or
// unavailable status list). Never exposes credential contents.
var ErrStatusResolution = errors.New("status resolution failed")

// StatusResolver fetches a signed BitstringStatusListCredential JWT by URL.
// It is a pure port; HTTP(S) transport and same-host redirect rules live in the adapter.
type StatusResolver interface {
	ResolveStatusList(credentialURL string) (string, error)
}

// DefaultMaxStatusStaleness is the default production/staging freshness bound
// for BitstringStatusListCredential documents under VER-T09.
const DefaultMaxStatusStaleness = 15 * time.Minute

// StatusPolicy controls list freshness and trust checks for VER-T09. Resolution
// failures fail closed by default (returning ErrStatusResolution).
type StatusPolicy struct {
	MaxStaleness      time.Duration
	RequireValidUntil bool
}

// DefaultStatusPolicy returns the recommended production/staging VER-T09 policy:
// status lists must be published within DefaultMaxStatusStaleness and carry an
// explicit expiration (validUntil / exp).
func DefaultStatusPolicy() StatusPolicy {
	return StatusPolicy{
		MaxStaleness:      DefaultMaxStatusStaleness,
		RequireValidUntil: true,
	}
}

type rawStatusEntry struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"`
	StatusPurpose        string `json:"statusPurpose"`
	StatusListIndex      string `json:"statusListIndex"`
	StatusListCredential string `json:"statusListCredential"`
}

const maxDecodedStatusBytes = 1 << 20

func parseCredentialStatusEntries(raw json.RawMessage) ([]rawStatusEntry, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, false
	}
	var list []rawStatusEntry
	switch trimmed[0] {
	case '[':
		if err := json.Unmarshal(trimmed, &list); err != nil || len(list) == 0 || len(list) > 8 {
			return nil, false
		}
	case '{':
		var single rawStatusEntry
		if err := json.Unmarshal(trimmed, &single); err != nil {
			return nil, false
		}
		list = []rawStatusEntry{single}
	default:
		return nil, false
	}
	return list, true
}

func parseBitIndex(s string) (int, bool) {
	if s == "" || strings.TrimSpace(s) != s {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func decodeBitstringList(encoded string) ([]byte, bool) {
	if len(encoded) < 2 || encoded[0] != 'u' {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded[1:])
	if err != nil {
		return nil, false
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, false
	}
	defer zr.Close()
	bits, err := io.ReadAll(io.LimitReader(zr, maxDecodedStatusBytes+1))
	if err != nil || len(bits) == 0 || len(bits) > maxDecodedStatusBytes {
		return nil, false
	}
	return bits, true
}

func bitSet(bits []byte, index int) (set, inBounds bool) {
	byteIdx := index / 8
	if index < 0 || byteIdx >= len(bits) {
		return false, false
	}
	mask := byte(1 << (7 - uint(index%8)))
	return (bits[byteIdx] & mask) != 0, true
}

type verifiedStatusList struct {
	purpose string
	bits    []byte
}

func (v *Verifier) evaluateStatus(parsed *ParsedCredential) (Check, error) {
	if !parsed.DeclaresStatus {
		return optionalSkip(CheckStatus, false), nil
	}
	if v.status == nil {
		return optionalSkip(CheckStatus, true), nil
	}
	entries, ok := parseCredentialStatusEntries(parsed.RawStatus)
	if !ok {
		return Failed(CheckStatus, CodeStatusInvalid), nil
	}

	now := v.clock.Now().UTC()
	cache := map[string]verifiedStatusList{}
	var suspended bool

	for _, entry := range entries {
		if entry.Type != "BitstringStatusListEntry" ||
			(entry.StatusPurpose != "revocation" && entry.StatusPurpose != "suspension") ||
			!strings.HasPrefix(entry.StatusListCredential, parsed.Issuer+"/") ||
			strings.ContainsAny(entry.StatusListCredential, "?# \t\r\n") {
			return Failed(CheckStatus, CodeStatusInvalid), nil
		}
		idx, idxOK := parseBitIndex(entry.StatusListIndex)
		if !idxOK {
			return Failed(CheckStatus, CodeStatusInvalid), nil
		}

		list, cached := cache[entry.StatusListCredential]
		if !cached {
			verified, failCode, err := v.fetchAndVerifyStatusList(entry.StatusListCredential, parsed.Issuer, now)
			if err != nil {
				return Check{}, err
			}
			if failCode != "" {
				return Failed(CheckStatus, failCode), nil
			}
			list = verified
			cache[entry.StatusListCredential] = list
		}

		if list.purpose != entry.StatusPurpose {
			return Failed(CheckStatus, CodeStatusInvalid), nil
		}
		isSet, inBounds := bitSet(list.bits, idx)
		if !inBounds {
			return Failed(CheckStatus, CodeStatusInvalid), nil
		}
		if isSet {
			if entry.StatusPurpose == "revocation" {
				return Failed(CheckStatus, CodeStatusRevoked), nil
			}
			suspended = true
		}
	}

	if suspended {
		return Failed(CheckStatus, CodeStatusSuspended), nil
	}
	return Passed(CheckStatus, true), nil
}

func (v *Verifier) fetchAndVerifyStatusList(credURL, expectedIssuer string, now time.Time) (verifiedStatusList, Code, error) {
	listJWS, err := v.status.ResolveStatusList(credURL)
	if err != nil {
		return verifiedStatusList{}, "", ErrStatusResolution
	}
	listParsed, checks, err := integrityChecks(listJWS, v.limits, v.keys)
	if err != nil {
		return verifiedStatusList{}, "", err
	}
	if listParsed == nil || len(checks) < 3 ||
		checks[len(checks)-1].Result != Pass ||
		checks[len(checks)-2].Result != Pass ||
		listParsed.Issuer != expectedIssuer {
		return verifiedStatusList{}, CodeStatusInvalid, nil
	}
	if validity := checkValidity(listParsed, now, v.clockSkew); validity.Result != Pass {
		return verifiedStatusList{}, CodeStatusInvalid, nil
	}
	if v.statusPolicy.RequireValidUntil && listParsed.ValidUntilAt == nil {
		return verifiedStatusList{}, CodeStatusInvalid, nil
	}
	if v.statusPolicy.MaxStaleness > 0 {
		if listParsed.ValidFromAt == nil || now.Sub(*listParsed.ValidFromAt) > v.statusPolicy.MaxStaleness {
			return verifiedStatusList{}, CodeStatusInvalid, nil
		}
	}

	compact, ok := decodeCompact(listJWS, v.limits.MaxJWSBytes, v.limits.MaxJSONDepth)
	if !ok || !hasType(compact.Payload["type"], "BitstringStatusListCredential") {
		return verifiedStatusList{}, CodeStatusInvalid, nil
	}
	subj, err := decodeStrictObject(compact.Payload["credentialSubject"], v.limits.MaxJSONDepth)
	if err != nil {
		return verifiedStatusList{}, CodeStatusInvalid, nil
	}
	subjType, _ := stringMember(subj, "type")
	purpose, _ := stringMember(subj, "statusPurpose")
	encoded, _ := stringMember(subj, "encodedList")
	if subjType != "BitstringStatusList" || (purpose != "revocation" && purpose != "suspension") {
		return verifiedStatusList{}, CodeStatusInvalid, nil
	}
	bits, bitsOK := decodeBitstringList(encoded)
	if !bitsOK {
		return verifiedStatusList{}, CodeStatusInvalid, nil
	}
	return verifiedStatusList{purpose: purpose, bits: bits}, "", nil
}

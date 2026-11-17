package issuance

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	// PurposeRevocation marks terminal revocation bitstring lists (HK-050).
	PurposeRevocation = "revocation"
	// PurposeSuspension marks reversible suspension bitstring lists (HK-050).
	PurposeSuspension = "suspension"

	// CredentialStatusActive, Suspended, and Revoked track desired/published states.
	CredentialStatusActive    = "active"
	CredentialStatusSuspended = "suspended"
	CredentialStatusRevoked   = "revoked"

	// BitstringListEntryType and BitstringListCredentialType match W3C Bitstring Status List v1.0.
	BitstringListEntryType      = "BitstringStatusListEntry"
	BitstringListCredentialType = "BitstringStatusListCredential"

	// DefaultStatusListSize is the bit capacity per list (2048 bytes -> ~35B gzipped).
	DefaultStatusListSize = 16384
	// DefaultStatusListTTL bounds status list freshness for verifiers.
	DefaultStatusListTTL = 1 * time.Hour

	maxStatusBitstringDecodedBytes = 1 << 20
)

var (
	// ErrInvalidStatusTransition rejects illegal lifecycle transitions (e.g. reactivating revoked credentials).
	ErrInvalidStatusTransition = errors.New("invalid status transition")
	// ErrStatusListFull indicates the configured bitstring capacity was exhausted.
	ErrStatusListFull = errors.New("status list capacity exhausted")
)

// CredentialStatusEntry embeds one W3C BitstringStatusListEntry inside a VC.
type CredentialStatusEntry struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"`
	StatusPurpose        string `json:"statusPurpose"`
	StatusListIndex      string `json:"statusListIndex"`
	StatusListCredential string `json:"statusListCredential"`
}

// StatusListRecord tracks one issuer-scoped bitstring status list.
type StatusListRecord struct {
	TenantID         string
	IssuerID         string
	ListID           string
	Purpose          string
	BitstringSize    int
	NextIndex        int
	RawBits          []byte
	Version          int64
	PublishedVersion int64
	PublishedJWT     string
	ValidFrom        time.Time
	ValidUntil       time.Time
	UpdatedAt        time.Time
}

// IssuedCredentialRecord tracks an issued credential's opaque handle and status slots without storing PII.
type IssuedCredentialRecord struct {
	CredentialID     string
	TenantID         string
	IssuerID         string
	RequestID        string
	ClientID         string
	SigningKID       string
	Digest           string
	RevocationListID string
	RevocationIndex  *int
	SuspensionListID string
	SuspensionIndex  *int
	DesiredStatus    string
	PublishedStatus  string
	StatusVersion    int64
	ReasonCode       string
	IssuedAt         time.Time
	SuspendedAt      *time.Time
	RevokedAt        *time.Time
}

// StatusChangeInput describes a suspend or revoke request (HK-050).
type StatusChangeInput struct {
	ReasonCode string `json:"reasonCode,omitempty"`
	Comment    string `json:"comment,omitempty"`
}

// StatusChangeResult describes the accepted/published state after a status transition.
type StatusChangeResult struct {
	CredentialID      string    `json:"credentialId"`
	State             string    `json:"state"`
	DesiredStatus     string    `json:"desiredStatus"`
	PublishedStatus   string    `json:"publishedStatus"`
	StatusListVersion int64     `json:"statusListVersion"`
	PropagationState  string    `json:"propagationState"`
	EffectiveAt       time.Time `json:"effectiveAt"`
}

// EncodeBitstring GZIP-compresses bits and encodes as W3C multibase base64url ("u...").
func EncodeBitstring(bits []byte) (string, error) {
	if len(bits) == 0 {
		return "", ErrInvalidRequest
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := zw.Write(bits); err != nil {
		_ = zw.Close()
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return "u" + base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// DecodeBitstring decodes a W3C multibase base64url gzipped bitstring ("u...").
func DecodeBitstring(encoded string) ([]byte, error) {
	if len(encoded) < 2 || encoded[0] != 'u' {
		return nil, ErrInvalidRequest
	}
	compressed, err := base64.RawURLEncoding.DecodeString(encoded[1:])
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	bits, err := io.ReadAll(io.LimitReader(zr, maxStatusBitstringDecodedBytes+1))
	if err != nil || len(bits) > maxStatusBitstringDecodedBytes || len(bits) == 0 {
		return nil, ErrInvalidRequest
	}
	return bits, nil
}

// SetBitstringBit sets bit at zero-based index (MSB-first within each byte per W3C v1.0).
func SetBitstringBit(bits []byte, index int, active bool) error {
	byteIdx := index / 8
	if index < 0 || byteIdx >= len(bits) {
		return ErrInvalidRequest
	}
	mask := byte(1 << (7 - uint(index%8)))
	if active {
		bits[byteIdx] |= mask
	} else {
		bits[byteIdx] &^= mask
	}
	return nil
}

// GetBitstringBit reads bit at zero-based index (MSB-first per W3C v1.0).
func GetBitstringBit(bits []byte, index int) (bool, error) {
	byteIdx := index / 8
	if index < 0 || byteIdx >= len(bits) {
		return false, ErrInvalidRequest
	}
	mask := byte(1 << (7 - uint(index%8)))
	return (bits[byteIdx] & mask) != 0, nil
}

// BuildStatusListURL returns the canonical credentialStatus list URL.
func BuildStatusListURL(issuerURI, purpose, listID string) string {
	return strings.TrimRight(issuerURI, "/") + "/status/" + purpose + "/" + listID
}

// BuildCredentialStatusEntry creates a W3C BitstringStatusListEntry object.
func BuildCredentialStatusEntry(issuerURI, purpose, listID string, index int) CredentialStatusEntry {
	listURL := BuildStatusListURL(issuerURI, purpose, listID)
	idx := strconv.Itoa(index)
	return CredentialStatusEntry{
		ID:                   listURL + "#" + idx,
		Type:                 BitstringListEntryType,
		StatusPurpose:        purpose,
		StatusListIndex:      idx,
		StatusListCredential: listURL,
	}
}

// IssueStatusListVC signs a BitstringStatusListCredential as application/vc+jwt using signer.
func IssueStatusListVC(signer Signer, listID, purpose string, rawBits []byte, validFrom, validUntil time.Time) (string, error) {
	if signer == nil || listID == "" || (purpose != PurposeRevocation && purpose != PurposeSuspension) {
		return "", ErrInvalidCredentialInput
	}
	if validFrom.IsZero() || !validFrom.UTC().Before(validUntil.UTC()) {
		return "", ErrInvalidCredentialInput
	}
	encoded, err := EncodeBitstring(rawBits)
	if err != nil {
		return "", err
	}
	listURL := BuildStatusListURL(signer.Issuer(), purpose, listID)
	payload := map[string]any{
		"@context":   []string{VCDMBaseContext},
		"id":         listURL,
		"type":       []string{"VerifiableCredential", BitstringListCredentialType},
		"issuer":     signer.Issuer(),
		"validFrom":  validFrom.UTC().Format(time.RFC3339),
		"validUntil": validUntil.UTC().Format(time.RFC3339),
		"credentialSubject": map[string]any{
			"id":            listURL + "#list",
			"type":          "BitstringStatusList",
			"statusPurpose": purpose,
			"encodedList":   encoded,
		},
	}
	return signCompactVC(signer, payload)
}

func isValidStatusPurpose(p string) bool {
	return p == PurposeRevocation || p == PurposeSuspension
}

func sortStatusPurposes(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

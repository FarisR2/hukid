package issuance

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"
	"time"

	"hukid.local/platform/internal/verification"
)

const (
	// ProofJWTType is the mandatory JOSE typ header for OpenID4VCI key proofs (§7.3).
	ProofJWTType = "openid4vci-proof+jwt"

	// DefaultProofSkew bounds clock drift when validating proof iat.
	DefaultProofSkew = time.Minute

	// MaxProofAge limits how old an issued proof JWT can be.
	MaxProofAge = 5 * time.Minute

	maxProofBytes = 16 * 1024
	maxJSONDepth  = 8
)

var (
	// ErrProofInvalid indicates any structural, cryptographic or binding failure
	// in an OpenID4VCI holder proof JWT.
	ErrProofInvalid = errors.New("holder proof invalid")
)

// VerifyHolderProof validates an OpenID4VCI ES256 proof JWT against the expected
// issuer audience and c_nonce, returning the RFC 7638 JWK thumbprint (cnf.jkt)
// and parsed P-256 public key of the holder wallet.
func VerifyHolderProof(proofJWT, expectedIssuer, expectedNonce string, now time.Time, skew time.Duration) (string, *ecdsa.PublicKey, error) {
	if expectedIssuer == "" || expectedNonce == "" || skew < 0 {
		return "", nil, ErrProofInvalid
	}
	if len(proofJWT) == 0 || len(proofJWT) > maxProofBytes {
		return "", nil, ErrProofInvalid
	}
	parts := strings.Split(proofJWT, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", nil, ErrProofInvalid
	}
	headerRaw, errH := base64.RawURLEncoding.DecodeString(parts[0])
	payloadRaw, errP := base64.RawURLEncoding.DecodeString(parts[1])
	sig, errS := base64.RawURLEncoding.DecodeString(parts[2])
	if errH != nil || errP != nil || errS != nil || len(sig) != 64 {
		return "", nil, ErrProofInvalid
	}

	header, err := decodeStrictObject(headerRaw, maxJSONDepth)
	if err != nil {
		return "", nil, ErrProofInvalid
	}
	payload, err := decodeStrictObject(payloadRaw, maxJSONDepth)
	if err != nil {
		return "", nil, ErrProofInvalid
	}

	if alg, ok := stringMember(header, "alg"); !ok || alg != "ES256" {
		return "", nil, ErrProofInvalid
	}
	if typ, ok := stringMember(header, "typ"); !ok || typ != ProofJWTType {
		return "", nil, ErrProofInvalid
	}
	holderKey, ok := parsePublicECJWK(header["jwk"], maxJSONDepth)
	if !ok {
		return "", nil, ErrProofInvalid
	}

	signingInput := parts[0] + "." + parts[1]
	if !verifyES256Raw(holderKey, signingInput, sig) {
		return "", nil, ErrProofInvalid
	}

	aud, okAud := stringMember(payload, "aud")
	nonce, okNonce := stringMember(payload, "nonce")
	if !okAud || !okNonce ||
		!constantTimeEqual(aud, expectedIssuer) ||
		!constantTimeEqual(nonce, expectedNonce) {
		return "", nil, ErrProofInvalid
	}

	iatSec, okIAT := int64Member(payload, "iat")
	if !okIAT {
		return "", nil, ErrProofInvalid
	}
	issuedAt := time.Unix(iatSec, 0).UTC()
	nowUTC := now.UTC()
	earliest := nowUTC.Add(-MaxProofAge - skew)
	latest := nowUTC.Add(skew)
	if issuedAt.Before(earliest) || issuedAt.After(latest) {
		return "", nil, ErrProofInvalid
	}

	jkt, err := verification.JWKThumbprint(holderKey)
	if err != nil {
		return "", nil, ErrProofInvalid
	}
	return jkt, holderKey, nil
}

// BuildHolderProof constructs and signs an OpenID4VCI proof JWT for laboratory
// tests using a P-256 holder key.
func BuildHolderProof(holderKey *ecdsa.PrivateKey, issuer, nonce string, issuedAt time.Time, random io.Reader) (string, error) {
	if holderKey == nil || holderKey.Curve != elliptic.P256() || !holderKey.Curve.IsOnCurve(holderKey.X, holderKey.Y) || holderKey.D == nil {
		return "", ErrProofInvalid
	}
	if issuer == "" || nonce == "" {
		return "", ErrProofInvalid
	}
	if random == nil {
		random = rand.Reader
	}
	jwk, err := ExportPublicJWK(&holderKey.PublicKey, "")
	if err != nil {
		return "", ErrProofInvalid
	}
	header := map[string]any{
		"alg": "ES256",
		"typ": ProofJWTType,
		"jwk": jwk,
	}
	payload := map[string]any{
		"aud":   issuer,
		"nonce": nonce,
		"iat":   issuedAt.UTC().Unix(),
	}
	hBytes, err := json.Marshal(header)
	if err != nil {
		return "", ErrProofInvalid
	}
	pBytes, err := json.Marshal(payload)
	if err != nil {
		return "", ErrProofInvalid
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hBytes) + "." + base64.RawURLEncoding.EncodeToString(pBytes)
	digest := sha256.Sum256([]byte(signingInput))
	der, err := ecdsa.SignASN1(random, holderKey, digest[:])
	if err != nil {
		return "", ErrProofInvalid
	}
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &sig); err != nil || len(rest) != 0 {
		return "", ErrProofInvalid
	}
	rawSig := make([]byte, 64)
	sig.R.FillBytes(rawSig[:32])
	sig.S.FillBytes(rawSig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(rawSig), nil
}

func verifyES256Raw(key *ecdsa.PublicKey, signingInput string, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if r.Sign() == 0 || s.Sign() == 0 {
		return false
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(signingInput))
	return ecdsa.VerifyASN1(key, digest[:], der)
}

func parsePublicECJWK(raw json.RawMessage, maxDepth int) (*ecdsa.PublicKey, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	object, err := decodeStrictObject(raw, maxDepth)
	if err != nil {
		return nil, false
	}
	for _, priv := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, found := object[priv]; found {
			return nil, false
		}
	}
	kty, okKty := stringMember(object, "kty")
	crv, okCrv := stringMember(object, "crv")
	xStr, okX := stringMember(object, "x")
	yStr, okY := stringMember(object, "y")
	if !okKty || !okCrv || !okX || !okY || kty != "EC" || crv != "P-256" {
		return nil, false
	}
	xBytes, errX := base64.RawURLEncoding.DecodeString(xStr)
	yBytes, errY := base64.RawURLEncoding.DecodeString(yStr)
	if errX != nil || errY != nil || len(xBytes) != 32 || len(yBytes) != 32 {
		return nil, false
	}
	encoded := make([]byte, 65)
	encoded[0] = 0x04
	copy(encoded[1:33], xBytes)
	copy(encoded[33:65], yBytes)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
	if err != nil {
		return nil, false
	}
	return pub, true
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func stringMember(object map[string]json.RawMessage, name string) (string, bool) {
	raw, present := object[name]
	if !present {
		return "", false
	}
	var val string
	if err := json.Unmarshal(raw, &val); err != nil {
		return "", false
	}
	return val, true
}

func int64Member(object map[string]json.RawMessage, name string) (int64, bool) {
	raw, present := object[name]
	if !present {
		return 0, false
	}
	var val int64
	if err := json.Unmarshal(raw, &val); err != nil {
		return 0, false
	}
	return val, true
}

type strictJSONError string

func (e strictJSONError) Error() string { return string(e) }

func decodeStrictObject(raw []byte, maxDepth int) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	type frame struct {
		isObject  bool
		keys      map[string]bool
		expectKey bool
	}
	var stack []frame
	first := true
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if first {
			if delim, ok := token.(json.Delim); !ok || delim != '{' {
				return nil, strictJSONError("top level is not an object")
			}
			first = false
		}
		delim, isDelim := token.(json.Delim)
		if isDelim && (delim == '}' || delim == ']') {
			stack = stack[:len(stack)-1]
			if len(stack) > 0 && stack[len(stack)-1].isObject {
				stack[len(stack)-1].expectKey = true
			}
			continue
		}
		if len(stack) > 0 && stack[len(stack)-1].isObject && stack[len(stack)-1].expectKey {
			key, ok := token.(string)
			if !ok {
				return nil, strictJSONError("object key is not a string")
			}
			top := &stack[len(stack)-1]
			if top.keys[key] {
				return nil, strictJSONError("duplicate object member")
			}
			top.keys[key] = true
			top.expectKey = false
			continue
		}
		if isDelim {
			if len(stack) >= maxDepth {
				return nil, strictJSONError("nesting too deep")
			}
			stack = append(stack, frame{isObject: delim == '{', keys: map[string]bool{}, expectKey: delim == '{'})
			continue
		}
		if len(stack) > 0 && stack[len(stack)-1].isObject {
			stack[len(stack)-1].expectKey = true
		}
	}
	if len(stack) != 0 {
		return nil, strictJSONError("unterminated JSON")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, strictJSONError("not a JSON object")
	}
	return object, nil
}

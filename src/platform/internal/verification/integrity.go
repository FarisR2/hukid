package verification

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// checkIssuerKey resolves the verification key. Key-bearing headers supplied
// by the credential are rejected before any lookup (profile section 3).
// A nil key accompanies every failed check. A resolver failure other than
// ErrKeyNotFound is returned as an error: it says nothing about the credential.
func checkIssuerKey(parsed *ParsedCredential, keys IssuerKeyResolver) (*ecdsa.PublicKey, Check, error) {
	if len(parsed.UntrustedKeyHeaders) > 0 {
		return nil, Failed(CheckIssuerKey, CodeKeyUntrustedHeader), nil
	}
	resolved, err := keys.ResolveKey(parsed.Issuer, parsed.KID)
	if errors.Is(err, ErrKeyNotFound) {
		return nil, Failed(CheckIssuerKey, CodeKeyUnknownKID), nil
	}
	if err != nil {
		return nil, Check{}, fmt.Errorf("%w: %v", ErrKeyResolution, err)
	}
	if resolved.Key == nil {
		return nil, Check{}, fmt.Errorf("%w: resolver returned no key", ErrKeyResolution)
	}
	if resolved.Issuer != parsed.Issuer {
		return nil, Failed(CheckIssuerKey, CodeKeyIssuerMismatch), nil
	}
	return resolved.Key, Passed(CheckIssuerKey, true), nil
}

// checkSignature verifies the raw ES256 (r||s) signature over the signing input.
func checkSignature(parsed *ParsedCredential, key *ecdsa.PublicKey) Check {
	return checkES256(parsed.SigningInput, parsed.Signature, key)
}

// checkES256 verifies a raw ES256 (r||s) JWS signature. It is shared by the
// credential and the presentation, whose key comes from different sources.
func checkES256(signingInput string, signature []byte, key *ecdsa.PublicKey) Check {
	if len(signature) != 64 {
		return Failed(CheckSignature, CodeSignatureInvalid)
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if r.Sign() == 0 || s.Sign() == 0 {
		return Failed(CheckSignature, CodeSignatureInvalid)
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return Failed(CheckSignature, CodeSignatureInvalid)
	}
	digest := sha256.Sum256([]byte(signingInput))
	if !ecdsa.VerifyASN1(key, digest[:], der) {
		return Failed(CheckSignature, CodeSignatureInvalid)
	}
	return Passed(CheckSignature, true)
}

// integrityChecks runs format, issuerKey and signature in order. When a check
// fails, the later ones are reported as skipped because their precondition
// failed; a skipped required check never counts as a pass. The parsed
// credential is returned when the format check passed.
func integrityChecks(jws string, limits Limits, keys IssuerKeyResolver) (*ParsedCredential, []Check, error) {
	parsed, format := ParseCredential(jws, limits)
	if format.Result != Pass {
		return nil, []Check{
			format,
			SkippedCheck(CheckIssuerKey, CodeSkippedPrecondition, true),
			SkippedCheck(CheckSignature, CodeSkippedPrecondition, true),
		}, nil
	}
	key, keyCheck, err := checkIssuerKey(parsed, keys)
	if err != nil {
		return parsed, nil, err
	}
	if keyCheck.Result != Pass {
		return parsed, []Check{format, keyCheck, SkippedCheck(CheckSignature, CodeSkippedPrecondition, true)}, nil
	}
	return parsed, []Check{format, keyCheck, checkSignature(parsed, key)}, nil
}

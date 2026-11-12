package verification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	presentationContext = "https://schemas.hukid.pe/contexts/presentation/v1"
	envelopedVCPrefix   = "data:application/vc+jwt,"
)

// presentationContexts are the only JSON-LD contexts a presentation may use.
var presentationContexts = []string{vcdmBaseContext, presentationContext}

// Request is what the verifier expects from the wallet's response.
type Request struct {
	Audience string
	Nonce    string
	State    string
}

// Response is what the wallet sent. State travels as a response parameter of
// the OpenID4VP authorization response, not inside the VP; audience and nonce
// are inside the VP (profile section 9.6).
type Response struct {
	VP    string
	State string
}

// PresentationReport carries the presentation-level checks (format, signature,
// requestBinding, holderBinding) and one full report per enveloped credential.
// Like Report, it holds a digest and codes only.
type PresentationReport struct {
	CodesVersion    int             `json:"codesVersion"`
	Checks          []Check         `json:"checks"`
	Credentials     []Report        `json:"credentials"`
	TechnicalResult TechnicalResult `json:"technicalResult"`
	Trust           *Trust          `json:"trust,omitempty"`
	Digest          string          `json:"digest"`
}

// WithTrust returns a copy carrying the trust decision; the technical result
// is unchanged by design.
func (r PresentationReport) WithTrust(d Decision) PresentationReport {
	r.Trust = &Trust{Decision: d}
	return r
}

// JWKThumbprint returns the RFC 7638 thumbprint of a P-256 public key, the
// value HukID binds to a credential as cnf.jkt (profile section 4.1).
func JWKThumbprint(key *ecdsa.PublicKey) (string, error) {
	raw, err := key.Bytes()
	if err != nil || len(raw) != 65 {
		return "", fmt.Errorf("unsupported public key")
	}
	enc := base64.RawURLEncoding
	canonical := `{"crv":"P-256","kty":"EC","x":"` + enc.EncodeToString(raw[1:33]) + `","y":"` + enc.EncodeToString(raw[33:65]) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return enc.EncodeToString(sum[:]), nil
}

// parsedPresentation is a structurally valid vp+jwt.
type parsedPresentation struct {
	SigningInput string
	Signature    []byte
	HolderKey    *ecdsa.PublicKey
	Audience     string
	Nonce        string
	Credentials  []string
}

// parsePresentation applies the format rules the profile gives for a
// presentation: compact JWS with alg ES256 and typ vp+jwt, the holder's public
// JWK in the header, a VCDM 2.0 presentation whose credentials are enveloped
// as data:application/vc+jwt URLs. The exact payload layout is inferred from
// profile sections 2.3, 2.5 and 9.6: the reference example
// (vp-jwt-structure.json) is not part of this repository. A holder kid that
// resolves elsewhere is not supported: the header must carry the JWK.
func parsePresentation(vp string, limits Limits) (*parsedPresentation, Code) {
	compact, ok := decodeCompact(vp, limits.MaxPresentationBytes, limits.MaxJSONDepth)
	if !ok {
		return nil, CodeFormatMalformed
	}
	if alg, ok := stringMember(compact.Header, "alg"); !ok || alg != "ES256" {
		return nil, CodeFormatHeaderAlg
	}
	if typ, ok := stringMember(compact.Header, "typ"); !ok || typ != "vp+jwt" {
		return nil, CodeFormatHeaderTyp
	}
	key, ok := holderKeyFromHeader(compact.Header, limits.MaxJSONDepth)
	if !ok {
		return nil, CodeFormatMalformed
	}
	payload := compact.Payload
	if !hasBaseContext(payload["@context"]) || !hasType(payload["type"], "VerifiablePresentation") {
		return nil, CodeFormatMalformed
	}
	if !contextsAllowed(payload["@context"], presentationContexts) {
		return nil, CodeFormatContextNotAllowed
	}
	var entries []json.RawMessage
	if json.Unmarshal(payload["verifiableCredential"], &entries) != nil || len(entries) == 0 || len(entries) > limits.MaxCredentials {
		return nil, CodeFormatMalformed
	}
	credentials := make([]string, 0, len(entries))
	for _, entry := range entries {
		object, err := decodeStrictObject(entry, limits.MaxJSONDepth)
		if err != nil || !hasType(object["type"], "EnvelopedVerifiableCredential") {
			return nil, CodeFormatMalformed
		}
		if raw, present := object["@context"]; present {
			if value, isString := stringValue(raw); !isString || value != vcdmBaseContext {
				return nil, CodeFormatContextNotAllowed
			}
		}
		id, ok := stringMember(object, "id")
		if !ok || !strings.HasPrefix(id, envelopedVCPrefix) || len(id) == len(envelopedVCPrefix) {
			return nil, CodeFormatMalformed
		}
		credentials = append(credentials, strings.TrimPrefix(id, envelopedVCPrefix))
	}
	// aud and nonce are compared by the requestBinding check; a missing or
	// non-text value simply cannot match.
	audience, _ := stringMember(payload, "aud")
	nonce, _ := stringMember(payload, "nonce")
	return &parsedPresentation{
		SigningInput: compact.SigningInput,
		Signature:    compact.Signature,
		HolderKey:    key,
		Audience:     audience,
		Nonce:        nonce,
		Credentials:  credentials,
	}, ""
}

// holderKeyFromHeader reads a public P-256 JWK from the JOSE header. A JWK
// carrying private members, another curve or an invalid point is rejected.
func holderKeyFromHeader(header map[string]json.RawMessage, maxDepth int) (*ecdsa.PublicKey, bool) {
	raw, present := header["jwk"]
	if !present {
		return nil, false
	}
	object, err := decodeStrictObject(raw, maxDepth)
	if err != nil {
		return nil, false
	}
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, found := object[private]; found {
			return nil, false
		}
	}
	kty, _ := stringMember(object, "kty")
	crv, _ := stringMember(object, "crv")
	xs, _ := stringMember(object, "x")
	ys, _ := stringMember(object, "y")
	x, errX := base64.RawURLEncoding.DecodeString(xs)
	y, errY := base64.RawURLEncoding.DecodeString(ys)
	if kty != "EC" || crv != "P-256" || errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
		return nil, false
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		return nil, false
	}
	return key, true
}

// constantTimeEqual compares two strings without an early exit on content.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// VerifyPresentation checks a vp+jwt against the request it answers and
// verifies every enveloped credential. Order matters and is part of the
// contract: format, holder signature, request binding (audience, nonce, state),
// replay, then holder binding and the credentials. A request is consumed only
// after the response matched it and carried a valid holder signature, so an
// unauthenticated sender cannot burn a legitimate request. The error is non-nil
// only for a failure of the resolver or the replay store.
func (v *Verifier) VerifyPresentation(resp Response, req Request) (PresentationReport, error) {
	if v.replay == nil {
		return PresentationReport{}, fmt.Errorf("%w: no replay store", ErrConfig)
	}
	skip := func(name CheckName) Check { return SkippedCheck(name, CodeSkippedPrecondition, true) }
	finish := func(checks []Check, credentials []Report) PresentationReport {
		result := technicalResult(checks)
		for _, c := range credentials {
			if c.TechnicalResult != Valid {
				result = Invalid
			}
		}
		report := PresentationReport{CodesVersion: CodesVersion, Checks: checks, Credentials: append([]Report{}, credentials...), TechnicalResult: result, Digest: Digest([]byte(resp.VP))}
		if v.trust != nil {
			report = report.WithTrust(aggregateTrust(credentials))
		}
		return report
	}

	parsed, code := parsePresentation(resp.VP, v.limits)
	if parsed == nil {
		return finish([]Check{Failed(CheckFormat, code), skip(CheckSignature), skip(CheckRequestBinding), skip(CheckHolderBinding)}, nil), nil
	}
	format := Passed(CheckFormat, true)

	signature := checkES256(parsed.SigningInput, parsed.Signature, parsed.HolderKey)
	if signature.Result != Pass {
		return finish([]Check{format, signature, skip(CheckRequestBinding), skip(CheckHolderBinding)}, nil), nil
	}

	if code := matchRequest(parsed, resp.State, req); code != "" {
		return finish([]Check{format, signature, Failed(CheckRequestBinding, code), skip(CheckHolderBinding)}, nil), nil
	}
	first, err := v.replay.Consume(Digest([]byte(parsed.Nonce + "\x00" + resp.State)))
	if err != nil {
		return PresentationReport{}, fmt.Errorf("%w: %v", ErrReplayStore, err)
	}
	if !first {
		return finish([]Check{format, signature, Failed(CheckRequestBinding, CodeRequestReplayed), skip(CheckHolderBinding)}, nil), nil
	}
	binding := Passed(CheckRequestBinding, true)

	thumbprint, err := JWKThumbprint(parsed.HolderKey)
	if err != nil {
		return finish([]Check{format, signature, binding, skip(CheckHolderBinding)}, nil), nil
	}
	reports := make([]Report, 0, len(parsed.Credentials))
	holder := Passed(CheckHolderBinding, true)
	unparsable := false
	for _, jws := range parsed.Credentials {
		report, err := v.Verify(jws)
		if err != nil {
			return PresentationReport{}, err
		}
		reports = append(reports, report)
		credential, check := ParseCredential(jws, v.limits)
		switch {
		case check.Result != Pass:
			unparsable = true
		case holder.Result == Pass && credential.CNFJKT == "":
			holder = Failed(CheckHolderBinding, CodeBindingMissingCNF)
		case holder.Result == Pass && !constantTimeEqual(thumbprint, credential.CNFJKT):
			holder = Failed(CheckHolderBinding, CodeBindingMismatch)
		}
	}
	if holder.Result == Pass && unparsable {
		holder = skip(CheckHolderBinding)
	}
	return finish([]Check{format, signature, binding, holder}, reports), nil
}

// matchRequest compares the response with the request in constant time and
// returns the code of the first mismatch, or "" when all three match. A
// missing value cannot match a non-empty expectation.
func matchRequest(parsed *parsedPresentation, state string, req Request) Code {
	switch {
	case req.Audience == "" || !constantTimeEqual(parsed.Audience, req.Audience):
		return CodeRequestAudience
	case req.Nonce == "" || !constantTimeEqual(parsed.Nonce, req.Nonce):
		return CodeRequestNonce
	case req.State == "" || !constantTimeEqual(state, req.State):
		return CodeRequestState
	}
	return ""
}

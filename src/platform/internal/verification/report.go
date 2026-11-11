// Package verification defines the technical verification contract for HukID
// credentials: a structured report with one check per criterion and a closed,
// versioned set of failure codes. It performs no network or database access.
package verification

import (
	"crypto/sha256"
	"encoding/hex"
)

// CodesVersion identifies the closed failure-code set. Adding or renaming a
// code requires a new version.
const CodesVersion = 1

// CheckName identifies one verification criterion.
type CheckName string

const (
	CheckFormat         CheckName = "format"
	CheckIssuerKey      CheckName = "issuerKey"
	CheckSignature      CheckName = "signature"
	CheckValidity       CheckName = "validity"
	CheckHolderBinding  CheckName = "holderBinding"
	CheckRequestBinding CheckName = "requestBinding"
	CheckStatus         CheckName = "status"
	CheckSchema         CheckName = "schema"
)

// Result is the outcome of one check. Skipped is never a pass.
type Result string

const (
	Pass    Result = "pass"
	Fail    Result = "fail"
	Skipped Result = "skipped"
)

// Code is a stable failure or skip reason. Codes carry no claims and no
// credential material.
type Code string

const (
	CodeFormatMalformed       Code = "format.malformed"
	CodeFormatHeaderAlg       Code = "format.header.alg"
	CodeFormatHeaderTyp       Code = "format.header.typ"
	CodeFormatVCContainer     Code = "format.payload.vc_container"
	CodeFormatDuplicateClaim  Code = "format.payload.duplicate_claim"
	CodeKeyUntrustedHeader    Code = "key.untrusted_header"
	CodeKeyUnknownKID         Code = "key.unknown_kid"
	CodeKeyIssuerMismatch     Code = "key.issuer_mismatch"
	CodeSignatureInvalid      Code = "signature.invalid"
	CodeValidityNotYetValid   Code = "validity.not_yet_valid"
	CodeValidityExpired       Code = "validity.expired"
	CodeBindingMissingCNF     Code = "binding.missing_cnf"
	CodeBindingMismatch       Code = "binding.mismatch"
	CodeRequestAudience       Code = "request.audience_mismatch"
	CodeRequestNonce          Code = "request.nonce_mismatch"
	CodeRequestState          Code = "request.state_mismatch"
	CodeRequestReplayed       Code = "request.replayed"
	CodeSkippedNotDeclared    Code = "skipped.not_declared"
	CodeSkippedNotImplemented Code = "skipped.not_implemented"
	CodeSkippedPrecondition   Code = "skipped.precondition_failed"
)

var failureCodes = map[CheckName][]Code{
	CheckFormat:         {CodeFormatMalformed, CodeFormatHeaderAlg, CodeFormatHeaderTyp, CodeFormatVCContainer, CodeFormatDuplicateClaim},
	CheckIssuerKey:      {CodeKeyUntrustedHeader, CodeKeyUnknownKID, CodeKeyIssuerMismatch},
	CheckSignature:      {CodeSignatureInvalid},
	CheckValidity:       {CodeValidityNotYetValid, CodeValidityExpired},
	CheckHolderBinding:  {CodeBindingMissingCNF, CodeBindingMismatch},
	CheckRequestBinding: {CodeRequestAudience, CodeRequestNonce, CodeRequestState, CodeRequestReplayed},
}

var skipCodes = []Code{CodeSkippedNotDeclared, CodeSkippedNotImplemented, CodeSkippedPrecondition}

// AllCodes returns every code of the closed set, in a stable order.
func AllCodes() []Code {
	var out []Code
	for _, name := range []CheckName{CheckFormat, CheckIssuerKey, CheckSignature, CheckValidity, CheckHolderBinding, CheckRequestBinding} {
		out = append(out, failureCodes[name]...)
	}
	return append(out, skipCodes...)
}

// IsKnown reports whether c belongs to the closed set.
func IsKnown(c Code) bool {
	for _, known := range AllCodes() {
		if c == known {
			return true
		}
	}
	return false
}

// Check is the outcome of one criterion. Required marks criteria the
// verification must pass for the technical result to be valid.
type Check struct {
	Name     CheckName `json:"name"`
	Result   Result    `json:"result"`
	Code     Code      `json:"code,omitempty"`
	Required bool      `json:"required"`
}

// Decision is the trust-policy outcome, kept apart from the technical result.
type Decision string

const (
	Trusted      Decision = "trusted"
	Untrusted    Decision = "untrusted"
	NotEvaluated Decision = "notEvaluated"
)

// Trust is the optional trust-policy result. It never changes TechnicalResult.
type Trust struct {
	Decision Decision `json:"decision"`
}

// TechnicalResult is derived only from the checks.
type TechnicalResult string

const (
	Valid   TechnicalResult = "valid"
	Invalid TechnicalResult = "invalid"
)

// Report is the structured outcome of one verification. It holds a digest and
// codes only: never the JWS, the vp_token or any claim.
type Report struct {
	CodesVersion    int             `json:"codesVersion"`
	Checks          []Check         `json:"checks"`
	TechnicalResult TechnicalResult `json:"technicalResult"`
	Trust           *Trust          `json:"trust,omitempty"`
	Digest          string          `json:"digest"`
}

// NewReport builds a report from checks and the verified input. The technical
// result is valid only when there is at least one check, no check failed, and
// every required check passed. A skipped required check makes it invalid.
func NewReport(input []byte, checks []Check) Report {
	return Report{
		CodesVersion:    CodesVersion,
		Checks:          append([]Check(nil), checks...),
		TechnicalResult: technicalResult(checks),
		Digest:          Digest(input),
	}
}

// WithTrust returns a copy carrying the trust decision. The technical result
// is unchanged by design.
func (r Report) WithTrust(d Decision) Report {
	r.Trust = &Trust{Decision: d}
	return r
}

func technicalResult(checks []Check) TechnicalResult {
	if len(checks) == 0 {
		return Invalid
	}
	for _, c := range checks {
		if c.Result == Fail {
			return Invalid
		}
		if c.Required && c.Result != Pass {
			return Invalid
		}
	}
	return Valid
}

// Digest returns "sha256:" followed by the lowercase hex SHA-256 of input.
func Digest(input []byte) string {
	sum := sha256.Sum256(input)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Passed builds a passing check.
func Passed(name CheckName, required bool) Check {
	return Check{Name: name, Result: Pass, Required: required}
}

// Failed builds a failing check. It panics if code is not a failure code of
// name: a programming error, never a runtime input condition.
func Failed(name CheckName, code Code) Check {
	for _, allowed := range failureCodes[name] {
		if code == allowed {
			return Check{Name: name, Result: Fail, Code: code, Required: true}
		}
	}
	panic("verification: code " + string(code) + " is not a failure code of check " + string(name))
}

// SkippedCheck builds a skipped check with a skip code. It panics on an
// unknown skip code.
func SkippedCheck(name CheckName, code Code, required bool) Check {
	for _, allowed := range skipCodes {
		if code == allowed {
			return Check{Name: name, Result: Skipped, Code: code, Required: required}
		}
	}
	panic("verification: code " + string(code) + " is not a skip code")
}

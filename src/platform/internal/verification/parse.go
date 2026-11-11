package verification

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
)

const vcdmBaseContext = "https://www.w3.org/ns/credentials/v2"

// Limits bound the input before any cryptographic work. The values are a
// proposal of FEAT-004 (VER-QR05), not a profile requirement.
type Limits struct {
	MaxJWSBytes  int
	MaxJSONDepth int
}

// DefaultLimits are the proposed defaults: 16 KiB per compact JWS and 8 levels
// of JSON nesting.
var DefaultLimits = Limits{MaxJWSBytes: 16 * 1024, MaxJSONDepth: 8}

// ParsedCredential is the structurally valid content of a vc+jwt. It is the
// input of the later checks: key resolution, signature, validity and binding.
type ParsedCredential struct {
	SigningInput string
	Signature    []byte
	KID          string
	Issuer       string
	ValidFrom    string
	ValidUntil   string
	CNFJKT       string
	// UntrustedKeyHeaders lists key-bearing JOSE headers supplied by the
	// credential itself (jku, jwk, x5u, x5c). The profile forbids using them;
	// the issuerKey check rejects the credential when this is not empty.
	UntrustedKeyHeaders []string
}

var untrustedKeyHeaders = []string{"jku", "jwk", "x5u", "x5c"}

// ParseCredential checks the format rules of the HukID profile §2 for a
// compact vc+jwt and returns the parsed credential with the format check.
// On failure the parsed credential is nil. It never verifies the signature.
func ParseCredential(jws string, limits Limits) (*ParsedCredential, Check) {
	fail := func(code Code) (*ParsedCredential, Check) { return nil, Failed(CheckFormat, code) }

	if len(jws) == 0 || len(jws) > limits.MaxJWSBytes {
		return fail(CodeFormatMalformed)
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return fail(CodeFormatMalformed)
	}
	headerRaw, errH := base64.RawURLEncoding.DecodeString(parts[0])
	payloadRaw, errP := base64.RawURLEncoding.DecodeString(parts[1])
	signature, errS := base64.RawURLEncoding.DecodeString(parts[2])
	if errH != nil || errP != nil || errS != nil {
		return fail(CodeFormatMalformed)
	}
	header, err := decodeStrictObject(headerRaw, limits.MaxJSONDepth)
	if err != nil {
		return fail(CodeFormatMalformed)
	}
	payload, err := decodeStrictObject(payloadRaw, limits.MaxJSONDepth)
	if err != nil {
		return fail(CodeFormatMalformed)
	}

	if alg, ok := stringMember(header, "alg"); !ok || alg != "ES256" {
		return fail(CodeFormatHeaderAlg)
	}
	if typ, ok := stringMember(header, "typ"); !ok || typ != "vc+jwt" {
		return fail(CodeFormatHeaderTyp)
	}
	kid, ok := stringMember(header, "kid")
	if !ok || kid == "" {
		return fail(CodeFormatMalformed)
	}

	if _, present := payload["vc"]; present {
		return fail(CodeFormatVCContainer)
	}
	for _, registered := range []string{"iss", "nbf", "sub"} {
		if _, present := payload[registered]; present {
			return fail(CodeFormatDuplicateClaim)
		}
	}
	issuer, ok := stringMember(payload, "issuer")
	if !ok || issuer == "" || !hasBaseContext(payload["@context"]) || !hasType(payload["type"], "VerifiableCredential") {
		return fail(CodeFormatMalformed)
	}

	parsed := &ParsedCredential{
		SigningInput: parts[0] + "." + parts[1],
		Signature:    signature,
		KID:          kid,
		Issuer:       issuer,
	}
	for _, name := range untrustedKeyHeaders {
		if _, present := header[name]; present {
			parsed.UntrustedKeyHeaders = append(parsed.UntrustedKeyHeaders, name)
		}
	}
	// Optional members must have the right JSON type when present; their
	// values are interpreted by later checks.
	for name, target := range map[string]*string{"validFrom": &parsed.ValidFrom, "validUntil": &parsed.ValidUntil} {
		if raw, present := payload[name]; present {
			value, isString := stringValue(raw)
			if !isString {
				return fail(CodeFormatMalformed)
			}
			*target = value
		}
	}
	if raw, present := payload["cnf"]; present {
		cnf, err := decodeStrictObject(raw, limits.MaxJSONDepth)
		if err != nil {
			return fail(CodeFormatMalformed)
		}
		if raw, present := cnf["jkt"]; present {
			value, isString := stringValue(raw)
			if !isString {
				return fail(CodeFormatMalformed)
			}
			parsed.CNFJKT = value
		}
	}
	return parsed, Passed(CheckFormat, true)
}

func stringMember(object map[string]json.RawMessage, name string) (string, bool) {
	raw, present := object[name]
	if !present {
		return "", false
	}
	return stringValue(raw)
}

func stringValue(raw json.RawMessage) (string, bool) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

func hasBaseContext(raw json.RawMessage) bool {
	var contexts []json.RawMessage
	if json.Unmarshal(raw, &contexts) != nil || len(contexts) == 0 {
		return false
	}
	first, ok := stringValue(contexts[0])
	return ok && first == vcdmBaseContext
}

func hasType(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil {
		return false
	}
	for _, t := range many {
		if t == want {
			return true
		}
	}
	return false
}

type jsonError string

func (e jsonError) Error() string { return string(e) }

// decodeStrictObject decodes one JSON object and rejects duplicate member
// names at any level, nesting beyond maxDepth and trailing data. Go's decoder
// alone would silently keep the last of two duplicate members, which lets a
// crafted token present different values to different parsers.
func decodeStrictObject(raw []byte, maxDepth int) (map[string]json.RawMessage, error) {
	if err := checkStrictJSON(raw, maxDepth); err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, jsonError("not a JSON object")
	}
	return object, nil
}

func checkStrictJSON(raw []byte, maxDepth int) error {
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
			return err
		}
		if first {
			if delim, ok := token.(json.Delim); !ok || delim != '{' {
				return jsonError("top level is not an object")
			}
			first = false
		}
		delim, isDelim := token.(json.Delim)
		if isDelim && (delim == '}' || delim == ']') {
			stack = stack[:len(stack)-1]
			// A closed container is a finished value of the enclosing object.
			if len(stack) > 0 && stack[len(stack)-1].isObject {
				stack[len(stack)-1].expectKey = true
			}
			continue
		}
		if len(stack) > 0 && stack[len(stack)-1].isObject && stack[len(stack)-1].expectKey {
			key, ok := token.(string)
			if !ok {
				return jsonError("object key is not a string")
			}
			top := &stack[len(stack)-1]
			if top.keys[key] {
				return jsonError("duplicate object member")
			}
			top.keys[key] = true
			top.expectKey = false
			continue
		}
		if isDelim {
			if len(stack) >= maxDepth {
				return jsonError("nesting too deep")
			}
			stack = append(stack, frame{isObject: delim == '{', keys: map[string]bool{}, expectKey: delim == '{'})
			continue
		}
		// A scalar value finished: the enclosing object expects its next key.
		if len(stack) > 0 && stack[len(stack)-1].isObject {
			stack[len(stack)-1].expectKey = true
		}
	}
	if len(stack) != 0 {
		return jsonError("unterminated JSON")
	}
	return nil
}

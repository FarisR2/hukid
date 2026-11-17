package issuance

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"
	"time"
	"unicode/utf8"

	"hukid.local/platform/internal/verification"
)

// ProofExpectation is trusted caller policy, with no runtime defaults.
// MaxBytes <= 16384 and MaxDepth <= 8 bound parsing work (root depth is 1).
// Now must be explicit; MaxAge > 0 and ClockSkew >= 0 are durations.
// Issuer is the credential issuer, not the credential endpoint.
type ProofExpectation struct {
	Issuer, Nonce      string
	Now                time.Time
	MaxAge, ClockSkew  time.Duration
	MaxBytes, MaxDepth int
}

var errProof = errors.New("invalid issuance proof")

// ValidateProof authenticates a strict public ES256 proof and returns its RFC7638
// JKT. It does not issue, track or consume nonces: repeated valid input succeeds.
func ValidateProof(jwt string, expected ProofExpectation) (string, error) {
	p := expected
	if p.Issuer == "" || p.Nonce == "" || p.Now.IsZero() ||
		p.Now.Year() < 1 || p.Now.Year() > 9999 || p.MaxAge <= 0 || p.ClockSkew < 0 ||
		p.MaxBytes < 1 || p.MaxBytes > 16384 || p.MaxDepth < 1 || p.MaxDepth > 8 || len(jwt) > p.MaxBytes {
		return "", errProof
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "", errProof
	}
	h, eh := proofBase64(parts[0])
	b, eb := proofBase64(parts[1])
	sig, es := proofBase64(parts[2])
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		JWK struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"jwk"`
	}
	var claims struct {
		Aud   string          `json:"aud"`
		Nonce string          `json:"nonce"`
		Iat   json.RawMessage `json:"iat"`
	}
	if eh != nil || eb != nil || es != nil || len(sig) != 64 ||
		proofObject(h, p.MaxDepth, &header) != nil || proofObject(b, p.MaxDepth, &claims) != nil ||
		header.Alg != "ES256" || header.Typ != "openid4vci-proof+jwt" ||
		header.JWK.Kty != "EC" || header.JWK.Crv != "P-256" ||
		claims.Aud != p.Issuer || claims.Nonce != p.Nonce {
		return "", errProof
	}
	var iat int64
	err := json.Unmarshal(claims.Iat, &iat)
	// Restrict NumericDate to calendar years 1..9999 before time conversion.
	if err != nil || iat < -62135596800 || iat > 253402300799 {
		return "", errProof
	}
	at := time.Unix(iat, 0)
	// Separate Add calls avoid overflowing MaxAge + ClockSkew; no Unix subtraction.
	if at.Before(p.Now.Add(-p.MaxAge).Add(-p.ClockSkew)) || at.After(p.Now.Add(p.ClockSkew)) {
		return "", errProof
	}
	x, ex := proofBase64(header.JWK.X)
	y, ey := proofBase64(header.JWK.Y)
	if ex != nil || ey != nil || len(x) != 32 || len(y) != 32 {
		return "", errProof
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		return "", errProof
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return "", errProof
	}
	jkt, err := verification.JWKThumbprint(key)
	if err != nil {
		return "", errProof
	}
	return jkt, nil
}

func proofBase64(s string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || s == "" || base64.RawURLEncoding.EncodeToString(raw) != s {
		return nil, errProof
	}
	return raw, nil
}

// proofObject checks duplicates recursively before typed decoding; it also
// rejects null everywhere. Unknown members and wrong types never get ignored.
func proofObject(raw []byte, depth int, target any) error {
	if !utf8.Valid(raw) {
		return errProof
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) error
	value = func(level int) error {
		token, err := d.Token()
		if err != nil || token == nil {
			return errProof
		}
		delim, container := token.(json.Delim)
		if !container {
			return nil
		}
		if level > depth || (delim != '{' && delim != '[') {
			return errProof
		}
		seen := map[string]bool{}
		for d.More() {
			if delim == '{' {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return errProof
				}
				seen[name] = true
			}
			if value(level+1) != nil {
				return errProof
			}
		}
		_, err = d.Token()
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' || value(1) != nil {
		return errProof
	}
	if _, err := d.Token(); err != io.EOF {
		return errProof
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return errProof
	}
	// encoding/json matches struct names case-insensitively. Require exact names
	// independently so JOSE/claim/JWK allowlists are case-sensitive.
	var exact func(json.RawMessage) bool
	exact = func(b json.RawMessage) bool {
		var obj map[string]json.RawMessage
		if json.Unmarshal(b, &obj) != nil {
			return false
		}
		for name, child := range obj {
			switch name {
			case "alg", "typ", "kty", "crv", "x", "y", "aud", "nonce", "iat":
			case "jwk":
				if !exact(child) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	if !exact(raw) {
		return errProof
	}
	return nil
}

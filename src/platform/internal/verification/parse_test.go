package verification

import (
	"encoding/base64"
	"strings"
	"testing"
)

func enc(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

const goodHeader = `{"alg":"ES256","typ":"vc+jwt","kid":"k1"}`
const goodPayload = `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"https://issuer.hukid.pe/lab"}`

func token(header, payload string) string { return enc(header) + "." + enc(payload) + "." + enc("sig") }

func wantFormat(t *testing.T, jws string, want Code) {
	t.Helper()
	parsed, check := ParseCredential(jws, DefaultLimits)
	if want == "" {
		if check.Result != Pass || parsed == nil {
			t.Fatalf("expected pass, got %+v", check)
		}
		return
	}
	if check.Result != Fail || check.Code != want || check.Name != CheckFormat || parsed != nil {
		t.Fatalf("expected %s, got %+v (parsed=%v)", want, check, parsed != nil)
	}
}

func TestParseAcceptsAWellFormedCredential(t *testing.T) {
	payload := `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":"VerifiableCredential","issuer":"https://issuer.hukid.pe/lab","validFrom":"2026-01-01T00:00:00Z","validUntil":"2027-01-01T00:00:00Z","cnf":{"jkt":"abc"}}`
	parsed, check := ParseCredential(token(goodHeader, payload), DefaultLimits)
	if check.Result != Pass || !check.Required {
		t.Fatalf("unexpected check %+v", check)
	}
	if parsed.KID != "k1" || parsed.Issuer != "https://issuer.hukid.pe/lab" || parsed.ValidFrom != "2026-01-01T00:00:00Z" || parsed.ValidUntil != "2027-01-01T00:00:00Z" || parsed.CNFJKT != "abc" || len(parsed.UntrustedKeyHeaders) != 0 {
		t.Fatalf("unexpected parsed credential %+v", parsed)
	}
	if parsed.SigningInput != enc(goodHeader)+"."+enc(payload) {
		t.Fatal("signing input must be the original header.payload segments")
	}
}

func TestParseHeaderRules(t *testing.T) {
	cases := map[string]struct {
		header string
		want   Code
	}{
		"alg none":         {`{"alg":"none","typ":"vc+jwt","kid":"k1"}`, CodeFormatHeaderAlg},
		"alg HS256":        {`{"alg":"HS256","typ":"vc+jwt","kid":"k1"}`, CodeFormatHeaderAlg},
		"alg RS256":        {`{"alg":"RS256","typ":"vc+jwt","kid":"k1"}`, CodeFormatHeaderAlg},
		"alg lowercase":    {`{"alg":"es256","typ":"vc+jwt","kid":"k1"}`, CodeFormatHeaderAlg},
		"alg missing":      {`{"typ":"vc+jwt","kid":"k1"}`, CodeFormatHeaderAlg},
		"alg not a string": {`{"alg":256,"typ":"vc+jwt","kid":"k1"}`, CodeFormatHeaderAlg},
		"typ JWT":          {`{"alg":"ES256","typ":"JWT","kid":"k1"}`, CodeFormatHeaderTyp},
		"typ uppercase":    {`{"alg":"ES256","typ":"VC+JWT","kid":"k1"}`, CodeFormatHeaderTyp},
		"typ missing":      {`{"alg":"ES256","kid":"k1"}`, CodeFormatHeaderTyp},
		"kid missing":      {`{"alg":"ES256","typ":"vc+jwt"}`, CodeFormatMalformed},
		"kid empty":        {`{"alg":"ES256","typ":"vc+jwt","kid":""}`, CodeFormatMalformed},
		"kid not a string": {`{"alg":"ES256","typ":"vc+jwt","kid":7}`, CodeFormatMalformed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) { wantFormat(t, token(tc.header, goodPayload), tc.want) })
	}
}

func TestParsePayloadRules(t *testing.T) {
	ctx := `"@context":["https://www.w3.org/ns/credentials/v2"]`
	cases := map[string]struct {
		payload string
		want    Code
	}{
		"vc container":        {`{"vc":{` + ctx + `}}`, CodeFormatVCContainer},
		"vc beside the claim": {`{` + ctx + `,"type":["VerifiableCredential"],"issuer":"i","vc":{}}`, CodeFormatVCContainer},
		"iss duplicate":       {`{` + ctx + `,"type":["VerifiableCredential"],"issuer":"i","iss":"i"}`, CodeFormatDuplicateClaim},
		"nbf duplicate":       {`{` + ctx + `,"type":["VerifiableCredential"],"issuer":"i","nbf":1}`, CodeFormatDuplicateClaim},
		"sub duplicate":       {`{` + ctx + `,"type":["VerifiableCredential"],"issuer":"i","sub":"s"}`, CodeFormatDuplicateClaim},
		"issuer missing":      {`{` + ctx + `,"type":["VerifiableCredential"]}`, CodeFormatMalformed},
		"issuer not string":   {`{` + ctx + `,"type":["VerifiableCredential"],"issuer":{"id":"i"}}`, CodeFormatMalformed},
		"wrong first context": {`{"@context":["https://example.invalid/ctx"],"type":["VerifiableCredential"],"issuer":"i"}`, CodeFormatMalformed},
		"context not a list":  {`{"@context":"https://www.w3.org/ns/credentials/v2","type":["VerifiableCredential"],"issuer":"i"}`, CodeFormatMalformed},
		"type lacks VC":       {`{` + ctx + `,"type":["Other"],"issuer":"i"}`, CodeFormatMalformed},
		"validFrom not text":  {`{` + ctx + `,"type":["VerifiableCredential"],"issuer":"i","validFrom":5}`, CodeFormatMalformed},
		"cnf not an object":   {`{` + ctx + `,"type":["VerifiableCredential"],"issuer":"i","cnf":"x"}`, CodeFormatMalformed},
		"jkt not a string":    {`{` + ctx + `,"type":["VerifiableCredential"],"issuer":"i","cnf":{"jkt":1}}`, CodeFormatMalformed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) { wantFormat(t, token(goodHeader, tc.payload), tc.want) })
	}
}

func TestParseRejectsMalformedEnvelopes(t *testing.T) {
	cases := map[string]string{
		"empty":              "",
		"two segments":       enc(goodHeader) + "." + enc(goodPayload),
		"four segments":      token(goodHeader, goodPayload) + ".x",
		"empty header":       "." + enc(goodPayload) + "." + enc("s"),
		"empty payload":      enc(goodHeader) + ".." + enc("s"),
		"padded base64":      enc(goodHeader) + "=." + enc(goodPayload) + "." + enc("s"),
		"standard alphabet":  strings.Replace(token(goodHeader, goodPayload), "-", "+", 1) + "+/",
		"header not json":    token("not json", goodPayload),
		"payload not json":   token(goodHeader, "not json"),
		"header is an array": token(`["alg"]`, goodPayload),
		"payload is null":    token(goodHeader, `null`),
		"trailing data":      token(goodHeader, goodPayload+`{}`),
	}
	for name, jws := range cases {
		t.Run(name, func(t *testing.T) { wantFormat(t, jws, CodeFormatMalformed) })
	}
}

func TestParseRejectsDuplicateMembersAtAnyLevel(t *testing.T) {
	wantFormat(t, token(`{"alg":"none","alg":"ES256","typ":"vc+jwt","kid":"k1"}`, goodPayload), CodeFormatMalformed)
	wantFormat(t, token(goodHeader, `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"a","issuer":"b"}`), CodeFormatMalformed)
	wantFormat(t, token(goodHeader, `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"i","credentialSubject":{"x":1,"x":2}}`), CodeFormatMalformed)
}

func TestParseEnforcesSizeAndDepthLimits(t *testing.T) {
	limits := Limits{MaxJWSBytes: 200, MaxJSONDepth: 3}
	small := token(goodHeader, goodPayload)
	if len(small) <= limits.MaxJWSBytes {
		t.Fatalf("test needs the token to exceed the byte limit, got %d", len(small))
	}
	if _, check := ParseCredential(small, limits); check.Code != CodeFormatMalformed {
		t.Fatalf("oversize token must be malformed, got %+v", check)
	}
	if _, check := ParseCredential(small, DefaultLimits); check.Result != Pass {
		t.Fatalf("same token must pass under the default limits, got %+v", check)
	}

	nested := func(levels int) string {
		return `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"i","credentialSubject":` +
			strings.Repeat(`{"a":`, levels) + `1` + strings.Repeat(`}`, levels) + `}`
	}
	// The top-level object is level 1; credentialSubject plus its n objects add n levels, and "@context"/"type" arrays reach level 2.
	atLimit := DefaultLimits.MaxJSONDepth - 1
	wantFormat(t, token(goodHeader, nested(atLimit)), "")
	wantFormat(t, token(goodHeader, nested(atLimit+1)), CodeFormatMalformed)
	if _, check := ParseCredential(token(goodHeader, nested(10_000)), Limits{MaxJWSBytes: 1 << 20, MaxJSONDepth: 8}); check.Code != CodeFormatMalformed {
		t.Fatalf("pathological nesting must be rejected, got %+v", check)
	}
}

func TestParseRecordsUntrustedKeyHeadersWithoutRejectingFormat(t *testing.T) {
	header := `{"alg":"ES256","typ":"vc+jwt","kid":"k1","jku":"https://x.invalid/j","jwk":{"kty":"EC"},"x5u":"u","x5c":["c"]}`
	parsed, check := ParseCredential(token(header, goodPayload), DefaultLimits)
	if check.Result != Pass {
		t.Fatalf("format must pass; the issuerKey check owns this rejection: %+v", check)
	}
	if got := strings.Join(parsed.UntrustedKeyHeaders, ","); got != "jku,jwk,x5u,x5c" {
		t.Fatalf("UntrustedKeyHeaders = %q", got)
	}
}

func TestParseOutcomeMatchesTheVectorSet(t *testing.T) {
	file := loadVectors(t)
	for _, v := range file.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			parsed, check := ParseCredential(v.JWS, DefaultLimits)
			if v.Expected.FailedCheck == CheckFormat {
				if check.Result != Fail || check.Code != v.Expected.Code {
					t.Fatalf("expected format failure %s, got %+v", v.Expected.Code, check)
				}
				return
			}
			if check.Result != Pass || parsed == nil {
				t.Fatalf("format must pass for a vector that fails elsewhere, got %+v", check)
			}
			if v.ID == "v05-header-jku" && (len(parsed.UntrustedKeyHeaders) != 1 || parsed.UntrustedKeyHeaders[0] != "jku") {
				t.Fatalf("v05 must expose its jku header, got %v", parsed.UntrustedKeyHeaders)
			}
			if v.ID == "v01-valid" && parsed.CNFJKT != file.HolderJKT {
				t.Fatalf("cnf.jkt = %q, want %q", parsed.CNFJKT, file.HolderJKT)
			}
		})
	}
}

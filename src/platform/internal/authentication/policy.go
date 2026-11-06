// Package authentication defines console policy independently of HTTP and storage.
package authentication

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"slices"
	"strconv"
	"time"
)

// Policy currently supports the isolated AUTH-T02 test environment only.
// Production requires a separately approved provider and assurance policy.
type Policy struct {
	Environment            string    `json:"environment"`
	Issuer                 string    `json:"issuer"`
	ClientID               string    `json:"clientId"`
	Audience               string    `json:"audience"`
	ConsoleOrigin          string    `json:"consoleOrigin"`
	RedirectURI            string    `json:"redirectUri"`
	CookieName             string    `json:"cookieName"`
	CookieSecure           *bool     `json:"cookieSecure"`
	CookieSameSite         string    `json:"cookieSameSite"`
	ClockSkewSeconds       int       `json:"clockSkewSeconds"`
	AccessTokenSeconds     int       `json:"accessTokenSeconds"`
	SessionIdleSeconds     int       `json:"sessionIdleSeconds"`
	SessionAbsoluteSeconds int       `json:"sessionAbsoluteSeconds"`
	TransactionSeconds     int       `json:"transactionSeconds"`
	RefreshTokenSeconds    int       `json:"refreshTokenSeconds"`
	StepUpSeconds          int       `json:"stepUpSeconds"`
	LoginRateLimit         RateLimit `json:"loginRateLimit"`
	RequiredAMR            []string  `json:"requiredAmr"`
	AcceptedACR            []string  `json:"acceptedAcr"`
	AllowedReturnTo        []string  `json:"allowedReturnTo"`
	Scopes                 []string  `json:"scopes"`
}

type RateLimit struct {
	WindowSeconds int `json:"windowSeconds"`
	MaxAttempts   int `json:"maxAttempts"`
}

// LoadPolicy rejects missing, unknown and incoherent configuration; no defaults.
func LoadPolicy(reader io.Reader, environment string) (Policy, error) {
	var policy Policy
	decoder := json.NewDecoder(io.LimitReader(reader, 65537))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, errors.New("invalid auth policy JSON")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return Policy{}, errors.New("auth policy must contain one JSON object")
	}
	if err := policy.Validate(environment); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func (p Policy) Validate(environment string) error {
	invalid := errors.New("invalid or unsupported auth policy; only explicit isolated test configuration is supported")
	if environment != "test" || p.Environment != environment {
		return invalid
	}
	if !loopbackOrigin(p.Issuer) || !loopbackOrigin(p.ConsoleOrigin) || p.Issuer == p.ConsoleOrigin || p.RedirectURI != p.ConsoleOrigin+"/console/auth/callback" {
		return invalid
	}
	if p.ClientID != "hukid-console-test" || p.Audience != "https://api.hukid.pe/operator" || p.CookieName != "hukid_test_session" || p.CookieSecure == nil || *p.CookieSecure || p.CookieSameSite != "Lax" {
		return invalid
	}
	for _, seconds := range []int{p.ClockSkewSeconds, p.AccessTokenSeconds, p.SessionIdleSeconds, p.SessionAbsoluteSeconds, p.TransactionSeconds, p.RefreshTokenSeconds, p.StepUpSeconds, p.LoginRateLimit.WindowSeconds} {
		if seconds <= 0 || seconds > 86400 {
			return invalid
		}
	}
	if p.ClockSkewSeconds > 60 || p.ClockSkewSeconds >= p.AccessTokenSeconds || p.AccessTokenSeconds > p.SessionIdleSeconds || p.SessionIdleSeconds > p.SessionAbsoluteSeconds || p.RefreshTokenSeconds > p.SessionAbsoluteSeconds || p.StepUpSeconds > p.SessionIdleSeconds || p.TransactionSeconds > p.SessionIdleSeconds || p.LoginRateLimit.MaxAttempts < 1 || p.LoginRateLimit.MaxAttempts > 100 {
		return invalid
	}
	if !slices.Equal(p.RequiredAMR, []string{"pwd", "otp"}) || !slices.Equal(p.AcceptedACR, []string{"urn:hukid:test:mfa"}) || !slices.Equal(p.AllowedReturnTo, []string{"/"}) || !slices.Equal(p.Scopes, []string{"openid", "email", "offline_access", "operator:read"}) {
		return invalid
	}
	return nil
}

func loopbackOrigin(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Port() == "" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	port, err := strconv.Atoi(u.Port())
	return ip != nil && ip.IsLoopback() && err == nil && port > 0 && port <= 65535
}

// CheckMFA applies only to evidence already verified from the configured IdP.
// This method does not verify signatures, tokens or memberships.
func (p Policy) CheckMFA(authTime, now time.Time, amr []string, acr string, stepUp bool) error {
	invalid := errors.New("MFA evidence insufficient or stale")
	if authTime.IsZero() || authTime.After(now.Add(time.Duration(p.ClockSkewSeconds)*time.Second)) || !slices.Contains(p.AcceptedACR, acr) {
		return invalid
	}
	for _, method := range p.RequiredAMR {
		if !slices.Contains(amr, method) {
			return invalid
		}
	}
	maxAge := p.SessionAbsoluteSeconds
	if stepUp {
		maxAge = p.StepUpSeconds
	}
	if !now.Before(authTime.Add(time.Duration(maxAge) * time.Second)) {
		return invalid
	}
	return nil
}

// SessionExpired uses local timestamps and strict boundaries, without skew.
func (p Policy) SessionExpired(created, lastSeen, now time.Time) bool {
	return created.IsZero() || lastSeen.Before(created) || now.Before(lastSeen) ||
		!now.Before(created.Add(time.Duration(p.SessionAbsoluteSeconds)*time.Second)) ||
		!now.Before(lastSeen.Add(time.Duration(p.SessionIdleSeconds)*time.Second))
}

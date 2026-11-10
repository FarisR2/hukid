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
	"strings"
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

// SupportedEnvironment lists the only environments this build accepts. "test" is the
// isolated automated laboratory; "local" is a persistent single-machine profile that
// talks to a real IdP and database on loopback; "staging" is a remote pre-production
// profile behind HTTPS (ADR-0028). None of them is a production profile.
func SupportedEnvironment(environment string) bool {
	return environment == "test" || environment == "local" || environment == "staging"
}

func (p Policy) Validate(environment string) error {
	invalid := errors.New("invalid or unsupported auth policy; only explicit loopback test or local configuration is supported")
	if !SupportedEnvironment(environment) || p.Environment != environment {
		return invalid
	}
	issuerOK, consoleOK, clientID, cookieName, secure := loopbackOrigin(p.Issuer), loopbackOrigin(p.ConsoleOrigin), "hukid-console-test", "hukid_test_session", false
	switch environment {
	case "local":
		issuerOK, clientID, cookieName = loopbackRealmIssuer(p.Issuer), "hukid-console", "hukid_local_session"
	case "staging":
		// Remote profile: HTTPS-only public origins and a __Host- cookie (Secure, Path=/, no Domain).
		issuerOK, consoleOK, clientID, cookieName, secure = publicRealmIssuer(p.Issuer), publicHTTPSOrigin(p.ConsoleOrigin), "hukid-console", "__Host-hukid_session", true
	}
	if !issuerOK || !consoleOK || issuerOrigin(p.Issuer) == p.ConsoleOrigin || p.RedirectURI != p.ConsoleOrigin+"/console/auth/callback" {
		return invalid
	}
	if p.ClientID != clientID || p.Audience != "https://api.hukid.pe/operator" || p.CookieName != cookieName || p.CookieSecure == nil || *p.CookieSecure != secure || p.CookieSameSite != "Lax" {
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
	if !slices.Equal(p.AllowedReturnTo, []string{"/"}) || !slices.Equal(p.Scopes, []string{"openid", "email", "offline_access", "operator:read"}) {
		return invalid
	}
	if environment == "test" {
		if !slices.Equal(p.RequiredAMR, []string{"pwd", "otp"}) || !slices.Equal(p.AcceptedACR, []string{"urn:hukid:test:mfa"}) {
			return invalid
		}
		return nil
	}
	// local and staging: the real IdP names its own ACR values, but MFA evidence stays mandatory:
	// both factors are required and at least one explicit ACR must be accepted.
	if !slices.Equal(p.RequiredAMR, []string{"pwd", "otp"}) || len(p.AcceptedACR) == 0 || len(p.AcceptedACR) > 8 || slices.Contains(p.AcceptedACR, "") || slices.Contains(p.AcceptedACR, "0") {
		return invalid
	}
	return nil
}

// loopbackRealmIssuer accepts a loopback http issuer whose only path is a Keycloak-style
// realm (/realms/<name>); the origin part still has to satisfy loopbackOrigin.
func loopbackRealmIssuer(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, "/realms/") {
		return false
	}
	realm := strings.TrimPrefix(u.Path, "/realms/")
	if realm == "" || len(realm) > 64 || strings.Trim(realm, "abcdefghijklmnopqrstuvwxyz0123456789_-") != "" || value != u.Scheme+"://"+u.Host+u.Path {
		return false
	}
	return loopbackOrigin(u.Scheme + "://" + u.Host)
}

// publicRealmIssuer accepts an https issuer on a public DNS name whose only path is a
// Keycloak-style realm (/realms/<name>).
func publicRealmIssuer(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, "/realms/") || !publicHTTPSOrigin(u.Scheme+"://"+u.Host) {
		return false
	}
	realm := strings.TrimPrefix(u.Path, "/realms/")
	return realm != "" && len(realm) <= 64 && strings.Trim(realm, "abcdefghijklmnopqrstuvwxyz0123456789_-") == "" && value == u.Scheme+"://"+u.Host+u.Path
}

// publicHTTPSOrigin accepts scheme://host only: https, default port, a DNS name with at
// least one dot, never an IP literal, localhost or a reserved test/internal suffix.
func publicHTTPSOrigin(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" || value != "https://"+u.Host {
		return false
	}
	host := u.Hostname()
	if host == "" || len(host) > 253 || net.ParseIP(host) != nil || host != strings.ToLower(host) || !strings.Contains(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".invalid", ".test", ".example"} {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") || strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			return false
		}
	}
	return true
}

// issuerOrigin is scheme://host of the issuer, so a realm path cannot hide a shared origin.
func issuerOrigin(value string) string {
	u, err := url.Parse(value)
	if err != nil {
		return value
	}
	return u.Scheme + "://" + u.Host
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

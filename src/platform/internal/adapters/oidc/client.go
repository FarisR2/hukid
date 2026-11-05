// Package oidc adapts an explicitly configured OIDC authority to the login port.
package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
	"hukid.local/platform/internal/authentication"
)

type Client struct {
	policy     authentication.Policy
	oauth      oauth2.Config
	verifier   *coreoidc.IDTokenVerifier
	keys       *coreoidc.RemoteKeySet
	http       *http.Client
	revocation string
	now        func() time.Time
}

// confinedTransport also covers library-internal discovery, JWKS and token calls.
type confinedTransport struct {
	origin string
	base   http.RoundTripper
}

func (t confinedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme+"://"+r.URL.Host != t.origin || r.URL.User != nil || r.URL.Fragment != "" {
		return nil, errors.New("authority not allowed")
	}
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, errors.New("OIDC request failed")
	}
	defer response.Body.Close()
	b, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(b) > 1<<20 {
		return nil, errors.New("OIDC response exceeds limits")
	}
	response.Body = io.NopCloser(bytes.NewReader(b))
	return response, nil
}

func New(ctx context.Context, p authentication.Policy, secret string, now func() time.Time) (*Client, error) {
	if p.Validate("test") != nil || secret == "" || now == nil {
		return nil, authentication.ErrDependency
	}
	u, _ := url.Parse(p.Issuer)
	hc := &http.Client{Timeout: 5 * time.Second, Transport: confinedTransport{u.Scheme + "://" + u.Host, http.DefaultTransport}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx = coreoidc.ClientContext(ctx, hc)
	provider, err := coreoidc.NewProvider(ctx, p.Issuer)
	if err != nil {
		return nil, authentication.ErrDependency
	}
	var metadata struct {
		JWKS            string   `json:"jwks_uri"`
		IssuerParameter bool     `json:"authorization_response_iss_parameter_supported"`
		PKCE            []string `json:"code_challenge_methods_supported"`
		AuthMethods     []string `json:"token_endpoint_auth_methods_supported"`
		Algorithms      []string `json:"id_token_signing_alg_values_supported"`
		Revocation      string   `json:"revocation_endpoint"`
	}
	if provider.Claims(&metadata) != nil || !metadata.IssuerParameter || !slices.Contains(metadata.PKCE, "S256") || !slices.Contains(metadata.AuthMethods, "client_secret_basic") || !slices.Contains(metadata.Algorithms, "ES256") {
		return nil, authentication.ErrDependency
	}
	endpoints := provider.Endpoint()
	urls := []string{endpoints.AuthURL, endpoints.TokenURL, metadata.JWKS}
	if metadata.Revocation != "" {
		urls = append(urls, metadata.Revocation)
	}
	for _, raw := range urls {
		endpoint, e := url.Parse(raw)
		if e != nil || endpoint.Scheme != u.Scheme || endpoint.Host != u.Host || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return nil, authentication.ErrDependency
		}
	}
	keys := coreoidc.NewRemoteKeySet(ctx, metadata.JWKS)
	verifier := coreoidc.NewVerifier(p.Issuer, keys, &coreoidc.Config{ClientID: p.ClientID, SupportedSigningAlgs: []string{"ES256"}, Now: now})
	endpoints.AuthStyle = oauth2.AuthStyleInHeader
	return &Client{policy: p, oauth: oauth2.Config{ClientID: p.ClientID, ClientSecret: secret, Endpoint: endpoints, RedirectURL: p.RedirectURI, Scopes: p.Scopes}, verifier: verifier, keys: keys, http: hc, revocation: metadata.Revocation, now: now}, nil
}

func (c *Client) AuthorizationURL(state, nonce, challenge string) string {
	return c.oauth.AuthCodeURL(state, coreoidc.Nonce(nonce), oauth2.SetAuthURLParam("code_challenge", challenge), oauth2.SetAuthURLParam("code_challenge_method", "S256"), oauth2.SetAuthURLParam("resource", c.policy.Audience), oauth2.SetAuthURLParam("prompt", "consent"), oauth2.SetAuthURLParam("acr_values", strings.Join(c.policy.AcceptedACR, " ")))
}

func (c *Client) Exchange(ctx context.Context, code, verifier string, nonceHash []byte) (authentication.VerifiedLogin, error) {
	ctx = coreoidc.ClientContext(ctx, c.http)
	tokens, err := c.oauth.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier), oauth2.SetAuthURLParam("resource", c.policy.Audience))
	if err != nil {
		var failure *oauth2.RetrieveError
		if errors.As(err, &failure) && failure.ErrorCode == "invalid_grant" {
			return authentication.VerifiedLogin{}, authentication.ErrCallback
		}
		return authentication.VerifiedLogin{}, authentication.ErrDependency
	}
	rawID, ok := tokens.Extra("id_token").(string)
	if !ok || tokens.RefreshToken == "" || tokens.TokenType != "Bearer" {
		return authentication.VerifiedLogin{}, authentication.ErrCallback
	}
	identity, err := c.Validate(ctx, rawID, tokens.AccessToken, nonceHash)
	if err != nil {
		return authentication.VerifiedLogin{}, err
	}
	identity.AccessToken = tokens.AccessToken
	identity.RefreshToken = tokens.RefreshToken
	return identity, nil
}

type evidence struct {
	Issuer          string          `json:"iss"`
	Subject         string          `json:"sub"`
	Audience        json.RawMessage `json:"aud"`
	Expires         int64           `json:"exp"`
	Issued          int64           `json:"iat"`
	NotBefore       int64           `json:"nbf"`
	AuthTime        int64           `json:"auth_time"`
	AMR             []string        `json:"amr"`
	ACR             string          `json:"acr"`
	Client          string          `json:"client_id"`
	AuthorizedParty string          `json:"azp"`
	Class           string          `json:"hukid_token_class"`
	Grant           string          `json:"hukid_grant"`
	Scope           string          `json:"scope"`
	JTI             string          `json:"jti"`
}

func (c *Client) checkTimes(e evidence) bool {
	return c.checkEvidenceTimes(e, false)
}

func (c *Client) checkEvidenceTimes(e evidence, allowExpired bool) bool {
	now := c.now()
	future := now.Add(time.Duration(c.policy.ClockSkewSeconds) * time.Second).Unix()
	return e.Issued > 0 && e.Expires > e.Issued && (allowExpired || now.Unix() < e.Expires) && e.Issued <= future && e.NotBefore <= future && e.Expires-e.Issued <= int64(c.policy.AccessTokenSeconds) && e.AuthTime > 0
}

// Validate keeps ID-token authentication distinct from operator access authority.
// Management uses VerifyOperator independently of ID-token authentication.
func (c *Client) Validate(ctx context.Context, rawID, access string, nonceHash []byte) (authentication.VerifiedLogin, error) {
	invalid := authentication.ErrCallback
	for _, raw := range []string{rawID, access} {
		if len(raw) == 0 || len(raw) > 64<<10 {
			return authentication.VerifiedLogin{}, invalid
		}
		parsed, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil || len(parsed.Signatures) != 1 || parsed.Signatures[0].Header.KeyID == "" {
			return authentication.VerifiedLogin{}, invalid
		}
		if !uniqueClaims(parsed.UnsafePayloadWithoutVerification()) {
			return authentication.VerifiedLogin{}, invalid
		}
		header := parsed.Signatures[0].Header
		if header.JSONWebKey != nil || header.ExtraHeaders[jose.HeaderKey("jku")] != nil || header.ExtraHeaders[jose.HeaderKey("x5u")] != nil {
			return authentication.VerifiedLogin{}, invalid
		}
		if raw == access && header.ExtraHeaders[jose.HeaderType] != "at+jwt" {
			return authentication.VerifiedLogin{}, invalid
		}
	}
	id, err := c.verifier.Verify(ctx, rawID)
	if err != nil {
		return authentication.VerifiedLogin{}, invalid
	}
	if !authentication.EqualDigest(authentication.Digest(id.Nonce), nonceHash) || id.Subject == "" || len(id.Subject) > 128 {
		return authentication.VerifiedLogin{}, invalid
	}
	if id.AccessTokenHash != "" && id.VerifyAccessToken(access) != nil {
		return authentication.VerifiedLogin{}, invalid
	}
	var ie evidence
	if id.Claims(&ie) != nil || !c.checkTimes(ie) || (ie.AuthorizedParty != "" && ie.AuthorizedParty != c.policy.ClientID) {
		return authentication.VerifiedLogin{}, invalid
	}
	if len(id.Audience) != 1 || id.Audience[0] != c.policy.ClientID {
		return authentication.VerifiedLogin{}, invalid
	}
	ae, err := c.operatorEvidence(ctx, access)
	if err != nil {
		if errors.Is(err, authentication.ErrMFA) {
			return authentication.VerifiedLogin{}, err
		}
		return authentication.VerifiedLogin{}, invalid
	}
	if ae.Subject != id.Subject {
		return authentication.VerifiedLogin{}, invalid
	}
	if ae.AuthTime != ie.AuthTime || ae.ACR != ie.ACR || !sameMethods(ae.AMR, ie.AMR) {
		return authentication.VerifiedLogin{}, invalid
	}
	if c.policy.CheckMFA(time.Unix(ae.AuthTime, 0), c.now(), ae.AMR, ae.ACR, false) != nil {
		return authentication.VerifiedLogin{}, authentication.ErrMFA
	}
	return authentication.VerifiedLogin{Issuer: ae.Issuer, Subject: ae.Subject, AuthTime: time.Unix(ae.AuthTime, 0), AMR: ae.AMR, ACR: ae.ACR}, nil
}

// VerifyOperator accepts access authority alone; an ID token can never substitute it.
func (c *Client) VerifyOperator(ctx context.Context, raw string) (authentication.Operator, error) {
	e, err := c.operatorEvidence(ctx, raw)
	if err != nil {
		return authentication.Operator{}, err
	}
	return authentication.Operator{Issuer: e.Issuer, Subject: e.Subject}, nil
}

func (c *Client) operatorEvidence(ctx context.Context, raw string) (evidence, error) {
	return c.validateOperator(ctx, raw, false)
}

func (c *Client) validateOperator(ctx context.Context, raw string, allowExpired bool) (evidence, error) {
	invalid := authentication.ErrCredential
	if len(raw) == 0 || len(raw) > 64<<10 {
		return evidence{}, invalid
	}
	parsed, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(parsed.Signatures) != 1 || !uniqueClaims(parsed.UnsafePayloadWithoutVerification()) {
		return evidence{}, invalid
	}
	h := parsed.Signatures[0].Header
	if h.KeyID == "" || h.ExtraHeaders[jose.HeaderType] != "at+jwt" || h.JSONWebKey != nil || h.ExtraHeaders[jose.HeaderKey("jku")] != nil || h.ExtraHeaders[jose.HeaderKey("x5u")] != nil {
		return evidence{}, invalid
	}
	payload, err := c.keys.VerifySignature(ctx, raw)
	if err != nil {
		return evidence{}, invalid
	}
	var e evidence
	var audience string
	if json.Unmarshal(payload, &e) != nil || !c.checkEvidenceTimes(e, allowExpired) || json.Unmarshal(e.Audience, &audience) != nil || audience != c.policy.Audience || e.Issuer != c.policy.Issuer || e.Subject == "" || len(e.Subject) > 128 || e.Client != c.policy.ClientID || e.Class != "operator" || e.Grant != "authorization_code" || !slices.Contains(strings.Fields(e.Scope), "operator:read") || e.JTI == "" || len(e.JTI) > 128 || !sameMethods(e.AMR, e.AMR) {
		return evidence{}, invalid
	}
	if c.policy.CheckMFA(time.Unix(e.AuthTime, 0), c.now(), e.AMR, e.ACR, false) != nil {
		return evidence{}, authentication.ErrMFA
	}
	return e, nil
}

func sameMethods(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a = slices.Clone(a)
	b = slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b) && len(slices.Compact(a)) == len(a)
}

// Structural inspection cannot grant authority; signature verification follows.
func uniqueClaims(payload []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return false
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return false
		}
	}
	if _, err := decoder.Token(); err != nil {
		return false
	}
	return decoder.Decode(new(any)) == io.EOF
}

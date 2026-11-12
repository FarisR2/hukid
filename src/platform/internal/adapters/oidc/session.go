package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	a "hukid.local/platform/internal/authentication"
)

// postToken uses the configured authority and a single HTTP attempt. In
// particular it never delegates uncertain refreshes to an automatic retryer.
func (c *Client) postToken(ctx context.Context, endpoint string, form url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, a.ErrDependency
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(c.oauth.ClientID), url.QueryEscape(c.oauth.ClientSecret))
	response, err := c.http.Do(req)
	if err != nil {
		return nil, a.ErrDependency
	}
	return response, nil
}

func (c *Client) Refresh(ctx context.Context, oldAccess, refresh string, nonceHash []byte) (a.VerifiedLogin, error) {
	// Only this server-side path permits an expired access token as historical
	// evidence. Signature, identity, class, grant and MFA remain mandatory.
	previous, err := c.validateOperator(ctx, oldAccess, true)
	if err != nil {
		return a.VerifiedLogin{}, a.ErrSession
	}
	response, err := c.postToken(ctx, c.oauth.Endpoint.TokenURL, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "resource": {c.policy.Audience}})
	if err != nil {
		return a.VerifiedLogin{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		var failure struct {
			Code string `json:"error"`
		}
		if json.NewDecoder(response.Body).Decode(&failure) == nil && failure.Code == "invalid_grant" {
			return a.VerifiedLogin{}, a.ErrSession
		}
		return a.VerifiedLogin{}, a.ErrDependency
	}
	var tokens struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		Type    string `json:"token_type"`
		ID      string `json:"id_token"`
	}
	if json.NewDecoder(response.Body).Decode(&tokens) != nil || tokens.Type != "Bearer" || tokens.Refresh == "" || tokens.Refresh == refresh {
		return a.VerifiedLogin{}, a.ErrSession
	}
	e, err := c.operatorEvidence(ctx, tokens.Access)
	if err != nil || e.Subject != previous.Subject || e.AuthTime != previous.AuthTime || e.ACR != previous.ACR || !sameMethods(e.AMR, previous.AMR) {
		return a.VerifiedLogin{}, a.ErrSession
	}
	if tokens.ID != "" {
		parsed, err := jose.ParseSigned(tokens.ID, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil || len(parsed.Signatures) != 1 || !uniqueClaims(parsed.UnsafePayloadWithoutVerification()) {
			return a.VerifiedLogin{}, a.ErrSession
		}
		h := parsed.Signatures[0].Header
		if h.KeyID == "" || h.JSONWebKey != nil || h.ExtraHeaders[jose.HeaderKey("jku")] != nil || h.ExtraHeaders[jose.HeaderKey("x5u")] != nil {
			return a.VerifiedLogin{}, a.ErrSession
		}
		// Refresh ID tokens may omit nonce. They cannot establish new identity
		// or make the original authentication fresher.
		id, err := c.verifier.Verify(ctx, tokens.ID)
		if err != nil {
			return a.VerifiedLogin{}, a.ErrSession
		}
		if id.Nonce != "" && !a.EqualDigest(a.Digest(id.Nonce), nonceHash) {
			return a.VerifiedLogin{}, a.ErrSession
		}
		var ie evidence
		if id.Claims(&ie) != nil || !c.checkTimes(ie) || len(id.Audience) != 1 || id.Audience[0] != c.policy.ClientID || id.Subject != e.Subject || ie.AuthTime != e.AuthTime || ie.ACR != e.ACR || !sameMethods(ie.AMR, e.AMR) || (ie.AuthorizedParty != "" && ie.AuthorizedParty != c.policy.ClientID) || (id.AccessTokenHash != "" && id.VerifyAccessToken(tokens.Access) != nil) {
			return a.VerifiedLogin{}, a.ErrSession
		}
	}
	return a.VerifiedLogin{Issuer: e.Issuer, Subject: e.Subject, AccessToken: tokens.Access, RefreshToken: tokens.Refresh, AuthTime: time.Unix(e.AuthTime, 0), AMR: e.AMR, ACR: e.ACR}, nil
}

func (c *Client) Revoke(ctx context.Context, refresh string) error {
	if c.revocation == "" {
		return a.ErrDependency
	}
	response, err := c.postToken(ctx, c.revocation, url.Values{"token": {refresh}, "token_type_hint": {"refresh_token"}})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return a.ErrDependency
	}
	return nil
}

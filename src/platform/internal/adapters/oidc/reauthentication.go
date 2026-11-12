package oidc

import (
	"context"
	a "hukid.local/platform/internal/authentication"
	"net/url"
	"time"
)

func (c *Client) ReauthenticationURL(state, nonce, challenge string) string {
	u, _ := url.Parse(c.AuthorizationURL(state, nonce, challenge))
	q := u.Query()
	// offline_access requires explicit consent as well as fresh authentication.
	q.Set("prompt", "login consent")
	q.Set("max_age", "0")
	u.RawQuery = q.Encode()
	return u.String()
}

// VerifyPrivilegedOperator is the freshness gate for future privileged writes.
// Local capability and membership checks must still follow in their handlers.
func (c *Client) VerifyPrivilegedOperator(ctx context.Context, raw string) (a.Operator, error) {
	e, err := c.operatorEvidence(ctx, raw)
	if err != nil {
		return a.Operator{}, err
	}
	if c.policy.CheckMFA(time.Unix(e.AuthTime, 0), c.now(), e.AMR, e.ACR, true) != nil {
		return a.Operator{}, a.ErrStepUp
	}
	return a.Operator{Issuer: e.Issuer, Subject: e.Subject}, nil
}

// The local deadline lets a writer recheck freshness after taking its DB lock
// without holding the lock during OIDC/JWKS I/O.
func (c *Client) VerifyInvitationOperator(ctx context.Context, raw string) (a.Operator, time.Time, error) {
	e, err := c.operatorEvidence(ctx, raw)
	if err != nil {
		return a.Operator{}, time.Time{}, err
	}
	if c.policy.CheckMFA(time.Unix(e.AuthTime, 0), c.now(), e.AMR, e.ACR, true) != nil {
		return a.Operator{}, time.Time{}, a.ErrStepUp
	}
	deadline := time.Unix(e.AuthTime, 0).Add(time.Duration(c.policy.StepUpSeconds) * time.Second)
	if expires := time.Unix(e.Expires, 0); expires.Before(deadline) {
		deadline = expires
	}
	return a.Operator{Issuer: e.Issuer, Subject: e.Subject}, deadline, nil
}

// Only session reauthentication may use signed expired access evidence to bind
// the old identity. This method never grants Management access.
func (c *Client) SessionIdentity(ctx context.Context, raw string) (a.Operator, error) {
	e, err := c.validateOperator(ctx, raw, true)
	if err != nil {
		return a.Operator{}, err
	}
	return a.Operator{Issuer: e.Issuer, Subject: e.Subject}, nil
}

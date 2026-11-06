package tenancy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	a "hukid.local/platform/internal/authentication"
	"time"
)

var (
	ErrInvitationInvalid = errors.New("invitation invalid")
	ErrMembershipExists  = errors.New("membership exists")
)

type Acceptance struct {
	TenantID   string     `json:"tenantId"`
	Membership MemberView `json:"membership"`
}
type AcceptanceCommand struct {
	Actor, Key, Token  string
	Proof              a.RecipientEvidence
	TokenHash, KeyHash []byte
}
type AcceptanceStore interface {
	AcceptInvitation(context.Context, AcceptanceCommand, func(string) []byte) (Acceptance, error)
}
type AcceptanceService struct {
	Store   AcceptanceStore
	Policy  MembershipPolicy
	HMACKey []byte
	Now     func() time.Time
}

func (s *AcceptanceService) Execute(ctx context.Context, c AcceptanceCommand) (Acceptance, error) {
	if s.Store == nil || s.Now == nil || len(s.HMACKey) != 32 || s.Policy.Validate("test") != nil {
		return Acceptance{}, a.ErrDependency
	}
	// Evidence is checked before parsing or resolving a token.
	if !a.RecipientFresh(c.Proof, s.Now(), time.Duration(s.Policy.EmailEvidenceSeconds)*time.Second) {
		return Acceptance{}, a.ErrRecipient
	}
	email, err := NormalizeInvitationEmail(c.Proof.Email)
	if err != nil {
		return Acceptance{}, a.ErrRecipient
	}
	if !memberIssuerID.MatchString(c.Actor) || !commandKey.MatchString(c.Key) {
		return Acceptance{}, ErrDirectoryRequest
	}
	token, err := base64.RawURLEncoding.Strict().DecodeString(c.Token)
	if err != nil || len(token) != 32 {
		return Acceptance{}, ErrMemberInput
	}
	clear(token)
	c.TokenHash = a.Digest(c.Token)
	c.KeyHash = a.Digest(c.Key)
	c.Token = ""
	return s.Store.AcceptInvitation(ctx, c, func(tenant string) []byte {
		mac := hmac.New(sha256.New, s.HMACKey)
		mac.Write([]byte(tenant + ":" + email))
		return mac.Sum(nil)
	})
}

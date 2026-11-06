package authentication

import (
	"context"
	"errors"
	"time"
)

var ErrRecipient = errors.New("recipient evidence unavailable")

type RecipientSessionReader interface {
	ReadRecipientSession(context.Context, []byte, time.Time) (ReadSession, error)
}

// Recipient resolves only evidence obtained by this server in Code/PKCE. The
// bearer must also be independently verified by the caller before using it.
func (s *SessionService) Recipient(ctx context.Context, access, actor string, operator Operator, maxAge time.Duration) (RecipientEvidence, error) {
	reader, ok := s.Store.(RecipientSessionReader)
	if !ok {
		return RecipientEvidence{}, ErrDependency
	}
	v, err := reader.ReadRecipientSession(ctx, Digest(access), s.Now())
	if err != nil {
		return RecipientEvidence{}, err
	}
	if !s.valid(v, s.Now()) || v.ActorID != actor {
		return RecipientEvidence{}, ErrRecipient
	}
	secret, err := s.open(v)
	if err != nil {
		return RecipientEvidence{}, err
	}
	if secret.AccessToken != access || secret.Recipient == nil {
		return RecipientEvidence{}, ErrRecipient
	}
	proof := *secret.Recipient
	now := s.Now()
	if proof.Issuer != operator.Issuer || proof.Subject != operator.Subject || proof.Email == "" || !RecipientFresh(proof, now, maxAge) {
		return RecipientEvidence{}, ErrRecipient
	}
	return proof, nil
}

func RecipientFresh(p RecipientEvidence, now time.Time, maxAge time.Duration) bool {
	return maxAge > 0 && !p.IssuedAt.IsZero() && !p.AuthTime.IsZero() && !now.Before(p.IssuedAt) && !now.Before(p.AuthTime) && now.Before(p.IssuedAt.Add(maxAge)) && now.Before(p.AuthTime.Add(maxAge)) && now.Before(p.ExpiresAt)
}

package authentication

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

type recipientReader struct {
	SessionReader
	value ReadSession
}

func (r recipientReader) ReadRecipientSession(context.Context, []byte, time.Time) (ReadSession, error) {
	return r.value, nil
}

func TestRecipientEvidenceBindsSessionIdentityAccessAndDeadlines(t *testing.T) {
	now := time.Now().UTC()
	for _, name := range []string{"valid", "missing", "actor", "subject", "issuer", "access", "auth_deadline", "issued_deadline", "expired", "future"} {
		t.Run(name, func(t *testing.T) {
			proof := &RecipientEvidence{Issuer: "issuer", Subject: "subject", Email: "recipient@example.invalid", IssuedAt: now, AuthTime: now, ExpiresAt: now.Add(time.Hour)}
			secret := SessionSecrets{AccessToken: "access", CSRF: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Recipient: proof}
			actor := "actor"
			operator := Operator{Issuer: "issuer", Subject: "subject"}
			switch name {
			case "missing":
				secret.Recipient = nil
			case "actor":
				actor = "foreign"
			case "subject":
				operator.Subject = "foreign"
			case "issuer":
				operator.Issuer = "foreign"
			case "access":
				secret.AccessToken = "foreign"
			case "auth_deadline":
				proof.AuthTime = now.Add(-5 * time.Minute)
			case "issued_deadline":
				proof.IssuedAt = now.Add(-5 * time.Minute)
			case "expired":
				proof.ExpiresAt = now
			case "future":
				proof.IssuedAt = now.Add(time.Second)
			}
			plain, _ := json.Marshal(secret)
			value := ReadSession{ActorID: "actor", FamilyID: "family", Generation: 1, PolicyVersion: "auth-test-v1", CSRFHash: Digest(secret.CSRF), CreatedAt: now, FamilyCreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(time.Minute), AbsoluteExpiresAt: now.Add(time.Hour)}
			service := SessionService{Store: recipientReader{value: value}, Cipher: readCipher{data: plain}, Policy: Policy{SessionAbsoluteSeconds: 3600, SessionIdleSeconds: 1800}, Now: func() time.Time { return now }}
			_, err := service.Recipient(context.Background(), "access", actor, operator, 5*time.Minute)
			if (err == nil) != (name == "valid") {
				t.Fatal("recipient binding", err)
			}
		})
	}
}

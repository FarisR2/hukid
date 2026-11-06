package tenancy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"time"

	a "hukid.local/platform/internal/authentication"
)

var (
	ErrInvitationConflict = errors.New("idempotency conflict")
	ErrInvitationBusy     = errors.New("invitation operation in progress")
	ErrInvitationState    = errors.New("invitation not pending")
	ErrInvitationRevision = errors.New("invitation revision mismatch")
)

type InviteInput struct {
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	IssuerIDs []string `json:"issuerIds"`
}
type RevokeInput struct {
	ReasonCode string `json:"reasonCode"`
}

// PrivilegeDeadline comes from verified token evidence, never request JSON.
type InvitationCommand struct {
	Actor, Tenant, Operation, Key, InvitationID string
	Input                                       InviteInput
	Reason                                      string
	Revision                                    int64
	PrivilegeDeadline                           time.Time
	KeyHash, RequestHash                        []byte
}
type InvitationMaterial struct {
	ID                                                              string
	TokenHash, RecipientHMAC                                        []byte
	Recipient, Delivery                                             a.Envelope
	CreatedAt, ExpiresAt, RecipientDeleteAfter, DeliveryDeleteAfter time.Time
}
type InvitationStore interface {
	MutateInvitation(context.Context, InvitationCommand, func(time.Time) (InvitationMaterial, error)) (InvitationView, error)
}
type InvitationService struct {
	Store   InvitationStore
	Cipher  a.Cipher
	HMACKey []byte
	Random  io.Reader
	Policy  MembershipPolicy
}

var commandKey = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

func (s *InvitationService) Execute(ctx context.Context, c InvitationCommand) (InvitationView, error) {
	if !memberIssuerID.MatchString(c.Actor) || !memberIssuerID.MatchString(c.Tenant) {
		return InvitationView{}, a.ErrTenant
	}
	if !commandKey.MatchString(c.Key) {
		return InvitationView{}, ErrDirectoryRequest
	}
	if s.Policy.Validate("test") != nil || s.Store == nil || s.Cipher == nil || len(s.HMACKey) != 32 || s.Random == nil {
		return InvitationView{}, a.ErrDependency
	}
	var canonical any
	switch c.Operation {
	case "invitation.create":
		email, err := NormalizeInvitationEmail(c.Input.Email)
		if err != nil || c.Input.Roles == nil || c.Input.IssuerIDs == nil || !DirectoryGrantShape(c.Input.Roles, c.Input.IssuerIDs) {
			return InvitationView{}, ErrMemberInput
		}
		c.Input.Email = email
		c.Input.Roles = slices.Clone(c.Input.Roles)
		c.Input.IssuerIDs = slices.Clone(c.Input.IssuerIDs)
		slices.Sort(c.Input.Roles)
		slices.Sort(c.Input.IssuerIDs)
		canonical = c.Input
	case "invitation.revoke":
		if c.Revision < 1 || c.Revision > 9007199254740991 {
			return InvitationView{}, ErrDirectoryRequest
		}
		if !memberIssuerID.MatchString(c.InvitationID) {
			return InvitationView{}, a.ErrTenant
		}
		if !slices.Contains([]string{"access_change", "security_response", "operator_request", "invitation_cancelled"}, c.Reason) {
			return InvitationView{}, ErrMemberInput
		}
		canonical = struct {
			ID, Reason string
			Revision   int64
		}{c.InvitationID, c.Reason, c.Revision}
	default:
		return InvitationView{}, ErrDirectoryRequest
	}
	data, _ := json.Marshal(canonical)
	sum := sha256.Sum256(data)
	c.RequestHash = sum[:]
	sumKey := sha256.Sum256([]byte(c.Key))
	c.KeyHash = sumKey[:]
	return s.Store.MutateInvitation(ctx, c, func(now time.Time) (InvitationMaterial, error) { return s.material(c, now) })
}

func invitationPurpose(tenant, id, purpose string) string {
	return "hukid:invitation:v1:" + tenant + ":" + id + ":" + purpose
}

type DeliveryPayload struct{ Email, Token string }

func (s *InvitationService) material(c InvitationCommand, now time.Time) (InvitationMaterial, error) {
	var m InvitationMaterial
	id := make([]byte, 16)
	token := make([]byte, 32)
	if _, err := io.ReadFull(s.Random, id); err != nil {
		return m, a.ErrDependency
	}
	if _, err := io.ReadFull(s.Random, token); err != nil {
		return m, a.ErrDependency
	}
	id[6] = (id[6] & 15) | 64
	id[8] = (id[8] & 63) | 128
	// UUID formatting without introducing a UUID dependency.
	const digits = "0123456789abcdef"
	text := make([]byte, 0, 36)
	for i, b := range id {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			text = append(text, '-')
		}
		text = append(text, digits[b>>4], digits[b&15])
	}
	m.ID = string(text)
	raw := base64.RawURLEncoding.EncodeToString(token)
	digest := sha256.Sum256([]byte(raw))
	m.TokenHash = digest[:]
	mac := hmac.New(sha256.New, s.HMACKey)
	mac.Write([]byte(c.Tenant + ":" + c.Input.Email))
	m.RecipientHMAC = mac.Sum(nil)
	var err error
	m.Recipient, err = s.Cipher.Seal([]byte(c.Input.Email), invitationPurpose(c.Tenant, m.ID, "recipient"))
	if err != nil {
		return m, a.ErrDependency
	}
	payload, _ := json.Marshal(DeliveryPayload{c.Input.Email, raw})
	m.Delivery, err = s.Cipher.Seal(payload, invitationPurpose(c.Tenant, m.ID, "delivery"))
	clear(payload)
	clear(token)
	if err != nil {
		return m, a.ErrDependency
	}
	m.CreatedAt = now
	m.ExpiresAt = now.Add(time.Duration(s.Policy.InvitationSeconds) * time.Second)
	m.RecipientDeleteAfter = now.Add(time.Duration(s.Policy.RecipientRetentionSeconds) * time.Second)
	m.DeliveryDeleteAfter = minTime(m.ExpiresAt, now.Add(time.Duration(s.Policy.DeliverySecretSeconds)*time.Second))
	return m, nil
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// NotificationProvider must deduplicate durably by tenant/invitation/generation.
// Send errors are deliberately not exposed in API, audit or worker logs.
type NotificationProvider interface {
	Send(context.Context, string, string, int64, DeliveryPayload) error
}
type DeliveryWork struct {
	Tenant, ID string
	Generation int64
	Envelope   a.Envelope
	Deadline   time.Time
	TokenHash  []byte
}
type InvitationDeliveryStore interface {
	PendingDelivery(context.Context, string, string, time.Time) ([]DeliveryWork, error)
	FinishDelivery(context.Context, string, DeliveryWork, bool, time.Time) error
	PurgeInvitations(context.Context, string, string, time.Time) error
}
type InvitationWorker struct {
	Store    InvitationDeliveryStore
	Provider NotificationProvider
	Cipher   a.Cipher
	Now      func() time.Time
}

func (w *InvitationWorker) Run(ctx context.Context, actor, tenant string) error {
	if w.Store == nil || w.Provider == nil || w.Cipher == nil || w.Now == nil {
		return a.ErrDependency
	}
	if err := w.Store.PurgeInvitations(ctx, actor, tenant, w.Now().UTC()); err != nil {
		return err
	}
	work, err := w.Store.PendingDelivery(ctx, actor, tenant, w.Now().UTC())
	if err != nil {
		return err
	}
	for _, item := range work {
		if !w.Now().Before(item.Deadline) {
			continue
		}
		plain, e := w.Cipher.Open(item.Envelope, invitationPurpose(item.Tenant, item.ID, "delivery"))
		var payload DeliveryPayload
		valid := e == nil && json.Unmarshal(plain, &payload) == nil
		clear(plain)
		if valid {
			email, e := NormalizeInvitationEmail(payload.Email)
			token, e2 := base64.RawURLEncoding.Strict().DecodeString(payload.Token)
			hash := sha256.Sum256([]byte(payload.Token))
			valid = e == nil && email == payload.Email && e2 == nil && len(token) == 32 && hmac.Equal(hash[:], item.TokenHash)
			clear(token)
		}
		sent := valid && w.Now().Before(item.Deadline) && w.Provider.Send(ctx, item.Tenant, item.ID, item.Generation, payload) == nil
		if err = w.Store.FinishDelivery(ctx, actor, item, sent, w.Now().UTC()); err != nil {
			return err
		}
	}
	return w.Store.PurgeInvitations(ctx, actor, tenant, w.Now().UTC())
}

package dashboard

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"time"

	"hukid.local/platform/internal/authentication"
)

type ActivityPage struct {
	TenantID    string    `json:"tenantId"`
	IssuerID    *string   `json:"issuerId"`
	GeneratedAt time.Time `json:"generatedAt"`
	Window      Window    `json:"window"`
	AsOf        time.Time `json:"asOf"`
	Items       []Event   `json:"items"`
	NextCursor  *string   `json:"nextCursor"`
}

// Activity uses a dedicated key and domain-separated authenticated encryption.
// Only the binding digest enters the token, keeping even large grant sets bounded.
type Activity struct {
	service *Service
	aead    cipher.AEAD
}

func NewActivity(service *Service, key []byte) (*Activity, error) {
	if service == nil || len(key) != 32 {
		return nil, ErrRequest
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Activity{service, aead}, nil
}

type activityCursor struct {
	Version        int
	Binding        [32]byte
	AsOf, Deadline time.Time
	Position       Position
}

func activityBinding(actor, tenant string, access Access, f Filter) [32]byte {
	access.Roles = slices.Clone(access.Roles)
	access.IssuerIDs = slices.Clone(access.IssuerIDs)
	slices.Sort(access.Roles)
	slices.Sort(access.IssuerIDs)
	f.Cursor = ""
	data, _ := json.Marshal(struct {
		Operation, Actor, Tenant string
		Access                   Access
		Filter                   Filter
	}{"activity", actor, tenant, access, f})
	return sha256.Sum256(data)
}

func (a *Activity) List(ctx context.Context, actor, tenant, raw string) (ActivityPage, error) {
	var page ActivityPage
	err := a.service.ReadActivity(ctx, actor, tenant, raw, func(reader Snapshot, f Filter) error {
		// This callback runs only after live membership/capability/scope checks.
		now := a.service.now().UTC()
		ttl := time.Duration(a.service.policy.CursorSeconds) * time.Second
		binding := activityBinding(actor, tenant, reader.Access(), f)
		c := activityCursor{Version: 1, Binding: binding, AsOf: now, Deadline: now.Add(ttl)}
		if f.Cursor != "" {
			data, err := base64.RawURLEncoding.Strict().DecodeString(f.Cursor)
			if err != nil || len(data) < a.aead.NonceSize()+a.aead.Overhead() {
				return ErrCursor
			}
			plain, err := a.aead.Open(nil, data[:a.aead.NonceSize()], data[a.aead.NonceSize():], []byte("hukid:dashboard:activity:v1"))
			if err != nil || json.Unmarshal(plain, &c) != nil || c.Version != 1 || c.Binding != binding || !now.Before(c.Deadline) || c.AsOf.IsZero() || c.AsOf.After(now) || !c.Deadline.Equal(c.AsOf.Add(ttl)) || !issuerID.MatchString(c.Position.ID) || c.Position.At.Before(f.From) || !c.Position.At.Before(f.To) || c.Position.At.After(c.AsOf) {
				return ErrCursor
			}
		}
		items, err := reader.Activity(ctx, f, c.Position, c.AsOf)
		if err != nil {
			return authentication.ErrDependency
		}
		if items == nil {
			items = []Event{}
		}
		more := len(items) > f.Limit
		if more {
			items = items[:f.Limit]
		}
		page = ActivityPage{TenantID: tenant, GeneratedAt: a.service.now().UTC(), Window: window(f), AsOf: c.AsOf, Items: items}
		if more {
			last := items[len(items)-1]
			c.Position = Position{last.OccurredAt, last.EventID}
			plain, err := json.Marshal(c)
			if err != nil {
				return authentication.ErrDependency
			}
			nonce := make([]byte, a.aead.NonceSize())
			if _, err = rand.Read(nonce); err != nil {
				return authentication.ErrDependency
			}
			next := base64.RawURLEncoding.EncodeToString(a.aead.Seal(nonce, nonce, plain, []byte("hukid:dashboard:activity:v1")))
			page.NextCursor = &next
		}
		return nil
	})
	if err != nil {
		return ActivityPage{}, err
	}
	return page, nil
}

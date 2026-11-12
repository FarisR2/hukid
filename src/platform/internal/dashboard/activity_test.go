package dashboard

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"hukid.local/platform/internal/authentication"
)

type activitySnapshot struct {
	access    Access
	events    []Event
	err       error
	calls     int
	positions []Position
	ceilings  []time.Time
}

func (r *activitySnapshot) Access() Access { return r.access }
func (r *activitySnapshot) GeneratedAt(context.Context) (time.Time, error) {
	panic("activity must keep the application clock for cursor expiry")
}
func (r *activitySnapshot) ActiveMembers(context.Context) (int64, time.Time, error) {
	panic("unexpected members read")
}
func (r *activitySnapshot) Activity(_ context.Context, f Filter, pos Position, asOf time.Time) ([]Event, error) {
	r.calls++
	r.positions = append(r.positions, pos)
	r.ceilings = append(r.ceilings, asOf)
	for i, event := range r.events {
		if event.EventID == pos.ID {
			return r.events[i+1:], r.err
		}
	}
	return r.events, r.err
}

func TestActivityContinuationDoesNotRenewTTL(t *testing.T) {
	origin := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	now := origin
	actor, tenant := "20000000-0000-4000-8000-000000000001", "10000000-0000-4000-8000-000000000001"
	r := &activitySnapshot{access: Access{1, []string{"tenant_admin"}, nil}, events: []Event{
		{EventID: "90000000-0000-4000-8000-000000000003", OccurredAt: origin.Add(-time.Second)},
		{EventID: "90000000-0000-4000-8000-000000000002", OccurredAt: origin.Add(-2 * time.Second)},
		{EventID: "90000000-0000-4000-8000-000000000001", OccurredAt: origin.Add(-3 * time.Second)},
	}}
	s, _ := New(activityStore{r}, testPolicy(), func() time.Time { return now })
	a, _ := NewActivity(s, make([]byte, 32))
	first, err := a.List(context.Background(), actor, tenant, "limit=1")
	if err != nil || first.NextCursor == nil {
		t.Fatal("first page", err)
	}
	q := url.Values{"from": {first.Window.From.Format(time.RFC3339Nano)}, "to": {first.Window.To.Format(time.RFC3339Nano)}, "limit": {"1"}, "cursor": {*first.NextCursor}}
	now = origin.Add(899 * time.Second)
	second, err := a.List(context.Background(), actor, tenant, q.Encode())
	if err != nil || second.NextCursor == nil || !second.AsOf.Equal(origin) || len(second.Items) != 1 || second.Items[0].EventID != r.events[1].EventID {
		t.Fatal("continuation", err)
	}
	q.Set("cursor", *second.NextCursor)
	// A token issued one second before expiry still has the original deadline.
	now = origin.Add(900 * time.Second)
	before := r.calls
	page, err := a.List(context.Background(), actor, tenant, q.Encode())
	if !errors.Is(err, ErrCursor) || r.calls != before || page.Items != nil || page.NextCursor != nil {
		t.Fatal("continuation extended TTL", err)
	}
	now = origin.Add(900*time.Second - time.Nanosecond)
	last, err := a.List(context.Background(), actor, tenant, q.Encode())
	if err != nil || len(last.Items) != 1 || last.NextCursor != nil || !last.AsOf.Equal(origin) {
		t.Fatal("valid deadline boundary rejected", err)
	}
	// Mutate nonce, ciphertext and authentication tag separately.
	token, err := base64.RawURLEncoding.DecodeString(*first.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0, a.aead.NonceSize(), len(token) - 1} {
		changed := append([]byte(nil), token...)
		changed[offset] ^= 1
		q.Set("cursor", base64.RawURLEncoding.EncodeToString(changed))
		before = r.calls
		if _, err := a.List(context.Background(), actor, tenant, q.Encode()); !errors.Is(err, ErrCursor) || r.calls != before {
			t.Fatal("tampered token reached source", offset, err)
		}
	}
}

type activityStore struct{ reader *activitySnapshot }

func (s activityStore) Read(_ context.Context, _, _ string, fn func(Snapshot) error) error {
	return fn(s.reader)
}

func TestActivityCursorBoundToLiveContextAndFixedDeadline(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	origin := now
	actor, tenant := "20000000-0000-4000-8000-000000000001", "10000000-0000-4000-8000-000000000001"
	r := &activitySnapshot{access: Access{1, []string{"tenant_admin"}, nil}, events: []Event{
		{EventID: "90000000-0000-4000-8000-000000000002", OccurredAt: now.Add(-time.Second)},
		{EventID: "90000000-0000-4000-8000-000000000001", OccurredAt: now.Add(-2 * time.Second)},
	}}
	s, _ := New(activityStore{r}, testPolicy(), func() time.Time { return now })
	a, _ := NewActivity(s, make([]byte, 32))
	first, err := a.List(context.Background(), actor, tenant, "limit=1")
	if err != nil || len(first.Items) != 1 || first.NextCursor == nil || len(*first.NextCursor) > 2048 {
		t.Fatal("first page", err)
	}
	q := url.Values{"from": {first.Window.From.Format(time.RFC3339Nano)}, "to": {first.Window.To.Format(time.RFC3339Nano)}, "limit": {"1"}, "cursor": {*first.NextCursor}}
	now = now.Add(time.Minute)
	second, err := a.List(context.Background(), actor, tenant, q.Encode())
	if err != nil || len(second.Items) != 1 || second.NextCursor != nil || !second.AsOf.Equal(first.AsOf) || r.positions[1].ID != first.Items[0].EventID || !r.ceilings[1].Equal(first.AsOf) {
		t.Fatal("second page", err)
	}
	checkDenied := func(actorID, tenantID, query string, want error) {
		t.Helper()
		before := r.calls
		if _, err := a.List(context.Background(), actorID, tenantID, query); !errors.Is(err, want) || r.calls != before {
			t.Fatalf("replay read source: %v", err)
		}
	}
	checkDenied("20000000-0000-4000-8000-000000000002", tenant, q.Encode(), ErrCursor)
	checkDenied(actor, "10000000-0000-4000-8000-000000000002", q.Encode(), ErrCursor)
	for key, value := range map[string]string{"limit": "2", "from": first.Window.From.Add(time.Second).Format(time.RFC3339Nano), "to": first.Window.To.Add(-time.Second).Format(time.RFC3339Nano), "cursor": strings.Repeat("A", len(*first.NextCursor))} {
		changed, _ := url.ParseQuery(q.Encode())
		changed.Set(key, value)
		checkDenied(actor, tenant, changed.Encode(), ErrCursor)
	}
	r.access.Revision++
	checkDenied(actor, tenant, q.Encode(), ErrCursor)
	r.access.Revision--
	r.access.Roles = []string{"security_admin"}
	checkDenied(actor, tenant, q.Encode(), ErrCursor)
	r.access.Roles = []string{"support_readonly"}
	checkDenied(actor, tenant, q.Encode(), ErrForbidden)
	r.access.Roles = []string{"tenant_admin"}
	now = origin.Add(900 * time.Second)
	checkDenied(actor, tenant, q.Encode(), ErrCursor)
	// Rotating the key invalidates outstanding tokens without exposing internals.
	key := make([]byte, 32)
	key[0] = 1
	rotated, _ := NewActivity(s, key)
	now = origin.Add(time.Minute)
	if _, err := rotated.List(context.Background(), actor, tenant, q.Encode()); !errors.Is(err, ErrCursor) {
		t.Fatal(err)
	}
	r.events = nil
	empty, err := a.List(context.Background(), actor, tenant, "")
	if err != nil || empty.Items == nil || len(empty.Items) != 0 || empty.NextCursor != nil {
		t.Fatal("empty", err)
	}
	r.err = errors.New("private SQL details")
	if _, err := a.List(context.Background(), actor, tenant, ""); !errors.Is(err, authentication.ErrDependency) {
		t.Fatal("failure became empty", err)
	}
}

func TestActivityBindingCanonicalizesGrantOrder(t *testing.T) {
	a := Access{1, []string{"tenant_admin", "security_admin"}, []string{"b", "a"}}
	b := Access{1, []string{"security_admin", "tenant_admin"}, []string{"a", "b"}}
	if activityBinding("a", "t", a, Filter{}) != activityBinding("a", "t", b, Filter{}) {
		t.Fatal("order changed binding")
	}
	b.IssuerIDs = []string{"a"}
	if activityBinding("a", "t", a, Filter{}) == activityBinding("a", "t", b, Filter{}) {
		t.Fatal("scope not bound")
	}
}

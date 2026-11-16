package issuance_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hukid.local/platform/internal/issuance"
)

func config() issuance.OfferConfig {
	return issuance.OfferConfig{TTL: time.Minute, Capacity: 2}
}

func store(t *testing.T, cfg issuance.OfferConfig) *issuance.OfferStore {
	t.Helper()
	s, err := issuance.NewOfferStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func create(t *testing.T, s *issuance.OfferStore) issuance.Offer {
	t.Helper()
	o, err := s.Create()
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestConfig(t *testing.T) {
	for _, ttl := range []time.Duration{-1, 0, 300*time.Second + 1} {
		cfg := config()
		cfg.TTL = ttl
		if s, err := issuance.NewOfferStore(cfg); s != nil || err != issuance.ErrConfig {
			t.Fatalf("TTL %v: %v, %v", ttl, s, err)
		}
	}
	for _, capacity := range []int{-1, 0} {
		cfg := config()
		cfg.Capacity = capacity
		if s, err := issuance.NewOfferStore(cfg); s != nil || err != issuance.ErrConfig {
			t.Fatalf("capacity %d: %v, %v", capacity, s, err)
		}
	}
	for _, ttl := range []time.Duration{1, 300 * time.Second} {
		cfg := config()
		cfg.TTL = ttl
		store(t, cfg)
	}
}

func invalid(t *testing.T, s *issuance.OfferStore, code string) {
	t.Helper()
	if got, err := s.Redeem(code); got != (issuance.Redemption{}) || err != issuance.ErrInvalidCode || err.Error() != "invalid pre-authorized code" {
		t.Fatalf("invalid redemption: %+v, %v", got, err)
	}
}

func TestLifecycle(t *testing.T) {
	s := store(t, config())
	o := create(t, s)
	for _, token := range []string{o.Code, o.ID} {
		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil || len(raw) != 32 {
			t.Fatal("expected 32-byte random values")
		}
	}
	if o.ID == o.Code {
		t.Fatal("identity must be independent of code")
	}
	for _, code := range []string{"", "unknown", " " + o.Code, o.Code + "=", strings.Repeat("x", 10000), o.ID} {
		invalid(t, s, code)
	}
	original := o
	o.ID = "caller mutation"
	got, err := s.Redeem(o.Code)
	if err != nil || got.ID != original.ID || got.ExpiresAt != original.ExpiresAt {
		t.Fatalf("redemption: %+v, %v", got, err)
	}
	got.ID = "another caller mutation"
	invalid(t, s, o.Code)
}

func TestExpiry(t *testing.T) {
	for _, exact := range []bool{false, true} {
		t.Run(map[bool]string{false: "just-before", true: "exact"}[exact], func(t *testing.T) {
			now := time.Unix(1700000000, 0)
			cfg := config()
			cfg.Now = func() time.Time { return now }
			s := store(t, cfg)
			o := create(t, s)
			if o.ExpiresAt != now.Add(cfg.TTL) {
				t.Fatal("wrong expiry")
			}
			now = o.ExpiresAt
			if exact {
				invalid(t, s, o.Code)
			} else {
				now = now.Add(-time.Nanosecond)
				if _, err := s.Redeem(o.Code); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestConcurrentRedeemAndCreate(t *testing.T) {
	cfg := config()
	cfg.Capacity = 33
	// bytes.Reader is deliberately not concurrency-safe; store must serialize it.
	cfg.Random = bytes.NewReader(bytes.Repeat([]byte{7}, 64*33))
	s := store(t, cfg)
	o := create(t, s)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if _, err := s.Redeem(o.Code); err == nil {
				successes.Add(1)
			} else if err != issuance.ErrInvalidCode {
				t.Errorf("redeem: %v", err)
			}
			if _, err := s.Create(); err != issuance.ErrCollision {
				t.Errorf("collision: %v", err)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful redemptions: %d", successes.Load())
	}
}

func TestCreationFailuresPreserveState(t *testing.T) {
	for _, scenario := range []string{"entropy", "short-code", "short-id", "live-collision", "redeemed-collision", "identity-collision"} {
		t.Run(scenario, func(t *testing.T) {
			first := append(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)...)
			var tail []byte
			want := issuance.ErrEntropy
			switch scenario {
			case "short-code":
				tail = []byte{3}
			case "short-id":
				tail = bytes.Repeat([]byte{3}, 33)
			case "live-collision", "redeemed-collision":
				tail, want = first, issuance.ErrCollision
			case "identity-collision":
				tail = append(bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{2}, 32)...)
				want = issuance.ErrCollision
			}
			cfg := config()
			entropy := &switchReader{source: io.MultiReader(bytes.NewReader(append(first, tail...)), failureReader{})}
			cfg.Random = entropy
			s := store(t, cfg)
			o := create(t, s)
			if scenario == "redeemed-collision" {
				if _, err := s.Redeem(o.Code); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := s.Create(); got != (issuance.Offer{}) || err != want {
				t.Fatalf("create: %+v, %v; want %v", got, err, want)
			}
			if scenario == "redeemed-collision" {
				invalid(t, s, o.Code)
			} else if got, err := s.Redeem(o.Code); err != nil || got.ID != o.ID {
				t.Fatalf("prior offer changed: %+v, %v", got, err)
			}
			entropy.source = bytes.NewReader(bytes.Repeat([]byte{4}, 64))
			create(t, s) // Failure must not consume the remaining capacity.
		})
	}
}

type switchReader struct{ source io.Reader }

func (r *switchReader) Read(p []byte) (int, error) { return r.source.Read(p) }

type failureReader struct{}

func (failureReader) Read([]byte) (int, error) { return 0, errors.New("private entropy detail") }

func TestCapacityAndReclaim(t *testing.T) {
	for _, redeemed := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "redeemed"}[redeemed], func(t *testing.T) {
			now := time.Unix(1700000000, 0)
			cfg := config()
			cfg.Now = func() time.Time { return now }
			s := store(t, cfg)
			a := create(t, s)
			now = now.Add(time.Second)
			b := create(t, s)
			if redeemed {
				if _, err := s.Redeem(a.Code); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := s.Create(); got != (issuance.Offer{}) || err != issuance.ErrStoreFull {
				t.Fatalf("capacity: %+v, %v", got, err)
			}
			now = a.ExpiresAt
			create(t, s)
			invalid(t, s, a.Code)
			if got, err := s.Redeem(b.Code); err != nil || got.ID != b.ID {
				t.Fatalf("live entry evicted: %+v, %v", got, err)
			}
		})
	}
}

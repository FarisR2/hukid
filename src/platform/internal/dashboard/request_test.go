package dashboard

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestUTCWindowAndPagination(t *testing.T) {
	data, err := os.ReadFile("../../config/dashboard.test.json")
	if err != nil {
		t.Fatal(err)
	}
	var p Policy
	if err = json.Unmarshal(data, &p); err != nil || p.Validate() != nil {
		t.Fatal("invalid test policy", err)
	}
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	f, err := ParseQuery("", true, now, p)
	if err != nil || f.To != now || f.To.Sub(f.From) != 24*time.Hour || f.Limit != 25 {
		t.Fatal(f, err)
	}
	valid := "from=2026-10-06T12:00:00Z&to=2026-11-06T12:00:00Z&limit=100&issuerId=60000000-0000-4000-8000-000000000001&cursor=" + strings.Repeat("A", 32)
	if _, err = ParseQuery(valid, true, now, p); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"from=2026-11-06T12:00:00Z", "to=2026-11-06T12:00:00Z",
		"from=2026-11-06T12:00:00Z&to=2026-11-06T12:00:00Z",
		"from=2026-11-06T12:00:00Z&to=2026-11-05T12:00:00Z",
		"from=2026-10-06T11:59:59Z&to=2026-11-06T12:00:00Z",
		"from=2026-11-05T12:00:00Z&to=2026-11-06T12:00:00.000000001Z",
		"from=2026-02-30T12:00:00Z&to=2026-03-01T12:00:00Z",
		"from=2026-11-05T12:00:00%2B00:00&to=2026-11-06T12:00:00Z",
		"limit=0", "limit=101", "limit=9999999999999999999999", "limit=1.5", "limit=+1", "limit=",
		"limit=1&limit=2", "tenantId=other", "issuerId=UPPERCASE", "issuerId=", "cursor=short", "x=%zz",
		"cursor=" + strings.Repeat("A", 32), strings.Repeat("a", 4097),
	} {
		if _, err = ParseQuery(raw, true, now, p); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"limit=1", "cursor=" + strings.Repeat("A", 32)} {
		if _, err = ParseQuery(raw, false, now, p); err == nil {
			t.Errorf("overview accepted pagination: %s", raw)
		}
	}
	if _, err = ParseQuery("from=2026-11-06T11:59:59.999999999Z&to=2026-11-06T12:00:00Z", false, now, p); err != nil {
		t.Fatal(err)
	}
	for raw, want := range map[string]error{
		"unexpected=1": ErrRequest,
		"limit=101":    ErrInput,
		"cursor=short": ErrCursor,
	} {
		if _, got := ParseQuery(raw, true, now, p); got != want {
			t.Errorf("%s: got %v, want %v", raw, got, want)
		}
	}
	for _, size := range []int{31, 2049} {
		if _, err = ParseQuery("from=2026-11-05T12:00:00Z&to=2026-11-06T12:00:00Z&cursor="+strings.Repeat("A", size), true, now, p); err != ErrCursor {
			t.Errorf("accepted cursor length %d", size)
		}
	}
	p.Environment = "production"
	if _, err = ParseQuery("", false, now, p); err == nil {
		t.Fatal("accepted production profile")
	}
}

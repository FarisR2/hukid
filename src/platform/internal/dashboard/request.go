// Package dashboard defines contract rules only; no operational sources are connected.
package dashboard

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

var (
	ErrRequest = errors.New("invalid dashboard request")
	ErrInput   = errors.New("invalid dashboard input")
	ErrCursor  = errors.New("invalid dashboard cursor")
)

// Policy is an explicit isolated-test profile, not wired into the runtime yet.
type Policy struct {
	Environment          string `json:"environment"`
	DefaultWindowSeconds int    `json:"defaultWindowSeconds"`
	MaxWindowSeconds     int    `json:"maxWindowSeconds"`
	DefaultPageSize      int    `json:"defaultPageSize"`
	MaxPageSize          int    `json:"maxPageSize"`
	CursorSeconds        int    `json:"cursorSeconds"`
	StaleAfterSeconds    int    `json:"staleAfterSeconds"`
	MaxQueryBytes        int    `json:"maxQueryBytes"`
}

func (p Policy) Validate() error {
	if p.Environment != "test" || p.DefaultWindowSeconds != 86400 || p.MaxWindowSeconds != 2678400 || p.DefaultPageSize != 25 || p.MaxPageSize != 100 || p.CursorSeconds != 900 || p.StaleAfterSeconds != 300 || p.MaxQueryBytes != 4096 {
		return ErrRequest
	}
	return nil
}

type Filter struct {
	From, To time.Time
	IssuerID string
	Cursor   string
	Limit    int
}

var (
	utcTime    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`)
	issuerID   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	cursorText = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	pageSize   = regexp.MustCompile(`^[0-9]+$`)
)

// ParseQuery validates shape and UTC bounds, never issuer ownership or cursor
// authenticity. Adapters must authorize selectors and authenticate cursors later.
func ParseQuery(raw string, activity bool, now time.Time, p Policy) (Filter, error) {
	f := Filter{}
	if p.Validate() != nil || now.IsZero() || len(raw) > p.MaxQueryBytes {
		return f, ErrRequest
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return f, ErrRequest
	}
	for key, values := range values {
		allowed := key == "from" || key == "to" || key == "issuerId" || activity && (key == "cursor" || key == "limit")
		if !allowed || len(values) != 1 || values[0] == "" {
			return f, ErrRequest
		}
	}
	f.To = now.UTC()
	f.From = f.To.Add(-time.Duration(p.DefaultWindowSeconds) * time.Second)
	if values.Has("from") || values.Has("to") {
		if !utcTime.MatchString(values.Get("from")) || !utcTime.MatchString(values.Get("to")) {
			return Filter{}, ErrInput
		}
		f.From, err = time.Parse(time.RFC3339Nano, values.Get("from"))
		if err != nil {
			return Filter{}, ErrInput
		}
		f.To, err = time.Parse(time.RFC3339Nano, values.Get("to"))
		if err != nil || !f.From.Before(f.To) || f.To.After(now) || f.To.Sub(f.From) > time.Duration(p.MaxWindowSeconds)*time.Second {
			return Filter{}, ErrInput
		}
	}
	f.IssuerID = values.Get("issuerId")
	if f.IssuerID != "" && !issuerID.MatchString(f.IssuerID) {
		return Filter{}, ErrInput
	}
	f.Cursor = values.Get("cursor")
	if f.Cursor != "" && (len(f.Cursor) < 32 || len(f.Cursor) > 2048 || !cursorText.MatchString(f.Cursor) || !values.Has("from") || !values.Has("to")) {
		return Filter{}, ErrCursor
	}
	if activity {
		f.Limit = p.DefaultPageSize
		if values.Has("limit") {
			if !pageSize.MatchString(values.Get("limit")) {
				return Filter{}, ErrInput
			}
			f.Limit, err = strconv.Atoi(values.Get("limit"))
			if err != nil || f.Limit < 1 || f.Limit > p.MaxPageSize {
				return Filter{}, ErrInput
			}
		}
	}
	return f, nil
}

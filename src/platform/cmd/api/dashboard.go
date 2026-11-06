package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	consolehttp "hukid.local/platform/internal/adapters/console"
	"hukid.local/platform/internal/adapters/postgres"
	"hukid.local/platform/internal/adapters/privateapi"
	"hukid.local/platform/internal/dashboard"
)

type dashboardConfig struct {
	DSN    string
	Key    []byte
	Policy dashboard.Policy
}

func loadDashboardConfiguration() (*dashboardConfig, error) {
	dsn, path, raw := os.Getenv("HUKID_DASHBOARD_DATABASE_URL"), os.Getenv("HUKID_DASHBOARD_POLICY"), os.Getenv("HUKID_DASHBOARD_CURSOR_KEY")
	if dsn == "" && path == "" && raw == "" {
		return nil, nil
	}
	invalid := errors.New("complete isolated dashboard configuration required")
	if dsn == "" || path == "" || raw == "" || os.Getenv("HUKID_ENV") != "test" || os.Getenv("HUKID_AUTH_POLICY") == "" || postgres.ValidateLoginDatabase(dsn) != nil {
		return nil, invalid
	}
	key, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, invalid
	}
	file, err := os.Open(path)
	if err != nil {
		clear(key)
		return nil, invalid
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(data) > 8192 {
		clear(key)
		return nil, invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var p dashboard.Policy
	if decoder.Decode(&p) != nil || decoder.Decode(new(any)) != io.EOF || p.Validate() != nil {
		clear(key)
		return nil, invalid
	}
	return &dashboardConfig{dsn, key, p}, nil
}

func configureDashboard(ctx context.Context, operators *privateapi.Handler, me *consolehttp.MeHandler) (func(*http.ServeMux), func(), error) {
	c, err := loadDashboardConfiguration()
	if err != nil {
		return nil, nil, err
	}
	if c == nil {
		return func(*http.ServeMux) {}, func() {}, nil
	}
	defer clear(c.Key)
	pool, err := postgres.OpenRuntimePool(ctx, c.DSN, "hukid_dashboard_runtime", 4)
	if err != nil {
		return nil, nil, err
	}
	service, err := dashboard.New(&postgres.DashboardStore{Pool: pool}, c.Policy, time.Now)
	if err != nil {
		pool.Close()
		return nil, nil, err
	}
	activity, err := dashboard.NewActivity(service, c.Key)
	if err != nil {
		pool.Close()
		return nil, nil, err
	}
	management := &privateapi.DashboardHandler{Operators: operators, Overview: service, Activity: activity}
	browser := &consolehttp.DashboardHandler{Auth: me, Management: management}
	return func(mux *http.ServeMux) { management.Register(mux); browser.Register(mux) }, pool.Close, nil
}

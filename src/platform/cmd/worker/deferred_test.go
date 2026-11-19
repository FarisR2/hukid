package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestParseDeferredWorkerArgs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		want  string
		limit int
		valid bool
	}{
		{name: "default batch", args: []string{"tenant-1"}, want: "tenant-1", limit: defaultDeferredBatchSize, valid: true},
		{name: "bounded batch", args: []string{"tenant-1", "7"}, want: "tenant-1", limit: 7, valid: true},
		{name: "reject empty tenant", args: []string{" "}},
		{name: "reject zero batch", args: []string{"tenant-1", "0"}},
		{name: "reject oversized batch", args: []string{"tenant-1", "501"}},
		{name: "reject extra arguments", args: []string{"tenant-1", "2", "extra"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenant, limit, err := parseDeferredWorkerArgs(tc.args)
			if tc.valid {
				if err != nil || tenant != tc.want || limit != tc.limit {
					t.Fatalf("parseDeferredWorkerArgs() = %q, %d, %v", tenant, limit, err)
				}
			} else if err == nil {
				t.Fatalf("parseDeferredWorkerArgs(%v) unexpectedly succeeded", tc.args)
			}
		})
	}
}

func TestParseDeferredWorkerOptionsWithInterval(t *testing.T) {
	opts, err := parseDeferredWorkerOptions([]string{"tenant-1", "25", "--interval=5s"})
	if err != nil || opts.tenantID != "tenant-1" || opts.limit != 25 || opts.interval != 5*time.Second {
		t.Fatalf("unexpected options: %+v, err=%v", opts, err)
	}
	opts, err = parseDeferredWorkerOptions([]string{"--interval", "1m", "tenant-2"})
	if err != nil || opts.tenantID != "tenant-2" || opts.limit != defaultDeferredBatchSize || opts.interval != time.Minute {
		t.Fatalf("unexpected space-separated options: %+v, err=%v", opts, err)
	}
	for _, bad := range [][]string{
		{"tenant-1", "--interval=500ms"},
		{"tenant-1", "--interval=2h"},
		{"tenant-1", "--interval=not-a-dur"},
		{"tenant-1", "--interval=5s", "--interval=10s"},
		{"tenant-1", "--unknown=1"},
	} {
		if _, err := parseDeferredWorkerOptions(bad); err == nil {
			t.Fatalf("expected error for %v", bad)
		}
	}
}

func TestRunDeferredSchedulerOneShotAndLoop(t *testing.T) {
	calls := 0
	if err := runDeferredScheduler(context.Background(), 0, func(context.Context) error {
		calls++
		return nil
	}); err != nil || calls != 1 {
		t.Fatalf("one-shot failed: calls=%d err=%v", calls, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loopCalls := 0
	if err := runDeferredScheduler(ctx, 5*time.Millisecond, func(context.Context) error {
		loopCalls++
		if loopCalls >= 3 {
			cancel()
		}
		return nil
	}); err != nil || loopCalls < 3 {
		t.Fatalf("scheduler loop failed: calls=%d err=%v", loopCalls, err)
	}

	wantErr := errors.New("boom")
	if err := runDeferredScheduler(context.Background(), 5*time.Millisecond, func(context.Context) error {
		return wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("expected %v, got %v", wantErr, err)
	}
}

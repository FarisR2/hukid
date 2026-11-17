package main

import "testing"

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

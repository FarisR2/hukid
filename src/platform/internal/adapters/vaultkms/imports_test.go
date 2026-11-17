package vaultkms

import (
	"go/parser"
	gotoken "go/token"
	"path/filepath"
	"strings"
	"testing"
)

var forbidden = map[string]string{
	"hukid.local/platform/internal/authentication": "token classes must stay separate",
	"log":           "logging must not leak KMS tokens or DEKs",
	"log/slog":      "logging must not leak KMS tokens or DEKs",
	"runtime/debug": "stack output must not leak KMS tokens or DEKs",
	"database/sql":  "KMS adapter has no direct SQL dependency",
	"os":            "environment lookups belong to cmd/api",
}

func TestVaultKMSPackageBoundaries(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no sources found: %v", err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(gotoken.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			p := strings.Trim(spec.Path.Value, `"`)
			if reason, bad := forbidden[p]; bad {
				t.Errorf("%s imports %s (%s)", name, p, reason)
			}
		}
	}
}

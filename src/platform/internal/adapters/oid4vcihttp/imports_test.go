package oid4vcihttp

import (
	"go/parser"
	gotoken "go/token"
	"path/filepath"
	"strings"
	"testing"
)

// The HTTP adapter must stay separated from console authentication, logging,
// database drivers and environment lookups.
var forbidden = map[string]string{
	"hukid.local/platform/internal/authentication": "token classes must stay separate (profile 6)",
	"log":           "logging must not leak issuance material",
	"log/slog":      "logging must not leak issuance material",
	"runtime/debug": "stack output must not leak issuance material",
	"database/sql":  "persistence belongs behind ports",
	"os":            "file-system or environment access belongs to cmd/api",
}

func TestPackageDoesNotLogOrTouchConsoleAuthentication(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no sources: %v", err)
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
			path := strings.Trim(spec.Path.Value, `"`)
			if reason, bad := forbidden[path]; bad {
				t.Errorf("%s imports %s (%s)", name, path, reason)
			}
		}
	}
}

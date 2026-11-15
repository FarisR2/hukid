package oid4vphttp

import (
	"go/parser"
	gotoken "go/token"
	"path/filepath"
	"strings"
	"testing"
)

// The endpoints carry a vp_token, so the package must not log, print or reach
// console authentication (profile section 6: token classes stay separate).
var forbidden = map[string]string{
	"hukid.local/platform/internal/authentication": "token classes must stay separate (profile 6)",
	"log":           "logging could leak the vp_token",
	"log/slog":      "logging could leak the vp_token",
	"runtime/debug": "stack output could leak the vp_token",
	"database/sql":  "persistence belongs to the stores behind the ports",
	"os":            "file-system or environment access",
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

package jwksresolver

import (
	"go/parser"
	gotoken "go/token"
	"path/filepath"
	"strings"
	"testing"
)

// The resolver reads remote key sets, so it must not log (a response body could
// reach the logs), touch the file system or reach console authentication
// (profile section 6: token classes stay separate).
var forbidden = map[string]string{
	"hukid.local/platform/internal/authentication": "token classes must stay separate (profile 6)",
	"log":           "logging could leak remote content",
	"log/slog":      "logging could leak remote content",
	"runtime/debug": "stack output could leak remote content",
	"database/sql":  "persistence is not this adapter's job",
	"os":            "file-system or environment access",
	"os/exec":       "process execution",
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

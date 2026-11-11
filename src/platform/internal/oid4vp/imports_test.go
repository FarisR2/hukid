package oid4vp

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// This increment of the adapter is pure. It may import the standard library,
// the verification core and go-jose; it must not import console
// authentication (profile section 6, ADR-0031 #1), reach the network, a
// database or the file system, or print (the response carries a vp_token).
var forbiddenImports = map[string]string{
	"hukid.local/platform/internal/authentication": "token classes must stay separate (profile 6)",
	"net":           "network access belongs to a later increment",
	"net/http":      "endpoints belong to a later increment",
	"database/sql":  "persistence belongs to a later increment",
	"os":            "file-system or environment access",
	"os/exec":       "process execution",
	"io/ioutil":     "file-system access",
	"log":           "logging could leak the vp_token",
	"log/slog":      "logging could leak the vp_token",
	"runtime/debug": "stack output could leak the vp_token",
}

var allowedThirdParty = map[string]bool{
	"github.com/go-jose/go-jose/v4":              true,
	"hukid.local/platform/internal/verification": true,
}

var forbiddenFmtCalls = map[string]bool{"Print": true, "Printf": true, "Println": true, "Fprint": true, "Fprintf": true, "Fprintln": true}

func sourceViolations(filename string, src any) []string {
	fset := gotoken.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	if err != nil {
		return []string{filename + ": cannot parse: " + err.Error()}
	}
	var violations []string
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		switch {
		case forbiddenImports[path] != "":
			violations = append(violations, filename+": imports "+path+" ("+forbiddenImports[path]+")")
		case strings.Contains(strings.SplitN(path, "/", 2)[0], ".") && !allowedThirdParty[path]:
			violations = append(violations, filename+": imports "+path+" (not on the allowlist)")
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "fmt" && forbiddenFmtCalls[sel.Sel.Name] {
					violations = append(violations, filename+": calls fmt."+sel.Sel.Name)
				}
			}
		}
		return true
	})
	return violations
}

func TestPackageRespectsTheImportRules(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no sources found: %v", err)
	}
	sort.Strings(files)
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		if v := sourceViolations(name, nil); len(v) > 0 {
			t.Errorf("%s", strings.Join(v, "\n"))
		}
	}
}

func TestImportRuleDetectsViolations(t *testing.T) {
	bad := map[string]string{
		"authentication": `package x; import _ "hukid.local/platform/internal/authentication"`,
		"net/http":       `package x; import _ "net/http"`,
		"log":            `package x; import _ "log"`,
		"unlisted":       `package x; import _ "github.com/example/lib"`,
		"print":          `package x; import "fmt"; func f() { fmt.Println("x") }`,
	}
	for name, src := range bad {
		if len(sourceViolations(name+".go", src)) == 0 {
			t.Errorf("%s: violation not detected", name)
		}
	}
	good := `package x; import (_ "github.com/go-jose/go-jose/v4"; _ "hukid.local/platform/internal/verification"; "fmt"); func f() error { return fmt.Errorf("x") }`
	if v := sourceViolations("good.go", good); len(v) != 0 {
		t.Errorf("false positive: %v", v)
	}
}

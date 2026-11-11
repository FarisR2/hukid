package verification

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// forbiddenStdlib are standard-library packages the core must not use: network,
// database, process, file-system and logging access. The core receives keys,
// time, trust and replay state through ports and reports through return
// values only (VER-QR01, VER-QR04, VER-FR08).
var forbiddenStdlib = map[string]string{
	"net":           "network access",
	"net/http":      "network access",
	"net/url":       "network-oriented parsing is not needed by the core",
	"database/sql":  "database access",
	"os":            "file-system or environment access",
	"os/exec":       "process execution",
	"io/ioutil":     "file-system access",
	"log":           "logging could leak credential material",
	"log/slog":      "logging could leak credential material",
	"runtime/debug": "stack output could leak credential material",
}

var forbiddenFmtCalls = map[string]bool{"Print": true, "Printf": true, "Println": true, "Fprint": true, "Fprintf": true, "Fprintln": true}

// sourceViolations returns the rule violations of one Go source file. Every
// import must be standard library (no dependency on other platform packages,
// in particular internal/authentication, nor third-party code) and none may
// be in forbiddenStdlib; the code must not print.
func sourceViolations(filename string, src any) []string {
	fset := gotoken.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	if err != nil {
		return []string{filename + ": cannot parse: " + err.Error()}
	}
	var violations []string
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		firstElement := strings.SplitN(path, "/", 2)[0]
		switch {
		case strings.Contains(firstElement, "."):
			violations = append(violations, filename+": imports non-standard package "+path)
		case forbiddenStdlib[path] != "":
			violations = append(violations, filename+": imports "+path+" ("+forbiddenStdlib[path]+")")
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "fmt" && forbiddenFmtCalls[sel.Sel.Name] {
				violations = append(violations, filename+": calls fmt."+sel.Sel.Name)
			}
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && (ident.Name == "print" || ident.Name == "println") {
			violations = append(violations, filename+": calls builtin "+ident.Name)
		}
		return true
	})
	return violations
}

func TestPackageStaysPureAndSilent(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var checked []string
	var violations []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked = append(checked, name)
		violations = append(violations, sourceViolations(filepath.Join(".", name), nil)...)
	}
	sort.Strings(checked)
	if len(checked) < 8 {
		t.Fatalf("expected the package sources to be inspected, got %v", checked)
	}
	if len(violations) > 0 {
		t.Fatalf("the verification core must stay free of network, database, process, file, log and platform dependencies:\n%s", strings.Join(violations, "\n"))
	}
}

// TestTheImportRuleCanFail proves the check above is not vacuous: sources that
// break each rule are reported.
func TestTheImportRuleCanFail(t *testing.T) {
	cases := map[string]string{
		"net/http":                 "package p\nimport \"net/http\"\nvar _ = http.StatusOK\n",
		"net":                      "package p\nimport \"net\"\nvar _ net.Conn\n",
		"database/sql":             "package p\nimport \"database/sql\"\nvar _ sql.DB\n",
		"os":                       "package p\nimport \"os\"\nvar _ = os.Args\n",
		"os/exec":                  "package p\nimport \"os/exec\"\nvar _ = exec.Command\n",
		"log":                      "package p\nimport \"log\"\nvar _ = log.Println\n",
		"log/slog":                 "package p\nimport \"log/slog\"\nvar _ = slog.Info\n",
		"authentication package":   "package p\nimport \"hukid.local/platform/internal/authentication\"\nvar _ = authentication.X\n",
		"another platform package": "package p\nimport \"hukid.local/platform/internal/tenancy\"\nvar _ = tenancy.X\n",
		"third-party package":      "package p\nimport \"github.com/jackc/pgx/v5\"\nvar _ = pgx.X\n",
		"fmt.Println":              "package p\nimport \"fmt\"\nfunc f() { fmt.Println(1) }\n",
		"fmt.Fprintf":              "package p\nimport \"fmt\"\nfunc f() { fmt.Fprintf(nil, \"x\") }\n",
		"builtin println":          "package p\nfunc f() { println(1) }\n",
	}
	for name, src := range cases {
		if got := sourceViolations(name+".go", src); len(got) == 0 {
			t.Fatalf("%s: the rule did not flag a violating source", name)
		}
	}
	allowed := "package p\nimport (\n\t\"crypto/ecdsa\"\n\t\"fmt\"\n\t\"errors\"\n)\nvar _ = ecdsa.PublicKey{}\nvar _ = errors.New\nfunc f() error { return fmt.Errorf(\"x\") }\nfunc g() string { return fmt.Sprintf(\"x\") }\n"
	if got := sourceViolations("allowed.go", allowed); len(got) != 0 {
		t.Fatalf("fmt.Errorf, fmt.Sprintf and crypto imports must stay allowed, got %v", got)
	}
}

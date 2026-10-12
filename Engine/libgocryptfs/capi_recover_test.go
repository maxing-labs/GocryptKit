package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

type cExport struct {
	fn   *ast.FuncDecl
	file string
}

// cExports returns every //export in the package's non-test files, by name.
// D-7: every file is scanned, not only capi_c.go.
func cExports(t *testing.T) map[string]cExport {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	exports := map[string]cExport{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Doc == nil || !strings.Contains(fn.Doc.Text()+commentText(fn.Doc), "export "+fn.Name.Name) {
				continue
			}
			exports[fn.Name.Name] = cExport{fn: fn, file: name}
		}
	}
	if len(exports) < 20 {
		t.Fatalf("found only %d exports; the scan is broken", len(exports))
	}
	return exports
}

// Every export must open with `defer recoverTo(...)` / `defer recoverVoid()`.
// A panic escaping the C boundary kills the host FSKit extension process.
func TestEveryCExportRecovers(t *testing.T) {
	for name, e := range cExports(t) {
		if len(e.fn.Body.List) == 0 || !isRecoverDefer(e.fn.Body.List[0]) {
			t.Errorf("%s (%s) does not start with a deferred recover", name, e.file)
		}
	}
}

// Doc.Text() drops directive-style comments such as "//export name".
func commentText(group *ast.CommentGroup) string {
	var b strings.Builder
	for _, c := range group.List {
		b.WriteString(strings.TrimPrefix(c.Text, "//"))
		b.WriteString("\n")
	}
	return b.String()
}

func isRecoverDefer(stmt ast.Stmt) bool {
	d, ok := stmt.(*ast.DeferStmt)
	if !ok {
		return false
	}
	name, ok := d.Call.Fun.(*ast.Ident)
	return ok && (name.Name == "recoverTo" || name.Name == "recoverVoid")
}

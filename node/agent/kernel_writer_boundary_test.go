package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Ban-map mutations must remain inside the checked UEE adapter. This catches
// newly introduced direct writers even when their code path is not exercised
// by an ordinary unit test.
func TestBanMapHasOneWriter(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Clean(name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			method, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (method.Sel.Name != "Put" && method.Sel.Name != "Delete") {
				return true
			}
			object, ok := method.X.(*ast.SelectorExpr)
			if !ok || (object.Sel.Name != "BanMap" && object.Sel.Name != "BanMapV6") {
				return true
			}
			if name != "uee_kernel_adapter.go" {
				t.Errorf("%s writes %s outside the UEE kernel adapter", name, object.Sel.Name)
			}
			return true
		})
	}
}

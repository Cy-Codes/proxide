package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate go.mod walking up from working directory")
		}
		dir = parent
	}
}

func TestPackageDependencyBoundaries(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	fset := token.NewFileSet()

	modelForbidden := map[string]bool{
		"os":          true,
		"os/exec":     true,
		"net":         true,
		"net/http":    true,
		"crypto/tls":  true,
		"crypto/x509": true,
		"io/fs":       true,
	}

	corePackages := map[string]bool{
		"internal/ca":        true,
		"internal/clientreg": true,
		"internal/portal":    true,
		"internal/rewrite":   true,
		"internal/bus":       true,
		"internal/tlsmitm":   true,
	}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		pkgDir := filepath.ToSlash(filepath.Dir(relSlash))
		isTest := strings.HasSuffix(relSlash, "_test.go")

		fileAST, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse imports %s: %v", relSlash, err)
		}

		for _, imp := range fileAST.Imports {
			impPath := strings.Trim(imp.Path.Value, `"`)

			if pkgDir == "internal/model" {
				if strings.HasPrefix(impPath, "proxide/internal/") {
					t.Errorf("%s: internal/model must not import %s", relSlash, impPath)
				}
				if modelForbidden[impPath] {
					t.Errorf("%s: internal/model must stay pure (forbidden import %s)", relSlash, impPath)
				}
			}

			if corePackages[pkgDir] && !isTest {
				if impPath == "proxide/internal/proxy" || impPath == "proxide/internal/api" {
					t.Errorf("%s: core package %s must not import %s", relSlash, pkgDir, impPath)
				}
			}

			if pkgDir == "internal/proxy" && !isTest {
				if impPath == "proxide/internal/api" {
					t.Errorf("%s: internal/proxy must not import internal/api", relSlash)
				}
			}

			if pkgDir == "internal/api" && !isTest {
				if impPath == "proxide/internal/proxy" || impPath == "proxide/internal/portal" {
					t.Errorf("%s: internal/api must not import %s", relSlash, impPath)
				}
			}
		}

		if !isTest {
			fullAST, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse AST %s: %v", relSlash, err)
			}
			ast.Inspect(fullAST, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok || ident.Name != "http" {
					return true
				}
				if sel.Sel.Name == "DefaultClient" || sel.Sel.Name == "DefaultServeMux" {
					t.Errorf("%s: forbidden global http.%s usage", relSlash, sel.Sel.Name)
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
}

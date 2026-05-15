package tool_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/tool"
)

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := tool.NewRegistry()
	lf := tool.NewListFiles("/tmp")
	r.Register(lf)

	got, ok := r.Get("list_files")
	if !ok {
		t.Fatalf("list_files not found")
	}
	if got.Name() != "list_files" {
		t.Errorf("name = %q", got.Name())
	}
}

func TestRegistry_DeclsExposeAllRegistered(t *testing.T) {
	r := tool.NewRegistry()
	r.Register(tool.NewListFiles("/tmp"))
	decls := r.Decls()
	if len(decls) != 1 {
		t.Fatalf("decls = %d, want 1", len(decls))
	}
	if decls[0].Name != "list_files" {
		t.Errorf("decl name = %q", decls[0].Name)
	}
	if decls[0].Description == "" {
		t.Error("decl description must be set")
	}
	if decls[0].Schema == nil {
		t.Error("decl schema must be set")
	}
}

func TestListFiles_ReturnsRepoRelativePaths(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.go"), "package main\n")
	mustWrite(t, filepath.Join(root, "pkg/a/file.go"), "package a\n")
	mustWrite(t, filepath.Join(root, "pkg/b/file.go"), "package b\n")

	lf := tool.NewListFiles(root)
	out, err := lf.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	for _, want := range []string{"main.go", "pkg/a/file.go", "pkg/b/file.go"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}

func TestListFiles_RejectsEscapeAttempt(t *testing.T) {
	root := t.TempDir()
	lf := tool.NewListFiles(root)
	if _, err := lf.Execute(context.Background(), map[string]any{"path": "../"}); err == nil {
		t.Error("expected error when path escapes root")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

package tool_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

// sessionWith returns a Session pre-rooted at root, the common setup pattern.
func sessionWith(root string) *session.Session {
	s := session.New()
	s.SetRoot(root)
	return s
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := tool.NewRegistry()
	lf := tool.NewListFiles(sessionWith("/tmp"))
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
	r.Register(tool.NewListFiles(sessionWith("/tmp")))
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

func TestRegistry_AdmissionIsAPerToolDecision(t *testing.T) {
	// Admission onto an external surface is a decision someone makes per Tool
	// (ADR 0023): registering is not it. What the surface then does with the
	// admitted Tools is asserted through the MCP protocol (pkg/channel/mcp);
	// what is asserted here is the half a client cannot see — that a merely
	// registered Tool stays available to Argus's own agent loop.
	r := tool.NewRegistry()
	r.Register(tool.NewListFiles(sessionWith("/tmp")))
	r.Expose(tool.NewListContext(t.TempDir()))

	if got := exposedNames(r); len(got) != 1 || got[0] != "list_context" {
		t.Errorf("Exposed() = %v, want [list_context]: registration alone must never admit a Tool", got)
	}
	for _, name := range []string{"list_files", "list_context"} {
		if _, ok := r.Get(name); !ok {
			t.Errorf("%q must stay callable by Argus's own agent loop whatever its admission", name)
		}
	}
}

func TestRegistry_WithCarriesTheAdmissionDecision(t *testing.T) {
	// A per-run copy (a channel layering request-scoped tools) must not silently
	// widen or narrow what the surface serves.
	r := tool.NewRegistry()
	r.Expose(tool.NewListContext(t.TempDir()))
	copied := r.With(tool.NewListFiles(sessionWith("/tmp")))

	if got := exposedNames(copied); len(got) != 1 || got[0] != "list_context" {
		t.Errorf("Exposed() on the copy = %v, want [list_context]", got)
	}
}

// exposedNames is the names of the Tools a Registry admits, in order.
func exposedNames(r *tool.Registry) []string {
	names := make([]string, 0)
	for _, tl := range r.Exposed() {
		names = append(names, tl.Name())
	}
	return names
}

func TestListFiles_ReturnsRepoRelativePaths(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.go"), "package main\n")
	mustWrite(t, filepath.Join(root, "pkg/a/file.go"), "package a\n")
	mustWrite(t, filepath.Join(root, "pkg/b/file.go"), "package b\n")

	lf := tool.NewListFiles(sessionWith(root))
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
	lf := tool.NewListFiles(sessionWith(root))
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

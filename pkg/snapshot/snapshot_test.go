package snapshot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspace_MaterializesFilesAtRelativePaths(t *testing.T) {
	ws, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.Close() })

	files := []File{
		{Path: "main.go", Content: "package main\n"},
		{Path: "internal/auth/login.go", Content: "package auth\n"},
	}
	if err := ws.Add(files); err != nil {
		t.Fatalf("Add: %v", err)
	}

	for _, f := range files {
		got, err := os.ReadFile(filepath.Join(ws.Path(), filepath.FromSlash(f.Path)))
		if err != nil {
			t.Fatalf("read %s: %v", f.Path, err)
		}
		if string(got) != f.Content {
			t.Errorf("%s content = %q, want %q", f.Path, got, f.Content)
		}
		if !ws.Has(f.Path) {
			t.Errorf("Has(%q) = false, want true", f.Path)
		}
	}
	if ws.Has("not/added.go") {
		t.Error("Has reported a file that was never added")
	}
}

func TestWorkspace_AddAccumulatesAcrossCalls(t *testing.T) {
	ws, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.Close() })

	if err := ws.Add([]File{{Path: "a.go", Content: "first\n"}}); err != nil {
		t.Fatal(err)
	}
	if err := ws.Add([]File{{Path: "b.go", Content: "second\n"}}); err != nil {
		t.Fatal(err)
	}

	// The follow-up Add must not disturb the file from the first call.
	if !ws.Has("a.go") || !ws.Has("b.go") {
		t.Fatalf("accumulation lost a file: a=%v b=%v", ws.Has("a.go"), ws.Has("b.go"))
	}
	got, err := os.ReadFile(filepath.Join(ws.Path(), "a.go"))
	if err != nil || string(got) != "first\n" {
		t.Errorf("a.go after second Add = %q, %v", got, err)
	}
}

func TestWorkspace_CleanupRemovesScratchCheckout(t *testing.T) {
	ws, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.Add([]File{{Path: "x.go", Content: "x\n"}}); err != nil {
		t.Fatal(err)
	}
	root := ws.Path()

	if err := ws.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("workspace root still exists after Close: stat err = %v", err)
	}
	// Close is idempotent and Path is now empty.
	if err := ws.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if ws.Path() != "" {
		t.Errorf("Path after Close = %q, want empty", ws.Path())
	}
}

func TestWorkspace_RejectsEscapingPaths(t *testing.T) {
	ws, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.Close() })

	for _, bad := range []string{"../escape.go", "../../etc/passwd", "/etc/passwd", "a/../../b.go", ""} {
		if err := ws.Add([]File{{Path: bad, Content: "x"}}); err == nil {
			t.Errorf("Add(%q) = nil, want rejection", bad)
		}
	}
	// A traversal that stays within the root is fine ("a/../b.go" → "b.go").
	if err := ws.Add([]File{{Path: "a/../b.go", Content: "ok\n"}}); err != nil {
		t.Errorf("Add(in-root traversal) = %v, want nil", err)
	}
	if !ws.Has("b.go") {
		t.Error("in-root traversal did not land at the cleaned path")
	}
}

func TestWorkspace_AddAfterCloseFails(t *testing.T) {
	ws, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ws.Add([]File{{Path: "a.go", Content: "x"}}); err == nil {
		t.Error("Add after Close = nil, want error")
	}
}

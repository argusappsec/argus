package tool_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/tool"
)

func TestListContext_ListsMarkdownFilesOnly(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "architecture.md"), "# Architecture\n")
	mustWrite(t, filepath.Join(dir, "threat-model.md"), "# Threats\n")
	mustWrite(t, filepath.Join(dir, "ignore.txt"), "not markdown\n")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}

	lc := tool.NewListContext(dir)
	out, err := lc.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out, "architecture.md") || !strings.Contains(out, "threat-model.md") {
		t.Errorf("missing expected files: %q", out)
	}
	if strings.Contains(out, "ignore.txt") {
		t.Errorf("non-markdown file listed: %q", out)
	}
	if strings.Contains(out, "sub") {
		t.Errorf("subdirectory listed: %q", out)
	}
}

func TestListContext_MissingDirIsEmpty(t *testing.T) {
	lc := tool.NewListContext(filepath.Join(t.TempDir(), "missing"))
	out, err := lc.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("missing dir should not error: %v", err)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("missing dir should yield empty, got %q", out)
	}
}

func TestReadContext_ReturnsFileContent(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "architecture.md"), "# Architecture\nWe use microservices.\n")

	rc := tool.NewReadContext(dir)
	out, err := rc.Execute(context.Background(), map[string]any{"name": "architecture.md"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out, "microservices") {
		t.Errorf("output = %q", out)
	}
}

func TestReadContext_AcceptsNameWithoutExtension(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "threat-model.md"), "BODY")
	rc := tool.NewReadContext(dir)
	out, err := rc.Execute(context.Background(), map[string]any{"name": "threat-model"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out, "BODY") {
		t.Errorf("name without .md extension should still resolve: %q", out)
	}
}

func TestReadContext_RejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	rc := tool.NewReadContext(dir)
	for _, bad := range []string{"../etc/passwd", "../../secret", "subdir/../../escape"} {
		if _, err := rc.Execute(context.Background(), map[string]any{"name": bad}); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

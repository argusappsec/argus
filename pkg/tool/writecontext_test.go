package tool_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/tool"
)

func TestWriteContext_TracerCreatesFile(t *testing.T) {
	dir := t.TempDir()
	wc := tool.NewWriteContext(dir)

	out, err := wc.Execute(context.Background(), map[string]any{
		"name":    "architecture",
		"content": "# Architecture\n\nWe run microservices on EKS.\n",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if out == "" {
		t.Error("expected a confirmation message")
	}

	body, err := os.ReadFile(filepath.Join(dir, "architecture.md"))
	if err != nil {
		t.Fatalf("file not created: %v", err)
	}
	if !strings.Contains(string(body), "microservices on EKS") {
		t.Errorf("content not persisted: %q", body)
	}
}

func TestWriteContext_AcceptsNameWithExtension(t *testing.T) {
	dir := t.TempDir()
	wc := tool.NewWriteContext(dir)
	if _, err := wc.Execute(context.Background(), map[string]any{
		"name":    "threat-model.md",
		"content": "BODY",
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "threat-model.md")); err != nil {
		t.Errorf("expected threat-model.md to exist: %v", err)
	}
}

func TestWriteContext_OverwritesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notes.md")
	if err := os.WriteFile(path, []byte("OLD"), 0o600); err != nil {
		t.Fatal(err)
	}
	wc := tool.NewWriteContext(dir)
	if _, err := wc.Execute(context.Background(), map[string]any{
		"name":    "notes",
		"content": "NEW",
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	body, _ := os.ReadFile(path)
	if string(body) != "NEW" {
		t.Errorf("file not overwritten: %q", body)
	}
}

func TestWriteContext_RejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	wc := tool.NewWriteContext(dir)
	for _, bad := range []string{
		"../etc/passwd",
		"../../escape",
		"sub/dir/file",
		"/absolute/path",
	} {
		if _, err := wc.Execute(context.Background(), map[string]any{
			"name":    bad,
			"content": "x",
		}); err == nil {
			t.Errorf("expected rejection for name %q", bad)
		}
	}
}

func TestWriteContext_RequiresNameAndContent(t *testing.T) {
	wc := tool.NewWriteContext(t.TempDir())
	if _, err := wc.Execute(context.Background(), map[string]any{"content": "x"}); err == nil {
		t.Error("expected error when name missing")
	}
	if _, err := wc.Execute(context.Background(), map[string]any{"name": "x"}); err == nil {
		t.Error("expected error when content missing")
	}
}

func TestWriteContext_CreatesDirIfMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "context")
	wc := tool.NewWriteContext(dir)
	if _, err := wc.Execute(context.Background(), map[string]any{
		"name":    "n",
		"content": "c",
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}
}

func TestWriteContext_RoundTripsWithReadContext(t *testing.T) {
	dir := t.TempDir()
	wc := tool.NewWriteContext(dir)
	rc := tool.NewReadContext(dir)

	if _, err := wc.Execute(context.Background(), map[string]any{
		"name":    "vault-conventions",
		"content": "All ${VAULT_*} variables are placeholders, not real secrets.",
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := rc.Execute(context.Background(), map[string]any{"name": "vault-conventions"})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(out, "placeholders") {
		t.Errorf("round-trip failed: %q", out)
	}
}

func TestWriteContext_Metadata(t *testing.T) {
	wc := tool.NewWriteContext("/tmp")
	if wc.Name() != "write_context" {
		t.Errorf("name = %q", wc.Name())
	}
	if wc.Description() == "" {
		t.Error("description empty")
	}
	if wc.Schema() == nil {
		t.Error("schema nil")
	}
}

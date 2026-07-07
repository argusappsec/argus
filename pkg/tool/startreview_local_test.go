package tool_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

func TestStartReviewLocal_SetsSessionRoot(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sess := session.New()
	srl := tool.NewStartReviewLocal(sess)

	out, err := srl.Execute(context.Background(), map[string]any{"path": repo})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if sess.Root() != repo {
		t.Errorf("session root = %q, want %q", sess.Root(), repo)
	}
	if out == "" {
		t.Error("expected confirmation message, got empty")
	}
}

func TestStartReviewLocal_RejectsNonexistentPath(t *testing.T) {
	sess := session.New()
	srl := tool.NewStartReviewLocal(sess)
	if _, err := srl.Execute(context.Background(), map[string]any{"path": "/nonexistent/path/xyz"}); err == nil {
		t.Error("expected error for nonexistent path")
	}
	if sess.Root() != "" {
		t.Errorf("root should remain unset on error, got %q", sess.Root())
	}
}

func TestStartReviewLocal_RejectsFile(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "x.txt")
	if err := os.WriteFile(file, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	sess := session.New()
	srl := tool.NewStartReviewLocal(sess)
	if _, err := srl.Execute(context.Background(), map[string]any{"path": file}); err == nil {
		t.Error("expected error when path is a file, not a directory")
	}
}

func TestStartReviewLocal_RequiresPathArg(t *testing.T) {
	srl := tool.NewStartReviewLocal(session.New())
	if _, err := srl.Execute(context.Background(), map[string]any{}); err == nil {
		t.Error("expected error when path arg missing")
	}
}

func TestStartReviewLocal_Metadata(t *testing.T) {
	srl := tool.NewStartReviewLocal(session.New())
	if srl.Name() != "start_review_local" {
		t.Errorf("name = %q", srl.Name())
	}
	if srl.Description() == "" {
		t.Error("description empty")
	}
	if srl.Schema() == nil {
		t.Error("schema must not be nil")
	}
}

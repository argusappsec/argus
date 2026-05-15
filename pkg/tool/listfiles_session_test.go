package tool_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/session"
	"github.com/redcarbon-dev/argus/pkg/tool"
)

// TestListFiles_UsesSessionRoot is the v0.2 tracer: list_files no longer takes
// a fixed root at construction time. Instead it reads the current target from a
// Session, so that start_review_* tools can change the target mid-conversation
// and subsequent file-scoped tool calls see the new root immediately.
func TestListFiles_UsesSessionRoot(t *testing.T) {
	first := t.TempDir()
	mustWrite(t, filepath.Join(first, "alpha.go"), "package alpha\n")

	second := t.TempDir()
	mustWrite(t, filepath.Join(second, "beta.go"), "package beta\n")

	sess := session.New()
	lf := tool.NewListFiles(sess)

	// No root set yet → tool reports the missing target rather than panicking.
	if _, err := lf.Execute(context.Background(), map[string]any{}); err == nil {
		t.Error("expected error when session has no root set")
	}

	// Set the first root: list_files sees alpha.go.
	sess.SetRoot(first)
	out, err := lf.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("execute (first): %v", err)
	}
	if !strings.Contains(out, "alpha.go") {
		t.Errorf("first root: expected alpha.go, got %q", out)
	}

	// Re-target the session: SAME tool instance now sees beta.go, not alpha.go.
	sess.SetRoot(second)
	out, err = lf.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("execute (second): %v", err)
	}
	if !strings.Contains(out, "beta.go") {
		t.Errorf("second root: expected beta.go, got %q", out)
	}
	if strings.Contains(out, "alpha.go") {
		t.Errorf("second root should NOT contain alpha.go (stale cache?): %q", out)
	}
}

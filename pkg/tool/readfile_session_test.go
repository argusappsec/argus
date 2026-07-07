package tool_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

// TestReadFile_UsesSessionRoot: same dynamic-target behavior, applied to read_file.
func TestReadFile_UsesSessionRoot(t *testing.T) {
	first := t.TempDir()
	mustWrite(t, filepath.Join(first, "f.txt"), "FIRST\n")
	second := t.TempDir()
	mustWrite(t, filepath.Join(second, "f.txt"), "SECOND\n")

	sess := session.New()
	rf := tool.NewReadFile(sess)

	if _, err := rf.Execute(context.Background(), map[string]any{"path": "f.txt"}); err == nil {
		t.Error("expected error when session has no root set")
	}

	sess.SetRoot(first)
	out, err := rf.Execute(context.Background(), map[string]any{"path": "f.txt"})
	if err != nil {
		t.Fatalf("first execute: %v", err)
	}
	if !strings.Contains(out, "FIRST") {
		t.Errorf("first root: %q", out)
	}

	sess.SetRoot(second)
	out, err = rf.Execute(context.Background(), map[string]any{"path": "f.txt"})
	if err != nil {
		t.Fatalf("second execute: %v", err)
	}
	if !strings.Contains(out, "SECOND") {
		t.Errorf("second root: %q", out)
	}
}

package tool_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/tool"
)

func TestReadFile_ReturnsFullContent(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.txt"), "line1\nline2\nline3\n")

	rf := tool.NewReadFile(sessionWith(root))
	out, err := rf.Execute(context.Background(), map[string]any{"path": "a.txt"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out, "line1") || !strings.Contains(out, "line3") {
		t.Errorf("output = %q", out)
	}
}

func TestReadFile_LineRange(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.txt"), "L1\nL2\nL3\nL4\nL5\n")

	rf := tool.NewReadFile(sessionWith(root))
	out, err := rf.Execute(context.Background(), map[string]any{
		"path":       "a.txt",
		"line_start": float64(2),
		"line_end":   float64(4),
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if strings.Contains(out, "L1") || strings.Contains(out, "L5") {
		t.Errorf("range filter failed: %q", out)
	}
	if !strings.Contains(out, "L2") || !strings.Contains(out, "L3") || !strings.Contains(out, "L4") {
		t.Errorf("expected L2-L4 present: %q", out)
	}
}

func TestReadFile_RejectsEscape(t *testing.T) {
	rf := tool.NewReadFile(sessionWith(t.TempDir()))
	if _, err := rf.Execute(context.Background(), map[string]any{"path": "../etc/passwd"}); err == nil {
		t.Error("expected escape rejection")
	}
}

func TestGrep_FindsMatchesWithLineNumbers(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "code.go"), "package main\nfunc secret() {}\nvar password string\n")
	mustWrite(t, filepath.Join(root, "skip.md"), "# password\n")

	g := tool.NewGrep(sessionWith(root))
	out, err := g.Execute(context.Background(), map[string]any{"pattern": "password"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out, "code.go:3") {
		t.Errorf("missing code.go:3 hit; got:\n%s", out)
	}
	if !strings.Contains(out, "skip.md:1") {
		t.Errorf("missing skip.md hit; got:\n%s", out)
	}
}

func TestGrep_RejectsInvalidRegex(t *testing.T) {
	g := tool.NewGrep(sessionWith(t.TempDir()))
	if _, err := g.Execute(context.Background(), map[string]any{"pattern": "[unterminated"}); err == nil {
		t.Error("expected error for invalid regex")
	}
}

package security_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/security"
	"github.com/argusappsec/argus/pkg/session"
)

func sessionAt(root string) *session.Session {
	s := session.New()
	s.SetRoot(root)
	return s
}

func TestSemgrep_ToolMetadata(t *testing.T) {
	s := security.NewSemgrep(sessionAt("/tmp"), &fakeRunner{})
	if s.Name() != "run_semgrep" {
		t.Errorf("name = %q", s.Name())
	}
	if s.Description() == "" {
		t.Error("description empty")
	}
}

func TestSemgrep_PassesPathAndReturnsOutput(t *testing.T) {
	fr := &fakeRunner{out: `{"results": []}`}
	s := security.NewSemgrep(sessionAt("/repo"), fr)
	out, err := s.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out, "results") {
		t.Errorf("output = %q", out)
	}
	joined := strings.Join(fr.gotArgs, " ")
	if !strings.Contains(joined, "--json") {
		t.Errorf("expected --json in args: %v", fr.gotArgs)
	}
	if !strings.Contains(joined, "/repo") {
		t.Errorf("expected /repo in args: %v", fr.gotArgs)
	}
}

// With no review to inherit a target from — the Toolbox surface's Session — the
// caller names the directory and that is what gets scanned.
func TestSemgrep_ScansTheTargetTheCallerNamesWhenNoReviewPinnedOne(t *testing.T) {
	dir := t.TempDir()
	fr := &fakeRunner{out: `{"results": []}`}
	s := security.NewSemgrep(session.New(), fr)
	if _, err := s.Execute(context.Background(), map[string]any{"path": dir}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if joined := strings.Join(fr.gotArgs, " "); !strings.Contains(joined, dir) {
		t.Errorf("expected the caller's target %q in args: %v", dir, fr.gotArgs)
	}
}

// A review pins the checkout, and from then on the scanners stay inside it like
// every other file-scoped Tool. This is what keeps the target argument from
// becoming a way for content inside a repository under review to talk the model
// into scanning the rest of the daemon's disk.
func TestSemgrep_RefusesATargetOutsideTheReviewCheckout(t *testing.T) {
	fr := &fakeRunner{out: `{"results": []}`}
	s := security.NewSemgrep(sessionAt(t.TempDir()), fr)
	elsewhere := t.TempDir()

	_, err := s.Execute(context.Background(), map[string]any{"path": elsewhere})
	if err == nil {
		t.Fatal("a target outside the checkout under review must be refused")
	}
	if !strings.Contains(err.Error(), "review") {
		t.Errorf("the refusal must say the review is what scopes the scan: %v", err)
	}
	if fr.gotArgs != nil {
		t.Errorf("a refused target must not reach the binary: %v", fr.gotArgs)
	}
}

func TestSemgrep_AcceptsASubdirectoryOfTheReviewCheckout(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "services", "api")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	fr := &fakeRunner{out: `{"results": []}`}
	s := security.NewSemgrep(sessionAt(root), fr)

	if _, err := s.Execute(context.Background(), map[string]any{"path": sub}); err != nil {
		t.Fatalf("narrowing a review's scan to a subdirectory must be allowed: %v", err)
	}
	if joined := strings.Join(fr.gotArgs, " "); !strings.Contains(joined, sub) {
		t.Errorf("expected the subdirectory %q in args: %v", sub, fr.gotArgs)
	}
}

func TestSemgrep_ErrorsWhenNoTargetSet(t *testing.T) {
	s := security.NewSemgrep(session.New(), &fakeRunner{})
	if _, err := s.Execute(context.Background(), map[string]any{}); err == nil {
		t.Error("expected error when session has no root set")
	}
}

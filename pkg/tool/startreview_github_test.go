package tool_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/codehost/github"
	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

// fakeGitRunner simulates `git ls-remote` and `git clone` without network.
type fakeGitRunner struct{}

func (fakeGitRunner) Run(_ context.Context, _ string, args ...string) (string, error) {
	if len(args) > 0 && args[0] == "ls-remote" {
		return "abc1234567890abcdef0000000000000000000000\tHEAD\n", nil
	}
	if len(args) >= 2 && args[0] == "clone" {
		target := args[len(args)-1]
		_ = os.MkdirAll(target, 0o700)
		_ = os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\n"), 0o600)
		return "", nil
	}
	return "", nil
}

func TestStartReviewGitHub_ClonesAndSetsRoot(t *testing.T) {
	cacheDir := t.TempDir()
	cloner := github.NewClonerWithRunner(cacheDir, fakeGitRunner{})

	sess := session.New()
	srg := tool.NewStartReviewGitHub(sess, cloner)

	out, err := srg.Execute(context.Background(), map[string]any{
		"url": "https://github.com/example/repo",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if sess.Root() == "" {
		t.Error("session root must be set after clone")
	}
	if !strings.HasPrefix(sess.Root(), cacheDir) {
		t.Errorf("root %q not under cacheDir %q", sess.Root(), cacheDir)
	}
	if !strings.Contains(out, "abc1234567890") {
		t.Errorf("output should mention the resolved SHA: %q", out)
	}
}

func TestStartReviewGitHub_RejectsInvalidURL(t *testing.T) {
	cloner := github.NewClonerWithRunner(t.TempDir(), fakeGitRunner{})
	srg := tool.NewStartReviewGitHub(session.New(), cloner)
	if _, err := srg.Execute(context.Background(), map[string]any{"url": "https://gitlab.com/x/y"}); err == nil {
		t.Error("expected error for non-github URL")
	}
}

func TestStartReviewGitHub_Metadata(t *testing.T) {
	srg := tool.NewStartReviewGitHub(session.New(), nil)
	if srg.Name() != "start_review_github" {
		t.Errorf("name = %q", srg.Name())
	}
	if srg.Description() == "" {
		t.Error("description empty")
	}
}

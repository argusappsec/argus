package tool_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/codehost"
	"github.com/argusappsec/argus/pkg/codehost/github"
	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

// fakeCodeHost stands in for the shared authenticated CodeHost: it parses a
// github reference like the real client and "clones" by materializing a tiny
// checkout under root, so the tool's parse → clone → set-root path is exercised
// without network or an App identity. A cloneErr simulates a repo the App
// cannot see.
type fakeCodeHost struct {
	root     string
	cloneErr error
}

func (f fakeCodeHost) ParseURL(raw string) (codehost.Repo, error) {
	u, err := github.ParseURL(raw)
	if err != nil {
		return codehost.Repo{}, err
	}
	return codehost.Repo{Host: u.Host, Owner: u.Owner, Name: u.Name, FullName: u.FullName}, nil
}

func (f fakeCodeHost) Clone(_ context.Context, repo codehost.Repo, _ string) (codehost.Checkout, error) {
	if f.cloneErr != nil {
		return codehost.Checkout{}, f.cloneErr
	}
	dir := filepath.Join(f.root, repo.Owner+"__"+repo.Name, "abc1234567890")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return codehost.Checkout{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o600); err != nil {
		return codehost.Checkout{}, err
	}
	return codehost.Checkout{Path: dir, SHA: "abc1234567890"}, nil
}

func TestStartReviewGitHub_ClonesAndSetsRoot(t *testing.T) {
	cacheDir := t.TempDir()
	host := fakeCodeHost{root: cacheDir}

	sess := session.New()
	srg := tool.NewStartReviewGitHub(sess, host)

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
	srg := tool.NewStartReviewGitHub(session.New(), fakeCodeHost{root: t.TempDir()})
	if _, err := srg.Execute(context.Background(), map[string]any{"url": "https://gitlab.com/x/y"}); err == nil {
		t.Error("expected error for non-github URL")
	}
}

// A repo the App cannot see surfaces the codehost's clear error to the caller.
func TestStartReviewGitHub_CloneErrorSurfaces(t *testing.T) {
	host := fakeCodeHost{root: t.TempDir(), cloneErr: errors.New("github: the App is not installed on github.com/example/repo")}
	srg := tool.NewStartReviewGitHub(session.New(), host)
	_, err := srg.Execute(context.Background(), map[string]any{"url": "github.com/example/repo"})
	if err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("expected an installation error, got %v", err)
	}
}

// With no codehost configured the tool fails with a clear, user-facing message
// naming what to enable rather than silently doing nothing.
func TestStartReviewGitHub_NoCodeHost(t *testing.T) {
	srg := tool.NewStartReviewGitHub(session.New(), nil)
	_, err := srg.Execute(context.Background(), map[string]any{"url": "github.com/example/repo"})
	if err == nil || !strings.Contains(err.Error(), "codehosts:") {
		t.Fatalf("expected a no-codehost error naming codehosts:, got %v", err)
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

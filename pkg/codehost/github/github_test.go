package github_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/codehost/github"
)

func TestParseURL_HTTPSForm(t *testing.T) {
	u, err := github.ParseURL("https://github.com/argusappsec/argus")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Owner != "argusappsec" || u.Name != "argus" {
		t.Errorf("got %+v", u)
	}
	if u.FullName != "github.com/argusappsec/argus" {
		t.Errorf("full = %q", u.FullName)
	}
}

func TestParseURL_HTTPSWithDotGit(t *testing.T) {
	u, err := github.ParseURL("https://github.com/argusappsec/argus.git")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Name != "argus" {
		t.Errorf("name = %q", u.Name)
	}
}

func TestParseURL_ShortForm(t *testing.T) {
	u, err := github.ParseURL("github.com/argusappsec/argus")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Owner != "argusappsec" {
		t.Errorf("owner = %q", u.Owner)
	}
}

func TestParseURL_Invalid(t *testing.T) {
	for _, in := range []string{"", "not a url", "https://gitlab.com/x/y", "https://github.com/onlyowner"} {
		if _, err := github.ParseURL(in); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

// fakeRunner records git invocations and lets the test simulate clone effects.
type fakeRunner struct {
	calls [][]string
	onRun func(args ...string) (string, error)
}

func (f *fakeRunner) Run(_ context.Context, dir string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{"@" + dir}, args...))
	if f.onRun != nil {
		return f.onRun(args...)
	}
	return "", nil
}

func TestCloner_ClonesWhenCacheMiss(t *testing.T) {
	cacheRoot := t.TempDir()
	runs := &fakeRunner{
		onRun: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "ls-remote" {
				return "fakesha1234567890abcdef0000000000000000000\tHEAD\n", nil
			}
			if len(args) >= 2 && args[0] == "clone" {
				target := args[len(args)-1]
				_ = os.MkdirAll(target, 0o700)
				_ = os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\n"), 0o600)
				return "", nil
			}
			return "", nil
		},
	}

	c := github.NewClonerWithRunner(cacheRoot, runs)
	u, _ := github.ParseURL("https://github.com/argusappsec/argus")
	co, err := c.Clone(context.Background(), u, "")
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	if co.SHA != "fakesha1234567890abcdef0000000000000000000" {
		t.Errorf("sha = %q", co.SHA)
	}
	if !strings.HasPrefix(co.Path, cacheRoot) {
		t.Errorf("path %q not under cache root %q", co.Path, cacheRoot)
	}
	if _, err := os.Stat(filepath.Join(co.Path, "main.go")); err != nil {
		t.Errorf("expected file in checkout: %v", err)
	}

	// First call: at least one git clone command should have been issued.
	sawClone := false
	for _, c := range runs.calls {
		for _, tok := range c {
			if tok == "clone" {
				sawClone = true
			}
		}
	}
	if !sawClone {
		t.Errorf("expected a git clone call, got: %v", runs.calls)
	}
}

func TestCloner_CacheHitSkipsClone(t *testing.T) {
	cacheRoot := t.TempDir()
	runs := &fakeRunner{
		onRun: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "ls-remote" {
				return "cachedsha1234567890abcdef0000000000000000\tHEAD\n", nil
			}
			if len(args) >= 2 && args[0] == "clone" {
				target := args[len(args)-1]
				_ = os.MkdirAll(target, 0o700)
				return "", nil
			}
			return "", nil
		},
	}
	c := github.NewClonerWithRunner(cacheRoot, runs)
	u, _ := github.ParseURL("https://github.com/argusappsec/argus")

	if _, err := c.Clone(context.Background(), u, ""); err != nil {
		t.Fatalf("first clone: %v", err)
	}
	firstCalls := len(runs.calls)

	if _, err := c.Clone(context.Background(), u, ""); err != nil {
		t.Fatalf("second clone: %v", err)
	}
	// Second clone should not invoke git clone again (cache hit on same SHA).
	for _, c := range runs.calls[firstCalls:] {
		for _, tok := range c {
			if tok == "clone" {
				t.Errorf("unexpected clone on cache hit: %v", c)
			}
		}
	}
}

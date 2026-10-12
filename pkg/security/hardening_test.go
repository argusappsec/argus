package security_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/security"
	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

// scanners is every scanner Tool this package wraps, built over a Session
// pinned at root and a fake runner, so the hardening rules are asserted once
// for all of them.
var scanners = map[string]func(*session.Session, security.Runner) tool.Tool{
	"semgrep":     security.NewSemgrep,
	"gitleaks":    security.NewGitleaks,
	"osv-scanner": security.NewOSVScanner,
}

// emptyReport is what each binary writes when it finds nothing.
var emptyReport = map[string]string{
	"semgrep":     `{"results":[],"errors":[]}`,
	"gitleaks":    `[]`,
	"osv-scanner": `{"results":[]}`,
}

// checkout is a real directory standing in for the tree under review. Scanners
// stat their target, so it must exist.
func checkout(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestScanners_RunOutsideTheCheckout: the checkout is untrusted review content.
// A scanner whose working directory is the checkout picks up the config and
// ignore files a pull request committed there, so each one runs from a
// directory that is neither the checkout nor inside it, and is handed the
// checkout as an argument instead.
func TestScanners_RunOutsideTheCheckout(t *testing.T) {
	for name, build := range scanners {
		t.Run(name, func(t *testing.T) {
			root := checkout(t)
			fr := &fakeRunner{out: emptyReport[name]}
			if _, err := build(sessionAt(root), fr).Execute(context.Background(), map[string]any{}); err != nil {
				t.Fatalf("execute: %v", err)
			}
			dir := fr.gotCmd.Dir
			if dir == "" {
				t.Fatal("working directory is unset, so the child would inherit the daemon's")
			}
			if inside(root, dir) {
				t.Errorf("working directory %q is the checkout or inside it (%q)", dir, root)
			}
			if !strings.Contains(strings.Join(fr.gotArgs, " "), root) {
				t.Errorf("checkout %q is not passed as an argument: %v", root, fr.gotArgs)
			}
		})
	}
}

// TestScanners_ReceiveOnlyTheirAllowListedEnvironment: the daemon's process
// environment carries `.env` secrets (daemon.Build applies it). A scanner sees
// PATH, a scratch HOME and its own cache locations, and nothing else: no
// token, no API key, nothing inherited.
func TestScanners_ReceiveOnlyTheirAllowListedEnvironment(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_should-never-reach-a-scanner")
	t.Setenv("OPENAI_API_KEY", "sk-should-never-reach-a-scanner")
	realHome, _ := os.UserHomeDir()

	allowed := map[string]bool{
		"PATH": true, "HOME": true, "TMPDIR": true,
		"XDG_CACHE_HOME": true, "XDG_CONFIG_HOME": true, "XDG_DATA_HOME": true,
		"PYTHONUTF8": true,
	}
	for name, build := range scanners {
		t.Run(name, func(t *testing.T) {
			root := checkout(t)
			fr := &fakeRunner{out: emptyReport[name]}
			if _, err := build(sessionAt(root), fr).Execute(context.Background(), map[string]any{}); err != nil {
				t.Fatalf("execute: %v", err)
			}
			env := envMap(fr.gotCmd.Env)
			for k, v := range env {
				if !allowed[k] {
					t.Errorf("%s=%s is not on the allow-list", k, v)
				}
				if strings.Contains(v, "should-never-reach") {
					t.Errorf("%s carries a secret from the daemon's environment", k)
				}
			}
			if env["PATH"] != os.Getenv("PATH") {
				t.Errorf("PATH = %q, want the daemon's PATH so the scanner can find its own helpers", env["PATH"])
			}
			home := env["HOME"]
			if home == "" || home == realHome || inside(root, home) {
				t.Errorf("HOME = %q, want a scratch directory outside the checkout and the real home", home)
			}
		})
	}
}

// TestScanners_CleanUpTheirScratchDirectory: the scratch HOME and working
// directory belong to one run. Leaving them behind would let one scan's caches
// and reports leak into the next, and fill the disk on a busy daemon.
func TestScanners_CleanUpTheirScratchDirectory(t *testing.T) {
	for name, build := range scanners {
		t.Run(name, func(t *testing.T) {
			fr := &fakeRunner{out: emptyReport[name]}
			if _, err := build(sessionAt(checkout(t)), fr).Execute(context.Background(), map[string]any{}); err != nil {
				t.Fatalf("execute: %v", err)
			}
			if _, err := os.Stat(fr.gotCmd.Dir); !os.IsNotExist(err) {
				t.Errorf("scratch directory %q still exists after the run (stat err: %v)", fr.gotCmd.Dir, err)
			}
		})
	}
}

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

// inside reports whether path is root itself or lies under it, after
// resolving symlinks (macOS's /var is /private/var).
func inside(root, path string) bool {
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	if p, err := filepath.EvalSymlinks(path); err == nil {
		path = p
	}
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

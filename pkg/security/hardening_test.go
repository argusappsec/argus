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

// scanners is every scanner Tool the Catalog lists, built from its Entry over
// a Session and a fake runner, so the hardening rules are asserted once for
// all of them and a newly catalogued Tool is held to them without being added
// here.
//
// It is keyed by the binary the Tool runs: the Entry's ID, or, for a Tool over
// Alternatives, each engine's name. The SAST Tool appears once per engine:
// opengrep and semgrep are different binaries and each is held to the same
// rules.
var scanners = catalogScanners()

func catalogScanners() map[string]func(*session.Session, security.Runner) tool.Tool {
	out := map[string]func(*session.Session, security.Runner) tool.Tool{}
	for _, e := range security.Catalog() {
		build := func(engine string) func(*session.Session, security.Runner) tool.Tool {
			return func(s *session.Session, r security.Runner) tool.Tool {
				return e.New(security.Deps{Session: s, Commands: r, Engine: engine})
			}
		}
		if !e.Alternatives {
			out[e.ID] = build("")
			continue
		}
		for _, b := range e.Binaries {
			out[b.Name] = build(b.Name)
		}
	}
	return out
}

// toolFixture is what the shared scanner tests need from one scanner. Each
// Tool's test file declares its own, next to its tests, from an init function
// (see fixture), so adding a Tool adds a fixture there and edits no shared
// list.
type toolFixture struct {
	// empty is what the binary writes when it finds nothing.
	empty string
	// repoConfig is what makes the scanner obey only Argus's config:
	// switches that must be present, and options whose value must be a file
	// Argus wrote into the run's scratch directory rather than anything in
	// the checkout.
	repoConfig struct {
		switches []string
		scratch  []string
	}
}

// fixtures holds every scanner's toolFixture, keyed as scanners is.
var fixtures = map[string]toolFixture{}

// fixture declares a scanner's toolFixture, from its test file's init.
func fixture(name string, f toolFixture) { fixtures[name] = f }

// emptyReport is what the named binary writes when it finds nothing.
func emptyReport(name string) string { return fixtures[name].empty }

// A newly catalogued Tool must not slip past the hardening tests: every
// scanner the Catalog yields has a fixture, so it is run by every test above
// and below with a report it can parse.
func TestScanners_EveryCataloguedToolHasHardeningCoverage(t *testing.T) {
	if len(scanners) == 0 {
		t.Fatal("the Catalog yields no scanner")
	}
	for name := range scanners {
		if fixtures[name].empty == "" {
			t.Errorf("%s has no toolFixture: declare one with fixture() in its test file", name)
		}
	}
	for name := range fixtures {
		if scanners[name] == nil {
			t.Errorf("fixture %q names no catalogued scanner", name)
		}
	}
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
			fr := &fakeRunner{out: emptyReport(name)}
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
		// The hardened Go profile of the Tools that drive the go command
		// (gosec, govulncheck, osv-scanner's Go call analysis): each one
		// closes a door the go command's defaults leave open, and none
		// carries a credential.
		"GOTOOLCHAIN": true, "GOFLAGS": true, "GOWORK": true, "CGO_ENABLED": true,
		"GOPROXY": true, "GOSUMDB": true, "GOENV": true, "GOPACKAGESDRIVER": true,
		"GOPATH": true, "GOCACHE": true,
		// trivy's network lock-out: a proxy that does not exist, git with no
		// transport, cloud metadata endpoints off. Each takes access away.
		"HTTPS_PROXY": true, "HTTP_PROXY": true, "ALL_PROXY": true,
		"https_proxy": true, "http_proxy": true, "all_proxy": true,
		"GIT_ALLOW_PROTOCOL": true, "AWS_EC2_METADATA_DISABLED": true, "GCE_METADATA_HOST": true,
	}
	for name, build := range scanners {
		t.Run(name, func(t *testing.T) {
			root := checkout(t)
			fr := &fakeRunner{out: emptyReport(name)}
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

// TestScanners_FindEveryDirectoryTheirEnvironmentNames: a directory variable
// on the allow-list points at a directory that exists while the scanner runs.
// opengrep (1.30.1) aborts with Sys_error when XDG_CONFIG_HOME names a
// directory that is not there, before it reads a single rule.
func TestScanners_FindEveryDirectoryTheirEnvironmentNames(t *testing.T) {
	for name, build := range scanners {
		t.Run(name, func(t *testing.T) {
			fr := &fakeRunner{out: emptyReport(name)}
			if _, err := build(sessionAt(checkout(t)), fr).Execute(context.Background(), map[string]any{}); err != nil {
				t.Fatalf("execute: %v", err)
			}
			if len(fr.absentDirs) > 0 {
				t.Errorf("the scanner ran with directories that did not exist: %v", fr.absentDirs)
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
			fr := &fakeRunner{out: emptyReport(name)}
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

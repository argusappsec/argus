package doctor_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/doctor"
	"github.com/argusappsec/argus/pkg/tool"
)

// makeStubBinary creates an executable file at <dir>/<name>. It returns a
// PATH value that includes only that dir, so tests can control which
// binaries doctor.Run "finds".
func makeStubBinary(t *testing.T, dir, name string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		name += ".bat"
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestRun_DetectsPresentAndMissingBinaries(t *testing.T) {
	binDir := t.TempDir()
	homeDir := t.TempDir()
	makeStubBinary(t, binDir, "semgrep")
	makeStubBinary(t, binDir, "git")
	// gitleaks intentionally missing

	t.Setenv("PATH", binDir)
	t.Setenv("GEMINI_API_KEY", "stub-key")

	checks := doctor.Run(doctor.Options{
		Home: homeDir,
		ExtraBinaries: []doctor.ExtraBinary{
			{Name: "git", Required: true, UsedBy: "cloning", InstallHint: "brew install git"},
			{Name: "semgrep", Required: false, UsedBy: "run_semgrep", InstallHint: "brew install semgrep"},
			{Name: "gitleaks", Required: false, UsedBy: "run_gitleaks", InstallHint: "brew install gitleaks"},
		},
	})

	gotByName := map[string]doctor.Check{}
	for _, c := range checks {
		gotByName[c.Name] = c
	}

	if gotByName["git"].Status != doctor.Pass {
		t.Errorf("git should be Pass, got %v (%s)", gotByName["git"].Status, gotByName["git"].Message)
	}
	if gotByName["semgrep"].Status != doctor.Pass {
		t.Errorf("semgrep should be Pass, got %v", gotByName["semgrep"].Status)
	}
	if gotByName["gitleaks"].Status != doctor.Fail {
		t.Errorf("gitleaks should be Fail, got %v", gotByName["gitleaks"].Status)
	}
	if !strings.Contains(gotByName["gitleaks"].Hint, "install") {
		t.Errorf("missing optional binary should have an install hint, got %q", gotByName["gitleaks"].Hint)
	}
}

func TestRun_FlagsMissingGitAsRequired(t *testing.T) {
	binDir := t.TempDir()
	homeDir := t.TempDir()
	// no git
	t.Setenv("PATH", binDir)
	t.Setenv("GEMINI_API_KEY", "stub")

	checks := doctor.Run(doctor.Options{
		Home: homeDir,
		ExtraBinaries: []doctor.ExtraBinary{
			{Name: "git", Required: true, UsedBy: "cloning", InstallHint: "brew install git"},
			{Name: "semgrep", Required: false, UsedBy: "run_semgrep", InstallHint: "brew install semgrep"},
			{Name: "gitleaks", Required: false, UsedBy: "run_gitleaks", InstallHint: "brew install gitleaks"},
		},
	})

	for _, c := range checks {
		if c.Name == "git" {
			if c.Status != doctor.Fail {
				t.Errorf("git missing should be Fail")
			}
			if c.Severity != doctor.SeverityRequired {
				t.Errorf("git should be Required, got %v", c.Severity)
			}
			return
		}
	}
	t.Error("no git check produced")
}

func TestRun_DetectsConfiguredProvider(t *testing.T) {
	home := t.TempDir()
	cfg := &config.Config{
		Providers: map[string]config.ProviderConfig{
			"gemini": {Type: "gemini", APIKey: "env(GEMINI_API_KEY)"},
		},
		DefaultModel: "gemini-2.5-flash",
	}
	if err := config.SaveConfig(filepath.Join(home, "argus.yaml"), cfg); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")
	t.Setenv("GEMINI_API_KEY", "stub")

	checks := doctor.Run(doctor.Options{Home: home})

	for _, c := range checks {
		if c.Name == "argus.yaml" {
			if c.Status != doctor.Pass {
				t.Errorf("argus.yaml should be Pass: %v (%s)", c.Status, c.Message)
			}
			if !strings.Contains(c.Message, "gemini-2.5-flash") {
				t.Errorf("message should mention default model: %q", c.Message)
			}
			return
		}
	}
	t.Error("no argus.yaml check produced")
}

func TestRun_FlagsMissingAPIKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PATH", "")
	t.Setenv("GEMINI_API_KEY", "")

	checks := doctor.Run(doctor.Options{Home: home})

	for _, c := range checks {
		if c.Name == "GEMINI_API_KEY" {
			if c.Status != doctor.Fail {
				t.Errorf("missing key should be Fail")
			}
			if c.Severity != doctor.SeverityRequired {
				t.Errorf("missing key should be Required")
			}
			if !strings.Contains(c.Hint, "init") {
				t.Errorf("hint should mention `argus init`: %q", c.Hint)
			}
			return
		}
	}
	t.Error("no GEMINI_API_KEY check produced")
}

func TestRun_DetectsSoulPresence(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "SOUL.md"), []byte("---\ncompany: Acme\n---\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")
	t.Setenv("GEMINI_API_KEY", "stub")

	checks := doctor.Run(doctor.Options{Home: home})
	for _, c := range checks {
		if c.Name == "SOUL.md" {
			if c.Status != doctor.Pass {
				t.Errorf("SOUL.md present should be Pass: %v", c.Status)
			}
			if !strings.Contains(c.Message, "Acme") {
				t.Errorf("message should mention company name: %q", c.Message)
			}
			return
		}
	}
	t.Error("no SOUL.md check produced")
}

// stubRequirer is a Tool that declares a fake binary dep. Used to verify
// that doctor discovers binary requirements via the Requirer interface
// instead of a hardcoded list.
type stubRequirer struct{ binary, hint string }

func (s stubRequirer) Name() string             { return "stub_tool" }
func (s stubRequirer) Description() string      { return "stub" }
func (s stubRequirer) Schema() map[string]any   { return map[string]any{"type": "object"} }
func (s stubRequirer) Execute(_ context.Context, _ map[string]any) (string, error) {
	return "", nil
}
func (s stubRequirer) Requires() []tool.Requirement {
	return []tool.Requirement{{Binary: s.binary, InstallHint: s.hint}}
}

func TestRun_DiscoversBinaryDepsFromRegisteredTools(t *testing.T) {
	binDir := t.TempDir()
	homeDir := t.TempDir()
	t.Setenv("PATH", binDir)
	t.Setenv("GEMINI_API_KEY", "stub")

	reg := tool.NewRegistry()
	reg.Register(stubRequirer{binary: "definitely-not-installed-xyz", hint: "brew install xyz"})

	checks := doctor.Run(doctor.Options{Home: homeDir, Registry: reg})

	for _, c := range checks {
		if c.Name == "definitely-not-installed-xyz" {
			if c.Status != doctor.Fail {
				t.Errorf("tool-declared binary should be checked and Fail when missing, got %v", c.Status)
			}
			if !strings.Contains(c.Hint, "brew install xyz") {
				t.Errorf("hint should come from the tool's Requires(), got %q", c.Hint)
			}
			return
		}
	}
	t.Error("doctor did not discover binary dep from registered tool")
}

func TestRun_DedupesBinariesAcrossSources(t *testing.T) {
	binDir := t.TempDir()
	homeDir := t.TempDir()
	t.Setenv("PATH", binDir)
	t.Setenv("GEMINI_API_KEY", "stub")

	// Both ExtraBinaries AND a registered tool declare "shared-bin".
	reg := tool.NewRegistry()
	reg.Register(stubRequirer{binary: "shared-bin", hint: "brew install shared-bin"})

	checks := doctor.Run(doctor.Options{
		Home: homeDir,
		ExtraBinaries: []doctor.ExtraBinary{
			{Name: "shared-bin", Required: true, UsedBy: "extras source", InstallHint: "extras hint"},
		},
		Registry: reg,
	})

	count := 0
	for _, c := range checks {
		if c.Name == "shared-bin" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("shared-bin reported %d times, want 1 (extras should win)", count)
	}
}

func TestRun_BinariesOnly_AllPresentSucceeds(t *testing.T) {
	binDir := t.TempDir()
	homeDir := t.TempDir()
	makeStubBinary(t, binDir, "git")
	makeStubBinary(t, binDir, "scanner-bin")
	t.Setenv("PATH", binDir)
	// No API key / config on purpose: they must not affect the outcome.
	t.Setenv("GEMINI_API_KEY", "")

	reg := tool.NewRegistry()
	reg.Register(stubRequirer{binary: "scanner-bin", hint: "brew install scanner-bin"})

	checks := doctor.Run(doctor.Options{
		Home:         homeDir,
		Registry:     reg,
		BinariesOnly: true,
		ExtraBinaries: []doctor.ExtraBinary{
			{Name: "git", Required: true, UsedBy: "cloning", InstallHint: "brew install git"},
		},
	})

	for _, c := range checks {
		if c.Status != doctor.Pass {
			t.Errorf("check %q should Pass, got %v (%s)", c.Name, c.Status, c.Hint)
		}
	}
	if doctor.Summarize(checks).HasBlockingFailure() {
		t.Error("all binaries present should not be a blocking failure")
	}
}

func TestRun_BinariesOnly_MissingToolBinaryBlocks(t *testing.T) {
	binDir := t.TempDir()
	homeDir := t.TempDir()
	makeStubBinary(t, binDir, "git")
	// scanner-bin intentionally missing
	t.Setenv("PATH", binDir)
	t.Setenv("GEMINI_API_KEY", "stub")

	reg := tool.NewRegistry()
	reg.Register(stubRequirer{binary: "scanner-bin", hint: "brew install scanner-bin"})

	checks := doctor.Run(doctor.Options{
		Home:         homeDir,
		Registry:     reg,
		BinariesOnly: true,
		ExtraBinaries: []doctor.ExtraBinary{
			{Name: "git", Required: true, UsedBy: "cloning", InstallHint: "brew install git"},
		},
	})

	if !doctor.Summarize(checks).HasBlockingFailure() {
		t.Error("a missing tool-declared binary must be a blocking failure in binaries-only mode")
	}
}

func TestRun_BinariesOnly_MissingExtraBinaryBlocks(t *testing.T) {
	binDir := t.TempDir()
	homeDir := t.TempDir()
	makeStubBinary(t, binDir, "scanner-bin")
	// git (an extra, optional-by-default here) intentionally missing
	t.Setenv("PATH", binDir)
	t.Setenv("GEMINI_API_KEY", "stub")

	reg := tool.NewRegistry()
	reg.Register(stubRequirer{binary: "scanner-bin", hint: "brew install scanner-bin"})

	checks := doctor.Run(doctor.Options{
		Home:         homeDir,
		Registry:     reg,
		BinariesOnly: true,
		ExtraBinaries: []doctor.ExtraBinary{
			// Declared as NOT required — binaries-only mode must still block.
			{Name: "git", Required: false, UsedBy: "cloning", InstallHint: "brew install git"},
		},
	})

	if !doctor.Summarize(checks).HasBlockingFailure() {
		t.Error("a missing extra binary must block even when declared optional in binaries-only mode")
	}
}

func TestRun_BinariesOnly_SkipsNonBinaryChecks(t *testing.T) {
	binDir := t.TempDir()
	homeDir := t.TempDir()
	makeStubBinary(t, binDir, "git")
	t.Setenv("PATH", binDir)
	// Missing API key and config would normally produce a required failure.
	t.Setenv("GEMINI_API_KEY", "")

	checks := doctor.Run(doctor.Options{
		Home:         homeDir,
		BinariesOnly: true,
		ExtraBinaries: []doctor.ExtraBinary{
			{Name: "git", Required: true, UsedBy: "cloning", InstallHint: "brew install git"},
		},
	})

	for _, c := range checks {
		switch c.Name {
		case "argus.yaml", "GEMINI_API_KEY", "SOUL.md", "context/", "github":
			t.Errorf("non-binary check %q must not run in binaries-only mode", c.Name)
		}
	}
	if doctor.Summarize(checks).HasBlockingFailure() {
		t.Error("missing API key/config must not affect the binaries-only outcome")
	}
}

func TestSummary_CountsByStatus(t *testing.T) {
	checks := []doctor.Check{
		{Status: doctor.Pass},
		{Status: doctor.Pass},
		{Status: doctor.Fail, Severity: doctor.SeverityRequired},
		{Status: doctor.Fail, Severity: doctor.SeverityOptional},
		{Status: doctor.Info},
	}
	s := doctor.Summarize(checks)
	if s.OK != 2 {
		t.Errorf("OK = %d, want 2", s.OK)
	}
	if s.RequiredFailed != 1 {
		t.Errorf("RequiredFailed = %d, want 1", s.RequiredFailed)
	}
	if s.OptionalMissing != 1 {
		t.Errorf("OptionalMissing = %d, want 1", s.OptionalMissing)
	}
	if !s.HasBlockingFailure() {
		t.Error("HasBlockingFailure should be true when a required check failed")
	}
}

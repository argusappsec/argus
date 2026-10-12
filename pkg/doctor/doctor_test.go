package doctor_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/deployment"
	"github.com/argusappsec/argus/pkg/doctor"
	"github.com/argusappsec/argus/pkg/security"
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

	checks := doctor.Run(doctor.Options{Home: home, Shape: deployment.Colleague})

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

func TestRun_BlocksWhenDefaultModelResolvesToNoProvider(t *testing.T) {
	// Two providers and a bare model id matching neither: nothing Argus does can
	// start a Session, so doctor must not report the config as ready.
	home := t.TempDir()
	cfg := &config.Config{
		Providers: map[string]config.ProviderConfig{
			"groq":       {Type: "openai-compatible", URL: "https://api.groq.com/openai/v1"},
			"openrouter": {Type: "openai-compatible", URL: "https://openrouter.ai/api/v1"},
		},
		DefaultModel: "some-model",
	}
	if err := config.SaveConfig(filepath.Join(home, "argus.yaml"), cfg); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")

	checks := doctor.Run(doctor.Options{Home: home, Shape: deployment.Colleague})
	c := findCheck(checks, "argus.yaml")
	if c == nil || c.Status != doctor.Fail || c.Severity != doctor.SeverityRequired {
		t.Fatalf("check = %+v, want a blocking Fail", c)
	}
	if !strings.Contains(c.Hint, "some-model") {
		t.Errorf("hint should name the unresolvable model id: %q", c.Hint)
	}
	if !doctor.Summarize(checks).HasBlockingFailure() {
		t.Error("a default_model that names no configured provider must block")
	}
}

// doctor reports the Deployment shape the daemon derived — it is told the
// shape rather than deriving a second opinion of its own.
func TestRun_ReportsTheDeploymentShape(t *testing.T) {
	t.Setenv("PATH", "")
	t.Setenv("GEMINI_API_KEY", "")

	toolbox := findCheck(doctor.Run(doctor.Options{Home: t.TempDir(), Shape: deployment.Toolbox}), "deployment")
	if toolbox == nil {
		t.Fatal("no deployment row")
	}
	if toolbox.Status != doctor.Info || !strings.Contains(toolbox.Message, "toolbox") {
		t.Errorf("toolbox row = %+v, want an Info naming the toolbox shape", toolbox)
	}

	home := writeProviders(t, "gemini-2.5-flash", map[string]config.ProviderConfig{
		"gemini": {Type: "gemini", APIKey: "literal"},
	})
	colleague := findCheck(doctor.Run(doctor.Options{Home: home, Shape: deployment.Colleague}), "deployment")
	if colleague == nil {
		t.Fatal("no deployment row")
	}
	if colleague.Status != doctor.Info || !strings.Contains(colleague.Message, "colleague") {
		t.Errorf("colleague row = %+v, want an Info naming the colleague shape", colleague)
	}
}

// A Toolbox is a Deployment shape, not a broken Colleague: having no Provider
// and no model is exactly what it is, so nothing about it may be reported as a
// failure — least of all a blocking one.
func TestRun_ToolboxIsNotReportedAsBroken(t *testing.T) {
	t.Setenv("PATH", "")
	t.Setenv("GEMINI_API_KEY", "")

	checks := doctor.Run(doctor.Options{Home: t.TempDir(), Shape: deployment.Toolbox})
	for _, c := range checks {
		if c.Status == doctor.Fail {
			t.Errorf("check %q failed in a Toolbox: %s", c.Name, c.Hint)
		}
	}
	if doctor.Summarize(checks).HasBlockingFailure() {
		t.Error("a Toolbox must not be reported as an environment that is not ready")
	}

	yaml := findCheck(checks, "argus.yaml")
	if yaml == nil || yaml.Status == doctor.Fail {
		t.Fatalf("argus.yaml row = %+v, want no failure for a config that configures no Provider", yaml)
	}
	if !strings.Contains(yaml.Message, "toolbox") {
		t.Errorf("argus.yaml row should say why there is no Provider: %q", yaml.Message)
	}
}

func TestRun_SurfacesLegacyConfigKeyError(t *testing.T) {
	home := t.TempDir()
	// A config v2 legacy key: LoadConfig hard-errors with a message naming the
	// replacement. Doctor must surface that message, not a generic "run init".
	legacy := "github:\n  app_id: \"123\"\n"
	if err := os.WriteFile(filepath.Join(home, "argus.yaml"), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	checks := doctor.Run(doctor.Options{Home: home})
	c := findCheck(checks, "argus.yaml")
	if c == nil || c.Status != doctor.Fail {
		t.Fatalf("check = %+v, want Fail for a legacy key", c)
	}
	if !strings.Contains(c.Hint, "codehosts:") {
		t.Errorf("hint should name the v2 replacement, got %q", c.Hint)
	}
	// A shape derived from a config nobody could read is a guess. Doctor says
	// nothing rather than announcing a toolbox next to a file that may well
	// declare a Provider.
	if d := findCheck(checks, "deployment"); d != nil {
		t.Errorf("deployment row = %+v, want none when argus.yaml cannot be read", d)
	}
}

// The API-key rows are derived from the configured Providers rather than from a
// hardcoded Gemini literal, so their tests — including the missing-key case that
// used to live here — are in provider_test.go alongside the severity matrix.

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

// stubEntry is a catalogued Tool requiring the given binaries. doctor reads the
// Catalog's metadata only, so the Entry needs no constructor.
func stubEntry(id string, binaries ...string) security.Entry {
	e := security.Entry{ID: id, Tool: "run_" + id}
	for _, b := range binaries {
		e.Binaries = append(e.Binaries, security.Binary{Name: b, InstallHint: "brew install " + b})
	}
	return e
}

func checkNamed(t *testing.T, checks []doctor.Check, name string) doctor.Check {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q row in %+v", name, checks)
	return doctor.Check{}
}

// Every catalogued Tool gets a row. An installed one passes and says which Tool
// it is.
func TestRun_ReportsAnInstalledCataloguedTool(t *testing.T) {
	binDir := t.TempDir()
	makeStubBinary(t, binDir, "scanner-bin")
	t.Setenv("PATH", binDir)
	t.Setenv("GEMINI_API_KEY", "stub")

	checks := doctor.Run(doctor.Options{
		Home:    t.TempDir(),
		Catalog: []security.Entry{stubEntry("scanner", "scanner-bin")},
	})

	c := checkNamed(t, checks, "scanner")
	if c.Status != doctor.Pass {
		t.Errorf("an installed Tool should Pass, got %v (%s)", c.Status, c.Hint)
	}
	if !strings.Contains(c.Message, "run_scanner") {
		t.Errorf("message should name the Tool, got %q", c.Message)
	}
}

// A catalogued Tool that is not installed is information, not a failure: a
// minimal install is healthy. The row says how to install it and links the
// catalog page that explains why one would.
func TestRun_ReportsAMissingCataloguedToolAsInfoWithItsCatalogLink(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("GEMINI_API_KEY", "stub")

	entry := stubEntry("scanner", "scanner-bin")
	checks := doctor.Run(doctor.Options{Home: t.TempDir(), Catalog: []security.Entry{entry}})

	c := checkNamed(t, checks, "scanner")
	if c.Status != doctor.Info || c.Severity != doctor.SeverityInfo {
		t.Errorf("a missing Tool should be Info, got status %v severity %v", c.Status, c.Severity)
	}
	for _, want := range []string{"not installed", "brew install scanner-bin", entry.URL()} {
		if !strings.Contains(c.Message, want) {
			t.Errorf("message %q should mention %q", c.Message, want)
		}
	}
	if s := doctor.Summarize([]doctor.Check{c}); s.HasBlockingFailure() || s.OptionalMissing != 0 {
		t.Errorf("a missing Tool must neither fail the run nor count as missing: %+v", s)
	}
}

// What is installed is the injected lookup's answer, not the host's PATH: the
// same seam the daemon's discovery has, so doctor and registration can be held
// to one answer under test.
func TestRun_AsksTheInjectedLookupWhatIsInstalled(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("GEMINI_API_KEY", "stub")

	lookPath := func(name string) (string, error) {
		if name == "scanner-bin" {
			return "/opt/bin/" + name, nil
		}
		return "", os.ErrNotExist
	}
	checks := doctor.Run(doctor.Options{
		Home:     t.TempDir(),
		Catalog:  []security.Entry{stubEntry("scanner", "scanner-bin")},
		LookPath: lookPath,
	})

	if c := checkNamed(t, checks, "scanner"); c.Status != doctor.Pass {
		t.Errorf("the lookup finds scanner-bin, so the Tool is installed; got %+v", c)
	}
}

// A Tool the operator switched off (tools.disabled) gets a "disabled" row,
// even though its binary is installed: it is not offered, and that is a choice,
// so the row is information — never a failure, and never an install hint.
func TestRun_ReportsADisabledCataloguedToolAsDisabled(t *testing.T) {
	binDir := t.TempDir()
	makeStubBinary(t, binDir, "scanner-bin")
	t.Setenv("PATH", binDir)
	t.Setenv("GEMINI_API_KEY", "stub")

	checks := doctor.Run(doctor.Options{
		Home:          t.TempDir(),
		Catalog:       []security.Entry{stubEntry("scanner", "scanner-bin"), stubEntry("other", "scanner-bin")},
		DisabledTools: []string{"scanner"},
	})

	c := checkNamed(t, checks, "scanner")
	if c.Status != doctor.Info || c.Severity != doctor.SeverityInfo {
		t.Errorf("a disabled Tool should be Info, got status %v severity %v", c.Status, c.Severity)
	}
	if !strings.Contains(c.Message, "disabled") || !strings.Contains(c.Message, "tools.disabled") {
		t.Errorf("message %q should say the Tool is disabled in tools.disabled", c.Message)
	}
	if strings.Contains(c.Message, "install") || c.Hint != "" {
		t.Errorf("a disabled Tool needs no install hint, got message %q hint %q", c.Message, c.Hint)
	}
	if other := checkNamed(t, checks, "other"); other.Status != doctor.Pass {
		t.Errorf("a Tool that is not disabled is unaffected, got %v", other.Status)
	}
}

// The image contract is about what the image ships, not what argus.yaml
// happens to use: disabling a Tool cannot hide its missing binary from it.
func TestRun_BinariesOnly_DisabledToolStillOwesItsBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	checks := doctor.Run(doctor.Options{
		Catalog:       []security.Entry{manifestEntry("scanner", "scanner-bin")},
		DisabledTools: []string{"scanner"},
		BinariesOnly:  true,
	})

	if c := checkNamed(t, checks, "scanner"); c.Status != doctor.Fail || c.Severity != doctor.SeverityRequired {
		t.Errorf("a missing binary must block the image contract even when disabled, got %v/%v", c.Status, c.Severity)
	}
}

// A Tool needing several binaries is one row, and it names the ones missing.
func TestRun_NamesTheMissingBinariesOfAMultiBinaryTool(t *testing.T) {
	binDir := t.TempDir()
	makeStubBinary(t, binDir, "scanner-bin")
	t.Setenv("PATH", binDir)
	t.Setenv("GEMINI_API_KEY", "stub")

	checks := doctor.Run(doctor.Options{
		Home:    t.TempDir(),
		Catalog: []security.Entry{stubEntry("scanner", "scanner-bin", "toolchain")},
	})

	c := checkNamed(t, checks, "scanner")
	if c.Status != doctor.Info {
		t.Errorf("a Tool missing one of its binaries is not installed, got %v", c.Status)
	}
	if !strings.Contains(c.Message, "brew install toolchain") || strings.Contains(c.Message, "brew install scanner-bin") {
		t.Errorf("message should give the install hint of the missing binary only, got %q", c.Message)
	}
}

// enginesEntry is a catalogued Tool over two alternative engines, preferred
// first, like the SAST Tool's opengrep and semgrep.
func enginesEntry() security.Entry {
	e := stubEntry("sast", "preferred-engine", "fallback-engine")
	e.Alternatives = true
	return e
}

// A Tool over alternative engines is installed when either engine is, and its
// row says which one it will run: the preferred one when both are there.
func TestRun_ReportsAToolOverAlternativeEnginesAsInstalledWithEitherEngine(t *testing.T) {
	for _, tc := range []struct {
		name, onPath, want string
		both               bool
	}{
		{name: "fallback only", onPath: "fallback-engine", want: "fallback-engine"},
		{name: "both", onPath: "fallback-engine", want: "preferred-engine", both: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binDir := t.TempDir()
			makeStubBinary(t, binDir, tc.onPath)
			if tc.both {
				makeStubBinary(t, binDir, "preferred-engine")
			}
			t.Setenv("PATH", binDir)
			t.Setenv("GEMINI_API_KEY", "stub")

			c := checkNamed(t, doctor.Run(doctor.Options{Home: t.TempDir(), Catalog: []security.Entry{enginesEntry()}}), "sast")

			if c.Status != doctor.Pass {
				t.Errorf("one engine is enough, got %v (%s)", c.Status, c.Message)
			}
			if !strings.Contains(c.Message, tc.want) {
				t.Errorf("message %q should name the engine that will run, %s", c.Message, tc.want)
			}
		})
	}
}

// With neither engine, the row offers either one, not both: installing one is
// enough.
func TestRun_ReportsAToolOverAlternativeEnginesAsMissingWithEitherInstallHint(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("GEMINI_API_KEY", "stub")

	c := checkNamed(t, doctor.Run(doctor.Options{Home: t.TempDir(), Catalog: []security.Entry{enginesEntry()}}), "sast")

	if c.Status != doctor.Info {
		t.Errorf("a Tool with no engine is not installed, got %v", c.Status)
	}
	for _, want := range []string{"one of", "brew install preferred-engine", "brew install fallback-engine"} {
		if !strings.Contains(c.Message, want) {
			t.Errorf("message %q should mention %q", c.Message, want)
		}
	}
}

// manifestEntry is a catalogued Tool the official image ships (the Manifest).
func manifestEntry(id string, binaries ...string) security.Entry {
	e := stubEntry(id, binaries...)
	e.Manifest = true
	return e
}

// The image contract is the Manifest: a Tool the image does not ship is the
// operator's to install, so its absence is not a broken image.
func TestRun_BinariesOnly_IgnoresAToolOutsideTheManifest(t *testing.T) {
	binDir := t.TempDir()
	makeStubBinary(t, binDir, "scanner-bin")
	t.Setenv("PATH", binDir)

	checks := doctor.Run(doctor.Options{
		Catalog: []security.Entry{
			manifestEntry("scanner", "scanner-bin"),
			stubEntry("extra", "toolchain", "extra-bin"),
		},
		BinariesOnly: true,
	})

	if doctor.Summarize(checks).HasBlockingFailure() {
		t.Errorf("a missing Tool outside the Manifest must not fail the image contract: %+v", checks)
	}
	if slices.ContainsFunc(checks, func(c doctor.Check) bool { return c.Name == "extra" }) {
		t.Errorf("the image contract checks the Manifest only, got an %q row: %+v", "extra", checks)
	}
}

// Every Manifest Tool is owed, and the row names what is missing.
func TestRun_BinariesOnly_MissingManifestBinaryBlocks(t *testing.T) {
	binDir := t.TempDir()
	makeStubBinary(t, binDir, "scanner-bin")
	t.Setenv("PATH", binDir)

	checks := doctor.Run(doctor.Options{
		Catalog:      []security.Entry{manifestEntry("scanner", "scanner-bin", "toolchain")},
		BinariesOnly: true,
	})

	c := checkNamed(t, checks, "scanner")
	if c.Status != doctor.Fail || c.Severity != doctor.SeverityRequired {
		t.Errorf("a Manifest Tool missing a binary must block, got %v/%v", c.Status, c.Severity)
	}
	if !strings.Contains(c.Message, "brew install toolchain") {
		t.Errorf("the row should name the missing binary's install hint, got %q", c.Message)
	}
}

// A Manifest Tool over alternative engines is owed one engine, not all of
// them: the image ships whichever it chose.
func TestRun_BinariesOnly_AManifestToolOverAlternativeEnginesNeedsOneEngine(t *testing.T) {
	engines := enginesEntry()
	engines.Manifest = true

	t.Run("one engine", func(t *testing.T) {
		binDir := t.TempDir()
		makeStubBinary(t, binDir, "preferred-engine")
		t.Setenv("PATH", binDir)

		checks := doctor.Run(doctor.Options{Catalog: []security.Entry{engines}, BinariesOnly: true})

		if c := checkNamed(t, checks, "sast"); c.Status != doctor.Pass {
			t.Errorf("one engine satisfies the image contract, got %v (%s)", c.Status, c.Message)
		}
	})
	t.Run("no engine", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())

		checks := doctor.Run(doctor.Options{Catalog: []security.Entry{engines}, BinariesOnly: true})

		if c := checkNamed(t, checks, "sast"); c.Status != doctor.Fail || c.Severity != doctor.SeverityRequired {
			t.Errorf("no engine must block the image contract, got %v/%v", c.Status, c.Severity)
		}
	})
}

func TestRun_BinariesOnly_AllPresentSucceeds(t *testing.T) {
	binDir := t.TempDir()
	homeDir := t.TempDir()
	makeStubBinary(t, binDir, "git")
	makeStubBinary(t, binDir, "scanner-bin")
	t.Setenv("PATH", binDir)
	// No API key / config on purpose: they must not affect the outcome.
	t.Setenv("GEMINI_API_KEY", "")

	checks := doctor.Run(doctor.Options{
		Home:         homeDir,
		Catalog:      []security.Entry{manifestEntry("scanner", "scanner-bin")},
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

	checks := doctor.Run(doctor.Options{
		Home:         homeDir,
		Catalog:      []security.Entry{manifestEntry("scanner", "scanner-bin")},
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

	checks := doctor.Run(doctor.Options{
		Home:         homeDir,
		Catalog:      []security.Entry{manifestEntry("scanner", "scanner-bin")},
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
		// Supplied on purpose: the image-contract check must not reach the network
		// even when the caller has a Provider to probe.
		Provider: &doctor.ProviderTarget{Type: "openai-compatible", Model: "m", Endpoint: "http://x/v1"},
		ProviderModels: func(context.Context) ([]string, error) {
			t.Error("binaries-only mode must not probe the LLM provider")
			return nil, nil
		},
	})

	for _, c := range checks {
		switch c.Name {
		case "deployment", "argus.yaml", "gemini api key", "llm provider", "SOUL.md", "context/", "github":
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

package security_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/security"
)

func init() {
	f := toolFixture{empty: `{"Golang errors":{},"Issues":[],"Stats":{"files":1,"lines":1,"nosec":0,"found":0}}`}
	// #nosec and //gosec:disable annotations are ignored. gosec loads no
	// config file unless told to, and is never told to.
	f.repoConfig.switches = []string{"-nosec=true"}
	fixture("gosec", f)
}

// TestGosec_RunsInTheHardenedGoEnvironment: gosec loads the reviewed packages
// through the go command, which on its defaults downloads a newer toolchain
// when go.mod asks for one, rewrites go.mod, honours a go.work found above the
// tree, compiles C through cgo, fetches modules from wherever go.mod points and
// runs a gopackagesdriver it finds on PATH. Its environment is exactly the
// hardened Go profile over the scratch directory: whatever the daemon's own Go
// settings say, and with nothing else (no token, no LLM key) inherited.
func TestGosec_RunsInTheHardenedGoEnvironment(t *testing.T) {
	// The daemon's environment loosens every one of these, and carries the
	// keys that would turn gosec's AI fix suggestions on.
	for k, v := range map[string]string{
		"GOTOOLCHAIN":       "auto",
		"GOFLAGS":           "-mod=mod",
		"GOWORK":            "/elsewhere/go.work",
		"CGO_ENABLED":       "1",
		"GOPROXY":           "https://proxy.golang.org,direct",
		"GONOSUMDB":         "*",
		"GOPACKAGESDRIVER":  "/usr/local/bin/driver",
		"GOSEC_AI_API_KEY":  "sk-should-never-reach-gosec",
		"GOSEC_AI_PROVIDER": "claude",
		"ANTHROPIC_API_KEY": "sk-should-never-reach-gosec",
		"GITHUB_TOKEN":      "ghp_should-never-reach-gosec",
	} {
		t.Setenv(k, v)
	}

	fr := &fakeRunner{out: emptyReport("gosec")}
	if _, err := security.NewGosec(sessionAt(checkout(t)), fr).Execute(context.Background(), map[string]any{}); err != nil {
		t.Fatalf("execute: %v", err)
	}

	scratch := fr.gotCmd.Dir
	home := filepath.Join(scratch, "home")
	want := map[string]string{
		"PATH":            os.Getenv("PATH"),
		"HOME":            home,
		"TMPDIR":          filepath.Join(scratch, "tmp"),
		"XDG_CACHE_HOME":  filepath.Join(home, ".cache"),
		"XDG_CONFIG_HOME": filepath.Join(home, ".config"),
		"XDG_DATA_HOME":   filepath.Join(home, ".local", "share"),

		"GOTOOLCHAIN":      "local",
		"GOFLAGS":          "-mod=readonly",
		"GOWORK":           "off",
		"CGO_ENABLED":      "0",
		"GOPROXY":          "https://proxy.golang.org",
		"GOSUMDB":          "sum.golang.org",
		"GOENV":            "off",
		"GOPACKAGESDRIVER": "off",
		"GOPATH":           filepath.Join(home, "go"),
		"GOCACHE":          filepath.Join(home, ".cache", "go-build"),
	}
	got := envMap(fr.gotCmd.Env)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	for k, v := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("%s=%s is not part of the hardened Go environment", k, v)
		}
	}
	if len(fr.gotCmd.Env) != len(got) {
		t.Errorf("a variable is set twice, so which value wins is up to the child: %v", fr.gotCmd.Env)
	}
	if strings.Contains(got["GOPROXY"], "direct") {
		t.Errorf("GOPROXY = %q must never fall back to direct", got["GOPROXY"])
	}
}

// TestGosec_NeverTurnsOnItsAIFeatures: gosec sends the issues it found, code
// included, to an LLM when it is given a provider. Argus never gives it one,
// neither by flag nor by environment.
func TestGosec_NeverTurnsOnItsAIFeatures(t *testing.T) {
	t.Setenv("GOSEC_AI_PROVIDER", "claude")
	fr := &fakeRunner{out: emptyReport("gosec")}
	if _, err := security.NewGosec(sessionAt(checkout(t)), fr).Execute(context.Background(), map[string]any{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	for _, a := range fr.gotArgs {
		if strings.HasPrefix(strings.TrimLeft(a, "-"), "ai-") {
			t.Errorf("gosec was passed an AI flag: %v", fr.gotArgs)
		}
	}
	for _, kv := range fr.gotCmd.Env {
		if strings.HasPrefix(kv, "GOSEC_") {
			t.Errorf("gosec was handed %s", kv)
		}
	}
}

// TestGosec_ScansEveryPackageUnderTheTarget: the target is a directory tree,
// and gosec only descends into it when told with the /... pattern.
func TestGosec_ScansEveryPackageUnderTheTarget(t *testing.T) {
	root := checkout(t)
	fr := &fakeRunner{out: emptyReport("gosec")}
	if _, err := security.NewGosec(sessionAt(root), fr).Execute(context.Background(), map[string]any{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if want := root + "/..."; !slices.Contains(fr.gotArgs, want) {
		t.Errorf("gosec args %v do not name %q", fr.gotArgs, want)
	}
	if v, _ := optionValue(fr.gotArgs, "-fmt"); v != "json" {
		t.Errorf("gosec must report JSON, got %v", fr.gotArgs)
	}
}

// TestGosec_ReportsNosecFindingsAsSuppressedInRepo: gosec runs with its
// in-code suppressions ignored, so a `#nosec` or `//gosec:disable` the pull
// request added no longer hides the hit. The finding comes back marked, and
// only for the rules the annotation names: `#nosec G204` says nothing about
// the command-injection taint finding (G702) on the same line.
func TestGosec_ReportsNosecFindingsAsSuppressedInRepo(t *testing.T) {
	rep := scan(t, "gosec")
	if rep.Scanner != "gosec" {
		t.Errorf("scanner = %q, want gosec", rep.Scanner)
	}
	if len(rep.Findings) != 6 {
		t.Fatalf("got %d findings, want the 6 in the recorded report: %+v", len(rep.Findings), rep.Findings)
	}
	for _, f := range rep.Findings {
		if f.File != "main.go" {
			t.Errorf("%s: file = %q, want main.go relative to the checkout", f.RuleID, f.File)
		}
	}
	if f := atRule(t, rep, 15, "G204"); !f.SuppressedInRepo || !strings.Contains(f.Suppression, "#nosec") {
		t.Errorf("a #nosec G204 finding must be reported as suppressed in the repo: %+v", f)
	}
	if f := atRule(t, rep, 15, "G702"); f.SuppressedInRepo {
		t.Errorf("#nosec G204 does not name G702, so G702 must not be marked: %+v", f)
	}
	if f := atRule(t, rep, 20, "G401"); !f.SuppressedInRepo || !strings.Contains(f.Suppression, "gosec:disable") {
		t.Errorf("a //gosec:disable on the line above must mark the finding: %+v", f)
	}
	plain := atRule(t, rep, 11, "G204")
	if plain.SuppressedInRepo || plain.Suppression != "" {
		t.Errorf("a finding nobody tried to silence must not be marked: %+v", plain)
	}
	if plain.Severity != "medium" || plain.Title == "" || plain.Details["cwe"] != "CWE-78" {
		t.Errorf("finding lost gosec's severity, title or CWE: %+v", plain)
	}
}

// TestGosec_PassesItsIgnoreNosecSwitchOnEveryRun: the annotations are the
// pull request's, so gosec never honours them, and nothing that would hide
// generated files (which a pull request can claim to be) is ever switched on.
func TestGosec_PassesItsIgnoreNosecSwitchOnEveryRun(t *testing.T) {
	fr := &fakeRunner{out: emptyReport("gosec")}
	if _, err := security.NewGosec(sessionAt(checkout(t)), fr).Execute(context.Background(), map[string]any{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if v, ok := optionValue(fr.gotArgs, "-nosec"); !ok || v != "true" {
		t.Errorf("gosec must run with -nosec=true, got %v", fr.gotArgs)
	}
	for _, banned := range []string{"-exclude-generated", "-conf", "-nosec-tag", "-track-suppressions"} {
		if slices.ContainsFunc(fr.gotArgs, func(a string) bool { return a == banned || strings.HasPrefix(a, banned+"=") }) {
			t.Errorf("gosec must not run with %s: %v", banned, fr.gotArgs)
		}
	}
}

// TestGosec_ReportsPackagesItCouldNotLoadAsErrors: in the hardened
// environment gosec can fail to load a package (a go.mod asking for a newer Go
// than the host's, a dependency the module cache does not have). Those are
// gaps in coverage the model must be told about, not a clean result.
func TestGosec_ReportsPackagesItCouldNotLoadAsErrors(t *testing.T) {
	root := checkout(t)
	report := `{"Golang errors":{"` + root + `":[{"line":0,"column":0,"error":"go: go.mod requires go >= 1.99 (running go 1.26.0; GOTOOLCHAIN=local)"}],` +
		`"` + root + `/main.go":[{"line":8,"column":2,"error":"could not import golang.org/x/text/language"}]},"Issues":[],"Stats":{}}`
	out, err := security.NewGosec(sessionAt(root), &fakeRunner{out: report}).Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	var rep security.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("output is not a findings report: %v\n%s", err, out)
	}
	if len(rep.Errors) != 2 {
		t.Fatalf("errors = %v, want both load failures", rep.Errors)
	}
	joined := strings.Join(rep.Errors, "\n")
	if !strings.Contains(joined, "GOTOOLCHAIN=local") || !strings.Contains(joined, "main.go:8: could not import") {
		t.Errorf("errors = %v, want each load failure with its file and line", rep.Errors)
	}
	if strings.Contains(joined, root) {
		t.Errorf("errors name the checkout by absolute path instead of relative to it: %v", rep.Errors)
	}
}

// TestGosec_CleansUpAReadOnlyModuleCache: the go command writes its module
// cache read-only. Whatever it downloaded during the run is still removed with
// the scratch directory.
func TestGosec_CleansUpAReadOnlyModuleCache(t *testing.T) {
	r := &moduleCacheRunner{}
	if _, err := security.NewGosec(sessionAt(checkout(t)), r).Execute(context.Background(), map[string]any{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if r.dir == "" {
		t.Fatal("the runner never ran")
	}
	if _, err := os.Stat(r.dir); !os.IsNotExist(err) {
		t.Errorf("scratch directory %q survived the run (stat err: %v)", r.dir, err)
	}
}

// moduleCacheRunner behaves like the go command filling its module cache: it
// leaves read-only directories behind in GOPATH, then writes an empty report.
type moduleCacheRunner struct{ dir string }

func (m *moduleCacheRunner) Run(_ context.Context, cmd security.Command) (string, error) {
	m.dir = cmd.Dir
	mod := filepath.Join(envMap(cmd.Env)["GOPATH"], "pkg", "mod", "example.com", "dep@v1.0.0")
	if err := os.MkdirAll(mod, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(mod, "dep.go"), []byte("package dep\n"), 0o444); err != nil {
		return "", err
	}
	for _, d := range []string{mod, filepath.Dir(mod)} {
		if err := os.Chmod(d, 0o555); err != nil {
			return "", err
		}
	}
	out, _ := optionValue(cmd.Args, "-out")
	return "", os.WriteFile(out, []byte(emptyReport("gosec")), 0o600)
}

// atRule finds the one finding for rule on line of main.go.
func atRule(t *testing.T, rep security.Report, line int, rule string) security.Finding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.Line == line && f.RuleID == rule {
			return f
		}
	}
	t.Fatalf("no %s finding on line %d in %+v", rule, line, rep.Findings)
	return security.Finding{}
}

package security_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/argusappsec/argus/pkg/security"
	"github.com/argusappsec/argus/pkg/session"
)

// repoConfigFlags is, per scanner, what makes it obey only Argus's config:
// switches that must be present, and options whose value must be a file Argus
// wrote into the run's scratch directory rather than anything in the checkout.
var repoConfigFlags = map[string]struct {
	switches []string
	scratch  []string
}{
	// nosem comments and .semgrepignore files are the pull request's; the
	// ruleset is Argus's own.
	"semgrep": {
		switches: []string{"--disable-nosem", "--x-ignore-semgrepignore-files"},
		scratch:  []string{"--config"},
	},
	// gitleaks:allow comments are ignored; the config and the ignore-file
	// location are Argus's, so (target)/.gitleaks.toml is never read.
	"gitleaks": {
		switches: []string{"--ignore-gitleaks-allow"},
		scratch:  []string{"--config", "--gitleaks-ignore-path"},
	},
	// An explicit --config overrides every osv-scanner.toml next to a
	// lockfile, and --no-ignore stops a committed .gitignore from hiding one.
	"osv-scanner": {
		switches: []string{"--no-ignore"},
		scratch:  []string{"--config"},
	},
	// #nosec and //gosec:disable annotations are ignored. gosec loads no
	// config file unless told to, and is never told to.
	"gosec": {
		switches: []string{"-nosec=true"},
	},
	// govulncheck has no config file, ignore file or in-code suppression to
	// switch off: it obeys nothing in the checkout.
	"govulncheck": {},
}

// TestScanners_AlwaysPassTheirIgnoreRepoConfigFlags: the checkout is the pull
// request's, and so is every config or ignore file in it. Each scanner is told
// explicitly to use Argus's settings, on every run, whoever asked for the scan:
// a review pinned on a checkout, or a caller naming a directory (the Toolbox).
// A Tool takes no review kind, so automatic reviews and reviews a Person
// requested run the scanner identically.
func TestScanners_AlwaysPassTheirIgnoreRepoConfigFlags(t *testing.T) {
	for name, build := range scanners {
		want := repoConfigFlags[name]
		runs := map[string]func(root string) (*session.Session, map[string]any){
			"review": func(root string) (*session.Session, map[string]any) { return sessionAt(root), map[string]any{} },
			"caller-named target": func(root string) (*session.Session, map[string]any) {
				return session.New(), map[string]any{"path": root}
			},
		}
		for how, setup := range runs {
			t.Run(name+"/"+how, func(t *testing.T) {
				root := checkout(t)
				fr := &fakeRunner{out: emptyReport[name]}
				sess, args := setup(root)
				if _, err := build(sess, fr).Execute(context.Background(), args); err != nil {
					t.Fatalf("execute: %v", err)
				}
				for _, sw := range want.switches {
					if !slices.Contains(fr.gotArgs, sw) {
						t.Errorf("missing %s in %v", sw, fr.gotArgs)
					}
				}
				for _, opt := range want.scratch {
					v, ok := optionValue(fr.gotArgs, opt)
					if !ok {
						t.Errorf("missing %s in %v", opt, fr.gotArgs)
						continue
					}
					if !inside(fr.gotCmd.Dir, v) || inside(root, v) {
						t.Errorf("%s %q must name Argus's file in the scratch directory %q, never the checkout %q",
							opt, v, fr.gotCmd.Dir, root)
					}
				}
			})
		}
	}
}

// TestGitleaks_ScansTheDirectoryWithTheDefaultRules: the config Argus hands
// gitleaks extends the built-in rules and adds nothing, so gitleaks finds what
// it finds out of the box, minus nothing a pull request committed. It scans
// the tree as files: in git mode a committed .gitleaksignore can match the
// repository-relative fingerprints gitleaks prints there.
func TestGitleaks_ScansTheDirectoryWithTheDefaultRules(t *testing.T) {
	fr := &fakeRunner{out: `[]`}
	if _, err := security.NewGitleaks(sessionAt(checkout(t)), fr).Execute(context.Background(), map[string]any{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(fr.gotArgs) < 2 || fr.gotArgs[1] != "dir" {
		t.Errorf("gitleaks must run its `dir` scan, got %v", fr.gotArgs)
	}
	cfg, _ := optionValue(fr.gotArgs, "--config")
	body := strings.Join(strings.Fields(fr.gotFiles[cfg]), " ")
	if body != "[extend] useDefault = true" {
		t.Errorf("gitleaks config = %q, want only an extension of the default rules", fr.gotFiles[cfg])
	}
}

// TestOSVScanner_UsesAnEmptyConfig: with an empty config osv-scanner applies
// no ignores and no overrides at all.
func TestOSVScanner_UsesAnEmptyConfig(t *testing.T) {
	fr := &fakeRunner{out: `{"results":[]}`}
	if _, err := security.NewOSVScanner(sessionAt(checkout(t)), fr).Execute(context.Background(), map[string]any{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	cfg, _ := optionValue(fr.gotArgs, "--config")
	if body, ok := fr.gotFiles[cfg]; !ok || strings.TrimSpace(body) != "" {
		t.Errorf("osv-scanner config %q = %q, want an empty file", cfg, body)
	}
}

// TestSemgrep_AlwaysRunsThePinnedRuleset: ADR 0019 Phase 1. `--config auto`
// fetches rules from the registry and sends metrics, and a model-chosen config
// is a lever a prompt injection can pull to point semgrep at a ruleset the
// pull request committed. semgrep runs Argus's pinned ruleset and nothing else,
// whatever the caller passes.
func TestSemgrep_AlwaysRunsThePinnedRuleset(t *testing.T) {
	pinned, err := os.ReadFile(filepath.Join("rules", "semgrep.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, asked := range []string{"", "auto", "p/security-audit", "/repo/.semgrep.yml"} {
		t.Run("config="+asked, func(t *testing.T) {
			root := checkout(t)
			fr := &fakeRunner{out: `{"results":[],"errors":[]}`}
			args := map[string]any{}
			if asked != "" {
				args["config"] = asked
			}
			if _, err := security.NewSemgrep(sessionAt(root), fr).Execute(context.Background(), args); err != nil {
				t.Fatalf("execute: %v", err)
			}
			var configs []string
			for i, a := range fr.gotArgs {
				if a == "--config" && i+1 < len(fr.gotArgs) {
					configs = append(configs, fr.gotArgs[i+1])
				}
			}
			if len(configs) != 1 {
				t.Fatalf("semgrep must get exactly one --config, got %v", fr.gotArgs)
			}
			if fr.gotFiles[configs[0]] != string(pinned) {
				t.Errorf("--config %q is not the pinned ruleset", configs[0])
			}
			if v, _ := optionValue(fr.gotArgs, "--metrics"); v != "off" {
				t.Errorf("semgrep must run with --metrics off, got %v", fr.gotArgs)
			}
			if slices.Contains(fr.gotArgs, "auto") {
				t.Errorf("semgrep was invoked with auto: %v", fr.gotArgs)
			}
		})
	}
}

// TestSemgrep_OffersNoRulesetChoice: the schema no longer advertises a config
// argument, so the model is not invited to pick one.
func TestSemgrep_OffersNoRulesetChoice(t *testing.T) {
	props, _ := security.NewSemgrep(session.New(), &fakeRunner{}).Schema()["properties"].(map[string]any)
	if _, ok := props["config"]; ok {
		t.Error("run_semgrep must not offer a config argument")
	}
}

// TestSemgrepRuleset_IsSelfContained: the pinned ruleset is the whole of what
// runs, so it must parse, give every rule a stable argus.* id once, and
// reference nothing outside itself.
func TestSemgrepRuleset_IsSelfContained(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("rules", "semgrep.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var rs struct {
		Rules []map[string]any `yaml:"rules"`
	}
	if err := yaml.Unmarshal(body, &rs); err != nil {
		t.Fatalf("ruleset does not parse: %v", err)
	}
	if len(rs.Rules) == 0 {
		t.Fatal("ruleset has no rules")
	}
	seen := map[string]bool{}
	for _, r := range rs.Rules {
		id, _ := r["id"].(string)
		if !strings.HasPrefix(id, "argus.") {
			t.Errorf("rule id %q must start with argus.", id)
		}
		if seen[id] {
			t.Errorf("rule id %q is declared twice", id)
		}
		seen[id] = true
		for _, k := range []string{"languages", "severity", "message"} {
			if _, ok := r[k]; !ok {
				t.Errorf("rule %q has no %s", id, k)
			}
		}
	}
	if strings.Contains(string(body), "http://") || strings.Contains(string(body), "https://") {
		t.Error("the pinned ruleset must not reference anything remote")
	}
}

// optionValue returns the value following opt in args, also accepting the
// --opt=value spelling.
func optionValue(args []string, opt string) (string, bool) {
	for i, a := range args {
		if a == opt && i+1 < len(args) {
			return args[i+1], true
		}
		if v, ok := strings.CutPrefix(a, opt+"="); ok {
			return v, true
		}
	}
	return "", false
}

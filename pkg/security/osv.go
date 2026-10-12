package security

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

// NewOSVScanner returns a `run_osv_scanner` tool that scans the Session's
// current target directory for known vulnerabilities in its dependencies
// (supply-chain coverage), complementing semgrep (static analysis) and
// gitleaks (secrets).
func NewOSVScanner(s *session.Session, r Runner) tool.Tool {
	return &osvScanner{sess: s, runner: r}
}

type osvScanner struct {
	sess   *session.Session
	runner Runner

	// noCallAnalysis is set on automatic reviews. With go on PATH, osv-scanner
	// runs Go call analysis by default, which loads the reviewed packages
	// through the Go toolchain: not something to do with a stranger's code
	// (ADR 0027). Reviews a Person asked for keep the reachability filtering.
	noCallAnalysis bool
}

func (o *osvScanner) Name() string { return "run_osv_scanner" }

func (o *osvScanner) Description() string {
	return "Run osv-scanner to detect known vulnerabilities (CVEs) in the dependencies declared under a " +
		"directory on the machine Argus runs on. Returns one finding per vulnerability and package, which you " +
		"must triage. A finding marked suppressed_in_repo is ignored by an osv-scanner.toml in the code: it is " +
		"still a finding, and the attempt to silence it is itself worth a look."
}

func (o *osvScanner) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": targetSchemaProperty(),
		},
	}
}

func init() {
	catalogue(Entry{
		ID:      "osv-scanner",
		Tool:    "run_osv_scanner",
		Name:    "OSV-Scanner",
		Purpose: "Finds dependencies with known vulnerabilities by reading lockfiles and manifests.",
		Why: "Most exploitable flaws in an application live in its dependencies. OSV-Scanner reads " +
			"the lockfiles of every major ecosystem and matches them against the OSV database, so a " +
			"review reports a vulnerable version the moment a change introduces it.",
		Finds:      []Find{FindSCA},
		Reads:      []Read{ReadMultiLanguage},
		DocsURL:    "https://google.github.io/osv-scanner/",
		InstallURL: "https://google.github.io/osv-scanner/installation/",
		License:    "Apache-2.0",
		Manifest:   true,
		Binaries: []Binary{{
			Name:        "osv-scanner",
			InstallHint: "brew install osv-scanner  (or go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest)",
		}},
		// Safe because an automatic review switches off its one toolchain-driving
		// mode, Go call analysis (see Execute).
		Trust: TrustSafe,
		New: func(d Deps) tool.Tool {
			return &osvScanner{sess: d.Session, runner: d.Commands, noCallAnalysis: d.Automatic}
		},
	})
}

func (o *osvScanner) Execute(ctx context.Context, args map[string]any) (string, error) {
	root, err := scanTarget(o.sess, args)
	if err != nil {
		return "", err
	}

	// The JSON report goes to a file via --output rather than stdout:
	// osv-scanner logs progress to stderr, which the Runner merges with
	// stdout, so the combined stream is not reliably JSON (see runForReport).
	sc, err := newScratch("osv-scanner")
	if err != nil {
		return "", err
	}
	defer sc.remove()
	reportPath := sc.file("report.json")
	// An explicit --config, even an empty one, overrides every
	// osv-scanner.toml next to a scanned lockfile: the repository's
	// IgnoredVulns and PackageOverrides no longer apply.
	config, err := sc.write("osv-scanner.toml", nil)
	if err != nil {
		return "", fmt.Errorf("osv-scanner: %w", err)
	}

	// osv-scanner keeps its vulnerability database cache under the user cache
	// directory, which Go resolves through XDG_CACHE_HOME or HOME; both point
	// into the scratch directory.
	argv := []string{"osv-scanner",
		"--format", "json",
		"--output", reportPath,
		"--config", config,
		// A .gitignore the pull request committed must not hide a lockfile.
		"--no-ignore",
	}
	if o.noCallAnalysis {
		argv = append(argv, "--no-call-analysis=go")
	}
	argv = append(argv, "--recursive", root)
	body, err := runForReport(ctx, o.runner, "osv-scanner", sc.command(sc.xdg(), argv...), reportPath)
	if err != nil {
		return "", err
	}
	return parseOSV(body, openCheckout(o.sess, root))
}

// osvOutput is the part of osv-scanner's JSON report Argus reads.
type osvOutput struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []osvVuln `json:"vulnerabilities"`
			Groups          []struct {
				IDs         []string `json:"ids"`
				Aliases     []string `json:"aliases"`
				MaxSeverity string   `json:"max_severity"`
			} `json:"groups"`
		} `json:"packages"`
	} `json:"results"`
}

type osvVuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// fixedIn lists the versions that fix this vulnerability for one package.
func (v osvVuln) fixedIn(pkg string) []string {
	var out []string
	for _, a := range v.Affected {
		if a.Package.Name != pkg {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if f := e["fixed"]; f != "" && !slices.Contains(out, f) {
					out = append(out, f)
				}
			}
		}
	}
	return out
}

func parseOSV(body []byte, files *checkoutFiles) (string, error) {
	defer files.close()
	var out osvOutput
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("osv-scanner: unreadable report: %w", err)
	}
	configs := map[string]osvRepoConfig{}
	rep := Report{Scanner: "osv-scanner"}
	for _, res := range out.Results {
		file, inCheckout := files.rel(res.Source.Path)
		var cfg osvRepoConfig
		if inCheckout {
			dir := path.Dir(file)
			if _, seen := configs[dir]; !seen {
				configs[dir] = readOSVConfig(files, dir)
			}
			cfg = configs[dir]
		}
		for _, p := range res.Packages {
			vulns := map[string]osvVuln{}
			for _, v := range p.Vulnerabilities {
				vulns[v.ID] = v
			}
			// osv-scanner groups the advisories that describe one
			// vulnerability (a GO- id and its GHSA twin); one finding per
			// group. A report without groups gets one per advisory.
			type group struct {
				ids, aliases []string
				severity     string
			}
			var groups []group
			for _, g := range p.Groups {
				groups = append(groups, group{g.IDs, g.Aliases, g.MaxSeverity})
			}
			if len(groups) == 0 {
				for _, v := range p.Vulnerabilities {
					groups = append(groups, group{ids: []string{v.ID}, aliases: v.Aliases})
				}
			}
			for _, g := range groups {
				if len(g.ids) == 0 {
					continue
				}
				lead := vulns[g.ids[0]]
				aliases := g.aliases
				if len(aliases) == 0 {
					aliases = lead.Aliases
				}
				details := map[string]any{
					"package":   p.Package.Name,
					"version":   p.Package.Version,
					"ecosystem": p.Package.Ecosystem,
				}
				if len(aliases) > 0 {
					details["aliases"] = aliases
				}
				if fixed := lead.fixedIn(p.Package.Name); len(fixed) > 0 {
					details["fixed_in"] = fixed
				}
				f := Finding{
					RuleID:   g.ids[0],
					Severity: g.severity,
					File:     file,
					Title:    lead.Summary,
					Details:  details,
				}
				if how := cfg.ignores(append(slices.Clone(g.ids), aliases...), p.Package.Name, p.Package.Ecosystem); how != "" {
					f.suppressed(how)
				}
				rep.Findings = append(rep.Findings, f)
			}
		}
	}
	return rep.encode()
}

// osvRepoConfig is the part of a repository's osv-scanner.toml that hides
// findings. osv-scanner itself never sees it (Argus passes its own --config);
// Argus reads it only to report what it tried to hide.
type osvRepoConfig struct {
	path         string
	IgnoredVulns []struct {
		ID string `toml:"id"`
	} `toml:"IgnoredVulns"`
	PackageOverrides []struct {
		Name          string `toml:"name"`
		Ecosystem     string `toml:"ecosystem"`
		Ignore        bool   `toml:"ignore"`
		Vulnerability struct {
			Ignore bool `toml:"ignore"`
		} `toml:"vulnerability"`
	} `toml:"PackageOverrides"`
}

// readOSVConfig reads the osv-scanner.toml osv-scanner would have applied to a
// lockfile in dir: the one next to it. A missing or unparseable file hides
// nothing.
func readOSVConfig(files *checkoutFiles, dir string) osvRepoConfig {
	p := joinSlash(dir, "osv-scanner.toml")
	body, ok := files.read(p)
	if !ok {
		return osvRepoConfig{}
	}
	var cfg osvRepoConfig
	if _, err := toml.Decode(string(body), &cfg); err != nil {
		return osvRepoConfig{}
	}
	cfg.path = p
	return cfg
}

// ignores says how the config would have hidden a vulnerability known by ids
// in a package, or "" when it would not.
func (c osvRepoConfig) ignores(ids []string, pkg, ecosystem string) string {
	for _, v := range c.IgnoredVulns {
		if v.ID != "" && slices.Contains(ids, v.ID) {
			return "IgnoredVulns entry in " + c.path
		}
	}
	for _, o := range c.PackageOverrides {
		if o.Name != pkg || (o.Ecosystem != "" && !strings.EqualFold(o.Ecosystem, ecosystem)) {
			continue
		}
		if o.Ignore || o.Vulnerability.Ignore {
			return "PackageOverrides entry in " + c.path
		}
	}
	return ""
}

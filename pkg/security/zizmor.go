package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

// NewZizmor returns a `run_zizmor` tool that audits the GitHub Actions
// workflows (and Dependabot and pre-commit config) under the Session's current
// target directory with zizmor.
func NewZizmor(s *session.Session, r Runner) tool.Tool {
	return &zizmor{sess: s, runner: r}
}

type zizmor struct {
	sess   *session.Session
	runner Runner
}

func (z *zizmor) Name() string { return "run_zizmor" }

func (z *zizmor) Description() string {
	return "Run zizmor, a static auditor for GitHub Actions, over the workflows, composite actions, Dependabot " +
		"and pre-commit config under a directory on the machine Argus runs on. Finds template injection, " +
		"dangerous triggers such as pull_request_target, over-broad permissions, credentials persisted to " +
		"artifacts, unpinned actions and similar CI/CD issues. It runs offline, so audits that need the GitHub " +
		"API are skipped. Returns its findings, which you must triage, and any file it could not parse (listed " +
		"as errors: coverage gaps, not a clean result). A finding marked suppressed_in_repo carries a " +
		"`# zizmor: ignore` comment or a zizmor.yml entry in the code: it is still a finding, and the attempt " +
		"to silence it is itself worth a look."
}

func (z *zizmor) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": targetSchemaProperty(),
		},
	}
}

func init() {
	catalogue(Entry{
		ID:      "zizmor",
		Tool:    "run_zizmor",
		Name:    "zizmor",
		Purpose: "Audits GitHub Actions workflows for template injection, dangerous triggers, over-broad permissions and unpinned actions.",
		Why: "A workflow runs with the repository's secrets and a token that can write to it, and a pull " +
			"request can change the workflow itself. zizmor knows how GitHub Actions expands expressions " +
			"and which triggers run untrusted code with privileges, so a review catches the injectable " +
			"`run:` step or the `pull_request_target` job before it merges. It also checks Dependabot and " +
			"pre-commit config.",
		Finds:      []Find{FindCICD},
		Reads:      []Read{ReadGitHubActions},
		DocsURL:    "https://docs.zizmor.sh/",
		InstallURL: "https://docs.zizmor.sh/installation/",
		License:    "MIT",
		Manifest:   true,
		Binaries: []Binary{{
			Name:        "zizmor",
			InstallHint: "brew install zizmor  (or pipx install zizmor)",
		}},
		Trust: TrustSafe, // parses YAML; runs nothing it reads, and runs offline
		New:   func(d Deps) tool.Tool { return NewZizmor(d.Session, d.Commands) },
	})
}

func (z *zizmor) Execute(ctx context.Context, args map[string]any) (string, error) {
	root, err := scanTarget(z.sess, args)
	if err != nil {
		return "", err
	}
	sc, err := newScratch("zizmor")
	if err != nil {
		return "", err
	}
	defer sc.remove()

	// zizmor goes online, calling the GitHub API, when it finds GH_TOKEN,
	// GITHUB_TOKEN or ZIZMOR_GITHUB_TOKEN. Its environment is the scratch
	// allow-list, which carries none of them, and --offline is passed as well,
	// so a token that ever reached it would still not take it online.
	//
	// zizmor has no report-file option: its JSON goes to stdout and its log
	// to stderr, which the Runner merges, and parseZizmor takes them apart.
	out, runErr := z.runner.Run(ctx, sc.command(sc.xdg(), "zizmor",
		"--offline",
		// The repository's say over the audit, and how each is switched off:
		//   - a zizmor.yml or .github/zizmor.yml (which can disable audits and
		//     ignore findings): --no-config loads no configuration at all;
		//   - `# zizmor: ignore[...]` comments: --no-ignores;
		//   - a .gitignore listing a workflow, which zizmor's default
		//     collection skips: --collect=all.
		// What they would have hidden comes back marked suppressed_in_repo.
		"--no-config",
		"--no-ignores",
		"--collect=all",
		// The versioned JSON format, named, so a later default cannot change
		// the shape under Argus.
		"--format=json-v1",
		// Exit codes 11-14 encode the worst severity found; finding something
		// is a successful audit.
		"--no-exit-codes",
		"--no-progress",
		"--color=never",
		"--quiet",
		root,
	))
	if runErr != nil {
		// A tree with no workflows, actions or Dependabot or pre-commit
		// config has nothing to audit, which is a clean answer.
		if strings.Contains(out, "no inputs collected") {
			_, logs, _ := splitZizmorOutput(out)
			return Report{Scanner: "zizmor", Errors: logs}.encode()
		}
		return "", fmt.Errorf("zizmor failed: %w (output: %s)", runErr, strings.TrimSpace(out))
	}
	return parseZizmor(out, root, openCheckout(z.sess, root))
}

// zizmorFinding is the part of a zizmor json-v1 finding Argus reads.
type zizmorFinding struct {
	Ident          string `json:"ident"`
	Desc           string `json:"desc"`
	URL            string `json:"url"`
	Determinations struct {
		Confidence string `json:"confidence"`
		Severity   string `json:"severity"`
	} `json:"determinations"`
	Locations []zizmorLocation `json:"locations"`
	// Ignored is zizmor's own verdict that an ignore comment in the code
	// covers the finding. With --no-ignores the finding is reported anyway.
	Ignored bool `json:"ignored"`
}

type zizmorLocation struct {
	Symbolic struct {
		Key struct {
			Local *struct {
				VerbatimPath string `json:"verbatim_path"`
			} `json:"Local"`
		} `json:"key"`
		Annotation string `json:"annotation"`
		Kind       string `json:"kind"` // Primary, Related or Hidden
	} `json:"symbolic"`
	Concrete struct {
		Location struct {
			StartPoint zizmorPoint `json:"start_point"`
			EndPoint   zizmorPoint `json:"end_point"`
		} `json:"location"`
	} `json:"concrete"`
}

// zizmorPoint is a 0-based position in a file.
type zizmorPoint struct {
	Row    int `json:"row"`
	Column int `json:"column"`
}

func (l zizmorLocation) file() string {
	if l.Symbolic.Key.Local == nil {
		return ""
	}
	return l.Symbolic.Key.Local.VerbatimPath
}

// splitZizmorOutput takes zizmor's merged output apart: the JSON findings
// list, and the warnings and errors it logged (a file it could not parse).
// ok is false when no findings list is there.
func splitZizmorOutput(out string) (findings []zizmorFinding, logs []string, ok bool) {
	rest := out
	for rest != "" {
		line, next, _ := strings.Cut(rest, "\n")
		if strings.HasPrefix(line, "[") {
			dec := json.NewDecoder(strings.NewReader(rest))
			if err := dec.Decode(&findings); err == nil {
				ok = true
				next = rest[dec.InputOffset():]
			}
		} else if msg, isLog := zizmorLog(line); isLog {
			logs = append(logs, msg)
		}
		rest = next
	}
	return findings, logs, ok
}

// zizmorLog reads one line of zizmor's log, keeping warnings and errors and
// dropping the level and the module that logged it.
func zizmorLog(line string) (string, bool) {
	line = strings.TrimSpace(line)
	for _, level := range []string{"WARN ", "ERROR "} {
		if msg, ok := strings.CutPrefix(line, level); ok {
			// "zizmor::registry::input: failed to parse input: …"
			if module, text, found := strings.Cut(msg, ": "); found && !strings.Contains(module, " ") {
				msg = text
			}
			return msg, true
		}
	}
	return "", false
}

func parseZizmor(out, target string, files *checkoutFiles) (string, error) {
	defer files.close()
	found, logs, ok := splitZizmorOutput(out)
	if !ok {
		return "", fmt.Errorf("zizmor: unreadable report: no findings list in %q", strings.TrimSpace(out))
	}
	config := zizmorRepoConfig(files, target)
	rep := Report{Scanner: "zizmor", Errors: logs}
	for _, zf := range found {
		f := Finding{
			RuleID:   zf.Ident,
			Severity: strings.ToLower(zf.Determinations.Severity),
			Title:    zf.Desc,
			Details:  map[string]any{"confidence": strings.ToLower(zf.Determinations.Confidence)},
		}
		if zf.URL != "" {
			f.Details["url"] = zf.URL
		}
		if p, ok := zizmorPrimary(zf.Locations); ok {
			f.File, _ = files.rel(p.file())
			f.Line = p.Concrete.Location.StartPoint.Row + 1
			end := p.Concrete.Location.EndPoint
			endLine := end.Row + 1
			if end.Column == 0 {
				// The span ends at the start of a line: its last line is the one before.
				endLine = end.Row
			}
			if endLine > f.Line {
				f.EndLine = endLine
			}
			f.Description = p.Symbolic.Annotation
		}
		switch {
		case zf.Ignored:
			f.suppressed("# zizmor: ignore comment in the code")
		case config.suppresses(zf):
			f.suppressed(config.how(zf))
		}
		rep.Findings = append(rep.Findings, f)
	}
	return rep.encode()
}

// zizmorPrimary is the location a finding is about. Related and hidden
// locations give it context.
func zizmorPrimary(locs []zizmorLocation) (zizmorLocation, bool) {
	for _, l := range locs {
		if l.Symbolic.Kind == "Primary" {
			return l, true
		}
	}
	if len(locs) > 0 {
		return locs[0], true
	}
	return zizmorLocation{}, false
}

// zizmorConfig is the zizmor.yml the repository carries, which zizmor would
// have loaded without --no-config: its name, and per audit whether it is
// disabled and which locations it ignores.
type zizmorConfig struct {
	name  string
	Rules map[string]struct {
		Disable bool     `yaml:"disable"`
		Ignore  []string `yaml:"ignore"`
	} `yaml:"rules"`
}

// zizmorConfigNames are where zizmor looks for its config, in its order.
var zizmorConfigNames = []string{".github/zizmor.yml", ".github/zizmor.yaml", "zizmor.yml", "zizmor.yaml"}

// zizmorRepoConfig reads the first config zizmor would discover, at the
// scanned directory or at the root of the checkout it belongs to.
func zizmorRepoConfig(files *checkoutFiles, target string) zizmorConfig {
	dirs := []string{""}
	if dir, ok := files.rel(target); ok && dir != "." && dir != "" {
		dirs = []string{dir, ""}
	}
	for _, dir := range dirs {
		for _, name := range zizmorConfigNames {
			rel := joinSlash(dir, name)
			body, ok := files.read(rel)
			if !ok {
				continue
			}
			var c zizmorConfig
			if yaml.NewDecoder(bytes.NewReader(body)).Decode(&c) != nil {
				return zizmorConfig{}
			}
			c.name = rel
			return c
		}
	}
	return zizmorConfig{}
}

func (c zizmorConfig) suppresses(f zizmorFinding) bool { return c.how(f) != "" }

// how says how the config would have hidden f, or "" when it would not. An
// ignore entry is `file.yml[:line[:column]]`, with the workflow's base name
// and 1-based positions; without a line it covers the whole file.
func (c zizmorConfig) how(f zizmorFinding) string {
	rule, ok := c.Rules[f.Ident]
	if !ok {
		return ""
	}
	if rule.Disable {
		return "audit disabled in " + c.name + " in the repository"
	}
	for _, entry := range rule.Ignore {
		parts := strings.Split(entry, ":")
		line, col := 0, 0
		if len(parts) > 1 {
			line, _ = strconv.Atoi(parts[1])
		}
		if len(parts) > 2 {
			col, _ = strconv.Atoi(parts[2])
		}
		for _, l := range f.Locations {
			start := l.Concrete.Location.StartPoint
			switch {
			case path.Base(strings.ReplaceAll(l.file(), `\`, "/")) != parts[0]:
			case line != 0 && start.Row+1 != line:
			case col != 0 && start.Column+1 != col:
			default:
				return "ignore entry in " + c.name + " in the repository"
			}
		}
	}
	return ""
}

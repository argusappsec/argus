package security

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

// pinnedRules is the only ruleset the SAST Tool ever runs (ADR 0019 Phase 1),
// whichever engine runs it: opengrep reads semgrep's rule format. It is
// compiled into the binary: never fetched from the registry (`--config auto`
// both reaches the network and requires metrics), never read from the
// checkout, never chosen by the model.
//
//go:embed rules/semgrep.yaml
var pinnedRules []byte

// Engine is a binary the SAST Tool can run. opengrep is a fork of semgrep: the
// same rule format, the same flags for everything Argus passes except metrics,
// and the same JSON report.
type Engine string

const (
	// EngineOpengrep is the preferred engine (ADR 0027): a static binary,
	// LGPL-2.1, with no telemetry.
	EngineOpengrep Engine = "opengrep"
	// EngineSemgrep stays supported for hosts that have it.
	EngineSemgrep Engine = "semgrep"
)

// NewSAST returns the `run_sast` tool, which scans the Session's current target
// directory with engine. The name is the same whichever engine runs, so Skills
// and MCP callers name the capability, never the binary; the report names the
// engine.
func NewSAST(s *session.Session, r Runner, engine Engine) tool.Tool {
	return &sast{scanner: scanner{name: sastTool, binary: string(engine), sess: s, runner: r}, engine: engine}
}

const sastTool = "run_sast"

type sast struct {
	scanner
	engine Engine
}

func (s *sast) Description() string {
	return "Run static analysis (SAST), with Argus's pinned security ruleset, over a directory on the " +
		"machine Argus runs on. This host runs it with " + string(s.engine) + "; the report's scanner " +
		"field names the engine that ran. Returns its findings, which you must triage. A finding marked " +
		"suppressed_in_repo carries a nosemgrep or noopengrep comment in the code: it is still a " +
		"finding, and the attempt to silence it is itself worth a look."
}

func init() {
	catalogue(Entry{
		ID:      "sast",
		Tool:    sastTool,
		Name:    "SAST (Opengrep or Semgrep)",
		Purpose: "Pattern-based static analysis (SAST) for insecure code across many languages.",
		Why: "Opengrep and Semgrep match rules against the syntax of the code rather than its text, so " +
			"they find injection, unsafe deserialization, weak cryptography and similar flaws in most " +
			"mainstream languages without building the project. This is the baseline SAST pass of a " +
			"review. Opengrep is an open-source fork of Semgrep that reads the same rules. Argus runs " +
			"Opengrep when it is installed and Semgrep otherwise, with the same built-in ruleset, and " +
			"the report says which one ran.",
		Finds:      []Find{FindSAST},
		Reads:      []Read{ReadMultiLanguage},
		DocsURL:    "https://github.com/opengrep/opengrep#readme",
		InstallURL: "https://github.com/opengrep/opengrep#installation",
		License:    "LGPL-2.1-only", // both engines
		Manifest:   true,
		Binaries: []Binary{{
			Name:        "opengrep",
			InstallHint: "curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash",
		}, {
			Name:        "semgrep",
			InstallHint: "brew install semgrep  (or pip install semgrep)",
		}},
		Alternatives: true,      // opengrep first: the preferred engine
		Trust:        TrustSafe, // pattern-matches source files; never builds them
		New: func(d Deps) tool.Tool {
			return NewSAST(d.Session, d.Commands, sastEngine(d.Engine))
		},
	})
}

// sastEngine is the engine to run given the one discovery picked (the
// Entry's Engine). A Tool built without discovery runs semgrep, the engine
// Argus has always run.
func sastEngine(name string) Engine {
	if e := Engine(name); e == EngineOpengrep {
		return e
	}
	return EngineSemgrep
}

func (s *sast) Execute(ctx context.Context, args map[string]any) (string, error) {
	return s.scan(ctx, args, s.run, func(body []byte, _ string, files *checkoutFiles) (Report, error) {
		return parseSemgrep(string(s.engine), body, files)
	})
}

func (s *sast) run(ctx context.Context, sc *scratch, root string) ([]byte, error) {
	engine := string(s.engine)
	rules, err := sc.write("rules.yaml", pinnedRules)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", engine, err)
	}

	argv := []string{engine,
		"--config", rules,
		"--json",
		"--output", sc.file(reportFile),
		"--quiet",
	}
	// semgrep sends usage metrics unless told not to. opengrep has no
	// telemetry and no --metrics flag: it refuses to start when given one.
	if s.engine == EngineSemgrep {
		argv = append(argv, "--metrics", "off")
	}
	argv = append(argv,
		"--disable-version-check",
		// Rule ids stay as written in the ruleset (argus.*), not prefixed with
		// the scratch directory's path, so they are stable across runs.
		"--no-rewrite-rule-ids",
		// The repository's say over the scan: `nosemgrep` (and opengrep's
		// `noopengrep`) comments and .semgrepignore files. Both are switched
		// off; nosem hits come back and are marked suppressed_in_repo below.
		// The --x- flag is semgrep's own spelling (opengrep has it too) and
		// warns on stderr, which is one more reason the report goes to a file.
		"--disable-nosem",
		"--x-ignore-semgrepignore-files",
		root,
	)

	// Both engines keep their settings and caches under XDG and HOME, all in
	// the scratch directory. PYTHONUTF8 keeps their Python runtime (opengrep is
	// a compiled Python program too) on UTF-8 without inheriting the daemon's
	// locale variables.
	env := append(sc.xdg(), "PYTHONUTF8=1")
	return s.runForReport(ctx, sc, env, argv...)
}

// semgrepOutput is the part of semgrep's JSON report Argus reads. opengrep
// writes the same report.
type semgrepOutput struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
		} `json:"end"`
		Extra struct {
			Message  string         `json:"message"`
			Severity string         `json:"severity"`
			Metadata map[string]any `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
	Errors []struct {
		Message string `json:"message"`
		Type    any    `json:"type"`
		Path    string `json:"path"`
	} `json:"errors"`
}

// nosemInline is a suppression comment anywhere on a finding's lines: semgrep's
// `nosem`/`nosemgrep`, or opengrep's `noopengrep`. nosemAbove is the same
// comment alone on the line before it.
var (
	nosemInline = regexp.MustCompile(`(?i)\b(nosem(grep)?|noopengrep)\b`)
	nosemAbove  = regexp.MustCompile(`(?i)^\W*(nosem(grep)?|noopengrep)\b`)
)

// parseSemgrep reads a semgrep-format report that engine wrote. The report
// names engine as its scanner.
func parseSemgrep(engine string, body []byte, files *checkoutFiles) (Report, error) {
	var out semgrepOutput
	if err := json.Unmarshal(body, &out); err != nil {
		return Report{}, fmt.Errorf("%s: unreadable report: %w", engine, err)
	}
	rep := Report{Scanner: engine}
	for _, r := range out.Results {
		file, inCheckout := files.rel(r.Path)
		f := Finding{
			RuleID:      r.CheckID,
			Severity:    strings.ToLower(r.Extra.Severity),
			File:        file,
			Line:        r.Start.Line,
			EndLine:     r.End.Line,
			Description: strings.TrimSpace(r.Extra.Message),
		}
		if len(r.Extra.Metadata) > 0 {
			f.Details = map[string]any{"metadata": r.Extra.Metadata}
		}
		if inCheckout {
			above, own := files.findingLines(file, r.Start.Line, r.End.Line)
			if word := firstMatch(own, nosemInline); word != "" {
				f.suppressed(word + " comment in the code")
			} else if word := firstMatch(above, nosemAbove); word != "" {
				f.suppressed(word + " comment in the code")
			}
		}
		rep.Findings = append(rep.Findings, f)
	}
	for _, e := range out.Errors {
		msg := strings.TrimSpace(e.Message)
		if e.Path != "" {
			msg = files.located(e.Path, 0, e.Message)
		}
		rep.Errors = append(rep.Errors, msg)
	}
	return rep, nil
}

// firstMatch is the suppression keyword re finds on the first line that has
// one (`nosemgrep`, `noopengrep`), or "".
func firstMatch(lines []string, re *regexp.Regexp) string {
	for _, l := range lines {
		if m := re.FindStringSubmatch(l); m != nil {
			return strings.ToLower(m[1])
		}
	}
	return ""
}

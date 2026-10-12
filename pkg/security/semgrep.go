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

// pinnedRules is the only ruleset semgrep ever runs (ADR 0019 Phase 1). It is
// compiled into the binary: never fetched from the registry (`--config auto`
// both reaches the network and requires metrics), never read from the
// checkout, never chosen by the model.
//
//go:embed rules/semgrep.yaml
var pinnedRules []byte

// NewSemgrep returns a `run_semgrep` tool that scans the Session's current
// target directory.
func NewSemgrep(s *session.Session, r Runner) tool.Tool {
	return &semgrep{sess: s, runner: r}
}

type semgrep struct {
	sess   *session.Session
	runner Runner
}

func (s *semgrep) Name() string { return "run_semgrep" }

func (s *semgrep) Description() string {
	return "Run semgrep static analysis, with Argus's pinned security ruleset, over a directory on the " +
		"machine Argus runs on. Returns its findings, which you must triage. A finding marked " +
		"suppressed_in_repo carries a nosemgrep comment in the code: it is still a finding, and the attempt " +
		"to silence it is itself worth a look."
}

func (s *semgrep) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": targetSchemaProperty(),
		},
	}
}

// Requires advertises this tool's binary dependency to argus doctor.
func (s *semgrep) Requires() []tool.Requirement {
	return []tool.Requirement{{
		Binary:      "semgrep",
		InstallHint: "brew install semgrep  (or pip install semgrep)",
	}}
}

func (s *semgrep) Execute(ctx context.Context, args map[string]any) (string, error) {
	root, err := scanTarget(s.sess, args)
	if err != nil {
		return "", err
	}
	sc, err := newScratch("semgrep")
	if err != nil {
		return "", err
	}
	defer sc.remove()
	rules, err := sc.write("rules.yaml", pinnedRules)
	if err != nil {
		return "", fmt.Errorf("semgrep: %w", err)
	}
	reportPath := sc.file("report.json")

	// semgrep keeps its settings and caches under XDG and HOME, both in the
	// scratch directory. PYTHONUTF8 keeps its Python runtime on UTF-8 without
	// inheriting the daemon's locale variables.
	env := append(sc.xdg(), "PYTHONUTF8=1")
	body, err := runForReport(ctx, s.runner, "semgrep", sc.command(env, "semgrep",
		"--config", rules,
		"--json",
		"--output", reportPath,
		"--quiet",
		"--metrics", "off",
		"--disable-version-check",
		// Rule ids stay as written in the ruleset (argus.*), not prefixed with
		// the scratch directory's path, so they are stable across runs.
		"--no-rewrite-rule-ids",
		// The repository's say over the scan: `nosemgrep` comments and
		// .semgrepignore files. Both are switched off; nosem hits come back
		// and are marked suppressed_in_repo below. The --x- flag is semgrep's
		// own spelling (opengrep has it too) and warns on stderr, which is
		// one more reason the report goes to a file.
		"--disable-nosem",
		"--x-ignore-semgrepignore-files",
		root,
	), reportPath)
	if err != nil {
		return "", err
	}
	return parseSemgrep(body, openCheckout(s.sess, root))
}

// semgrepOutput is the part of semgrep's JSON report Argus reads.
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

// nosemInline is semgrep's suppression comment anywhere on a finding's lines;
// nosemAbove is the same comment alone on the line before it.
var (
	nosemInline = regexp.MustCompile(`(?i)\bnosem(grep)?\b`)
	nosemAbove  = regexp.MustCompile(`(?i)^\W*nosem(grep)?\b`)
)

func parseSemgrep(body []byte, files *checkoutFiles) (string, error) {
	defer files.close()
	var out semgrepOutput
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("semgrep: unreadable report: %w", err)
	}
	rep := Report{Scanner: "semgrep"}
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
			above := files.lines(file, r.Start.Line-1, r.Start.Line-1)
			own := files.lines(file, r.Start.Line, max(r.End.Line, r.Start.Line))
			if anyLine(own, nosemInline.MatchString) || anyLine(above, nosemAbove.MatchString) {
				f.suppressed("nosemgrep comment in the code")
			}
		}
		rep.Findings = append(rep.Findings, f)
	}
	for _, e := range out.Errors {
		msg := strings.TrimSpace(e.Message)
		if e.Path != "" {
			p, _ := files.rel(e.Path)
			msg = p + ": " + msg
		}
		rep.Errors = append(rep.Errors, msg)
	}
	return rep.encode()
}

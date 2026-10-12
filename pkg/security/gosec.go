package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

// NewGosec returns a `run_gosec` tool that runs gosec, type-aware Go static
// analysis, over the Session's current target directory.
func NewGosec(s *session.Session, r Runner) tool.Tool {
	return &gosec{sess: s, runner: r}
}

type gosec struct {
	sess   *session.Session
	runner Runner
}

func (g *gosec) Name() string { return "run_gosec" }

func (g *gosec) Description() string {
	return "Run gosec, Go-specific static analysis with type information and taint tracking, over the Go " +
		"packages under a directory on the machine Argus runs on. Finds SQL and command injection, path " +
		"traversal, SSRF, weak cryptography and similar issues in Go code. Returns its findings, which you must " +
		"triage, and the packages it could not load (listed as errors: coverage gaps, not a clean result). A " +
		"finding marked suppressed_in_repo carries a #nosec or //gosec:disable annotation in the code: it is " +
		"still a finding, and the attempt to silence it is itself worth a look."
}

func (g *gosec) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": targetSchemaProperty(),
		},
	}
}

func init() {
	catalogue(Entry{
		ID:      "gosec",
		Tool:    "run_gosec",
		Name:    "gosec",
		Purpose: "Go security analysis with type information and taint tracking.",
		Why: "gosec understands Go's types, so it follows untrusted input into SQL queries, shell " +
			"commands, file paths and outgoing requests, and flags weak cryptography and unsafe " +
			"defaults that pattern matching alone misses. For an organization that writes Go it is " +
			"the deepest SAST pass Argus can run.",
		Finds:      []Find{FindSAST},
		Reads:      []Read{ReadGo},
		DocsURL:    "https://github.com/securego/gosec#readme",
		InstallURL: "https://github.com/securego/gosec#local-installation",
		License:    "Apache-2.0",
		// The official image ships no Go toolchain, and gosec cannot run
		// without one; the catalog recommends both to Go organizations.
		Manifest: false,
		Binaries: []Binary{
			{Name: "go", InstallHint: "brew install go  (or see https://go.dev/doc/install)"},
			{Name: "gosec", InstallHint: "go install github.com/securego/gosec/v2/cmd/gosec@latest  (or brew install gosec)"},
		},
		// gosec loads the reviewed packages through the go command, which
		// resolves modules and compiles export data: a toolchain over hostile
		// code, however hardened its environment (see goEnv).
		Trust: TrustToolchain,
		New:   func(d Deps) tool.Tool { return NewGosec(d.Session, d.Commands) },
	})
}

func (g *gosec) Execute(ctx context.Context, args map[string]any) (string, error) {
	root, err := scanTarget(g.sess, args)
	if err != nil {
		return "", err
	}
	sc, err := newScratch("gosec")
	if err != nil {
		return "", err
	}
	defer sc.remove()
	reportPath := sc.file("report.json")

	// gosec's AI fix suggestions send the findings, code included, to an LLM.
	// They switch on only with a provider (a flag or GOSEC_AI_*), and gosec is
	// given neither: its environment is the scratch allow-list plus the
	// hardened Go profile, nothing inherited.
	env := append(sc.xdg(), sc.goEnv()...)
	body, err := runForReport(ctx, g.runner, "gosec", sc.command(env, "gosec",
		"-fmt=json",
		"-out="+reportPath,
		// #nosec and //gosec:disable annotations are the pull request's say
		// over the scan, so they are switched off; the hits they would have
		// hidden come back and are marked suppressed_in_repo below. gosec
		// loads no config file unless given -conf, and is never given one.
		"-nosec=true",
		"-no-fail",
		// Not -quiet: with it gosec writes no report at all when it finds
		// nothing, which would read as a failed run.
		filepath.Join(root, "..."),
	), reportPath)
	if err != nil {
		return "", err
	}
	return parseGosec(body, openCheckout(g.sess, root))
}

// gosecOutput is the part of gosec's JSON report Argus reads.
type gosecOutput struct {
	Errors map[string][]struct {
		Line  int    `json:"line"`
		Error string `json:"error"`
	} `json:"Golang errors"`
	Issues []struct {
		Severity   string `json:"severity"`
		Confidence string `json:"confidence"`
		CWE        struct {
			ID string `json:"id"`
		} `json:"cwe"`
		RuleID  string `json:"rule_id"`
		Details string `json:"details"`
		File    string `json:"file"`
		Line    string `json:"line"` // "12", or "12-14" for a multi-line node
	} `json:"Issues"`
}

// gosecDirective is an in-code gosec suppression, `#nosec` or
// `//gosec:disable`, and what follows it: the rule ids it names, if any, then
// an optional `-- justification`.
var (
	gosecDirective = regexp.MustCompile(`(#nosec|//gosec:disable)\b(.*)`)
	gosecRuleID    = regexp.MustCompile(`\bG\d{3}\b`)
)

func parseGosec(body []byte, files *checkoutFiles) (string, error) {
	defer files.close()
	var out gosecOutput
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("gosec: unreadable report: %w", err)
	}
	if out.Issues == nil {
		return "", errors.New("gosec: unreadable report: no Issues list")
	}
	rep := Report{Scanner: "gosec"}
	for _, is := range out.Issues {
		file, inCheckout := files.rel(is.File)
		start, end := gosecLines(is.Line)
		f := Finding{
			RuleID:   is.RuleID,
			Severity: strings.ToLower(is.Severity),
			File:     file,
			Line:     start,
			Title:    is.Details,
			Details:  map[string]any{"confidence": strings.ToLower(is.Confidence)},
		}
		if end > start {
			f.EndLine = end
		}
		if is.CWE.ID != "" {
			f.Details["cwe"] = "CWE-" + is.CWE.ID
		}
		if inCheckout {
			if how := gosecSuppression(files, file, start, end, is.RuleID); how != "" {
				f.suppressed(how)
			}
		}
		rep.Findings = append(rep.Findings, f)
	}
	for path, errs := range out.Errors {
		p, _ := files.rel(path)
		for _, e := range errs {
			msg := p + ": " + strings.TrimSpace(e.Error)
			if e.Line > 0 {
				msg = p + ":" + strconv.Itoa(e.Line) + ": " + strings.TrimSpace(e.Error)
			}
			rep.Errors = append(rep.Errors, msg)
		}
	}
	slices.Sort(rep.Errors) // the report's errors are a map: give them a stable order
	return rep.encode()
}

// gosecLines reads gosec's line field, "12" or "12-14".
func gosecLines(s string) (start, end int) {
	from, to, ok := strings.Cut(s, "-")
	start, _ = strconv.Atoi(strings.TrimSpace(from))
	end = start
	if ok {
		if n, err := strconv.Atoi(strings.TrimSpace(to)); err == nil {
			end = n
		}
	}
	return start, end
}

// gosecSuppression says how the code tried to suppress a finding of rule on
// lines start..end, or "" when it did not. gosec honours an annotation that
// trails the flagged statement or sits alone on the line above it, and one
// that names rules applies to those rules only.
//
// An annotation on an enclosing block (a whole function) also suppresses in
// gosec, but is not looked for here: such a finding is still reported, just
// without the marker.
func gosecSuppression(files *checkoutFiles, file string, start, end int, rule string) string {
	var candidates []string
	for _, l := range files.lines(file, start-1, start-1) {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") {
			candidates = append(candidates, l)
		}
	}
	candidates = append(candidates, files.lines(file, start, max(end, start))...)
	for _, l := range candidates {
		m := gosecDirective.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		rules, _, _ := strings.Cut(m[2], "--")
		named := gosecRuleID.FindAllString(rules, -1)
		if len(named) == 0 || slices.Contains(named, rule) {
			return m[1] + " annotation in the code"
		}
	}
	return ""
}

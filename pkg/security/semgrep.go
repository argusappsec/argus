package security

import (
	"context"

	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

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
	return "Run semgrep static analysis over a directory on the machine Argus runs on. " +
		"Returns semgrep's JSON results, which you must parse and triage."
}

func (s *semgrep) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": targetSchemaProperty(),
			"config": map[string]any{
				"type":        "string",
				"description": "Semgrep ruleset to use, e.g. p/security-audit. Defaults to auto.",
			},
		},
	}
}

func init() {
	catalogue(Entry{
		ID:      "semgrep",
		Tool:    "run_semgrep",
		Name:    "Semgrep",
		Purpose: "Pattern-based static analysis for insecure code across many languages.",
		Why: "Semgrep matches rules against the syntax of the code rather than its text, so it finds " +
			"injection, unsafe deserialization, weak cryptography and similar flaws in most mainstream " +
			"languages without building the project. It is the baseline SAST pass of a review.",
		Finds:      []Find{FindSAST},
		Reads:      []Read{ReadMultiLanguage},
		DocsURL:    "https://semgrep.dev/docs/",
		InstallURL: "https://semgrep.dev/docs/getting-started/cli",
		License:    "LGPL-2.1-only",
		Manifest:   true,
		Binaries: []Binary{{
			Name:        "semgrep",
			InstallHint: "brew install semgrep  (or pip install semgrep)",
		}},
		Trust: TrustSafe, // pattern-matches source files; never builds them
		New:   func(d Deps) tool.Tool { return NewSemgrep(d.Session, d.Commands) },
	})
}

func (s *semgrep) Execute(ctx context.Context, args map[string]any) (string, error) {
	root, err := scanTarget(s.sess, args)
	if err != nil {
		return "", err
	}
	config, _ := args["config"].(string)
	if config == "" {
		config = "auto"
	}
	sc, err := newScratch("semgrep")
	if err != nil {
		return "", err
	}
	defer sc.remove()
	// semgrep keeps its settings and caches under XDG and HOME, both in the
	// scratch directory. PYTHONUTF8 keeps its Python runtime on UTF-8 without
	// inheriting the daemon's locale variables.
	env := append(sc.xdg(), "PYTHONUTF8=1")
	return s.runner.Run(ctx, sc.command(env, "semgrep", "--config", config, "--json", "--quiet", root))
}

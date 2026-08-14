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
	config, _ := args["config"].(string)
	if config == "" {
		config = "auto"
	}
	return s.runner.Run(ctx, root, "semgrep", "--config", config, "--json", "--quiet", root)
}

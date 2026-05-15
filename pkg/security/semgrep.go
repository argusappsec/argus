package security

import (
	"context"
	"errors"

	"github.com/redcarbon-dev/argus/pkg/session"
	"github.com/redcarbon-dev/argus/pkg/tool"
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
	return "Run semgrep static analysis on the cloned repository. Returns JSON results that you must parse and triage."
}

func (s *semgrep) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"config": map[string]any{
				"type":        "string",
				"description": "Semgrep ruleset to use, e.g. p/security-audit. Defaults to auto.",
			},
		},
	}
}

func (s *semgrep) Execute(ctx context.Context, args map[string]any) (string, error) {
	root := s.sess.Root()
	if root == "" {
		return "", errors.New("no target set: call start_review_local or start_review_github first")
	}
	config, _ := args["config"].(string)
	if config == "" {
		config = "auto"
	}
	return s.runner.Run(ctx, root, "semgrep", "--config", config, "--json", "--quiet", root)
}

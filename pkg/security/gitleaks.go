package security

import (
	"context"
	"errors"

	"github.com/redcarbon-dev/argus/pkg/session"
	"github.com/redcarbon-dev/argus/pkg/tool"
)

// NewGitleaks returns a `run_gitleaks` tool that scans the Session's current
// target directory for committed secrets.
func NewGitleaks(s *session.Session, r Runner) tool.Tool {
	return &gitleaks{sess: s, runner: r}
}

type gitleaks struct {
	sess   *session.Session
	runner Runner
}

func (g *gitleaks) Name() string { return "run_gitleaks" }

func (g *gitleaks) Description() string {
	return "Run gitleaks to detect secrets in the cloned repository. Returns JSON findings."
}

func (g *gitleaks) Schema() map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": map[string]any{},
	}
}

// Requires advertises this tool's binary dependency to argus doctor.
func (g *gitleaks) Requires() []tool.Requirement {
	return []tool.Requirement{{
		Binary:      "gitleaks",
		InstallHint: "brew install gitleaks",
	}}
}

func (g *gitleaks) Execute(ctx context.Context, _ map[string]any) (string, error) {
	root := g.sess.Root()
	if root == "" {
		return "", errors.New("no target set: call start_review_local or start_review_github first")
	}
	return g.runner.Run(ctx, root, "gitleaks", "detect", "--source", root, "--no-banner", "--report-format", "json", "--report-path", "/dev/stdout")
}

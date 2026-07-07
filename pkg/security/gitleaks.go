package security

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
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

	// gitleaks insists on a file for --report-path. Passing "/dev/stdout"
	// works on some setups but breaks under the bubbletea TUI (where stdout
	// is bound to a pseudoterminal that gitleaks can't open for write).
	// Use a temp file and read it back — always works, OS-independent.
	tmp, err := os.CreateTemp("", "argus-gitleaks-*.json")
	if err != nil {
		return "", fmt.Errorf("gitleaks: create temp report: %w", err)
	}
	reportPath := tmp.Name()
	tmp.Close()
	defer os.Remove(reportPath)

	// gitleaks exits 1 when it finds secrets — that is the expected outcome,
	// not an error. We treat the report file as the source of truth: if it
	// exists and is readable after the run, the scan succeeded regardless of
	// the binary's exit code. If the file is missing AND the run errored,
	// that's a real failure (binary not found, permission issues, etc.).
	runOut, runErr := g.runner.Run(ctx, root, "gitleaks", "detect",
		"--source", root,
		"--no-banner",
		"--report-format", "json",
		"--report-path", reportPath,
	)

	body, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		if runErr != nil {
			return "", fmt.Errorf("gitleaks failed: %w (combined output: %s)", runErr, runOut)
		}
		return "", fmt.Errorf("gitleaks: read report: %w", readErr)
	}
	return string(body), nil
}

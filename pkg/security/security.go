// Package security wraps external static-analysis binaries (semgrep, gitleaks)
// as agent tools. Each wrapper takes a Runner so tests can drive them without
// the binary being installed.
//
// We deliberately do NOT parse the JSON output here: the agent is the consumer,
// and asking the LLM to read structured JSON is the whole point of the tool.
package security

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/redcarbon-dev/argus/pkg/tool"
)

// Runner is the same shape used elsewhere in the codebase (kept local to
// avoid an inter-package dependency on github.Runner).
type Runner interface {
	Run(ctx context.Context, dir string, args ...string) (string, error)
}

// ExecRunner runs commands via os/exec. Use it in production.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, dir string, args ...string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("no command")
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s failed: %w: %s", args[0], err, string(out))
	}
	return string(out), nil
}

// NewSemgrep returns a `run_semgrep` tool scanning files under root.
func NewSemgrep(root string, r Runner) tool.Tool {
	return &semgrep{root: root, runner: r}
}

type semgrep struct {
	root   string
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
	config, _ := args["config"].(string)
	if config == "" {
		config = "auto"
	}
	return s.runner.Run(ctx, s.root, "semgrep", "--config", config, "--json", "--quiet", s.root)
}

// NewGitleaks returns a `run_gitleaks` tool scanning files under root.
func NewGitleaks(root string, r Runner) tool.Tool {
	return &gitleaks{root: root, runner: r}
}

type gitleaks struct {
	root   string
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

func (g *gitleaks) Execute(ctx context.Context, _ map[string]any) (string, error) {
	return g.runner.Run(ctx, g.root, "gitleaks", "detect", "--source", g.root, "--no-banner", "--report-format", "json", "--report-path", "/dev/stdout")
}

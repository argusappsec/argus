package security

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/redcarbon-dev/argus/pkg/session"
	"github.com/redcarbon-dev/argus/pkg/tool"
)

// NewOSVScanner returns a `run_osv_scanner` tool that scans the Session's
// current target directory for known vulnerabilities in its dependencies
// (supply-chain coverage), complementing semgrep (static analysis) and
// gitleaks (secrets).
func NewOSVScanner(s *session.Session, r Runner) tool.Tool {
	return &osvScanner{sess: s, runner: r}
}

type osvScanner struct {
	sess   *session.Session
	runner Runner
}

func (o *osvScanner) Name() string { return "run_osv_scanner" }

func (o *osvScanner) Description() string {
	return "Run osv-scanner to detect known vulnerabilities (CVEs) in the cloned repository's dependencies. Returns JSON results that you must parse and triage."
}

func (o *osvScanner) Schema() map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": map[string]any{},
	}
}

// Requires advertises this tool's binary dependency to argus doctor.
func (o *osvScanner) Requires() []tool.Requirement {
	return []tool.Requirement{{
		Binary:      "osv-scanner",
		InstallHint: "brew install osv-scanner  (or go install github.com/google/osv-scanner/cmd/osv-scanner@latest)",
	}}
}

func (o *osvScanner) Execute(ctx context.Context, _ map[string]any) (string, error) {
	root := o.sess.Root()
	if root == "" {
		return "", errors.New("no target set: call start_review_local or start_review_github first")
	}

	// Write the JSON report to a temp file via --output rather than reading
	// stdout. Two reasons, both learned from gitleaks:
	//   1. osv-scanner exits non-zero (1) when it FINDS vulnerabilities — the
	//      expected outcome here, not an error — so we can't gate on exit code.
	//   2. osv-scanner writes progress logs to stderr; our Runner merges stdout
	//      and stderr, so parsing the combined stream as JSON is unreliable.
	// The report file is the source of truth: if it's readable after the run,
	// the scan succeeded regardless of the binary's exit code. A missing report
	// alongside a run error is a genuine failure (binary absent, bad flags).
	tmp, err := os.CreateTemp("", "argus-osv-*.json")
	if err != nil {
		return "", fmt.Errorf("osv-scanner: create temp report: %w", err)
	}
	reportPath := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(reportPath) }()

	runOut, runErr := o.runner.Run(ctx, root, "osv-scanner",
		"--format", "json",
		"--output", reportPath,
		"--recursive", root,
	)

	body, readErr := os.ReadFile(reportPath)
	if runErr != nil && (readErr != nil || len(body) == 0) {
		return "", fmt.Errorf("osv-scanner failed: %w (output: %s)", runErr, runOut)
	}
	if readErr != nil {
		return "", fmt.Errorf("osv-scanner: read report: %w", readErr)
	}
	return string(body), nil
}

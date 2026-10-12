package security

import (
	"context"
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
	return "Run gitleaks to detect committed secrets in a directory on the machine Argus runs on. " +
		"Returns gitleaks's JSON findings."
}

func (g *gitleaks) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": targetSchemaProperty(),
		},
	}
}

func init() {
	catalogue(Entry{
		ID:      "gitleaks",
		Tool:    "run_gitleaks",
		Name:    "Gitleaks",
		Purpose: "Detects secrets committed to a repository: API keys, tokens, passwords and private keys.",
		Why: "A leaked credential is exploitable the moment it is pushed, whatever language the code is " +
			"in. Gitleaks recognises hundreds of credential formats and high-entropy strings, so a " +
			"review catches the secret before it reaches a public branch.",
		Finds:      []Find{FindSecrets},
		Reads:      []Read{ReadMultiLanguage},
		DocsURL:    "https://github.com/gitleaks/gitleaks#readme",
		InstallURL: "https://github.com/gitleaks/gitleaks#installing",
		License:    "MIT",
		Binaries: []Binary{{
			Name:        "gitleaks",
			InstallHint: "brew install gitleaks",
		}},
		Trust: TrustSafe, // reads files and git history; runs nothing
		New:   func(d Deps) tool.Tool { return NewGitleaks(d.Session, d.Commands) },
	})
}

func (g *gitleaks) Execute(ctx context.Context, args map[string]any) (string, error) {
	root, err := scanTarget(g.sess, args)
	if err != nil {
		return "", err
	}

	// gitleaks insists on a file for --report-path. Passing "/dev/stdout"
	// works on some setups but breaks under the bubbletea TUI (where stdout
	// is bound to a pseudoterminal that gitleaks can't open for write).
	// Use a file in the run's scratch directory and read it back — always
	// works, OS-independent.
	sc, err := newScratch("gitleaks")
	if err != nil {
		return "", err
	}
	defer sc.remove()
	reportPath := sc.file("report.json")

	// gitleaks exits 1 when it finds secrets — that is the expected outcome,
	// not an error. We treat the report file as the source of truth: if it
	// exists and is readable after the run, the scan succeeded regardless of
	// the binary's exit code. If the file is missing AND the run errored,
	// that's a real failure (binary not found, permission issues, etc.).
	// gitleaks needs nothing beyond the base allow-list.
	runOut, runErr := g.runner.Run(ctx, sc.command(nil, "gitleaks", "detect",
		"--source", root,
		"--no-banner",
		"--report-format", "json",
		"--report-path", reportPath,
	))

	body, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		if runErr != nil {
			return "", fmt.Errorf("gitleaks failed: %w (combined output: %s)", runErr, runOut)
		}
		return "", fmt.Errorf("gitleaks: read report: %w", readErr)
	}
	return string(body), nil
}

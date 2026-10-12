package security

import (
	"context"
	"fmt"
	"os"

	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
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

	// noCallAnalysis is set on automatic reviews. With go on PATH, osv-scanner
	// runs Go call analysis by default, which loads the reviewed packages
	// through the Go toolchain: not something to do with a stranger's code
	// (ADR 0027). Reviews a Person asked for keep the reachability filtering.
	noCallAnalysis bool
}

func (o *osvScanner) Name() string { return "run_osv_scanner" }

func (o *osvScanner) Description() string {
	return "Run osv-scanner to detect known vulnerabilities (CVEs) in the dependencies declared under a " +
		"directory on the machine Argus runs on. Returns osv-scanner's JSON results, which you must parse and triage."
}

func (o *osvScanner) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": targetSchemaProperty(),
		},
	}
}

func init() {
	catalogue(Entry{
		ID:      "osv-scanner",
		Tool:    "run_osv_scanner",
		Name:    "OSV-Scanner",
		Purpose: "Finds dependencies with known vulnerabilities by reading lockfiles and manifests.",
		Why: "Most exploitable flaws in an application live in its dependencies. OSV-Scanner reads " +
			"the lockfiles of every major ecosystem and matches them against the OSV database, so a " +
			"review reports a vulnerable version the moment a change introduces it.",
		Finds:      []Find{FindSCA},
		Reads:      []Read{ReadMultiLanguage},
		DocsURL:    "https://google.github.io/osv-scanner/",
		InstallURL: "https://google.github.io/osv-scanner/installation/",
		License:    "Apache-2.0",
		Binaries: []Binary{{
			Name:        "osv-scanner",
			InstallHint: "brew install osv-scanner  (or go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest)",
		}},
		// Safe because an automatic review switches off its one toolchain-driving
		// mode, Go call analysis (see Execute).
		Trust: TrustSafe,
		New: func(d Deps) tool.Tool {
			return &osvScanner{sess: d.Session, runner: d.Commands, noCallAnalysis: d.Automatic}
		},
	})
}

func (o *osvScanner) Execute(ctx context.Context, args map[string]any) (string, error) {
	root, err := scanTarget(o.sess, args)
	if err != nil {
		return "", err
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
	sc, err := newScratch("osv-scanner")
	if err != nil {
		return "", err
	}
	defer sc.remove()
	reportPath := sc.file("report.json")

	// osv-scanner keeps its vulnerability database cache under the user cache
	// directory, which Go resolves through XDG_CACHE_HOME or HOME; both point
	// into the scratch directory.
	argv := []string{"osv-scanner",
		"--format", "json",
		"--output", reportPath,
	}
	if o.noCallAnalysis {
		argv = append(argv, "--no-call-analysis=go")
	}
	argv = append(argv, "--recursive", root)
	runOut, runErr := o.runner.Run(ctx, sc.command(sc.xdg(), argv...))

	body, readErr := os.ReadFile(reportPath)
	if runErr != nil && (readErr != nil || len(body) == 0) {
		return "", fmt.Errorf("osv-scanner failed: %w (output: %s)", runErr, runOut)
	}
	if readErr != nil {
		return "", fmt.Errorf("osv-scanner: read report: %w", readErr)
	}
	return string(body), nil
}

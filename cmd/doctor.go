package cmd

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	ghchannel "github.com/argusappsec/argus/pkg/channel/github"
	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/doctor"
	"github.com/argusappsec/argus/pkg/security"
	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

// doctorCmd performs a pre-flight check of the environment. Exits 0 when all
// required checks pass (optional missing is fine), 1 otherwise. This makes
// the command CI-friendly: scripts can gate "should I run argus?" on
// `argus doctor`'s exit code.
func doctorCmd() *cobra.Command {
	var homeDir string
	var binariesOnly bool
	c := &cobra.Command{
		Use:   "doctor",
		Short: "Check that Argus's dependencies and configuration are ready.",
		Long: "Run a pre-flight check on:\n" +
			"  • CLI binaries Argus shells out to (git, semgrep, gitleaks, osv-scanner, …)\n" +
			"  • argus.yaml (provider configured? default model set?)\n" +
			"  • GEMINI_API_KEY (in .env or shell)\n" +
			"  • SOUL.md (present? populated?)\n" +
			"  • context/ (any documents on file?)\n\n" +
			"Exit code 0 = all required checks pass; 1 = at least one required check failed.\n\n" +
			"--binaries runs the image-contract check only: it verifies just the CLI\n" +
			"binaries and treats every one as blocking (ADR 0013). This is the gate CI\n" +
			"runs inside the official batteries-included image — there \"optional\" does\n" +
			"not exist; everything the image promises is owed. Exit 0 = all present, 1 =\n" +
			"any missing.",
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := resolveHome(homeDir)
			if err != nil {
				return err
			}
			opts := doctor.Options{
				Home:          home,
				Registry:      doctorRegistry(),
				ExtraBinaries: extraBinaries(),
				BinariesOnly:  binariesOnly,
			}
			if !binariesOnly {
				opts.GitHub, opts.GitHubMint = githubDoctorOptions(home)
			}
			checks := doctor.Run(opts)
			renderChecks(cmd.OutOrStdout(), checks)
			summary := doctor.Summarize(checks)
			renderSummary(cmd.OutOrStdout(), summary)
			if summary.HasBlockingFailure() {
				return fmt.Errorf("one or more required checks failed")
			}
			return nil
		},
	}
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	c.Flags().BoolVar(&binariesOnly, "binaries", false, "Check only CLI binaries, treating every one as blocking (image contract / CI gate)")
	return c
}

var (
	stylePass   = lipgloss.NewStyle().Foreground(lipgloss.Color("#7ee5a3")).Bold(true)
	styleFailRq = lipgloss.NewStyle().Foreground(lipgloss.Color("#e07070")).Bold(true)
	styleFailOp = lipgloss.NewStyle().Foreground(lipgloss.Color("#e0c060"))
	styleInfo   = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
	styleName   = lipgloss.NewStyle().Bold(true)
	styleMsg    = lipgloss.NewStyle().Foreground(lipgloss.Color("#aaaaaa"))
	styleHint   = lipgloss.NewStyle().Foreground(lipgloss.Color("#aaaaaa")).Italic(true)
)

func renderChecks(w io.Writer, checks []doctor.Check) {
	nameW := 12
	for _, c := range checks {
		if l := lipgloss.Width(c.Name); l > nameW {
			nameW = l
		}
	}
	fmt.Fprintln(w)
	for _, c := range checks {
		fmt.Fprintln(w, renderCheck(c, nameW))
	}
	fmt.Fprintln(w)
}

func renderCheck(c doctor.Check, nameW int) string {
	var glyph string
	switch c.Status {
	case doctor.Pass:
		glyph = stylePass.Render("✓")
	case doctor.Fail:
		if c.Severity == doctor.SeverityRequired {
			glyph = styleFailRq.Render("✗")
		} else {
			glyph = styleFailOp.Render("✗")
		}
	case doctor.Info:
		glyph = styleInfo.Render("ℹ")
	}

	name := styleName.Render(padRight(c.Name, nameW))
	body := c.Message
	if body == "" && c.Hint != "" {
		body = c.Hint
	}
	var rendered string
	if c.Status == doctor.Fail {
		rendered = styleHint.Render(body)
	} else {
		rendered = styleMsg.Render(body)
	}
	return fmt.Sprintf("  %s  %s  %s", glyph, name, rendered)
}

func renderSummary(w io.Writer, s doctor.Summary) {
	parts := []string{stylePass.Render(fmt.Sprintf("%d ok", s.OK))}
	if s.OptionalMissing > 0 {
		parts = append(parts, styleFailOp.Render(fmt.Sprintf("%d optional missing", s.OptionalMissing)))
	}
	if s.RequiredFailed > 0 {
		parts = append(parts, styleFailRq.Render(fmt.Sprintf("%d required failed", s.RequiredFailed)))
	}
	if s.Infos > 0 {
		parts = append(parts, styleInfo.Render(fmt.Sprintf("%d info", s.Infos)))
	}
	fmt.Fprintf(w, "  summary: %s\n", strings.Join(parts, " • "))
	if s.HasBlockingFailure() {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, styleFailRq.Render("  ✗ environment is NOT ready. Fix the items marked above before running argus."))
	}
}

// doctorRegistry builds a throwaway registry containing every tool that
// might shell out to a binary. Tools that implement tool.Requirer expose
// their binary deps to doctor; tools that don't are still registered but
// invisible to the check (this is fine — they have no binary deps).
//
// Single source of truth: when a new security tool is added (e.g. trivy),
// registering it here is enough — doctor picks it up automatically.
func doctorRegistry() *tool.Registry {
	sess := session.New()
	runner := security.ExecRunner{}
	reg := tool.NewRegistry()
	reg.Register(security.NewSemgrep(sess, runner))
	reg.Register(security.NewGitleaks(sess, runner))
	reg.Register(security.NewOSVScanner(sess, runner))
	// Future: trivy, trufflehog, govulncheck — adding them in
	// pkg/security and registering them here is the only change needed.
	return reg
}

// githubDoctorOptions loads argus.yaml's github: section and, when it is
// configured, returns it plus a mint closure that proves a token can be
// minted (the network call lives here, not in the pure doctor package). When
// the section is absent, both are nil and doctor skips the check.
func githubDoctorOptions(home string) (*config.GitHubConfig, func(context.Context) error) {
	cfg, err := config.LoadConfig(filepath.Join(home, "argus.yaml"))
	if err != nil || !cfg.GitHub.Configured() {
		if err == nil && cfg != nil {
			return &cfg.GitHub, nil // present but unconfigured → Info row
		}
		return nil, nil
	}
	// Load .env so env() references in the github: section resolve.
	if e, lerr := config.LoadEnv(filepath.Join(home, ".env")); lerr == nil {
		e.ApplyToProcess()
	}
	gh := cfg.GitHub
	mint := func(ctx context.Context) error {
		m, err := ghchannel.MintFromConfig(gh)
		if err != nil {
			return err
		}
		_, err = m.Token(ctx)
		return err
	}
	return &gh, mint
}

// extraBinaries lists binary deps that aren't owned by any Tool (because
// they're used by core infra like pkg/codehost/github).
func extraBinaries() []doctor.ExtraBinary {
	return []doctor.ExtraBinary{
		{
			Name:        "git",
			Required:    true,
			UsedBy:      "cloning repositories",
			InstallHint: "install via your OS package manager (brew install git / apt-get install git / ...)",
		},
	}
}

func padRight(s string, n int) string {
	w := lipgloss.Width(s)
	if w >= n {
		return s
	}
	return s + strings.Repeat(" ", n-w)
}

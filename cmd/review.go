package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/redcarbon-dev/argus/pkg/agent"
	"github.com/redcarbon-dev/argus/pkg/channel/tui"
	"github.com/redcarbon-dev/argus/pkg/codehost/github"
	"github.com/redcarbon-dev/argus/pkg/memory"
)

// reviewCmd runs a security review on a GitHub repository.
//
// By default it opens the same TUI as `argus chat`, seeded with the review
// prompt. The user observes the agent live and can intervene at any time
// (answer questions, redirect focus, add context). After the agent finalizes
// the report the chat stays open — useful for follow-ups.
//
// With --headless the command runs non-interactively: clone, agent.Run,
// memory curate, exit. This is the CI/cron mode.
func reviewCmd() *cobra.Command {
	var (
		model    string
		ref      string
		maxTurns int
		homeDir  string
		headless bool
	)
	c := &cobra.Command{
		Use:   "review <github-url>",
		Short: "Run a security review on a GitHub repository (interactive by default).",
		Long: "Clone a GitHub repository and run a security review.\n\n" +
			"By default the command opens an interactive chat seeded with the\n" +
			"review prompt — the agent works live and you can intervene.\n\n" +
			"With --headless the command runs non-interactively (clone, review,\n" +
			"exit at finalize_report). Use this in CI / cron / scripted runs.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if headless {
				ctx2, cancel := context.WithTimeout(ctx, 10*time.Minute)
				defer cancel()
				ctx = ctx2
			}

			rt, err := buildRuntime(ctx, runtimeOptions{HomeOverride: homeDir, Model: model})
			if err != nil {
				return err
			}
			defer rt.Close()

			u, err := github.ParseURL(args[0])
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "→ resolving %s@%s\n", u.FullName, defaultIfEmpty(ref, "HEAD"))
			co, err := rt.Cloner.Clone(ctx, u, ref)
			if err != nil {
				return fmt.Errorf("clone: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "→ checkout ready at %s (sha=%s)\n", co.Path, co.SHA)
			rt.Session.SetRoot(co.Path)

			seedPrompt := fmt.Sprintf(
				"Please run a thorough security review of %s at commit %s. "+
					"The repository is already checked out locally — use list_files / read_file / "+
					"grep / run_semgrep / run_gitleaks freely. Record each issue you confirm via "+
					"add_finding, then call finalize_report with a concise summary when you are done. "+
					"If something is genuinely ambiguous, ask me; otherwise proceed autonomously.",
				u.FullName, co.SHA,
			)
			target := agent.Target{Repo: u.FullName, SHA: co.SHA, Path: co.Path}

			if headless {
				return runReviewHeadless(ctx, cmd, rt, target, maxTurns)
			}
			return runReviewInteractive(ctx, cmd, rt, target, seedPrompt, maxTurns)
		},
	}
	c.Flags().StringVar(&model, "model", "", "Override the default model from argus.yaml (e.g. gemini-2.5-pro)")
	c.Flags().StringVar(&ref, "ref", "", "Branch, tag, or commit SHA to review (default: remote HEAD)")
	c.Flags().IntVar(&maxTurns, "max-turns", 50, "Safety-net cap on agent loop turns")
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	c.Flags().BoolVar(&headless, "headless", false, "Non-interactive mode for CI/cron (no TUI, exits at finalize_report)")
	return c
}

// runReviewHeadless is the non-interactive path: one agent.Run with the
// default review seed, optional memory curation, done. Suited for CI/cron.
func runReviewHeadless(ctx context.Context, cmd *cobra.Command, rt *runtime, target agent.Target, maxTurns int) error {
	ag := agent.New(agent.Options{
		Provider:     rt.Provider,
		Audit:        rt.Audit,
		Reports:      rt.Reports,
		Tools:        rt.Registry,
		Conversation: rt.Conversation,
		Soul:         rt.Soul,
		Memory:       rt.Memory,
		MaxTurns:     maxTurns,
	})

	fmt.Fprintln(cmd.OutOrStdout(), "→ running agent loop")
	rep, err := ag.Run(ctx, target)
	if err != nil {
		return fmt.Errorf("agent: %w", err)
	}

	reportPath := filepath.Join(rt.Home, "reports", reportSlug(target.Repo), target.SHA+".md")
	fmt.Fprintf(cmd.OutOrStdout(), "✓ review complete: %d findings — %s\n", len(rep.Findings), reportPath)
	fmt.Fprintf(cmd.OutOrStdout(), "  conversation log: %s\n", rt.ConvoPath)

	fmt.Fprintln(cmd.OutOrStdout(), "→ curating memory")
	if err := memory.Curate(ctx, memory.Options{
		ConversationPath: rt.ConvoPath,
		MemoryPath:       filepath.Join(rt.Home, "MEMORY.md"),
		Provider:         rt.Provider,
	}); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "  warning: memory curation failed: %v\n", err)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "  memory: %s\n", filepath.Join(rt.Home, "MEMORY.md"))
	}
	return nil
}

// runReviewInteractive opens the same chat TUI as `argus chat`, but with
// AutoSubmit set so the agent starts working on the review as soon as the
// program boots. The user can intervene, ask follow-ups, or just observe.
// On clean exit (/quit or Ctrl-D) memory curation runs in the background.
func runReviewInteractive(ctx context.Context, cmd *cobra.Command, rt *runtime, target agent.Target, seedPrompt string, maxTurns int) error {
	_ = target // target is used inside the chat agent via session.Root
	fmt.Fprintf(cmd.OutOrStdout(), "session %s — conversation log at %s\n", rt.Session.ID(), rt.ConvoPath)

	var program *tea.Program

	dispatch := func(userInput string) tea.Cmd {
		go runChatAgent(ctx, rt, userInput, maxTurns, program)
		return nil
	}

	tuiModel := tui.New(tui.Config{
		Dispatch:     dispatch,
		Title:        "argus review " + target.Repo,
		AutoSubmit:   seedPrompt,
		ResolveSkill: skillResolver(rt.Skills),
	})
	program = tea.NewProgram(tuiModel, tea.WithAltScreen(), tea.WithContext(ctx))
	if _, err := program.Run(); err != nil {
		return fmt.Errorf("tui: %w", err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), "→ curating memory")
	if err := memory.Curate(context.Background(), memory.Options{
		ConversationPath: rt.ConvoPath,
		MemoryPath:       filepath.Join(rt.Home, "MEMORY.md"),
		Provider:         rt.Provider,
	}); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "  warning: memory curation skipped: %v\n", err)
	}
	return nil
}

func reportSlug(full string) string {
	out := make([]rune, 0, len(full))
	for _, r := range full {
		switch r {
		case '/', '\\', ':', ' ':
			out = append(out, '_')
		default:
			out = append(out, r)
		}
	}
	return string(out)
}

func defaultIfEmpty(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

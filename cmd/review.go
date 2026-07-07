package cmd

import (
	"errors"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/argusappsec/argus/pkg/channel/tui"
	"github.com/argusappsec/argus/pkg/channel/uds"
	"github.com/argusappsec/argus/pkg/codehost/github"
)

// reviewCmd runs a security review on a GitHub repository through the
// daemon: the client sends the structured review target and the daemon
// clones (into ITS cache) and drives the agent. Starting the review is
// deterministic — it never depends on the model calling a tool. This is the
// same dispatch entry point the webhook channel will use.
//
// By default it opens the same TUI as `argus chat` so the user observes the
// agent live and can intervene. With --headless it runs non-interactively:
// send target, stream until done, exit. This is the CI/cron mode.
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
		Long: "Run a security review of a GitHub repository through the Argus daemon.\n\n" +
			"By default the command opens an interactive chat seeded with the\n" +
			"review — the agent works live and you can intervene.\n\n" +
			"With --headless the command runs non-interactively (review, exit at\n" +
			"finalize_report). Use this in CI / cron / scripted runs.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate the URL client-side for fast feedback; the daemon
			// re-parses it anyway (it cannot trust its callers).
			u, err := github.ParseURL(args[0])
			if err != nil {
				return err
			}

			cs, err := connectOrSpawn(homeDir, uds.HelloOptions{Model: model, MaxTurns: maxTurns})
			if err != nil {
				return err
			}
			defer cs.Close()

			if cs.InProcess {
				fmt.Fprintln(cmd.OutOrStdout(), "argus: no daemon on the socket — running one in-process")
			}
			fmt.Fprintf(cmd.OutOrStdout(), "session %s — reviewing %s@%s\n",
				cs.Client.SessionID(), u.FullName, defaultIfEmpty(ref, "HEAD"))

			if headless {
				return runReviewHeadless(cmd, cs, args[0], ref)
			}
			return runReviewInteractive(cmd, cs, u.FullName, args[0], ref)
		},
	}
	c.Flags().StringVar(&model, "model", "", "Override the daemon's default model for this session (must be configured on the daemon)")
	c.Flags().StringVar(&ref, "ref", "", "Branch, tag, or commit SHA to review (default: remote HEAD)")
	c.Flags().IntVar(&maxTurns, "max-turns", 50, "Safety-net cap on agent loop turns")
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	c.Flags().BoolVar(&headless, "headless", false, "Non-interactive mode for CI/cron (no TUI, exits at finalize_report)")
	return c
}

// headlessTimeout bounds an unattended review before the client cancels it.
const headlessTimeout = 10 * time.Minute

// runReviewHeadless sends the review target and consumes frames until the
// terminal one, printing a terse progress trail suited to CI logs.
func runReviewHeadless(cmd *cobra.Command, cs *clientSession, githubURL, ref string) error {
	if err := cs.Client.SendReview(githubURL, ref); err != nil {
		return fmt.Errorf("send review: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "→ running agent loop (daemon-side)")

	timeout := time.AfterFunc(headlessTimeout, func() { _ = cs.Client.Cancel() })
	defer timeout.Stop()

	for {
		f, err := cs.Client.Recv()
		if err != nil {
			return fmt.Errorf("daemon connection: %w", err)
		}
		switch f.Type {
		case uds.TypeDone:
			fmt.Fprintf(cmd.OutOrStdout(), "✓ review complete: %d findings", f.Findings)
			if f.ReportPath != "" {
				fmt.Fprintf(cmd.OutOrStdout(), " — %s", f.ReportPath)
			}
			fmt.Fprintln(cmd.OutOrStdout())
			return nil
		case uds.TypeError:
			if f.Reason == "cancelled" {
				return fmt.Errorf("review timed out after %s", headlessTimeout)
			}
			return errors.New(f.Reason)
		case uds.TypeUsage, uds.TypeAgentMessage:
			// Headless stays quiet turn-by-turn; the conversation log on the
			// daemon host is the forensic trail.
		}
	}
}

// runReviewInteractive opens the chat TUI already marked busy: the run was
// started by the review frame, not by a typed message. The user observes,
// intervenes with follow-up messages, or cancels.
func runReviewInteractive(cmd *cobra.Command, cs *clientSession, repoFullName, githubURL, ref string) error {
	var program *tea.Program

	dispatch := func(userInput string) tea.Cmd {
		go func() {
			if err := cs.Client.SendMessage(userInput); err != nil {
				program.Send(tui.AgentErrorMsg{Err: err})
			}
		}()
		return nil
	}

	model := tui.New(tui.Config{
		Dispatch:     dispatch,
		Title:        "argus review " + repoFullName,
		ForwardSlash: true,
		StartBusy:    true,
		Cancel:       func() { _ = cs.Client.Cancel() },
	}).WithInitialMessages([]tui.Message{{
		Role:    "system",
		Content: fmt.Sprintf("review of %s@%s started — the agent is working, you can intervene at any time", repoFullName, defaultIfEmpty(ref, "HEAD")),
	}})
	program = tea.NewProgram(model, tea.WithAltScreen(), tea.WithContext(cmd.Context()))

	go receiveLoop(cs.Client, program)
	go func() {
		if err := cs.Client.SendReview(githubURL, ref); err != nil {
			program.Send(tui.AgentErrorMsg{Err: err})
		}
	}()

	if _, err := program.Run(); err != nil {
		return fmt.Errorf("tui: %w", err)
	}
	return nil
}

func defaultIfEmpty(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

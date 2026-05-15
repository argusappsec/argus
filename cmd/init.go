package cmd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/redcarbon-dev/argus/pkg/agent"
	"github.com/redcarbon-dev/argus/pkg/channel/tui"
	"github.com/redcarbon-dev/argus/pkg/provider"
	"github.com/redcarbon-dev/argus/pkg/provider/gemini"
	"github.com/redcarbon-dev/argus/pkg/soul"
	"github.com/redcarbon-dev/argus/pkg/tool"
)

// initCmd opens a chat with a dedicated "interviewer" agent that walks the
// user through creating their SOUL.md. The interviewer asks one question at a
// time and, when satisfied, calls the write_soul tool with the collected
// answers in structured form.
//
// This command reuses the same TUI/agent machinery as `argus chat`, only with:
//   - a different system prompt (the interviewer persona, defined inline here)
//   - a tiny tool registry: write_soul + finalize_report (no file-scoped tools)
//   - no SOUL.md loaded (we're CREATING it, not consuming one)
//
// Bails out if SOUL.md already exists — re-init is a destructive operation
// and should be explicit.
func initCmd() *cobra.Command {
	var (
		model   string
		homeDir string
		force   bool
	)
	c := &cobra.Command{
		Use:   "init",
		Short: "Interactive bootstrap interview to create your SOUL.md.",
		Long: "Start a guided interview with the Argus agent to populate SOUL.md.\n" +
			"The interviewer agent asks about your company, industry, compliance frameworks, " +
			"risk tolerance, escalation contact, monitored repos, and preferred persona. " +
			"When you're satisfied, the agent calls write_soul and exits.\n\n" +
			"If SOUL.md already exists, this command refuses to overwrite (use --force).",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			home, err := resolveHome(homeDir)
			if err != nil {
				return err
			}
			soulPath := filepath.Join(home, "SOUL.md")

			if !force {
				if _, err := os.Stat(soulPath); err == nil {
					return fmt.Errorf("SOUL.md already exists at %s — delete it first or pass --force", soulPath)
				} else if !errors.Is(err, fs.ErrNotExist) {
					return fmt.Errorf("stat SOUL.md: %w", err)
				}
			}

			apiKey := os.Getenv("GEMINI_API_KEY")
			if apiKey == "" {
				return fmt.Errorf("GEMINI_API_KEY is required (export it or place it in %s/.env)", home)
			}

			prov, err := gemini.New(ctx, apiKey, model)
			if err != nil {
				return err
			}

			reg := tool.NewRegistry()
			reg.Register(tool.NewWriteSoul(soulPath))

			interviewer := &soul.Soul{Persona: interviewerPersona()}

			var program *tea.Program

			dispatch := func(userInput string) tea.Cmd {
				go runInterview(ctx, prov, reg, interviewer, userInput, program)
				return nil
			}

			seed := "Hi, I'm here to help you set up Argus for your team. " +
				"I'll ask a few questions, then write a SOUL.md you can edit later. " +
				"Reply with anything to begin (or describe your company/use-case if you already know what you want)."

			tuiModel := tui.New(tui.Config{Dispatch: dispatch}).WithInput(seed)
			// Auto-submit the seed so the chat already shows the welcome line.
			updated, _ := tuiModel.Update(tea.KeyMsg{Type: tea.KeyEnter})
			tuiModel = updated.(tui.Model)

			program = tea.NewProgram(tuiModel, tea.WithAltScreen(), tea.WithContext(ctx))
			if _, err := program.Run(); err != nil {
				return fmt.Errorf("tui: %w", err)
			}

			if _, err := os.Stat(soulPath); err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "✓ SOUL written to %s\n", soulPath)
			} else {
				fmt.Fprintln(cmd.ErrOrStderr(), "(no SOUL.md written — interview exited early)")
			}
			return nil
		},
	}
	c.Flags().StringVar(&model, "model", "gemini-2.5-flash", "Gemini model id")
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	c.Flags().BoolVar(&force, "force", false, "Overwrite SOUL.md if it already exists")
	return c
}

// runInterview is the interviewer-side dispatcher: it kicks off one agent.Run
// per user message, streaming responses back into the TUI program.
func runInterview(ctx context.Context, prov provider.Provider, reg *tool.Registry, interviewer *soul.Soul, userInput string, program *tea.Program) {
	ag := agent.New(agent.Options{
		Provider: prov,
		Tools:    reg,
		Soul:     interviewer,
		MaxTurns: 20,
		SeedMessages: []provider.Message{{
			Role:    "user",
			Content: userInput,
		}},
		OnMessage: func(m provider.Message) {
			program.Send(tui.AgentMessageMsg{Message: m})
		},
		OnUsage: func(u provider.Usage) {
			program.Send(tui.AgentUsageMsg{
				InputTokens:  u.InputTokens,
				OutputTokens: u.OutputTokens,
			})
		},
		// Reports omitted: the interviewer ends via finalize_report without
		// writing a security report (Reports nil-safe).
	})

	if _, err := ag.Run(ctx, agent.Target{}); err != nil {
		program.Send(tui.AgentErrorMsg{Err: err})
		return
	}
	program.Send(tui.AgentDoneMsg{})
}

// interviewerPersona is the hardcoded system prompt for the bootstrap agent.
// Lives here (not in pkg/soul) because it's CLI-flow-specific.
func interviewerPersona() string {
	return `You are the **Argus onboarding interviewer**.

Your job is to interview the human in front of you and produce a SOUL.md for
the Argus security agent. SOUL.md captures the agent's identity: who it works
for, in what industry, under which compliance frameworks, what risk tolerance,
who to escalate to, which repositories it watches, and what tone/persona to
adopt.

INTERVIEW STYLE:
- Ask ONE focused question per turn. Do not dump a checklist.
- Acknowledge each answer briefly, then move on to the next topic.
- Be conversational and respectful. The user may not know all answers right
  away — accept "skip" or "I don't know" for optional fields.
- Aim for ~6-8 turns total. Don't drag it out.

TOPICS TO COVER (in roughly this order):
1. Company name and industry.
2. Compliance frameworks (SOC2, ISO27001, HIPAA, PCI-DSS, GDPR, none).
3. Risk tolerance (low / medium / high).
4. Escalation contact (email or chat handle of the security owner).
5. Repositories to monitor (GitHub URLs or "decide later").
6. Tone preferences (terse vs friendly, technical vs executive-oriented).

WHEN DONE:
- Call write_soul ONCE with all collected fields. Required: company + persona.
- The 'persona' field should be a concise paragraph (~3-5 sentences) you AUTHOR
  based on the user's tone preferences. It is the prose body of SOUL.md.
- After write_soul succeeds, call finalize_report with a one-line summary.

GUARDRAILS:
- Do not call write_soul more than once.
- Do not invent compliance frameworks the user didn't mention.
- If the user gets impatient, finalize early with what you have (only company
  + a generic persona are strictly required).`
}

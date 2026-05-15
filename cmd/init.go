package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/redcarbon-dev/argus/pkg/agent"
	"github.com/redcarbon-dev/argus/pkg/channel/tui"
	"github.com/redcarbon-dev/argus/pkg/config"
	"github.com/redcarbon-dev/argus/pkg/provider"
	"github.com/redcarbon-dev/argus/pkg/provider/gemini"
	"github.com/redcarbon-dev/argus/pkg/soul"
	"github.com/redcarbon-dev/argus/pkg/tool"
)

// initCmd is the bootstrap flow. It runs in two phases:
//
//	Phase A: pre-LLM config. Plain stdin prompts ask for provider / model /
//	         API key and write them to ~/.argus/.env. We do this in Go (no
//	         agent involved) because the agent needs the API key to talk —
//	         chicken-and-egg.
//
//	Phase B: SOUL interview. Standard chat TUI with a curated "interviewer"
//	         agent that asks about company, persona, etc., then calls
//	         write_soul + finalize_report. Already implemented in v0.2.1.
//
// Either phase can be skipped if the relevant artifact already exists and
// --force was not passed.
func initCmd() *cobra.Command {
	var (
		homeDir string
		force   bool
	)
	c := &cobra.Command{
		Use:   "init",
		Short: "Interactive bootstrap: configure your provider/API key and create SOUL.md.",
		Long: "Run a two-phase bootstrap:\n" +
			"  1) plain prompts for LLM provider, model id, and API key (saved to ~/.argus/.env)\n" +
			"  2) a chat-based interview with the Argus agent to populate SOUL.md\n\n" +
			"Existing values are kept unless --force is passed; missing values are prompted.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			home, err := resolveHome(homeDir)
			if err != nil {
				return err
			}

			// --- Phase A: config (~/.argus/.env) -------------------------------
			env, err := config.LoadEnv(filepath.Join(home, ".env"))
			if err != nil {
				return err
			}

			cfg, err := promptConfig(cmd.InOrStdin(), cmd.OutOrStdout(), env)
			if err != nil {
				return err
			}

			env.Set("GEMINI_API_KEY", cfg.APIKey)
			env.Set("ARGUS_DEFAULT_MODEL", cfg.Model)
			if err := env.Save(); err != nil {
				return fmt.Errorf("save .env: %w", err)
			}
			env.ApplyToProcess()
			fmt.Fprintf(cmd.OutOrStdout(), "✓ config saved to %s\n\n", filepath.Join(home, ".env"))

			// --- Phase B: SOUL interview ---------------------------------------
			soulPath := filepath.Join(home, "SOUL.md")
			if !force {
				if _, err := os.Stat(soulPath); err == nil {
					fmt.Fprintf(cmd.OutOrStdout(), "SOUL.md already exists at %s — skipping interview (use --force to redo)\n", soulPath)
					return nil
				} else if !errors.Is(err, fs.ErrNotExist) {
					return fmt.Errorf("stat SOUL.md: %w", err)
				}
			}

			prov, err := gemini.New(ctx, cfg.APIKey, cfg.Model)
			if err != nil {
				return err
			}

			reg := tool.NewRegistry()
			reg.Register(tool.NewWriteSoul(soulPath))

			interviewer := &soul.Soul{Persona: interviewerPersona()}

			var program *tea.Program
			dispatch := func(userInput string) tea.Cmd {
				go runInterview(ctx, prov, reg, interviewer, userInput, cfg.Model, program)
				return nil
			}

			welcome := "Welcome! I'm the Argus onboarding interviewer.\n" +
				"I'll ask a few questions about your company and how you want the agent to behave, " +
				"then write your SOUL.md. Type anything to begin (e.g. \"hi\" or a short intro about your team)."

			tuiModel := tui.New(tui.Config{Dispatch: dispatch, Title: "argus init"}).
				WithInitialMessages([]tui.Message{{Role: "system", Content: welcome}})

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
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	c.Flags().BoolVar(&force, "force", false, "Re-run the SOUL interview even if SOUL.md exists")
	return c
}

// initConfig holds the values collected in Phase A.
type initConfig struct {
	Provider string // currently always "gemini" — kept for forward-compat
	Model    string
	APIKey   string
}

// promptConfig asks the user for provider / model / API key, defaulting to
// any values already present in env. The provider question is hidden today
// (we only support gemini) but the structure is ready for multi-provider.
func promptConfig(in io.Reader, out io.Writer, env *config.Env) (initConfig, error) {
	r := bufio.NewReader(in)

	fmt.Fprintln(out, "=== Argus init — provider configuration ===")
	fmt.Fprintln(out)

	cfg := initConfig{Provider: "gemini"}

	// Model.
	defaultModel := env.Get("ARGUS_DEFAULT_MODEL")
	if defaultModel == "" {
		defaultModel = "gemini-2.5-flash"
	}
	model, err := promptLine(r, out, "Model id", defaultModel)
	if err != nil {
		return cfg, err
	}
	cfg.Model = model

	// API key. Show only the last 4 chars of any existing key as a hint.
	existingKey := env.Get("GEMINI_API_KEY")
	hint := ""
	if existingKey != "" {
		if len(existingKey) > 8 {
			hint = "current: …" + existingKey[len(existingKey)-4:]
		} else {
			hint = "current set"
		}
	}
	prompt := "Gemini API key"
	if hint != "" {
		prompt = fmt.Sprintf("Gemini API key (%s — press Enter to keep)", hint)
	}
	key, err := promptLine(r, out, prompt, existingKey)
	if err != nil {
		return cfg, err
	}
	if strings.TrimSpace(key) == "" {
		return cfg, errors.New("a Gemini API key is required (get one at https://aistudio.google.com/apikey)")
	}
	cfg.APIKey = strings.TrimSpace(key)

	return cfg, nil
}

// promptLine writes a prompt and reads one line from r. Pressing Enter with
// no input returns def. An EOF is returned as io.EOF so callers can decide
// (init treats it as an abort).
func promptLine(r *bufio.Reader, out io.Writer, label, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(out, "%s [%s]: ", label, redactSecret(def))
	} else {
		fmt.Fprintf(out, "%s: ", label)
	}
	line, err := r.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if strings.TrimSpace(line) == "" {
		return def, nil
	}
	return line, nil
}

// redactSecret returns a display-safe rendering of v. Long strings (assumed
// to be keys/tokens) are shown as the last 4 chars only.
func redactSecret(v string) string {
	if len(v) <= 8 {
		return v
	}
	return "…" + v[len(v)-4:]
}

// runInterview is the interviewer-side dispatcher: it kicks off one agent.Run
// per user message, streaming responses back into the TUI program.
func runInterview(ctx context.Context, prov provider.Provider, reg *tool.Registry, interviewer *soul.Soul, userInput, model string, program *tea.Program) {
	_ = model // reserved for future per-turn model override
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
	})

	if _, err := ag.Run(ctx, agent.Target{}); err != nil {
		program.Send(tui.AgentErrorMsg{Err: err})
		return
	}
	program.Send(tui.AgentDoneMsg{})
}

// interviewerPersona is the hardcoded system prompt for the bootstrap agent.
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

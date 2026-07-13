package cmd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/argusappsec/argus/pkg/agent"
	"github.com/argusappsec/argus/pkg/budget"
	"github.com/argusappsec/argus/pkg/channel/tui"
	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/provider"
	"github.com/argusappsec/argus/pkg/provider/gemini"
	"github.com/argusappsec/argus/pkg/soul"
	"github.com/argusappsec/argus/pkg/tool"
)

// initCmd is the bootstrap flow. Two phases:
//
//	Phase A — provider & API key (no LLM yet, huh-driven form).
//	          Select provider → select model → enter API key.
//	          Writes ~/.argus/argus.yaml + ~/.argus/.env.
//	Phase B — SOUL interview via the chat TUI (existing).
//
// Either phase is skipped if its artifact already exists, unless --force.
func initCmd() *cobra.Command {
	var (
		homeDir string
		force   bool
	)
	c := &cobra.Command{
		Use:   "init",
		Short: "Interactive bootstrap: pick provider, set API key, and create SOUL.md.",
		Long: "Run a two-phase bootstrap:\n" +
			"  1) provider/model selection + API key (saved to ~/.argus/argus.yaml and ~/.argus/.env)\n" +
			"  2) chat-based interview with the Argus agent to populate SOUL.md\n\n" +
			"Existing values are kept unless --force is passed.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			home, err := resolveHome(homeDir)
			if err != nil {
				return err
			}

			// --- Phase A: provider + API key ---------------------------------
			cfgPath := filepath.Join(home, "argus.yaml")
			envPath := filepath.Join(home, ".env")

			cfg, err := config.LoadConfig(cfgPath)
			if err != nil {
				return err
			}
			env, err := config.LoadEnv(envPath)
			if err != nil {
				return err
			}

			picked, err := runProviderForm(cfg, env)
			if err != nil {
				return err
			}

			cfg.Providers = map[string]config.ProviderConfig{
				picked.Provider: {
					Type:   picked.Provider,
					APIKey: config.EnvRef(providerEnvVar(picked.Provider)),
				},
			}
			cfg.DefaultModel = picked.Model
			// The instance name is asked deterministically in the Phase A form
			// (already normalized), so it lands in argus.yaml alongside the rest
			// of this phase's config. An empty value keeps the brand default.
			cfg.Persona.Name = picked.PersonaName
			if err := config.SaveConfig(cfgPath, cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}

			env.Set(providerEnvVar(picked.Provider), picked.APIKey)
			if err := env.Save(); err != nil {
				return fmt.Errorf("save .env: %w", err)
			}
			env.ApplyToProcess()
			fmt.Fprintf(cmd.OutOrStdout(), "\n✓ config:  %s\n✓ secrets: %s\n\n", cfgPath, envPath)

			// --- Phase B: SOUL interview -------------------------------------
			soulPath := filepath.Join(home, "SOUL.md")
			if !force {
				if _, err := os.Stat(soulPath); err == nil {
					fmt.Fprintf(cmd.OutOrStdout(), "SOUL.md already exists at %s — skipping interview (use --force to redo)\n", soulPath)
					return nil
				} else if !errors.Is(err, fs.ErrNotExist) {
					return fmt.Errorf("stat SOUL.md: %w", err)
				}
			}

			prov, err := gemini.New(ctx, picked.APIKey, picked.Model)
			if err != nil {
				return err
			}

			reg := tool.NewRegistry()
			reg.Register(tool.NewWriteSoul(soulPath))

			interviewer := &soul.Soul{Persona: interviewerPersona()}

			state := &interviewState{}
			pricing := defaultPricing()

			// Snapshot the SOUL.md state BEFORE the interview so we can detect
			// when the agent writes (or rewrites) it during this run.
			initialSoulMtime := soulMtime(soulPath)

			var program *tea.Program
			dispatch := func(userInput string) tea.Cmd {
				go func() {
					runInterview(ctx, prov, reg, interviewer, userInput, picked.Model, pricing, state, program)

					// After every turn, check whether SOUL.md was just written.
					// If yes, the interview is done — show the user a clear
					// closing message and exit the TUI so they're not stuck
					// in a now-purposeless chat.
					if cur := soulMtime(soulPath); !cur.IsZero() && cur.After(initialSoulMtime) {
						program.Send(tui.AgentMessageMsg{Message: provider.Message{
							Role: "system",
							Content: fmt.Sprintf(
								"✓ SOUL.md saved to %s\n\nSetup complete. Press Esc (or Ctrl+C) to exit, then try:\n  • argus chat — open an interactive chat with your agent\n    (ask it to review a github.com/owner/repo right in the conversation)",
								soulPath,
							),
						}})
						// Give the user 4s to read the goodbye, then exit through
						// the same Esc path a manual quit takes — it blanks the
						// inline footer for a clean exit (a bare program.Quit()
						// would leave the input box lingering above the shell
						// prompt). This is exactly what the goodbye tells them to
						// press.
						time.Sleep(4 * time.Second)
						program.Send(tea.KeyMsg{Type: tea.KeyEsc})
					}
				}()
				return nil
			}

			// The interviewer speaks first: a hidden kick-off message starts the
			// agent run immediately, so the first thing the user sees is the
			// greeting + question 1 — not an empty prompt waiting for input.
			tuiModel := tui.New(tui.Config{
				Dispatch:         dispatch,
				Title:            "argus init",
				AutoSubmit:       interviewKickoff,
				AutoSubmitHidden: true,
			})

			// Inline (no alt-screen): the interview transcript stays in the
			// terminal scrollback, below the Phase A form output.
			program = tea.NewProgram(tuiModel, tea.WithContext(ctx))
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

// providerSelection captures the answers of the provider form.
type providerSelection struct {
	Provider string
	Model    string
	APIKey   string
	// PersonaName is the operator-chosen instance name (persona.name in
	// argus.yaml), already trimmed and stripped of a leading @. Empty means the
	// brand default (the instance answers to Argus only).
	PersonaName string
}

// runProviderForm shows a huh form: pick provider → pick model → enter API key.
// Existing values from cfg/env are used as the form's defaults so re-running
// init only needs ENTER on what you want to keep.
func runProviderForm(cfg *config.Config, env *config.Env) (providerSelection, error) {
	sel := providerSelection{
		Provider:    "gemini",
		Model:       cfg.DefaultModel,
		APIKey:      env.Get(providerEnvVar("gemini")),
		PersonaName: cfg.Persona.Name,
	}
	if sel.Provider == "" {
		sel.Provider = "gemini"
	}

	var modelChoice string
	var customModel string

	providerStep := huh.NewSelect[string]().
		Title("Provider").
		Description("Which LLM provider does Argus talk to?").
		Options(
			huh.NewOption("Gemini (Google)", "gemini"),
			huh.NewOption("OpenAI — not yet implemented", "openai").Selected(false),
			huh.NewOption("Anthropic — not yet implemented", "anthropic").Selected(false),
		).
		Validate(func(s string) error {
			if s != "gemini" {
				return fmt.Errorf("%s is not implemented yet (only gemini works today)", s)
			}
			return nil
		}).
		Value(&sel.Provider)

	modelStep := huh.NewSelect[string]().
		Title("Model").
		Description("Pick the default model. You can override with --model on every command.").
		OptionsFunc(func() []huh.Option[string] {
			return modelOptionsFor(sel.Provider, sel.Model)
		}, &sel.Provider).
		Value(&modelChoice)

	customStep := huh.NewInput().
		Title("Custom model id").
		Description("Enter any model name supported by your provider.").
		Placeholder("gemini-2.5-flash-latest").
		Value(&customModel).
		Validate(func(s string) error {
			if strings.TrimSpace(s) == "" {
				return errors.New("model id required")
			}
			return nil
		})

	hint := "Get a free Gemini key at https://aistudio.google.com/apikey"
	if sel.APIKey != "" {
		hint += "  •  current: …" + tailOf(sel.APIKey, 4) + " (leave empty to keep)"
	}
	keyStep := huh.NewInput().
		Title("API key").
		Description(hint).
		EchoMode(huh.EchoModePassword).
		Value(&sel.APIKey).
		Validate(func(s string) error {
			if strings.TrimSpace(s) == "" {
				return errors.New("API key required")
			}
			return nil
		})

	nameStep := huh.NewInput().
		Title("Instance name (optional)").
		Description("A name colleagues address this agent by on GitHub — e.g. \"Ercole, look at this\" — in addition to the brand name Argus. Leave empty to keep just Argus.").
		Placeholder("Ercole").
		Value(&sel.PersonaName)

	form := huh.NewForm(
		huh.NewGroup(providerStep),
		huh.NewGroup(modelStep),
		huh.NewGroup(customStep).WithHideFunc(func() bool { return modelChoice != "custom" }),
		huh.NewGroup(keyStep),
		huh.NewGroup(nameStep),
	).WithTheme(huh.ThemeBase16())

	if err := form.Run(); err != nil {
		return providerSelection{}, fmt.Errorf("init form: %w", err)
	}

	if modelChoice == "custom" {
		sel.Model = strings.TrimSpace(customModel)
	} else {
		sel.Model = modelChoice
	}
	sel.APIKey = strings.TrimSpace(sel.APIKey)
	sel.PersonaName = normalizePersonaName(sel.PersonaName)
	return sel, nil
}

// modelOptionsFor returns a curated list of models for the chosen provider,
// always with a "custom" tail option for keys we don't know about. The
// `current` arg is the model already in config; it's marked as the
// preselected option.
func modelOptionsFor(provider string, current string) []huh.Option[string] {
	var models []string
	switch provider {
	case "gemini":
		models = []string{
			"gemini-2.5-flash",
			"gemini-2.5-pro",
			"gemini-2.0-flash",
			"gemini-1.5-pro",
			"gemini-1.5-flash",
		}
	default:
		models = []string{"gemini-2.5-flash"}
	}

	opts := make([]huh.Option[string], 0, len(models)+1)
	for _, m := range models {
		label := m
		switch m {
		case "gemini-2.5-flash":
			label += " (recommended)"
		case "gemini-2.5-pro":
			label += " (premium quality, slower)"
		case "gemini-2.0-flash":
			label += " (cheaper)"
		}
		o := huh.NewOption(label, m)
		if m == current {
			o = o.Selected(true)
		}
		opts = append(opts, o)
	}
	opts = append(opts, huh.NewOption("custom...", "custom"))
	return opts
}

// providerEnvVar returns the env var name where the secret for `provider`
// is stored. Kept in one place so the convention is consistent.
func providerEnvVar(provider string) string {
	switch provider {
	case "gemini":
		return "GEMINI_API_KEY"
	case "openai":
		return "OPENAI_API_KEY"
	case "anthropic":
		return "ANTHROPIC_API_KEY"
	default:
		return strings.ToUpper(provider) + "_API_KEY"
	}
}

func tailOf(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// interviewState carries the multi-turn conversation history for an
// `argus init` session. The interview command has no conversation log on
// disk, so the dispatcher keeps the history in-memory and threads it into
// each agent run as SeedMessages.
type interviewState struct {
	mu      sync.Mutex
	history []provider.Message
}

// soulMtime returns the modification time of soulPath, or the zero time if
// the file does not exist.
func soulMtime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// runInterview kicks off one agent run per user message, streaming responses
// back into the TUI program. The full prior history (from earlier turns) is
// passed as SeedMessages so the agent has the full conversational context.
func runInterview(ctx context.Context, prov provider.Provider, reg *tool.Registry, interviewer *soul.Soul, userInput, modelID string, pricing budget.Pricing, state *interviewState, program *tea.Program) {
	state.mu.Lock()
	seed := append([]provider.Message{}, state.history...)
	userMsg := provider.Message{Role: "user", Content: userInput}
	seed = append(seed, userMsg)
	state.history = append(state.history, userMsg)
	state.mu.Unlock()

	ag := agent.New(agent.Options{
		Provider:     prov,
		Tools:        reg,
		Soul:         interviewer,
		MaxTurns:     20,
		SeedMessages: seed,
		OnMessage: func(m provider.Message) {
			state.mu.Lock()
			state.history = append(state.history, m)
			state.mu.Unlock()
			program.Send(tui.AgentMessageMsg{Message: m})
		},
		OnUsage: func(u provider.Usage) {
			program.Send(tui.AgentUsageMsg{
				InputTokens:  u.InputTokens,
				OutputTokens: u.OutputTokens,
				CostUSD:      budget.CostFor(pricing, modelID, u.InputTokens, u.OutputTokens),
			})
		},
	})

	if _, err := ag.Run(ctx, agent.Target{}); err != nil {
		program.Send(tui.AgentErrorMsg{Err: err})
		return
	}
	program.Send(tui.AgentDoneMsg{})
}

// interviewKickoff is the hidden first message that starts the interview.
// It is dispatched automatically when the TUI opens (AutoSubmitHidden), so
// the interviewer greets the user instead of waiting for input. The user
// never sees this text — only the agent's reply to it.
const interviewKickoff = "[kick-off] The human just launched `argus init`. " +
	"They have typed nothing yet. Greet them and ask your first question."

// normalizePersonaName cleans an operator-entered instance name for
// persona.name in argus.yaml: it strips a leading @ (the config stores the
// bare name) and collapses surrounding and internal whitespace. An empty
// result is valid and means "no persona name" — the brand default (the
// instance answers to Argus only). A multi-word name is valid too: it forms
// no single-word @handle, but the GitHub channel answers to it as a vocative
// opening the comment (see pkg/channel/github newMentionMatcher).
func normalizePersonaName(raw string) string {
	name := strings.TrimPrefix(strings.TrimSpace(raw), "@")
	return strings.Join(strings.Fields(name), " ")
}

// interviewerPersona is the hardcoded system prompt for the bootstrap agent.
func interviewerPersona() string {
	return `You are the **Argus onboarding interviewer**.

Your job is to interview the human and produce a SOUL.md for the Argus
security agent. SOUL.md captures the slow-moving identity facts the agent
needs at the start of EVERY review — not project-deep-dive details (those
live in CONTEXT/ documents the agent will grow over time on its own).

KICK-OFF:
- The first user message is a synthetic note from the CLI marked [kick-off];
  the human has typed nothing yet. Introduce yourself in one short sentence
  and ask question 1. Start in English; from the human's first real reply
  onward, switch permanently to whatever language THEY write in.

INTERVIEW STYLE — you are a guide, not a form:
- Ask ONE question per turn. You may add a closely-related follow-up in the
  same turn ONLY when it belongs to the same theme (e.g. stack + infra).
  Never pair unrelated topics in one question.
- ALWAYS PROPOSE YOUR RECOMMENDED ANSWER with the question, inferred from
  everything you already know (industry, previous answers), so the user can
  just confirm: "You build AI for SOC teams — I'd guess your systems handle
  customer security logs and personal data. Does that sound right?"
- MEET THE HUMAN AT THEIR LEVEL. The person may be a developer with no
  security background. Never present a bare jargon enum (PII/PHI/PCI) as a
  question. Ask about their concrete reality instead — "does the product
  store personal data of end users? health data? payment cards?" — then map
  the answer to the right category YOURSELF and say how you're recording it:
  "that's what security folks call PII — I'll note it as that."
- If a term of art is unavoidable, gloss it in a few words inline.
- BUILD ON PREVIOUS ANSWERS. Each answer narrows the next question: if they
  said Kubernetes on GCP, ask about secrets as "Vault? GCP Secret Manager?
  plain K8s Secrets?" — not as an open-ended cold question.
- When an answer is vague, don't move on: probe once with a concrete
  scenario ("if a contractor's laptop leaked a repo tomorrow, how bad?").
- Accept "skip" or "I don't know" for any optional field, and offer a
  sensible default when they hesitate.
- Aim for ~7 turns. Don't drag it out.
- Never re-ask a topic already covered.

TOPICS TO COVER (adaptive order — follow the conversation, not the list):
1. Company name and what they build, for whom. Much of what follows can be
   INFERRED from this — use it.
2. Tech: primary languages/runtimes, then where it runs (cloud/on-prem,
   orchestrator). Related pair — fine in one or two turns.
3. Secrets: where production secrets actually live (Vault, cloud secret
   manager, K8s Secrets, .env). Propose the likely answer from their infra.
4. Data: what actually flows through their systems, asked concretely (end
   users' personal data? health? payments? just telemetry?). YOU derive the
   sensitivity category (public / internal / pii / phi / pci / regulated)
   and confirm it. Then compliance as its natural follow-up: certifications
   or obligations (SOC2, ISO27001, HIPAA, PCI-DSS, GDPR) — propose likely
   ones from industry + data before asking cold.
5. Reporting posture, in human terms: "want me to flag everything including
   minor issues, or only what really matters?" → map to risk tolerance
   low/medium/high. If they mention something that is ALWAYS serious for
   them, capture it as a severity rule (optional — do not press).
6. Output: language for findings/reports, tone + audience (developers?
   C-level? both?).

WHEN DONE:
- Call write_soul ONCE with ALL collected fields. Required: company + persona.
  Pass each captured value into the matching field name — do NOT cram
  stack/infra/severity rules into the persona prose if you've collected them
  as lists, use the structured fields.
- The 'persona' field is a markdown identity body you AUTHOR in two sections:
    ## Mission — who the agent serves, what it does (security reviews, chat,
    reports for <company>) and what it does NOT do (it is not a generic
    linter, it does not fix code). Ground it in what you learned.
    ## Conduct — tone, audience, priorities, and any context that doesn't
    fit a structured field. Example:
      "Be terse and technical. Cite CWE/OWASP IDs. Write for developers
       first, but keep summaries readable by C-level. Defer
       architecture-specific reasoning to context docs once they exist."
- After write_soul succeeds, call finalize_report with a one-line summary.

DO NOT ASK ABOUT:
- Architecture diagrams, service inventory, threat models, known false
  positives — those grow over time in CONTEXT/ as the agent learns from
  chats and reviews. They do NOT belong in SOUL.md.
- Which specific repos to monitor — review takes the URL on the command
  line. Multi-repo monitoring comes later.
- Escalation contacts or on-call routing — the agent has no channel to
  escalate through; do not collect data it cannot act on.

GUARDRAILS:
- Do not call write_soul more than once.
- Proposing inferred guesses is encouraged, but write_soul must contain
  ONLY what the user confirmed — never an unconfirmed guess, never a
  stack/compliance/severity item they didn't agree to.
- If the user gets impatient, finalize early (only company + persona are
  strictly required).
- Respond in the language the human writes in. If Italian → Italian.
  If English → English. Don't mix.`
}

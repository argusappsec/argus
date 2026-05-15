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

	"github.com/redcarbon-dev/argus/pkg/agent"
	"github.com/redcarbon-dev/argus/pkg/budget"
	"github.com/redcarbon-dev/argus/pkg/channel/tui"
	"github.com/redcarbon-dev/argus/pkg/config"
	"github.com/redcarbon-dev/argus/pkg/provider"
	"github.com/redcarbon-dev/argus/pkg/provider/gemini"
	"github.com/redcarbon-dev/argus/pkg/soul"
	"github.com/redcarbon-dev/argus/pkg/tool"
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
								"✓ SOUL.md saved to %s\n\nSetup complete. Press q (or Ctrl+C) to exit, then try:\n  • argus chat — open an interactive chat with your agent\n  • argus review <github-url> — run a one-shot review",
								soulPath,
							),
						}})
						// Give the user 4s to read the goodbye, then quit.
						time.Sleep(4 * time.Second)
						program.Quit()
					}
				}()
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

// providerSelection captures the answers of the provider form.
type providerSelection struct {
	Provider string
	Model    string
	APIKey   string
}

// runProviderForm shows a huh form: pick provider → pick model → enter API key.
// Existing values from cfg/env are used as the form's defaults so re-running
// init only needs ENTER on what you want to keep.
func runProviderForm(cfg *config.Config, env *config.Env) (providerSelection, error) {
	sel := providerSelection{
		Provider: "gemini",
		Model:    cfg.DefaultModel,
		APIKey:   env.Get(providerEnvVar("gemini")),
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

	form := huh.NewForm(
		huh.NewGroup(providerStep),
		huh.NewGroup(modelStep),
		huh.NewGroup(customStep).WithHideFunc(func() bool { return modelChoice != "custom" }),
		huh.NewGroup(keyStep),
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

// interviewerPersona is the hardcoded system prompt for the bootstrap agent.
func interviewerPersona() string {
	return `You are the **Argus onboarding interviewer**.

Your job is to interview the human in front of you and produce a SOUL.md for
the Argus security agent. SOUL.md captures the agent's identity: who it works
for, in what industry, what they build, where they run, under which compliance
frameworks, what risk tolerance, who to escalate to, which repositories it
watches, and what tone/persona to adopt.

INTERVIEW STYLE:
- Ask ONE focused question per turn. Do not dump a checklist.
- Acknowledge each answer briefly, then move on to the next topic.
- Be conversational and respectful. The user may not know all answers right
  away — accept "skip" or "I don't know" for optional fields.
- Aim for ~8-10 turns total. Don't drag it out.
- Pay attention to context: the user's previous answers are visible in your
  history. Never re-ask a topic you already covered.

TOPICS TO COVER (in roughly this order):
1. Company name and industry.
2. **Tech stack** — primary languages (e.g. Go, Python, TypeScript), main
   frameworks/runtimes (e.g. React, Django, Spring), key data stores
   (PostgreSQL, Redis, Mongo). This shapes which security rules the agent
   will emphasise (e.g. Bandit-style Python rules, npm audit, govulncheck).
3. **Infrastructure** — where the code runs (AWS / GCP / Azure / self-host
   on-prem / hybrid), orchestration (Kubernetes? Docker Compose? bare VMs?
   serverless?), notable services (RDS, Cloud SQL, S3, etc.). This shapes
   which IaC rules and cloud-specific checks matter.
4. Compliance frameworks (SOC2, ISO27001, HIPAA, PCI-DSS, GDPR, none).
5. Risk tolerance (low / medium / high).
6. Escalation contact (email or chat handle of the security owner).
7. Repositories to monitor (GitHub URLs or "decide later").
8. Tone preferences (terse vs friendly, technical vs executive-oriented).

WHEN DONE:
- Call write_soul ONCE with all collected fields. Required: company + persona.
- The 'persona' field should be a concise paragraph (~5-7 sentences) you AUTHOR
  based on the user's stack/infra/tone answers. Include CONCRETE facts that
  will guide future reviews:
    * "RedCarbon ships a Go+Python SaaS on AWS+Kubernetes (EKS) with
       PostgreSQL/Redis. SOC2 + ISO27001 + GDPR. Low risk tolerance —
       flag medium and above. Be terse and cite CWE IDs."
  This prose IS the body of SOUL.md and feeds every future agent run as system
  prompt, so make it precise and useful.
- After write_soul succeeds, call finalize_report with a one-line summary.

GUARDRAILS:
- Do not call write_soul more than once.
- Do not invent stack/compliance items the user didn't mention.
- If the user gets impatient, finalize early with what you have (only company
  + a generic persona are strictly required).
- Respond in the same language the user is using. If they write in Italian,
  reply in Italian; if English, reply in English. Don't mix.`
}

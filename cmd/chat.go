package cmd

import (
	"context"
	"fmt"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/redcarbon-dev/argus/pkg/agent"
	"github.com/redcarbon-dev/argus/pkg/channel/tui"
	"github.com/redcarbon-dev/argus/pkg/memory"
	"github.com/redcarbon-dev/argus/pkg/provider"
)

// chatCmd is the interactive entry point. Each user submission becomes one
// agent.Run with the input as a SeedMessage; messages from the agent are
// streamed back to the TUI via OnMessage → tea.Program.Send.
//
// The dispatcher closure captures the *tea.Program so that the agent
// goroutine — which runs outside bubbletea's normal Cmd flow — can post
// AgentMessageMsg / AgentUsageMsg / AgentDoneMsg / AgentErrorMsg events.
func chatCmd() *cobra.Command {
	var (
		model    string
		maxTurns int
		homeDir  string
	)
	c := &cobra.Command{
		Use:   "chat",
		Short: "Open an interactive chat with the Argus agent.",
		Long: "Open an interactive terminal chat with the Argus agent.\n" +
			"Type natural language to drive a review; slash commands (/help, /clear, /cost, /cancel, /quit) " +
			"are intercepted client-side and never reach the LLM.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			rt, err := buildRuntime(ctx, runtimeOptions{HomeOverride: homeDir, Model: model})
			if err != nil {
				return err
			}
			defer rt.Close()

			fmt.Fprintf(cmd.OutOrStdout(), "session %s — conversation log at %s\n", rt.Session.ID(), rt.ConvoPath)

			// Forward declared: dispatcher closes over the program created below.
			var program *tea.Program

			dispatch := func(userInput string) tea.Cmd {
				go runChatAgent(ctx, rt, userInput, maxTurns, program)
				return nil
			}

			model := tui.New(tui.Config{Dispatch: dispatch})
			program = tea.NewProgram(model, tea.WithAltScreen(), tea.WithContext(ctx))
			if _, err := program.Run(); err != nil {
				return fmt.Errorf("tui: %w", err)
			}

			// On clean exit, curate memory if there was any interaction worth
			// remembering. A failure here is non-fatal — the user already
			// has the conversation log on disk.
			fmt.Fprintln(cmd.OutOrStdout(), "→ curating memory")
			if err := memory.Curate(context.Background(), memory.Options{
				ConversationPath: rt.ConvoPath,
				MemoryPath:       filepath.Join(rt.Home, "MEMORY.md"),
				Provider:         rt.Provider,
			}); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "  warning: memory curation skipped: %v\n", err)
			}
			return nil
		},
	}
	c.Flags().StringVar(&model, "model", "gemini-2.5-flash", "Gemini model id")
	c.Flags().IntVar(&maxTurns, "max-turns", 50, "Safety-net cap per turn of the agent loop")
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	return c
}

// runChatAgent executes one agent run for a single user input and streams its
// progress to the TUI program. Called in its own goroutine by the dispatcher.
func runChatAgent(ctx context.Context, rt *runtime, userInput string, maxTurns int, program *tea.Program) {
	ag := agent.New(agent.Options{
		Provider:     rt.Provider,
		Audit:        rt.Audit,
		Tools:        rt.Registry,
		Conversation: rt.Conversation,
		Soul:         rt.Soul,
		MaxTurns:     maxTurns,
		SeedMessages: []provider.Message{{Role: "user", Content: userInput}},

		OnMessage: func(m provider.Message) {
			program.Send(tui.AgentMessageMsg{Message: m})
		},
		OnUsage: func(u provider.Usage) {
			// Cost computation deferred — for now we surface raw token counts.
			// pkg/budget will be wired in once the pricing table is populated.
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

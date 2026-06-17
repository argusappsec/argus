package cmd

import (
	"errors"
	"fmt"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/redcarbon-dev/argus/pkg/channel/tui"
	"github.com/redcarbon-dev/argus/pkg/channel/uds"
)

// chatCmd is the interactive entry point. The TUI is a pure UDS client: it
// connects to a running argusd, or to an in-process daemon spawned on a
// private socket when none is listening (connectOrSpawn). Either way the
// dispatch path is identical — auth, SessionManager, agent — and skills
// resolve on the daemon against the organization's catalog.
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
			"Type natural language to drive a review; client commands (/help, /clear, /cost, /cancel, /quit) " +
			"never leave the client, while /<skill-name> travels to the daemon and runs the org's skill.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cs, err := connectOrSpawn(homeDir, uds.HelloOptions{Model: model, MaxTurns: maxTurns})
			if err != nil {
				return err
			}
			defer cs.Close()

			if cs.InProcess {
				fmt.Fprintln(cmd.OutOrStdout(), "argus: no daemon on the socket — running one in-process")
			}
			convoPath := filepath.Join(cs.Home, "conversations", cs.Client.SessionID()+".jsonl")
			fmt.Fprintf(cmd.OutOrStdout(), "session %s — conversation log at %s\n", cs.Client.SessionID(), convoPath)

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
				ForwardSlash: true,
				Cancel:       func() { _ = cs.Client.Cancel() },
			})
			program = tea.NewProgram(model, tea.WithAltScreen(), tea.WithContext(cmd.Context()))

			go receiveLoop(cs.Client, program)

			if _, err := program.Run(); err != nil {
				return fmt.Errorf("tui: %w", err)
			}
			// Memory curation happens on the daemon when the Session is
			// released (the connection drop, a few microseconds from now).
			return nil
		},
	}
	c.Flags().StringVar(&model, "model", "", "Override the daemon's default model for this session (must be configured on the daemon)")
	c.Flags().IntVar(&maxTurns, "max-turns", 50, "Safety-net cap per turn of the agent loop")
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	return c
}

// receiveLoop pumps server frames into the TUI until the connection closes.
// Terminal frames (done/error) close one run; the loop itself lives as long
// as the connection.
func receiveLoop(c *uds.Client, program *tea.Program) {
	for {
		f, err := c.Recv()
		if err != nil {
			if !errors.Is(err, uds.ErrConnClosed) {
				program.Send(tui.AgentErrorMsg{Err: err})
			}
			return
		}
		switch f.Type {
		case uds.TypeAgentMessage:
			if f.Message != nil {
				program.Send(tui.AgentMessageMsg{Message: *f.Message})
			}
		case uds.TypeUsage:
			program.Send(tui.AgentUsageMsg{
				InputTokens:  f.InputTokens,
				OutputTokens: f.OutputTokens,
				CostUSD:      f.CostUSD,
			})
		case uds.TypeDone:
			program.Send(tui.AgentDoneMsg{})
		case uds.TypeError:
			program.Send(tui.AgentErrorMsg{Err: errors.New(f.Reason)})
		}
	}
}

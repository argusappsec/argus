package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// isSlashCommand returns true if the line begins with "/".
func isSlashCommand(line string) bool {
	return strings.HasPrefix(line, "/")
}

// runSlashCommand executes a client-side slash command, returning the updated
// Model and an optional tea.Cmd. Every command echoes the typed line to the
// scrollback; most also print a "system" reply. Unknown commands report an
// error line. The command is recorded in the `messages` registry too, so the
// test-facing Messages() accessor stays authoritative.
//
// Pedagogically: slash commands NEVER reach the LLM. They live entirely in
// the client and are the boundary between "what the UX decides" and "what the
// agent decides". /cost and /cancel must be instant and free of LLM cost.
func (m Model) runSlashCommand(line string) (Model, tea.Cmd) {
	// Echo the command itself so the user has a record.
	echo := Message{Role: "user", Content: line}
	m.messages = append(m.messages, echo)

	// First token is the command, the rest are args (currently unused).
	parts := strings.Fields(line)
	cmd := parts[0]

	switch cmd {
	case "/help":
		sys := Message{Role: "system", Content: helpText()}
		m.messages = append(m.messages, sys)
		return m, m.printMessages(echo, sys)

	case "/clear":
		// Wipe the display registry. The native scrollback cannot be erased in
		// inline mode, so earlier lines remain visible in the terminal — this
		// clears Argus's own record (and any lingering error), not the screen.
		m.messages = nil
		m.lastErr = nil
		return m, m.printMessages(echo)

	case "/cost":
		sys := Message{
			Role: "system",
			Content: fmt.Sprintf("tokens in:%d out:%d  cost:$%.4f",
				m.tokensIn, m.tokensOut, m.costUSD),
		}
		m.messages = append(m.messages, sys)
		return m, m.printMessages(echo, sys)

	case "/cancel":
		// Tell the source to abort (the daemon cancels the run's context),
		// then clear the local busy flag so the user can type again.
		if m.busy {
			if m.cfg.Cancel != nil {
				m.cfg.Cancel()
			}
			m.busy = false
			sys := Message{Role: "system", Content: "cancelled"}
			m.messages = append(m.messages, sys)
			return m, m.printMessages(echo, sys)
		}
		return m, m.printMessages(echo)

	case "/quit":
		// Return tea.Quit unadorned so the caller's Cmd resolves to QuitMsg;
		// quitting blanks the footer for a clean exit (see Model.View).
		m.quitting = true
		return m, tea.Quit

	default:
		// Not a built-in client command. Fall back to skill resolution:
		// "/pr-quick-check" loads that skill and runs it through the agent.
		// This is the ONE slash path that reaches the LLM (see ResolveSkill).
		name := strings.TrimPrefix(cmd, "/")
		if m.cfg.ResolveSkill != nil {
			if prompt, ok := m.cfg.ResolveSkill(name); ok {
				return m.dispatchSkill(echo, name, prompt)
			}
		}
		// Daemon-client mode: the catalog lives on the daemon host, so the
		// raw line travels and the daemon resolves it (unknown skills come
		// back as an error frame).
		if m.cfg.ForwardSlash {
			return m.dispatchSkill(echo, name, line)
		}
		sys := Message{
			Role:    "system",
			Content: fmt.Sprintf("unknown command %s (try /help)", cmd),
		}
		m.messages = append(m.messages, sys)
		return m, m.printMessages(echo, sys)
	}
}

// dispatchSkill sends a skill invocation through the regular Dispatch flow,
// guarding the single-run-at-a-time invariant. echo is the already-recorded
// command line; it is printed alongside the notice so the scrollback keeps
// both in order.
func (m Model) dispatchSkill(echo Message, name, prompt string) (Model, tea.Cmd) {
	if m.busy {
		sys := Message{
			Role:    "system",
			Content: "agent is busy — wait for the current turn to finish, then retry",
		}
		m.messages = append(m.messages, sys)
		return m, m.printMessages(echo, sys)
	}
	notice := Message{
		Role:    "system",
		Content: fmt.Sprintf("invoking skill: %s", name),
	}
	m.messages = append(m.messages, notice)
	m.busy = true
	cmds := []tea.Cmd{m.printMessages(echo, notice), m.spinner.Tick}
	if m.cfg.Dispatch != nil {
		cmds = append(cmds, m.cfg.Dispatch(prompt))
	}
	return m, tea.Batch(cmds...)
}

func helpText() string {
	return strings.Join([]string{
		"client-side slash commands (never reach the agent):",
		"  /help    show this help",
		"  /clear   wipe the chat history",
		"  /cost    show cumulative tokens and USD spend",
		"  /cancel  abort the current agent run",
		"  /quit    exit Argus",
		"",
		"skills (run through the agent):",
		"  /<skill-name>  load and run a saved skill (list them: `argus skill ls`)",
	}, "\n")
}

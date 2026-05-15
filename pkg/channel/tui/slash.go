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
// Model and an optional tea.Cmd (used by /quit). Unknown commands produce a
// "system" message in the chat history.
//
// Pedagogically: slash commands NEVER reach the LLM. They live entirely in
// the client and are the boundary between "what the UX decides" and "what the
// agent decides". /cost and /cancel must be instant and free of LLM cost.
func (m Model) runSlashCommand(line string) (Model, tea.Cmd) {
	// Echo the command itself in history so the user has a record.
	m.messages = append(m.messages, Message{Role: "user", Content: line})

	// First token is the command, the rest are args (currently unused).
	parts := strings.Fields(line)
	cmd := parts[0]

	switch cmd {
	case "/help":
		m.messages = append(m.messages, Message{Role: "system", Content: helpText()})
		return m, nil

	case "/clear":
		// Drop everything except the just-recorded /clear line, then drop that too.
		m.messages = nil
		m.lastErr = nil
		return m, nil

	case "/cost":
		m.messages = append(m.messages, Message{
			Role: "system",
			Content: fmt.Sprintf("tokens in:%d out:%d  cost:$%.4f",
				m.tokensIn, m.tokensOut, m.costUSD),
		})
		return m, nil

	case "/cancel":
		// Best-effort: clear the busy flag so the user can type again. The
		// in-flight goroutine is not actually killed yet (that requires the
		// dispatcher to honor a context cancellation — wired in cmd/chat.go).
		if m.busy {
			m.busy = false
			m.messages = append(m.messages, Message{Role: "system", Content: "cancelled"})
		}
		return m, nil

	case "/quit":
		return m, tea.Quit

	default:
		m.messages = append(m.messages, Message{
			Role:    "system",
			Content: fmt.Sprintf("unknown command %s (try /help)", cmd),
		})
		return m, nil
	}
}

func helpText() string {
	return strings.Join([]string{
		"slash commands (client-side, never reach the agent):",
		"  /help    show this help",
		"  /clear   wipe the chat history",
		"  /cost    show cumulative tokens and USD spend",
		"  /cancel  abort the current agent run",
		"  /quit    exit Argus",
	}, "\n")
}

// Package tui implements the bubbletea-based terminal chat for Argus.
//
// The TUI is structured around the Elm pattern: an immutable Model + an
// Update function that returns a new Model in response to messages. The
// program owns rendering (View) and dispatches input events.
//
// External integration:
//
//   - Submitting text triggers a goroutine (started by the dispatcher
//     supplied via Config.Dispatch) that calls agent.Run with the input as a
//     SeedMessage. The agent's OnMessage hook funnels each generated message
//     back to the bubbletea program as AgentMessageMsg via tea.Program.Send.
//   - When the agent run terminates, the dispatcher posts AgentDoneMsg or
//     AgentErrorMsg, which clears the busy state.
package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/redcarbon-dev/argus/pkg/provider"
)

// Message is the displayable form of one conversation entry.
type Message struct {
	Role    string // "user" | "agent" | "tool" | "system"
	Content string
	Name    string // tool name when Role=="tool"
}

// Dispatcher kicks off an agent run for the given user prompt. The dispatcher
// is responsible for: (a) running agent.Run in a goroutine, (b) wiring its
// OnMessage hook to call program.Send(AgentMessageMsg{...}) for each emitted
// message, (c) posting AgentDoneMsg or AgentErrorMsg when the run terminates.
//
// The dispatcher is injected so tests can avoid spinning up real Bubble Tea
// programs and real agents.
type Dispatcher func(prompt string) tea.Cmd

// Config bundles the optional dependencies the TUI needs.
type Config struct {
	// Dispatch is invoked when the user submits a line of input. If nil, the
	// submission is recorded in history but no agent run is started — useful
	// for tests that exercise Model state without provider/agent wiring.
	Dispatch Dispatcher
}

// --- tea.Msg types emitted by the dispatcher ---

// AgentMessageMsg carries one streamed message from the agent loop.
type AgentMessageMsg struct {
	Message provider.Message
}

// AgentUsageMsg reports the token and cost delta of one LLM call. Dispatched
// by the cmd/chat.go runner after each agent turn (cost is computed using
// pkg/budget against the active pricing table).
type AgentUsageMsg struct {
	InputTokens  int
	OutputTokens int
	CostUSD      float64
}

// AgentDoneMsg signals the agent loop terminated normally.
type AgentDoneMsg struct{}

// AgentErrorMsg signals the agent loop returned an error.
type AgentErrorMsg struct {
	Err error
}

// --- Model ---

// Model is the Elm-pattern state. Methods return new Model values; the value
// type is intentional so accidental shared mutation is impossible.
type Model struct {
	cfg      Config
	messages []Message
	input    textinput.Model
	busy     bool
	lastErr  error

	// Cumulative usage across the session, for the status bar.
	tokensIn, tokensOut int
	costUSD             float64
}

// New constructs a Model with empty history and a configured text input.
func New(cfg Config) Model {
	ti := textinput.New()
	ti.Placeholder = "Type your message and press Enter..."
	ti.Focus()
	return Model{
		cfg:   cfg,
		input: ti,
	}
}

// Init satisfies tea.Model.
func (m Model) Init() tea.Cmd { return textinput.Blink }

// Update handles one bubbletea event.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEnter:
			return m.handleSubmit()
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit
		}

	case AgentMessageMsg:
		m.messages = append(m.messages, fromProviderMessage(msg.Message))
		return m, nil

	case AgentDoneMsg:
		m.busy = false
		return m, nil

	case AgentErrorMsg:
		m.busy = false
		m.lastErr = msg.Err
		return m, nil

	case AgentUsageMsg:
		m.tokensIn += msg.InputTokens
		m.tokensOut += msg.OutputTokens
		m.costUSD += msg.CostUSD
		return m, nil
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m Model) handleSubmit() (tea.Model, tea.Cmd) {
	text := strings.TrimSpace(m.input.Value())
	if text == "" {
		return m, nil
	}
	m.input.SetValue("")

	// Slash commands are client-side: they NEVER reach the dispatcher/agent.
	// /cancel is the only one allowed while busy; the others are a no-op then.
	if isSlashCommand(text) {
		newModel, cmd := m.runSlashCommand(text)
		return newModel, cmd
	}

	if m.busy {
		// Ignore plain text while the agent is running. We could queue it,
		// but silent ignoring is least surprising.
		return m, nil
	}

	m.messages = append(m.messages, Message{Role: "user", Content: text})
	m.busy = true

	if m.cfg.Dispatch != nil {
		return m, m.cfg.Dispatch(text)
	}
	// No dispatcher configured (tests): the model is "busy" but never
	// receives AgentDoneMsg. Tests can dispatch that themselves.
	return m, nil
}

// View renders the current Model state.
func (m Model) View() string {
	var b strings.Builder
	for _, msg := range m.messages {
		b.WriteString(renderMessage(msg))
		b.WriteByte('\n')
	}
	if m.lastErr != nil {
		fmt.Fprintf(&b, "\n[error] %s\n", m.lastErr.Error())
	}
	if m.busy {
		b.WriteString("\n(working...)\n")
	}
	b.WriteByte('\n')
	b.WriteString(m.input.View())
	b.WriteByte('\n')
	b.WriteString(m.statusBar())
	return b.String()
}

// statusBar renders the bottom line showing cumulative usage.
func (m Model) statusBar() string {
	return fmt.Sprintf("─── tokens in:%d out:%d  cost:$%.4f ───",
		m.tokensIn, m.tokensOut, m.costUSD)
}

func renderMessage(msg Message) string {
	switch msg.Role {
	case "user":
		return "> " + msg.Content
	case "agent":
		if msg.Content == "" {
			return "argus: …"
		}
		return "argus: " + msg.Content
	case "tool":
		return "  [tool " + msg.Name + "] " + truncate(msg.Content, 200)
	default:
		return msg.Content
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + " …"
}

// fromProviderMessage converts the agent's wire-format Message into one or
// more displayable Messages. A single agent turn may produce multiple tool
// call lines and/or a text body — we collapse them here into a representative
// display Message (we may iterate later if granular display is needed).
func fromProviderMessage(m provider.Message) Message {
	switch m.Role {
	case "model":
		// Prefer text content if present; else describe the tool calls.
		if m.Content != "" {
			return Message{Role: "agent", Content: m.Content}
		}
		if len(m.ToolCalls) > 0 {
			names := make([]string, 0, len(m.ToolCalls))
			for _, tc := range m.ToolCalls {
				names = append(names, fmt.Sprintf("→ %s(%s)", tc.Name, summarizeArgs(tc.Args)))
			}
			return Message{Role: "agent", Content: strings.Join(names, "\n")}
		}
		return Message{Role: "agent", Content: ""}

	case "tool":
		if len(m.ToolResults) == 0 {
			return Message{Role: "tool", Content: ""}
		}
		tr := m.ToolResults[0] // simplification: show only first result
		return Message{
			Role:    "tool",
			Name:    tr.Name,
			Content: tr.Output,
		}

	case "user":
		return Message{Role: "user", Content: m.Content}

	default:
		return Message{Role: "system", Content: m.Content}
	}
}

func summarizeArgs(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	parts := make([]string, 0, len(args))
	for k, v := range args {
		s := fmt.Sprintf("%v", v)
		if len(s) > 40 {
			s = s[:37] + "…"
		}
		parts = append(parts, fmt.Sprintf("%s=%s", k, s))
	}
	return strings.Join(parts, ", ")
}

// --- Test-facing accessors / helpers ---

// Messages returns the current chat history. The returned slice is a copy;
// mutation is safe.
func (m Model) Messages() []Message {
	out := make([]Message, len(m.messages))
	copy(out, m.messages)
	return out
}

// InputValue returns the current text in the input box.
func (m Model) InputValue() string { return m.input.Value() }

// IsBusy reports whether the model is currently waiting on an agent run.
func (m Model) IsBusy() bool { return m.busy }

// TokensIn returns the cumulative input tokens consumed in this session.
func (m Model) TokensIn() int { return m.tokensIn }

// TokensOut returns the cumulative output tokens consumed in this session.
func (m Model) TokensOut() int { return m.tokensOut }

// CostUSD returns the cumulative USD cost of this session.
func (m Model) CostUSD() float64 { return m.costUSD }

// WithInput returns a new Model with the input box pre-populated. Used by
// tests to avoid simulating keystroke-by-keystroke entry.
func (m Model) WithInput(s string) Model {
	m.input.SetValue(s)
	return m
}

// WithInitialMessages returns a new Model with the supplied history baked in.
// Used to display a welcome/instructions message before the first user input.
// Do NOT use this to inject "user" messages that should be processed by the
// agent — those must go through the Dispatch flow.
func (m Model) WithInitialMessages(msgs []Message) Model {
	m.messages = append([]Message{}, msgs...)
	return m
}

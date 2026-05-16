// Package tui implements the bubbletea-based terminal chat for Argus.
//
// Visual style is intentionally close to Claude Code's terminal UI:
// bordered viewport for scrollable history on top, bordered input at the
// bottom, single-line status bar showing cumulative usage and a spinner
// while the agent is working.
//
// The model follows the Elm pattern: Update returns a new Model in response
// to messages; View renders the current state. External integration is via
// a Dispatcher closure (see Config) and tea.Program.Send for streaming
// agent events.
package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

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

	// Title appears in the header. Empty defaults to "argus".
	Title string

	// AutoSubmit, if non-empty, is submitted as the first user message after
	// the TUI starts. Used by `argus review <url>` to drop the user straight
	// into a chat where the agent is already working on the requested review.
	AutoSubmit string
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

// autoSubmitMsg fires once after Init() when Config.AutoSubmit is set. The
// handler treats it as if the user had typed AutoSubmit and pressed Enter.
type autoSubmitMsg struct{ text string }

// AgentErrorMsg signals the agent loop returned an error.
type AgentErrorMsg struct {
	Err error
}

// --- Model ---

// Model is the Elm-pattern state. Methods return new Model values; the value
// type is intentional so accidental shared mutation is impossible.
type Model struct {
	cfg     Config
	styles  styles

	// Layout — populated by WindowSizeMsg.
	width, height int
	ready         bool

	// Components.
	viewport viewport.Model
	input    textinput.Model
	spinner  spinner.Model

	// State.
	messages []Message
	busy     bool
	lastErr  error

	// Cumulative usage for the status bar.
	tokensIn, tokensOut int
	costUSD             float64
}

// New constructs a Model with empty history and a configured text input.
func New(cfg Config) Model {
	ti := textinput.New()
	ti.Placeholder = "Type a message and press Enter — slash commands like /help work here"
	ti.Prompt = "▷ "
	ti.Focus()
	ti.CharLimit = 4096

	sp := spinner.New()
	sp.Spinner = spinner.Dot

	return Model{
		cfg:     cfg,
		styles:  newStyles(),
		input:   ti,
		spinner: sp,
	}
}

// Init satisfies tea.Model. If Config.AutoSubmit is set, a one-shot Cmd is
// scheduled that delivers an autoSubmitMsg — handled in Update as if the user
// had typed it.
func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{textinput.Blink, m.spinner.Tick}
	if m.cfg.AutoSubmit != "" {
		text := m.cfg.AutoSubmit
		cmds = append(cmds, func() tea.Msg { return autoSubmitMsg{text: text} })
	}
	return tea.Batch(cmds...)
}

// Update handles one bubbletea event.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m = m.relayout()
		return m, nil

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEnter:
			return m.handleSubmit()
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit
		}

	case AgentMessageMsg:
		// Drop user-role echoes from the agent's OnMessage hook (we already
		// rendered them locally in handleSubmit).
		if msg.Message.Role == "user" {
			return m, nil
		}
		m.messages = append(m.messages, fromProviderMessage(msg.Message))
		m.refreshViewport()
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

	case autoSubmitMsg:
		m.input.SetValue(msg.text)
		return m.handleSubmit()

	case spinner.TickMsg:
		if !m.busy {
			return m, nil
		}
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	// Forward everything else to the input + viewport so they get keystrokes,
	// scroll wheels, etc.
	var cmds []tea.Cmd
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	cmds = append(cmds, cmd)
	if m.ready {
		m.viewport, cmd = m.viewport.Update(msg)
		cmds = append(cmds, cmd)
	}
	return m, tea.Batch(cmds...)
}

func (m Model) handleSubmit() (tea.Model, tea.Cmd) {
	text := strings.TrimSpace(m.input.Value())
	if text == "" {
		return m, nil
	}
	m.input.SetValue("")

	if isSlashCommand(text) {
		newModel, cmd := m.runSlashCommand(text)
		newModel.refreshViewport()
		return newModel, cmd
	}

	if m.busy {
		return m, nil
	}

	m.messages = append(m.messages, Message{Role: "user", Content: text})
	m.busy = true
	m.refreshViewport()

	cmds := []tea.Cmd{m.spinner.Tick}
	if m.cfg.Dispatch != nil {
		cmds = append(cmds, m.cfg.Dispatch(text))
	}
	return m, tea.Batch(cmds...)
}

// relayout recomputes the viewport size and rebuilds its content. Called on
// WindowSizeMsg.
func (m Model) relayout() Model {
	// Reserve rows for: input box (3: border+line+border) + status bar (1) +
	// some breathing room between input and status (1).
	const inputRows = 3
	const statusRows = 1
	const padding = 1

	historyHeight := m.height - inputRows - statusRows - padding
	if historyHeight < 3 {
		historyHeight = 3
	}
	historyWidth := m.width - 2 // borders
	if historyWidth < 20 {
		historyWidth = 20
	}

	if !m.ready {
		m.viewport = viewport.New(historyWidth, historyHeight)
		m.ready = true
	} else {
		m.viewport.Width = historyWidth
		m.viewport.Height = historyHeight
	}

	m.input.Width = m.width - 4 // borders + prompt

	m.refreshViewport()
	return m
}

// refreshViewport re-renders all history into the viewport and keeps the user
// pinned to the bottom (chat-style auto-scroll).
func (m *Model) refreshViewport() {
	if !m.ready {
		return
	}
	m.viewport.SetContent(m.renderHistory())
	m.viewport.GotoBottom()
}

// View renders the current Model state.
func (m Model) View() string {
	if !m.ready {
		// Test / pre-size fallback: simple top-to-bottom rendering so unit
		// tests that don't dispatch WindowSizeMsg still see the expected text.
		return m.fallbackView()
	}

	historyPane := m.styles.historyBox.
		Width(m.viewport.Width).
		Height(m.viewport.Height).
		Render(m.viewport.View())

	inputPane := m.styles.inputBox.
		Width(m.width - 2).
		Render(m.input.View())

	statusLine := m.styles.statusBar.Render(m.statusLine())

	return lipgloss.JoinVertical(lipgloss.Left, historyPane, inputPane, statusLine)
}

// fallbackView is used when no WindowSizeMsg has arrived (typical in tests).
// It mirrors View() conceptually but skips lipgloss boxing so plain-string
// assertions still match.
func (m Model) fallbackView() string {
	var b strings.Builder
	b.WriteString(m.renderHistory())
	if m.lastErr != nil {
		fmt.Fprintf(&b, "\n[error] %s\n", m.lastErr.Error())
	}
	if m.busy {
		b.WriteString("\n(working...)\n")
	}
	b.WriteString("\n")
	b.WriteString(m.input.View())
	b.WriteString("\n")
	b.WriteString(m.statusLine())
	return b.String()
}

func (m Model) renderHistory() string {
	if len(m.messages) == 0 {
		return ""
	}
	var b strings.Builder
	for i, msg := range m.messages {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(m.renderMessage(msg))
	}
	return b.String()
}

func (m Model) renderMessage(msg Message) string {
	switch msg.Role {
	case "user":
		return m.styles.userPrompt.Render("▶ you") + "\n" +
			m.styles.userBody.Render(indent(msg.Content, "  "))
	case "agent":
		body := msg.Content
		if body == "" {
			body = "…"
		}
		return m.styles.agentPrompt.Render("◆ argus") + "\n" +
			m.styles.agentBody.Render(indent(body, "  "))
	case "tool":
		header := m.styles.toolPrefix.Render(fmt.Sprintf("  ↳ %s", msg.Name))
		body := m.styles.toolBody.Render(indent(truncate(msg.Content, 400), "    "))
		return header + "\n" + body
	case "system":
		return m.styles.systemPrefix.Render("• system") + "\n" +
			m.styles.systemBody.Render(indent(msg.Content, "  "))
	default:
		return msg.Content
	}
}

func (m Model) statusLine() string {
	parts := []string{
		fmt.Sprintf("%s %s",
			m.styles.statusLabel.Render("tokens in:"),
			m.styles.statusValue.Render(fmt.Sprintf("%d", m.tokensIn))),
		fmt.Sprintf("%s %s",
			m.styles.statusLabel.Render("out:"),
			m.styles.statusValue.Render(fmt.Sprintf("%d", m.tokensOut))),
		fmt.Sprintf("%s %s",
			m.styles.statusLabel.Render("cost:"),
			m.styles.statusValue.Render(fmt.Sprintf("$%.4f", m.costUSD))),
	}
	line := strings.Join(parts, m.styles.statusDivide.Render(" │ "))

	if m.busy {
		line += "  " + m.styles.statusWork.Render(m.spinner.View()+" working")
	}
	if m.lastErr != nil {
		line += "  " + m.styles.errorBody.Render("⚠ "+m.lastErr.Error())
	}
	return line
}

func indent(s, prefix string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + " …"
}

// fromProviderMessage converts the agent's wire-format Message into one
// displayable Message. A single agent turn may produce multiple tool call
// lines and/or a text body — we collapse them into a representative display
// message (granular per-call display can be added later if needed).
func fromProviderMessage(m provider.Message) Message {
	switch m.Role {
	case "model":
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
		tr := m.ToolResults[0]
		return Message{Role: "tool", Name: tr.Name, Content: tr.Output}

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

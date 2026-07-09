// Package tui implements the bubbletea-based terminal chat for Argus.
//
// The TUI runs INLINE (no alt-screen): completed messages are printed once
// into the terminal's native scrollback via tea.Println, and bubbletea only
// manages a small footer frame at the bottom — the input textarea (bordered,
// growing 1→6 rows) plus a single status line with cumulative usage and a
// spinner while the agent works. Printing to scrollback (instead of a bordered
// viewport) means the terminal owns wrapping and selection: long lines are no
// longer truncated, and the mouse stays free for copy/paste.
//
// The model follows the Elm pattern: Update returns a new Model in response to
// messages; View renders the current footer. Every message that reaches the
// scrollback is also kept in the internal `messages` slice, which backs the
// test-facing Messages() accessor. External integration is via a Dispatcher
// closure (see Config) and tea.Program.Send for streaming agent events.
package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/argusappsec/argus/pkg/provider"
)

// Message is the displayable form of one conversation entry.
type Message struct {
	Role    string // "user" | "agent" | "tool" | "system"
	Content string
	Name    string // tool name when Role=="tool"

	// markdown flags an agent message whose body is genuine prose that should
	// be rendered through glamour. Tool-call summaries (also Role=="agent")
	// leave it false so their line breaks survive — markdown collapses single
	// newlines into spaces, which would merge one call per line into a blob.
	markdown bool
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

	// AutoSubmitHidden dispatches AutoSubmit to the agent without echoing it
	// in the history. Used by `argus init`, whose kick-off text is a synthetic
	// protocol note ("the interview just started") the user should never see —
	// the first visible message is the agent's greeting.
	AutoSubmitHidden bool

	// ResolveSkill maps a skill name (the token after the leading slash — e.g.
	// "pr-quick-check" for "/pr-quick-check") to the prompt to dispatch to the
	// agent, and reports whether a skill by that name exists. The TUI consults
	// it when a slash command is not a built-in client command, so "/<name>"
	// loads that skill and runs it through the agent. Nil disables skill slash
	// commands (an unknown slash command is then simply rejected).
	ResolveSkill func(name string) (prompt string, ok bool)

	// ForwardSlash, when true, dispatches non-built-in slash lines raw
	// (e.g. "/secret-rotation-plan focus on infra") instead of rejecting
	// them. This is the daemon-client mode: skills are resolved server-side
	// against the organization's catalog, not the client's filesystem.
	// Checked only when ResolveSkill is nil or doesn't know the name.
	ForwardSlash bool

	// Cancel, if non-nil, is invoked by the /cancel command so the client
	// can abort the in-flight run at its source (the daemon) instead of
	// merely clearing the local busy flag.
	Cancel func()

	// StartBusy marks the model busy from the first frame. Used by
	// `argus review`, where the run is started by the command itself
	// (structured review target) rather than by a typed message.
	StartBusy bool
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
// handler treats it as if the user had typed AutoSubmit and pressed Enter;
// with hidden set, the text is dispatched but not echoed in the history.
type autoSubmitMsg struct {
	text   string
	hidden bool
}

// AgentErrorMsg signals the agent loop returned an error.
type AgentErrorMsg struct {
	Err error
}

// --- Model ---

// Model is the Elm-pattern state. Methods return new Model values; the value
// type is intentional so accidental shared mutation is impossible.
type Model struct {
	cfg    Config
	styles styles

	// width is the last terminal width reported by a WindowSizeMsg; it drives
	// the input box width and the wrap width for printed messages. Zero until
	// the first WindowSizeMsg, so renderers fall back to a sane default.
	width int

	// Components. The scrollback is the terminal's own — there is no viewport;
	// completed messages are printed with tea.Println.
	input   textarea.Model
	spinner spinner.Model

	// State.
	messages []Message
	busy     bool
	lastErr  error
	quitting bool // set on the quit path so the final View() is blank (clean exit)

	// Input history (shell-style recall with Up/Down). submitted holds every
	// line the user sent; histIdx == len(submitted) means "not browsing";
	// histDraft preserves whatever was being typed when browsing started.
	submitted []string
	histIdx   int
	histDraft string

	// Cumulative usage for the status bar.
	tokensIn, tokensOut int
	costUSD             float64
}

// New constructs a Model with empty history and a configured text input.
func New(cfg Config) Model {
	ta := textarea.New()
	ta.Placeholder = "Type a message — Enter sends, Alt+Enter adds a line, /help lists commands"
	ta.ShowLineNumbers = false
	ta.CharLimit = 4096
	ta.SetHeight(1)
	// "▷ " on the first line, plain indent on continuation lines — a repeated
	// prompt glyph on every wrapped row reads as multiple inputs.
	ta.SetPromptFunc(2, func(lineIdx int) string {
		if lineIdx == 0 {
			return "▷ "
		}
		return "  "
	})
	// The default cursor-line background paints the whole row; inside a
	// bordered one-line input that looks like a rendering glitch.
	ta.FocusedStyle.CursorLine = lipgloss.NewStyle()
	// Enter is claimed by submit (see Update); newlines go through Alt+Enter
	// or Ctrl+J instead.
	ta.KeyMap.InsertNewline = key.NewBinding(
		key.WithKeys("alt+enter", "ctrl+j"),
		key.WithHelp("alt+enter", "insert newline"),
	)
	ta.Focus()

	sp := spinner.New()
	sp.Spinner = spinner.Dot

	return Model{
		cfg:     cfg,
		styles:  newStyles(),
		input:   ta,
		spinner: sp,
		busy:    cfg.StartBusy,
	}
}

// Init satisfies tea.Model. It prints any messages baked in with
// WithInitialMessages into the scrollback, and — if Config.AutoSubmit is set —
// schedules a one-shot autoSubmitMsg handled in Update as if the user typed it.
func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{textarea.Blink, m.spinner.Tick}
	if len(m.messages) > 0 {
		cmds = append(cmds, m.printMessages(m.messages...))
	}
	if m.cfg.AutoSubmit != "" {
		text, hidden := m.cfg.AutoSubmit, m.cfg.AutoSubmitHidden
		cmds = append(cmds, func() tea.Msg { return autoSubmitMsg{text: text, hidden: hidden} })
	}
	return tea.Batch(cmds...)
}

// Update handles one bubbletea event.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		// Inline mode: no layout budget to balance against the terminal
		// height — bubbletea sizes the footer frame itself. We only need the
		// width for the input box and for wrapping printed messages.
		m.width = msg.Width
		m.input.SetWidth(max(msg.Width-2, 20))
		return m, nil

	case tea.KeyMsg:
		switch {
		case msg.Type == tea.KeyEnter && !msg.Alt:
			return m.handleSubmit()
		case msg.Type == tea.KeyCtrlC, msg.Type == tea.KeyEsc:
			m.quitting = true
			return m, tea.Quit
		case msg.Type == tea.KeyUp:
			if next, handled := m.recallOlder(); handled {
				return next, nil
			}
		case msg.Type == tea.KeyDown:
			if next, handled := m.recallNewer(); handled {
				return next, nil
			}
		}

	case AgentMessageMsg:
		// Drop user-role echoes from the agent's OnMessage hook (we already
		// printed them locally in handleSubmit).
		if msg.Message.Role == "user" {
			return m, nil
		}
		dm := fromProviderMessage(msg.Message)
		m.messages = append(m.messages, dm)
		return m, m.printMessages(dm)

	case AgentDoneMsg:
		m.busy = false
		return m, nil

	case AgentErrorMsg:
		m.busy = false
		m.lastErr = msg.Err
		// The status line keeps the last error at a glance; the scrollback
		// keeps a permanent record.
		return m, tea.Println("\n" + m.renderError(msg.Err))

	case AgentUsageMsg:
		m.tokensIn += msg.InputTokens
		m.tokensOut += msg.OutputTokens
		m.costUSD += msg.CostUSD
		return m, nil

	case autoSubmitMsg:
		if msg.hidden {
			m.busy = true
			cmds := []tea.Cmd{m.spinner.Tick}
			if m.cfg.Dispatch != nil {
				cmds = append(cmds, m.cfg.Dispatch(msg.text))
			}
			return m, tea.Batch(cmds...)
		}
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

	// Forward everything else to the input so it gets keystrokes, blink ticks,
	// etc. The input grows/shrinks with its content.
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	m = m.syncInputHeight()
	return m, cmd
}

func (m Model) handleSubmit() (tea.Model, tea.Cmd) {
	text := strings.TrimSpace(m.input.Value())
	if text == "" {
		return m, nil
	}
	m.input.SetValue("")
	m = m.syncInputHeight()

	// Every submitted line is recallable with Up, slash commands included.
	m.submitted = append(m.submitted, text)
	m.histIdx = len(m.submitted)
	m.histDraft = ""

	if isSlashCommand(text) {
		return m.runSlashCommand(text)
	}

	if m.busy {
		return m, nil
	}

	userMsg := Message{Role: "user", Content: text}
	m.messages = append(m.messages, userMsg)
	m.busy = true

	cmds := []tea.Cmd{m.printMessages(userMsg), m.spinner.Tick}
	if m.cfg.Dispatch != nil {
		cmds = append(cmds, m.cfg.Dispatch(text))
	}
	return m, tea.Batch(cmds...)
}

// recallOlder implements the Up half of shell-style input history. It fires
// only when the cursor sits on the first line of the input AND the user is
// either already browsing or has typed nothing — so Up inside a multiline
// draft still moves the cursor instead of clobbering the text.
func (m Model) recallOlder() (Model, bool) {
	browsing := m.histIdx < len(m.submitted)
	if m.input.Line() != 0 || (!browsing && strings.TrimSpace(m.input.Value()) != "") {
		return m, false
	}
	if m.histIdx == 0 {
		return m, browsing // at the oldest entry: swallow the key while browsing
	}
	if !browsing {
		m.histDraft = m.input.Value()
	}
	m.histIdx--
	m.input.SetValue(m.submitted[m.histIdx])
	m = m.syncInputHeight()
	return m, true
}

// recallNewer is the Down half: only meaningful while browsing, with the
// cursor on the last line. Walking past the newest entry restores whatever
// was being typed when browsing started.
func (m Model) recallNewer() (Model, bool) {
	if m.histIdx >= len(m.submitted) || m.input.Line() != m.input.LineCount()-1 {
		return m, false
	}
	m.histIdx++
	if m.histIdx == len(m.submitted) {
		m.input.SetValue(m.histDraft)
	} else {
		m.input.SetValue(m.submitted[m.histIdx])
	}
	m = m.syncInputHeight()
	return m, true
}

// syncInputHeight grows and shrinks the input box with its content, capped at
// six rows. In inline mode this is all the layout there is: the footer frame
// tracks the input height automatically, so there is nothing else to recompute.
func (m Model) syncInputHeight() Model {
	h := min(m.input.LineCount(), 6)
	if h != m.input.Height() {
		m.input.SetHeight(h)
	}
	return m
}

// printMessages renders the given messages and returns a single tea.Println
// Cmd that writes them into the scrollback as one atomic block — one write
// keeps ordering deterministic (tea.Batch would race). A leading blank line
// separates each block from the previous scrollback content.
func (m Model) printMessages(msgs ...Message) tea.Cmd {
	if len(msgs) == 0 {
		return nil
	}
	blocks := make([]string, 0, len(msgs))
	for _, msg := range msgs {
		blocks = append(blocks, m.renderMessage(msg))
	}
	return tea.Println("\n" + strings.Join(blocks, "\n\n"))
}

// View renders the managed footer: the bordered input box and the status line.
// Everything else lives in the terminal scrollback (see printMessages).
func (m Model) View() string {
	if m.quitting {
		// Blank the footer on exit so only the scrollback remains — bubbletea
		// writes this View once more before it tears the renderer down.
		return ""
	}

	box := m.styles.inputBox
	if m.width > 0 {
		box = box.Width(m.width - 2) // border adds the remaining 2 columns
	}
	inputPane := box.Render(m.input.View())
	statusLine := m.styles.statusBar.Render(m.statusLine())

	return lipgloss.JoinVertical(lipgloss.Left, inputPane, statusLine)
}

func (m Model) renderMessage(msg Message) string {
	width := m.wrapWidth()
	switch msg.Role {
	case "user":
		return m.styles.userPrompt.Render("▶ you") + "\n" +
			m.styles.userBody.Render(indent(wrapText(msg.Content, width-2), "  "))
	case "agent":
		body := msg.Content
		if body == "" {
			body = "…"
		}
		header := m.styles.agentPrompt.Render("◆ argus")
		if msg.markdown {
			// glamour supplies its own left margin and wrapping — do NOT also
			// indent(2), or the body drifts right by four columns.
			if rendered, ok := renderMarkdown(body, width); ok {
				return header + "\n" + rendered
			}
		}
		return header + "\n" +
			m.styles.agentBody.Render(indent(wrapText(body, width-2), "  "))
	case "tool":
		header := m.styles.toolPrefix.Render(fmt.Sprintf("  ↳ %s", msg.Name))
		body := m.styles.toolBody.Render(indent(wrapText(truncate(msg.Content, 400), width-4), "    "))
		return header + "\n" + body
	case "system":
		return m.styles.systemPrefix.Render("• system") + "\n" +
			m.styles.systemBody.Render(indent(wrapText(msg.Content, width-2), "  "))
	default:
		return msg.Content
	}
}

// renderError formats an error for the scrollback (the status line carries a
// live copy separately).
func (m Model) renderError(err error) string {
	return m.styles.errorPrefix.Render("⚠ error") + "\n" +
		m.styles.errorBody.Render(indent(wrapText(err.Error(), m.wrapWidth()-2), "  "))
}

// renderMarkdown renders an agent body as markdown at the given wrap width.
// It reports ok=false on any failure so the caller can fall back to raw text.
func renderMarkdown(body string, width int) (string, bool) {
	if width < 1 {
		width = 1
	}
	r, err := glamour.NewTermRenderer(glamour.WithAutoStyle(), glamour.WithWordWrap(width))
	if err != nil {
		return "", false
	}
	out, err := r.Render(body)
	if err != nil {
		return "", false
	}
	// glamour brackets its output with blank lines; drop them so message
	// blocks stack tightly (printMessages controls inter-block spacing).
	return strings.Trim(out, "\n"), true
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

// wrapWidth is the column budget for wrapping printed messages: the last known
// terminal width, or a sane default before the first WindowSizeMsg (typical in
// tests, and while the very first frame is still pending).
func (m Model) wrapWidth() int {
	if m.width > 0 {
		return m.width
	}
	return 80
}

// wrapText hard-wraps s at width columns on word boundaries. Explicit newlines
// are preserved. Wrapping is done on the raw text (before styling) so the
// indent prefix stays flush; the terminal would wrap anyway, but doing it here
// keeps the indentation clean.
func wrapText(s string, width int) string {
	if width < 1 {
		width = 1
	}
	return ansi.Wordwrap(s, width, "")
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
			return Message{Role: "agent", Content: m.Content, markdown: true}
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
// Used to display a welcome/instructions message before the first user input;
// Init() prints them into the scrollback. Do NOT use this to inject "user"
// messages that should be processed by the agent — those must go through the
// Dispatch flow.
func (m Model) WithInitialMessages(msgs []Message) Model {
	m.messages = append([]Message{}, msgs...)
	return m
}

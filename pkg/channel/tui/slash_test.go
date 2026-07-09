package tui_test

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/argusappsec/argus/pkg/channel/tui"
)

// TestSlashCommand_HelpDoesNotInvokeAgent: typing `/help` and pressing Enter
// shows the help text inline AND does NOT mark the model busy (no agent
// dispatch happens). This is the central pedagogical point of slash commands:
// they're handled by the client, not by the LLM.
func TestSlashCommand_HelpDoesNotInvokeAgent(t *testing.T) {
	dispatched := false
	cfg := tui.Config{
		Dispatch: func(string) tea.Cmd {
			dispatched = true
			return nil
		},
	}
	m := tui.New(cfg).WithInput("/help")

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model := updated.(tui.Model)

	if dispatched {
		t.Error("slash commands must NOT reach the agent dispatcher")
	}
	if model.IsBusy() {
		t.Error("slash command should not mark model busy")
	}
	// Help lands in the scrollback (a system message), not the footer.
	if !historyContains(model, "/help") || !historyContains(model, "/clear") {
		t.Errorf("help output should list available commands; got:\n%+v", model.Messages())
	}
}

func TestSlashCommand_ClearWipesHistory(t *testing.T) {
	cfg := tui.Config{Dispatch: func(string) tea.Cmd { return nil }}
	m := tui.New(cfg).WithInput("hello")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})

	// /clear, even when followed by an AgentDoneMsg, should erase the history.
	updated, _ = updated.(tui.Model).Update(tui.AgentDoneMsg{})
	model := updated.(tui.Model)
	if len(model.Messages()) == 0 {
		t.Fatal("test setup failed: expected at least one message before /clear")
	}

	model = model.WithInput("/clear")
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(tui.Model)

	if len(model.Messages()) != 0 {
		t.Errorf("/clear should wipe history, got %d messages", len(model.Messages()))
	}
}

func TestSlashCommand_CostShowsCurrentSpend(t *testing.T) {
	m := tui.New(tui.Config{})
	updated, _ := m.Update(tui.AgentUsageMsg{InputTokens: 1000, OutputTokens: 200, CostUSD: 0.0123})
	model := updated.(tui.Model).WithInput("/cost")
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(tui.Model)

	// /cost prints a system line into the scrollback with the current spend.
	if !historyContains(model, "1000") || !historyContains(model, "200") {
		t.Errorf("/cost should report cumulative tokens; got:\n%+v", model.Messages())
	}
	if !historyContains(model, "0.0123") {
		t.Errorf("/cost should report cumulative USD; got:\n%+v", model.Messages())
	}
}

func TestSlashCommand_QuitReturnsQuitCmd(t *testing.T) {
	m := tui.New(tui.Config{}).WithInput("/quit")
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})

	if cmd == nil {
		t.Fatal("/quit must return a non-nil tea.Cmd (tea.Quit)")
	}
	// Calling the cmd returns the tea.QuitMsg sentinel.
	msg := cmd()
	if _, ok := msg.(tea.QuitMsg); !ok {
		t.Errorf("/quit cmd should produce tea.QuitMsg, got %T", msg)
	}
}

func TestSlashCommand_UnknownIsRejected(t *testing.T) {
	dispatched := false
	cfg := tui.Config{Dispatch: func(string) tea.Cmd { dispatched = true; return nil }}
	m := tui.New(cfg).WithInput("/nonsense")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model := updated.(tui.Model)

	if dispatched {
		t.Error("unknown slash command must not be dispatched to the agent")
	}
	if !historyContains(model, "unknown") || !historyContains(model, "/nonsense") {
		t.Errorf("unknown slash command should produce a system message naming it; got:\n%+v", model.Messages())
	}
}

func TestNonSlashTextStillReachesAgent(t *testing.T) {
	dispatched := false
	cfg := tui.Config{
		Dispatch: func(prompt string) tea.Cmd {
			dispatched = true
			if prompt != "review github.com/x/y" {
				t.Errorf("dispatch got prompt %q", prompt)
			}
			return nil
		},
	}
	m := tui.New(cfg).WithInput("review github.com/x/y")
	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})

	if !dispatched {
		t.Error("non-slash input must reach the dispatcher")
	}
}

// TestSlashCommand_SkillIsDispatchedToAgent: typing `/<skill>` for a skill
// that resolves loads its body and dispatches it to the agent (the ONE slash
// path that reaches the LLM), marking the model busy and showing a notice.
func TestSlashCommand_SkillIsDispatchedToAgent(t *testing.T) {
	var dispatched string
	cfg := tui.Config{
		Dispatch: func(p string) tea.Cmd { dispatched = p; return nil },
		ResolveSkill: func(name string) (string, bool) {
			if name == "pr-check" {
				return "Use the \"pr-check\" skill. Follow:\n\nDo the thing.", true
			}
			return "", false
		},
	}
	m := tui.New(cfg).WithInput("/pr-check")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model := updated.(tui.Model)

	if !strings.Contains(dispatched, "Do the thing") {
		t.Errorf("a resolved skill must be dispatched with its body; got %q", dispatched)
	}
	if !model.IsBusy() {
		t.Error("invoking a skill should mark the model busy")
	}
	if !historyContains(model, "invoking skill") {
		t.Errorf("expected an 'invoking skill' notice; got:\n%+v", model.Messages())
	}
}

// TestSlashCommand_UnknownSkillIsRejected: a `/<name>` that resolves to no
// skill must not reach the agent and is reported as unknown.
func TestSlashCommand_UnknownSkillIsRejected(t *testing.T) {
	dispatched := false
	cfg := tui.Config{
		Dispatch:     func(string) tea.Cmd { dispatched = true; return nil },
		ResolveSkill: func(string) (string, bool) { return "", false },
	}
	m := tui.New(cfg).WithInput("/does-not-exist")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model := updated.(tui.Model)

	if dispatched {
		t.Error("an unresolved skill slash command must not be dispatched")
	}
	if !historyContains(model, "unknown") {
		t.Errorf("unresolved skill should be reported as unknown; got:\n%+v", model.Messages())
	}
}

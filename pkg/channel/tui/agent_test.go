package tui_test

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/redcarbon-dev/argus/pkg/channel/tui"
	"github.com/redcarbon-dev/argus/pkg/provider"
)

// TestModel_AgentMessageAppendsToHistory: when the agent dispatcher sends an
// AgentMessageMsg back into the TUI (via tea.Program.Send), the new message
// is appended to history with the appropriate role.
func TestModel_AgentMessageAppendsToHistory(t *testing.T) {
	m := tui.New(tui.Config{})

	// Simulate a streamed agent turn that includes a tool call.
	updated, _ := m.Update(tui.AgentMessageMsg{
		Message: provider.Message{
			Role: "model",
			ToolCalls: []provider.ToolCall{
				{ID: "c1", Name: "list_files", Args: map[string]any{}},
			},
		},
	})
	model := updated.(tui.Model)

	msgs := model.Messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message after agent emission, got %d", len(msgs))
	}
	if msgs[0].Role != "agent" {
		t.Errorf("model emission should be displayed with role=agent, got %q", msgs[0].Role)
	}
}

// TestModel_ToolResultAppendsAsTool: tool result messages from the agent are
// rendered with role=tool and the tool's name attached.
func TestModel_ToolResultAppendsAsTool(t *testing.T) {
	m := tui.New(tui.Config{})

	updated, _ := m.Update(tui.AgentMessageMsg{
		Message: provider.Message{
			Role: "tool",
			ToolResults: []provider.ToolResult{
				{CallID: "c1", Name: "list_files", Output: "main.go\nREADME.md"},
			},
		},
	})
	model := updated.(tui.Model)

	msgs := model.Messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].Role != "tool" {
		t.Errorf("tool result should display with role=tool, got %q", msgs[0].Role)
	}
	if msgs[0].Name != "list_files" {
		t.Errorf("tool name = %q, want list_files", msgs[0].Name)
	}
}

func TestModel_SubmitMarksBusy(t *testing.T) {
	m := tui.New(tui.Config{})
	if m.IsBusy() {
		t.Error("fresh model should not be busy")
	}
	m = m.WithInput("hi")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model := updated.(tui.Model)
	if !model.IsBusy() {
		t.Error("model should be busy after submit while agent runs")
	}
}

func TestModel_SubmitWhileBusyIsIgnored(t *testing.T) {
	m := tui.New(tui.Config{})
	m = m.WithInput("first")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model := updated.(tui.Model)
	if !model.IsBusy() {
		t.Fatal("model should be busy after first submit")
	}

	// Try to submit a second message while busy.
	model = model.WithInput("second")
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(tui.Model)

	if len(model.Messages()) != 1 {
		t.Errorf("second submit should be ignored while busy; got %d messages", len(model.Messages()))
	}
}

func TestModel_AgentDoneClearsBusy(t *testing.T) {
	m := tui.New(tui.Config{})
	m = m.WithInput("hi")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model := updated.(tui.Model)

	updated, _ = model.Update(tui.AgentDoneMsg{})
	model = updated.(tui.Model)

	if model.IsBusy() {
		t.Error("model should be idle after AgentDoneMsg")
	}
}

func TestModel_AgentErrorClearsBusyAndShowsError(t *testing.T) {
	m := tui.New(tui.Config{})
	m = m.WithInput("hi")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model := updated.(tui.Model)

	updated, _ = model.Update(tui.AgentErrorMsg{Err: errExample{"boom"}})
	model = updated.(tui.Model)

	if model.IsBusy() {
		t.Error("model should be idle after AgentErrorMsg")
	}
	view := model.View()
	if !contains(view, "boom") {
		t.Errorf("view should show the error message; got:\n%s", view)
	}
}

type errExample struct{ msg string }

func (e errExample) Error() string { return e.msg }

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

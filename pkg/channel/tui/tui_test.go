package tui_test

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/redcarbon-dev/argus/pkg/channel/tui"
)

// TestModel_TracerSubmitsTextToHistory: when the user types text and presses
// Enter, the text is added to the chat history as a user-role message and the
// input box is cleared.
func TestModel_TracerSubmitsTextToHistory(t *testing.T) {
	m := tui.New(tui.Config{})
	m = m.WithInput("hello")

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model := updated.(tui.Model)

	if model.InputValue() != "" {
		t.Errorf("input not cleared, got %q", model.InputValue())
	}

	msgs := model.Messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message after submit, got %d: %+v", len(msgs), msgs)
	}
	if msgs[0].Role != "user" || msgs[0].Content != "hello" {
		t.Errorf("first message = %+v, want user/hello", msgs[0])
	}
}

func TestModel_EmptyInputDoesNotSubmit(t *testing.T) {
	m := tui.New(tui.Config{})
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model := updated.(tui.Model)
	if len(model.Messages()) != 0 {
		t.Errorf("empty submit should not add to history, got %d messages", len(model.Messages()))
	}
}

func TestModel_ViewIncludesHistoryAndInput(t *testing.T) {
	m := tui.New(tui.Config{})
	m = m.WithInput("hi")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model := updated.(tui.Model)

	view := model.View()
	if !strings.Contains(view, "hi") {
		t.Errorf("view missing submitted message %q:\n%s", "hi", view)
	}
}

// TestModel_WithInitialMessages: pre-populating the history at construction
// (used by `argus init` for the welcome banner) must NOT trigger the
// dispatcher. This is the regression guard for a panic where the init flow
// auto-submitted the welcome text before the *tea.Program had been wired up.
func TestModel_WithInitialMessages(t *testing.T) {
	dispatched := false
	cfg := tui.Config{Dispatch: func(string) tea.Cmd {
		dispatched = true
		return nil
	}}
	m := tui.New(cfg).WithInitialMessages([]tui.Message{
		{Role: "system", Content: "welcome"},
	})

	if dispatched {
		t.Error("WithInitialMessages must NOT invoke the dispatcher")
	}
	if got := m.Messages(); len(got) != 1 || got[0].Content != "welcome" {
		t.Errorf("messages = %+v, want one welcome system message", got)
	}
	if m.IsBusy() {
		t.Error("WithInitialMessages must NOT mark the model busy")
	}
}

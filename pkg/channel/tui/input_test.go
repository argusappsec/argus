package tui_test

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/argusappsec/argus/pkg/channel/tui"
)

func pressKey(t *testing.T, m tui.Model, k tea.KeyMsg) tui.Model {
	t.Helper()
	updated, _ := m.Update(k)
	return updated.(tui.Model)
}

// TestModel_MultilineSubmit: a value containing newlines (typed via
// Alt+Enter or pasted) is submitted whole — the textarea input must not
// mangle or split it.
func TestModel_MultilineSubmit(t *testing.T) {
	m := tui.New(tui.Config{})
	m = m.WithInput("first line\nsecond line")

	m = pressKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})

	msgs := m.Messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d: %+v", len(msgs), msgs)
	}
	if msgs[0].Content != "first line\nsecond line" {
		t.Errorf("multiline content mangled: %q", msgs[0].Content)
	}
}

// TestModel_AltEnterInsertsNewline: Alt+Enter must NOT submit — it reaches
// the textarea, which inserts a newline instead.
func TestModel_AltEnterInsertsNewline(t *testing.T) {
	m := tui.New(tui.Config{})
	m = m.WithInput("first")

	m = pressKey(t, m, tea.KeyMsg{Type: tea.KeyEnter, Alt: true})

	if got := m.Messages(); len(got) != 0 {
		t.Fatalf("alt+enter must not submit, got %+v", got)
	}
	if m.InputValue() != "first\n" {
		t.Errorf("alt+enter should insert a newline, input = %q", m.InputValue())
	}
}

// TestModel_HistoryRecall: Up walks back through submitted lines, Down walks
// forward and finally restores the draft that was being typed.
func TestModel_HistoryRecall(t *testing.T) {
	m := tui.New(tui.Config{})
	for _, s := range []string{"first", "second"} {
		m = m.WithInput(s)
		m = pressKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	}
	m = m.WithInput("draft")
	// A non-empty fresh draft must NOT be clobbered by Up (cursor movement).
	m = pressKey(t, m, tea.KeyMsg{Type: tea.KeyUp})
	if m.InputValue() != "draft" {
		t.Fatalf("up over a fresh draft must not recall, input = %q", m.InputValue())
	}

	m = m.WithInput("")
	m = pressKey(t, m, tea.KeyMsg{Type: tea.KeyUp})
	if m.InputValue() != "second" {
		t.Fatalf("first Up should recall newest, got %q", m.InputValue())
	}
	m = pressKey(t, m, tea.KeyMsg{Type: tea.KeyUp})
	if m.InputValue() != "first" {
		t.Fatalf("second Up should recall oldest, got %q", m.InputValue())
	}
	// One more Up at the oldest entry: stays put.
	m = pressKey(t, m, tea.KeyMsg{Type: tea.KeyUp})
	if m.InputValue() != "first" {
		t.Fatalf("Up at oldest should stay, got %q", m.InputValue())
	}

	m = pressKey(t, m, tea.KeyMsg{Type: tea.KeyDown})
	if m.InputValue() != "second" {
		t.Fatalf("Down should walk forward, got %q", m.InputValue())
	}
	// Walking past the newest entry restores the (empty) draft.
	m = pressKey(t, m, tea.KeyMsg{Type: tea.KeyDown})
	if m.InputValue() != "" {
		t.Fatalf("Down past newest should restore draft, got %q", m.InputValue())
	}
}

// TestModel_InputHeightTracksSoftWrap: a single long logical line wraps into
// several display rows; the input box must grow to show them all, not sit at
// one row displaying only the last wrapped row (LineCount counts logical
// lines, so height math must be soft-wrap aware).
func TestModel_InputHeightTracksSoftWrap(t *testing.T) {
	m := tui.New(tui.Config{})
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 40, Height: 24})
	m = updated.(tui.Model)

	baseline := lipgloss.Height(m.View())

	// ~120 columns of text in a 40-column terminal → at least 3 wrapped rows.
	m = m.WithInput(strings.Repeat("parola ", 17))

	grown := lipgloss.Height(m.View())
	if grown < baseline+2 {
		t.Errorf("footer height %d after soft-wrapped input, want >= %d (input box must grow with wrapped rows)", grown, baseline+2)
	}

	// Clearing via submit shrinks it back.
	m = pressKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if h := lipgloss.Height(m.View()); h != baseline {
		t.Errorf("footer height %d after submit, want baseline %d", h, baseline)
	}
}

// TestModel_ViewRendersWithGrownInput: after a real resize, growing the input
// past one line (Alt+Enter) must relayout and render without panicking — the
// regression guard for the dynamic input-height / viewport-height math.
func TestModel_ViewRendersWithGrownInput(t *testing.T) {
	m := tui.New(tui.Config{})
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = updated.(tui.Model)

	m = m.WithInput("uno")
	m = pressKey(t, m, tea.KeyMsg{Type: tea.KeyEnter, Alt: true})
	m = pressKey(t, m, tea.KeyMsg{Type: tea.KeyEnter, Alt: true})

	view := m.View()
	if view == "" {
		t.Fatal("empty view after resize")
	}
	if !strings.Contains(view, "tokens in:") {
		t.Errorf("status line missing from view:\n%s", view)
	}
}

// TestModel_RecalledEntryIsEditableAndResubmittable: recall an entry, submit
// it again, and the history keeps both submissions.
func TestModel_RecalledEntryResubmits(t *testing.T) {
	m := tui.New(tui.Config{})
	m = m.WithInput("only")
	m = pressKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	// The first submit leaves the model busy; complete that run before
	// resubmitting, as a real agent turn would.
	updated, _ := m.Update(tui.AgentDoneMsg{})
	m = updated.(tui.Model)

	m = pressKey(t, m, tea.KeyMsg{Type: tea.KeyUp})
	if m.InputValue() != "only" {
		t.Fatalf("recall failed, got %q", m.InputValue())
	}
	m = pressKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})

	msgs := m.Messages()
	if len(msgs) != 2 || msgs[1].Content != "only" {
		t.Errorf("resubmit of recalled entry failed: %+v", msgs)
	}
}

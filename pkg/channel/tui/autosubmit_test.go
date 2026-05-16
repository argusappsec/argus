package tui_test

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/redcarbon-dev/argus/pkg/channel/tui"
)

// TestAutoSubmit_FiresOnInit: when Config.AutoSubmit is set, Init() returns
// a Cmd that resolves to a synthetic submission. Driving that submission
// through Update() should produce a user message in history and mark the
// model busy (i.e. an agent run has started), exactly as if the user had
// typed and pressed Enter.
func TestAutoSubmit_FiresOnInit(t *testing.T) {
	dispatchedWith := ""
	cfg := tui.Config{
		Dispatch: func(s string) tea.Cmd {
			dispatchedWith = s
			return nil
		},
		AutoSubmit: "review github.com/redcarbon-dev/argus",
	}
	m := tui.New(cfg)

	cmd := m.Init()
	if cmd == nil {
		t.Fatal("Init() returned nil Cmd; expected a batch including the AutoSubmit one-shot")
	}

	// Pump every Cmd produced by Init() through Update(). Exactly one of them
	// should produce a submission (the autoSubmitMsg); the others (Blink,
	// Tick) are harmless.
	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	if !ok {
		batch = tea.BatchMsg{func() tea.Msg { return msg }}
	}
	for _, c := range batch {
		if c == nil {
			continue
		}
		updated, _ := m.Update(c())
		m = updated.(tui.Model)
	}

	if dispatchedWith != "review github.com/redcarbon-dev/argus" {
		t.Errorf("dispatch should receive the AutoSubmit text, got %q", dispatchedWith)
	}
	if !m.IsBusy() {
		t.Error("auto-submit should mark the model busy (agent run kicked off)")
	}
	msgs := m.Messages()
	if len(msgs) != 1 || msgs[0].Role != "user" || msgs[0].Content != "review github.com/redcarbon-dev/argus" {
		t.Errorf("history after AutoSubmit = %+v", msgs)
	}
}

func TestAutoSubmit_EmptyIsNoOp(t *testing.T) {
	m := tui.New(tui.Config{Dispatch: func(string) tea.Cmd { return nil }})
	cmd := m.Init()
	if cmd == nil {
		return
	}
	msg := cmd()
	if bm, ok := msg.(tea.BatchMsg); ok {
		for _, c := range bm {
			if c == nil {
				continue
			}
			updated, _ := m.Update(c())
			m = updated.(tui.Model)
		}
	}
	if m.IsBusy() {
		t.Error("empty AutoSubmit must not mark the model busy")
	}
	if len(m.Messages()) != 0 {
		t.Errorf("empty AutoSubmit must not add to history, got %d msgs", len(m.Messages()))
	}
}

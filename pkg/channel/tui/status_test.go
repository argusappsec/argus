package tui_test

import (
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/channel/tui"
)

func TestModel_UsageAccumulates(t *testing.T) {
	m := tui.New(tui.Config{})

	if got := m.TokensIn(); got != 0 {
		t.Errorf("fresh tokens_in = %d, want 0", got)
	}

	updated, _ := m.Update(tui.AgentUsageMsg{InputTokens: 100, OutputTokens: 50})
	updated, _ = updated.(tui.Model).Update(tui.AgentUsageMsg{InputTokens: 200, OutputTokens: 30})
	model := updated.(tui.Model)

	if model.TokensIn() != 300 {
		t.Errorf("tokens_in = %d, want 300", model.TokensIn())
	}
	if model.TokensOut() != 80 {
		t.Errorf("tokens_out = %d, want 80", model.TokensOut())
	}
}

func TestModel_ViewIncludesStatusBar(t *testing.T) {
	m := tui.New(tui.Config{})
	updated, _ := m.Update(tui.AgentUsageMsg{InputTokens: 1234, OutputTokens: 567})
	model := updated.(tui.Model)

	view := model.View()

	if !strings.Contains(view, "1234") {
		t.Errorf("status bar missing input tokens; view:\n%s", view)
	}
	if !strings.Contains(view, "567") {
		t.Errorf("status bar missing output tokens; view:\n%s", view)
	}
	// Never a dollar figure Argus cannot compute for the operator's endpoint:
	// a cost cell reading $0.0000 on a paid endpoint is worse than no cell.
	if strings.Contains(view, "$") {
		t.Errorf("status bar shows a currency figure; view:\n%s", view)
	}
}

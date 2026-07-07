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

	updated, _ := m.Update(tui.AgentUsageMsg{InputTokens: 100, OutputTokens: 50, CostUSD: 0.01})
	updated, _ = updated.(tui.Model).Update(tui.AgentUsageMsg{InputTokens: 200, OutputTokens: 30, CostUSD: 0.02})
	model := updated.(tui.Model)

	if model.TokensIn() != 300 {
		t.Errorf("tokens_in = %d, want 300", model.TokensIn())
	}
	if model.TokensOut() != 80 {
		t.Errorf("tokens_out = %d, want 80", model.TokensOut())
	}
	if model.CostUSD() != 0.03 {
		t.Errorf("cost_usd = %v, want 0.03", model.CostUSD())
	}
}

func TestModel_ViewIncludesStatusBar(t *testing.T) {
	m := tui.New(tui.Config{})
	updated, _ := m.Update(tui.AgentUsageMsg{InputTokens: 1234, OutputTokens: 567, CostUSD: 0.0042})
	model := updated.(tui.Model)

	view := model.View()

	if !strings.Contains(view, "1234") {
		t.Errorf("status bar missing input tokens; view:\n%s", view)
	}
	if !strings.Contains(view, "567") {
		t.Errorf("status bar missing output tokens; view:\n%s", view)
	}
	if !strings.Contains(view, "0.00") {
		// 0.0042 should render as $0.0042 or similar — at minimum we expect 0.00 prefix
		t.Errorf("status bar missing cost; view:\n%s", view)
	}
}

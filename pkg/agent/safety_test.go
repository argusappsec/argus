package agent_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/agent"
	"github.com/redcarbon-dev/argus/pkg/audit"
	"github.com/redcarbon-dev/argus/pkg/provider"
	"github.com/redcarbon-dev/argus/pkg/report"
)

// loopingProvider never calls finalize_report — it always asks to add another finding.
type loopingProvider struct{ calls int }

func (l *loopingProvider) Generate(_ context.Context, _ provider.Request) (provider.Response, error) {
	l.calls++
	return provider.Response{
		ToolCalls: []provider.ToolCall{{
			ID:   "x",
			Name: "add_finding",
			Args: map[string]any{
				"severity": "low",
				"rule_id":  "LOOP",
				"snippet":  "x",
			},
		}},
		Usage: provider.Usage{InputTokens: 1, OutputTokens: 1},
	}, nil
}

func TestAgentRunStopsOnMaxTurns(t *testing.T) {
	tmp := t.TempDir()
	aud, _ := audit.NewLogger(filepath.Join(tmp, "audit.jsonl"))
	defer aud.Close()
	rw := report.NewWriter(filepath.Join(tmp, "reports"))

	lp := &loopingProvider{}
	ag := agent.New(agent.Options{
		Provider: lp,
		Audit:    aud,
		Reports:  rw,
		MaxTurns: 5,
	})

	_, err := ag.Run(context.Background(), agent.Target{Repo: "github.com/x/y", SHA: "deadbeef"})
	if !errors.Is(err, agent.ErrMaxTurnsExceeded) {
		t.Fatalf("err = %v, want ErrMaxTurnsExceeded", err)
	}
	if lp.calls != 5 {
		t.Errorf("provider calls = %d, want 5", lp.calls)
	}
}

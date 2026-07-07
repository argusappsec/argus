package agent_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/argusappsec/argus/pkg/agent"
	"github.com/argusappsec/argus/pkg/audit"
	"github.com/argusappsec/argus/pkg/provider"
	"github.com/argusappsec/argus/pkg/report"
)

// TestAgentEmitsOnMessageForEveryTurn: when Options.OnMessage is set, the
// agent invokes it for every message added to the running history (user seed,
// model turns, tool results). This is the streaming hook the TUI uses to
// render the conversation as it unfolds.
func TestAgentEmitsOnMessageForEveryTurn(t *testing.T) {
	tmp := t.TempDir()

	fp := &scriptedProvider{
		responses: []provider.Response{
			{ToolCalls: []provider.ToolCall{{
				ID:   "c1",
				Name: "add_finding",
				Args: map[string]any{"severity": "high", "rule_id": "R1", "snippet": "x"},
			}}},
			{ToolCalls: []provider.ToolCall{{
				ID:   "c2",
				Name: "finalize_report",
				Args: map[string]any{"summary": "ok"},
			}}},
		},
	}

	aud, _ := audit.NewLogger(filepath.Join(tmp, "audit.jsonl"))
	defer aud.Close()
	rw := report.NewWriter(filepath.Join(tmp, "reports"))

	var (
		mu       sync.Mutex
		captured []provider.Message
	)
	ag := agent.New(agent.Options{
		Provider: fp,
		Audit:    aud,
		Reports:  rw,
		OnMessage: func(m provider.Message) {
			mu.Lock()
			captured = append(captured, m)
			mu.Unlock()
		},
	})

	if _, err := ag.Run(context.Background(), agent.Target{Repo: "r", SHA: "s"}); err != nil {
		t.Fatalf("run: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(captured) < 3 {
		t.Fatalf("expected at least 3 OnMessage calls (user seed + model + tool result), got %d", len(captured))
	}
	if captured[0].Role != "user" {
		t.Errorf("first emitted message role = %q, want user", captured[0].Role)
	}

	sawModel := false
	sawTool := false
	for _, m := range captured {
		if m.Role == "model" && len(m.ToolCalls) > 0 {
			sawModel = true
		}
		if m.Role == "tool" && len(m.ToolResults) > 0 {
			sawTool = true
		}
	}
	if !sawModel {
		t.Error("no model message with tool calls was emitted")
	}
	if !sawTool {
		t.Error("no tool result message was emitted")
	}
}

func TestAgentOnMessageIsOptional(t *testing.T) {
	// No OnMessage set: agent must run without panic.
	tmp := t.TempDir()
	fp := &scriptedProvider{
		responses: []provider.Response{
			{ToolCalls: []provider.ToolCall{{ID: "c", Name: "finalize_report", Args: map[string]any{"summary": "ok"}}}},
		},
	}
	aud, _ := audit.NewLogger(filepath.Join(tmp, "audit.jsonl"))
	defer aud.Close()
	rw := report.NewWriter(filepath.Join(tmp, "reports"))
	ag := agent.New(agent.Options{Provider: fp, Audit: aud, Reports: rw})
	if _, err := ag.Run(context.Background(), agent.Target{Repo: "r", SHA: "s"}); err != nil {
		t.Fatalf("run: %v", err)
	}
}

package agent_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/agent"
	"github.com/redcarbon-dev/argus/pkg/audit"
	"github.com/redcarbon-dev/argus/pkg/provider"
)

// TestAgentTextOnlyResponseExitsNaturally guards the chat-style behavior:
// when the model emits a turn with no tool calls (just text), the agent loop
// exits cleanly rather than asking the model another turn. Without this, the
// loop spins on empty responses until max-turns trips — wasting tokens and
// producing the "argus: …" spam the user reported.
func TestAgentTextOnlyResponseExitsNaturally(t *testing.T) {
	tmp := t.TempDir()
	fp := &scriptedProvider{
		responses: []provider.Response{
			{Text: "Hello! What is your company's name?", Usage: provider.Usage{InputTokens: 10, OutputTokens: 8}},
			// If the agent kept looping, it would consume this second response.
			// Test passes if we never reach it.
			{Text: "I should never be called.", Usage: provider.Usage{InputTokens: 20, OutputTokens: 5}},
		},
	}

	aud, _ := audit.NewLogger(filepath.Join(tmp, "audit.jsonl"))
	defer aud.Close()

	ag := agent.New(agent.Options{
		Provider: fp,
		Audit:    aud,
		MaxTurns: 10,
	})

	if _, err := ag.Run(context.Background(), agent.Target{Repo: "r", SHA: "s"}); err != nil {
		t.Fatalf("run: %v", err)
	}

	if fp.idx != 1 {
		t.Errorf("expected exactly 1 LLM call before natural exit, got %d", fp.idx)
	}
}

// TestAgentToolCallsThenTextExitsAfterText: a more realistic chat round —
// the model first calls a tool, gets the result, then emits final text.
// Should terminate after the text emission.
func TestAgentToolCallsThenTextExitsAfterText(t *testing.T) {
	tmp := t.TempDir()
	fp := &scriptedProvider{
		responses: []provider.Response{
			{ToolCalls: []provider.ToolCall{{ID: "c1", Name: "add_finding", Args: map[string]any{"severity": "low", "rule_id": "X", "snippet": "x"}}}},
			{Text: "Done — found 1 issue. What next?", Usage: provider.Usage{InputTokens: 50, OutputTokens: 10}},
			{Text: "should not run", Usage: provider.Usage{InputTokens: 99, OutputTokens: 99}},
		},
	}
	aud, _ := audit.NewLogger(filepath.Join(tmp, "audit.jsonl"))
	defer aud.Close()

	ag := agent.New(agent.Options{Provider: fp, Audit: aud, MaxTurns: 10})

	if _, err := ag.Run(context.Background(), agent.Target{Repo: "r", SHA: "s"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if fp.idx != 2 {
		t.Errorf("expected exactly 2 LLM calls (tool turn + text turn), got %d", fp.idx)
	}
}

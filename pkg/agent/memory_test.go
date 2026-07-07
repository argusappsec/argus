package agent_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/agent"
	"github.com/argusappsec/argus/pkg/audit"
	"github.com/argusappsec/argus/pkg/provider"
	"github.com/argusappsec/argus/pkg/report"
	"github.com/argusappsec/argus/pkg/soul"
)

// TestAgentInjectsMemoryIntoSystemPrompt: when Options.Memory is non-empty,
// the agent appends it to the system prompt under a "# Memory" header so the
// model remembers what prior sessions curated.
func TestAgentInjectsMemoryIntoSystemPrompt(t *testing.T) {
	tmp := t.TempDir()
	op := &observingProvider{
		responses: []provider.Response{
			{ToolCalls: []provider.ToolCall{{ID: "c", Name: "finalize_report", Args: map[string]any{"summary": "ok"}}}},
		},
	}
	aud, _ := audit.NewLogger(filepath.Join(tmp, "audit.jsonl"))
	defer aud.Close()
	rw := report.NewWriter(filepath.Join(tmp, "reports"))

	ag := agent.New(agent.Options{
		Provider: op,
		Audit:    aud,
		Reports:  rw,
		Soul:     &soul.Soul{Company: "Acme", Persona: "Be terse."},
		Memory:   "- Operator prefers HIGH+ only.\n- Rule X-001 is FP on test files.",
	})

	if _, err := ag.Run(context.Background(), agent.Target{Repo: "r", SHA: "s"}); err != nil {
		t.Fatalf("run: %v", err)
	}

	sys := op.requests[0].System
	if !strings.Contains(sys, "Acme") {
		t.Errorf("system prompt should still include SOUL identity: %q", sys)
	}
	if !strings.Contains(sys, "# Memory") {
		t.Errorf("system prompt should include the # Memory section header: %q", sys)
	}
	if !strings.Contains(sys, "Rule X-001 is FP") {
		t.Errorf("system prompt should include MEMORY content: %q", sys)
	}
}

// TestAgentMemoryWithoutSoul: Memory alone (no SOUL) still surfaces under
// the Memory header. Useful for users who haven't run init yet but already
// have a curator-written MEMORY.md.
func TestAgentMemoryWithoutSoul(t *testing.T) {
	tmp := t.TempDir()
	op := &observingProvider{
		responses: []provider.Response{
			{ToolCalls: []provider.ToolCall{{ID: "c", Name: "finalize_report", Args: map[string]any{"summary": "ok"}}}},
		},
	}
	aud, _ := audit.NewLogger(filepath.Join(tmp, "audit.jsonl"))
	defer aud.Close()
	rw := report.NewWriter(filepath.Join(tmp, "reports"))

	ag := agent.New(agent.Options{
		Provider: op,
		Audit:    aud,
		Reports:  rw,
		Memory:   "Important: never delete user data.",
	})
	if _, err := ag.Run(context.Background(), agent.Target{Repo: "r", SHA: "s"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	sys := op.requests[0].System
	if !strings.Contains(sys, "never delete user data") {
		t.Errorf("memory should reach the system prompt even without SOUL: %q", sys)
	}
}

func TestAgentEmptyMemoryIsNoOp(t *testing.T) {
	tmp := t.TempDir()
	op := &observingProvider{
		responses: []provider.Response{
			{ToolCalls: []provider.ToolCall{{ID: "c", Name: "finalize_report", Args: map[string]any{"summary": "ok"}}}},
		},
	}
	aud, _ := audit.NewLogger(filepath.Join(tmp, "audit.jsonl"))
	defer aud.Close()
	rw := report.NewWriter(filepath.Join(tmp, "reports"))

	ag := agent.New(agent.Options{
		Provider: op,
		Audit:    aud,
		Reports:  rw,
		Memory:   "",
	})
	if _, err := ag.Run(context.Background(), agent.Target{Repo: "r", SHA: "s"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(op.requests[0].System, "# Memory") {
		t.Errorf("empty memory should not produce a Memory section: %q", op.requests[0].System)
	}
}

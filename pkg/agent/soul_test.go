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

func TestAgentInjectsSoulIntoSystemPrompt(t *testing.T) {
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
		Soul: &soul.Soul{
			Company: "Acme",
			Persona: "You are technical and terse.",
		},
	})

	if _, err := ag.Run(context.Background(), agent.Target{Repo: "r", SHA: "s"}); err != nil {
		t.Fatalf("run: %v", err)
	}

	if len(op.requests) == 0 {
		t.Fatal("no requests recorded")
	}
	system := op.requests[0].System
	if !strings.Contains(system, "Acme") {
		t.Errorf("system prompt missing company: %q", system)
	}
	if !strings.Contains(system, "technical and terse") {
		t.Errorf("system prompt missing persona: %q", system)
	}
}

func TestAgentInjectsPersonaNameIntoSystemPrompt(t *testing.T) {
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
		Provider:    op,
		Audit:       aud,
		Reports:     rw,
		PersonaName: "Ercole",
		Soul:        &soul.Soul{Company: "Acme"},
	})

	if _, err := ag.Run(context.Background(), agent.Target{Repo: "r", SHA: "s"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	system := op.requests[0].System
	if !strings.Contains(system, "Ercole") {
		t.Errorf("system prompt missing persona name: %q", system)
	}
	// The SOUL still stacks after the persona line.
	if !strings.Contains(system, "Acme") {
		t.Errorf("system prompt missing company: %q", system)
	}
}

func TestAgentNoPersonaLeavesPromptUnchanged(t *testing.T) {
	tmp := t.TempDir()
	op := &observingProvider{
		responses: []provider.Response{
			{ToolCalls: []provider.ToolCall{{ID: "c", Name: "finalize_report", Args: map[string]any{"summary": "ok"}}}},
		},
	}
	aud, _ := audit.NewLogger(filepath.Join(tmp, "audit.jsonl"))
	defer aud.Close()
	rw := report.NewWriter(filepath.Join(tmp, "reports"))

	ag := agent.New(agent.Options{Provider: op, Audit: aud, Reports: rw})
	if _, err := ag.Run(context.Background(), agent.Target{Repo: "r", SHA: "s"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if op.requests[0].System != "" {
		t.Errorf("no soul and no persona should yield empty system, got %q", op.requests[0].System)
	}
}

func TestAgentNoSoulMeansEmptySystemPrompt(t *testing.T) {
	tmp := t.TempDir()
	op := &observingProvider{
		responses: []provider.Response{
			{ToolCalls: []provider.ToolCall{{ID: "c", Name: "finalize_report", Args: map[string]any{"summary": "ok"}}}},
		},
	}
	aud, _ := audit.NewLogger(filepath.Join(tmp, "audit.jsonl"))
	defer aud.Close()
	rw := report.NewWriter(filepath.Join(tmp, "reports"))

	ag := agent.New(agent.Options{Provider: op, Audit: aud, Reports: rw})
	if _, err := ag.Run(context.Background(), agent.Target{Repo: "r", SHA: "s"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if op.requests[0].System != "" {
		t.Errorf("no soul should yield empty system, got %q", op.requests[0].System)
	}
}

package agent_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/agent"
	"github.com/redcarbon-dev/argus/pkg/audit"
	"github.com/redcarbon-dev/argus/pkg/provider"
	"github.com/redcarbon-dev/argus/pkg/report"
	"github.com/redcarbon-dev/argus/pkg/tool"
)

// observingProvider records every Request it gets so we can assert the agent
// fed tool results back on the next turn.
type observingProvider struct {
	responses []provider.Response
	requests  []provider.Request
	idx       int
}

func (o *observingProvider) Generate(_ context.Context, req provider.Request) (provider.Response, error) {
	o.requests = append(o.requests, req)
	r := o.responses[o.idx]
	o.idx++
	return r, nil
}

func TestAgentDispatchesEnvTool(t *testing.T) {
	tmp := t.TempDir()
	repoDir := filepath.Join(tmp, "checkout")
	if err := os.MkdirAll(filepath.Join(repoDir, "pkg"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	op := &observingProvider{
		responses: []provider.Response{
			{ToolCalls: []provider.ToolCall{{ID: "c1", Name: "list_files", Args: map[string]any{}}}},
			{ToolCalls: []provider.ToolCall{{ID: "c2", Name: "finalize_report", Args: map[string]any{"summary": "ok"}}}},
		},
	}

	aud, _ := audit.NewLogger(filepath.Join(tmp, "audit.jsonl"))
	defer aud.Close()
	rw := report.NewWriter(filepath.Join(tmp, "reports"))

	reg := tool.NewRegistry()
	reg.Register(tool.NewListFiles(repoDir))

	ag := agent.New(agent.Options{
		Provider: op,
		Audit:    aud,
		Reports:  rw,
		Tools:    reg,
	})

	if _, err := ag.Run(context.Background(), agent.Target{Repo: "github.com/x/y", SHA: "sha1", Path: repoDir}); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Turn 2 must have received the list_files output as a tool result.
	if len(op.requests) < 2 {
		t.Fatalf("expected at least 2 requests, got %d", len(op.requests))
	}
	turn2 := op.requests[1]
	found := false
	for _, m := range turn2.Messages {
		for _, tr := range m.ToolResults {
			if tr.CallID == "c1" && strings.Contains(tr.Output, "main.go") {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("turn 2 request did not contain list_files result with main.go; messages: %+v", turn2.Messages)
	}
}

// TestToolResultsCarryName guards a regression: Gemini rejects FunctionResponse
// parts that omit the function name. The agent loop must therefore propagate
// the originating ToolCall.Name into every ToolResult it produces.
func TestToolResultsCarryName(t *testing.T) {
	tmp := t.TempDir()
	repoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(repoDir, "x.go"), []byte("package x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	op := &observingProvider{
		responses: []provider.Response{
			{ToolCalls: []provider.ToolCall{{ID: "c1", Name: "list_files", Args: map[string]any{}}}},
			{ToolCalls: []provider.ToolCall{
				{ID: "c2", Name: "add_finding", Args: map[string]any{"severity": "low", "rule_id": "R", "snippet": "x"}},
				{ID: "c3", Name: "bogus_tool", Args: map[string]any{}},
			}},
			{ToolCalls: []provider.ToolCall{{ID: "c4", Name: "finalize_report", Args: map[string]any{"summary": "ok"}}}},
		},
	}
	aud, _ := audit.NewLogger(filepath.Join(tmp, "audit.jsonl"))
	defer aud.Close()
	rw := report.NewWriter(filepath.Join(tmp, "reports"))
	reg := tool.NewRegistry()
	reg.Register(tool.NewListFiles(repoDir))

	ag := agent.New(agent.Options{Provider: op, Audit: aud, Reports: rw, Tools: reg})
	if _, err := ag.Run(context.Background(), agent.Target{Repo: "r", SHA: "s", Path: repoDir}); err != nil {
		t.Fatalf("run: %v", err)
	}

	want := map[string]string{"c1": "list_files", "c2": "add_finding", "c3": "bogus_tool"}
	got := map[string]string{}
	for _, req := range op.requests {
		for _, m := range req.Messages {
			for _, tr := range m.ToolResults {
				got[tr.CallID] = tr.Name
			}
		}
	}
	for id, name := range want {
		if got[id] != name {
			t.Errorf("tool result %s: name = %q, want %q", id, got[id], name)
		}
	}
}

func TestAgentExposesRegistryDeclsToProvider(t *testing.T) {
	tmp := t.TempDir()
	op := &observingProvider{
		responses: []provider.Response{
			{ToolCalls: []provider.ToolCall{{ID: "c", Name: "finalize_report", Args: map[string]any{"summary": "done"}}}},
		},
	}
	aud, _ := audit.NewLogger(filepath.Join(tmp, "audit.jsonl"))
	defer aud.Close()
	rw := report.NewWriter(filepath.Join(tmp, "reports"))

	reg := tool.NewRegistry()
	reg.Register(tool.NewListFiles(tmp))
	reg.Register(tool.NewReadFile(tmp))
	reg.Register(tool.NewGrep(tmp))

	ag := agent.New(agent.Options{
		Provider: op,
		Audit:    aud,
		Reports:  rw,
		Tools:    reg,
	})
	if _, err := ag.Run(context.Background(), agent.Target{Repo: "r", SHA: "s"}); err != nil {
		t.Fatalf("run: %v", err)
	}

	if len(op.requests) == 0 {
		t.Fatal("no requests")
	}
	names := map[string]bool{}
	for _, td := range op.requests[0].Tools {
		names[td.Name] = true
	}
	for _, want := range []string{"list_files", "read_file", "grep", "add_finding", "finalize_report"} {
		if !names[want] {
			t.Errorf("tool decl missing: %s; got %v", want, names)
		}
	}
}

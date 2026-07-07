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
)

// TestFinalizeReport_EmitsAcknowledgmentToolResult: when the agent calls
// finalize_report, a tool result with a human-readable ack must reach the
// TUI / conversation log so the user sees the report path inline.
func TestFinalizeReport_EmitsAcknowledgmentToolResult(t *testing.T) {
	tmp := t.TempDir()

	fp := &scriptedProvider{
		responses: []provider.Response{
			{ToolCalls: []provider.ToolCall{{
				ID:   "c1",
				Name: "add_finding",
				Args: map[string]any{
					"severity": "high", "rule_id": "S101",
					"file": "main.go", "line": float64(42),
					"snippet": "x", "title": "Hardcoded JWT secret",
				},
			}}},
			{ToolCalls: []provider.ToolCall{{
				ID:   "c2",
				Name: "finalize_report",
				Args: map[string]any{"summary": "1 finding"},
			}}},
		},
	}
	aud, _ := audit.NewLogger(filepath.Join(tmp, "audit.jsonl"))
	defer aud.Close()
	rw := report.NewWriter(filepath.Join(tmp, "reports"))

	var emitted []provider.Message
	ag := agent.New(agent.Options{
		Provider:  fp,
		Audit:     aud,
		Reports:   rw,
		MaxTurns:  10,
		OnMessage: func(m provider.Message) { emitted = append(emitted, m) },
	})

	if _, err := ag.Run(context.Background(), agent.Target{Repo: "github.com/x/y", SHA: "abc123"}); err != nil {
		t.Fatalf("run: %v", err)
	}

	// The last emitted message must be the tool message containing the
	// finalize_report acknowledgment.
	var ack provider.ToolResult
	for _, m := range emitted {
		for _, tr := range m.ToolResults {
			if tr.Name == "finalize_report" {
				ack = tr
			}
		}
	}
	if ack.Name == "" {
		t.Fatal("no finalize_report tool result was emitted via OnMessage")
	}
	if !strings.Contains(ack.Output, ".md") {
		t.Errorf("ack should mention the report path: %q", ack.Output)
	}
	if !strings.Contains(ack.Output, "1 finding") && !strings.Contains(ack.Output, "Findings: 1") {
		t.Errorf("ack should mention findings count: %q", ack.Output)
	}
	if !strings.Contains(ack.Output, "Hardcoded JWT secret") {
		t.Errorf("ack should list finding titles: %q", ack.Output)
	}
}

// TestFinalizeReport_AckTruncatesLongFindingList: with >10 findings the
// ack lists the first 10 and adds "…and N more".
func TestFinalizeReport_AckTruncatesLongFindingList(t *testing.T) {
	tmp := t.TempDir()

	// Build a fake provider that produces 12 add_finding then finalize.
	resps := make([]provider.Response, 0, 13)
	for i := 0; i < 12; i++ {
		resps = append(resps, provider.Response{ToolCalls: []provider.ToolCall{{
			ID:   "c",
			Name: "add_finding",
			Args: map[string]any{
				"severity": "low", "rule_id": "R", "snippet": "x",
				"title": "Finding number",
			},
		}}})
	}
	resps = append(resps, provider.Response{ToolCalls: []provider.ToolCall{{
		ID:   "f",
		Name: "finalize_report",
		Args: map[string]any{"summary": "12 found"},
	}}})

	fp := &scriptedProvider{responses: resps}
	aud, _ := audit.NewLogger(filepath.Join(tmp, "audit.jsonl"))
	defer aud.Close()
	rw := report.NewWriter(filepath.Join(tmp, "reports"))

	var emitted []provider.Message
	ag := agent.New(agent.Options{
		Provider: fp, Audit: aud, Reports: rw, MaxTurns: 20,
		OnMessage: func(m provider.Message) { emitted = append(emitted, m) },
	})
	if _, err := ag.Run(context.Background(), agent.Target{Repo: "r", SHA: "s"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	var ack string
	for _, m := range emitted {
		for _, tr := range m.ToolResults {
			if tr.Name == "finalize_report" {
				ack = tr.Output
			}
		}
	}
	if !strings.Contains(ack, "…and 2 more") {
		t.Errorf("ack should truncate with '…and 2 more' for 12 findings: %q", ack)
	}
}

package agent_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/argusappsec/argus/pkg/agent"
	"github.com/argusappsec/argus/pkg/audit"
	"github.com/argusappsec/argus/pkg/provider"
	"github.com/argusappsec/argus/pkg/report"
)

// scriptedProvider returns canned responses in order.
type scriptedProvider struct {
	responses []provider.Response
	idx       int
}

func (f *scriptedProvider) Generate(_ context.Context, _ provider.Request) (provider.Response, error) {
	r := f.responses[f.idx]
	f.idx++
	return r, nil
}

func TestAgentRunProducesReport(t *testing.T) {
	tmp := t.TempDir()

	fp := &scriptedProvider{
		responses: []provider.Response{
			{
				ToolCalls: []provider.ToolCall{{
					ID:   "c1",
					Name: "add_finding",
					Args: map[string]any{
						"severity":    "high",
						"rule_id":     "S101",
						"file":        "main.go",
						"line":        float64(42),
						"snippet":     `password := "hardcoded"`,
						"title":       "Hardcoded password",
						"description": "Hardcoded credential in main.go",
						"remediation": "Move to env var",
					},
				}},
				Usage: provider.Usage{InputTokens: 100, OutputTokens: 20},
			},
			{
				ToolCalls: []provider.ToolCall{{
					ID:   "c2",
					Name: "finalize_report",
					Args: map[string]any{"summary": "1 high finding"},
				}},
				Usage: provider.Usage{InputTokens: 200, OutputTokens: 10},
			},
		},
	}

	aud, err := audit.NewLogger(filepath.Join(tmp, "audit.jsonl"))
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	defer aud.Close()

	rw := report.NewWriter(filepath.Join(tmp, "reports"))

	ag := agent.New(agent.Options{
		Provider: fp,
		Audit:    aud,
		Reports:  rw,
		MaxTurns: 10,
	})

	rep, err := ag.Run(context.Background(), agent.Target{
		Repo: "github.com/example/sample",
		SHA:  "abc123",
	})
	if err != nil {
		t.Fatalf("agent run: %v", err)
	}

	if rep.Summary != "1 high finding" {
		t.Errorf("summary = %q, want %q", rep.Summary, "1 high finding")
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(rep.Findings))
	}
	f := rep.Findings[0]
	if f.Severity != "high" || f.RuleID != "S101" {
		t.Errorf("finding mismatch: %+v", f)
	}
	if f.ID == "" {
		t.Error("finding ID should be set")
	}

	reportPath := filepath.Join(tmp, "reports", "github.com_example_sample", "abc123.md")
	if _, err := os.Stat(reportPath); err != nil {
		t.Errorf("report file not found at %s: %v", reportPath, err)
	}
}

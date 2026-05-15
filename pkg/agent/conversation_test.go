package agent_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/agent"
	"github.com/redcarbon-dev/argus/pkg/audit"
	"github.com/redcarbon-dev/argus/pkg/conversation"
	"github.com/redcarbon-dev/argus/pkg/provider"
	"github.com/redcarbon-dev/argus/pkg/report"
)

// TestAgentPersistsConversation: when a conversation.Writer is provided in
// Options, every message exchanged with the provider (user seed, model turn,
// tool results) is appended to the conversation log.
func TestAgentPersistsConversation(t *testing.T) {
	tmp := t.TempDir()
	convoPath := filepath.Join(tmp, "convo.jsonl")

	convoWriter, err := conversation.NewWriter(convoPath, "test-session")
	if err != nil {
		t.Fatalf("new convo writer: %v", err)
	}
	defer convoWriter.Close()

	fp := &scriptedProvider{
		responses: []provider.Response{
			{
				ToolCalls: []provider.ToolCall{{
					ID:   "c1",
					Name: "add_finding",
					Args: map[string]any{"severity": "high", "rule_id": "R1", "snippet": "x"},
				}},
			},
			{
				ToolCalls: []provider.ToolCall{{
					ID:   "c2",
					Name: "finalize_report",
					Args: map[string]any{"summary": "1 finding"},
				}},
			},
		},
	}

	aud, _ := audit.NewLogger(filepath.Join(tmp, "audit.jsonl"))
	defer aud.Close()
	rw := report.NewWriter(filepath.Join(tmp, "reports"))

	ag := agent.New(agent.Options{
		Provider:     fp,
		Audit:        aud,
		Reports:      rw,
		Conversation: convoWriter,
	})

	if _, err := ag.Run(context.Background(), agent.Target{Repo: "r", SHA: "s"}); err != nil {
		t.Fatalf("run: %v", err)
	}

	records, err := conversation.ReadAll(convoPath)
	if err != nil {
		t.Fatalf("read convo: %v", err)
	}
	if len(records) < 3 {
		t.Fatalf("expected at least 3 records (user seed + model turn + tool results), got %d", len(records))
	}

	// First record must be the user seed.
	if records[0].Message.Role != "user" {
		t.Errorf("record[0] role = %q, want user", records[0].Message.Role)
	}

	// Some record must contain the model's add_finding tool call.
	sawAddFinding := false
	for _, r := range records {
		for _, tc := range r.Message.ToolCalls {
			if tc.Name == "add_finding" {
				sawAddFinding = true
			}
		}
	}
	if !sawAddFinding {
		t.Error("expected at least one record with add_finding tool call")
	}
}

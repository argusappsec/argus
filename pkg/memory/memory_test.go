package memory_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/conversation"
	"github.com/redcarbon-dev/argus/pkg/memory"
	"github.com/redcarbon-dev/argus/pkg/provider"
)

// scriptedProvider is a tiny canned provider used by the curator tests.
type scriptedProvider struct {
	responses []provider.Response
	requests  []provider.Request
	idx       int
}

func (s *scriptedProvider) Generate(_ context.Context, req provider.Request) (provider.Response, error) {
	s.requests = append(s.requests, req)
	r := s.responses[s.idx]
	s.idx++
	return r, nil
}

// TestCurate_TracerBullet: given a conversation log and an empty memory file,
// the curator agent loop calls update_memory with curated content and
// finalize_report to terminate. Afterwards MEMORY.md contains the curated
// content and the source conversation file is untouched.
func TestCurate_TracerBullet(t *testing.T) {
	tmp := t.TempDir()
	convoPath := filepath.Join(tmp, "convo.jsonl")
	memPath := filepath.Join(tmp, "MEMORY.md")

	// Seed the conversation file with a realistic exchange.
	w, err := conversation.NewWriter(convoPath, "sess-1")
	if err != nil {
		t.Fatalf("new convo writer: %v", err)
	}
	_ = w.Append(conversation.Record{Message: provider.Message{Role: "user", Content: "review github.com/x/y"}})
	_ = w.Append(conversation.Record{Message: provider.Message{Role: "model", ToolCalls: []provider.ToolCall{{ID: "c1", Name: "list_files"}}}})
	_ = w.Append(conversation.Record{Message: provider.Message{Role: "tool", ToolResults: []provider.ToolResult{{CallID: "c1", Name: "list_files", Output: "main.go\npkg/auth.go"}}}})
	w.Close()

	// Scripted: turn 1 calls update_memory, turn 2 finalizes.
	fp := &scriptedProvider{
		responses: []provider.Response{
			{ToolCalls: []provider.ToolCall{{
				ID:   "c1",
				Name: "update_memory",
				Args: map[string]any{"content": "User reviews Go repos. Pattern: list_files → triage main.go and auth code first."},
			}}},
			{ToolCalls: []provider.ToolCall{{
				ID:   "c2",
				Name: "finalize_report",
				Args: map[string]any{"summary": "memory updated"},
			}}},
		},
	}

	if err := memory.Curate(context.Background(), memory.Options{
		ConversationPath: convoPath,
		MemoryPath:       memPath,
		Provider:         fp,
	}); err != nil {
		t.Fatalf("curate: %v", err)
	}

	// MEMORY.md must contain the curated content.
	got, err := os.ReadFile(memPath)
	if err != nil {
		t.Fatalf("read memory: %v", err)
	}
	if !strings.Contains(string(got), "User reviews Go repos") {
		t.Errorf("memory missing curated content; got:\n%s", got)
	}

	// The conversation file must NOT have been mutated.
	convoBytes, _ := os.ReadFile(convoPath)
	if !strings.Contains(string(convoBytes), "review github.com/x/y") {
		t.Error("source conversation file was mutated")
	}

	// The curator must have RECEIVED the transcript on its first request.
	if len(fp.requests) == 0 {
		t.Fatal("provider received no requests")
	}
	firstReq := fp.requests[0]
	sawTranscript := false
	for _, m := range firstReq.Messages {
		if strings.Contains(m.Content, "list_files") || strings.Contains(m.Content, "main.go") {
			sawTranscript = true
		}
	}
	if !sawTranscript {
		t.Errorf("curator's first request did not include the conversation transcript; messages: %+v", firstReq.Messages)
	}
}

func TestCurate_MissingMemoryFileCreatesIt(t *testing.T) {
	tmp := t.TempDir()
	convoPath := filepath.Join(tmp, "convo.jsonl")
	memPath := filepath.Join(tmp, "subdir", "MEMORY.md") // dir doesn't exist yet

	w, _ := conversation.NewWriter(convoPath, "x")
	_ = w.Append(conversation.Record{Message: provider.Message{Role: "user", Content: "hi"}})
	w.Close()

	fp := &scriptedProvider{
		responses: []provider.Response{
			{ToolCalls: []provider.ToolCall{{ID: "c1", Name: "update_memory", Args: map[string]any{"content": "first memory"}}}},
			{ToolCalls: []provider.ToolCall{{ID: "c2", Name: "finalize_report", Args: map[string]any{"summary": "done"}}}},
		},
	}
	if err := memory.Curate(context.Background(), memory.Options{
		ConversationPath: convoPath,
		MemoryPath:       memPath,
		Provider:         fp,
	}); err != nil {
		t.Fatalf("curate: %v", err)
	}
	got, err := os.ReadFile(memPath)
	if err != nil {
		t.Fatalf("memory file should have been created: %v", err)
	}
	if !strings.Contains(string(got), "first memory") {
		t.Errorf("memory missing: %q", got)
	}
}

func TestCurate_MissingConversationIsError(t *testing.T) {
	err := memory.Curate(context.Background(), memory.Options{
		ConversationPath: filepath.Join(t.TempDir(), "nope.jsonl"),
		MemoryPath:       filepath.Join(t.TempDir(), "MEMORY.md"),
		Provider:         &scriptedProvider{},
	})
	if err == nil {
		t.Error("expected error when conversation file is missing")
	}
}

func TestCurate_EmptyConversationIsError(t *testing.T) {
	tmp := t.TempDir()
	convoPath := filepath.Join(tmp, "empty.jsonl")
	if err := os.WriteFile(convoPath, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	err := memory.Curate(context.Background(), memory.Options{
		ConversationPath: convoPath,
		MemoryPath:       filepath.Join(tmp, "MEMORY.md"),
		Provider:         &scriptedProvider{},
	})
	if err == nil {
		t.Error("expected error for empty conversation (nothing to curate)")
	}
}

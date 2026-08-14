package memory_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/conversation"
	"github.com/argusappsec/argus/pkg/memory"
	"github.com/argusappsec/argus/pkg/provider"
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
		Store:            memory.NewStore(memPath),
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
		Store:            memory.NewStore(memPath),
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
		Store:            memory.NewStore(filepath.Join(t.TempDir(), "MEMORY.md")),
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
		Store:            memory.NewStore(filepath.Join(tmp, "MEMORY.md")),
		Provider:         &scriptedProvider{},
	})
	if err == nil {
		t.Error("expected error for empty conversation (nothing to curate)")
	}
}

// TestCurate_WritesThroughTheOneMechanismAndIsToldWhenMemoryIsFull: the curator
// is one of two callers of the same write (ADR 0023), not a second memory of its
// own. Proven where it is visible: what it writes lands through the Store the
// external AI writes through, and past the ceiling the curator is told exactly
// what an external AI would be — in the tool result it reads on its next turn,
// with nothing dropped from what it wrote.
func TestCurate_WritesThroughTheOneMechanismAndIsToldWhenMemoryIsFull(t *testing.T) {
	tmp := t.TempDir()
	convoPath := filepath.Join(tmp, "convo.jsonl")
	store := memory.NewStore(filepath.Join(tmp, "MEMORY.md"))

	w, _ := conversation.NewWriter(convoPath, "sess-full")
	_ = w.Append(conversation.Record{Message: provider.Message{Role: "user", Content: "review the payments service"}})
	w.Close()

	curated := strings.Repeat("- The payments service pins its own TLS roots.\n", memory.Ceiling/40)
	fp := &scriptedProvider{
		responses: []provider.Response{
			{ToolCalls: []provider.ToolCall{{ID: "c1", Name: "update_memory", Args: map[string]any{"content": curated}}}},
			{ToolCalls: []provider.ToolCall{{ID: "c2", Name: "finalize_report", Args: map[string]any{"summary": "done"}}}},
		},
	}
	if err := memory.Curate(context.Background(), memory.Options{
		ConversationPath: convoPath,
		Store:            store,
		Provider:         fp,
	}); err != nil {
		t.Fatalf("curate: %v", err)
	}

	// The curator reads the signal on its next turn, in the result of the write
	// it just made.
	var told string
	for _, req := range fp.requests {
		for _, m := range req.Messages {
			for _, tr := range m.ToolResults {
				if tr.Name == "update_memory" {
					told = tr.Output
				}
			}
		}
	}
	if !strings.Contains(told, memory.FullSignal) {
		t.Errorf("the curator must be told MEMORY is full on the same terms an external AI is; got %q", told)
	}
	if !strings.Contains(told, "write_context") {
		t.Errorf("the signal must name where the material should migrate to; got %q", told)
	}

	// Nothing was truncated: the curator's rewrite is on disk in full, and the
	// Store is the one that has it.
	got, err := store.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got != curated {
		t.Error("a full MEMORY tells its writer; it never edits what it was given")
	}
}

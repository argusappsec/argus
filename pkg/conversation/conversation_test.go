package conversation_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/argusappsec/argus/pkg/conversation"
	"github.com/argusappsec/argus/pkg/provider"
)

func TestWriter_AppendsAndReadAllReturnsInOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "abc.jsonl")

	w, err := conversation.NewWriter(path, "abc")
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}

	records := []conversation.Record{
		{Message: provider.Message{Role: "user", Content: "review github.com/x/y"}},
		{Message: provider.Message{Role: "model", ToolCalls: []provider.ToolCall{{ID: "c1", Name: "start_review_github"}}}},
		{Message: provider.Message{Role: "tool", ToolResults: []provider.ToolResult{{CallID: "c1", Name: "start_review_github", Output: "Cloned ..."}}}},
	}
	for _, r := range records {
		if err := w.Append(r); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got, err := conversation.ReadAll(path)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if len(got) != len(records) {
		t.Fatalf("got %d records, want %d", len(got), len(records))
	}
	for i := range got {
		if got[i].Message.Role != records[i].Message.Role {
			t.Errorf("record[%d] role = %q, want %q", i, got[i].Message.Role, records[i].Message.Role)
		}
		if got[i].SessionID != "abc" {
			t.Errorf("record[%d] session_id = %q, want abc", i, got[i].SessionID)
		}
		if got[i].Timestamp.IsZero() {
			t.Errorf("record[%d] timestamp should be set", i)
		}
	}
	if got[1].Message.ToolCalls[0].Name != "start_review_github" {
		t.Errorf("tool call name lost in roundtrip")
	}
	if got[2].Message.ToolResults[0].Output != "Cloned ..." {
		t.Errorf("tool result output lost in roundtrip")
	}
}

func TestWriter_PreservesTimestampOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.jsonl")
	w, _ := conversation.NewWriter(path, "x")
	defer w.Close()
	_ = w.Append(conversation.Record{Message: provider.Message{Role: "user", Content: "a"}})
	time.Sleep(2 * time.Millisecond)
	_ = w.Append(conversation.Record{Message: provider.Message{Role: "user", Content: "b"}})

	got, _ := conversation.ReadAll(path)
	if len(got) != 2 {
		t.Fatalf("len = %d", len(got))
	}
	if !got[1].Timestamp.After(got[0].Timestamp) {
		t.Errorf("timestamps not monotonic: %v vs %v", got[0].Timestamp, got[1].Timestamp)
	}
}

func TestReadAll_MissingFileReturnsEmpty(t *testing.T) {
	got, err := conversation.ReadAll(filepath.Join(t.TempDir(), "nope.jsonl"))
	if err != nil {
		t.Fatalf("missing file should not error, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %d records", len(got))
	}
}

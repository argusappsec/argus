package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// With must stamp its fields into every event, share the parent's hash
// chain, and let explicit Data keys win on collision.
func TestWith_StampsFieldsAndSharesChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log.jsonl")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	derived := l.With(map[string]any{
		"session_id": "abc123",
		"channel":    "uds",
		"principal":  "davide",
	})

	if err := l.Log(Event{Type: "plain"}); err != nil {
		t.Fatalf("Log plain: %v", err)
	}
	if err := derived.Log(Event{Type: "attributed", Data: map[string]any{"turn": 1}}); err != nil {
		t.Fatalf("Log attributed: %v", err)
	}
	if err := derived.Log(Event{Type: "override", Data: map[string]any{"principal": "explicit"}}); err != nil {
		t.Fatalf("Log override: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var events []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("parse line: %v", err)
		}
		events = append(events, e)
	}
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}

	if _, ok := events[0].Data["session_id"]; ok {
		t.Errorf("plain event must not carry derived fields")
	}
	if got := events[1].Data["session_id"]; got != "abc123" {
		t.Errorf("session_id = %v, want abc123", got)
	}
	if got := events[1].Data["turn"]; got != float64(1) {
		t.Errorf("turn = %v, want 1", got)
	}
	if got := events[2].Data["principal"]; got != "explicit" {
		t.Errorf("explicit Data key must win, got %v", got)
	}

	// The chain must be linear across parent and derived writes.
	if events[1].PrevHash != events[0].Hash || events[2].PrevHash != events[1].Hash {
		t.Errorf("hash chain broken across derived loggers")
	}
}

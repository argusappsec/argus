package audit_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/audit"
)

func writeEvents(t *testing.T, path string, events []audit.Event) {
	t.Helper()
	lg, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer lg.Close()
	for _, e := range events {
		if err := lg.Log(e); err != nil {
			t.Fatalf("log: %v", err)
		}
	}
}

func readEvents(t *testing.T, path string) []audit.Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	var out []audit.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e audit.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		out = append(out, e)
	}
	return out
}

func TestLoggerChainsHashes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeEvents(t, path, []audit.Event{
		{Type: "session_start", Data: map[string]any{"repo": "r1"}},
		{Type: "tool_call", Data: map[string]any{"name": "list_files"}},
		{Type: "session_end", Data: map[string]any{"reason": "ok"}},
	})

	events := readEvents(t, path)
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3", len(events))
	}
	if events[0].PrevHash != "" {
		t.Errorf("first prev_hash must be empty, got %q", events[0].PrevHash)
	}
	if events[1].PrevHash != events[0].Hash {
		t.Errorf("event[1].prev_hash = %q, want %q", events[1].PrevHash, events[0].Hash)
	}
	if events[2].PrevHash != events[1].Hash {
		t.Errorf("event[2].prev_hash = %q, want %q", events[2].PrevHash, events[1].Hash)
	}
	for i, e := range events {
		if e.Hash == "" {
			t.Errorf("event[%d].hash is empty", i)
		}
	}
}

// TestTamperingIsDetectable asserts that modifying any previously written
// record makes its recomputed hash mismatch what the next record stored as
// prev_hash. We don't ship a Verify() yet (deferred), but the chain MUST
// have the structural property that tampering is detectable.
func TestTamperingIsDetectable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeEvents(t, path, []audit.Event{
		{Type: "a"},
		{Type: "b"},
		{Type: "c"},
	})

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Flip the type of the first record from "a" to "X".
	tampered := strings.Replace(string(raw), `"type":"a"`, `"type":"X"`, 1)
	if tampered == string(raw) {
		t.Fatalf("test setup failed: no replacement made")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	events := readEvents(t, path)
	// The chain link from events[0] -> events[1] must now be broken:
	// events[1].prev_hash was computed against the ORIGINAL events[0],
	// so it cannot match a hash recomputed from the tampered events[0].
	recomputedFirstHash := mustRehash(t, events[0])
	if events[1].PrevHash == recomputedFirstHash {
		t.Errorf("tampering should break the chain, but hashes still match")
	}
}

// mustRehash re-derives the hash that would have been stored for evt, mirroring
// the logger's rule: hash = sha256(marshal(evt with hash="")).
func mustRehash(t *testing.T, evt audit.Event) string {
	t.Helper()
	evt.Hash = ""
	payload, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return sha256Hex(payload)
}

func sha256Hex(b []byte) string {
	// Local minimal helper to avoid importing crypto in test boilerplate noise.
	return hexEncode(sha256Sum(b))
}

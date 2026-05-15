// Package conversation persists the running message history of an agent
// session as append-only JSONL on disk.
//
// Each Record is one row, written as JSON, terminated by a newline. The file
// is the *forensic audit trail* of the agent's reasoning chain — when a
// finding is contested later, this file is the answer to "show me exactly
// what the agent saw and did".
//
// Schema is intentionally simple: a SessionID + Timestamp envelope around a
// provider.Message. We don't try to abstract over providers here — the model
// turn / tool call / tool result structure is universal enough.
package conversation

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/redcarbon-dev/argus/pkg/provider"
)

// Record is one append-only entry in a conversation file.
type Record struct {
	Timestamp time.Time        `json:"timestamp"`
	SessionID string           `json:"session_id"`
	Message   provider.Message `json:"message"`
}

// Writer appends Records to a JSONL file. Safe for concurrent use.
type Writer struct {
	sessionID string

	mu sync.Mutex
	f  *os.File
}

// NewWriter opens (or creates) path for append. The parent directory is
// created if missing.
func NewWriter(path, sessionID string) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("conversation: mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("conversation: open: %w", err)
	}
	return &Writer{sessionID: sessionID, f: f}, nil
}

// Append serializes rec and writes it as one line. The caller doesn't need to
// fill Timestamp or SessionID — they are stamped here.
func (w *Writer) Append(rec Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	}
	if rec.SessionID == "" {
		rec.SessionID = w.sessionID
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("conversation: marshal: %w", err)
	}
	if _, err := w.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("conversation: write: %w", err)
	}
	return nil
}

// Close flushes and closes the underlying file.
func (w *Writer) Close() error {
	if w.f == nil {
		return nil
	}
	return w.f.Close()
}

// ReadAll loads every record from path in write order. A missing file is not
// an error — it yields an empty slice, since "no conversation yet" is a
// legitimate state for resume/list flows.
func ReadAll(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("conversation: open: %w", err)
	}
	defer f.Close()

	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	line := 0
	for sc.Scan() {
		line++
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("conversation: line %d: %w", line, err)
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("conversation: scan: %w", err)
	}
	return out, nil
}

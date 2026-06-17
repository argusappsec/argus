// Package audit writes a tamper-evident JSONL log: each record carries the
// SHA-256 of the previous record, so any in-place edit invalidates the chain.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Event is one audit record. Type-specific fields go into Data.
type Event struct {
	Timestamp time.Time      `json:"timestamp"`
	Type      string         `json:"type"`
	Data      map[string]any `json:"data,omitempty"`
	PrevHash  string         `json:"prev_hash"`
	Hash      string         `json:"hash"`
}

// Logger appends Events to a file, chaining hashes for tamper-evidence.
// Derived loggers created via With share the same file and hash chain but
// stamp extra attribution fields (session_id, channel, principal) into the
// Data of every event they log.
type Logger struct {
	core   *core
	fields map[string]any
}

// core is the shared write end: one per file, guarded by one mutex so the
// hash chain stays linear no matter how many derived Loggers write to it.
type core struct {
	mu       sync.Mutex
	f        *os.File
	prevHash string
}

// NewLogger opens (or creates) the audit file in append mode. If the file
// already exists, the chain continues from the last record's hash.
func NewLogger(path string) (*Logger, error) {
	if err := ensureDir(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	prev, err := lastHash(path)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Logger{core: &core{f: f, prevHash: prev}}, nil
}

// With returns a derived Logger that adds fields to every event's Data.
// The derived Logger writes to the same file and continues the same hash
// chain as its parent. Explicit Data keys set by the caller win over the
// derived fields on collision.
func (l *Logger) With(fields map[string]any) *Logger {
	merged := make(map[string]any, len(l.fields)+len(fields))
	for k, v := range l.fields {
		merged[k] = v
	}
	for k, v := range fields {
		merged[k] = v
	}
	return &Logger{core: l.core, fields: merged}
}

// Log appends an event. Caller need not fill Timestamp/PrevHash/Hash.
func (l *Logger) Log(evt Event) error {
	if len(l.fields) > 0 {
		data := make(map[string]any, len(l.fields)+len(evt.Data))
		for k, v := range l.fields {
			data[k] = v
		}
		for k, v := range evt.Data {
			data[k] = v
		}
		evt.Data = data
	}

	l.core.mu.Lock()
	defer l.core.mu.Unlock()
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now().UTC()
	}
	evt.PrevHash = l.core.prevHash
	evt.Hash = "" // exclude from hashing

	payload, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	sum := sha256.Sum256(payload)
	evt.Hash = hex.EncodeToString(sum[:])

	line, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	if _, err := l.core.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	l.core.prevHash = evt.Hash
	return nil
}

// Close flushes and closes the underlying file. Closing any derived Logger
// closes the shared file for all of them.
func (l *Logger) Close() error {
	if l.core.f == nil {
		return nil
	}
	return l.core.f.Close()
}

func ensureDir(path string) error {
	dir := dirOf(path)
	if dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o700)
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return ""
}

// lastHash returns the Hash of the last record in the file, or empty if the
// file is empty or does not exist.
func lastHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	if len(data) == 0 {
		return "", nil
	}
	// Find last newline-terminated record.
	end := len(data)
	if data[end-1] == '\n' {
		end--
	}
	start := end
	for start > 0 && data[start-1] != '\n' {
		start--
	}
	var evt Event
	if err := json.Unmarshal(data[start:end], &evt); err != nil {
		return "", fmt.Errorf("parse last audit record: %w", err)
	}
	return evt.Hash, nil
}

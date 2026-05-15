// Package session holds the mutable state shared across an agent run.
//
// A Session is what makes the file-scoped tools (list_files, read_file, grep,
// run_semgrep, ...) "session-aware": their target directory is not cemented at
// construction time, it is read from the Session at each Execute. When a
// start_review_* tool calls SetRoot mid-conversation, every subsequent tool
// invocation immediately sees the new target.
//
// The struct is intentionally small. Anything that doesn't need to be
// run-scoped lives elsewhere (the Agent, the Provider, the audit logger).
package session

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Session carries the per-run state used by tools. It is safe for concurrent
// use because tools may be invoked in parallel from a single agent loop.
type Session struct {
	id        string
	createdAt time.Time

	mu   sync.RWMutex
	root string
}

// New creates a Session with a fresh random id and no target set.
func New() *Session {
	return &Session{
		id:        newID(),
		createdAt: time.Now().UTC(),
	}
}

// ID returns this session's identifier, stable for the lifetime of the Session.
// Useful as a key for conversation files, audit correlation, and resume.
func (s *Session) ID() string { return s.id }

// CreatedAt is the timestamp at which New() was called.
func (s *Session) CreatedAt() time.Time { return s.createdAt }

// Root returns the current target directory, or "" if no review has started yet.
func (s *Session) Root() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.root
}

// SetRoot updates the current target directory. Tools that read Root() on
// every Execute will see the new value on their next invocation.
func (s *Session) SetRoot(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.root = path
}

// newID returns a 12-hex-char identifier. Short enough to be human-typeable
// for `argus chat --resume <id>` later, long enough to be collision-free
// across a single user's sessions.
func newID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to a timestamp-based id if the random source fails.
		// This path is extremely rare on supported OSes.
		return time.Now().UTC().Format("060102150405")
	}
	return hex.EncodeToString(b[:])
}

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

	"github.com/argusappsec/argus/pkg/codehost"
)

// Session carries the per-run state used by tools. It is safe for concurrent
// use because tools may be invoked in parallel from a single agent loop.
type Session struct {
	id        string
	createdAt time.Time

	mu      sync.RWMutex
	root    string
	prDiff  *codehost.PRDiff // set for a PR review; nil otherwise
	missRec MissRecorder     // set for a Snapshot review; nil otherwise
}

// MissRecorder is the Snapshot workspace seen through the file-scoped tools: it
// reports whether a path is held and records reads of paths it does not hold.
// Only a Snapshot review (ADR 0011) sets one — for a repo/PR review a read of an
// absent path stays a plain error. pkg/snapshot.Workspace implements it.
type MissRecorder interface {
	Has(path string) bool
	RecordMiss(path string)
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

// PRDiff returns the pull-request diff set for this Session, and whether one
// was set. A PR review pre-fetches the diff and stashes it here so the pr_diff
// tool can expose the changed files/hunks to the agent without a live API call
// mid-loop (ADR 0009). A non-PR review (e.g. a chat-requested repo review)
// never sets it.
func (s *Session) PRDiff() (codehost.PRDiff, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.prDiff == nil {
		return codehost.PRDiff{}, false
	}
	return *s.prDiff, true
}

// SetPRDiff stashes the pull-request diff for this Session. The pr_diff tool
// reads it on its next invocation.
func (s *Session) SetPRDiff(d codehost.PRDiff) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prDiff = &d
}

// MissRecorder returns the Snapshot workspace's miss recorder, or nil when this
// is not a Snapshot review. The file-scoped tools consult it on every Execute,
// so SetMissRecorder takes effect on the next tool call.
func (s *Session) MissRecorder() MissRecorder {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.missRec
}

// SetMissRecorder wires the Snapshot workspace in as the recorder of reads of
// absent paths. A Snapshot review sets it alongside SetRoot; other reviews leave
// it nil so an absent path stays an error.
func (s *Session) SetMissRecorder(r MissRecorder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.missRec = r
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

package memory

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// MEMORY has one mechanism and two callers (ADR 0023). This file is the
// mechanism: the single writer of MEMORY.md, whoever is asking. The external AI
// reaches it through the save_memory / mark_false_positive Tools on the MCP
// surface; Argus's own memory curator reaches it through Curate, which rewrites
// the whole file at the end of a session. There is no third way to write MEMORY
// and no path that bypasses the ceiling below.

// Ceiling is the size in bytes past which MEMORY is full. MEMORY is loaded into
// every LLM call, so its size is a fixed cost on every single request — roughly
// two thousand tokens at this ceiling. A curator prunes as it rewrites; a
// deterministic append by an external client does not, which is why the limit is
// stated here rather than left to whoever is writing.
//
// It is not an enforcement: a write past it still lands in full (see Write).
// The ceiling is what turns unbounded growth from something a developer
// discovers in a bill into something they are told about at the moment they
// cause it.
const Ceiling = 8 << 10 // 8 KiB

// FullSignal is the phrase that opens the explicit signal a write past the
// Ceiling returns. It is a constant so the guide and the tests can name the
// signal rather than quote a sentence that will be reworded.
const FullSignal = "MEMORY is full"

// Write is the outcome of one MEMORY write, reported to whoever made it. Both
// callers get the same Write for the same file, which is the point of having one
// mechanism: a Colleague's curator is told MEMORY is full on exactly the terms an
// external AI is.
type Write struct {
	// Size is how large MEMORY is after the write, in bytes.
	Size int
	// Full reports that MEMORY is past the Ceiling. The write still happened —
	// in full, unedited — so this is a signal to act on, never a failure.
	Full bool
}

// Signal is what the caller is told about the state MEMORY is now in: empty
// while there is room, and past the Ceiling an explanation of what is full, that
// nothing was dropped, and where the material should go instead. CONTEXT is the
// destination because the boundary between the two is context cost: MEMORY is
// paid for on every call, a CONTEXT document only when it is read.
func (w Write) Signal() string {
	if !w.Full {
		return ""
	}
	return fmt.Sprintf(
		"%s: it now holds %d bytes, past its %d-byte ceiling. Nothing was truncated or dropped — what you just "+
			"wrote was saved in full — but MEMORY is loaded into every call, so everything in it is now a fixed "+
			"cost on every request. Move the material that does not need to be present in every conversation out "+
			"into a CONTEXT document with write_context, and keep MEMORY for what earns that price.",
		FullSignal, w.Size, Ceiling)
}

// Store is the one writer of one MEMORY.md. Its lock serializes every writer in
// the process — the curator's whole-file rewrite, an append from the MCP
// surface, a false positive a teammate accepted on a pull request — so a note
// written while a curation is in flight cannot be lost to the rewrite that
// follows it.
type Store struct {
	path string
	mu   sync.Mutex
}

// NewStore returns the Store for the MEMORY.md at path. One per daemon: two
// Stores over the same file would be two locks and therefore no lock at all.
func NewStore(path string) *Store { return &Store{path: path} }

// Load returns the current MEMORY. A file that does not exist yet is empty
// memory, not an error — a daemon that has never remembered anything is normal.
func (s *Store) Load() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

// Append adds one entry to MEMORY and reports the state it leaves it in. The
// entry is stored exactly as given (as a Markdown list item when it is not
// already one) — a full MEMORY is signalled, never silently trimmed.
func (s *Store) Append(entry string) (Write, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.append(entry)
}

// Replace rewrites MEMORY wholesale. This is the curator's shape of write: it
// reads what is there, decides what still earns its place, and hands back the
// whole file.
func (s *Store) Replace(content string) (Write, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.replace(content)
}

// hold takes the writers' lock for a caller whose write spans more than one
// step, returning its release. The curator needs it: it reads MEMORY into its
// prompt, thinks for as long as an LLM call takes, and then rewrites the whole
// file — an append that landed in between would be erased by that rewrite. It is
// unexported because the only such caller lives in this package, and because a
// caller holding it must use the unlocked internals below rather than the
// methods above.
func (s *Store) hold() func() {
	s.mu.Lock()
	return s.mu.Unlock
}

func (s *Store) load() (string, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("memory: read: %w", err)
	}
	return string(b), nil
}

func (s *Store) append(entry string) (Write, error) {
	line := listItem(entry)
	if line == "" {
		return Write{}, errors.New("memory: nothing to save")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return Write{}, fmt.Errorf("memory: mkdir: %w", err)
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return Write{}, fmt.Errorf("memory: open: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		return Write{}, fmt.Errorf("memory: append: %w", err)
	}
	return s.measure()
}

func (s *Store) replace(content string) (Write, error) {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return Write{}, fmt.Errorf("memory: mkdir: %w", err)
	}
	if err := os.WriteFile(s.path, []byte(content), 0o600); err != nil {
		return Write{}, fmt.Errorf("memory: write: %w", err)
	}
	return s.measure()
}

// measure sizes MEMORY after a write and decides whether it is full.
func (s *Store) measure() (Write, error) {
	info, err := os.Stat(s.path)
	if err != nil {
		return Write{}, fmt.Errorf("memory: size: %w", err)
	}
	size := int(info.Size())
	return Write{Size: size, Full: size > Ceiling}, nil
}

// listItem renders one entry as a line of MEMORY.md: a Markdown list item,
// unless the caller already wrote one (or a heading). The entry's own text is
// never altered — MEMORY keeps what it was given.
func listItem(entry string) string {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return ""
	}
	if !strings.HasPrefix(entry, "-") && !strings.HasPrefix(entry, "*") && !strings.HasPrefix(entry, "#") {
		entry = "- " + entry
	}
	return entry + "\n"
}

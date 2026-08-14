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
// the whole file at the end of a session. There is no way to write MEMORY that
// does not pass the ceiling below.

// Ceiling is the size in bytes past which MEMORY is full. MEMORY is loaded into
// every LLM call, so its size is a fixed cost on every single request — roughly
// two thousand tokens at this ceiling. A curator prunes as it rewrites; a
// deterministic append by an external client does not, which is why the limit is
// stated here rather than left to whoever is writing.
//
// It is not an enforcement: a write past it still lands in full (see State).
// The ceiling is what turns unbounded growth from something a developer
// discovers in a bill into something they are told about at the moment they
// cause it.
const Ceiling = 8 << 10 // 8 KiB

// FullSignal is the phrase that opens the explicit signal a write past the
// Ceiling returns. It is a constant so the guide and the tests can name the
// signal rather than quote a sentence that will be reworded.
const FullSignal = "MEMORY is full"

// State is what MEMORY is like after a write, reported to whoever made it. Both
// callers get the same State for the same file, which is the point of having one
// mechanism: a Colleague's curator is told MEMORY is full on exactly the terms an
// external AI is.
type State struct {
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
func (st State) Signal() string {
	if !st.Full {
		return ""
	}
	return fmt.Sprintf(
		"%s: it now holds %d bytes, past its %d-byte ceiling. Nothing was truncated or dropped — what you just "+
			"wrote was saved in full — but MEMORY is loaded into every call, so everything in it is now a fixed "+
			"cost on every request. Move the material that does not need to be present in every conversation out "+
			"into a CONTEXT document with write_context, and keep MEMORY for what earns that price.",
		FullSignal, st.Size, Ceiling)
}

// Store is the one writer of one MEMORY.md. Its lock serializes every writer in
// the process — the curator's whole-file rewrite, an append from the MCP
// surface, a false positive a teammate accepted on a pull request — so a note
// written while a curation is in flight cannot be lost to the rewrite that
// follows it.
//
// Readers do not take that lock and are never made to wait for a writer: a
// curation holds it across an LLM call, and a Session snapshotting MEMORY at
// that moment must not block behind somebody else's model. What makes that safe
// is that every write lands by rename (see write), so a reader sees one whole
// version of MEMORY or the other, never half of each.
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
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("memory: read: %w", err)
	}
	return string(b), nil
}

// Append adds one entry to MEMORY and reports the state it leaves it in. The
// entry is stored exactly as given (as a Markdown list item when it is not
// already one) — a full MEMORY is signalled, never silently trimmed.
func (s *Store) Append(entry string) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.append(entry)
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

// append adds one entry to the end of MEMORY. Callers must hold the lock.
func (s *Store) append(entry string) (State, error) {
	line := listItem(entry)
	if line == "" {
		return State{}, errors.New("memory: nothing to save")
	}
	existing, err := s.Load()
	if err != nil {
		return State{}, err
	}
	// A previous writer may have left MEMORY mid-line — a curator rewrite is
	// whatever the model produced. Starting a list item on the end of somebody
	// else's sentence would lose both.
	if existing != "" && !strings.HasSuffix(existing, "\n") {
		existing += "\n"
	}
	return s.write(existing + line)
}

// replace rewrites MEMORY wholesale — the curator's shape of write: it reads
// what is there, decides what still earns its place, and hands back the whole
// file. Callers must hold the lock.
func (s *Store) replace(content string) (State, error) {
	return s.write(content)
}

// write puts content in MEMORY's place and sizes what is now there. It lands by
// rename so a concurrent reader — a Session taking its snapshot, a
// resources/read on the MCP surface — sees one whole version or the other and
// never a torn file. Callers must hold the lock.
func (s *Store) write(content string) (State, error) {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return State{}, fmt.Errorf("memory: mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".MEMORY-*.tmp")
	if err != nil {
		return State{}, fmt.Errorf("memory: temp file: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op once the rename below has succeeded
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return State{}, fmt.Errorf("memory: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return State{}, fmt.Errorf("memory: write: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return State{}, fmt.Errorf("memory: chmod: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return State{}, fmt.Errorf("memory: replace: %w", err)
	}
	return State{Size: len(content), Full: len(content) > Ceiling}, nil
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

// Package snapshot materializes caller-supplied file content into a scratch
// workspace on disk — the Snapshot review of the MCP channel (ADR 0011).
//
// A remote/self-hosted Argus cannot read the developer's working tree, so the
// external AI hands over the changed files as {path, content} pairs. The
// Workspace writes them under a private temp root, exposes that root so the
// agent's existing file-scoped tools and scanners can be pointed at it
// (agent.Target.Path), and removes everything on Close so caller-supplied code
// does not accumulate on the daemon host.
//
// The workspace accumulates: a follow-up Add layers more files onto the same
// root without disturbing what is already present. (Miss tracking — surfacing
// the paths the agent reached for but the workspace does not hold — arrives in
// the collaborative slice; the type is shaped to grow into it.)
package snapshot

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

// File is one caller-supplied file: a repo-relative path and its content.
type File struct {
	Path    string
	Content string
}

// Workspace is a scratch checkout of caller-supplied files. It is safe for
// concurrent use: the agent's file-scoped tools may read it from parallel tool
// calls while a follow-up Add accumulates more files.
type Workspace struct {
	mu      sync.RWMutex
	root    string
	present map[string]struct{} // workspace-relative paths materialized so far
}

// New creates a Workspace rooted at a fresh temp directory. The caller owns its
// lifetime and must Close it to remove the scratch checkout.
func New() (*Workspace, error) {
	root, err := os.MkdirTemp("", "argus-snapshot-*")
	if err != nil {
		return nil, fmt.Errorf("snapshot: create workspace: %w", err)
	}
	return &Workspace{root: root, present: map[string]struct{}{}}, nil
}

// Path is the workspace root — the directory the agent's file-scoped tools and
// scanners are pointed at (agent.Target.Path with empty Repo/SHA).
func (w *Workspace) Path() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.root
}

// Add materializes files into the workspace, creating parent directories as
// needed. Adding accumulates: a later Add layers onto the same workspace
// without disturbing files already present. A path that would escape the
// workspace root (absolute, or via "..") is rejected so caller-supplied paths
// can never write outside the scratch checkout.
func (w *Workspace) Add(files []File) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.root == "" {
		return fmt.Errorf("snapshot: workspace is closed")
	}
	for _, f := range files {
		rel, err := safeRel(f.Path)
		if err != nil {
			return err
		}
		abs := filepath.Join(w.root, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
			return fmt.Errorf("snapshot: mkdir for %q: %w", f.Path, err)
		}
		if err := os.WriteFile(abs, []byte(f.Content), 0o600); err != nil {
			return fmt.Errorf("snapshot: write %q: %w", f.Path, err)
		}
		w.present[rel] = struct{}{}
	}
	return nil
}

// Has reports whether path (repo-relative) has been materialized. A path that
// does not normalize to a workspace-relative location is reported absent.
func (w *Workspace) Has(p string) bool {
	rel, err := safeRel(p)
	if err != nil {
		return false
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.present[rel]
	return ok
}

// Close removes the scratch checkout. Safe to call more than once; subsequent
// Add calls fail rather than recreate the root.
func (w *Workspace) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.root == "" {
		return nil
	}
	err := os.RemoveAll(w.root)
	w.root = ""
	if err != nil {
		return fmt.Errorf("snapshot: remove workspace: %w", err)
	}
	return nil
}

// safeRel normalizes a caller-supplied path to a clean workspace-relative path,
// rejecting anything that would escape the root: absolute paths and any path
// that climbs out via "..". Paths are interpreted with slash semantics (the
// wire format) regardless of host OS.
func safeRel(p string) (string, error) {
	s := filepath.ToSlash(p)
	// Reject both a leading-slash absolute path (path.IsAbs) and an OS-absolute
	// path such as a Windows drive letter `C:\...` (filepath.IsAbs), which the
	// slash form would not catch.
	if path.IsAbs(s) || filepath.IsAbs(p) {
		return "", fmt.Errorf("snapshot: absolute path not allowed: %q", p)
	}
	clean := path.Clean(s)
	if clean == "." || clean == "" {
		return "", fmt.Errorf("snapshot: empty path: %q", p)
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("snapshot: path escapes workspace: %q", p)
	}
	return filepath.FromSlash(clean), nil
}

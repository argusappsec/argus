package security

import (
	"fmt"
	"os"
	"path/filepath"
)

// scratch is one scanner run's private corner of the filesystem: the working
// directory the binary runs from, the HOME it sees, its caches and its report
// files. It lives outside the checkout under review and is removed when the run
// ends (ADR 0027).
//
// Running from here instead of from the checkout means a scanner never treats
// the reviewed tree as its working directory, and pointing HOME here means it
// never reads the daemon user's dotfiles or credentials either.
type scratch struct {
	dir string
}

// newScratch creates a fresh scratch directory for one run of the named tool.
func newScratch(tool string) (*scratch, error) {
	dir, err := os.MkdirTemp("", "argus-"+tool+"-*")
	if err != nil {
		return nil, fmt.Errorf("%s: create scratch directory: %w", tool, err)
	}
	s := &scratch{dir: dir}
	for _, sub := range []string{s.home(), s.tmp()} {
		if err := os.MkdirAll(sub, 0o700); err != nil {
			s.remove()
			return nil, fmt.Errorf("%s: create scratch directory: %w", tool, err)
		}
	}
	return s, nil
}

func (s *scratch) home() string { return filepath.Join(s.dir, "home") }
func (s *scratch) tmp() string  { return filepath.Join(s.dir, "tmp") }

// file names a file inside the scratch directory, for a report the scanner
// writes and Argus reads back.
func (s *scratch) file(name string) string { return filepath.Join(s.dir, name) }

// xdg is the XDG base-directory triple, pointed inside the scratch HOME. Tools
// that keep caches or settings through XDG (or through Go's os.UserCacheDir,
// which honours it) add it to their allow-list.
func (s *scratch) xdg() []string {
	return []string{
		"XDG_CACHE_HOME=" + filepath.Join(s.home(), ".cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(s.home(), ".config"),
		"XDG_DATA_HOME=" + filepath.Join(s.home(), ".local", "share"),
	}
}

// command builds a Command that runs from the scratch directory with the base
// allow-list (PATH, a scratch HOME, a scratch TMPDIR) plus the tool's own
// extra entries. Nothing else from the daemon's environment is passed on: no
// token or API key is ever on the list.
func (s *scratch) command(extraEnv []string, args ...string) Command {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + s.home(),
		"TMPDIR=" + s.tmp(),
	}
	return Command{Dir: s.dir, Env: append(env, extraEnv...), Args: args}
}

// remove deletes the scratch directory and everything the run left in it.
func (s *scratch) remove() { _ = os.RemoveAll(s.dir) }

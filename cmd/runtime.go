package cmd

import (
	"fmt"
	"os"
	"path/filepath"
)

// The per-command embedded runtime is gone: chat and review are UDS clients
// of the daemon (running or in-process — see connect.go), and the daemon
// owns provider construction, tool registries and soul/memory snapshots
// (pkg/daemon.Build). What remains here is the home-directory resolution
// shared by every command.

// resolveHome returns the directory Argus reads and writes state from.
// Precedence:
//  1. explicit override (--home)
//  2. ARGUS_HOME env var
//  3. ./.argus in the current working directory, but only if it already
//     exists (project-local home; never auto-created)
//  4. $HOME/.argus (the default; created if missing)
//
// Step 3 activates only when ./.argus already exists, so running Argus in an
// arbitrary directory never silently creates state there. Because a
// project-local home can carry SOUL.md, skills and .env authored by whoever
// owns that repo — i.e. instructions and secrets you didn't write — Argus
// prints a notice when it selects one, so you always know when you're running
// with directory-supplied state instead of your own ~/.argus.
func resolveHome(override string) (string, error) {
	if override != "" {
		if err := os.MkdirAll(override, 0o700); err != nil {
			return "", fmt.Errorf("create home: %w", err)
		}
		return override, nil
	}
	if env := os.Getenv("ARGUS_HOME"); env != "" {
		if err := os.MkdirAll(env, 0o700); err != nil {
			return "", fmt.Errorf("create home: %w", err)
		}
		return env, nil
	}
	// Project-local home: use ./.argus only if it already exists as a dir.
	// We never create it here — its mere presence is the opt-in signal.
	if cwd, err := os.Getwd(); err == nil {
		local := filepath.Join(cwd, ".argus")
		if info, statErr := os.Stat(local); statErr == nil && info.IsDir() {
			fmt.Fprintf(os.Stderr, "argus: using project-local home %s\n", local)
			return local, nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home dir: %w", err)
	}
	dir := filepath.Join(home, ".argus")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create home: %w", err)
	}
	return dir, nil
}

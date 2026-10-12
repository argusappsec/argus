package security_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/argusappsec/argus/pkg/security"
)

// fakeRunner records the Command passed to Run and returns a canned response.
// Shared by every per-tool test file in this package.
//
// Tools that write their report to a file (gitleaks via --report-path,
// osv-scanner via --output, gosec via -out=) get a faithful simulation: the fake writes the
// canned `out` to that file, so the tool's own "read the report" path is
// exercised end-to-end.
type fakeRunner struct {
	out     string
	err     error
	noFile  bool // simulate a binary that errored before writing any report
	gotCmd  security.Command
	gotArgs []string
	// gotFiles holds the content of every argument that names a file inside
	// the run's working directory, read while the run is in flight: the
	// scratch directory is gone by the time Execute returns, and the configs a
	// Tool hands its binary live there.
	gotFiles map[string]string
	// absentDirs lists every directory variable in the environment (HOME,
	// TMPDIR, XDG_*) whose directory did not exist while the run was in
	// flight. Some binaries refuse to start without them.
	absentDirs []string
}

func (f *fakeRunner) Run(_ context.Context, cmd security.Command) (string, error) {
	f.gotCmd = cmd
	f.gotArgs = cmd.Args
	f.gotFiles = map[string]string{}
	f.absentDirs = nil
	for _, kv := range cmd.Env {
		k, v, _ := strings.Cut(kv, "=")
		if k != "HOME" && k != "TMPDIR" && !strings.HasPrefix(k, "XDG_") {
			continue
		}
		if info, err := os.Stat(v); err != nil || !info.IsDir() {
			f.absentDirs = append(f.absentDirs, kv)
		}
	}
	for _, a := range cmd.Args {
		if cmd.Dir == "" || !strings.HasPrefix(a, cmd.Dir+string(filepath.Separator)) {
			continue
		}
		if body, err := os.ReadFile(a); err == nil {
			f.gotFiles[a] = string(body)
		}
	}
	if !f.noFile {
		for i, a := range cmd.Args {
			if (a == "--report-path" || a == "--output") && i+1 < len(cmd.Args) {
				_ = os.WriteFile(cmd.Args[i+1], []byte(f.out), 0o600)
			}
			if path, ok := strings.CutPrefix(a, "-out="); ok { // gosec's spelling
				_ = os.WriteFile(path, []byte(f.out), 0o600)
			}
		}
	}
	return f.out, f.err
}

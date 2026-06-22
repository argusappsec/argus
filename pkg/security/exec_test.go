package security_test

import (
	"context"
	"os"
)

// fakeRunner records the args passed to Run and returns a canned response.
// Shared by every per-tool test file in this package.
//
// Tools that write their report to a file (gitleaks via --report-path,
// osv-scanner via --output) get a faithful simulation: the fake writes the
// canned `out` to that file, so the tool's own "read the report" path is
// exercised end-to-end.
type fakeRunner struct {
	out     string
	err     error
	noFile  bool // simulate a binary that errored before writing any report
	gotArgs []string
}

func (f *fakeRunner) Run(_ context.Context, _ string, args ...string) (string, error) {
	f.gotArgs = args
	if !f.noFile {
		for i, a := range args {
			if (a == "--report-path" || a == "--output") && i+1 < len(args) {
				_ = os.WriteFile(args[i+1], []byte(f.out), 0o600)
			}
		}
	}
	return f.out, f.err
}

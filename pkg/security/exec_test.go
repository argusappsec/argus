package security_test

import "context"

// fakeRunner records the args passed to Run and returns a canned response.
// Shared by every per-tool test file in this package.
type fakeRunner struct {
	out     string
	err     error
	gotArgs []string
}

func (f *fakeRunner) Run(_ context.Context, _ string, args ...string) (string, error) {
	f.gotArgs = args
	return f.out, f.err
}

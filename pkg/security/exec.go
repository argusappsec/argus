package security

import (
	"context"
	"fmt"
	"os/exec"
)

// Runner abstracts execution of external commands so tests can stub them out.
// dir is the working directory; args[0] is the binary, args[1:] its flags.
type Runner interface {
	Run(ctx context.Context, dir string, args ...string) (string, error)
}

// ExecRunner runs commands via os/exec. Use it in production.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, dir string, args ...string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("no command")
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s failed: %w: %s", args[0], err, string(out))
	}
	return string(out), nil
}

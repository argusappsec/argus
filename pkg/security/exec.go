package security

import (
	"context"
	"fmt"
	"os/exec"
)

// Command is everything a scanner run needs, stated in full: where it runs,
// what environment it sees and what it executes. Nothing about it is implied by
// the daemon's own process (ADR 0027).
type Command struct {
	// Dir is the working directory. Scanners run from a scratch directory, never
	// from the checkout they scan, so config files committed there are not
	// picked up as the working directory's.
	Dir string
	// Env is the child's complete environment as KEY=value pairs. It is never
	// merged with the daemon's: an empty Env gives the child no environment at
	// all, so `.env` secrets cannot reach a third-party binary by inheritance.
	Env []string
	// Args is the command line; Args[0] is the binary, resolved on the daemon's
	// PATH, and Args[1:] its flags.
	Args []string
}

// Runner abstracts execution of external commands so tests can stub them out.
type Runner interface {
	Run(ctx context.Context, cmd Command) (string, error)
}

// ExecRunner runs commands via os/exec. Use it in production.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, c Command) (string, error) {
	if len(c.Args) == 0 {
		return "", fmt.Errorf("no command")
	}
	cmd := exec.CommandContext(ctx, c.Args[0], c.Args[1:]...)
	cmd.Dir = c.Dir
	// A nil cmd.Env means "inherit the parent's environment" in os/exec, so an
	// empty Command.Env must still become a non-nil, empty slice.
	cmd.Env = append([]string{}, c.Env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s failed: %w: %s", c.Args[0], err, string(out))
	}
	return string(out), nil
}

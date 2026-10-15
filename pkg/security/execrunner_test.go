package security_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/security"
)

// TestExecRunner_DoesNotInheritTheProcessEnvironment is the guarantee the
// whole hardening rests on: the daemon's environment holds `.env` secrets, and
// a scanner is a third-party binary reading hostile input. The child must see
// exactly the environment the Command names and nothing the daemon happens to
// carry.
func TestExecRunner_DoesNotInheritTheProcessEnvironment(t *testing.T) {
	t.Setenv("ARGUS_TEST_LEAKED_SECRET", "sk-should-never-reach-the-child")

	out, err := security.ExecRunner{}.Run(context.Background(), security.Command{
		Dir:  t.TempDir(),
		Env:  []string{"ARGUS_TEST_GRANTED=yes"},
		Args: []string{"env"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(out, "ARGUS_TEST_LEAKED_SECRET") {
		t.Errorf("child saw a variable from the test process:\n%s", out)
	}
	if !strings.Contains(out, "ARGUS_TEST_GRANTED=yes") {
		t.Errorf("child is missing the variable the Command granted:\n%s", out)
	}
}

// TestExecRunner_EmptyEnvironmentMeansEmpty guards os/exec's trap: a nil
// cmd.Env means "inherit everything". A Command that names no environment
// must give the child none, not the daemon's.
func TestExecRunner_EmptyEnvironmentMeansEmpty(t *testing.T) {
	t.Setenv("ARGUS_TEST_LEAKED_SECRET", "sk-should-never-reach-the-child")

	out, err := security.ExecRunner{}.Run(context.Background(), security.Command{
		Dir:  t.TempDir(),
		Args: []string{"env"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("child environment should be empty, got:\n%s", out)
	}
}

// TestExecRunner_RunsInTheCommandsDirectory: the working directory is part of
// the Command, so a scanner can be kept out of the checkout it scans.
func TestExecRunner_RunsInTheCommandsDirectory(t *testing.T) {
	dir := t.TempDir()

	out, err := security.ExecRunner{}.Run(context.Background(), security.Command{
		Dir:  dir,
		Args: []string{"pwd", "-P"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	want, _ := filepath.EvalSymlinks(dir)
	if strings.TrimSpace(out) != want {
		t.Errorf("working directory = %q, want %q", strings.TrimSpace(out), want)
	}
}

func TestExecRunner_RefusesACommandWithNoArgs(t *testing.T) {
	if _, err := (security.ExecRunner{}).Run(context.Background(), security.Command{Dir: os.TempDir()}); err == nil {
		t.Error("expected an error for a Command with no binary")
	}
}

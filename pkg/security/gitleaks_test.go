package security_test

import (
	"context"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/security"
	"github.com/argusappsec/argus/pkg/session"
)

func TestGitleaks_ToolMetadata(t *testing.T) {
	g := security.NewGitleaks(sessionAt("/tmp"), &fakeRunner{})
	if g.Name() != "run_gitleaks" {
		t.Errorf("name = %q", g.Name())
	}
}

func TestGitleaks_PassesPathAndReturnsOutput(t *testing.T) {
	fr := &fakeRunner{out: `[]`}
	g := security.NewGitleaks(sessionAt("/repo"), fr)
	out, err := g.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if out != "[]" {
		t.Errorf("output = %q", out)
	}
	joined := strings.Join(fr.gotArgs, " ")
	if !strings.Contains(joined, "/repo") {
		t.Errorf("expected /repo in args: %v", fr.gotArgs)
	}
}

func TestGitleaks_ErrorsWhenNoTargetSet(t *testing.T) {
	g := security.NewGitleaks(session.New(), &fakeRunner{})
	if _, err := g.Execute(context.Background(), map[string]any{}); err == nil {
		t.Error("expected error when session has no root set")
	}
}

// TestGitleaks_TolerantOfExit1WhenReportPresent guards a real-world quirk:
// gitleaks returns exit code 1 when it FINDS secrets (which is the expected
// outcome from our point of view). The wrapper must treat a readable report
// file as authoritative even if the binary errored.
func TestGitleaks_TolerantOfExit1WhenReportPresent(t *testing.T) {
	fr := &fakeRunner{
		out: `[{"RuleID":"generic-api-key","File":"main.go","Secret":"sk-abc"}]`,
		err: errExit1{},
	}
	g := security.NewGitleaks(sessionAt("/repo"), fr)
	out, err := g.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("execute should not error when report is readable, got: %v", err)
	}
	if !strings.Contains(out, "generic-api-key") {
		t.Errorf("output should be the report content: %q", out)
	}
}

// TestGitleaks_NoStdoutReportPath: the wrapper must NOT pass "/dev/stdout"
// or any other stdout-like path — that breaks under the bubbletea TUI. It
// must pass a real filesystem path. Regression guard.
func TestGitleaks_NoStdoutReportPath(t *testing.T) {
	fr := &fakeRunner{out: `[]`}
	g := security.NewGitleaks(sessionAt("/repo"), fr)
	if _, err := g.Execute(context.Background(), map[string]any{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	for i, a := range fr.gotArgs {
		if a == "--report-path" && i+1 < len(fr.gotArgs) {
			path := fr.gotArgs[i+1]
			if path == "/dev/stdout" || path == "-" || path == "/dev/stderr" {
				t.Errorf("--report-path must be a real file, got %q", path)
			}
			return
		}
	}
	t.Error("gitleaks invocation is missing --report-path")
}

// errExit1 is a fake error used in tests to mimic gitleaks's "found secrets"
// exit code 1 — it is NOT a real *exec.ExitError but suffices to assert the
// wrapper's tolerance.
type errExit1 struct{}

func (errExit1) Error() string { return "exit status 1" }

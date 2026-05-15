package security_test

import (
	"context"
	"strings"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/security"
)

type fakeRunner struct {
	out     string
	err     error
	gotArgs []string
}

func (f *fakeRunner) Run(_ context.Context, _ string, args ...string) (string, error) {
	f.gotArgs = args
	return f.out, f.err
}

func TestSemgrep_ToolMetadata(t *testing.T) {
	s := security.NewSemgrep("/tmp", &fakeRunner{})
	if s.Name() != "run_semgrep" {
		t.Errorf("name = %q", s.Name())
	}
	if s.Description() == "" {
		t.Error("description empty")
	}
}

func TestSemgrep_PassesPathAndReturnsOutput(t *testing.T) {
	fr := &fakeRunner{out: `{"results": []}`}
	s := security.NewSemgrep("/repo", fr)
	out, err := s.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out, "results") {
		t.Errorf("output = %q", out)
	}
	// Must have asked semgrep for JSON output and pointed at the repo path.
	joined := strings.Join(fr.gotArgs, " ")
	if !strings.Contains(joined, "--json") {
		t.Errorf("expected --json in args: %v", fr.gotArgs)
	}
	if !strings.Contains(joined, "/repo") {
		t.Errorf("expected /repo in args: %v", fr.gotArgs)
	}
}

func TestGitleaks_ToolMetadata(t *testing.T) {
	g := security.NewGitleaks("/tmp", &fakeRunner{})
	if g.Name() != "run_gitleaks" {
		t.Errorf("name = %q", g.Name())
	}
}

func TestGitleaks_PassesPathAndReturnsOutput(t *testing.T) {
	fr := &fakeRunner{out: `[]`}
	g := security.NewGitleaks("/repo", fr)
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

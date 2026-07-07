package security_test

import (
	"context"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/security"
	"github.com/argusappsec/argus/pkg/session"
)

func sessionAt(root string) *session.Session {
	s := session.New()
	s.SetRoot(root)
	return s
}

func TestSemgrep_ToolMetadata(t *testing.T) {
	s := security.NewSemgrep(sessionAt("/tmp"), &fakeRunner{})
	if s.Name() != "run_semgrep" {
		t.Errorf("name = %q", s.Name())
	}
	if s.Description() == "" {
		t.Error("description empty")
	}
}

func TestSemgrep_PassesPathAndReturnsOutput(t *testing.T) {
	fr := &fakeRunner{out: `{"results": []}`}
	s := security.NewSemgrep(sessionAt("/repo"), fr)
	out, err := s.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out, "results") {
		t.Errorf("output = %q", out)
	}
	joined := strings.Join(fr.gotArgs, " ")
	if !strings.Contains(joined, "--json") {
		t.Errorf("expected --json in args: %v", fr.gotArgs)
	}
	if !strings.Contains(joined, "/repo") {
		t.Errorf("expected /repo in args: %v", fr.gotArgs)
	}
}

func TestSemgrep_ErrorsWhenNoTargetSet(t *testing.T) {
	s := security.NewSemgrep(session.New(), &fakeRunner{})
	if _, err := s.Execute(context.Background(), map[string]any{}); err == nil {
		t.Error("expected error when session has no root set")
	}
}

package security_test

import (
	"context"
	"strings"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/security"
	"github.com/redcarbon-dev/argus/pkg/session"
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

package tool_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/soul"
	"github.com/redcarbon-dev/argus/pkg/tool"
)

func TestWriteSoul_TracerCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "SOUL.md")
	ws := tool.NewWriteSoul(path)

	out, err := ws.Execute(context.Background(), map[string]any{
		"company":          "RedCarbon",
		"industry":         "cybersecurity",
		"data_sensitivity": "pii",
		"primary_stack":    []any{"Go", "Python"},
		"infra":            []any{"AWS", "Kubernetes"},
		"secret_storage":   "HashiCorp Vault",
		"compliance":       []any{"SOC2", "ISO27001"},
		"risk_tolerance":   "low",
		"escalation":       "ciso@redcarbon.ai",
		"persona":          "You are RedCarbon's security copilot. Be terse and technical. Cite CWE/OWASP.",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if out == "" {
		t.Error("expected a confirmation message")
	}

	// Round-trip through soul.Load to confirm structure.
	s, err := soul.Load(path)
	if err != nil {
		t.Fatalf("soul.Load: %v", err)
	}
	if s == nil {
		t.Fatal("soul.Load returned nil")
	}
	if s.Company != "RedCarbon" {
		t.Errorf("company = %q", s.Company)
	}
	if s.Industry != "cybersecurity" {
		t.Errorf("industry = %q", s.Industry)
	}
	if len(s.Compliance) != 2 || s.Compliance[0] != "SOC2" {
		t.Errorf("compliance = %v", s.Compliance)
	}
	if s.RiskTolerance != "low" {
		t.Errorf("risk_tolerance = %q", s.RiskTolerance)
	}
	if s.Escalation != "ciso@redcarbon.ai" {
		t.Errorf("escalation = %q", s.Escalation)
	}
	if s.DataSensitivity != "pii" {
		t.Errorf("data_sensitivity = %q", s.DataSensitivity)
	}
	if len(s.PrimaryStack) != 2 || s.PrimaryStack[0] != "Go" {
		t.Errorf("primary_stack = %v", s.PrimaryStack)
	}
	if len(s.Infra) != 2 || s.Infra[1] != "Kubernetes" {
		t.Errorf("infra = %v", s.Infra)
	}
	if s.SecretStorage != "HashiCorp Vault" {
		t.Errorf("secret_storage = %q", s.SecretStorage)
	}
	if !strings.Contains(s.Persona, "RedCarbon's security copilot") {
		t.Errorf("persona = %q", s.Persona)
	}
}

func TestWriteSoul_RequiresCompany(t *testing.T) {
	ws := tool.NewWriteSoul(filepath.Join(t.TempDir(), "SOUL.md"))
	if _, err := ws.Execute(context.Background(), map[string]any{"persona": "..."}); err == nil {
		t.Error("expected error when company is missing")
	}
}

func TestWriteSoul_RequiresPersona(t *testing.T) {
	ws := tool.NewWriteSoul(filepath.Join(t.TempDir(), "SOUL.md"))
	if _, err := ws.Execute(context.Background(), map[string]any{"company": "X"}); err == nil {
		t.Error("expected error when persona is missing")
	}
}

func TestWriteSoul_OptionalFieldsCanBeOmitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "SOUL.md")
	ws := tool.NewWriteSoul(path)
	if _, err := ws.Execute(context.Background(), map[string]any{
		"company": "X",
		"persona": "Be helpful.",
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	s, _ := soul.Load(path)
	if s.Company != "X" || s.Persona != "Be helpful." {
		t.Errorf("got %+v", s)
	}
}

func TestWriteSoul_Metadata(t *testing.T) {
	ws := tool.NewWriteSoul("/tmp/SOUL.md")
	if ws.Name() != "write_soul" {
		t.Errorf("name = %q", ws.Name())
	}
	if ws.Description() == "" {
		t.Error("description empty")
	}
}

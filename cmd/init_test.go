package cmd

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/argusappsec/argus/pkg/config"
)

func TestSetPersonaName_SavesToConfig(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "argus.yaml")
	if err := config.SaveConfig(cfgPath, &config.Config{DefaultModel: "gemini-2.5-flash"}); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	tl := &setPersonaName{cfgPath: cfgPath}
	out, err := tl.Execute(context.Background(), map[string]any{"name": "@Ercole "})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if out == "" {
		t.Error("expected a confirmation message")
	}

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Persona.Name != "Ercole" {
		t.Errorf("persona.name = %q, want %q (leading @ and whitespace trimmed)", cfg.Persona.Name, "Ercole")
	}
	if cfg.DefaultModel != "gemini-2.5-flash" {
		t.Errorf("default_model clobbered: %q", cfg.DefaultModel)
	}
}

func TestSetPersonaName_RejectsEmptyAndMultiWord(t *testing.T) {
	tl := &setPersonaName{cfgPath: filepath.Join(t.TempDir(), "argus.yaml")}
	if _, err := tl.Execute(context.Background(), map[string]any{"name": "  "}); err == nil {
		t.Error("expected error for empty name")
	}
	if _, err := tl.Execute(context.Background(), map[string]any{"name": "Ercole di Tebe"}); err == nil {
		t.Error("expected error for multi-word name (cannot form a mention token)")
	}
}

package config

import (
	"slices"
	"strings"
	"testing"
)

// tools.disabled lists Catalog IDs the operator switched off. A known ID loads
// as written.
func TestToolsConfig_DisabledParsesFromYAML(t *testing.T) {
	path := writeConfigFile(t, `tools:
  disabled:
    - gitleaks
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !slices.Equal(cfg.Tools.Disabled, []string{"gitleaks"}) {
		t.Errorf("tools.disabled = %v, want [gitleaks]", cfg.Tools.Disabled)
	}
}

// Omitting the key disables nothing, so a Tool newly added to the image is on
// by default.
func TestToolsConfig_AbsentDisablesNothing(t *testing.T) {
	cfg, err := LoadConfig(writeConfigFile(t, "default_model: gemini-2.5-flash\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Tools.Disabled) != 0 {
		t.Errorf("absent tools.disabled must be empty, got %v", cfg.Tools.Disabled)
	}
}

// A typo in tools.disabled would silently leave a scanner on, so an ID that is
// not in the Catalog fails loading, and the error names it.
func TestToolsConfig_UnknownDisabledIDFailsLoadingAndIsNamed(t *testing.T) {
	path := writeConfigFile(t, `tools:
  disabled:
    - gitleaks
    - gitleak
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("an unknown tools.disabled ID must fail loading")
	}
	if !strings.Contains(err.Error(), `"gitleak"`) {
		t.Errorf("the error must name the unknown ID: %v", err)
	}
}

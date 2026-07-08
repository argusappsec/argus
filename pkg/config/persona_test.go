package config

import "testing"

func TestPersonaConfig_ParsesFromYAML(t *testing.T) {
	const yaml = `default_model: gemini-2.5-flash
persona:
  name: Ercole
`
	path := writeConfigFile(t, yaml)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Persona.Name != "Ercole" {
		t.Errorf("persona name = %q, want Ercole", cfg.Persona.Name)
	}
}

func TestPersonaConfig_AbsentIsEmpty(t *testing.T) {
	const yaml = `default_model: gemini-2.5-flash
`
	path := writeConfigFile(t, yaml)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Persona.Name != "" {
		t.Errorf("absent persona must be empty, got %q", cfg.Persona.Name)
	}
}

func TestPersonaConfig_RoundTrips(t *testing.T) {
	path := writeConfigFile(t, "")
	in := &Config{DefaultModel: "gemini-2.5-flash", Persona: PersonaConfig{Name: "Ercole"}}
	if err := SaveConfig(path, in); err != nil {
		t.Fatalf("save: %v", err)
	}
	out, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if out.Persona.Name != "Ercole" {
		t.Errorf("persona name after round-trip = %q, want Ercole", out.Persona.Name)
	}
}

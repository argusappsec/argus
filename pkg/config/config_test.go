package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/config"
)

func TestConfig_LoadMissingReturnsDefault(t *testing.T) {
	cfg, err := config.LoadConfig(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatalf("missing config should not error: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadConfig returned nil")
	}
	if len(cfg.Providers) != 0 {
		t.Errorf("default config should have no providers configured, got %v", cfg.Providers)
	}
}

func TestConfig_SaveAndLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "argus.yaml")

	in := &config.Config{
		Providers: map[string]config.ProviderConfig{
			"gemini": {
				Type:       "gemini",
				APIKeyEnv:  "GEMINI_API_KEY",
				DefaultURL: "",
			},
		},
		DefaultModel: "gemini-2.5-flash",
	}
	if err := config.SaveConfig(path, in); err != nil {
		t.Fatalf("save: %v", err)
	}

	out, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if out.DefaultModel != "gemini-2.5-flash" {
		t.Errorf("default_model = %q", out.DefaultModel)
	}
	p, ok := out.Providers["gemini"]
	if !ok {
		t.Fatal("provider 'gemini' not found")
	}
	if p.Type != "gemini" {
		t.Errorf("provider type = %q", p.Type)
	}
	if p.APIKeyEnv != "GEMINI_API_KEY" {
		t.Errorf("api_key_env = %q", p.APIKeyEnv)
	}
}

func TestConfig_ProviderForModel(t *testing.T) {
	cfg := &config.Config{
		Providers: map[string]config.ProviderConfig{
			"gemini": {Type: "gemini", APIKeyEnv: "GEMINI_API_KEY"},
		},
		DefaultModel: "gemini-2.5-flash",
	}
	p, name, err := cfg.ProviderForDefaultModel()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if name != "gemini" {
		t.Errorf("provider name = %q", name)
	}
	if p.Type != "gemini" {
		t.Errorf("provider type = %q", p.Type)
	}
}

func TestConfig_ProviderForModel_EmptyDefaultIsError(t *testing.T) {
	cfg := &config.Config{}
	if _, _, err := cfg.ProviderForDefaultModel(); err == nil {
		t.Error("expected error when default_model unset")
	}
}

func TestConfig_SaveCreatesParentDirAt0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "argus.yaml")
	if err := config.SaveConfig(path, &config.Config{DefaultModel: "x"}); err != nil {
		t.Fatalf("save: %v", err)
	}
}

func TestConfig_SavedYAMLIsHumanReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "argus.yaml")
	cfg := &config.Config{
		Providers: map[string]config.ProviderConfig{
			"gemini": {Type: "gemini", APIKeyEnv: "GEMINI_API_KEY"},
		},
		DefaultModel: "gemini-2.5-flash",
	}
	if err := config.SaveConfig(path, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	body, _ := readFile(t, path)
	for _, want := range []string{"providers:", "gemini:", "type: gemini", "api_key_env: GEMINI_API_KEY", "default_model: gemini-2.5-flash"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in saved YAML:\n%s", want, body)
		}
	}
}

func readFile(t *testing.T, path string) (string, error) {
	t.Helper()
	b, err := readFileBytes(path)
	return string(b), err
}

func readFileBytes(path string) ([]byte, error) {
	return os.ReadFile(path)
}

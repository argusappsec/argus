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
				Type:   "gemini",
				APIKey: config.EnvRef("GEMINI_API_KEY"),
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
	if p.APIKey != "env(GEMINI_API_KEY)" {
		t.Errorf("api_key = %q, want env(GEMINI_API_KEY)", p.APIKey)
	}
}

func TestResolveValue_LiteralPassesThrough(t *testing.T) {
	got, err := config.ResolveValue("just a string")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != "just a string" {
		t.Errorf("got %q", got)
	}
}

func TestResolveValue_EnvRefReadsVar(t *testing.T) {
	t.Setenv("ARGUS_TEST_KEY", "secret-value")
	got, err := config.ResolveValue("env(ARGUS_TEST_KEY)")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != "secret-value" {
		t.Errorf("got %q", got)
	}
}

func TestResolveValue_EnvRefAllowsInternalWhitespace(t *testing.T) {
	t.Setenv("ARGUS_TEST_KEY", "secret-value")
	got, err := config.ResolveValue("env( ARGUS_TEST_KEY )")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != "secret-value" {
		t.Errorf("got %q", got)
	}
}

func TestResolveValue_MissingVarIsError(t *testing.T) {
	t.Setenv("ARGUS_TEST_KEY_NEVER", "")
	if _, err := config.ResolveValue("env(ARGUS_TEST_KEY_NEVER)"); err == nil {
		t.Error("expected error when referenced env var is empty/unset")
	}
}

func TestResolveValue_EmptyVarNameIsError(t *testing.T) {
	if _, err := config.ResolveValue("env()"); err == nil {
		t.Error("expected error for env() with no variable name")
	}
}

func TestProviderConfig_ResolveAPIKey(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "abc-123")
	p := config.ProviderConfig{Type: "gemini", APIKey: "env(GEMINI_API_KEY)"}
	got, err := p.ResolveAPIKey()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != "abc-123" {
		t.Errorf("got %q", got)
	}
}

func TestConfig_ProviderForModel(t *testing.T) {
	cfg := &config.Config{
		Providers: map[string]config.ProviderConfig{
			"gemini": {Type: "gemini", APIKey: config.EnvRef("GEMINI_API_KEY")},
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
			"gemini": {Type: "gemini", APIKey: config.EnvRef("GEMINI_API_KEY")},
		},
		DefaultModel: "gemini-2.5-flash",
	}
	if err := config.SaveConfig(path, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	body, _ := readFile(t, path)
	for _, want := range []string{"providers:", "gemini:", "type: gemini", "api_key: env(GEMINI_API_KEY)", "default_model: gemini-2.5-flash"} {
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

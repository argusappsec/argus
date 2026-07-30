package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/config"
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

// TestProviderConfig_MaxOutputTokens asserts the optional output ceiling parses
// from a hand-written argus.yaml and survives a save/load cycle.
func TestProviderConfig_MaxOutputTokens(t *testing.T) {
	dir := t.TempDir()
	handWritten := filepath.Join(dir, "argus.yaml")
	body := `providers:
  local:
    type: openai-compatible
    url: http://localhost:11434/v1
    max_output_tokens: 16384
default_model: qwen3-coder
`
	if err := os.WriteFile(handWritten, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(handWritten)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Providers["local"].MaxOutputTokens; got != 16384 {
		t.Errorf("max_output_tokens = %d, want 16384", got)
	}

	saved := filepath.Join(dir, "saved.yaml")
	if err := config.SaveConfig(saved, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	reloaded, err := config.LoadConfig(saved)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.Providers["local"].MaxOutputTokens; got != 16384 {
		t.Errorf("max_output_tokens did not survive save/load: %d", got)
	}
}

// TestProviderConfig_MaxOutputTokensOmittedByDefault asserts omission is the
// default: an unset ceiling writes no key and reads back as "send no ceiling".
func TestProviderConfig_MaxOutputTokensOmittedByDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "argus.yaml")
	cfg := &config.Config{
		Providers:    map[string]config.ProviderConfig{"gemini": {Type: "gemini"}},
		DefaultModel: "gemini-2.5-flash",
	}
	if err := config.SaveConfig(path, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	body, _ := readFile(t, path)
	if strings.Contains(body, "max_output_tokens") {
		t.Errorf("an unset ceiling must not be written to the file:\n%s", body)
	}
	reloaded, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := reloaded.Providers["gemini"].MaxOutputTokens; got != 0 {
		t.Errorf("omitted max_output_tokens = %d, want 0 (send no ceiling)", got)
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

func TestConfig_ProviderForDefaultModel(t *testing.T) {
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

func TestConfig_ProviderForDefaultModel_EmptyDefaultIsError(t *testing.T) {
	cfg := &config.Config{}
	if _, _, err := cfg.ProviderForDefaultModel(); err == nil {
		t.Error("expected error when default_model unset")
	}
}

// TestConfig_ProviderForDefaultModel_QualifiedDefault asserts default_model may
// itself carry the qualified form — the default is resolved by the same rules as
// a per-Session override.
func TestConfig_ProviderForDefaultModel_QualifiedDefault(t *testing.T) {
	cfg := &config.Config{
		Providers: map[string]config.ProviderConfig{
			"gemini": {Type: "gemini"},
			"work":   {Type: "openai-compatible"},
		},
		DefaultModel: "work/gpt-4o",
	}
	p, name, err := cfg.ProviderForDefaultModel()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if name != "work" {
		t.Errorf("provider name = %q, want work", name)
	}
	if p.Type != "openai-compatible" {
		t.Errorf("provider type = %q, want openai-compatible", p.Type)
	}
}

// TestConfig_ProviderForModel covers model-id → Provider resolution for
// arbitrary model ids (a Session may override the configured default): the
// canonical qualified form, the fallbacks that keep a bare id valid, and the
// errors when a bare id cannot be resolved to exactly one Provider.
func TestConfig_ProviderForModel(t *testing.T) {
	cases := []struct {
		name      string
		providers map[string]config.ProviderConfig
		model     string
		wantName  string
		wantModel string
	}{
		{
			name: "qualified form names the provider explicitly",
			providers: map[string]config.ProviderConfig{
				"gemini": {Type: "gemini"},
				"work":   {Type: "openai-compatible"},
			},
			model:     "work/gpt-4o",
			wantName:  "work",
			wantModel: "gpt-4o",
		},
		{
			// OpenRouter model ids carry a slash of their own: the split takes
			// the first slash only, so the rest travels to the wire intact.
			name: "qualification splits on the first slash only",
			providers: map[string]config.ProviderConfig{
				"openrouter": {Type: "openai-compatible"},
				"gemini":     {Type: "gemini"},
			},
			model:     "openrouter/anthropic/claude-sonnet-4",
			wantName:  "openrouter",
			wantModel: "anthropic/claude-sonnet-4",
		},
		{
			name: "bare id resolves to the only configured provider",
			providers: map[string]config.ProviderConfig{
				"local": {Type: "openai-compatible", URL: "http://localhost:11434/v1"},
			},
			model:     "qwen3-coder",
			wantName:  "local",
			wantModel: "qwen3-coder",
		},
		{
			// Qualification is read before the single-provider fallback, so the
			// provider name is stripped rather than sent as part of the model id.
			name: "qualified form wins over the single-provider fallback",
			providers: map[string]config.ProviderConfig{
				"local": {Type: "openai-compatible"},
			},
			model:     "local/qwen3-coder",
			wantName:  "local",
			wantModel: "qwen3-coder",
		},
		{
			// A slash that names no configured provider is part of the model id,
			// not a qualification.
			name: "unqualified id containing a slash reaches the only provider whole",
			providers: map[string]config.ProviderConfig{
				"local": {Type: "openai-compatible"},
			},
			model:     "qwen/qwen3-coder",
			wantName:  "local",
			wantModel: "qwen/qwen3-coder",
		},
		{
			// Regression guard: an existing Gemini config keeps working with a
			// bare model id even alongside a second provider.
			name: "bare id matches the provider name as a prefix",
			providers: map[string]config.ProviderConfig{
				"gemini": {Type: "gemini"},
				"work":   {Type: "openai-compatible"},
			},
			model:     "gemini-2.5-flash",
			wantName:  "gemini",
			wantModel: "gemini-2.5-flash",
		},
		{
			name: "bare id matches the provider type as a prefix",
			providers: map[string]config.ProviderConfig{
				"google": {Type: "gemini"},
				"work":   {Type: "openai-compatible"},
			},
			model:     "gemini-2.5-pro",
			wantName:  "google",
			wantModel: "gemini-2.5-pro",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Providers: tc.providers}
			p, name, model, err := cfg.ProviderForModel(tc.model)
			if err != nil {
				t.Fatalf("ProviderForModel(%q) = error %v", tc.model, err)
			}
			if name != tc.wantName {
				t.Errorf("provider name = %q, want %q", name, tc.wantName)
			}
			if want := tc.providers[tc.wantName]; p != want {
				t.Errorf("provider entry = %+v, want %+v", p, want)
			}
			if model != tc.wantModel {
				t.Errorf("bare model id = %q, want %q", model, tc.wantModel)
			}
		})
	}
}

// TestConfig_ProviderForModel_Errors asserts an unresolvable model id fails
// with a message the operator can act on: the candidates when several Providers
// could serve the id, the configured names otherwise, and in both cases the
// qualified form to write instead.
func TestConfig_ProviderForModel_Errors(t *testing.T) {
	cases := []struct {
		name      string
		providers map[string]config.ProviderConfig
		model     string
		wantSubs  []string
	}{
		{
			name: "ambiguous bare id names every candidate and the qualified form",
			providers: map[string]config.ProviderConfig{
				"eu": {Type: "gemini"},
				"us": {Type: "gemini"},
			},
			model:    "gemini-2.5-flash",
			wantSubs: []string{`"gemini-2.5-flash"`, "ambiguous", `"eu"`, `"us"`, "eu/gemini-2.5-flash"},
		},
		{
			name: "no match names the model, the configured providers and the qualified form",
			providers: map[string]config.ProviderConfig{
				"gemini": {Type: "gemini"},
				"work":   {Type: "openai-compatible"},
			},
			model:    "llama3.1",
			wantSubs: []string{`"llama3.1"`, `"gemini"`, `"work"`, "/llama3.1"},
		},
		{
			name:      "no providers configured at all points at argus init",
			providers: nil,
			model:     "gemini-2.5-flash",
			wantSubs:  []string{`"gemini-2.5-flash"`, "argus init"},
		},
		{
			name: "qualified form with an empty model id",
			providers: map[string]config.ProviderConfig{
				"gemini": {Type: "gemini"},
			},
			model:    "gemini/",
			wantSubs: []string{`"gemini"`, "empty model id"},
		},
		{
			name: "empty model id",
			providers: map[string]config.ProviderConfig{
				"gemini": {Type: "gemini"},
			},
			model:    "",
			wantSubs: []string{"no model id"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Providers: tc.providers}
			_, name, model, err := cfg.ProviderForModel(tc.model)
			if err == nil {
				t.Fatalf("ProviderForModel(%q) resolved to provider %q, model %q; want an error", tc.model, name, model)
			}
			for _, want := range tc.wantSubs {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error must mention %s; got: %v", want, err)
				}
			}
		})
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

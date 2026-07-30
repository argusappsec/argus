package cmd

import (
	"net/url"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/provider"
)

func TestProviderEnvVar(t *testing.T) {
	tests := []struct {
		name         string
		providerType string
		want         string
	}{
		{"gemini", provider.TypeGemini, "GEMINI_API_KEY"},
		// The explicit case that stops the fallback rule from producing
		// "OPENAI-COMPATIBLE_API_KEY": OPENAI_API_KEY is the name every
		// compatible service documents, so an exported key pre-fills init.
		{"openai-compatible uses the ecosystem convention", provider.TypeOpenAICompatible, "OPENAI_API_KEY"},
		{"unknown type falls back to the upper-cased convention", "acme", "ACME_API_KEY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := providerEnvVar(tt.providerType); got != tt.want {
				t.Errorf("providerEnvVar(%q) = %q, want %q", tt.providerType, got, tt.want)
			}
		})
	}
}

func TestProviderBaseURLEnvVar(t *testing.T) {
	tests := []struct {
		name         string
		providerType string
		want         string
	}{
		{"openai-compatible uses the ecosystem convention", provider.TypeOpenAICompatible, "OPENAI_BASE_URL"},
		{"unknown type falls back to the upper-cased convention", "acme", "ACME_BASE_URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := providerBaseURLEnvVar(tt.providerType); got != tt.want {
				t.Errorf("providerBaseURLEnvVar(%q) = %q, want %q", tt.providerType, got, tt.want)
			}
		})
	}
}

// TestOfferedProviderTypes pins the Provider step to the two types Argus
// implements — one per protocol. A type that names a vendor or a runtime, or an
// option for something not implemented, does not belong here.
func TestOfferedProviderTypes(t *testing.T) {
	want := []string{"gemini", "openai-compatible"}
	got := offeredProviderTypes()
	if len(got) != len(want) {
		t.Fatalf("offeredProviderTypes() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("offeredProviderTypes()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// The select must render exactly those types, so no dead "not yet
	// implemented" entry can creep back in.
	opts := providerTypeOptions(provider.TypeOpenAICompatible)
	if len(opts) != len(want) {
		t.Fatalf("providerTypeOptions() rendered %d options, want %d", len(opts), len(want))
	}
	for i, o := range opts {
		if o.Value != want[i] {
			t.Errorf("option %d has value %q, want %q", i, o.Value, want[i])
		}
		if o.Key == "" {
			t.Errorf("option %d (%q) has no label", i, o.Value)
		}
	}
}

// TestEnvVarNamesAreShellSafe is the regression guard behind both explicit
// cases: a Provider type containing a hyphen must never leak into a variable
// name, because no shell can export one.
func TestEnvVarNamesAreShellSafe(t *testing.T) {
	shellSafe := regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	for _, providerType := range offeredProviderTypes() {
		for _, name := range []string{providerEnvVar(providerType), providerBaseURLEnvVar(providerType)} {
			if !shellSafe.MatchString(name) {
				t.Errorf("env var %q for provider type %q is not a shell-exportable name", name, providerType)
			}
		}
	}
}

// TestEndpointPresets pins every preset's base URL. These strings are the whole
// point of the feature — a wrong one is worse than no preset, because the user
// trusts it — so they are asserted verbatim, together with the URL path each
// service serves the API under.
func TestEndpointPresets(t *testing.T) {
	tests := []struct {
		id string
		// wantBaseURL is the endpoint the preset stands for.
		wantBaseURL string
		// wantPath is that URL's path: the suffix the service requires. Empty
		// means the service serves the API at the domain root.
		wantPath string
		// wantWritten is what init writes into argus.yaml's `url` for this
		// preset. Empty means no `url` key at all.
		wantWritten string
	}{
		{id: "openai", wantBaseURL: "https://api.openai.com/v1", wantPath: "/v1", wantWritten: ""},
		{id: "openrouter", wantBaseURL: "https://openrouter.ai/api/v1", wantPath: "/api/v1", wantWritten: "https://openrouter.ai/api/v1"},
		{id: "groq", wantBaseURL: "https://api.groq.com/openai/v1", wantPath: "/openai/v1", wantWritten: "https://api.groq.com/openai/v1"},
		{id: "together", wantBaseURL: "https://api.together.ai/v1", wantPath: "/v1", wantWritten: "https://api.together.ai/v1"},
		{id: "deepseek", wantBaseURL: "https://api.deepseek.com", wantPath: "", wantWritten: "https://api.deepseek.com"},
		{id: "mistral", wantBaseURL: "https://api.mistral.ai/v1", wantPath: "/v1", wantWritten: "https://api.mistral.ai/v1"},
		{id: "cerebras", wantBaseURL: "https://api.cerebras.ai/v1", wantPath: "/v1", wantWritten: "https://api.cerebras.ai/v1"},
		{id: "ollama", wantBaseURL: "http://localhost:11434/v1", wantPath: "/v1", wantWritten: "http://localhost:11434/v1"},
		// The escape hatch: the preset list must never be a limit on what a
		// user can point Argus at.
		{id: presetCustom, wantBaseURL: "", wantPath: "", wantWritten: ""},
	}

	if len(tests) != len(endpointPresets) {
		t.Fatalf("endpointPresets has %d entries, the table pins %d — update the table", len(endpointPresets), len(tests))
	}

	for i, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := endpointPresets[i].ID; got != tt.id {
				t.Fatalf("endpointPresets[%d].ID = %q, want %q", i, got, tt.id)
			}
			p, ok := presetByID(tt.id)
			if !ok {
				t.Fatalf("presetByID(%q) not found", tt.id)
			}
			if p.BaseURL != tt.wantBaseURL {
				t.Errorf("preset %q base URL = %q, want %q", tt.id, p.BaseURL, tt.wantBaseURL)
			}
			if got := presetBaseURL(tt.id); got != tt.wantWritten {
				t.Errorf("presetBaseURL(%q) = %q, want %q", tt.id, got, tt.wantWritten)
			}
			if p.Name == "" {
				t.Errorf("preset %q has no display name", tt.id)
			}
			if p.BaseURL == "" {
				return
			}
			u, err := url.Parse(p.BaseURL)
			if err != nil {
				t.Fatalf("preset %q base URL %q does not parse: %v", tt.id, p.BaseURL, err)
			}
			if !u.IsAbs() {
				t.Errorf("preset %q base URL %q is not absolute", tt.id, p.BaseURL)
			}
			if u.Scheme != "https" && u.Scheme != "http" {
				t.Errorf("preset %q base URL %q has scheme %q, want http(s)", tt.id, p.BaseURL, u.Scheme)
			}
			if u.Host == "" {
				t.Errorf("preset %q base URL %q has no host", tt.id, p.BaseURL)
			}
			if u.Path != tt.wantPath {
				t.Errorf("preset %q base URL path = %q, want %q", tt.id, u.Path, tt.wantPath)
			}
			if strings.HasSuffix(p.BaseURL, "/") {
				t.Errorf("preset %q base URL %q ends in a slash (Argus appends /chat/completions)", tt.id, p.BaseURL)
			}
			if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
				t.Errorf("preset %q base URL %q carries query, fragment or userinfo", tt.id, p.BaseURL)
			}
		})
	}
}

// TestPresetBaseURLUnknownID guards the write path: an id the table does not
// know writes no url rather than a guessed one.
func TestPresetBaseURLUnknownID(t *testing.T) {
	if got := presetBaseURL("nope"); got != "" {
		t.Errorf("presetBaseURL(%q) = %q, want empty", "nope", got)
	}
}

func TestPresetForBaseURL(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{"exact hosted match", "https://api.groq.com/openai/v1", "groq", true},
		{"exact local match", "http://localhost:11434/v1", "ollama", true},
		{"trailing slash as the Ollama docs print it", "http://localhost:11434/v1/", "ollama", true},
		{"surrounding whitespace", "  https://openrouter.ai/api/v1  ", "openrouter", true},
		{"OpenAI default resolves to its preset", "https://api.openai.com/v1", "openai", true},
		{"unknown endpoint falls to custom", "http://192.168.1.10:8000/v1", presetCustom, true},
		{"empty means no preselection", "", "", false},
		{"whitespace only means no preselection", "   ", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := presetForBaseURL(tt.in)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("presetForBaseURL(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"unchanged", "https://api.mistral.ai/v1", "https://api.mistral.ai/v1"},
		{"trailing slash stripped", "http://localhost:11434/v1/", "http://localhost:11434/v1"},
		{"repeated trailing slashes stripped", "http://localhost:11434/v1///", "http://localhost:11434/v1"},
		{"whitespace trimmed", "  https://api.deepseek.com  ", "https://api.deepseek.com"},
		{"empty stays empty", "  ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeBaseURL(tt.in); got != tt.want {
				t.Errorf("normalizeBaseURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidateBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"hosted https", "https://api.example.com/v1", false},
		{"local http with port", "http://localhost:11434/v1", false},
		{"domain root", "https://api.deepseek.com", false},
		{"trailing slash tolerated", "http://localhost:8000/v1/", false},
		{"empty rejected", "  ", true},
		{"missing scheme rejected", "localhost:11434/v1", true},
		{"bare host rejected", "api.example.com/v1", true},
		{"non-http scheme rejected", "ftp://api.example.com/v1", true},
		{"no host rejected", "https://", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBaseURL(tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateBaseURL(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
		})
	}
}

func TestLookupEnvDefault(t *testing.T) {
	t.Run("the .env file wins over the shell", func(t *testing.T) {
		t.Setenv("OPENAI_BASE_URL", "http://shell:1/v1")
		env := config.EnvFromMap(map[string]string{"OPENAI_BASE_URL": "http://dotenv:1/v1"})
		if got := lookupEnvDefault(env, "OPENAI_BASE_URL"); got != "http://dotenv:1/v1" {
			t.Errorf("got %q, want the .env value", got)
		}
	})
	t.Run("an exported shell value pre-fills the interview", func(t *testing.T) {
		t.Setenv("OPENAI_API_KEY", "sk-shell")
		if got := lookupEnvDefault(config.EnvFromMap(nil), "OPENAI_API_KEY"); got != "sk-shell" {
			t.Errorf("got %q, want the shell value", got)
		}
	})
	t.Run("absent everywhere is empty", func(t *testing.T) {
		t.Setenv("ARGUS_TEST_ABSENT", "")
		if got := lookupEnvDefault(config.EnvFromMap(nil), "ARGUS_TEST_ABSENT"); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
}

func TestDefaultProviderType(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{"empty config offers gemini", &config.Config{}, provider.TypeGemini},
		{
			"a sole openai-compatible entry is kept on re-run",
			&config.Config{Providers: map[string]config.ProviderConfig{
				"openai-compatible": {Type: provider.TypeOpenAICompatible},
			}},
			provider.TypeOpenAICompatible,
		},
		{
			"a sole gemini entry",
			&config.Config{Providers: map[string]config.ProviderConfig{
				"gemini": {Type: provider.TypeGemini},
			}},
			provider.TypeGemini,
		},
		{
			"ambiguous config falls back to gemini",
			&config.Config{Providers: map[string]config.ProviderConfig{
				"gemini": {Type: provider.TypeGemini},
				"local":  {Type: provider.TypeOpenAICompatible},
			}},
			provider.TypeGemini,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := defaultProviderType(tt.cfg); got != tt.want {
				t.Errorf("defaultProviderType() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestProviderEntryYAML pins the providers: entry init writes, as YAML: no
// `url` for the default endpoint, no `api_key` when the endpoint needs none,
// and the key as an env() reference so no secret ever lands in the file.
func TestProviderEntryYAML(t *testing.T) {
	tests := []struct {
		name   string
		picked providerSelection
		want   string
	}{
		{
			name:   "local runtime, no key",
			picked: providerSelection{Provider: provider.TypeOpenAICompatible, Model: "qwen3:8b", BaseURL: "http://localhost:11434/v1"},
			want: "type: openai-compatible\n" +
				"url: http://localhost:11434/v1\n",
		},
		{
			name:   "hosted service with a key",
			picked: providerSelection{Provider: provider.TypeOpenAICompatible, Model: "openai/gpt-4o-mini", BaseURL: "https://openrouter.ai/api/v1", APIKey: "sk-secret"},
			want: "type: openai-compatible\n" +
				"api_key: env(OPENAI_API_KEY)\n" +
				"url: https://openrouter.ai/api/v1\n",
		},
		{
			name:   "OpenAI itself: the default endpoint is the absence of url",
			picked: providerSelection{Provider: provider.TypeOpenAICompatible, Model: "gpt-4o-mini", APIKey: "sk-secret"},
			want: "type: openai-compatible\n" +
				"api_key: env(OPENAI_API_KEY)\n",
		},
		{
			name:   "gemini is unchanged",
			picked: providerSelection{Provider: provider.TypeGemini, Model: "gemini-2.5-flash", APIKey: "AIza-secret"},
			want: "type: gemini\n" +
				"api_key: env(GEMINI_API_KEY)\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := yaml.Marshal(providerEntry(tt.picked))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(out) != tt.want {
				t.Errorf("provider entry YAML =\n%s\nwant\n%s", out, tt.want)
			}
			if strings.Contains(string(out), tt.picked.APIKey) && tt.picked.APIKey != "" {
				t.Errorf("the secret leaked into the YAML:\n%s", out)
			}
		})
	}
}

func TestConfiguredBaseURL(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{"no providers", &config.Config{}, ""},
		{
			"literal url on the compatible entry",
			&config.Config{Providers: map[string]config.ProviderConfig{
				"openai-compatible": {Type: provider.TypeOpenAICompatible, URL: "http://localhost:11434/v1"},
			}},
			"http://localhost:11434/v1",
		},
		{
			"gemini entries carry no user-selectable endpoint",
			&config.Config{Providers: map[string]config.ProviderConfig{
				"gemini": {Type: provider.TypeGemini, URL: "http://ignored/v1"},
			}},
			"",
		},
		{
			"an unresolvable env() reference is skipped rather than written back",
			&config.Config{Providers: map[string]config.ProviderConfig{
				"openai-compatible": {Type: provider.TypeOpenAICompatible, URL: "env(ARGUS_TEST_UNSET_BASE_URL)"},
			}},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := configuredBaseURL(tt.cfg); got != tt.want {
				t.Errorf("configuredBaseURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

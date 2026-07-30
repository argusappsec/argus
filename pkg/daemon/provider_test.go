package daemon

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/provider"
)

// TestProviderSpecForModel covers the mapping from a configured Provider onto
// the Spec that constructs it: the type selects the implementation, env()
// indirection is resolved before the Provider ever sees a secret or an endpoint,
// and a qualified model id resolves to a Provider while the *bare* id is what
// travels to the wire.
func TestProviderSpecForModel(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		cfg     *config.Config
		modelID string
		want    provider.Spec
	}{
		{
			// The common case, unchanged by qualification: one Gemini entry, a
			// bare model id, a key held in the environment.
			name: "gemini entry with an env() key",
			env:  map[string]string{"GEMINI_API_KEY": "gem-secret"},
			cfg: &config.Config{Providers: map[string]config.ProviderConfig{
				"gemini": {Type: provider.TypeGemini, APIKey: "env(GEMINI_API_KEY)"},
			}},
			modelID: "gemini-2.5-flash",
			want: provider.Spec{
				Type:   provider.TypeGemini,
				APIKey: "gem-secret",
				Model:  "gemini-2.5-flash",
			},
		},
		{
			// An absent url is not a missing setting: it means "the Provider's
			// own default endpoint", and travels as an empty BaseURL so the
			// implementation — not this mapping — decides what that is.
			name: "openai-compatible entry without a url defers to the provider default",
			env:  map[string]string{"OPENAI_API_KEY": "sk-secret"},
			cfg: &config.Config{Providers: map[string]config.ProviderConfig{
				"openai": {Type: provider.TypeOpenAICompatible, APIKey: "env(OPENAI_API_KEY)"},
			}},
			modelID: "gpt-4o-mini",
			want: provider.Spec{
				Type:    provider.TypeOpenAICompatible,
				APIKey:  "sk-secret",
				BaseURL: "",
				Model:   "gpt-4o-mini",
			},
		},
		{
			name: "url and output ceiling are carried, url through env() too",
			env:  map[string]string{"OPENAI_BASE_URL": "http://localhost:11434/v1"},
			cfg: &config.Config{Providers: map[string]config.ProviderConfig{
				"local": {Type: provider.TypeOpenAICompatible, URL: "env(OPENAI_BASE_URL)", MaxOutputTokens: 8192},
			}},
			modelID: "qwen2.5-coder",
			want: provider.Spec{
				Type:            provider.TypeOpenAICompatible,
				BaseURL:         "http://localhost:11434/v1",
				Model:           "qwen2.5-coder",
				MaxOutputTokens: 8192,
			},
		},
		{
			// The qualified form is how an operator with two Providers names
			// one. Only the bare id belongs on the wire: the endpoint has never
			// heard of Argus's Provider names.
			name: "a qualified model id picks the provider and sends the bare id",
			env:  map[string]string{"OPENAI_API_KEY": "sk-secret"},
			cfg: &config.Config{Providers: map[string]config.ProviderConfig{
				"gemini":   {Type: provider.TypeGemini, APIKey: "env(GEMINI_API_KEY)"},
				"together": {Type: provider.TypeOpenAICompatible, APIKey: "env(OPENAI_API_KEY)", URL: "https://api.together.ai/v1"},
			}},
			modelID: "together/meta-llama/Llama-3.3-70B-Instruct-Turbo",
			want: provider.Spec{
				Type:    provider.TypeOpenAICompatible,
				APIKey:  "sk-secret",
				BaseURL: "https://api.together.ai/v1",
				// Split on the first slash only: the model id keeps its own.
				Model: "meta-llama/Llama-3.3-70B-Instruct-Turbo",
			},
		},
		{
			// User story 8: upgrading Argus must not force anyone to touch a
			// working setup. An install that exported the key and never ran
			// `argus init` has no providers: block to resolve against.
			name:    "no providers configured falls back to GEMINI_API_KEY",
			env:     map[string]string{"GEMINI_API_KEY": "gem-secret"},
			cfg:     &config.Config{},
			modelID: "gemini-2.5-flash",
			want: provider.Spec{
				Type:   provider.TypeGemini,
				APIKey: "gem-secret",
				Model:  "gemini-2.5-flash",
			},
		},
		{
			// Same fallback, qualified id: the bare half is still what reaches
			// the wire. Nothing else would split it here — there is no
			// providers: block to resolve against — and Google has never heard
			// of a model called "gemini/gemini-2.5-flash".
			name:    "the fallback strips a gemini/ qualification too",
			env:     map[string]string{"GEMINI_API_KEY": "gem-secret"},
			cfg:     &config.Config{},
			modelID: "gemini/gemini-2.5-flash",
			want: provider.Spec{
				Type:   provider.TypeGemini,
				APIKey: "gem-secret",
				Model:  "gemini-2.5-flash",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			got, err := ProviderSpecForModel(tt.cfg, tt.modelID)
			if err != nil {
				t.Fatalf("ProviderSpecForModel(%q) = error %v", tt.modelID, err)
			}
			if got != tt.want {
				t.Errorf("ProviderSpecForModel(%q) = %+v, want %+v", tt.modelID, got, tt.want)
			}
		})
	}
}

// TestProviderSpecForModelUnresolvableModelDoesNotFallBackToGemini is the regression
// guard for the bug the Provider work exists to close: with providers
// configured, an unresolvable model id must report *that*, never quietly build a
// Gemini client because GEMINI_API_KEY happens to be exported. Being connected
// to a different Provider than the one you asked for is the failure mode that
// points the operator at the wrong problem.
func TestProviderSpecForModelUnresolvableModelDoesNotFallBackToGemini(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "gem-secret")
	cfg := &config.Config{Providers: map[string]config.ProviderConfig{
		"openai": {Type: provider.TypeOpenAICompatible, APIKey: "env(OPENAI_API_KEY)"},
		"groq":   {Type: provider.TypeOpenAICompatible, APIKey: "env(GROQ_API_KEY)"},
	}}

	spec, err := ProviderSpecForModel(cfg, "no-such-model")
	if err == nil {
		t.Fatalf("ProviderSpecForModel resolved an unknown model to %+v, want an error", spec)
	}
	// The message config already writes names the candidates and the qualified
	// form to write instead; it must survive rather than be flattened.
	if !strings.Contains(err.Error(), "no-such-model") {
		t.Errorf("error %q does not name the model", err)
	}
}

// TestProviderSpecForModelNoProviderAndNoKey: nothing configured and nothing exported is
// the pre-`argus init` state, and must say so rather than construct a Provider
// with an empty key.
func TestProviderSpecForModelNoProviderAndNoKey(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "")
	if spec, err := ProviderSpecForModel(&config.Config{}, "gemini-2.5-flash"); err == nil {
		t.Fatalf("ProviderSpecForModel with no configuration returned %+v, want an error", spec)
	}
}

// TestProviderSpecForModelEnvKeyMissingIsAnError: an env() reference to a variable that
// is not set is a misconfiguration, and surfaces here rather than as a 401 from
// the endpoint.
func TestProviderSpecForModelEnvKeyMissingIsAnError(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	cfg := &config.Config{Providers: map[string]config.ProviderConfig{
		"openai": {Type: provider.TypeOpenAICompatible, APIKey: "env(OPENAI_API_KEY)"},
	}}
	if spec, err := ProviderSpecForModel(cfg, "gpt-4o-mini"); err == nil {
		t.Fatalf("ProviderSpecForModel with an unset env() key returned %+v, want an error", spec)
	}
}

// TestProviderFactoryHonoursTheConfiguredType is the regression guard for the bug
// this work exists to close: the daemon used to build a Gemini client whatever
// `type` said, so an openai-compatible entry silently talked to Google and failed
// with an authentication error that pointed at the wrong problem. A Session's
// Provider must reach the endpoint the entry configured.
func TestProviderFactoryHonoursTheConfiguredType(t *testing.T) {
	// Exported on purpose: even with a Gemini key in the environment, a
	// configured openai-compatible entry must win.
	t.Setenv("GEMINI_API_KEY", "gem-secret")

	var reached bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"hello"}}]}`)
	}))
	defer srv.Close()

	cfg := &config.Config{Providers: map[string]config.ProviderConfig{
		"local": {Type: provider.TypeOpenAICompatible, URL: srv.URL},
	}}

	prov, err := providerFactory(cfg)(context.Background(), "local/qwen2.5-coder")
	if err != nil {
		t.Fatalf("providerFactory: %v", err)
	}
	resp, err := prov.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !reached {
		t.Error("the configured endpoint was never called")
	}
	if resp.Text != "hello" {
		t.Errorf("response text = %q, want %q", resp.Text, "hello")
	}
}

// TestProviderFactoryUnknownTypeFails: a mistyped `type` must stop Session
// creation with a message naming what Argus supports, rather than hand the
// Session some other Provider.
func TestProviderFactoryUnknownTypeFails(t *testing.T) {
	cfg := &config.Config{Providers: map[string]config.ProviderConfig{
		"openai": {Type: "openai"},
	}}
	_, err := providerFactory(cfg)(context.Background(), "gpt-4o-mini")
	if err == nil {
		t.Fatal("providerFactory built a Provider for an unknown type")
	}
	for _, want := range []string{`"openai"`, "gemini", "openai-compatible"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

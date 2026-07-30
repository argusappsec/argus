package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/provider"
	"github.com/argusappsec/argus/pkg/provider/factory"
)

// writeDoctorHome writes an argus.yaml carrying yaml into a temp home and returns
// the home path.
func writeDoctorHome(t *testing.T, yaml string) string {
	t.Helper()
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "argus.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

func TestToolCallProbeRequest_AsksForExactlyOneThrowawayTool(t *testing.T) {
	req := toolCallProbeRequest()
	if len(req.Tools) != 1 {
		t.Fatalf("len(Tools) = %d, want 1: the probe must cost the operator as close to nothing as a generation can", len(req.Tools))
	}
	if len(req.Messages) != 1 {
		t.Errorf("len(Messages) = %d, want 1", len(req.Messages))
	}
	if !strings.Contains(req.Messages[0].Content, req.Tools[0].Name) {
		t.Errorf("the prompt should ask for the declared tool by name: %q vs %q", req.Messages[0].Content, req.Tools[0].Name)
	}
	if req.Tools[0].Schema["type"] != "object" {
		t.Errorf("the throwaway tool needs an object schema, got %v", req.Tools[0].Schema["type"])
	}
}

// TestProviderDoctorOptions_ProbesTheConfiguredEndpoint exercises the whole
// wiring against a stand-in endpoint: config → provider.Spec → factory → the two
// injected probes. It is the seam most likely to break silently, because each
// half compiles perfectly well while pointing at the wrong Provider.
func TestProviderDoctorOptions_ProbesTheConfiguredEndpoint(t *testing.T) {
	var sawToolDecls bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/models":
			_, _ = io.WriteString(w, `{"data":[{"id":"llama3.2:3b"},{"id":"tiny-model"}]}`)
		case "/v1/chat/completions":
			var body struct {
				Tools []any `json:"tools"`
			}
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &body)
			sawToolDecls = len(body.Tools) > 0
			_, _ = io.WriteString(w, `{"choices":[{"message":{"tool_calls":[{"id":"c1","type":"function","function":{"name":"argus_probe","arguments":"{\"ok\":true}"}}]}}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	home := writeDoctorHome(t, "providers:\n  local:\n    type: openai-compatible\n    url: "+srv.URL+"/v1\ndefault_model: tiny-model\n")

	target, models, toolCall := providerDoctorOptions(home)
	if target == nil {
		t.Fatal("no target: doctor would grow no provider row for a perfectly good config")
	}
	if target.Type != provider.TypeOpenAICompatible || target.Model != "tiny-model" {
		t.Errorf("target = %+v, want the openai-compatible provider backing default_model", target)
	}
	if target.Endpoint != srv.URL+"/v1" {
		t.Errorf("Endpoint = %q, want the configured base URL", target.Endpoint)
	}

	got, err := models(context.Background())
	if err != nil {
		t.Fatalf("models: %v", err)
	}
	if !slices.Contains(got, "tiny-model") {
		t.Errorf("models = %v, should carry the ids GET /models reported", got)
	}

	called, err := toolCall(context.Background())
	if err != nil {
		t.Fatalf("toolCall: %v", err)
	}
	if !called {
		t.Error("a response carrying a tool call must be reported as one")
	}
	if !sawToolDecls {
		t.Error("the probe generation must actually declare a tool: a 200 with no declarations proves nothing")
	}
}

func TestProviderDoctorOptions_ReportsToolDeclarationsIgnored(t *testing.T) {
	// The common local small-model failure: the declarations are accepted, the
	// answer is prose. A 200 is not a pass.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/models" {
			_, _ = io.WriteString(w, `{"data":[{"id":"tiny-model"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"Certainly! I will call it."}}]}`)
	}))
	defer srv.Close()

	home := writeDoctorHome(t, "providers:\n  local:\n    type: openai-compatible\n    url: "+srv.URL+"/v1\ndefault_model: tiny-model\n")
	_, _, toolCall := providerDoctorOptions(home)
	called, err := toolCall(context.Background())
	if err != nil {
		t.Fatalf("toolCall: %v", err)
	}
	if called {
		t.Error("prose with no tool call must not be reported as a tool call")
	}
}

func TestProviderDoctorOptions_GeminiGetsNoProbes(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "stub-key")
	home := writeDoctorHome(t, "providers:\n  gemini:\n    type: gemini\n    api_key: env(GEMINI_API_KEY)\ndefault_model: gemini-2.5-flash\n")

	target, models, toolCall := providerDoctorOptions(home)
	if target == nil || target.Type != provider.TypeGemini {
		t.Fatalf("target = %+v, want a gemini target so doctor can say why it was not probed", target)
	}
	if models != nil || toolCall != nil {
		t.Error("a gemini target must carry no probes: it has no /models endpoint, and a generation would spend tokens on a capability that is not in question")
	}
}

func TestProviderDoctorOptions_NamesTheDefaultEndpointWhenNoURLIsSet(t *testing.T) {
	// `url` is optional and defaults to the OpenAI public endpoint, so the row has
	// to name the endpoint being probed rather than show a blank.
	t.Setenv("OPENAI_API_KEY", "stub-key")
	home := writeDoctorHome(t, "providers:\n  openai:\n    type: openai-compatible\n    api_key: env(OPENAI_API_KEY)\ndefault_model: gpt-4o-mini\n")

	target, _, _ := providerDoctorOptions(home)
	if target == nil {
		t.Fatal("no target")
	}
	if target.Endpoint != factory.DefaultOpenAICompatibleBaseURL {
		t.Errorf("Endpoint = %q, want %q", target.Endpoint, factory.DefaultOpenAICompatibleBaseURL)
	}
}

func TestProviderDoctorOptions_NoTargetWhenTheModelResolvesToNoProvider(t *testing.T) {
	// Nothing to probe and nothing to name: the argus.yaml row owns config
	// problems, the same way the github and front-door helpers hand them over —
	// and it blocks on this one, so the absent probe row cannot read as a pass
	// (see TestRun_BlocksWhenDefaultModelResolvesToNoProvider).
	t.Setenv("GEMINI_API_KEY", "")
	home := writeDoctorHome(t, "providers:\n  a:\n    type: openai-compatible\n    url: http://a.invalid/v1\n  b:\n    type: openai-compatible\n    url: http://b.invalid/v1\ndefault_model: some-model\n")

	target, models, toolCall := providerDoctorOptions(home)
	if target != nil || models != nil || toolCall != nil {
		t.Errorf("target/models/toolCall = %+v/%v/%v, want all nil for an unresolvable default_model", target, models != nil, toolCall != nil)
	}
}

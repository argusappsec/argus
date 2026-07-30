package factory_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/provider"
	"github.com/argusappsec/argus/pkg/provider/factory"
)

// TestNewUnknownTypeNamesSupportedTypes is the whole point of having a factory:
// a mistyped type must fail with a message that says what to write instead.
// Before the switch existed, `type: openai` silently built a Gemini client and
// failed later, elsewhere, pointing the operator at the wrong problem.
func TestNewUnknownTypeNamesSupportedTypes(t *testing.T) {
	_, err := factory.New(context.Background(), provider.Spec{
		// The near-miss an operator actually types: the type names a protocol,
		// so the supported value is the longer "openai-compatible".
		Type:  "openai",
		Model: "gpt-4o-mini",
	})
	if err == nil {
		t.Fatal("New with an unknown provider type returned no error")
	}
	msg := err.Error()
	// The literals are spelled out rather than read from the constants: what is
	// under test is that the operator is told which strings argus.yaml accepts.
	for _, want := range []string{`"openai"`, "gemini", "openai-compatible"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not name %q", msg, want)
		}
	}
}

// TestNewOpenAICompatibleGenerates asserts the compatible type yields a Provider
// that actually generates against the endpoint and model the Spec named. It
// asserts behaviour rather than a concrete type: what matters is that a working
// Provider came back configured as asked, not which struct it is.
func TestNewOpenAICompatibleGenerates(t *testing.T) {
	var gotPath, gotModel, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(body, &req)
		gotModel = req.Model
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"pong"}}]}`)
	}))
	defer srv.Close()

	prov, err := factory.New(context.Background(), provider.Spec{
		Type:    provider.TypeOpenAICompatible,
		APIKey:  "sk-test",
		BaseURL: srv.URL,
		Model:   "some-model",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	resp, err := prov.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{{Role: "user", Content: "ping"}},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if resp.Text != "pong" {
		t.Errorf("response text = %q, want %q", resp.Text, "pong")
	}
	if gotPath != "/chat/completions" {
		t.Errorf("request path = %q, want %q", gotPath, "/chat/completions")
	}
	if gotModel != "some-model" {
		t.Errorf("model on the wire = %q, want %q", gotModel, "some-model")
	}
	if gotAuth != "Bearer sk-test" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer sk-test")
	}
}

// TestNewGeminiYieldsUsableProvider asserts the gemini type yields a live
// Provider. There is no endpoint to stand in for Google here, so the behaviour
// asserted is the most that can be without one: Generate runs and reports a
// failure through the error return. A Provider that was never constructed — or
// one built around a nil client — cannot do that.
func TestNewGeminiYieldsUsableProvider(t *testing.T) {
	prov, err := factory.New(context.Background(), provider.Spec{
		Type:   provider.TypeGemini,
		APIKey: "test-key",
		Model:  "gemini-2.5-flash",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if prov == nil {
		t.Fatal("New returned a nil Provider and no error")
	}

	// A cancelled context keeps the test off the network while still going
	// through the client the factory built.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := prov.Generate(ctx, provider.Request{
		Messages: []provider.Message{{Role: "user", Content: "ping"}},
	}); err == nil {
		t.Error("Generate on a cancelled context returned no error")
	}
}

// TestNewRejectsNegativeOutputCeiling: zero means "send no ceiling", so a
// negative value is a mistake nothing else in the stack would catch — the
// adapter simply omits the field again and the operator never learns their
// ceiling was ignored.
func TestNewRejectsNegativeOutputCeiling(t *testing.T) {
	for _, providerType := range []string{provider.TypeGemini, provider.TypeOpenAICompatible} {
		t.Run(providerType, func(t *testing.T) {
			_, err := factory.New(context.Background(), provider.Spec{
				Type:            providerType,
				APIKey:          "test-key",
				Model:           "some-model",
				MaxOutputTokens: -1,
			})
			if err == nil {
				t.Fatal("New with a negative output ceiling returned no error")
			}
			if !strings.Contains(err.Error(), "max_output_tokens") {
				t.Errorf("error %q does not name the setting at fault", err)
			}
		})
	}
}

// TestNewZeroOutputCeilingIsAccepted pins the other half of that rule: zero is
// the default, and must stay valid rather than be mistaken for "unset and
// therefore wrong".
func TestNewZeroOutputCeilingIsAccepted(t *testing.T) {
	if _, err := factory.New(context.Background(), provider.Spec{
		Type:            provider.TypeOpenAICompatible,
		BaseURL:         "http://localhost:11434/v1",
		Model:           "some-model",
		MaxOutputTokens: 0,
	}); err != nil {
		t.Fatalf("New with a zero output ceiling: %v", err)
	}
}

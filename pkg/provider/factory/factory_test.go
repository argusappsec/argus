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
	for _, providerType := range []string{provider.TypeGemini, provider.TypeOpenAICompatible} {
		t.Run(providerType, func(t *testing.T) {
			prov, err := factory.New(context.Background(), provider.Spec{
				Type:            providerType,
				APIKey:          "test-key",
				Model:           "some-model",
				MaxOutputTokens: 0,
			})
			if err != nil {
				t.Fatalf("New with a zero output ceiling: %v", err)
			}
			// A Provider, not merely the absence of an error: "zero is valid"
			// has to mean a Provider came back, or a nil-and-no-error return
			// would satisfy the rule too.
			if prov == nil {
				t.Fatal("New returned a nil Provider and no error")
			}
		})
	}
}

// TestNewRejectsOutputCeilingOnGemini: the Gemini client accepts no output
// ceiling, so a gemini Spec carrying one used to be dropped on the floor here —
// and a ceiling that is silently dropped delivers exactly the failure the field
// exists to prevent, a Report truncated mid-write with nothing to explain it.
// Failing at construction is the only place the operator can still connect the
// symptom to the key they wrote.
func TestNewRejectsOutputCeilingOnGemini(t *testing.T) {
	_, err := factory.New(context.Background(), provider.Spec{
		Type:            provider.TypeGemini,
		APIKey:          "test-key",
		Model:           "gemini-2.5-flash",
		MaxOutputTokens: 8192,
	})
	if err == nil {
		t.Fatal("New with an output ceiling on a gemini spec returned no error")
	}
	msg := err.Error()
	// Both halves have to be in the message: the key to delete, and the entry
	// to delete it from. Naming one without the other leaves the operator
	// guessing on a config file that may hold several Providers.
	for _, want := range []string{"max_output_tokens", "gemini"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not name %q", msg, want)
		}
	}
}

// TestNewCarriesOutputCeilingToTheWire is the counterweight to the rejection
// above: the ceiling is rejected because gemini cannot honour it, not because
// the factory has stopped carrying it. On the compatible type it must still
// reach the endpoint.
func TestNewCarriesOutputCeilingToTheWire(t *testing.T) {
	var gotMaxTokens *int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			MaxTokens *int `json:"max_tokens"`
		}
		_ = json.Unmarshal(body, &req)
		gotMaxTokens = req.MaxTokens
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"pong"}}]}`)
	}))
	defer srv.Close()

	prov, err := factory.New(context.Background(), provider.Spec{
		Type:            provider.TypeOpenAICompatible,
		BaseURL:         srv.URL,
		Model:           "some-model",
		MaxOutputTokens: 4096,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := prov.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{{Role: "user", Content: "ping"}},
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if gotMaxTokens == nil {
		t.Fatal("no output ceiling reached the endpoint")
	}
	if *gotMaxTokens != 4096 {
		t.Errorf("output ceiling on the wire = %d, want %d", *gotMaxTokens, 4096)
	}
}

// TestSwitchAndIsKnownTypeAgree guards the one duplication the import cycle
// forced: New's switch and provider.IsKnownType are the same vocabulary written
// twice, and Go offers no way to derive one from the other across that boundary.
// Both package docs say to treat them as one edit; this is what notices when
// somebody doesn't.
//
// The failure it catches is quiet in both directions. A type added to the switch
// but not to IsKnownType constructs a working Provider that `argus doctor` then
// calls unimplemented. A type added to IsKnownType but not to the switch passes
// every doctor check and fails at the first Session, in the one place the
// factory exists to stop failing.
//
// It asserts on the "unknown type" verdict rather than on New succeeding,
// because a known type may legitimately fail for its own reasons — a bad
// endpoint, a rejected key. What must never disagree is whether the type is one
// Argus implements.
func TestSwitchAndIsKnownTypeAgree(t *testing.T) {
	// Near-misses an operator actually types, plus the two real ones. `ollama`
	// and `openai` are the two the old reserved-type list invited (ADR 0020).
	for _, providerType := range []string{
		provider.TypeGemini,
		provider.TypeOpenAICompatible,
		"openai",
		"ollama",
		"anthropic",
		"",
		"GEMINI",
		"openai-compatible ", // trailing space: a YAML quoting slip
	} {
		t.Run("type="+providerType, func(t *testing.T) {
			_, err := factory.New(context.Background(), provider.Spec{
				Type:   providerType,
				APIKey: "test-key",
				Model:  "some-model",
			})
			// New's default case is the only thing that says "unknown type".
			rejectedAsUnknown := err != nil && strings.Contains(err.Error(), "unknown type")

			if known := provider.IsKnownType(providerType); known == rejectedAsUnknown {
				if known {
					t.Errorf("IsKnownType(%q) is true but New rejected it as an unknown type (%v): the switch is missing a case", providerType, err)
				} else {
					t.Errorf("IsKnownType(%q) is false but New did not reject it as an unknown type (err=%v): IsKnownType is missing a case", providerType, err)
				}
			}
		})
	}
}

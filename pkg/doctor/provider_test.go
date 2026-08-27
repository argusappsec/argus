package doctor_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/deployment"
	"github.com/argusappsec/argus/pkg/doctor"
	"github.com/argusappsec/argus/pkg/provider"
)

// These tests substitute the injected probe functions, exactly as the GitHub
// mint and front-door probe tests do. They assert on what the user is *told*:
// the three failure modes below (endpoint unreachable / model not served /
// model ignores tools) send an operator to three different fixes, so a message
// that fails to tell them apart is the defect worth testing for.

const (
	probeModel    = "tiny-model"
	probeEndpoint = "http://localhost:11434/v1"
)

func compatTarget() *doctor.ProviderTarget {
	return &doctor.ProviderTarget{
		Type:     provider.TypeOpenAICompatible,
		Model:    probeModel,
		Endpoint: probeEndpoint,
	}
}

// providerRow runs doctor against a target and returns the provider row, failing
// the test when there is none.
func providerRow(t *testing.T, opts doctor.Options) doctor.Check {
	t.Helper()
	if opts.Home == "" {
		opts.Home = t.TempDir()
	}
	c := findCheck(doctor.Run(opts), "llm provider")
	if c == nil {
		t.Fatal("no llm provider check produced")
	}
	return *c
}

func TestProviderCheck_AbsentWhenNoTarget(t *testing.T) {
	checks := doctor.Run(doctor.Options{Home: t.TempDir()}) // Provider nil
	if findCheck(checks, "llm provider") != nil {
		t.Error("provider row must be absent when the caller supplied no target")
	}
}

func TestProviderCheck_NotProbedWhenProbesAbsent(t *testing.T) {
	c := providerRow(t, doctor.Options{Provider: compatTarget()})
	if c.Status != doctor.Info {
		t.Fatalf("status = %v, want Info when nothing was injected (%s / %s)", c.Status, c.Message, c.Hint)
	}
	if c.Severity != doctor.SeverityInfo {
		t.Errorf("severity = %v, want SeverityInfo", c.Severity)
	}
	for _, want := range []string{probeModel, probeEndpoint, "not probed"} {
		if !strings.Contains(c.Message, want) {
			t.Errorf("message %q should contain %q", c.Message, want)
		}
	}
}

func TestProviderCheck_GeminiIsReportedAsNotApplicable(t *testing.T) {
	listCalled, toolCalled := false, false
	c := providerRow(t, doctor.Options{
		Provider: &doctor.ProviderTarget{Type: provider.TypeGemini, Model: "gemini-2.5-flash"},
		ProviderModels: func(context.Context) ([]string, error) {
			listCalled = true
			return nil, nil
		},
		ProviderToolCall: func(context.Context) (bool, error) {
			toolCalled = true
			return true, nil
		},
	})
	if listCalled || toolCalled {
		t.Error("a gemini target must not be probed: there is no /models endpoint, and a generation would spend tokens to confirm a capability that is not in question")
	}
	if c.Status != doctor.Info || c.Severity != doctor.SeverityInfo {
		t.Fatalf("status/severity = %v/%v, want Info/SeverityInfo (%s)", c.Status, c.Severity, c.Message)
	}
	if !strings.Contains(c.Message, provider.TypeGemini) || !strings.Contains(c.Message, "gemini-2.5-flash") {
		t.Errorf("message should name the type and model: %q", c.Message)
	}
	if !strings.Contains(c.Message, provider.TypeOpenAICompatible) {
		t.Errorf("message should say which type the probe applies to: %q", c.Message)
	}
}

func TestProviderCheck_UnknownTypeFailsNamingTheSupportedOnes(t *testing.T) {
	c := providerRow(t, doctor.Options{
		Provider: &doctor.ProviderTarget{Type: "openai", Model: "gpt-4o"},
	})
	if c.Status != doctor.Fail || c.Severity != doctor.SeverityRequired {
		t.Fatalf("status/severity = %v/%v, want Fail/SeverityRequired (%s)", c.Status, c.Severity, c.Hint)
	}
	for _, want := range []string{`"openai"`, provider.TypeOpenAICompatible, provider.TypeGemini} {
		if !strings.Contains(c.Hint, want) {
			t.Errorf("hint %q should contain %q", c.Hint, want)
		}
	}
}

func TestProviderCheck_UnreachableEndpointFails(t *testing.T) {
	c := providerRow(t, doctor.Options{
		Provider: compatTarget(),
		ProviderModels: func(context.Context) ([]string, error) {
			return nil, errors.New("dial tcp 127.0.0.1:11434: connect: connection refused")
		},
		ProviderToolCall: func(context.Context) (bool, error) {
			t.Error("the tool-calling probe must not run once the endpoint is unreachable: it would spend tokens on a question already answered")
			return false, nil
		},
	})
	if c.Status != doctor.Fail || c.Severity != doctor.SeverityRequired {
		t.Fatalf("status/severity = %v/%v, want Fail/SeverityRequired (%s)", c.Status, c.Severity, c.Hint)
	}
	for _, want := range []string{"/models", probeEndpoint, "connection refused", "url", "api_key"} {
		if !strings.Contains(c.Hint, want) {
			t.Errorf("hint %q should contain %q", c.Hint, want)
		}
	}
	// The three failure modes must not be confusable: this one is about the
	// endpoint, not about the model id or about tool calling.
	for _, unwanted := range []string{"tool call", "serves no model"} {
		if strings.Contains(c.Hint, unwanted) {
			t.Errorf("an unreachable endpoint must not be reported as %q: %q", unwanted, c.Hint)
		}
	}
}

func TestProviderCheck_ModelNotServedFails(t *testing.T) {
	c := providerRow(t, doctor.Options{
		Provider: compatTarget(),
		ProviderModels: func(context.Context) ([]string, error) {
			return []string{"llama3.2:3b", "qwen2.5-coder:7b"}, nil
		},
		ProviderToolCall: func(context.Context) (bool, error) {
			t.Error("the tool-calling probe must not run for a model the endpoint does not serve")
			return false, nil
		},
	})
	if c.Status != doctor.Fail || c.Severity != doctor.SeverityRequired {
		t.Fatalf("status/severity = %v/%v, want Fail/SeverityRequired (%s)", c.Status, c.Severity, c.Hint)
	}
	for _, want := range []string{probeModel, "llama3.2:3b", "qwen2.5-coder:7b", "default_model"} {
		if !strings.Contains(c.Hint, want) {
			t.Errorf("hint %q should contain %q", c.Hint, want)
		}
	}
	for _, unwanted := range []string{"tool call", "unreachable"} {
		if strings.Contains(c.Hint, unwanted) {
			t.Errorf("a missing model id must not be reported as %q: %q", unwanted, c.Hint)
		}
	}
}

func TestProviderCheck_ToolDeclarationsRejectedFails(t *testing.T) {
	// The adapter has already translated the server's client error into a plain
	// verdict and kept the server's own words after it; doctor's job is to say
	// which stage produced it and then get out of the way.
	rejection := errors.New(`openaicompat: model "tiny-model" at http://localhost:11434/v1: ` +
		`the endpoint rejected the request's tool declarations: this model does not support tool calling, ` +
		`which Argus needs for every Review (the endpoint said: registry.ollama.ai/library/tiny-model does not support tools)`)

	c := providerRow(t, doctor.Options{
		Provider:         compatTarget(),
		ProviderModels:   func(context.Context) ([]string, error) { return []string{probeModel}, nil },
		ProviderToolCall: func(context.Context) (bool, error) { return false, rejection },
	})
	if c.Status != doctor.Fail || c.Severity != doctor.SeverityRequired {
		t.Fatalf("status/severity = %v/%v, want Fail/SeverityRequired (%s)", c.Status, c.Severity, c.Hint)
	}
	if !strings.HasPrefix(c.Hint, "generation:") {
		t.Errorf("hint should name the stage that failed first: %q", c.Hint)
	}
	for _, want := range []string{
		"does not support tool calling", // the plain statement
		"does not support tools",        // the server's own words, preserved
	} {
		if !strings.Contains(c.Hint, want) {
			t.Errorf("hint %q should contain %q", c.Hint, want)
		}
	}
}

func TestProviderCheck_GenerationFailureIsNotBlamedOnToolCalling(t *testing.T) {
	// The adapter refuses to read a rate limit, a 5xx or a timeout as a missing
	// capability, precisely because "your model cannot call tools" would send the
	// operator to the wrong fix. This row must not re-attach that label.
	c := providerRow(t, doctor.Options{
		Provider:       compatTarget(),
		ProviderModels: func(context.Context) ([]string, error) { return []string{probeModel}, nil },
		ProviderToolCall: func(context.Context) (bool, error) {
			return false, errors.New("openaicompat: POST /chat/completions: status 429: rate limit exceeded")
		},
	})
	if c.Status != doctor.Fail {
		t.Fatalf("status = %v, want Fail", c.Status)
	}
	if !strings.Contains(c.Hint, "rate limit exceeded") {
		t.Errorf("hint should carry the server's own complaint: %q", c.Hint)
	}
	if strings.Contains(c.Hint, "tool calling:") || strings.Contains(c.Hint, "does not support") {
		t.Errorf("a failed generation must not be reported as a missing capability: %q", c.Hint)
	}
}

func TestProviderCheck_ToolCallNotEmittedFails(t *testing.T) {
	c := providerRow(t, doctor.Options{
		Provider:         compatTarget(),
		ProviderModels:   func(context.Context) ([]string, error) { return []string{probeModel}, nil },
		ProviderToolCall: func(context.Context) (bool, error) { return false, nil },
	})
	if c.Status != doctor.Fail || c.Severity != doctor.SeverityRequired {
		t.Fatalf("status/severity = %v/%v, want Fail/SeverityRequired (%s)", c.Status, c.Severity, c.Hint)
	}
	if !strings.HasPrefix(c.Hint, "tool calling:") {
		t.Errorf("hint should name the stage that failed first: %q", c.Hint)
	}
	for _, want := range []string{probeModel, probeEndpoint, "without calling it"} {
		if !strings.Contains(c.Hint, want) {
			t.Errorf("hint %q should contain %q", c.Hint, want)
		}
	}
	// A server that accepted the declarations and ignored them is a different
	// fact from one that refused them; neither may be reported as the other.
	if strings.Contains(c.Hint, "rejected") {
		t.Errorf("a silently ignored tool declaration must not be reported as a rejection: %q", c.Hint)
	}
}

func TestProviderCheck_FullSuccessPasses(t *testing.T) {
	c := providerRow(t, doctor.Options{
		Provider:         compatTarget(),
		ProviderModels:   func(context.Context) ([]string, error) { return []string{"llama3.2:3b", probeModel}, nil },
		ProviderToolCall: func(context.Context) (bool, error) { return true, nil },
	})
	if c.Status != doctor.Pass {
		t.Fatalf("status = %v, want Pass (%s / %s)", c.Status, c.Message, c.Hint)
	}
	for _, want := range []string{probeModel, probeEndpoint, "tool call"} {
		if !strings.Contains(c.Message, want) {
			t.Errorf("message %q should contain %q", c.Message, want)
		}
	}
}

func TestProviderCheck_EmptyModelListDoesNotConvictTheModelID(t *testing.T) {
	// A server that lists nothing has not said the model is absent. Reporting a
	// typo on that evidence would send the user to fix a correct model id.
	c := providerRow(t, doctor.Options{
		Provider:         compatTarget(),
		ProviderModels:   func(context.Context) ([]string, error) { return nil, nil },
		ProviderToolCall: func(context.Context) (bool, error) { return true, nil },
	})
	if c.Status != doctor.Pass {
		t.Fatalf("status = %v, want Pass (%s / %s)", c.Status, c.Message, c.Hint)
	}
	if !strings.Contains(c.Message, "could not be verified") {
		t.Errorf("message should say the model id went unverified: %q", c.Message)
	}
}

func TestProviderCheck_ToolProbeAbsentStillReportsTheListing(t *testing.T) {
	c := providerRow(t, doctor.Options{
		Provider:       compatTarget(),
		ProviderModels: func(context.Context) ([]string, error) { return []string{probeModel}, nil },
	})
	if c.Status != doctor.Pass {
		t.Fatalf("status = %v, want Pass (%s / %s)", c.Status, c.Message, c.Hint)
	}
	if !strings.Contains(c.Message, "not attempted") {
		t.Errorf("message should say the tool-calling probe did not run: %q", c.Message)
	}
}

func TestProviderCheck_MissingListingIsNotAnEmptyListing(t *testing.T) {
	// "Nobody asked" and "the endpoint answered with nothing" are different
	// facts, and only the second is about the endpoint.
	c := providerRow(t, doctor.Options{
		Provider:         compatTarget(),
		ProviderToolCall: func(context.Context) (bool, error) { return true, nil },
	})
	if c.Status != doctor.Pass {
		t.Fatalf("status = %v, want Pass (%s / %s)", c.Status, c.Message, c.Hint)
	}
	if !strings.Contains(c.Message, "not attempted") {
		t.Errorf("message should say the listing was never asked for: %q", c.Message)
	}
	if strings.Contains(c.Message, "lists nothing") {
		t.Errorf("an unasked question must not be reported as an empty answer: %q", c.Message)
	}
}

// --- API key severity matrix ------------------------------------------------

// writeProviders writes an argus.yaml carrying the given providers block and
// returns the home directory holding it.
func writeProviders(t *testing.T, defaultModel string, providers map[string]config.ProviderConfig) string {
	t.Helper()
	home := t.TempDir()
	cfg := &config.Config{Providers: providers, DefaultModel: defaultModel}
	if err := config.SaveConfig(filepath.Join(home, "argus.yaml"), cfg); err != nil {
		t.Fatal(err)
	}
	return home
}

func TestAPIKeyCheck_GeminiWithoutKeyStillBlocks(t *testing.T) {
	home := writeProviders(t, "gemini-2.5-flash", map[string]config.ProviderConfig{
		"gemini": {Type: provider.TypeGemini},
	})
	t.Setenv("PATH", "")

	checks := doctor.Run(doctor.Options{Home: home})
	c := findCheck(checks, "gemini api key")
	if c == nil {
		t.Fatal("no api key row for the gemini provider")
	}
	if c.Status != doctor.Fail || c.Severity != doctor.SeverityRequired {
		t.Fatalf("status/severity = %v/%v, want Fail/SeverityRequired: a Gemini provider with no key cannot make one call", c.Status, c.Severity)
	}
	if !doctor.Summarize(checks).HasBlockingFailure() {
		t.Error("a gemini provider with no api_key must be a blocking failure")
	}
}

func TestAPIKeyCheck_OpenAICompatibleWithoutKeyDoesNotBlock(t *testing.T) {
	// Story 5: a local runtime authenticates nobody, so there is no key to
	// supply — and doctor must not block an operator for a key they correctly
	// do not have.
	home := writeProviders(t, "llama3.2:3b", map[string]config.ProviderConfig{
		"local": {Type: provider.TypeOpenAICompatible, URL: "http://localhost:11434/v1"},
	})
	t.Setenv("PATH", "")
	t.Setenv("GEMINI_API_KEY", "")

	checks := doctor.Run(doctor.Options{Home: home})
	c := findCheck(checks, "local api key")
	if c == nil {
		t.Fatal("no api key row for the openai-compatible provider")
	}
	if c.Status == doctor.Fail {
		t.Errorf("an absent key must not fail for a type that legitimately needs none (%s)", c.Hint)
	}
	if c.Severity == doctor.SeverityRequired {
		t.Errorf("severity = SeverityRequired, want non-blocking")
	}
	if doctor.Summarize(checks).HasBlockingFailure() {
		for _, ch := range checks {
			if ch.Status == doctor.Fail && ch.Severity == doctor.SeverityRequired {
				t.Errorf("blocking failure on %q: %s", ch.Name, ch.Hint)
			}
		}
	}
	if findCheck(checks, "GEMINI_API_KEY") != nil {
		t.Error("an openai-compatible-only install must not be asked for a Gemini key")
	}
}

func TestAPIKeyCheck_DeclaredButUnresolvableReferenceBlocks(t *testing.T) {
	// Declaring a credential Argus cannot obtain is a broken config whatever the
	// type: provider construction hard-errors on it, so no Session can start.
	home := writeProviders(t, "gpt-4o-mini", map[string]config.ProviderConfig{
		"openai": {Type: provider.TypeOpenAICompatible, APIKey: config.EnvRef("OPENAI_API_KEY")},
	})
	t.Setenv("PATH", "")
	t.Setenv("OPENAI_API_KEY", "")

	checks := doctor.Run(doctor.Options{Home: home})
	c := findCheck(checks, "openai api key")
	if c == nil {
		t.Fatal("no api key row for the openai-compatible provider")
	}
	if c.Status != doctor.Fail || c.Severity != doctor.SeverityRequired {
		t.Fatalf("status/severity = %v/%v, want Fail/SeverityRequired for a declared key that does not resolve", c.Status, c.Severity)
	}
	if !strings.Contains(c.Hint, "OPENAI_API_KEY") {
		t.Errorf("hint should name the variable that is unset: %q", c.Hint)
	}
}

func TestAPIKeyCheck_ResolvedKeysPass(t *testing.T) {
	home := writeProviders(t, "gemini-2.5-flash", map[string]config.ProviderConfig{
		"gemini": {Type: provider.TypeGemini, APIKey: config.EnvRef("GEMINI_API_KEY")},
		"groq":   {Type: provider.TypeOpenAICompatible, APIKey: config.EnvRef("GROQ_KEY"), URL: "https://api.groq.com/openai/v1"},
	})
	t.Setenv("PATH", "")
	t.Setenv("GEMINI_API_KEY", "g-key")
	t.Setenv("GROQ_KEY", "q-key")

	checks := doctor.Run(doctor.Options{Home: home})
	for _, name := range []string{"gemini api key", "groq api key"} {
		c := findCheck(checks, name)
		if c == nil {
			t.Fatalf("no %q row: one row per configured provider", name)
		}
		if c.Status != doctor.Pass {
			t.Errorf("%s: status = %v, want Pass (%s)", name, c.Status, c.Hint)
		}
		if strings.Contains(c.Message, "g-key") || strings.Contains(c.Message, "q-key") {
			t.Errorf("%s: the secret itself must never be printed: %q", name, c.Message)
		}
	}
}

func TestAPIKeyCheck_NoProvidersFallsBackToGeminiKey(t *testing.T) {
	// With no providers: block, provider construction falls back to a Gemini
	// client keyed by GEMINI_API_KEY, so that variable is genuinely what Argus
	// would use — and an install that has it exported is a Colleague.
	t.Setenv("PATH", "")
	t.Setenv("GEMINI_API_KEY", "gem-secret")

	checks := doctor.Run(doctor.Options{Home: t.TempDir(), Shape: deployment.Colleague})
	c := findCheck(checks, "gemini api key")
	if c == nil {
		t.Fatal("no api key row for the no-providers fallback")
	}
	if c.Status != doctor.Pass {
		t.Fatalf("status = %v, want Pass (%s)", c.Status, c.Hint)
	}
	if !strings.Contains(c.Message, "GEMINI_API_KEY") {
		t.Errorf("message %q should name the variable Argus fell back to", c.Message)
	}
}

func TestAPIKeyCheck_ToolboxHasNoCredentialToCheck(t *testing.T) {
	// No providers and no fallback key is the Toolbox, so there is no
	// credential to demand: reporting a missing GEMINI_API_KEY here would call
	// a deployment shape a broken one.
	t.Setenv("PATH", "")
	t.Setenv("GEMINI_API_KEY", "")

	checks := doctor.Run(doctor.Options{Home: t.TempDir(), Shape: deployment.Toolbox})
	if c := findCheck(checks, "gemini api key"); c != nil {
		t.Errorf("a Toolbox has no Gemini fallback to report on: %+v", c)
	}
	c := findCheck(checks, "llm api key")
	if c == nil {
		t.Fatal("no api key row at all")
	}
	if c.Status != doctor.Info || c.Severity != doctor.SeverityInfo {
		t.Fatalf("status/severity = %v/%v, want Info/SeverityInfo (%s)", c.Status, c.Severity, c.Hint)
	}
}

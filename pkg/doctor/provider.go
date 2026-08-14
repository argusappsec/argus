package doctor

import (
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/deployment"
	"github.com/argusappsec/argus/pkg/provider"
)

// This file holds everything doctor says about the LLM Provider: the credential
// rows derived from the configured Providers, and the live capability probe.
//
// The probe is the mechanism that lets Argus call a Provider type
// "openai-compatible" honestly (ADR 0020). Argus implements a wire protocol and
// certifies nobody's server, so verification happens on the *user's* machine,
// against the *user's* model, at the moment they configure it — not as a
// compatibility matrix the maintainers would have to acquire models to test.
// What it turns "Argus is broken" into is "your model does not meet Argus's
// requirements", which is the difference between a bug report and a
// configuration fix.

// ProviderTarget describes the Provider doctor is about to report on: the same
// Provider the daemon would build for the configured default model. The caller
// resolves it (argus.yaml is not doctor's business) and hands over the
// already-resolved facts.
type ProviderTarget struct {
	// Type is a provider.Type* value. It decides what can be verified at all —
	// provider.SupportsCapabilityProbe and provider.IsKnownType own that
	// judgement, so a type Argus cannot probe, and a value Argus implements no
	// Provider for at all, are told apart there rather than here.
	Type string
	// Model is the bare model id that travels on the wire — the id the endpoint
	// itself knows, never the `provider-name/model-id` form Argus resolves
	// Providers by.
	Model string
	// Endpoint is the base URL the probe talks to, already defaulted by the
	// caller. It appears in every message on this row, because "which endpoint"
	// is half of every answer here.
	Endpoint string
}

// providerCheck reports on the configured Provider in one row, the way
// githubCheck reports a multi-stage result: each stage that fails leaves its own
// hint on the row, and the passing message names what was actually verified.
//
// The stages run in this order for a reason. GET /models is one request that
// establishes reachability, key validity and the existence of the configured
// model id **before a single token is spent** — a typo in a model id has to
// surface before it costs the user anything. Only then is a generation worth
// making.
//
// Both probes are injected so the network calls live in the caller, keeping this
// package pure; nil means that stage was not attempted, which is reported rather
// than assumed to have passed.
func providerCheck(t ProviderTarget, listModels func(context.Context) ([]string, error), toolCall func(context.Context) (bool, error)) Check {
	c := Check{Name: "llm provider", Severity: SeverityRequired}
	endpoint := t.Endpoint
	if endpoint == "" {
		// A guard, not a default: doctor cannot name a concrete implementation's
		// default endpoint without importing it, so the caller resolves it. This
		// keeps a message from reading "at " if one ever forgets.
		endpoint = "(default endpoint)"
	}

	// Which of the three outcomes below applies is a fact about the *type*, so it
	// is asked of pkg/provider rather than decided by a switch over type strings
	// here. "Cannot be probed" and "is not a type at all" both mean no probe runs,
	// and they are different findings — hence two questions, not one.
	switch {
	case provider.SupportsCapabilityProbe(t.Type):
		// The probe below is this protocol's. Fall through.
	case provider.IsKnownType(t.Type):
		// A type Argus implements but cannot verify live — why not is
		// provider.SupportsCapabilityProbe's to explain. What is doctor's is the
		// row: an Info that says so beats fabricating a check that cannot run,
		// and beats an absent row that reads like the feature is broken.
		//
		// The message names t.Type so a second such type is at least named
		// correctly, but the reason it gives is Gemini's — today the only
		// implemented type the probe does not reach. A second one would need its
		// own reason written here.
		c.Status = Info
		c.Severity = SeverityInfo
		c.Message = fmt.Sprintf("%s model %q — not probed: the capability probe (a /models listing, then a tool call) is the %s protocol's, and Gemini's tool calling is not the unknown it exists for",
			t.Type, t.Model, provider.TypeOpenAICompatible)
		return c
	default:
		// `type` selects an implementation, so a value Argus has none for is not
		// a Provider that might work — it is a configuration mistake, and the
		// operator needs the vocabulary rather than a probe result.
		c.Status = Fail
		c.Hint = fmt.Sprintf("type: provider type %q is not one Argus implements — a type names a protocol, not a vendor, so write %q for any server speaking the OpenAI chat-completions protocol (a hosted service or a local runtime, told apart by `url`) or %q for Google's Gemini API",
			t.Type, provider.TypeOpenAICompatible, provider.TypeGemini)
		return c
	}

	if listModels == nil && toolCall == nil {
		c.Status = Info
		c.Severity = SeverityInfo
		c.Message = fmt.Sprintf("%s model %q at %s (not probed)", t.Type, t.Model, endpoint)
		return c
	}

	// Stage 1 — reachability, key validity, and the model id, in one request.
	listing := "model listing not attempted"
	if listModels != nil {
		models, err := listModels(context.Background())
		if err != nil {
			c.Status = Fail
			c.Hint = fmt.Sprintf("endpoint: GET /models against %s failed: %v — check the provider's `url` (this protocol's API root usually ends in /v1, and some services do not serve it at the domain root) and its `api_key`; a local runtime has to be running. An endpoint that serves /chat/completions but not /models cannot be verified this way — please report it.", endpoint, err)
			return c
		}
		switch {
		case len(models) == 0:
			// An endpoint that listed nothing has not said the model is absent.
			// Convicting a correct model id on that evidence would send the user
			// to fix the one thing that is not broken.
			listing = fmt.Sprintf("/models lists nothing, so %q could not be verified", t.Model)
		case !slices.Contains(models, t.Model):
			c.Status = Fail
			c.Hint = fmt.Sprintf("model: %s answered, but it serves no model named %q — it offers %s. Point `default_model` at one of those (or at `<provider>/<model-id>` to name the provider too).", endpoint, t.Model, quotedSample(models))
			return c
		default:
			listing = fmt.Sprintf("/models lists %q", t.Model)
		}
	}

	// Stage 2 — one minimal generation carrying a throwaway tool declaration.
	// Not redundant with stage 1: a server that *accepts* tool declarations and
	// then ignores them — the common local small-model failure — passes stage 1
	// and fails here. That is the case documentation alone can never cover, which
	// is why the assertion is on a tool call actually arriving and not on a 200.
	if toolCall == nil {
		c.Status = Pass
		c.Message = fmt.Sprintf("%s at %s — %s; tool-calling probe not attempted", t.Type, endpoint, listing)
		return c
	}
	called, err := toolCall(context.Background())
	if err != nil {
		// Labelled "generation", not "tool calling", and the distinction is the
		// whole point of the stage labels. A refusal of the tool declarations
		// arrives here already translated by the adapter into a plain statement
		// that the model does not support tool calling, with the server's own
		// words preserved after it — so the honest thing is to name the stage and
		// get out of the way. But a rate limit, a 5xx or a timeout arrives through
		// this same return, and the adapter refuses to call any of those a
		// missing capability precisely because that would point the user at the
		// wrong fix. Re-attaching the label here would undo that.
		c.Status = Fail
		c.Hint = "generation: " + err.Error()
		return c
	}
	if !called {
		c.Status = Fail
		c.Hint = fmt.Sprintf("tool calling: model %q at %s accepted a tool declaration and answered without calling it — Argus is an agent loop built on tool calls, so this model cannot read a file, run a scanner or finalize a Report. Choose a model that supports function calling.", t.Model, endpoint)
		return c
	}

	c.Status = Pass
	c.Message = fmt.Sprintf("%s at %s — %s; model %q emitted a tool call", t.Type, endpoint, listing, t.Model)
	return c
}

// sampleLimit bounds how many model ids a "no such model" hint quotes back. Long
// enough to spot a typo against, short enough that an aggregator serving
// hundreds does not flood the row.
const sampleLimit = 8

// quotedSample renders a bounded, quoted sample of the ids an endpoint reported,
// in the order it reported them.
func quotedSample(models []string) string {
	shown := models
	suffix := ""
	if len(shown) > sampleLimit {
		shown = shown[:sampleLimit]
		suffix = fmt.Sprintf(" (+%d more)", len(models)-sampleLimit)
	}
	quoted := make([]string, len(shown))
	for i, m := range shown {
		quoted[i] = strconv.Quote(m)
	}
	return strings.Join(quoted, ", ") + suffix
}

// apiKeyChecks derives one credential row per configured Provider.
//
// It is derived rather than hardcoded because the hardcoded version was a bug
// the moment a second Provider type existed: a required GEMINI_API_KEY check
// blocks `argus doctor` for an operator configured only with
// openai-compatible — for a key they correctly do not have — and a local-runtime
// user has no API key at all, which is precisely the user this Provider exists
// to attract.
func apiKeyChecks(cfg *config.Config, envPath string, shape deployment.Shape) []Check {
	if cfg == nil || len(cfg.Providers) == 0 {
		return []Check{fallbackAPIKeyCheck(envPath, shape)}
	}
	// Sorted: map iteration would reorder the rows on every run.
	names := slices.Sorted(maps.Keys(cfg.Providers))
	out := make([]Check, 0, len(names))
	for _, name := range names {
		out = append(out, apiKeyCheck(name, cfg.Providers[name], envPath))
	}
	return out
}

// apiKeyCheck reports the credential one configured Provider needs.
//
// Two different questions, and conflating them is what made the old check wrong:
//
//   - An **absent** api_key is fine for a type that authenticates nobody, and
//     fatal for one that authenticates every request.
//   - A **declared** api_key that does not resolve is a broken configuration
//     whatever the type — provider construction hard-errors on it, so no Session
//     can start — and blocks accordingly.
func apiKeyCheck(name string, p config.ProviderConfig, envPath string) Check {
	c := Check{Name: name + " api key"}

	if strings.TrimSpace(p.APIKey) == "" {
		if provider.RequiresAPIKey(p.Type) {
			c.Status = Fail
			c.Severity = SeverityRequired
			c.Hint = fmt.Sprintf("provider %q declares no `api_key`, and type %s authenticates every request — run `argus init` to configure one, or add `api_key: env(VAR)` to the entry and put the secret in %s", name, p.Type, envPath)
			return c
		}
		c.Status = Info
		c.Severity = SeverityInfo
		c.Message = fmt.Sprintf("provider %q declares none — nothing to check: an endpoint that authenticates nobody (a local runtime) needs no key", name)
		return c
	}

	resolved, err := p.ResolveAPIKey()
	if err != nil {
		c.Status = Fail
		c.Severity = SeverityRequired
		c.Hint = fmt.Sprintf("provider %q declares `api_key: %s` and it does not resolve: %v — export it in your shell or add it to %s (or drop the key entirely if the endpoint needs none)", name, p.APIKey, err, envPath)
		return c
	}
	c.Status = Pass
	if resolved == p.APIKey {
		// No indirection took place, so the secret is sitting in the YAML.
		c.Message = "set literally in argus.yaml"
		return c
	}
	c.Message = fmt.Sprintf("%s → set (source: %s)", p.APIKey, keySource(envPath))
	return c
}

// fallbackAPIKeyCheck covers an install with no providers: block at all. Which
// row that deserves is the Deployment shape's answer, and the two cases are
// genuinely different questions:
//
//   - A **Toolbox** has no Provider by definition, so there is no credential to
//     hold it to. Demanding one would report a deployment shape as a broken
//     Colleague (ADR 0023).
//   - A **Colleague** with no `providers:` block is the environment-variable
//     fallback: provider construction reaches for a Gemini client keyed by
//     GEMINI_API_KEY (see daemon.ProviderSpecForModel), so that variable is
//     genuinely the credential Argus would use. The name is this fallback's, not
//     a naming rule: `argus init` owns which variable a Provider type defaults to.
func fallbackAPIKeyCheck(envPath string, shape deployment.Shape) Check {
	if shape.IsToolbox() {
		return Check{
			Name:     "llm api key",
			Status:   Info,
			Severity: SeverityInfo,
			Message:  "no LLM Provider configured — nothing to check: a toolbox reasons through its caller, not through a key of its own",
		}
	}
	c := Check{Name: provider.TypeGemini + " api key", Severity: SeverityRequired}
	if v := os.Getenv("GEMINI_API_KEY"); v != "" {
		c.Status = Pass
		c.Message = fmt.Sprintf("GEMINI_API_KEY set (source: %s) — no `providers:` block, so Argus falls back to Gemini", keySource(envPath))
		return c
	}
	c.Status = Fail
	c.Hint = "no `providers:` are configured and GEMINI_API_KEY is unset — run `argus init` to configure your provider and API key"
	return c
}

// keySource names where a resolved secret most plausibly came from. It is a
// guess by construction — .env values are applied to the process before anything
// reads them, so by this point the two are indistinguishable — and it exists to
// tell an operator which file to edit, not to audit provenance.
func keySource(envPath string) string {
	if _, err := os.Stat(envPath); err == nil {
		return envPath
	}
	return "shell environment"
}

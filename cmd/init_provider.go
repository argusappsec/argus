package cmd

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/charmbracelet/huh"

	"github.com/argusappsec/argus/pkg/config"
)

// This file holds the pure parts of the `argus init` Provider step: the
// Provider types the interview offers, the environment-variable naming
// convention, and the endpoint presets. The huh form itself is interactive and
// untested by design; everything here is a plain function so the knowledge it
// encodes can be pinned by a table test.

// Provider types the interview offers. These are the values written to `type`
// under providers: in argus.yaml. A type names a **protocol, not a vendor**:
// openai-compatible is any server speaking the OpenAI chat-completions
// protocol, so a local runtime is not a type of its own — it is a server that
// speaks one, reached as a base URL. Argus implements the wire protocol and
// certifies nobody's server.
const (
	providerTypeGemini           = "gemini"
	providerTypeOpenAICompatible = "openai-compatible"
)

// providerTypeChoices is the Provider type step, in the order the form presents
// it. One table so the select's options and offeredProviderTypes cannot drift.
var providerTypeChoices = []struct {
	Type  string
	Label string
}{
	{providerTypeGemini, "Gemini (Google)"},
	{providerTypeOpenAICompatible, "OpenAI-compatible — a hosted service or a local runtime"},
}

// offeredProviderTypes lists the Provider types the interview can write, in
// the order the form presents them.
func offeredProviderTypes() []string {
	types := make([]string, 0, len(providerTypeChoices))
	for _, c := range providerTypeChoices {
		types = append(types, c.Type)
	}
	return types
}

// providerTypeOptions renders the Provider type list for the form.
func providerTypeOptions(selected string) []huh.Option[string] {
	opts := make([]huh.Option[string], 0, len(providerTypeChoices))
	for _, c := range providerTypeChoices {
		opts = append(opts, huh.NewOption(c.Label, c.Type).Selected(c.Type == selected))
	}
	return opts
}

// openAIDefaultBaseURL is the endpoint an OpenAI-compatible Provider talks to
// when no `url` is configured — pkg/config treats an empty url that way, and
// the adapter defaults to it (openaicompat.DefaultBaseURL, whose own test pins
// the same string). Shown in the form so the user can see what the OpenAI
// preset stands for; never written into argus.yaml, because there the default
// is the absence of the key. Held here rather than imported so cmd depends on
// no concrete Provider implementation.
//
// Verified against the official OpenAI Python SDK, which falls back to this
// exact base URL when OPENAI_BASE_URL is unset (openai-python,
// src/openai/_client.py).
const openAIDefaultBaseURL = "https://api.openai.com/v1"

// endpointPreset is one entry in the base-URL list offered after the
// openai-compatible type is chosen.
type endpointPreset struct {
	// ID is the stable value bound to the select (and the key the write path
	// resolves a URL through). Never shown to the user.
	ID string
	// Name is the service name shown in the form.
	Name string
	// BaseURL is the complete base URL of the endpoint, ready for
	// "<BaseURL>/chat/completions". Empty only for the custom entry, where the
	// user types one.
	BaseURL string
	// Default marks the preset whose BaseURL is already Argus's default, so
	// choosing it writes no `url` key at all.
	Default bool
}

// presetCustom is the escape hatch: the preset list must never become a limit
// on what a user can point Argus at.
const presetCustom = "custom"

// endpointPresets is the URL knowledge this feature exists to encode. The
// protocol's sharpest footgun lives here: the /v1 suffix is mandatory, and some
// services do not serve the API at the domain root (Groq, OpenRouter) while
// others do (DeepSeek).
//
// Every URL below was verified against the service's own documentation — a
// wrong preset is worse than no preset, because the user trusts it. The source
// is noted per entry; re-verify before editing, and drop an entry rather than
// guessing one.
var endpointPresets = []endpointPreset{
	{
		// openai-python defaults base_url to this when OPENAI_BASE_URL is
		// unset (src/openai/_client.py). It is Argus's default too, so
		// choosing OpenAI writes no url.
		ID: "openai", Name: "OpenAI", BaseURL: openAIDefaultBaseURL, Default: true,
	},
	{
		// openrouter.ai/docs/quickstart — "Using the OpenAI SDK": baseURL
		// "https://openrouter.ai/api/v1". Not the domain root.
		ID: "openrouter", Name: "OpenRouter", BaseURL: "https://openrouter.ai/api/v1",
	},
	{
		// console.groq.com/docs/openai — "change the base_url to
		// https://api.groq.com/openai/v1". Not the domain root.
		ID: "groq", Name: "Groq", BaseURL: "https://api.groq.com/openai/v1",
	},
	{
		// docs.together.ai/docs/openai-api-compatibility — base_url
		// "https://api.together.ai/v1".
		ID: "together", Name: "Together AI", BaseURL: "https://api.together.ai/v1",
	},
	{
		// api-docs.deepseek.com — "base_url (OpenAI): https://api.deepseek.com",
		// and the reference documents POST https://api.deepseek.com/chat/completions.
		// DeepSeek serves the API at the domain root: no /v1 here.
		ID: "deepseek", Name: "DeepSeek", BaseURL: "https://api.deepseek.com",
	},
	{
		// docs.mistral.ai/api — POST https://api.mistral.ai/v1/chat/completions.
		ID: "mistral", Name: "Mistral AI", BaseURL: "https://api.mistral.ai/v1",
	},
	{
		// inference-docs.cerebras.ai/resources/openai — "change the baseURL to
		// https://api.cerebras.ai/v1".
		ID: "cerebras", Name: "Cerebras", BaseURL: "https://api.cerebras.ai/v1",
	},
	{
		// docs.ollama.com/openai — base_url "http://localhost:11434/v1/". The
		// trailing slash the docs print is dropped: Argus appends
		// /chat/completions to what it stores.
		ID: "ollama", Name: "Ollama (local runtime)", BaseURL: "http://localhost:11434/v1",
	},
	{
		ID: presetCustom, Name: "Custom endpoint",
	},
}

// presetByID returns the preset with the given id.
func presetByID(id string) (endpointPreset, bool) {
	for _, p := range endpointPresets {
		if p.ID == id {
			return p, true
		}
	}
	return endpointPreset{}, false
}

// presetBaseURL returns the value init writes into argus.yaml's `url` for the
// chosen preset. Empty means "write no url": either the preset is Argus's own
// default (OpenAI), or the URL comes from the custom input instead.
func presetBaseURL(id string) string {
	p, ok := presetByID(id)
	if !ok || p.Default {
		return ""
	}
	return p.BaseURL
}

// presetForBaseURL maps a base URL already in play — from argus.yaml or from an
// exported OPENAI_BASE_URL — back to the preset to preselect in the form. An
// endpoint no preset covers preselects the custom entry. ok is false when there
// is no URL to match, meaning "no preselection".
func presetForBaseURL(raw string) (string, bool) {
	u := normalizeBaseURL(raw)
	if u == "" {
		return "", false
	}
	for _, p := range endpointPresets {
		if p.BaseURL != "" && strings.EqualFold(p.BaseURL, u) {
			return p.ID, true
		}
	}
	return presetCustom, true
}

// normalizeBaseURL trims surrounding whitespace and any trailing slashes.
// Argus appends "/chat/completions" to the stored base URL, so a trailing
// slash — which is how the Ollama docs print theirs — would produce a double
// slash on the wire.
func normalizeBaseURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

// validateBaseURL rejects a custom endpoint the form can already tell is
// unusable, so the mistake surfaces on the screen that made it rather than as
// a connection error on the first Review. It deliberately does not require a
// /v1 suffix: some services serve the API at the domain root.
func validateBaseURL(raw string) error {
	s := normalizeBaseURL(raw)
	if s == "" {
		return errors.New("base URL required (e.g. http://localhost:11434/v1)")
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("not a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("base URL must start with http:// or https://")
	}
	if u.Host == "" {
		return errors.New("base URL is missing a host")
	}
	return nil
}

// providerEnvVar returns the env var name where the secret for a Provider type
// is stored. Kept in one place so the convention is consistent.
//
// openai-compatible needs its explicit case: the fallback rule would produce
// OPENAI-COMPATIBLE_API_KEY, a name with a hyphen in it that no shell can
// export. OPENAI_API_KEY is the name every compatible service documents, so a
// user who already exports it finds the interview pre-filled.
func providerEnvVar(providerType string) string {
	switch providerType {
	case providerTypeGemini:
		return "GEMINI_API_KEY"
	case providerTypeOpenAICompatible:
		return "OPENAI_API_KEY"
	default:
		return strings.ToUpper(providerType) + "_API_KEY"
	}
}

// providerBaseURLEnvVar returns the env var name carrying a Provider type's
// endpoint override. The sibling of providerEnvVar, and explicit for the same
// reason.
func providerBaseURLEnvVar(providerType string) string {
	switch providerType {
	case providerTypeOpenAICompatible:
		return "OPENAI_BASE_URL"
	default:
		return strings.ToUpper(providerType) + "_BASE_URL"
	}
}

// lookupEnvDefault returns the value to pre-fill a form field with: the entry
// in ~/.argus/.env when there is one, otherwise the variable exported in the
// shell. The shell fallback is what makes an already-exported OPENAI_API_KEY or
// OPENAI_BASE_URL show up on a first run, when no .env exists yet.
func lookupEnvDefault(env *config.Env, name string) string {
	if v := strings.TrimSpace(env.Get(name)); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv(name))
}

// defaultProviderType picks the Provider type the form starts on, so re-running
// init keeps what is already configured. Only an unambiguous config moves the
// default off gemini: with several entries the interview does not guess which
// one the operator meant to re-run.
func defaultProviderType(cfg *config.Config) string {
	if len(cfg.Providers) == 1 {
		for _, p := range cfg.Providers {
			for _, t := range offeredProviderTypes() {
				if p.Type == t {
					return t
				}
			}
		}
	}
	return providerTypeGemini
}

// configuredBaseURL returns the endpoint an already-configured
// openai-compatible entry points at, for the form's preset preselection.
// Gemini entries are ignored: their endpoint is not user-selectable today.
//
// An env() reference is resolved, so what the form preselects — and therefore
// what the user confirms — is the endpoint actually in effect. Note the
// consequence: init owns the providers: block and rewrites it whole, so a
// hand-written `url: env(OPENAI_BASE_URL)` comes back as the literal URL it
// resolved to. Flattening it is the lesser evil against re-running init and
// silently discarding an endpoint whose value the interview never saw. A
// reference that cannot be resolved is skipped rather than pre-filled verbatim,
// because an env() string is not a URL the user could confirm.
func configuredBaseURL(cfg *config.Config) string {
	for _, p := range cfg.Providers {
		if p.Type != providerTypeOpenAICompatible {
			continue
		}
		if u, err := p.ResolveURL(); err == nil && u != "" {
			return normalizeBaseURL(u)
		}
	}
	return ""
}

// providerEntry maps the interview's answers onto the providers: entry init
// writes into argus.yaml. Three rules, all visible in the produced YAML:
//
//   - `url` is written only when an endpoint was chosen or typed. Argus's
//     default endpoint is expressed by the absence of the key.
//   - `api_key` is written only when a key was supplied, so an endpoint that
//     needs none does not carry an empty credential.
//   - the key, when there is one, is an env() reference — the secret itself
//     lives in ~/.argus/.env and never in the YAML.
func providerEntry(picked providerSelection) config.ProviderConfig {
	entry := config.ProviderConfig{Type: picked.Provider, URL: picked.BaseURL}
	if picked.APIKey != "" {
		entry.APIKey = config.EnvRef(providerEnvVar(picked.Provider))
	}
	return entry
}

// endpointOptions renders the preset list for the form, showing each service's
// base URL next to its name so the user sees exactly what lands in argus.yaml.
func endpointOptions(selected string) []huh.Option[string] {
	opts := make([]huh.Option[string], 0, len(endpointPresets))
	for _, p := range endpointPresets {
		label := p.Name
		switch {
		case p.ID == presetCustom:
			label += " — enter any base URL"
		case p.Default:
			label += " — " + p.BaseURL + " (Argus default)"
		default:
			label += " — " + p.BaseURL
		}
		opts = append(opts, huh.NewOption(label, p.ID).Selected(p.ID == selected))
	}
	return opts
}

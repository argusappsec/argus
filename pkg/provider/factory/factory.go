// Package factory constructs the LLM Provider a provider.Spec names.
//
// It is the one place in Argus that knows which Provider implementations exist.
// Callers — the daemon's per-Session Provider constructor, the `argus init`
// interview, the `argus doctor` capability probe — hand over a Spec and receive
// a provider.Provider, so none of them imports a concrete implementation and
// none of them repeats the switch. Adding a protocol is a case here plus a type
// constant in pkg/provider (ADR 0020).
//
// Why it sits one directory below the abstraction it serves: every
// implementation package (gemini, openaicompat) imports pkg/provider for the
// Request/Response types, so the package holding a switch over those
// implementations cannot be pkg/provider itself without an import cycle.
// provider.Spec and the type constants stay in pkg/provider, where the Provider
// vocabulary belongs; only the switch lives here.
package factory

import (
	"context"
	"fmt"

	"github.com/argusappsec/argus/pkg/provider"
	"github.com/argusappsec/argus/pkg/provider/gemini"
	"github.com/argusappsec/argus/pkg/provider/openaicompat"
)

// DefaultOpenAICompatibleBaseURL is the endpoint an openai-compatible Provider
// talks to when Spec.BaseURL is empty. It is aliased from the adapter rather
// than copied, so the string exists once in the tree — and stays pinned by that
// package's own test — while a caller that needs to *show* the default, as the
// `argus init` endpoint list does, can read it here without importing a concrete
// implementation.
const DefaultOpenAICompatibleBaseURL = openaicompat.DefaultBaseURL

// New returns the Provider that spec names, or an error naming the supported
// types.
//
// That error is the load-bearing part: `type` selects an implementation, so a
// mistyped value must fail where the mistake was made rather than connect the
// operator to a different Provider than the one they asked for.
func New(ctx context.Context, spec provider.Spec) (provider.Provider, error) {
	// Spec validation lives here, ahead of the switch, so there is one gate to
	// read rather than a rule per case.

	// A ceiling of "minus five tokens" is a configuration mistake whatever
	// protocol it was written against, and the value is otherwise passed
	// straight through to a server that would reject it far from the file that
	// set it.
	if spec.MaxOutputTokens < 0 {
		return nil, fmt.Errorf("provider: max_output_tokens must be zero or positive, got %d (zero sends no output ceiling at all)", spec.MaxOutputTokens)
	}
	// The Gemini client accepts no ceiling, so honouring one is not on offer;
	// the choice is between rejecting the key and ignoring it. Rejecting is the
	// only option that reaches the operator: an ignored ceiling surfaces as a
	// truncated Report they have no way to trace back to the key they set.
	if spec.MaxOutputTokens != 0 && spec.Type == provider.TypeGemini {
		return nil, fmt.Errorf("provider: max_output_tokens is not supported by provider type %q: the Gemini client accepts no output ceiling, so omit the key rather than have it silently ignored", provider.TypeGemini)
	}

	switch spec.Type {
	case provider.TypeGemini:
		// Spec.BaseURL is not carried over: the SDK-backed Gemini client accepts
		// no endpoint, so setting `url` on a gemini entry has no effect. Unlike
		// the output ceiling above it is tolerated rather than rejected, because
		// it predates the factory and configurations already carry it.
		// Spec.MaxOutputTokens cannot arrive here non-zero — the gate rejected it.
		p, err := gemini.New(ctx, spec.APIKey, spec.Model)
		if err != nil {
			return nil, err
		}
		return p, nil
	case provider.TypeOpenAICompatible:
		// An empty BaseURL is passed through as empty on purpose: the default
		// endpoint is the adapter's to define, not this switch's to substitute.
		p, err := openaicompat.New(openaicompat.Config{
			APIKey:          spec.APIKey,
			BaseURL:         spec.BaseURL,
			Model:           spec.Model,
			MaxOutputTokens: spec.MaxOutputTokens,
		})
		if err != nil {
			return nil, err
		}
		return p, nil
	default:
		return nil, fmt.Errorf("provider: unknown type %q (supported: %q, %q)", spec.Type, provider.TypeGemini, provider.TypeOpenAICompatible)
	}
}

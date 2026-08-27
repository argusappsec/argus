package daemon

import (
	"context"
	"os"
	"strings"

	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/provider"
	"github.com/argusappsec/argus/pkg/provider/factory"
)

// This file is how a configured Provider becomes a live one: argus.yaml on one
// side, the Provider factory on the other, and the model-id resolution in
// between. It knows the file format and the resolution rules; it does not know
// which Provider implementations exist, which is the factory's business alone.

// providerFactory returns the per-Session provider constructor installed on the
// Context: it maps the configured Provider that backs modelID onto a
// provider.Spec and hands that to the factory.
func providerFactory(cfg *config.Config) func(ctx context.Context, modelID string) (provider.Provider, error) {
	return func(ctx context.Context, modelID string) (provider.Provider, error) {
		spec, err := ProviderSpecForModel(cfg, modelID)
		if err != nil {
			return nil, err
		}
		return factory.New(ctx, spec)
	}
}

// ProviderSpecForModel resolves modelID to the configured Provider that backs it
// (the rules are config.ProviderForModel's) and maps that entry onto the
// provider.Spec which constructs it: the Provider type, the resolved secret and
// endpoint — env() indirection included — the optional output ceiling, and the
// **bare** model id to send on the wire. A qualified `provider-name/model-id`
// names a Provider to Argus and means nothing to the endpoint, so only the bare
// half travels; the qualified form stays in what Argus *records*.
//
// It is exported because the daemon's per-Session constructor is not the only
// caller: the `argus doctor` capability probe has to build the same Provider the
// daemon would, and a second copy of this mapping is how the two drift apart.
// Pair it with factory.New to get a Provider.
//
// An install with no providers: block at all falls back to a Gemini Provider
// keyed by GEMINI_API_KEY, so a setup that exported the variable and never ran
// `argus init` keeps working. The fallback deliberately stops there: once
// providers *are* configured, a model id that resolves to none of them is
// reported as such rather than quietly connected to Gemini — being handed a
// different Provider than the one you asked for is exactly how a mistyped type
// or model used to point the operator at the wrong problem.
func ProviderSpecForModel(cfg *config.Config, modelID string) (provider.Spec, error) {
	if cfg == nil {
		cfg = &config.Config{}
	}
	if len(cfg.Providers) == 0 && hasFallbackAPIKey() {
		return provider.Spec{Type: provider.TypeGemini, APIKey: os.Getenv(fallbackAPIKeyEnv), Model: fallbackWireModel(modelID)}, nil
	}

	// Resolution errors travel out as they are: config names the candidates, the
	// ambiguity, and the qualified form to write instead — nothing here can say
	// it better.
	p, _, wireModel, err := cfg.ProviderForModel(modelID)
	if err != nil {
		return provider.Spec{}, err
	}
	apiKey, err := p.ResolveAPIKey()
	if err != nil {
		return provider.Spec{}, err
	}
	baseURL, err := p.ResolveURL()
	if err != nil {
		return provider.Spec{}, err
	}
	return provider.Spec{
		Type:            p.Type,
		APIKey:          apiKey,
		BaseURL:         baseURL,
		Model:           wireModel,
		MaxOutputTokens: p.MaxOutputTokens,
	}, nil
}

// fallbackAPIKeyEnv is the credential the no-`providers:` fallback above is
// keyed by. The variable name belongs to that fallback, not to a naming rule:
// `argus init` owns which variable a configured Provider type defaults to.
const fallbackAPIKeyEnv = "GEMINI_API_KEY"

// hasFallbackAPIKey reports whether the fallback credential is present. It is
// asked here, next to the fallback it describes, because the Deployment shape
// asks it too (ShapeOf): an install the fallback would serve is a Colleague,
// and the two answers must not be able to disagree.
func hasFallbackAPIKey() bool { return os.Getenv(fallbackAPIKeyEnv) != "" }

// fallbackWireModel strips the qualification off a model id on the GEMINI_API_KEY
// path. There is no providers: block there to resolve against, so nothing else
// would: the fallback stands in for a Provider named "gemini", and a model id
// qualified against that name must reach the wire bare exactly as a configured
// entry's would. Anything else is left alone — including an id qualified with
// some other name, which the endpoint will reject and say so.
func fallbackWireModel(modelID string) string {
	if bare, ok := strings.CutPrefix(modelID, provider.TypeGemini+"/"); ok && bare != "" {
		return bare
	}
	return modelID
}

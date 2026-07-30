package provider_test

import (
	"testing"

	"github.com/argusappsec/argus/pkg/provider"
)

// The three predicates below are the reason `argus doctor` does not switch on
// type strings of its own. What is worth testing is not the boolean — each is one
// comparison — but that the *three answers a type gives are not the same answer*:
// "needs no key", "cannot be probed" and "is not a type" are three different
// findings, and a caller that conflated any two of them would report the wrong
// one.

func TestIsKnownType(t *testing.T) {
	for _, tc := range []struct {
		providerType string
		want         bool
		why          string
	}{
		{provider.TypeGemini, true, "gemini is implemented"},
		{provider.TypeOpenAICompatible, true, "openai-compatible is implemented"},
		{"openai", false, "the type names a protocol, not a vendor — `openai` is the shorter string users will occasionally write, and it has to fail"},
		{"ollama", false, "a local runtime is a base URL, not a type (ADR 0020 removed it from the reserved list)"},
		{"anthropic", false, "reachable through a compatible gateway; not a type Argus implements"},
		{"", false, "an entry with no `type` at all is not a Provider Argus can build"},
		{"GEMINI", false, "type values are matched literally: a case-folded one is a configuration mistake, not a synonym"},
	} {
		if got := provider.IsKnownType(tc.providerType); got != tc.want {
			t.Errorf("IsKnownType(%q) = %v, want %v: %s", tc.providerType, got, tc.want, tc.why)
		}
	}
}

func TestRequiresAPIKey(t *testing.T) {
	if !provider.RequiresAPIKey(provider.TypeGemini) {
		t.Error("gemini must require a key: the Gemini API authenticates every request, so an entry with none cannot make one call")
	}
	if provider.RequiresAPIKey(provider.TypeOpenAICompatible) {
		t.Error("openai-compatible must not require a key: a local runtime authenticates nobody, and blocking that operator for a key they correctly do not have is the failure this answer exists to prevent")
	}
	for _, unknown := range []string{"openai", ""} {
		if provider.RequiresAPIKey(unknown) {
			t.Errorf("RequiresAPIKey(%q) = true, want false: Argus implements no Provider for it, so demanding a credential would send the operator after a key while the real finding — the type — went unsaid", unknown)
		}
	}
}

func TestSupportsCapabilityProbe(t *testing.T) {
	if !provider.SupportsCapabilityProbe(provider.TypeOpenAICompatible) {
		t.Error("openai-compatible must be probeable: the protocol serves GET /models, and the servers it reaches are certified by nobody, which is the whole reason the probe exists")
	}
	if provider.SupportsCapabilityProbe(provider.TypeGemini) {
		t.Error("gemini must not be probeable: the SDK-backed client offers no model listing, and a generation would spend tokens confirming tool calling that was never the unknown")
	}
	for _, unknown := range []string{"openai", ""} {
		if provider.SupportsCapabilityProbe(unknown) {
			t.Errorf("SupportsCapabilityProbe(%q) = true, want false: there is no client to probe with", unknown)
		}
	}
}

// TestProbeableTypesAreImplemented guards the one combination that would be
// incoherent: a type nothing can construct cannot be probed live, so any type
// answering yes to the probe must also be one Argus implements.
func TestProbeableTypesAreImplemented(t *testing.T) {
	for _, providerType := range []string{provider.TypeGemini, provider.TypeOpenAICompatible, "openai", ""} {
		if provider.SupportsCapabilityProbe(providerType) && !provider.IsKnownType(providerType) {
			t.Errorf("type %q claims to be capability-probeable but is not one Argus implements", providerType)
		}
	}
}

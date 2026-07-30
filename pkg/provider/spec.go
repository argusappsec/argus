package provider

// Provider type strings: the values `type` takes on a providers: entry in
// argus.yaml.
//
// A type names a *protocol, not a vendor* (ADR 0020) — hence
// "openai-compatible" and never "openai". Argus implements a wire protocol and
// certifies nobody's server, so the type must not imply a relationship with
// one, and a local runtime is not a type of its own: it is a server that speaks
// this protocol, reached as a base URL. There is one implementation per
// protocol.
//
// They live here, next to Spec, so the configuration file, the `argus init`
// interview and the factory that switches on them cannot drift apart. The
// per-type facts the rest of Argus reads off a type — does it need a
// credential, can it be verified live, is it a type at all — are answered
// immediately below them for the same reason: a caller that switches on these
// strings itself has taken a copy of the vocabulary, and copies drift.
const (
	TypeGemini           = "gemini"
	TypeOpenAICompatible = "openai-compatible"
)

// IsKnownType reports whether Argus implements a Provider for this type — that
// is, whether providerType is one of the constants above.
//
// `type` selects an implementation, so a value outside that vocabulary is not a
// Provider that might work: it is a configuration mistake, and what the operator
// needs is the vocabulary itself rather than a verdict about an endpoint Argus
// could never reach. It is also the question that keeps the two predicates below
// honest — both answer false for a type they know nothing about, which is not
// the same answer as "no".
//
// This list and the factory's construction switch are the same vocabulary
// written twice, because the import cycle that put the switch in
// pkg/provider/factory leaves no way to derive one from the other. Adding a type
// to one and not the other is a real defect, not a cosmetic one: the Provider
// would construct while `argus doctor` called its type unimplemented.
func IsKnownType(providerType string) bool {
	switch providerType {
	case TypeGemini, TypeOpenAICompatible:
		return true
	default:
		return false
	}
}

// RequiresAPIKey reports whether a Provider of this type cannot make a single
// call without a credential.
//
// The answer is per type, and the reasons are the load-bearing part:
//
//   - gemini — yes. The Gemini API authenticates every request, so an entry
//     carrying no key is a Provider that cannot make one call, and reporting
//     that early is the whole value of saying so.
//   - openai-compatible — no. A local runtime authenticates nobody, and that
//     operator is precisely the user this Provider type exists to attract; a
//     hosted endpoint that does want a key says so itself, on the first
//     request. Demanding one up front would block the setup that correctly has
//     none.
//
// An unknown type answers false. Argus implements no Provider for it, so what it
// would authenticate with is unanswerable — and guessing "yes" would send the
// operator after a credential while the real finding, the type, went unsaid. Ask
// IsKnownType about that.
func RequiresAPIKey(providerType string) bool {
	return providerType == TypeGemini
}

// SupportsCapabilityProbe reports whether a Provider of this type can be
// verified live: whether its client exposes a model listing to enumerate, and
// whether its tool calling is actually in doubt.
//
// Both halves have to hold, and again the reasons are per type:
//
//   - openai-compatible — yes, on both counts. The protocol serves GET /models,
//     so one request settles reachability, key validity and the existence of the
//     configured model id before a token is spent; and the servers this type
//     reaches are certified by nobody, which is the entire reason a probe exists
//     (ADR 0020).
//   - gemini — no, on both counts. The SDK-backed client offers no model listing
//     to enumerate, and a generation would spend tokens to confirm tool calling
//     on the one Provider whose tool calling was never the unknown.
//
// An unknown type answers false: there is no client to probe with. That is the
// same answer gemini gives for entirely different reasons, so a caller reporting
// *why* nothing was probed needs IsKnownType to tell the two apart.
func SupportsCapabilityProbe(providerType string) bool {
	return providerType == TypeOpenAICompatible
}

// Spec is everything needed to construct one Provider: which implementation,
// reached how, generating with which model. It is the input to the factory in
// pkg/provider/factory, which turns it into a Provider.
//
// Spec is owned here rather than by pkg/config deliberately: the Provider
// abstraction stays ignorant of the argus.yaml file format, and the *caller*
// maps its configuration onto a Spec — resolving env() indirection, picking the
// Provider a model id belongs to — before asking for a Provider. Nothing here
// is a file format; every field is already-resolved connection info, which is
// also what lets a caller that has no configuration file at all (the `argus
// init` interview, a test) build a Provider the same way the daemon does.
type Spec struct {
	// Type selects the implementation: one of the Type* constants above. An
	// unknown value is an error naming the supported ones — never a silent
	// fallback to whichever Provider happens to be the oldest.
	Type string
	// APIKey may be empty: a local runtime that authenticates nobody needs
	// none, and an endpoint that wants one says so itself.
	APIKey string
	// BaseURL is the endpoint's API root including any path prefix
	// ("http://localhost:11434/v1"). Empty means the implementation's own
	// default endpoint, which is how "no url configured" travels.
	//
	// Honoured by openai-compatible only: the gemini implementation takes no
	// endpoint, so a base URL set against a gemini Spec is **silently ignored**
	// — accepted and dropped, not rejected. That is deliberate, and the one
	// asymmetry with MaxOutputTokens below: `url` predates the factory, so
	// configurations already carry it against gemini entries and erroring would
	// break them — and an endpoint that is never read corrupts nothing on its
	// way past.
	BaseURL string
	// Model is the bare model id to send on the wire — the id the endpoint
	// itself knows, never the `provider-name/model-id` qualified form Argus
	// resolves Providers by.
	Model string
	// MaxOutputTokens caps the response length. Zero — the default — sends no
	// ceiling at all, matching both the ecosystem norm and what omitting the
	// configuration key means. Zero is valid for every Provider type; a negative
	// value is an error rather than a silently ignored one.
	//
	// Honoured by openai-compatible only: the gemini implementation accepts no
	// ceiling, so a non-zero value on a gemini Spec is an **error** from the
	// factory rather than an ignored setting. The ceiling exists as a lever
	// against servers whose own output cap truncates a Report mid-write, and a
	// lever that quietly does nothing delivers that same mutilated Report — so
	// the one Provider type that cannot pull it has to say so where the setting
	// was made.
	MaxOutputTokens int
}

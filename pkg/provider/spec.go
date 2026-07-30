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
// interview and the factory that switches on them cannot drift apart.
const (
	TypeGemini           = "gemini"
	TypeOpenAICompatible = "openai-compatible"
)

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
	// endpoint, so a base URL set against it has no effect.
	BaseURL string
	// Model is the bare model id to send on the wire — the id the endpoint
	// itself knows, never the `provider-name/model-id` qualified form Argus
	// resolves Providers by.
	Model string
	// MaxOutputTokens caps the response length. Zero — the default — sends no
	// ceiling at all, matching both the ecosystem norm and what omitting the
	// configuration key means. A negative value is an error rather than a
	// silently ignored one.
	//
	// Honoured by openai-compatible only, for the same reason as BaseURL: the
	// ceiling exists as a lever against servers whose own output cap truncates a
	// Report mid-write, and the gemini implementation accepts none.
	MaxOutputTokens int
}

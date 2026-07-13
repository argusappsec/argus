package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the user-editable preferences file (~/.argus/argus.yaml).
// Secrets do NOT live here — they belong in ~/.argus/.env. This file is
// intentionally readable: a human can hand-edit it to add a second provider
// or swap a default model.
//
// Any string field can use the env(VAR_NAME) reference syntax to pull a
// value from the process environment at load time. This is how secrets are
// kept out of the YAML while still being part of the same config surface.
//
// Example:
//
//	providers:
//	  gemini:
//	    type: gemini
//	    api_key: env(GEMINI_API_KEY)
//	default_model: gemini-2.5-flash
type Config struct {
	// Providers maps a logical name (free choice) to its connection config.
	// Multiple providers may coexist; the one used at runtime is the one
	// whose name matches the family of DefaultModel.
	Providers map[string]ProviderConfig `yaml:"providers,omitempty"`

	// DefaultModel is the model id used when no --model flag is passed.
	// Form: a plain model id (e.g. "gemini-2.5-flash"). The provider that
	// implements it is the one whose name matches the model's family.
	DefaultModel string `yaml:"default_model,omitempty"`

	// Daemon configures the long-running argusd process. Loaded once at
	// daemon start; changing it requires a restart (by design — see the
	// hot-reload policy: users.yaml/SOUL/MEMORY are re-read at use, the
	// process-level config is not).
	Daemon DaemonConfig `yaml:"daemon,omitempty"`

	// CodeHosts declares the outbound integration surface (ADR 0015): one
	// entry per platform instance, carrying the App identity every channel
	// clones and calls the API with. Keyed by a free-choice logical name;
	// the runtime binds by `type` and allows one codehost per type. Absent
	// means the daemon has no authenticated code host (MCP-only / local use).
	CodeHosts map[string]CodeHostConfig `yaml:"codehosts,omitempty"`

	// Channels declares the inbound integration surface (ADR 0015): one entry
	// per transport binding — the GitHub webhook (type: github) or MCP
	// (type: mcp). Keyed by a free-choice logical name; the runtime binds by
	// `type` and allows one channel per type. A github channel's outbound
	// credentials come implicitly from the single github codehost. Absent
	// leaves the daemon socket-only.
	Channels map[string]ChannelConfig `yaml:"channels,omitempty"`

	// Persona configures the operator-chosen display name this instance answers
	// to (e.g. "Ercole"). Optional and additive: an empty persona leaves the
	// instance known only by its brand name Argus, identical to prior
	// behavior.
	Persona PersonaConfig `yaml:"persona,omitempty"`
}

// PersonaConfig is the persona: section of argus.yaml — an operator-chosen name
// this Argus instance is addressed by, in addition to the always-accepted brand
// name. The name feeds two independent surfaces: the GitHub mention forms the
// bot answers to (the bare name opening a comment — "Ercole, look at this" —
// plus the @<Name> handle when the name is a single word), and a line in the
// agent's system prompt so the persona introduces and signs itself
// consistently. The SOUL stays free prose for the model; the name is a
// structured field so channel code never has to parse markdown to learn it.
type PersonaConfig struct {
	// Name is the custom name colleagues use, e.g. "Ercole" or "Ercole il
	// Guardiano". Empty means the brand default (the instance answers to
	// Argus only). Whitespace is trimmed by consumers.
	Name string `yaml:"name,omitempty"`
}

// Recognised codehost and channel types. The runtime binds config entries by
// these values (one per type), never by their free-choice map key.
const (
	// CodeHostTypeGitHub is the only implemented codehost type (ADR 0010).
	CodeHostTypeGitHub = "github"
	// ChannelTypeGitHub is the GitHub App webhook channel (ADR 0008).
	ChannelTypeGitHub = "github"
	// ChannelTypeMCP is the MCP channel (ADR 0011).
	ChannelTypeMCP = "mcp"
)

// CodeHostConfig is one entry under codehosts: — an outbound integration to a
// code-hosting platform (ADR 0015). It carries the App identity every channel
// clones and calls the API with; the installation is derived per event/repo,
// never configured. The private key lives as a PEM on the daemon host; app_id
// may be a literal or an env() reference.
type CodeHostConfig struct {
	// Type selects the platform implementation (only "github" today).
	Type string `yaml:"type"`

	// AppID is the numeric GitHub App id. Literal or env() reference.
	AppID string `yaml:"app_id,omitempty"`

	// PrivateKeyPath is the filesystem path to the App's PEM private key on
	// the daemon host (used to mint the App JWT).
	PrivateKeyPath string `yaml:"private_key_path,omitempty"`
}

// Configured reports whether the codehost carries the credentials it needs to
// authenticate: an App id and a private key path.
func (c CodeHostConfig) Configured() bool {
	return c.AppID != "" && c.PrivateKeyPath != ""
}

// ResolveAppID applies the env() reference syntax so the id can live in .env.
func (c CodeHostConfig) ResolveAppID() (string, error) { return ResolveValue(c.AppID) }

// ChannelConfig is one entry under channels: — an inbound transport binding
// (ADR 0015). A github channel carries the webhook secret and enrolment
// policy; its outbound credentials come implicitly from the single github
// codehost. An mcp channel carries nothing here — auth is per-Person bearer
// tokens in users.yaml.
type ChannelConfig struct {
	// Type selects the transport ("github" webhook, "mcp").
	Type string `yaml:"type"`

	// WebhookSecret is the GitHub App's webhook secret (github channel only).
	// env() reference (→ .env).
	WebhookSecret string `yaml:"webhook_secret,omitempty"`

	// AutoEnroll governs whether an installed repo is reviewed automatically
	// (ADR 0008). Unset means true (the single-owner default). When false, a
	// repo acts only if it also appears in EnabledRepos.
	AutoEnroll *bool `yaml:"auto_enroll,omitempty"`

	// EnabledRepos is the explicit allow-list consulted when AutoEnroll is
	// false. Entries are canonical names like "github.com/<owner>/<repo>".
	EnabledRepos []string `yaml:"enabled_repos,omitempty"`
}

// AutoEnrollEnabled reports the effective auto_enroll policy. Unset → true.
func (c ChannelConfig) AutoEnrollEnabled() bool {
	return c.AutoEnroll == nil || *c.AutoEnroll
}

// ResolveWebhookSecret applies the env() reference syntax (→ .env).
func (c ChannelConfig) ResolveWebhookSecret() (string, error) {
	return ResolveValue(c.WebhookSecret)
}

// CodeHost returns the codehost declared with the given type, if any. The
// runtime allows one codehost per type (enforced by Validate), so the match
// is unambiguous.
func (c *Config) CodeHost(hostType string) (CodeHostConfig, bool) {
	for _, h := range c.CodeHosts {
		if h.Type == hostType {
			return h, true
		}
	}
	return CodeHostConfig{}, false
}

// Channel returns the channel declared with the given type, if any. One
// channel per type (enforced by Validate) keeps the match unambiguous.
func (c *Config) Channel(chanType string) (ChannelConfig, bool) {
	for _, ch := range c.Channels {
		if ch.Type == chanType {
			return ch, true
		}
	}
	return ChannelConfig{}, false
}

// Validate enforces the config v2 invariants that must hold before the daemon
// wires channels: every entry has a known type, per-type required fields are
// present, at most one codehost and one channel exist per type, and a github
// channel has the github codehost its outbound credentials come from. It is
// the startup gate — a misconfigured file fails loudly here, never as a silent
// dead channel at runtime.
func (c *Config) Validate() error {
	seenHost := map[string]string{}
	for name, h := range c.CodeHosts {
		if prev, dup := seenHost[h.Type]; dup {
			return fmt.Errorf("config: codehosts %q and %q are both type %q; only one codehost per type is supported", prev, name, h.Type)
		}
		seenHost[h.Type] = name
		if err := h.validate(name); err != nil {
			return err
		}
	}
	seenChan := map[string]string{}
	for name, ch := range c.Channels {
		if prev, dup := seenChan[ch.Type]; dup {
			return fmt.Errorf("config: channels %q and %q are both type %q; only one channel per type is supported", prev, name, ch.Type)
		}
		seenChan[ch.Type] = name
		if err := ch.validate(name); err != nil {
			return err
		}
	}
	if _, ok := c.Channel(ChannelTypeGitHub); ok {
		if _, ok := c.CodeHost(CodeHostTypeGitHub); !ok {
			return fmt.Errorf("config: a github channel requires a github codehost under `codehosts:` (its clone/API credentials)")
		}
	}
	return nil
}

// validate checks a single codehost's required fields for its type.
func (c CodeHostConfig) validate(name string) error {
	switch c.Type {
	case CodeHostTypeGitHub:
		if c.AppID == "" {
			return fmt.Errorf("config: codehost %q (github): missing `app_id`", name)
		}
		if c.PrivateKeyPath == "" {
			return fmt.Errorf("config: codehost %q (github): missing `private_key_path`", name)
		}
	default:
		return fmt.Errorf("config: codehost %q: unknown type %q (only %q is supported)", name, c.Type, CodeHostTypeGitHub)
	}
	return nil
}

// validate checks a single channel's required fields for its type.
func (c ChannelConfig) validate(name string) error {
	switch c.Type {
	case ChannelTypeGitHub:
		if c.WebhookSecret == "" {
			return fmt.Errorf("config: channel %q (github): missing `webhook_secret`", name)
		}
	case ChannelTypeMCP:
		// No required fields: MCP auth is per-Person bearer tokens in users.yaml.
	default:
		return fmt.Errorf("config: channel %q: unknown type %q (supported: %q, %q)", name, c.Type, ChannelTypeGitHub, ChannelTypeMCP)
	}
	return nil
}

// DaemonConfig is the daemon: section of argus.yaml.
type DaemonConfig struct {
	// Socket overrides the Unix-domain-socket path the local channel
	// listens on. Empty means "<home>/argusd.sock".
	Socket string `yaml:"socket,omitempty"`

	// HTTPAddr is the address of the daemon's single HTTP front door (ADR
	// 0015): HTTP channels register fixed paths on it (/webhooks/github,
	// /mcp) rather than opening listeners of their own. Empty means the
	// default (":8080"). Exposure control belongs to the reverse proxy. The
	// front door slice binds it; the config v2 schema only accepts it here.
	HTTPAddr string `yaml:"http_addr,omitempty"`

	// MaxConcurrentSessions caps in-flight Sessions across all channels.
	// Above the cap new Sessions are politely rejected, never queued
	// (ADR 0004). Zero means the default of 4.
	MaxConcurrentSessions int `yaml:"max_concurrent_sessions,omitempty"`
}

// DefaultMaxConcurrentSessions is used when the config leaves the cap unset.
const DefaultMaxConcurrentSessions = 4

// DefaultHTTPAddr is the front-door address used when daemon.http_addr is
// unset (ADR 0015). Exposure control belongs to the reverse proxy, so the
// default binds every interface on the conventional port.
const DefaultHTTPAddr = ":8080"

// HTTPAddress returns the configured front-door address, or the default when
// unset. The daemon owns one HTTP listener here; HTTP channels register fixed
// paths on it rather than opening ports of their own.
func (d DaemonConfig) HTTPAddress() string {
	if d.HTTPAddr != "" {
		return d.HTTPAddr
	}
	return DefaultHTTPAddr
}

// SocketPath returns the configured socket path, or the default under home.
func (d DaemonConfig) SocketPath(home string) string {
	if d.Socket != "" {
		return d.Socket
	}
	return filepath.Join(home, "argusd.sock")
}

// SessionCap returns the configured cap, or the default when unset.
func (d DaemonConfig) SessionCap() int {
	if d.MaxConcurrentSessions > 0 {
		return d.MaxConcurrentSessions
	}
	return DefaultMaxConcurrentSessions
}

// ProviderConfig captures one provider's connection info. Today only `type`
// "gemini" is implemented; "openai" / "anthropic" / "ollama" are reserved.
//
// Both APIKey and URL accept the env(VAR_NAME) syntax for indirection —
// resolve them via ResolveAPIKey / ResolveURL rather than reading the raw
// fields directly.
type ProviderConfig struct {
	Type string `yaml:"type"`
	// APIKey is either a literal secret (discouraged) or an env() reference
	// like "env(GEMINI_API_KEY)". The env form is what `argus init` writes
	// so secrets stay out of the YAML file.
	APIKey string `yaml:"api_key,omitempty"`
	// URL is an optional base URL override (self-hosted or proxy
	// deployments). Empty means "use the provider's official endpoint".
	// Also accepts env() references.
	URL string `yaml:"url,omitempty"`
}

// ResolveValue takes a raw config string and returns:
//   - the value of the referenced env var, if `raw` is `env(VAR_NAME)`
//   - the raw string unchanged otherwise
//
// Whitespace inside env(...) is allowed: `env( GEMINI_API_KEY )` works.
// An empty env var name or a missing referenced variable both return an
// error so misconfiguration surfaces early rather than as a 401 from the
// provider.
func ResolveValue(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if !strings.HasPrefix(s, "env(") || !strings.HasSuffix(s, ")") {
		return raw, nil
	}
	name := strings.TrimSpace(s[len("env(") : len(s)-1])
	if name == "" {
		return "", fmt.Errorf("config: env() reference has empty variable name")
	}
	val := os.Getenv(name)
	if val == "" {
		return "", fmt.Errorf("config: env var %q is empty or unset", name)
	}
	return val, nil
}

// ResolveAPIKey returns the resolved secret. See ResolveValue for syntax.
func (p ProviderConfig) ResolveAPIKey() (string, error) {
	return ResolveValue(p.APIKey)
}

// ResolveURL returns the resolved URL (empty if not set).
func (p ProviderConfig) ResolveURL() (string, error) {
	if p.URL == "" {
		return "", nil
	}
	return ResolveValue(p.URL)
}

// EnvRef returns the raw config string formatted as an env() reference.
// Used by argus init when writing the YAML.
func EnvRef(varName string) string { return "env(" + varName + ")" }

// LoadConfig reads path. A missing file is not an error: the returned Config
// is empty and ready to be filled in by argus init.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	if err := checkLegacyKeys(b); err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return &c, nil
}

// checkLegacyKeys rejects config v1 keys with an error naming their v2
// replacement (ADR 0015). Argus has no installed base, so there is no
// dual-read: a stale key is a hard startup error, never a silently dead
// channel. It probes the raw YAML rather than the typed Config because the
// typed decode simply ignores unknown keys.
func checkLegacyKeys(b []byte) error {
	// Decode each section's entries as key→node maps so a removed sub-key is a
	// plain map lookup; presence of the removed top-level sections is a nil
	// check on their nodes.
	var probe struct {
		GitHub    *yaml.Node                      `yaml:"github"`
		MCP       *yaml.Node                      `yaml:"mcp"`
		CodeHosts map[string]map[string]yaml.Node `yaml:"codehosts"`
		Channels  map[string]map[string]yaml.Node `yaml:"channels"`
	}
	if err := yaml.Unmarshal(b, &probe); err != nil {
		// A genuine parse error surfaces from the typed decode with the path.
		return nil
	}
	if probe.GitHub != nil {
		return errors.New("config: the top-level `github:` section was removed (config v2, ADR 0015): declare the GitHub App under `codehosts:` (type: github, app_id, private_key_path) and its webhook under `channels:` (type: github, webhook_secret)")
	}
	if probe.MCP != nil {
		return errors.New("config: the top-level `mcp:` section was removed (config v2, ADR 0015): declare it under `channels:` with `type: mcp`")
	}
	for name, entry := range probe.CodeHosts {
		if _, ok := entry["installation_id"]; ok {
			return fmt.Errorf("config: codehost %q sets `installation_id`, which was removed (config v2, ADR 0015): the installation is derived per event/repository, so none is configured", name)
		}
	}
	for name, entry := range probe.Channels {
		if _, ok := entry["addr"]; ok {
			return fmt.Errorf("config: channel %q sets `addr`, which was removed (config v2, ADR 0015): the daemon exposes a single front door at `daemon.http_addr`", name)
		}
	}
	return nil
}

// SaveConfig serializes c to path, creating parent directories as needed.
// Permissions are 0644 (the file is non-secret).
func SaveConfig(path string, c *Config) error {
	if c == nil {
		return errors.New("config: cannot save nil Config")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("config: mkdir: %w", err)
	}
	out, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	return os.WriteFile(path, out, 0o644)
}

// ProviderForDefaultModel returns the provider entry whose name matches the
// family of DefaultModel. Today the matching is naive: model "gemini-x"
// maps to provider "gemini". Will grow when openai/anthropic land in v0.6.
func (c *Config) ProviderForDefaultModel() (ProviderConfig, string, error) {
	if c.DefaultModel == "" {
		return ProviderConfig{}, "", errors.New("config: default_model is unset (run `argus init`)")
	}
	for name, p := range c.Providers {
		if matchesProvider(name, p, c.DefaultModel) {
			return p, name, nil
		}
	}
	return ProviderConfig{}, "", fmt.Errorf("config: no provider configured for model %q", c.DefaultModel)
}

func matchesProvider(name string, p ProviderConfig, model string) bool {
	// Match on the provider name OR its type appearing as the model prefix.
	// e.g. provider name "gemini", model "gemini-2.5-flash" → match.
	for _, candidate := range []string{name, p.Type} {
		if candidate == "" {
			continue
		}
		if startsWith(model, candidate+"-") || model == candidate {
			return true
		}
	}
	return false
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

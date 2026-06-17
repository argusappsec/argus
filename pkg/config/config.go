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
}

// DaemonConfig is the daemon: section of argus.yaml.
type DaemonConfig struct {
	// Socket overrides the Unix-domain-socket path the local channel
	// listens on. Empty means "<home>/argusd.sock".
	Socket string `yaml:"socket,omitempty"`

	// MaxConcurrentSessions caps in-flight Sessions across all channels.
	// Above the cap new Sessions are politely rejected, never queued
	// (ADR 0004). Zero means the default of 4.
	MaxConcurrentSessions int `yaml:"max_concurrent_sessions,omitempty"`
}

// DefaultMaxConcurrentSessions is used when the config leaves the cap unset.
const DefaultMaxConcurrentSessions = 4

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
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return &c, nil
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

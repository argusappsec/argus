package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config is the user-editable preferences file (~/.argus/argus.yaml).
// Secrets do NOT live here — they belong in ~/.argus/.env. This file is
// intentionally readable: a human can hand-edit it to add a second provider
// or swap a default model.
//
// Example:
//
//	providers:
//	  gemini:
//	    type: gemini
//	    api_key_env: GEMINI_API_KEY
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
}

// ProviderConfig captures one provider's connection info. Today only `type`
// "gemini" is implemented; "openai" / "anthropic" / "ollama" are reserved.
type ProviderConfig struct {
	Type string `yaml:"type"`
	// APIKeyEnv is the name of the env var (in .env or the shell) that holds
	// the secret API key. Indirection on purpose: secrets never get committed.
	APIKeyEnv string `yaml:"api_key_env,omitempty"`
	// DefaultURL is an optional base URL override (for self-hosted or proxy
	// deployments). Empty means "use the provider's official endpoint".
	DefaultURL string `yaml:"default_url,omitempty"`
}

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

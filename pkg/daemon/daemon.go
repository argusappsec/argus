// Package daemon is the shared core of argusd: the DaemonContext every
// Channel receives, the SessionManager that allocates Sessions, and the
// dispatch that turns inbound events into agent runs.
//
// Shape fixed by ADR 0004: one process, one goroutine per Channel, shared
// state built once. Channels never construct Provider/Soul/Auth themselves —
// they receive a *Context and go through SessionManager.GetOrCreate and the
// Session dispatch methods.
//
// Freshness policy: users.yaml is re-read by the auth Resolver on every
// resolve; SOUL.md and MEMORY.md are snapshotted per Session via the Load*
// hooks; argus.yaml is read once at Build and requires a restart to change.
package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/argusappsec/argus/pkg/audit"
	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/budget"
	"github.com/argusappsec/argus/pkg/codehost/github"
	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/provider"
	"github.com/argusappsec/argus/pkg/provider/gemini"
	"github.com/argusappsec/argus/pkg/report"
	"github.com/argusappsec/argus/pkg/skill"
	"github.com/argusappsec/argus/pkg/soul"
)

// Channel is one transport binding (ADR 0004). Implementations listen on
// their own transport, extract an Identity, resolve it via Context.Auth,
// allocate a Session through Context.Sessions, and dispatch. Start blocks
// until ctx is cancelled.
type Channel interface {
	Name() string
	Start(ctx context.Context) error
}

// Context is the DaemonContext: state built once at daemon start and shared
// read-only by every Channel goroutine.
type Context struct {
	Home         string
	DefaultModel string
	SocketPath   string
	Pricing      budget.Pricing

	// PersonaName is the operator-chosen name this instance answers to
	// (persona.name in argus.yaml), or "" for the brand default. Like the rest
	// of argus.yaml it is read once at Build (restart to change): it feeds the
	// GitHub mention token and the agent's system prompt.
	PersonaName string

	Auth    *auth.Resolver
	Audit   *audit.Logger
	Reports *report.Writer
	Skills  *skill.Catalog
	Cloner  *github.Cloner

	// NewProvider builds a provider for modelID, validating it against the
	// configured providers. Called once per Session (cheap), so a --model
	// override is a per-Session concern, never a daemon restart.
	NewProvider func(ctx context.Context, modelID string) (provider.Provider, error)

	// LoadSoul / LoadMemory snapshot SOUL.md / MEMORY.md. Called at Session
	// creation so new Sessions see admin edits and freshly curated memory,
	// while a running Session keeps the identity it started with.
	LoadSoul   func() (*soul.Soul, error)
	LoadMemory func() (string, error)

	Sessions *SessionManager
}

// Build assembles a Context from the home directory and its argus.yaml.
// It loads <home>/.env into the process environment (provider secrets).
func Build(home string, cfg *config.Config) (*Context, error) {
	if cfg == nil {
		cfg = &config.Config{}
	}
	if cfg.DefaultModel == "" {
		return nil, fmt.Errorf("daemon: no model configured. Run `argus init` to pick one")
	}
	// The integration surface (codehosts:/channels:) is the startup gate: a
	// misconfigured file fails loudly here, never as a silent dead channel.
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	env, err := config.LoadEnv(filepath.Join(home, ".env"))
	if err != nil {
		return nil, fmt.Errorf("daemon: load .env: %w", err)
	}
	env.ApplyToProcess()

	aud, err := audit.NewLogger(filepath.Join(home, "audit.log.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("daemon: audit: %w", err)
	}

	dc := &Context{
		Home:         home,
		DefaultModel: cfg.DefaultModel,
		SocketPath:   cfg.Daemon.SocketPath(home),
		Pricing:      defaultPricing(),
		PersonaName:  strings.TrimSpace(cfg.Persona.Name),
		Auth:         auth.NewResolver(filepath.Join(home, "users.yaml")),
		Audit:        aud,
		Reports:      report.NewWriter(filepath.Join(home, "reports")),
		Skills:       skill.NewCatalog(skill.Builtin(), filepath.Join(home, "skills")),
		Cloner:       github.NewCloner(filepath.Join(home, "cache")),

		NewProvider: providerFactory(cfg),
		LoadSoul: func() (*soul.Soul, error) {
			return soul.Load(filepath.Join(home, "SOUL.md"))
		},
		LoadMemory: func() (string, error) {
			b, err := os.ReadFile(filepath.Join(home, "MEMORY.md"))
			if err != nil {
				if os.IsNotExist(err) {
					return "", nil
				}
				return "", err
			}
			return string(b), nil
		},
	}
	dc.Sessions = NewSessionManager(dc, cfg.Daemon.SessionCap())
	return dc, nil
}

// Close releases the Context's resources. It does NOT wait for in-flight
// curations — call Sessions.Drain first during graceful shutdown.
func (dc *Context) Close() error {
	if dc.Audit != nil {
		return dc.Audit.Close()
	}
	return nil
}

// providerFactory returns the per-Session provider constructor. The model id
// must map to a configured provider family (argus.yaml), with a direct
// GEMINI_API_KEY fallback for installs that exported the var but never ran
// `argus init`.
func providerFactory(cfg *config.Config) func(ctx context.Context, modelID string) (provider.Provider, error) {
	return func(ctx context.Context, modelID string) (provider.Provider, error) {
		apiKey, err := resolveAPIKey(cfg, modelID)
		if err != nil {
			return nil, err
		}
		return gemini.New(ctx, apiKey, modelID)
	}
}

// resolveAPIKey returns the secret for the provider that backs modelID.
func resolveAPIKey(cfg *config.Config, modelID string) (string, error) {
	if cfg != nil && len(cfg.Providers) > 0 {
		tmp := &config.Config{Providers: cfg.Providers, DefaultModel: modelID}
		if p, _, err := tmp.ProviderForDefaultModel(); err == nil {
			return p.ResolveAPIKey()
		}
	}
	if k := os.Getenv("GEMINI_API_KEY"); k != "" {
		return k, nil
	}
	return "", fmt.Errorf("no provider configured for model %q", modelID)
}

// defaultPricing is the hardcoded best-effort pricing table (USD per 1M
// tokens). The daemon owns cost computation — clients never see prices, only
// the resulting figures in usage frames.
func defaultPricing() budget.Pricing {
	return budget.Pricing{
		"gemini-2.5-flash": {InputUSDPer1M: 0.30, OutputUSDPer1M: 2.50},
		"gemini-2.5-pro":   {InputUSDPer1M: 1.25, OutputUSDPer1M: 10.00},
		"gemini-2.0-flash": {InputUSDPer1M: 0.10, OutputUSDPer1M: 0.40},
		"gemini-1.5-pro":   {InputUSDPer1M: 1.25, OutputUSDPer1M: 5.00},
		"gemini-1.5-flash": {InputUSDPer1M: 0.075, OutputUSDPer1M: 0.30},
	}
}

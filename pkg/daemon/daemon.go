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
	"github.com/argusappsec/argus/pkg/codehost"
	"github.com/argusappsec/argus/pkg/codehost/github"
	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/deployment"
	"github.com/argusappsec/argus/pkg/provider"
	"github.com/argusappsec/argus/pkg/report"
	"github.com/argusappsec/argus/pkg/security"
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

	// Shape is the derived Deployment shape (ADR 0023): deployment.Toolbox when
	// no LLM Provider is configured, deployment.Colleague when at least one is.
	// It is derived once at Build (ShapeOf) and never declared — no
	// configuration key selects it — and it is the single value every surface
	// whose extent depends on whether Argus can reason reads: the startup
	// notice, `argus doctor` and Channel validation today, and the MCP surface
	// ADR 0023 conditions on it. Nothing downstream asks again whether a
	// Provider exists.
	//
	// Its zero value is deployment.Toolbox, so a Context assembled by hand
	// promises reasoning only when it says so.
	Shape deployment.Shape

	// PersonaName is the operator-chosen name this instance answers to
	// (persona.name in argus.yaml), or "" for the brand default. Like the rest
	// of argus.yaml it is read once at Build (restart to change): it feeds the
	// GitHub mention token and the agent's system prompt.
	PersonaName string

	Auth    *auth.Resolver
	Audit   *audit.Logger
	Reports *report.Writer
	Skills  *skill.Catalog

	// CodeHost is the single authenticated codehost client, built once from
	// codehosts: at daemon start and shared by every consumer that clones or
	// calls the host API: the GitHub channel, the chat review tool, and the MCP
	// repo target (ADR 0015). It is nil when no codehost is configured — a
	// GitHub-free install (MCP-only, snapshot reviews, consult) is legitimate,
	// so consumers must guard for nil with a clear, user-facing error.
	CodeHost codehost.CodeHost

	// Commands is what the scanner Tools shell out through (semgrep, gitleaks,
	// osv-scanner). It lives on the Context rather than at Registry construction
	// because both places that build a Registry — a Session and the MCP surface
	// projected from one — must reach the same executor, and because a test that
	// drives the surface has to substitute it instead of running real binaries.
	//
	// Nil means the real executor (security.ExecRunner): a Context assembled by
	// hand runs actual scanners unless it deliberately says otherwise.
	Commands security.Runner

	// NewProvider builds a provider for modelID, validating it against the
	// configured providers. Called once per Session (cheap), so a --model
	// override is a per-Session concern, never a daemon restart — and not
	// called at all in a Toolbox, which has no Provider to build.
	//
	// modelID is the id as configured or overridden, which may carry a
	// `provider-name/` qualification: resolving it to a Provider — and to the
	// bare id that Provider puts on the wire — is this constructor's job, so
	// callers pass what the operator wrote and record that same form.
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
	// .env first: it holds the provider secrets, and the Deployment shape below
	// turns on one of them (the no-`providers:` fallback key), so the process
	// environment has to be complete before the shape is derived.
	env, err := config.LoadEnv(filepath.Join(home, ".env"))
	if err != nil {
		return nil, fmt.Errorf("daemon: load .env: %w", err)
	}
	env.ApplyToProcess()

	// Derived here, once, and carried on the Context from now on (ADR 0023).
	shape := ShapeOf(cfg)

	if !shape.IsToolbox() {
		// A Toolbox has no model to name — that is the shape, not a fault. A
		// Colleague still must: a Provider is configured, so a Session with
		// nothing to send it is a configuration error.
		if cfg.DefaultModel == "" {
			return nil, fmt.Errorf("daemon: no model configured. Run `argus init` to pick one")
		}
		// And the Provider it names has to be one a Session could actually
		// acquire. This is deliberately stricter than before: now that a
		// *missing* Provider is a deployment shape rather than a fatal error, a
		// *broken* one has to fail here — otherwise a typo (an ambiguous model
		// id, an api_key whose env() reference is unset) leaves a daemon that
		// looks healthy until the first turn, and reads like a working Toolbox.
		if _, err := ProviderSpecForModel(cfg, cfg.DefaultModel); err != nil {
			return nil, fmt.Errorf("daemon: %w", err)
		}
	}

	// The integration surface (codehosts:/channels:) is the startup gate: a
	// misconfigured file fails loudly here, never as a silent dead channel —
	// and in a Toolbox a Channel that cannot work without reasoning is exactly
	// that kind of misconfiguration.
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := validateChannelsForShape(cfg, shape); err != nil {
		return nil, err
	}

	aud, err := audit.NewLogger(filepath.Join(home, "audit.log.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("daemon: audit: %w", err)
	}

	dc := &Context{
		Home:         home,
		DefaultModel: cfg.DefaultModel,
		SocketPath:   cfg.Daemon.SocketPath(home),
		Shape:        shape,
		PersonaName:  strings.TrimSpace(cfg.Persona.Name),
		Auth:         auth.NewResolver(filepath.Join(home, "users.yaml")),
		Audit:        aud,
		Reports:      report.NewWriter(filepath.Join(home, "reports")),
		Skills:       skill.NewCatalog(skill.Builtin(), filepath.Join(home, "skills")),

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
	// Build the one authenticated codehost client from codehosts: and share it
	// (ADR 0015). Validate has already guaranteed a github channel has its
	// github codehost, so any consumer that needs the client finds it here.
	if host, ok := cfg.CodeHost(config.CodeHostTypeGitHub); ok {
		ch, err := github.BuildCodeHost(filepath.Join(home, "cache"), host)
		if err != nil {
			return nil, fmt.Errorf("daemon: github codehost: %w", err)
		}
		dc.CodeHost = ch
	}

	dc.Sessions = NewSessionManager(dc, cfg.Daemon.SessionCap())
	return dc, nil
}

// commands is the Runner the scanner Tools shell out through: the one injected
// on the Context, or the real executor when nothing was injected. The default
// lives next to the field it defaults, so there is one answer to what "nothing
// injected" means and both Registry callers get it.
func (dc *Context) commands() security.Runner {
	if dc.Commands != nil {
		return dc.Commands
	}
	return security.ExecRunner{}
}

// Close releases the Context's resources. It does NOT wait for in-flight
// curations — call Sessions.Drain first during graceful shutdown.
func (dc *Context) Close() error {
	if dc.Audit != nil {
		return dc.Audit.Close()
	}
	return nil
}

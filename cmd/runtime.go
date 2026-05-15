package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/redcarbon-dev/argus/pkg/audit"
	"github.com/redcarbon-dev/argus/pkg/budget"
	"github.com/redcarbon-dev/argus/pkg/codehost/github"
	"github.com/redcarbon-dev/argus/pkg/config"
	"github.com/redcarbon-dev/argus/pkg/conversation"
	"github.com/redcarbon-dev/argus/pkg/provider"
	"github.com/redcarbon-dev/argus/pkg/provider/gemini"
	"github.com/redcarbon-dev/argus/pkg/security"
	"github.com/redcarbon-dev/argus/pkg/session"
	"github.com/redcarbon-dev/argus/pkg/soul"
	"github.com/redcarbon-dev/argus/pkg/tool"
)

// runtime bundles all the per-run dependencies shared between argus chat and
// argus review. Constructing them in one place keeps the two commands
// drift-proof — if a new tool is added, it's registered here once.
type runtime struct {
	Home    string
	ModelID string // resolved model id (flag override > config default)

	Session      *session.Session
	Registry     *tool.Registry
	Soul         *soul.Soul
	Cloner       *github.Cloner
	Audit        *audit.Logger
	Conversation *conversation.Writer
	ConvoPath    string
	Provider     provider.Provider
}

// runtimeOptions captures user-facing knobs that affect the runtime.
type runtimeOptions struct {
	HomeOverride string
	Model        string
}

// buildRuntime assembles a runtime, creating files under the home dir as
// needed. The caller is responsible for calling Close() at end of life.
func buildRuntime(ctx context.Context, opts runtimeOptions) (*runtime, error) {
	home, err := resolveHome(opts.HomeOverride)
	if err != nil {
		return nil, err
	}

	// Load preferences first (argus.yaml) and then secrets (~/.argus/.env).
	// Shell-exported values still win in env (handled by ApplyToProcess).
	cfg, err := config.LoadConfig(filepath.Join(home, "argus.yaml"))
	if err != nil {
		return nil, err
	}
	if err := loadHomeEnv(home); err != nil {
		return nil, err
	}

	// Resolve the model id: explicit --model flag > argus.yaml default.
	modelID := opts.Model
	if modelID == "" {
		modelID = cfg.DefaultModel
	}
	if modelID == "" {
		return nil, fmt.Errorf("no model configured. Run `argus init` to pick one, or pass --model")
	}

	// Resolve the provider's API key via the config (env() reference is the
	// common case). Falls back to direct GEMINI_API_KEY lookup so users who
	// haven't run `argus init` yet but exported the var still get a working
	// runtime.
	apiKey, err := resolveAPIKey(cfg, modelID)
	if err != nil {
		return nil, fmt.Errorf("api key: %w (run `argus init` to configure)", err)
	}

	sess := session.New()

	convoPath := filepath.Join(home, "conversations", sess.ID()+".jsonl")
	convoWriter, err := conversation.NewWriter(convoPath, sess.ID())
	if err != nil {
		return nil, fmt.Errorf("conversation: %w", err)
	}

	aud, err := audit.NewLogger(filepath.Join(home, "audit.log.jsonl"))
	if err != nil {
		convoWriter.Close()
		return nil, fmt.Errorf("audit: %w", err)
	}

	soulPtr, err := soul.Load(filepath.Join(home, "SOUL.md"))
	if err != nil {
		aud.Close()
		convoWriter.Close()
		return nil, fmt.Errorf("soul: %w", err)
	}

	prov, err := gemini.New(ctx, apiKey, modelID)
	if err != nil {
		aud.Close()
		convoWriter.Close()
		return nil, fmt.Errorf("gemini: %w", err)
	}

	cloner := github.NewCloner(filepath.Join(home, "cache"))

	reg := tool.NewRegistry()
	reg.Register(tool.NewListFiles(sess))
	reg.Register(tool.NewReadFile(sess))
	reg.Register(tool.NewGrep(sess))
	reg.Register(tool.NewListContext(filepath.Join(home, "context")))
	reg.Register(tool.NewReadContext(filepath.Join(home, "context")))
	reg.Register(tool.NewWriteContext(filepath.Join(home, "context")))
	reg.Register(tool.NewStartReviewLocal(sess))
	reg.Register(tool.NewStartReviewGitHub(sess, cloner))
	reg.Register(security.NewSemgrep(sess, security.ExecRunner{}))
	reg.Register(security.NewGitleaks(sess, security.ExecRunner{}))

	return &runtime{
		Home:         home,
		ModelID:      modelID,
		Session:      sess,
		Registry:     reg,
		Soul:         soulPtr,
		Cloner:       cloner,
		Audit:        aud,
		Conversation: convoWriter,
		ConvoPath:    convoPath,
		Provider:     prov,
	}, nil
}

// defaultPricing returns a hardcoded best-effort pricing table for the
// models Argus knows about. Numbers are USD per 1M tokens, sourced from the
// provider's public pricing page as of the time this code was written. They
// drift; v0.4+ will move this to argus.yaml so users can override.
func defaultPricing() budget.Pricing {
	return budget.Pricing{
		"gemini-2.5-flash": {InputUSDPer1M: 0.30, OutputUSDPer1M: 2.50},
		"gemini-2.5-pro":   {InputUSDPer1M: 1.25, OutputUSDPer1M: 10.00},
		"gemini-2.0-flash": {InputUSDPer1M: 0.10, OutputUSDPer1M: 0.40},
		"gemini-1.5-pro":   {InputUSDPer1M: 1.25, OutputUSDPer1M: 5.00},
		"gemini-1.5-flash": {InputUSDPer1M: 0.075, OutputUSDPer1M: 0.30},
	}
}

// Close releases the runtime's resources. Safe to call on a nil runtime.
func (r *runtime) Close() error {
	if r == nil {
		return nil
	}
	var first error
	if r.Audit != nil {
		if err := r.Audit.Close(); err != nil {
			first = err
		}
	}
	if r.Conversation != nil {
		if err := r.Conversation.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// loadHomeEnv loads <home>/.env into the process environment. Missing file
// is not an error.
func loadHomeEnv(home string) error {
	e, err := config.LoadEnv(filepath.Join(home, ".env"))
	if err != nil {
		return fmt.Errorf("load .env: %w", err)
	}
	e.ApplyToProcess()
	return nil
}

// resolveAPIKey returns the secret for the provider that backs modelID.
// First tries cfg's provider entry (the canonical path after `argus init`).
// If the config has no matching provider, falls back to a direct lookup of
// GEMINI_API_KEY so a freshly-shell-exported value still works.
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
	return "", fmt.Errorf("no provider configured for model %q and GEMINI_API_KEY unset", modelID)
}

// resolveHome returns the directory Argus reads and writes state from.
// Precedence: explicit override > ARGUS_HOME env > $HOME/.argus.
// The directory is created if missing.
func resolveHome(override string) (string, error) {
	if override != "" {
		if err := os.MkdirAll(override, 0o700); err != nil {
			return "", fmt.Errorf("create home: %w", err)
		}
		return override, nil
	}
	if env := os.Getenv("ARGUS_HOME"); env != "" {
		if err := os.MkdirAll(env, 0o700); err != nil {
			return "", fmt.Errorf("create home: %w", err)
		}
		return env, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home dir: %w", err)
	}
	dir := filepath.Join(home, ".argus")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create home: %w", err)
	}
	return dir, nil
}

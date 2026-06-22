// Package doctor implements `argus doctor` — pre-flight check of the
// runtime environment. It verifies that required and optional dependencies
// are present, that the user's home directory is configured, and that an
// LLM API key is reachable.
//
// The checks are pure (only filesystem + os/exec.LookPath) so they are
// cheap to run and easy to test without touching the network.
package doctor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/redcarbon-dev/argus/pkg/config"
	"github.com/redcarbon-dev/argus/pkg/soul"
	"github.com/redcarbon-dev/argus/pkg/tool"
)

// Status is the outcome of a single check.
type Status int

const (
	Pass Status = iota
	Fail
	Info // informational only — neither pass nor fail
)

// Severity is how much the operator should care about a Fail.
type Severity int

const (
	SeverityRequired Severity = iota
	SeverityOptional
	SeverityInfo
)

// Check is one row in the doctor output.
type Check struct {
	Name     string   // short identifier (binary name, file name, etc.)
	Status   Status   // Pass / Fail / Info
	Severity Severity // how critical
	Message  string   // success detail (version, path, summary)
	Hint     string   // when Fail: how to fix
}

// ExtraBinary lets the caller declare binary deps that aren't owned by any
// Tool (e.g. git, used by pkg/codehost/github). doctor checks them with the
// same machinery as tool-owned binaries.
type ExtraBinary struct {
	Name        string
	Required    bool
	UsedBy      string // human-friendly description ("cloning repositories")
	InstallHint string
}

// Options control which environment doctor inspects.
type Options struct {
	Home string // ~/.argus directory; required

	// Registry is the tool registry to inspect for binary deps. Tools that
	// implement tool.Requirer are asked what they need; tools that don't are
	// ignored. Pass nil to skip tool-derived checks (rare; only useful in
	// tests).
	Registry *tool.Registry

	// ExtraBinaries are binary deps the caller knows about but aren't owned
	// by any tool (e.g. git).
	ExtraBinaries []ExtraBinary

	// GitHub, when non-nil, adds a check of the GitHub App channel (ADR 0008):
	// that the App credentials are present and a token can be minted.
	GitHub *config.GitHubConfig

	// GitHubMint mints an installation token to prove the credentials work.
	// It is injected (the network call lives in the caller, keeping the
	// doctor package itself pure). Nil means the mint is not attempted —
	// only credential presence is checked.
	GitHubMint func(ctx context.Context) error
}

// Run executes all checks and returns the results in display order.
func Run(opts Options) []Check {
	var out []Check
	out = append(out, binaryChecks(opts.Registry, opts.ExtraBinaries)...)
	out = append(out, configChecks(opts.Home)...)
	out = append(out, soulCheck(opts.Home))
	out = append(out, contextCheck(opts.Home))
	if opts.GitHub != nil {
		out = append(out, githubCheck(*opts.GitHub, opts.GitHubMint))
	}
	return out
}

// githubCheck verifies the GitHub App channel is ready: credentials present
// (env() references resolve, private key file exists) and — when a mint
// function is supplied — that an installation token can be minted.
func githubCheck(cfg config.GitHubConfig, mint func(ctx context.Context) error) Check {
	c := Check{Name: "github", Severity: SeverityOptional}
	if !cfg.Configured() {
		c.Status = Info
		c.Severity = SeverityInfo
		c.Message = "channel not configured (no github: section) — skipping"
		return c
	}
	for _, f := range []struct {
		name    string
		resolve func() (string, error)
	}{
		{"app_id", cfg.ResolveAppID},
		{"installation_id", cfg.ResolveInstallationID},
		{"webhook_secret", cfg.ResolveWebhookSecret},
	} {
		if _, err := f.resolve(); err != nil {
			c.Status = Fail
			c.Hint = fmt.Sprintf("github.%s: %v", f.name, err)
			return c
		}
	}
	if _, err := os.Stat(cfg.PrivateKeyPath); err != nil {
		c.Status = Fail
		c.Hint = "private key not readable at " + cfg.PrivateKeyPath
		return c
	}
	if mint == nil {
		c.Status = Pass
		c.Message = "App credentials present (token mint not attempted)"
		return c
	}
	if err := mint(context.Background()); err != nil {
		c.Status = Fail
		c.Hint = "could not mint installation token: " + err.Error()
		return c
	}
	c.Status = Pass
	c.Message = "App credentials present, installation token minted"
	return c
}

// binaryChecks composes two sources: (a) ExtraBinaries from the caller and
// (b) Requirements declared by tools in the registry that implement
// tool.Requirer. Duplicates (same Binary name) are kept only once.
func binaryChecks(reg *tool.Registry, extras []ExtraBinary) []Check {
	seen := map[string]bool{}
	out := make([]Check, 0, len(extras)+4)

	// ExtraBinaries first — they include the required ones (git).
	for _, e := range extras {
		if seen[e.Name] {
			continue
		}
		seen[e.Name] = true
		out = append(out, binaryCheck(e.Name, severityFromRequired(e.Required), e.UsedBy, e.InstallHint))
	}

	// Then tool-derived binaries.
	if reg != nil {
		for _, decl := range reg.Decls() {
			t, ok := reg.Get(decl.Name)
			if !ok {
				continue
			}
			req, ok := t.(tool.Requirer)
			if !ok {
				continue
			}
			for _, r := range req.Requires() {
				if seen[r.Binary] {
					continue
				}
				seen[r.Binary] = true
				out = append(out, binaryCheck(r.Binary, SeverityOptional, decl.Name+" tool", r.InstallHint))
			}
		}
	}
	return out
}

func binaryCheck(name string, sev Severity, usedBy, hint string) Check {
	c := Check{Name: name, Severity: sev}
	if _, err := exec.LookPath(name); err == nil {
		c.Status = Pass
		c.Message = usedBy
	} else {
		c.Status = Fail
		c.Hint = "install: " + hint
	}
	return c
}

func severityFromRequired(required bool) Severity {
	if required {
		return SeverityRequired
	}
	return SeverityOptional
}

func configChecks(home string) []Check {
	var out []Check

	// argus.yaml
	yamlPath := filepath.Join(home, "argus.yaml")
	cfg, err := config.LoadConfig(yamlPath)
	yamlCheck := Check{Name: "argus.yaml", Severity: SeverityOptional}
	switch {
	case err != nil:
		yamlCheck.Status = Fail
		yamlCheck.Hint = "run `argus init` to populate it"
	case cfg.DefaultModel == "" || len(cfg.Providers) == 0:
		yamlCheck.Status = Fail
		yamlCheck.Hint = "incomplete config; run `argus init` to (re-)populate"
	default:
		yamlCheck.Status = Pass
		var providerNames []string
		for name := range cfg.Providers {
			providerNames = append(providerNames, name)
		}
		yamlCheck.Message = fmt.Sprintf("provider=%s, default_model=%s", joinSorted(providerNames), cfg.DefaultModel)
	}
	out = append(out, yamlCheck)

	// .env / GEMINI_API_KEY (load .env into the process if not already)
	envPath := filepath.Join(home, ".env")
	if e, lerr := config.LoadEnv(envPath); lerr == nil {
		e.ApplyToProcess()
	}
	keyCheck := Check{Name: "GEMINI_API_KEY", Severity: SeverityRequired}
	if v := os.Getenv("GEMINI_API_KEY"); v != "" {
		keyCheck.Status = Pass
		source := "shell environment"
		if _, err := os.Stat(envPath); err == nil {
			source = envPath
		}
		keyCheck.Message = "set (source: " + source + ")"
	} else {
		keyCheck.Status = Fail
		keyCheck.Hint = "run `argus init` to configure your provider and API key"
	}
	out = append(out, keyCheck)

	return out
}

func soulCheck(home string) Check {
	path := filepath.Join(home, "SOUL.md")
	c := Check{Name: "SOUL.md", Severity: SeverityOptional}

	s, err := soul.Load(path)
	switch {
	case err != nil:
		c.Status = Fail
		c.Hint = "could not parse: " + err.Error()
	case s == nil:
		c.Status = Info
		c.Message = "not configured — run `argus init` to create one"
	default:
		c.Status = Pass
		populated := 0
		if s.Company != "" {
			populated++
		}
		if s.Industry != "" {
			populated++
		}
		if s.DataSensitivity != "" {
			populated++
		}
		if len(s.PrimaryStack) > 0 {
			populated++
		}
		if len(s.Infra) > 0 {
			populated++
		}
		if s.SecretStorage != "" {
			populated++
		}
		if len(s.Compliance) > 0 {
			populated++
		}
		if s.RiskTolerance != "" {
			populated++
		}
		if s.Escalation != "" {
			populated++
		}
		if s.Persona != "" {
			populated++
		}
		c.Message = fmt.Sprintf("company=%s, %d/10 fields populated", emptyOrValue(s.Company), populated)
	}
	return c
}

func contextCheck(home string) Check {
	dir := filepath.Join(home, "context")
	c := Check{Name: "context/", Severity: SeverityInfo, Status: Info}
	entries, err := os.ReadDir(dir)
	if err != nil {
		c.Message = "no context/ yet — agent will create it on first write_context"
		return c
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			n++
		}
	}
	if n == 0 {
		c.Message = "directory exists but is empty"
	} else {
		c.Message = fmt.Sprintf("%d document(s) on file", n)
	}
	return c
}

// Summary aggregates the result of Run for the top-line message.
type Summary struct {
	OK              int
	RequiredFailed  int
	OptionalMissing int
	Infos           int
}

// HasBlockingFailure returns true if any required check failed.
func (s Summary) HasBlockingFailure() bool { return s.RequiredFailed > 0 }

// Summarize counts the outcome categories.
func Summarize(checks []Check) Summary {
	var s Summary
	for _, c := range checks {
		switch {
		case c.Status == Pass:
			s.OK++
		case c.Status == Fail && c.Severity == SeverityRequired:
			s.RequiredFailed++
		case c.Status == Fail:
			s.OptionalMissing++
		case c.Status == Info:
			s.Infos++
		}
	}
	return s
}

func joinSorted(ss []string) string {
	switch len(ss) {
	case 0:
		return "-"
	case 1:
		return ss[0]
	}
	for i := range ss {
		for j := i + 1; j < len(ss); j++ {
			if ss[j] < ss[i] {
				ss[i], ss[j] = ss[j], ss[i]
			}
		}
	}
	out := ss[0]
	for _, s := range ss[1:] {
		out += "," + s
	}
	return out
}

func emptyOrValue(v string) string {
	if v == "" {
		return "(unset)"
	}
	return v
}

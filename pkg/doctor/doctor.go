// Package doctor implements `argus doctor` — pre-flight check of the
// runtime environment. It verifies that required and optional dependencies
// are present, that the user's home directory is configured, that each
// configured LLM Provider's API key is reachable, and — for a Provider whose
// protocol allows it to be asked — that the endpoint and model actually meet
// what Argus needs of them.
//
// The checks are pure (only filesystem + os/exec.LookPath) so they are
// cheap to run and easy to test without touching the network. Everything that
// does touch the network — minting a GitHub token, the front-door health check,
// the Provider capability probe — arrives as an injected function field on
// Options, so the call lives in the caller and this package stays testable by
// substitution.
package doctor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/deployment"
	"github.com/argusappsec/argus/pkg/soul"
	"github.com/argusappsec/argus/pkg/tool"
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

	// Shape is the daemon's derived Deployment shape (daemon.ShapeOf). It is
	// passed in rather than re-derived: the condition that decides it lives on
	// the daemon Context, and doctor holding a second opinion is how the two
	// come to disagree. It decides which checks apply at all — a Toolbox is a
	// deployment shape, not a Colleague missing its Provider, so it is never
	// reported as broken for having none.
	Shape deployment.Shape

	// Registry is the tool registry to inspect for binary deps. Tools that
	// implement tool.Requirer are asked what they need; tools that don't are
	// ignored. Pass nil to skip tool-derived checks (rare; only useful in
	// tests).
	Registry *tool.Registry

	// ExtraBinaries are binary deps the caller knows about but aren't owned
	// by any tool (e.g. git).
	ExtraBinaries []ExtraBinary

	// GitHub, when non-nil, adds a check of the GitHub codehost (ADR 0015):
	// that the App credentials are present and the private key can sign an
	// App JWT.
	GitHub *config.CodeHostConfig

	// GitHubMint mints an installation token to prove the credentials work.
	// It is injected (the network call lives in the caller, keeping the
	// doctor package itself pure). Nil means the mint is not attempted —
	// only credential presence is checked.
	GitHubMint func(ctx context.Context) error

	// FrontDoorAddr, when non-empty, adds a check that the daemon's single HTTP
	// front door (ADR 0015) answers its /healthz probe. It is set only when at
	// least one HTTP channel is configured — the front door exists only then, so
	// a socket-only install grows no front-door row.
	FrontDoorAddr string

	// FrontDoorProbe reports whether the front door answers its health check at
	// FrontDoorAddr. Injected so the network call lives in the caller, keeping
	// the doctor package pure. Nil means the address is reported (Info) but not
	// probed.
	FrontDoorProbe func(ctx context.Context) error

	// Provider, when non-nil, adds a check of the LLM Provider backing the
	// configured default model (ADR 0020): the same Provider the daemon would
	// build. Nil means the caller could not identify one, and the argus.yaml and
	// api-key rows already say why.
	Provider *ProviderTarget

	// ProviderModels lists the model ids the endpoint reports (GET /models). It is
	// the cheapest question worth asking — one request settles reachability, key
	// validity and the existence of the configured model id, all before a token is
	// spent — so it runs first. Injected, like every other probe here, so the
	// network call lives in the caller. Nil means the listing is not attempted.
	ProviderModels func(ctx context.Context) ([]string, error)

	// ProviderToolCall performs one minimal generation carrying a throwaway tool
	// declaration and reports whether the response actually contained a tool call.
	// It is a separate stage because it answers a separate question: servers that
	// accept tool declarations and then ignore them pass ProviderModels and fail
	// here. Nil means the generation is not attempted.
	ProviderToolCall func(ctx context.Context) (bool, error)

	// BinariesOnly restricts Run to the image-contract check (ADR 0013):
	// only binary checks execute, and every binary is treated as blocking
	// (Required) regardless of its per-tool "optional" severity. This is the
	// check CI runs against the batteries-included image — inside the official
	// image "optional" does not exist; everything the image promises is owed.
	// Non-binary checks (config, API keys, the LLM Provider probe, SOUL, context,
	// GitHub, the front door) are skipped and cannot affect the outcome — which
	// also means the image contract never reaches the network.
	BinariesOnly bool
}

// Run executes all checks and returns the results in display order.
func Run(opts Options) []Check {
	if opts.BinariesOnly {
		checks := binaryChecks(opts.Registry, opts.ExtraBinaries)
		for i := range checks {
			checks[i].Severity = SeverityRequired
		}
		return checks
	}

	var out []Check
	out = append(out, binaryChecks(opts.Registry, opts.ExtraBinaries)...)
	out = append(out, configChecks(opts.Home, opts.Shape)...)
	// Straight after the configuration rows: those say what is configured, this
	// one says whether it works.
	if opts.Provider != nil {
		out = append(out, providerCheck(*opts.Provider, opts.ProviderModels, opts.ProviderToolCall))
	}
	out = append(out, soulCheck(opts.Home))
	out = append(out, contextCheck(opts.Home))
	if opts.GitHub != nil {
		out = append(out, githubCheck(*opts.GitHub, opts.GitHubMint))
	}
	if opts.FrontDoorAddr != "" {
		out = append(out, frontDoorCheck(opts.FrontDoorAddr, opts.FrontDoorProbe))
	}
	return out
}

// deploymentCheck reports the Deployment shape this installation runs as. It is
// informational by construction: neither shape is a fault, and naming the one in
// force is what keeps an operator from hunting for a Review that this daemon was
// never going to offer (ADR 0023).
func deploymentCheck(shape deployment.Shape) Check {
	c := Check{Name: "deployment", Status: Info, Severity: SeverityInfo}
	if shape.IsToolbox() {
		c.Message = "toolbox — no LLM Provider configured: Argus serves its scanners, the organization's " +
			"knowledge and its Skills over MCP and does not reason on its own behalf (review, consult and " +
			"automatic PR review need a Provider — `argus init` adds one)"
		return c
	}
	c.Message = "colleague — an LLM Provider is configured: Argus reasons on its own behalf (review, consult, " +
		"automatic PR review) and serves the toolbox as well"
	return c
}

// frontDoorCheck verifies the daemon's single HTTP front door (ADR 0015) is
// reachable: a GET /healthz on daemon.http_addr answers 200. The probe is
// injected so the network call lives in the caller (keeping doctor pure); a nil
// probe reports the configured address without contacting it.
func frontDoorCheck(addr string, probe func(ctx context.Context) error) Check {
	c := Check{Name: "front door", Severity: SeverityOptional}
	if probe == nil {
		c.Status = Info
		c.Severity = SeverityInfo
		c.Message = "configured at " + addr + " (not probed)"
		return c
	}
	if err := probe(context.Background()); err != nil {
		c.Status = Fail
		c.Hint = fmt.Sprintf("not reachable at %s: %v — is `argus daemon` running and is %s the address your reverse proxy targets?", addr, err, addr)
		return c
	}
	c.Status = Pass
	c.Message = "reachable at " + addr + " (/healthz → 200)"
	return c
}

// githubCheck verifies the GitHub codehost is ready: credentials present
// (the app_id env() reference resolves, the private key file exists) and —
// when a verify function is supplied — that the private key can sign an App
// JWT. The installation is derived per event/repo (ADR 0015), so there is no
// pinned installation token to mint here.
func githubCheck(cfg config.CodeHostConfig, mint func(ctx context.Context) error) Check {
	c := Check{Name: "github", Severity: SeverityOptional}
	if !cfg.Configured() {
		c.Status = Info
		c.Severity = SeverityInfo
		c.Message = "codehost not configured (no github codehost) — skipping"
		return c
	}
	if _, err := cfg.ResolveAppID(); err != nil {
		c.Status = Fail
		c.Hint = fmt.Sprintf("codehosts.github.app_id: %v", err)
		return c
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
		c.Hint = "could not sign App JWT with the private key: " + err.Error()
		return c
	}
	c.Status = Pass
	c.Message = "App credentials present, private key signs an App JWT"
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

func configChecks(home string, shape deployment.Shape) []Check {
	var out []Check

	// argus.yaml
	yamlPath := filepath.Join(home, "argus.yaml")
	cfg, err := config.LoadConfig(yamlPath)

	// The Deployment shape leads the configuration rows, because it is what
	// they have to be read against: the same absent Provider is a fault in one
	// shape and the shape itself in the other. It is omitted when the config
	// could not be read at all — the caller derived the shape from an
	// environment it could only half see, and a confident "toolbox" beside a
	// config that may well declare Providers would be a guess presented as an
	// answer. The row below carries the real problem.
	if err == nil {
		out = append(out, deploymentCheck(shape))
	}

	yamlCheck := Check{Name: "argus.yaml", Severity: SeverityOptional}
	switch {
	case err != nil:
		// LoadConfig treats a missing file as an empty config, so a non-nil
		// error is a real problem: a legacy v2 key (whose message names the
		// replacement) or a parse error. Surface it verbatim rather than a
		// generic "run init" — the config's own message is the actionable one.
		yamlCheck.Status = Fail
		yamlCheck.Hint = err.Error()
	case shape.IsToolbox():
		// No Provider and no model is not an incomplete config here: it is the
		// Toolbox, which the deployment row above has already explained.
		// Reporting it as a fault would tell an operator to fix the thing they
		// chose.
		yamlCheck.Status = Info
		yamlCheck.Severity = SeverityInfo
		yamlCheck.Message = "no `providers:` configured, and none is needed in a toolbox"
	case cfg.DefaultModel == "" || len(cfg.Providers) == 0:
		yamlCheck.Status = Fail
		yamlCheck.Hint = "incomplete config; run `argus init` to (re-)populate"
	default:
		var providerNames []string
		for name := range cfg.Providers {
			providerNames = append(providerNames, name)
		}
		// A default_model that resolves to no configured Provider — or to several —
		// is a config no Session can start, and until this ran doctor reported a
		// pass for it and left the operator to discover it mid-Review. The rule set
		// is config's, and so is the message: it already names the candidates, the
		// ambiguity, and the qualified `<provider>/<model-id>` form to write
		// instead. Blocking, unlike the rest of this row: the failure is
		// unambiguous, purely local, and total.
		if _, _, _, rerr := cfg.ProviderForModel(cfg.DefaultModel); rerr != nil {
			yamlCheck.Status = Fail
			yamlCheck.Severity = SeverityRequired
			yamlCheck.Hint = fmt.Sprintf("provider=%s, but default_model=%s resolves to none of them: %v", joinSorted(providerNames), cfg.DefaultModel, rerr)
			break
		}
		yamlCheck.Status = Pass
		yamlCheck.Message = fmt.Sprintf("provider=%s, default_model=%s", joinSorted(providerNames), cfg.DefaultModel)
	}
	out = append(out, yamlCheck)

	// Credentials, one row per configured Provider. The .env file is applied to
	// the process first so the env() references in those entries resolve.
	envPath := filepath.Join(home, ".env")
	if e, lerr := config.LoadEnv(envPath); lerr == nil {
		e.ApplyToProcess()
	}
	// A config that failed to load yields a nil cfg; apiKeyChecks reads that as
	// "no Providers known" and reports the fallback credential, which is what
	// Argus would actually reach for.
	out = append(out, apiKeyChecks(cfg, envPath, shape)...)

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
		if s.Language != "" {
			populated++
		}
		if len(s.SeverityRules) > 0 {
			populated++
		}
		if s.Persona != "" {
			populated++
		}
		c.Message = fmt.Sprintf("company=%s, %d/11 fields populated", emptyOrValue(s.Company), populated)
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

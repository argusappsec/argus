package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	cdgithub "github.com/argusappsec/argus/pkg/codehost/github"
	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/daemon"
	"github.com/argusappsec/argus/pkg/doctor"
	"github.com/argusappsec/argus/pkg/provider"
	"github.com/argusappsec/argus/pkg/provider/factory"
	"github.com/argusappsec/argus/pkg/security"
	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

// doctorCmd performs a pre-flight check of the environment. Exits 0 when all
// required checks pass (optional missing is fine), 1 otherwise. This makes
// the command CI-friendly: scripts can gate "should I run argus?" on
// `argus doctor`'s exit code.
func doctorCmd() *cobra.Command {
	var homeDir string
	var binariesOnly bool
	c := &cobra.Command{
		Use:   "doctor",
		Short: "Check that Argus's dependencies and configuration are ready.",
		Long: "Run a pre-flight check on:\n" +
			"  • CLI binaries Argus shells out to (git, semgrep, gitleaks, osv-scanner, …)\n" +
			"  • argus.yaml (provider configured? default model set?)\n" +
			"  • the API key each configured provider needs (in .env or shell)\n" +
			"  • the LLM provider itself: for an openai-compatible endpoint, that it is\n" +
			"    reachable, that it serves your model id, and that your model actually\n" +
			"    emits a tool call — Argus certifies nobody's server, so this is where\n" +
			"    verification happens\n" +
			"  • SOUL.md (present? populated?)\n" +
			"  • context/ (any documents on file?)\n\n" +
			"Exit code 0 = all required checks pass; 1 = at least one required check failed.\n\n" +
			"--binaries runs the image-contract check only: it verifies just the CLI\n" +
			"binaries and treats every one as blocking (ADR 0013). This is the gate CI\n" +
			"runs inside the official batteries-included image — there \"optional\" does\n" +
			"not exist; everything the image promises is owed. Exit 0 = all present, 1 =\n" +
			"any missing.",
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := resolveHome(homeDir)
			if err != nil {
				return err
			}
			opts := doctor.Options{
				Home:          home,
				Registry:      doctorRegistry(),
				ExtraBinaries: extraBinaries(),
				BinariesOnly:  binariesOnly,
			}
			if !binariesOnly {
				opts.GitHub, opts.GitHubMint = githubDoctorOptions(home)
				opts.FrontDoorAddr, opts.FrontDoorProbe = frontDoorDoctorOptions(home)
				opts.Provider, opts.ProviderModels, opts.ProviderToolCall = providerDoctorOptions(home)
			}
			checks := doctor.Run(opts)
			renderChecks(cmd.OutOrStdout(), checks)
			summary := doctor.Summarize(checks)
			renderSummary(cmd.OutOrStdout(), summary)
			if summary.HasBlockingFailure() {
				return fmt.Errorf("one or more required checks failed")
			}
			return nil
		},
	}
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	c.Flags().BoolVar(&binariesOnly, "binaries", false, "Check only CLI binaries, treating every one as blocking (image contract / CI gate)")
	return c
}

var (
	stylePass   = lipgloss.NewStyle().Foreground(lipgloss.Color("#7ee5a3")).Bold(true)
	styleFailRq = lipgloss.NewStyle().Foreground(lipgloss.Color("#e07070")).Bold(true)
	styleFailOp = lipgloss.NewStyle().Foreground(lipgloss.Color("#e0c060"))
	styleInfo   = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
	styleName   = lipgloss.NewStyle().Bold(true)
	styleMsg    = lipgloss.NewStyle().Foreground(lipgloss.Color("#aaaaaa"))
	styleHint   = lipgloss.NewStyle().Foreground(lipgloss.Color("#aaaaaa")).Italic(true)
)

func renderChecks(w io.Writer, checks []doctor.Check) {
	nameW := 12
	for _, c := range checks {
		if l := lipgloss.Width(c.Name); l > nameW {
			nameW = l
		}
	}
	fmt.Fprintln(w)
	for _, c := range checks {
		fmt.Fprintln(w, renderCheck(c, nameW))
	}
	fmt.Fprintln(w)
}

func renderCheck(c doctor.Check, nameW int) string {
	var glyph string
	switch c.Status {
	case doctor.Pass:
		glyph = stylePass.Render("✓")
	case doctor.Fail:
		if c.Severity == doctor.SeverityRequired {
			glyph = styleFailRq.Render("✗")
		} else {
			glyph = styleFailOp.Render("✗")
		}
	case doctor.Info:
		glyph = styleInfo.Render("ℹ")
	}

	name := styleName.Render(padRight(c.Name, nameW))
	body := c.Message
	if body == "" && c.Hint != "" {
		body = c.Hint
	}
	var rendered string
	if c.Status == doctor.Fail {
		rendered = styleHint.Render(body)
	} else {
		rendered = styleMsg.Render(body)
	}
	return fmt.Sprintf("  %s  %s  %s", glyph, name, rendered)
}

func renderSummary(w io.Writer, s doctor.Summary) {
	parts := []string{stylePass.Render(fmt.Sprintf("%d ok", s.OK))}
	if s.OptionalMissing > 0 {
		parts = append(parts, styleFailOp.Render(fmt.Sprintf("%d optional missing", s.OptionalMissing)))
	}
	if s.RequiredFailed > 0 {
		parts = append(parts, styleFailRq.Render(fmt.Sprintf("%d required failed", s.RequiredFailed)))
	}
	if s.Infos > 0 {
		parts = append(parts, styleInfo.Render(fmt.Sprintf("%d info", s.Infos)))
	}
	fmt.Fprintf(w, "  summary: %s\n", strings.Join(parts, " • "))
	if s.HasBlockingFailure() {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, styleFailRq.Render("  ✗ environment is NOT ready. Fix the items marked above before running argus."))
	}
}

// doctorRegistry builds a throwaway registry containing every tool that
// might shell out to a binary. Tools that implement tool.Requirer expose
// their binary deps to doctor; tools that don't are still registered but
// invisible to the check (this is fine — they have no binary deps).
//
// Single source of truth: when a new security tool is added (e.g. trivy),
// registering it here is enough — doctor picks it up automatically.
func doctorRegistry() *tool.Registry {
	sess := session.New()
	runner := security.ExecRunner{}
	reg := tool.NewRegistry()
	reg.Register(security.NewSemgrep(sess, runner))
	reg.Register(security.NewGitleaks(sess, runner))
	reg.Register(security.NewOSVScanner(sess, runner))
	// Future: trivy, trufflehog, govulncheck — adding them in
	// pkg/security and registering them here is the only change needed.
	return reg
}

// githubDoctorOptions loads the github codehost from argus.yaml and, when it is
// configured, returns it plus a mint closure that proves the private key can
// sign an App JWT (the network-adjacent call lives here, not in the pure doctor
// package). When no github codehost is declared, an unconfigured (Info) row is
// still surfaced; a config load error skips the check entirely.
func githubDoctorOptions(home string) (*config.CodeHostConfig, func(context.Context) error) {
	cfg, err := config.LoadConfig(filepath.Join(home, "argus.yaml"))
	if err != nil {
		return nil, nil
	}
	host, _ := cfg.CodeHost(config.CodeHostTypeGitHub)
	if !host.Configured() {
		return &host, nil // absent or incomplete → Info/Fail row, no mint
	}
	// Load .env so the app_id env() reference resolves.
	if e, lerr := config.LoadEnv(filepath.Join(home, ".env")); lerr == nil {
		e.ApplyToProcess()
	}
	mint := func(_ context.Context) error {
		m, err := cdgithub.MintFromConfig(host)
		if err != nil {
			return err
		}
		// The installation is derived per event/repo (ADR 0015); there is no
		// pinned installation token to mint. Verify the private key can sign an
		// App JWT — the credential every installation-token mint builds on.
		_, err = m.AppJWT()
		return err
	}
	return &host, mint
}

// providerDoctorOptions resolves the LLM Provider backing the configured default
// model and, when it is an openai-compatible one, returns the two probes that
// verify it live.
//
// This is where "compatible" stops being a disclaimer (ADR 0020). Argus
// implements a wire protocol and certifies nobody's server, so verification runs
// on the user's machine, against the user's model, at the moment they configure
// it. The network calls live here rather than in pkg/doctor, exactly like the
// GitHub mint and the front-door health check.
//
// It builds the Provider through daemon.ProviderSpecForModel plus factory.New —
// the same two steps the daemon takes per Session — so what doctor verifies is
// the Provider a Review would actually get, not a second approximation of it. A
// config that cannot be loaded or a model that resolves to no Provider returns no
// target: the argus.yaml and api-key rows already report those.
func providerDoctorOptions(home string) (*doctor.ProviderTarget, func(context.Context) ([]string, error), func(context.Context) (bool, error)) {
	cfg, err := config.LoadConfig(filepath.Join(home, "argus.yaml"))
	if err != nil {
		return nil, nil, nil
	}
	// The api_key and url entries carry env() references; load .env so they
	// resolve to the values the daemon would see.
	if e, lerr := config.LoadEnv(filepath.Join(home, ".env")); lerr == nil {
		e.ApplyToProcess()
	}
	spec, err := daemon.ProviderSpecForModel(cfg, cfg.DefaultModel)
	if err != nil {
		return nil, nil, nil
	}

	target := &doctor.ProviderTarget{Type: spec.Type, Model: spec.Model, Endpoint: spec.BaseURL}
	if spec.Type != provider.TypeOpenAICompatible {
		// No probes: the capability probe is this protocol's, and doctor says so
		// on the row rather than inventing a check that cannot run.
		return target, nil, nil
	}
	if target.Endpoint == "" {
		// An empty BaseURL means "the implementation's default", which is what the
		// row has to name for the operator to recognize the endpoint being probed.
		target.Endpoint = factory.DefaultOpenAICompatibleBaseURL
	}

	// Constructed once, up front: both probes talk to the same endpoint, and a
	// construction failure (a base URL that is not a URL, an unimplemented type)
	// is reported through the first probe rather than swallowed into a row that
	// claims nothing was attempted.
	prov, buildErr := factory.New(context.Background(), spec)

	// /models is not on provider.Provider — it is the one question only this
	// protocol can answer. Asserted structurally so cmd needs no import of a
	// concrete implementation, and asserted here rather than inside the closure so
	// that a Provider which cannot list models leaves the probe unwired: doctor
	// then says the listing was not attempted, instead of mistaking "cannot ask"
	// for "the endpoint listed nothing".
	lister, canList := prov.(interface {
		ListModels(context.Context) ([]string, error)
	})

	var models func(ctx context.Context) ([]string, error)
	if canList || buildErr != nil {
		models = func(ctx context.Context) ([]string, error) {
			if buildErr != nil {
				return nil, buildErr
			}
			// A short deadline: this is one small GET, and a doctor run that hangs
			// on an unresponsive endpoint teaches the operator nothing.
			ctx, cancel := context.WithTimeout(ctx, providerListTimeout)
			defer cancel()
			return lister.ListModels(ctx)
		}
	}

	toolCall := func(ctx context.Context) (bool, error) {
		if buildErr != nil {
			return false, buildErr
		}
		// Longer than the listing deadline on purpose: a local runtime may have to
		// load the model into memory before it answers at all.
		ctx, cancel := context.WithTimeout(ctx, providerGenerateTimeout)
		defer cancel()
		resp, err := prov.Generate(ctx, toolCallProbeRequest())
		if err != nil {
			// Returned as it is. An endpoint that refuses tool declarations has
			// already had that client error translated by the adapter into a plain
			// statement that the model does not support tool calling, with the
			// server's own words kept after it — rewriting it here would only bury
			// the verdict.
			return false, err
		}
		// The assertion is on a tool call arriving, not on a 200: servers that
		// accept tool declarations and then ignore them answer 200 with prose.
		return len(resp.ToolCalls) > 0, nil
	}

	return target, models, toolCall
}

const (
	providerListTimeout     = 10 * time.Second
	providerGenerateTimeout = 60 * time.Second
)

// toolCallProbeRequest is the smallest generation that can prove a model emits
// tool calls: one throwaway tool, one sentence asking for it, no history. Small
// on purpose — the probe runs on every `argus doctor`, and it must cost the
// operator as close to nothing as a generation can.
func toolCallProbeRequest() provider.Request {
	return provider.Request{
		System: "You are a capability probe. Call the provided tool exactly once. Do not answer in prose.",
		Messages: []provider.Message{
			{Role: "user", Content: "Call the argus_probe tool with ok set to true."},
		},
		Tools: []provider.ToolDecl{{
			Name:        "argus_probe",
			Description: "Confirms this model can call a tool. Call it once with ok set to true.",
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"ok": map[string]any{"type": "boolean", "description": "Always true."},
				},
				"required": []string{"ok"},
			},
		}},
	}
}

// frontDoorDoctorOptions inspects argus.yaml for a configured HTTP channel
// (github webhook or MCP). When one is present the daemon owns a single HTTP
// front door (ADR 0015), so it returns its address plus a probe that GETs
// /healthz to prove the front door is up. A socket-only install (no HTTP
// channel) returns an empty address so doctor grows no front-door row; a config
// load error skips the check entirely (the argus.yaml row already reports it).
func frontDoorDoctorOptions(home string) (string, func(context.Context) error) {
	cfg, err := config.LoadConfig(filepath.Join(home, "argus.yaml"))
	if err != nil {
		return "", nil
	}
	_, hasGitHub := cfg.Channel(config.ChannelTypeGitHub)
	_, hasMCP := cfg.Channel(config.ChannelTypeMCP)
	if !hasGitHub && !hasMCP {
		return "", nil
	}
	addr := cfg.Daemon.HTTPAddress()
	probe := func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+healthHost(addr)+"/healthz", nil)
		if err != nil {
			return err
		}
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("GET /healthz returned %s", resp.Status)
		}
		return nil
	}
	return addr, probe
}

// healthHost turns a listen address into a dialable host:port. A bare ":8080"
// (bind every interface) is probed on localhost — doctor runs on the daemon
// host, so loopback reaches the same front door the proxy fronts.
func healthHost(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "localhost" + addr
	}
	return addr
}

// extraBinaries lists binary deps that aren't owned by any Tool (because
// they're used by core infra like pkg/codehost/github).
func extraBinaries() []doctor.ExtraBinary {
	return []doctor.ExtraBinary{
		{
			Name:        "git",
			Required:    true,
			UsedBy:      "cloning repositories",
			InstallHint: "install via your OS package manager (brew install git / apt-get install git / ...)",
		},
	}
}

func padRight(s string, n int) string {
	w := lipgloss.Width(s)
	if w >= n {
		return s
	}
	return s + strings.Repeat(" ", n-w)
}

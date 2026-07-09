package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/argusappsec/argus/pkg/config"
)

// codehostCmd configures a CodeHost channel (ADR 0010). Today GitHub is the
// only implementation; the command is shaped like `argus init`'s provider
// selection so a second host (GitLab, …) slots in beside it later.
func codehostCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "codehost",
		Short: "Configure a code host channel (GitHub today)",
	}
	c.AddCommand(codehostSetupCmd())
	return c
}

// setupInput is the resolved configuration applyGitHubSetup writes.
type setupInput struct {
	Home           string
	Host           string
	AppID          string
	InstallationID string
	WebhookSecret  string
	PrivateKeyPath string // source PEM; copied under home
	Addr           string
	AutoEnroll     bool
}

// setupResult reports what applyGitHubSetup did, for the caller to print.
type setupResult struct {
	PrivateKeyDest string
}

func codehostSetupCmd() *cobra.Command {
	var in setupInput
	c := &cobra.Command{
		Use:   "setup",
		Short: "Configure a code host: select the host, then write its channel config",
		Long: "Onboard a code host channel. Pick the host (GitHub today), then Argus\n" +
			"writes everything that host needs in one step. For GitHub (ADR 0008/0015):\n" +
			"the codehosts:/channels: sections of argus.yaml, the webhook secret in\n" +
			".env, and the private key under ~/.argus. The github-app Service is\n" +
			"synthesized by the channel — no users.yaml row is written. Missing values\n" +
			"are prompted interactively.",
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := resolveHome(in.Home)
			if err != nil {
				return err
			}
			needForm := in.Host == "" ||
				(in.Host == "github" && (in.AppID == "" || in.InstallationID == "" || in.WebhookSecret == "" || in.PrivateKeyPath == ""))
			if needForm {
				if err := in.runForm(); err != nil {
					return fmt.Errorf("interactive setup needs a terminal; otherwise pass --host and the host's flags: %w", err)
				}
			}
			if in.Host != "github" {
				return fmt.Errorf("code host %q is not implemented yet (only github works today)", in.Host)
			}
			res, err := applyGitHubSetup(home, in)
			if err != nil {
				return err
			}
			return printSetupResult(cmd, home, res)
		},
	}
	f := c.Flags()
	f.StringVar(&in.Home, "home", "", "Override ~/.argus home directory")
	f.StringVar(&in.Host, "host", "", "Code host: github (gitlab/bitbucket not yet implemented)")
	f.StringVar(&in.AppID, "app-id", "", "GitHub App id")
	f.StringVar(&in.InstallationID, "installation-id", "", "App installation id")
	f.StringVar(&in.WebhookSecret, "webhook-secret", "", "App webhook secret (stored in .env, its hash in users.yaml)")
	f.StringVar(&in.PrivateKeyPath, "private-key", "", "Path to the App's PEM private key (copied under ~/.argus)")
	f.StringVar(&in.Addr, "addr", ":8080", "HTTP listen address for webhook deliveries")
	f.BoolVar(&in.AutoEnroll, "auto-enroll", true, "Review every installed repo automatically")
	return c
}

// runForm collects the host and any missing host-specific values, pre-filled
// from flags. It mirrors `argus init`'s provider selection.
func (in *setupInput) runForm() error {
	if in.Host == "" {
		in.Host = "github"
	}
	hostStep := huh.NewSelect[string]().
		Title("Code host").
		Description("Which platform hosts the code Argus reviews?").
		Options(
			huh.NewOption("GitHub", "github"),
			huh.NewOption("GitLab — not yet implemented", "gitlab").Selected(false),
			huh.NewOption("Bitbucket — not yet implemented", "bitbucket").Selected(false),
		).
		Validate(func(s string) error {
			if s != "github" {
				return fmt.Errorf("%s is not implemented yet (only github works today)", s)
			}
			return nil
		}).
		Value(&in.Host)

	githubGroup := huh.NewGroup(
		huh.NewInput().Title("GitHub App ID").Value(&in.AppID).Validate(nonEmpty("App ID")),
		huh.NewInput().Title("Installation ID").Value(&in.InstallationID).Validate(nonEmpty("installation ID")),
		huh.NewInput().Title("Webhook secret").EchoMode(huh.EchoModePassword).
			Value(&in.WebhookSecret).Validate(nonEmpty("webhook secret")),
		huh.NewInput().Title("Private key path").Description("Path to the App's .pem file").
			Value(&in.PrivateKeyPath).Validate(func(s string) error {
			if strings.TrimSpace(s) == "" {
				return errors.New("private key path required")
			}
			if _, err := os.Stat(s); err != nil {
				return fmt.Errorf("not readable: %s", s)
			}
			return nil
		}),
	).WithHideFunc(func() bool { return in.Host != "github" })

	return huh.NewForm(huh.NewGroup(hostStep), githubGroup).WithTheme(huh.ThemeBase16()).Run()
}

func nonEmpty(what string) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s required", what)
		}
		return nil
	}
}

// applyGitHubSetup writes the GitHub channel configuration across argus.yaml,
// .env, and the private key file. No users.yaml Service row is written: the
// github-app Service is synthesized by the channel from the fact of being
// configured (ADR 0015). It is the testable core, free of prompts and cobra.
func applyGitHubSetup(home string, in setupInput) (setupResult, error) {
	var res setupResult
	if in.AppID == "" || in.InstallationID == "" || in.WebhookSecret == "" || in.PrivateKeyPath == "" {
		return res, errors.New("github setup: app-id, installation-id, webhook-secret and private-key are all required")
	}

	dest := filepath.Join(home, "github-app.pem")
	if err := copyPrivateKey(in.PrivateKeyPath, dest); err != nil {
		return res, err
	}
	res.PrivateKeyDest = dest

	cfgPath := filepath.Join(home, "argus.yaml")
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		return res, fmt.Errorf("github setup: load config: %w", err)
	}
	autoEnroll := in.AutoEnroll
	// Config v2 (ADR 0015): the outbound App identity lives under codehosts:,
	// the inbound webhook binding under channels:. No installation id (derived
	// per event/repo) and no per-channel addr (the daemon owns one front door).
	if cfg.CodeHosts == nil {
		cfg.CodeHosts = map[string]config.CodeHostConfig{}
	}
	cfg.CodeHosts[config.CodeHostTypeGitHub] = config.CodeHostConfig{
		Type:           config.CodeHostTypeGitHub,
		AppID:          in.AppID, // non-secret: stored as a literal
		PrivateKeyPath: dest,
	}
	if cfg.Channels == nil {
		cfg.Channels = map[string]config.ChannelConfig{}
	}
	cfg.Channels[config.ChannelTypeGitHub] = config.ChannelConfig{
		Type:          config.ChannelTypeGitHub,
		WebhookSecret: config.EnvRef("GITHUB_WEBHOOK_SECRET"),
		AutoEnroll:    &autoEnroll,
	}
	if err := config.SaveConfig(cfgPath, cfg); err != nil {
		return res, fmt.Errorf("github setup: save config: %w", err)
	}

	envPath := filepath.Join(home, ".env")
	env, err := config.LoadEnv(envPath)
	if err != nil {
		return res, fmt.Errorf("github setup: load .env: %w", err)
	}
	env.Set("GITHUB_WEBHOOK_SECRET", in.WebhookSecret)
	if err := env.Save(); err != nil {
		return res, fmt.Errorf("github setup: save .env: %w", err)
	}

	return res, nil
}

func copyPrivateKey(src, dst string) error {
	if src == dst {
		return nil
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("github setup: read private key %s: %w", src, err)
	}
	if !strings.Contains(string(b), "PRIVATE KEY") {
		return fmt.Errorf("github setup: %s does not look like a PEM private key", src)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		return fmt.Errorf("github setup: write private key: %w", err)
	}
	return nil
}

func printSetupResult(cmd *cobra.Command, home string, res setupResult) error {
	var b strings.Builder
	fmt.Fprintf(&b, "✓ wrote codehosts:/channels: sections to %s\n", filepath.Join(home, "argus.yaml"))
	fmt.Fprintf(&b, "✓ stored GITHUB_WEBHOOK_SECRET in %s\n", filepath.Join(home, ".env"))
	fmt.Fprintf(&b, "✓ private key at %s\n", res.PrivateKeyDest)
	b.WriteString("\nNext: run `argus doctor` — the github line should report a minted token.\n")
	_, err := fmt.Fprint(cmd.OutOrStdout(), b.String())
	return err
}

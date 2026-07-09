package cmd

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	ghchannel "github.com/argusappsec/argus/pkg/channel/github"
	"github.com/argusappsec/argus/pkg/config"
)

// fakePEM writes a believable private key file and returns its path.
func fakePEM(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key.pem")
	body := "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func baseInput(t *testing.T) setupInput {
	return setupInput{
		Host:           "github",
		AppID:          "123456",
		WebhookSecret:  "shhh",
		PrivateKeyPath: fakePEM(t),
		AutoEnroll:     true,
	}
}

func TestApplyGitHubSetup_WritesEverything(t *testing.T) {
	home := t.TempDir()
	res, err := applyGitHubSetup(home, baseInput(t))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	// argus.yaml codehosts:/channels: sections are configured and parseable,
	// and the whole config passes v2 validation.
	cfg, err := config.LoadConfig(filepath.Join(home, "argus.yaml"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("written config fails validation: %v", err)
	}
	host, ok := cfg.CodeHost(config.CodeHostTypeGitHub)
	if !ok || !host.Configured() {
		t.Errorf("github codehost not configured: %+v", host)
	}
	if got, _ := host.ResolveAppID(); got != "123456" {
		t.Errorf("app id = %q", got)
	}

	// The webhook secret resolves from .env via the env() reference on the channel.
	env, err := config.LoadEnv(filepath.Join(home, ".env"))
	if err != nil {
		t.Fatalf("load env: %v", err)
	}
	env.ApplyToProcess()
	ch, _ := cfg.Channel(config.ChannelTypeGitHub)
	if got, _ := ch.ResolveWebhookSecret(); got != "shhh" {
		t.Errorf("webhook secret resolved to %q", got)
	}

	// Private key was copied with tight perms.
	info, err := os.Stat(res.PrivateKeyDest)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key perms = %o", info.Mode().Perm())
	}

	// Setup writes no users.yaml Service row: the github-app Service is
	// synthesized by the channel (ADR 0015), not stored.
	if _, err := os.Stat(filepath.Join(home, "users.yaml")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("setup must not write users.yaml; stat err = %v", err)
	}
}

func TestApplyGitHubSetup_PreservesExistingConfig(t *testing.T) {
	home := t.TempDir()
	// A pre-existing provider config must survive the github write.
	seed := &config.Config{DefaultModel: "gemini-2.5-flash"}
	if err := config.SaveConfig(filepath.Join(home, "argus.yaml"), seed); err != nil {
		t.Fatal(err)
	}
	if _, err := applyGitHubSetup(home, baseInput(t)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	cfg, _ := config.LoadConfig(filepath.Join(home, "argus.yaml"))
	if cfg.DefaultModel != "gemini-2.5-flash" {
		t.Errorf("default_model clobbered: %q", cfg.DefaultModel)
	}
	host, ok := cfg.CodeHost(config.CodeHostTypeGitHub)
	if !ok || !host.Configured() {
		t.Error("github codehost not written alongside existing config")
	}
}

func TestApplyGitHubSetup_WritesNoInstallationIDOrAddr(t *testing.T) {
	home := t.TempDir()
	if _, err := applyGitHubSetup(home, baseInput(t)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Config v2 (ADR 0015): setup must never pin an installation id (derived
	// per event/repo) or a per-channel addr (the daemon owns one front door).
	// LoadConfig hard-errors on either legacy key, so a clean load is the proof.
	raw, err := os.ReadFile(filepath.Join(home, "argus.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if s := string(raw); strings.Contains(s, "installation_id") || strings.Contains(s, "addr") {
		t.Errorf("written config carries a removed v2 key:\n%s", s)
	}
	if _, err := config.LoadConfig(filepath.Join(home, "argus.yaml")); err != nil {
		t.Errorf("config with a legacy key would fail to load: %v", err)
	}
}

func TestPrintSetupResult_PrintsWebhookURLPath(t *testing.T) {
	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	if err := printSetupResult(cmd, t.TempDir(), setupResult{PrivateKeyDest: "/x/key.pem"}); err != nil {
		t.Fatalf("print: %v", err)
	}
	if !strings.Contains(buf.String(), ghchannel.WebhookPath) {
		t.Errorf("setup output does not name the webhook URL path %q:\n%s", ghchannel.WebhookPath, buf.String())
	}
}

func TestApplyGitHubSetup_RejectsNonPEM(t *testing.T) {
	home := t.TempDir()
	in := baseInput(t)
	bad := filepath.Join(t.TempDir(), "notes.txt")
	_ = os.WriteFile(bad, []byte("just some text"), 0o600)
	in.PrivateKeyPath = bad
	if _, err := applyGitHubSetup(home, in); err == nil {
		t.Error("expected a non-PEM private key to be rejected")
	}
}

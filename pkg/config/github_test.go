package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfigFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "argus.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGitHubConfig_AutoEnrollDefaultsTrue(t *testing.T) {
	if !(GitHubConfig{}).AutoEnrollEnabled() {
		t.Error("unset auto_enroll must default to true (single-owner default)")
	}
	f := false
	if (GitHubConfig{AutoEnroll: &f}).AutoEnrollEnabled() {
		t.Error("auto_enroll: false must disable auto-enroll")
	}
	tr := true
	if !(GitHubConfig{AutoEnroll: &tr}).AutoEnrollEnabled() {
		t.Error("auto_enroll: true must enable auto-enroll")
	}
}

func TestGitHubConfig_Configured(t *testing.T) {
	if (GitHubConfig{}).Configured() {
		t.Error("empty github config must not be considered configured")
	}
	full := GitHubConfig{AppID: "123", PrivateKeyPath: "/k.pem", WebhookSecret: "env(WH)"}
	if !full.Configured() {
		t.Error("complete github config must be considered configured")
	}
	// Missing any one credential leaves it unconfigured.
	partial := GitHubConfig{AppID: "123", WebhookSecret: "env(WH)"}
	if partial.Configured() {
		t.Error("missing private key path must leave config unconfigured")
	}
}

func TestGitHubConfig_ListenAddrDefault(t *testing.T) {
	if got := (GitHubConfig{}).ListenAddr(); got != ":8080" {
		t.Errorf("default addr = %q, want :8080", got)
	}
	if got := (GitHubConfig{Addr: ":9000"}).ListenAddr(); got != ":9000" {
		t.Errorf("addr = %q, want :9000", got)
	}
}

func TestGitHubConfig_ParsesFromYAML(t *testing.T) {
	const yaml = `default_model: gemini-2.5-flash
github:
  addr: ":7000"
  app_id: "123"
  installation_id: "456"
  private_key_path: /etc/argus/app.pem
  webhook_secret: env(GH_WEBHOOK_SECRET)
  auto_enroll: false
  enabled_repos:
    - github.com/redcarbon-dev/argus
`
	path := writeConfigFile(t, yaml)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.GitHub.AppID != "123" || cfg.GitHub.InstallationID != "456" {
		t.Errorf("ids = %q/%q", cfg.GitHub.AppID, cfg.GitHub.InstallationID)
	}
	if cfg.GitHub.PrivateKeyPath != "/etc/argus/app.pem" {
		t.Errorf("key path = %q", cfg.GitHub.PrivateKeyPath)
	}
	if cfg.GitHub.AutoEnrollEnabled() {
		t.Error("auto_enroll: false should parse as disabled")
	}
	if len(cfg.GitHub.EnabledRepos) != 1 || cfg.GitHub.EnabledRepos[0] != "github.com/redcarbon-dev/argus" {
		t.Errorf("enabled_repos = %v", cfg.GitHub.EnabledRepos)
	}
}

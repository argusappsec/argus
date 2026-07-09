package config

import (
	"os"
	"path/filepath"
	"strings"
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

// validV2 is a complete config v2: a github codehost, a github webhook channel
// with enrolment policy, and an mcp channel. Used as the happy-path fixture.
const validV2 = `default_model: gemini-2.5-flash
daemon:
  http_addr: ":9000"
codehosts:
  github:
    type: github
    app_id: "123"
    private_key_path: /etc/argus/app.pem
channels:
  github:
    type: github
    webhook_secret: env(GH_WEBHOOK_SECRET)
    auto_enroll: false
    enabled_repos:
      - github.com/argusappsec/argus
  mcp:
    type: mcp
`

func TestLoadConfig_ValidV2Parses(t *testing.T) {
	cfg, err := LoadConfig(writeConfigFile(t, validV2))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.Daemon.HTTPAddr != ":9000" {
		t.Errorf("http_addr = %q, want :9000", cfg.Daemon.HTTPAddr)
	}
	host, ok := cfg.CodeHost(CodeHostTypeGitHub)
	if !ok {
		t.Fatal("github codehost not found")
	}
	if host.AppID != "123" || host.PrivateKeyPath != "/etc/argus/app.pem" {
		t.Errorf("codehost = %+v", host)
	}
	ch, ok := cfg.Channel(ChannelTypeGitHub)
	if !ok {
		t.Fatal("github channel not found")
	}
	if ch.AutoEnrollEnabled() {
		t.Error("auto_enroll: false should parse as disabled")
	}
	if len(ch.EnabledRepos) != 1 || ch.EnabledRepos[0] != "github.com/argusappsec/argus" {
		t.Errorf("enabled_repos = %v", ch.EnabledRepos)
	}
	if _, ok := cfg.Channel(ChannelTypeMCP); !ok {
		t.Error("mcp channel not found")
	}
}

func TestChannelConfig_AutoEnrollDefaultsTrue(t *testing.T) {
	if !(ChannelConfig{}).AutoEnrollEnabled() {
		t.Error("unset auto_enroll must default to true (single-owner default)")
	}
	f := false
	if (ChannelConfig{AutoEnroll: &f}).AutoEnrollEnabled() {
		t.Error("auto_enroll: false must disable auto-enroll")
	}
}

func TestCodeHostConfig_Configured(t *testing.T) {
	if (CodeHostConfig{}).Configured() {
		t.Error("empty codehost must not be considered configured")
	}
	full := CodeHostConfig{Type: "github", AppID: "1", PrivateKeyPath: "/k.pem"}
	if !full.Configured() {
		t.Error("codehost with app id + key must be configured")
	}
	if (CodeHostConfig{Type: "github", AppID: "1"}).Configured() {
		t.Error("missing private key path must leave codehost unconfigured")
	}
}

// TestLoadConfig_LegacyKeysFail asserts each retired v1 key produces a hard
// startup error naming its v2 replacement (ADR 0015).
func TestLoadConfig_LegacyKeysFail(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantSub string // substring the error must name (the replacement)
	}{
		{
			name: "top-level github",
			yaml: "default_model: m\ngithub:\n  app_id: \"1\"\n  private_key_path: /k.pem\n  webhook_secret: env(S)\n",
			wantSub: "codehosts:",
		},
		{
			name:    "top-level mcp",
			yaml:    "default_model: m\nmcp:\n  addr: \":8090\"\n",
			wantSub: "channels:",
		},
		{
			name:    "codehost installation_id",
			yaml:    "default_model: m\ncodehosts:\n  github:\n    type: github\n    app_id: \"1\"\n    private_key_path: /k.pem\n    installation_id: \"42\"\n",
			wantSub: "installation_id",
		},
		{
			name:    "channel addr",
			yaml:    "default_model: m\nchannels:\n  github:\n    type: github\n    webhook_secret: env(S)\n    addr: \":8080\"\n",
			wantSub: "http_addr",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadConfig(writeConfigFile(t, tc.yaml))
			if err == nil {
				t.Fatalf("legacy key %q must fail startup", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error must name the replacement %q; got: %v", tc.wantSub, err)
			}
		})
	}
}

// TestValidate covers the config v2 invariants enforced at startup.
func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr string // "" means must pass
	}{
		{
			name: "valid github + mcp",
			cfg: Config{
				CodeHosts: map[string]CodeHostConfig{"gh": {Type: "github", AppID: "1", PrivateKeyPath: "/k.pem"}},
				Channels: map[string]ChannelConfig{
					"gh":  {Type: "github", WebhookSecret: "env(S)"},
					"mcp": {Type: "mcp"},
				},
			},
		},
		{
			name: "mcp-only (no codehost) is valid",
			cfg: Config{
				Channels: map[string]ChannelConfig{"mcp": {Type: "mcp"}},
			},
		},
		{
			name: "codehost missing app_id",
			cfg: Config{
				CodeHosts: map[string]CodeHostConfig{"gh": {Type: "github", PrivateKeyPath: "/k.pem"}},
			},
			wantErr: "app_id",
		},
		{
			name: "codehost missing private_key_path",
			cfg: Config{
				CodeHosts: map[string]CodeHostConfig{"gh": {Type: "github", AppID: "1"}},
			},
			wantErr: "private_key_path",
		},
		{
			name: "channel github missing webhook_secret",
			cfg: Config{
				CodeHosts: map[string]CodeHostConfig{"gh": {Type: "github", AppID: "1", PrivateKeyPath: "/k.pem"}},
				Channels:  map[string]ChannelConfig{"gh": {Type: "github"}},
			},
			wantErr: "webhook_secret",
		},
		{
			name: "unknown codehost type",
			cfg: Config{
				CodeHosts: map[string]CodeHostConfig{"gl": {Type: "gitlab"}},
			},
			wantErr: "unknown type",
		},
		{
			name: "unknown channel type",
			cfg: Config{
				Channels: map[string]ChannelConfig{"x": {Type: "slack"}},
			},
			wantErr: "unknown type",
		},
		{
			name: "two codehosts same type",
			cfg: Config{
				CodeHosts: map[string]CodeHostConfig{
					"a": {Type: "github", AppID: "1", PrivateKeyPath: "/k.pem"},
					"b": {Type: "github", AppID: "2", PrivateKeyPath: "/k2.pem"},
				},
			},
			wantErr: "only one codehost per type",
		},
		{
			name: "two channels same type",
			cfg: Config{
				CodeHosts: map[string]CodeHostConfig{"gh": {Type: "github", AppID: "1", PrivateKeyPath: "/k.pem"}},
				Channels: map[string]ChannelConfig{
					"a": {Type: "github", WebhookSecret: "env(S)"},
					"b": {Type: "github", WebhookSecret: "env(S2)"},
				},
			},
			wantErr: "only one channel per type",
		},
		{
			name: "github channel without github codehost",
			cfg: Config{
				Channels: map[string]ChannelConfig{"gh": {Type: "github", WebhookSecret: "env(S)"}},
			},
			wantErr: "requires a github codehost",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// TestResolveValue_EnvIndirection asserts env() references resolve for the v2
// credential fields exactly as they do elsewhere.
func TestResolveValue_EnvIndirection(t *testing.T) {
	t.Setenv("GH_APP_ID", "999")
	t.Setenv("GH_WEBHOOK_SECRET", "shhh")

	host := CodeHostConfig{Type: "github", AppID: "env(GH_APP_ID)", PrivateKeyPath: "/k.pem"}
	if got, err := host.ResolveAppID(); err != nil || got != "999" {
		t.Errorf("ResolveAppID = %q, %v; want 999", got, err)
	}
	ch := ChannelConfig{Type: "github", WebhookSecret: "env(GH_WEBHOOK_SECRET)"}
	if got, err := ch.ResolveWebhookSecret(); err != nil || got != "shhh" {
		t.Errorf("ResolveWebhookSecret = %q, %v; want shhh", got, err)
	}

	missing := CodeHostConfig{AppID: "env(NOPE_UNSET)"}
	if _, err := missing.ResolveAppID(); err == nil {
		t.Error("unset env var must produce an error")
	}
}

func TestDaemonConfig_HTTPAddress(t *testing.T) {
	// Unset falls back to the front-door default; a configured value wins.
	if got := (DaemonConfig{}).HTTPAddress(); got != DefaultHTTPAddr {
		t.Errorf("unset http_addr = %q, want %q", got, DefaultHTTPAddr)
	}
	if got := (DaemonConfig{HTTPAddr: ":9000"}).HTTPAddress(); got != ":9000" {
		t.Errorf("configured http_addr = %q, want :9000", got)
	}
}

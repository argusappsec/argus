package daemon

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/deployment"
	"github.com/argusappsec/argus/pkg/provider"
)

// The daemon-construction seam. What every test here asserts is what an
// operator gets when they start argusd against a given ~/.argus: whether the
// daemon comes up at all, and which Deployment shape it says it is.

// noFallbackKey clears the no-`providers:` fallback credential so a test that
// means "no Provider at all" is not turned into a Colleague by whatever the
// developer happens to have exported.
func noFallbackKey(t *testing.T) {
	t.Helper()
	t.Setenv("GEMINI_API_KEY", "")
}

// writeAppKey writes a real RSA private key under home: a github codehost is
// built at Build time, so the credentials have to be loadable for the channel
// cases below to reach the shape check they are about.
func writeAppKey(t *testing.T, home string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "app.pem")
	body := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBuild_NoProviderStartsAsAToolbox(t *testing.T) {
	noFallbackKey(t)

	// The fresh machine: nothing configured, no model chosen. This used to be
	// the single blocker behind the whole Toolbox shape.
	dc, err := Build(t.TempDir(), &config.Config{})
	if err != nil {
		t.Fatalf("Build with no Provider: %v", err)
	}
	defer dc.Close()

	if dc.Shape != deployment.Toolbox {
		t.Errorf("shape = %v, want toolbox", dc.Shape)
	}
}

func TestBuild_ConfiguredProviderStartsAsAColleague(t *testing.T) {
	noFallbackKey(t)
	t.Setenv("OPENAI_API_KEY", "sk-secret")

	cfg := &config.Config{
		Providers: map[string]config.ProviderConfig{
			"openai": {Type: provider.TypeOpenAICompatible, APIKey: "env(OPENAI_API_KEY)"},
		},
		DefaultModel: "gpt-4o-mini",
	}
	dc, err := Build(t.TempDir(), cfg)
	if err != nil {
		t.Fatalf("Build with a Provider: %v", err)
	}
	defer dc.Close()

	if dc.Shape != deployment.Colleague {
		t.Errorf("shape = %v, want colleague", dc.Shape)
	}
	if dc.DefaultModel != "gpt-4o-mini" {
		t.Errorf("default model = %q, want gpt-4o-mini", dc.DefaultModel)
	}
}

// The environment-variable fallback is a Provider like any other: an install
// that exported a key and never ran `argus init` reasons exactly as it did
// before, and must not silently degrade into a Toolbox.
func TestBuild_EnvFallbackKeyStillYieldsAColleague(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "gem-secret")

	dc, err := Build(t.TempDir(), &config.Config{DefaultModel: "gemini-2.5-flash"})
	if err != nil {
		t.Fatalf("Build with the fallback key: %v", err)
	}
	defer dc.Close()

	if dc.Shape != deployment.Colleague {
		t.Errorf("shape = %v, want colleague", dc.Shape)
	}
}

// The same fallback key, held in the daemon's own .env rather than the shell:
// .env is applied to the process before the shape is derived, so both spellings
// of "I have a Provider" agree.
func TestBuild_FallbackKeyInDotEnvYieldsAColleague(t *testing.T) {
	noFallbackKey(t)
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".env"), []byte("GEMINI_API_KEY=gem-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	dc, err := Build(home, &config.Config{DefaultModel: "gemini-2.5-flash"})
	if err != nil {
		t.Fatalf("Build with a .env fallback key: %v", err)
	}
	defer dc.Close()

	if dc.Shape != deployment.Colleague {
		t.Errorf("shape = %v, want colleague", dc.Shape)
	}
}

// A Provider that IS configured but cannot be acquired is a configuration
// error, not a deployment shape: it fails loudly at startup rather than looking
// healthy until the first Session, and it is never mistaken for a Toolbox.
func TestBuild_MisconfiguredProviderStillFailsLoudly(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{
			name: "api_key env() reference that resolves to nothing",
			cfg: &config.Config{
				Providers: map[string]config.ProviderConfig{
					"openai": {Type: provider.TypeOpenAICompatible, APIKey: "env(NOT_EXPORTED_ANYWHERE)"},
				},
				DefaultModel: "gpt-4o-mini",
			},
			want: "NOT_EXPORTED_ANYWHERE",
		},
		{
			name: "default_model that resolves to none of the configured Providers",
			cfg: &config.Config{
				Providers: map[string]config.ProviderConfig{
					"groq":       {Type: provider.TypeOpenAICompatible, URL: "https://api.groq.com/openai/v1"},
					"openrouter": {Type: provider.TypeOpenAICompatible, URL: "https://openrouter.ai/api/v1"},
				},
				DefaultModel: "some-model",
			},
			want: "some-model",
		},
		{
			name: "a Provider configured with no model to send it",
			cfg: &config.Config{
				Providers: map[string]config.ProviderConfig{
					"gemini": {Type: provider.TypeGemini, APIKey: "literal-key"},
				},
			},
			want: "no model configured",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			noFallbackKey(t)
			dc, err := Build(t.TempDir(), tc.cfg)
			if err == nil {
				dc.Close()
				t.Fatal("Build accepted a misconfigured Provider")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q", err, tc.want)
			}
		})
	}
}

// The fallback key without a model is the same misconfiguration: it says "I
// have a Provider" and gives the daemon nothing to send it. It must fail, not
// quietly become a Toolbox.
func TestBuild_FallbackKeyWithoutAModelFailsRatherThanDegrades(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "gem-secret")

	dc, err := Build(t.TempDir(), &config.Config{})
	if err == nil {
		dc.Close()
		t.Fatal("Build accepted a Provider with no model configured")
	}
	if !strings.Contains(err.Error(), "no model configured") {
		t.Errorf("error %q does not say the model is missing", err)
	}
}

// A Channel that cannot function without reasoning is a configuration error in
// a Toolbox, and fails at startup with a message naming the reason — the same
// posture that keeps a misconfigured integration surface from becoming a
// silently dead channel.
func TestBuild_ToolboxRefusesAChannelThatNeedsReasoning(t *testing.T) {
	noFallbackKey(t)
	home := t.TempDir()
	keyPath := writeAppKey(t, home)
	githubConfig := func() *config.Config {
		return &config.Config{
			CodeHosts: map[string]config.CodeHostConfig{
				"github": {Type: config.CodeHostTypeGitHub, AppID: "1", PrivateKeyPath: keyPath},
			},
			Channels: map[string]config.ChannelConfig{
				"github": {Type: config.ChannelTypeGitHub, WebhookSecret: "shh"},
			},
		}
	}

	dc, err := Build(home, githubConfig())
	if err == nil {
		dc.Close()
		t.Fatal("a Toolbox accepted the GitHub channel's automatic review path")
	}
	for _, want := range []string{"github", "Toolbox", "automatic"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	// Same channel, automatic reviews turned off: only the comment path
	// remains, which is refused per turn rather than at startup.
	off := false
	commentOnly := githubConfig()
	commentOnly.Channels["github"] = config.ChannelConfig{
		Type:          config.ChannelTypeGitHub,
		WebhookSecret: "shh",
		AutoEnroll:    &off,
	}
	dc, err = Build(home, commentOnly)
	if err != nil {
		t.Fatalf("a Toolbox refused a GitHub channel that reviews nothing automatically: %v", err)
	}
	dc.Close()
}

// The same channel is fine as soon as Argus can reason.
func TestBuild_ColleagueAcceptsTheAutomaticReviewPath(t *testing.T) {
	noFallbackKey(t)
	home := t.TempDir()
	keyPath := writeAppKey(t, home)
	cfg := &config.Config{
		Providers: map[string]config.ProviderConfig{
			"gemini": {Type: provider.TypeGemini, APIKey: "literal-key"},
		},
		DefaultModel: "gemini-2.5-flash",
		CodeHosts: map[string]config.CodeHostConfig{
			"github": {Type: config.CodeHostTypeGitHub, AppID: "1", PrivateKeyPath: keyPath},
		},
		Channels: map[string]config.ChannelConfig{
			"github": {Type: config.ChannelTypeGitHub, WebhookSecret: "shh"},
		},
	}

	dc, err := Build(home, cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer dc.Close()
	if dc.Shape != deployment.Colleague {
		t.Errorf("shape = %v, want colleague", dc.Shape)
	}
}

// The MCP channel is the Toolbox's whole reason to exist, so it is never a
// startup error there.
func TestBuild_ToolboxAcceptsTheMCPChannel(t *testing.T) {
	noFallbackKey(t)
	cfg := &config.Config{
		Channels: map[string]config.ChannelConfig{
			"mcp": {Type: config.ChannelTypeMCP},
		},
	}

	dc, err := Build(t.TempDir(), cfg)
	if err != nil {
		t.Fatalf("a Toolbox refused the MCP channel: %v", err)
	}
	defer dc.Close()
	if dc.Shape != deployment.Toolbox {
		t.Errorf("shape = %v, want toolbox", dc.Shape)
	}
}

// Slack is a Channel whose every event is a conversational turn with Argus's
// own agent, so it cannot run in a Toolbox — and it is refused at startup
// today, though not yet for that reason: the Channel is not implemented, so the
// config gate rejects `type: slack` as unknown before the shape is consulted.
//
// The assertion on "unknown type" is the point of this test. On the day the
// Slack Channel lands, that gate stops firing and this test fails — which is
// the reminder to add its case to channelNeedsReasoning, rather than letting
// the refusal disappear unnoticed.
func TestBuild_ToolboxRefusesASlackChannel(t *testing.T) {
	noFallbackKey(t)
	cfg := &config.Config{
		Channels: map[string]config.ChannelConfig{
			"slack": {Type: "slack"},
		},
	}

	dc, err := Build(t.TempDir(), cfg)
	if err == nil {
		dc.Close()
		t.Fatal("a Toolbox accepted a Slack channel")
	}
	if !strings.Contains(err.Error(), "slack") {
		t.Errorf("error %q does not name the channel", err)
	}
	if !strings.Contains(err.Error(), "unknown type") {
		t.Errorf("error %q is no longer the config gate's: give slack its case in channelNeedsReasoning", err)
	}
}

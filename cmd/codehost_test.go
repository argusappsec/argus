package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/argusappsec/argus/pkg/auth"
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
		InstallationID: "7890",
		WebhookSecret:  "shhh",
		PrivateKeyPath: fakePEM(t),
		Addr:           ":8080",
		AutoEnroll:     true,
		ServiceID:      "github-app",
	}
}

func TestApplyGitHubSetup_WritesEverything(t *testing.T) {
	home := t.TempDir()
	res, err := applyGitHubSetup(home, baseInput(t))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	// argus.yaml github section is configured and parseable.
	cfg, err := config.LoadConfig(filepath.Join(home, "argus.yaml"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !cfg.GitHub.Configured() {
		t.Errorf("github section not configured: %+v", cfg.GitHub)
	}
	if got, _ := cfg.GitHub.ResolveAppID(); got != "123456" {
		t.Errorf("app id = %q", got)
	}

	// The webhook secret resolves from .env via the env() reference.
	env, err := config.LoadEnv(filepath.Join(home, ".env"))
	if err != nil {
		t.Fatalf("load env: %v", err)
	}
	env.ApplyToProcess()
	if got, _ := cfg.GitHub.ResolveWebhookSecret(); got != "shhh" {
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

	// The Service resolves by the wire secret's hash — the channel's path.
	if !res.ServiceCreated {
		t.Error("expected the service to be created")
	}
	p, err := auth.NewResolver(filepath.Join(home, "users.yaml")).ResolveService(auth.SHA256Hex("shhh"))
	if err != nil {
		t.Fatalf("resolve service: %v", err)
	}
	if p.ID != "github-app" || p.Kind != auth.KindService {
		t.Errorf("resolved %+v", p)
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
	if !cfg.GitHub.Configured() {
		t.Error("github not written alongside existing config")
	}
}

func TestApplyGitHubSetup_DetectsSecretMismatch(t *testing.T) {
	home := t.TempDir()
	// A service with the id already exists, but with a different secret.
	store := auth.NewStore(filepath.Join(home, "users.yaml"))
	if err := store.AddService(auth.Service{
		ID: "github-app", Role: auth.RoleCITrigger, Kind: "github-app",
		SecretSHA256: auth.SHA256Hex("a-different-secret"),
	}); err != nil {
		t.Fatal(err)
	}
	res, err := applyGitHubSetup(home, baseInput(t))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !res.ServiceExisted || !res.SecretMismatch {
		t.Errorf("expected an existing service with a mismatched secret: %+v", res)
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

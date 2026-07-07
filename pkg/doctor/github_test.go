package doctor_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/doctor"
)

func findCheck(checks []doctor.Check, name string) *doctor.Check {
	for i := range checks {
		if checks[i].Name == name {
			return &checks[i]
		}
	}
	return nil
}

func TestGitHubCheck_NotConfiguredIsInfo(t *testing.T) {
	checks := doctor.Run(doctor.Options{Home: t.TempDir(), GitHub: &config.GitHubConfig{}})
	c := findCheck(checks, "github")
	if c == nil {
		t.Fatal("no github check")
	}
	if c.Status != doctor.Info {
		t.Errorf("status = %v, want Info for unconfigured channel", c.Status)
	}
}

func TestGitHubCheck_AbsentSectionSkipped(t *testing.T) {
	checks := doctor.Run(doctor.Options{Home: t.TempDir()}) // GitHub nil
	if findCheck(checks, "github") != nil {
		t.Error("github check must be absent when no config is supplied")
	}
}

func configuredGitHub(t *testing.T) config.GitHubConfig {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(keyPath, []byte("dummy"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GH_WH", "secret")
	return config.GitHubConfig{
		AppID:          "123",
		InstallationID: "456",
		PrivateKeyPath: keyPath,
		WebhookSecret:  "env(GH_WH)",
	}
}

func TestGitHubCheck_MintSuccessPasses(t *testing.T) {
	cfg := configuredGitHub(t)
	checks := doctor.Run(doctor.Options{
		Home:       t.TempDir(),
		GitHub:     &cfg,
		GitHubMint: func(context.Context) error { return nil },
	})
	c := findCheck(checks, "github")
	if c == nil || c.Status != doctor.Pass {
		t.Fatalf("check = %+v, want Pass", c)
	}
}

func TestGitHubCheck_MintFailureFails(t *testing.T) {
	cfg := configuredGitHub(t)
	checks := doctor.Run(doctor.Options{
		Home:       t.TempDir(),
		GitHub:     &cfg,
		GitHubMint: func(context.Context) error { return errors.New("401 bad credentials") },
	})
	c := findCheck(checks, "github")
	if c == nil || c.Status != doctor.Fail {
		t.Fatalf("check = %+v, want Fail", c)
	}
}

func TestGitHubCheck_MissingPrivateKeyFails(t *testing.T) {
	cfg := configuredGitHub(t)
	cfg.PrivateKeyPath = filepath.Join(t.TempDir(), "does-not-exist.pem")
	checks := doctor.Run(doctor.Options{Home: t.TempDir(), GitHub: &cfg})
	c := findCheck(checks, "github")
	if c == nil || c.Status != doctor.Fail {
		t.Fatalf("check = %+v, want Fail for missing key", c)
	}
}

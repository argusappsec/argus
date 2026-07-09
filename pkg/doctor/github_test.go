package doctor_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	checks := doctor.Run(doctor.Options{Home: t.TempDir(), GitHub: &config.CodeHostConfig{}})
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

func configuredGitHub(t *testing.T) config.CodeHostConfig {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(keyPath, []byte("dummy"), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.CodeHostConfig{
		Type:           "github",
		AppID:          "123",
		PrivateKeyPath: keyPath,
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

func TestFrontDoorCheck_AbsentWhenNoAddr(t *testing.T) {
	checks := doctor.Run(doctor.Options{Home: t.TempDir()}) // FrontDoorAddr ""
	if findCheck(checks, "front door") != nil {
		t.Error("front-door check must be absent for a socket-only install")
	}
}

func TestFrontDoorCheck_ReachablePasses(t *testing.T) {
	checks := doctor.Run(doctor.Options{
		Home:           t.TempDir(),
		FrontDoorAddr:  ":8080",
		FrontDoorProbe: func(context.Context) error { return nil },
	})
	c := findCheck(checks, "front door")
	if c == nil || c.Status != doctor.Pass {
		t.Fatalf("check = %+v, want Pass when the front door answers", c)
	}
}

func TestFrontDoorCheck_UnreachableFails(t *testing.T) {
	checks := doctor.Run(doctor.Options{
		Home:           t.TempDir(),
		FrontDoorAddr:  ":8080",
		FrontDoorProbe: func(context.Context) error { return errors.New("connection refused") },
	})
	c := findCheck(checks, "front door")
	if c == nil || c.Status != doctor.Fail {
		t.Fatalf("check = %+v, want Fail when the front door is unreachable", c)
	}
	if !strings.Contains(c.Hint, ":8080") {
		t.Errorf("hint should name the address: %q", c.Hint)
	}
}

func TestFrontDoorCheck_NoProbeIsInfo(t *testing.T) {
	checks := doctor.Run(doctor.Options{Home: t.TempDir(), FrontDoorAddr: ":8080"})
	c := findCheck(checks, "front door")
	if c == nil || c.Status != doctor.Info {
		t.Fatalf("check = %+v, want Info when the address is reported but not probed", c)
	}
}

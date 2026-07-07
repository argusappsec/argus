package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/auth"
)

func runUser(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := userCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func runService(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := serviceCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestUserAdd_GithubShortcutResolves(t *testing.T) {
	home := t.TempDir()
	// Always pass --home so the test never touches the real ~/.argus.
	if _, err := runUser(t, "add", "davide", "--role", "admin", "--github", "davideimola", "--home", home); err != nil {
		t.Fatalf("user add: %v", err)
	}

	// The --github shortcut must become a github: identity the Resolver finds.
	p, err := auth.NewResolver(filepath.Join(home, "users.yaml")).Resolve("github:davideimola")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if p.ID != "davide" || p.Role != auth.RoleAdmin {
		t.Errorf("resolved %+v", p)
	}

	out, err := runUser(t, "ls", "--home", home)
	if err != nil {
		t.Fatalf("user ls: %v", err)
	}
	if !strings.Contains(out, "davide") || !strings.Contains(out, "github:davideimola") {
		t.Errorf("ls missing person/identity:\n%s", out)
	}
}

func TestUserAdd_RejectsMissingRole(t *testing.T) {
	home := t.TempDir()
	if _, err := runUser(t, "add", "x", "--home", home); err == nil {
		t.Error("expected --role to be required")
	}
}

func TestServiceAdd_GithubAppStoresSecretHash(t *testing.T) {
	home := t.TempDir()
	secret := "webhook-secret"
	out, err := runService(t, "add", "argus-app",
		"--kind", "github-app", "--secret", secret, "--home", home)
	if err != nil {
		t.Fatalf("service add: %v", err)
	}
	if strings.Contains(out, secret) {
		t.Errorf("github-app add must not echo the provided secret:\n%s", out)
	}

	// The stored hash must satisfy the channel's ResolveService path.
	p, err := auth.NewResolver(filepath.Join(home, "users.yaml")).ResolveService(auth.SHA256Hex(secret))
	if err != nil {
		t.Fatalf("resolve service: %v", err)
	}
	if p.ID != "argus-app" || p.Kind != auth.KindService {
		t.Errorf("resolved %+v", p)
	}
}

func TestServiceAdd_GithubAppRequiresSecret(t *testing.T) {
	home := t.TempDir()
	if _, err := runService(t, "add", "argus-app", "--kind", "github-app", "--home", home); err == nil {
		t.Error("expected --secret to be required for github-app")
	}
}

func TestServiceAdd_CiTriggerGeneratesSecretWhenAbsent(t *testing.T) {
	home := t.TempDir()
	out, err := runService(t, "add", "ci", "--repo", "github.com/x/y", "--home", home)
	if err != nil {
		t.Fatalf("service add: %v", err)
	}
	if !strings.Contains(out, "generated secret") {
		t.Errorf("expected a generated secret to be printed:\n%s", out)
	}
}

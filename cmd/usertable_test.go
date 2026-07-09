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

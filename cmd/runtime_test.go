package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// resolveHome precedence: --home > ARGUS_HOME > ./.argus (if it exists) >
// $HOME/.argus. These tests pin that order, especially the project-local
// step, which only activates when ./.argus already exists.

func TestResolveHome_OverrideWins(t *testing.T) {
	t.Setenv("ARGUS_HOME", "")
	override := filepath.Join(t.TempDir(), "custom")
	got, err := resolveHome(override)
	if err != nil {
		t.Fatalf("resolveHome: %v", err)
	}
	if got != override {
		t.Errorf("got %q, want %q", got, override)
	}
	if fi, err := os.Stat(override); err != nil || !fi.IsDir() {
		t.Errorf("override dir should be created")
	}
}

func TestResolveHome_ArgusHomeEnv(t *testing.T) {
	envHome := filepath.Join(t.TempDir(), "envhome")
	t.Setenv("ARGUS_HOME", envHome)
	got, err := resolveHome("")
	if err != nil {
		t.Fatalf("resolveHome: %v", err)
	}
	if got != envHome {
		t.Errorf("got %q, want %q", got, envHome)
	}
}

func TestResolveHome_ProjectLocalUsedWhenPresent(t *testing.T) {
	t.Setenv("ARGUS_HOME", "")
	t.Setenv("HOME", t.TempDir()) // guard: fallback must not touch a real ~/.argus

	t.Chdir(t.TempDir())
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(cwd, ".argus")
	if err := os.MkdirAll(local, 0o700); err != nil {
		t.Fatal(err)
	}

	got, err := resolveHome("")
	if err != nil {
		t.Fatalf("resolveHome: %v", err)
	}
	if got != local {
		t.Errorf("got %q, want project-local %q", got, local)
	}
}

func TestResolveHome_FallsBackToHomeWhenNoLocal(t *testing.T) {
	t.Setenv("ARGUS_HOME", "")
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Chdir(t.TempDir()) // a CWD with no ./.argus

	got, err := resolveHome("")
	if err != nil {
		t.Fatalf("resolveHome: %v", err)
	}
	want := filepath.Join(fakeHome, ".argus")
	if got != want {
		t.Errorf("got %q, want default %q", got, want)
	}
}

func TestResolveHome_ExplicitBeatsProjectLocal(t *testing.T) {
	t.Setenv("ARGUS_HOME", "")
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, ".argus"), 0o700); err != nil {
		t.Fatal(err)
	}

	override := filepath.Join(t.TempDir(), "explicit")
	got, err := resolveHome(override)
	if err != nil {
		t.Fatalf("resolveHome: %v", err)
	}
	if got != override {
		t.Errorf("explicit --home must win over project-local; got %q", got)
	}
}

func TestResolveHome_FileNamedDotArgusIsIgnored(t *testing.T) {
	t.Setenv("ARGUS_HOME", "")
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Chdir(t.TempDir())
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// A *file* named .argus must not be treated as a home dir.
	if err := os.WriteFile(filepath.Join(cwd, ".argus"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := resolveHome("")
	if err != nil {
		t.Fatalf("resolveHome: %v", err)
	}
	if got != filepath.Join(fakeHome, ".argus") {
		t.Errorf("a file named .argus should be ignored, falling back to ~/.argus; got %q", got)
	}
}

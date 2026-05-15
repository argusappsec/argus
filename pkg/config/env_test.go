package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/config"
)

func TestEnv_LoadParsesKeyValuePairs(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	body := `# this is a comment
GEMINI_API_KEY=abc123
GITHUB_PAT="ghp_with spaces"

# inline comment OK
OTHER=plain_value
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := config.LoadEnv(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := e.Get("GEMINI_API_KEY"); got != "abc123" {
		t.Errorf("GEMINI_API_KEY = %q", got)
	}
	if got := e.Get("GITHUB_PAT"); got != "ghp_with spaces" {
		t.Errorf("GITHUB_PAT = %q (quotes should be stripped, spaces preserved)", got)
	}
	if got := e.Get("OTHER"); got != "plain_value" {
		t.Errorf("OTHER = %q", got)
	}
}

func TestEnv_LoadMissingFileIsEmpty(t *testing.T) {
	e, err := config.LoadEnv(filepath.Join(t.TempDir(), "missing.env"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if e.Get("ANYTHING") != "" {
		t.Error("expected empty env")
	}
}

func TestEnv_SetAndSaveRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	e, _ := config.LoadEnv(path)
	e.Set("GEMINI_API_KEY", "secret value with spaces")
	e.Set("PLAIN", "v1")
	if err := e.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	e2, err := config.LoadEnv(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := e2.Get("GEMINI_API_KEY"); got != "secret value with spaces" {
		t.Errorf("roundtrip key with spaces: got %q", got)
	}
	if got := e2.Get("PLAIN"); got != "v1" {
		t.Errorf("roundtrip plain: got %q", got)
	}

	// File permissions must be 0600 (it carries secrets).
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("env file should be 0600, got %o", info.Mode().Perm())
	}
}

func TestEnv_ApplyToProcessOnlySetsMissingKeys(t *testing.T) {
	e := config.EnvFromMap(map[string]string{
		"ARGUS_TEST_KEY_A": "from_env_file",
		"ARGUS_TEST_KEY_B": "from_env_file",
	})

	// Pre-set one of them via os.Setenv; ApplyToProcess must NOT overwrite it
	// (shell-exported values win).
	t.Setenv("ARGUS_TEST_KEY_A", "from_shell")
	t.Setenv("ARGUS_TEST_KEY_B", "")

	e.ApplyToProcess()

	if got := os.Getenv("ARGUS_TEST_KEY_A"); got != "from_shell" {
		t.Errorf("shell value must win, got %q", got)
	}
	if got := os.Getenv("ARGUS_TEST_KEY_B"); got != "from_env_file" {
		t.Errorf("empty shell value should be filled from .env, got %q", got)
	}
}

func TestEnv_SaveCreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", ".env")
	e, _ := config.LoadEnv(path)
	e.Set("X", "y")
	if err := e.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

func TestEnv_SavePreservesUnknownKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("# header\nKEEP_ME=intact\nGEMINI_API_KEY=old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e, _ := config.LoadEnv(path)
	e.Set("GEMINI_API_KEY", "new")
	if err := e.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "KEEP_ME=intact") {
		t.Errorf("KEEP_ME lost on save:\n%s", raw)
	}
	if !strings.Contains(string(raw), "GEMINI_API_KEY=new") {
		t.Errorf("GEMINI_API_KEY not updated:\n%s", raw)
	}
}

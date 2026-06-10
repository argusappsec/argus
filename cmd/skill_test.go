package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runSkill executes the `skill` command tree with args, returning stdout and
// stderr. Tests point --home at a temp dir so the user source is isolated; the
// built-in source is the real embedded one (pr-quick-check et al.).
func runSkill(t *testing.T, args ...string) (stdout, stderr string) {
	t.Helper()
	cmd := skillCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("skill %v: %v", args, err)
	}
	return out.String(), errOut.String()
}

// writeUserSkill drops a minimal user skill at <home>/skills/<name>/SKILL.md.
func writeUserSkill(t *testing.T, home, name, desc string) {
	t.Helper()
	dir := filepath.Join(home, "skills", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "---\nname: " + name + "\ndescription: " + desc + "\n---\n# " + name + "\n\nbody"
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSkillLs_SourceColumn(t *testing.T) {
	home := t.TempDir()
	// A user-only skill and a user override of a real built-in.
	writeUserSkill(t, home, "my-skill", "user authored")
	writeUserSkill(t, home, "pr-quick-check", "my override")

	out, _ := runSkill(t, "ls", "--home", home)
	if !strings.Contains(out, "SOURCE") {
		t.Fatalf("ls header should include a SOURCE column:\n%s", out)
	}

	// Each row's source classification.
	wantRow := map[string]string{
		"my-skill":             "user",
		"pr-quick-check":       "user (overrides built-in)",
		"secret-rotation-plan": "built-in",
	}
	for name, source := range wantRow {
		line := lineFor(out, name)
		if line == "" {
			t.Errorf("ls output missing a row for %q:\n%s", name, out)
			continue
		}
		if !strings.Contains(line, source) {
			t.Errorf("row for %q should show source %q, got: %q", name, source, line)
		}
	}
}

func TestSkillRm_PureBuiltin(t *testing.T) {
	home := t.TempDir()
	out, _ := runSkill(t, "rm", "pr-quick-check", "--home", home)
	if !strings.Contains(out, "built-in") || !strings.Contains(out, "binary") {
		t.Errorf("removing a pure built-in should explain it lives in the binary, got: %q", out)
	}
	// Nothing was created on disk.
	if _, err := os.Stat(filepath.Join(home, "skills", "pr-quick-check")); !os.IsNotExist(err) {
		t.Errorf("rm of a built-in must not create or leave a user directory")
	}
}

func TestSkillRm_Override(t *testing.T) {
	home := t.TempDir()
	writeUserSkill(t, home, "pr-quick-check", "my override")

	out, _ := runSkill(t, "rm", "pr-quick-check", "--home", home)
	if !strings.Contains(out, "built-in") || !strings.Contains(out, "active again") {
		t.Errorf("removing an override should report the built-in is active again, got: %q", out)
	}
	// The user override is gone from disk; the built-in resurfaces via the Catalog.
	if _, err := os.Stat(filepath.Join(home, "skills", "pr-quick-check")); !os.IsNotExist(err) {
		t.Errorf("rm of an override should delete the user directory")
	}
}

func TestSkillRm_UserOnly(t *testing.T) {
	home := t.TempDir()
	writeUserSkill(t, home, "my-skill", "user authored")

	out, _ := runSkill(t, "rm", "my-skill", "--home", home)
	if !strings.Contains(out, `Removed skill "my-skill"`) {
		t.Errorf("rm of a user-only skill should behave as today, got: %q", out)
	}
	if _, err := os.Stat(filepath.Join(home, "skills", "my-skill")); !os.IsNotExist(err) {
		t.Errorf("rm of a user-only skill should delete its directory")
	}
}

func TestSkillRm_Missing(t *testing.T) {
	home := t.TempDir()
	out, _ := runSkill(t, "rm", "does-not-exist", "--home", home)
	if !strings.Contains(out, "No skill named") {
		t.Errorf("rm of an unknown skill should report it was not found, got: %q", out)
	}
}

// lineFor returns the first line in out whose first whitespace-delimited field
// equals name, or "" if none. This isolates a skill's row from the table.
func lineFor(out, name string) string {
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == name {
			return line
		}
	}
	return ""
}

package skill_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/argusappsec/argus/pkg/skill"
)

func TestParse_Valid(t *testing.T) {
	data := []byte("---\nname: pr-quick-check\ndescription: Fast pass over a PR diff\ntags:\n  - pr\n  - quick\n---\n# PR Quick Check\n\nDo the thing.\n")
	s, err := skill.Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Name != "pr-quick-check" {
		t.Errorf("name = %q", s.Name)
	}
	if s.Description != "Fast pass over a PR diff" {
		t.Errorf("description = %q", s.Description)
	}
	if !reflect.DeepEqual(s.Tags, []string{"pr", "quick"}) {
		t.Errorf("tags = %v", s.Tags)
	}
	if s.Content != "# PR Quick Check\n\nDo the thing." {
		t.Errorf("content = %q", s.Content)
	}
}

func TestParse_TagsOptional(t *testing.T) {
	s, err := skill.Parse([]byte("---\nname: n\ndescription: d\n---\nbody\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(s.Tags) != 0 {
		t.Errorf("expected no tags, got %v", s.Tags)
	}
}

func TestParse_Errors(t *testing.T) {
	cases := map[string]string{
		"no opening delimiter": "name: n\ndescription: d\n",
		"no closing delimiter": "---\nname: n\ndescription: d\n",
		"missing name":         "---\ndescription: d\n---\nbody\n",
		"missing description":  "---\nname: n\n---\nbody\n",
	}
	for label, in := range cases {
		if _, err := skill.Parse([]byte(in)); err == nil {
			t.Errorf("%s: expected error, got nil", label)
		}
	}
}

func TestLoadAll_LoadsSkillsAndSkipsNonSkills(t *testing.T) {
	dir := t.TempDir()
	mustSave(t, dir, &skill.Skill{Name: "alpha", Description: "A", Content: "abody"})
	mustSave(t, dir, &skill.Skill{Name: "beta", Description: "B", Content: "bbody"})
	// A directory without a SKILL.md must be ignored, not error.
	if err := os.MkdirAll(filepath.Join(dir, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A loose file at the root must be ignored.
	if err := os.WriteFile(filepath.Join(dir, "loose.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	skills, errs := skill.LoadAll(dir)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(skills) != 2 {
		t.Fatalf("expected 2 skills, got %d", len(skills))
	}
}

func TestLoadAll_MissingDirIsEmpty(t *testing.T) {
	skills, errs := skill.LoadAll(filepath.Join(t.TempDir(), "missing"))
	if len(errs) != 0 {
		t.Errorf("missing dir should not error: %v", errs)
	}
	if len(skills) != 0 {
		t.Errorf("missing dir should yield no skills, got %d", len(skills))
	}
}

func TestLoadAll_CollectsParseErrors(t *testing.T) {
	dir := t.TempDir()
	mustSave(t, dir, &skill.Skill{Name: "good", Description: "G", Content: "g"})
	// Hand-write a malformed skill (no closing delimiter).
	bad := filepath.Join(dir, "bad")
	if err := os.MkdirAll(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, skill.SkillFile), []byte("---\nname: bad\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	skills, errs := skill.LoadAll(dir)
	if len(skills) != 1 || skills[0].Name != "good" {
		t.Errorf("expected only the good skill, got %v", skills)
	}
	if len(errs) != 1 {
		t.Errorf("expected 1 parse error, got %v", errs)
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := &skill.Skill{Name: "rt", Description: "round trip", Tags: []string{"x", "y"}, Content: "# Body\n\nstuff"}
	if err := skill.Save(dir, in); err != nil {
		t.Fatalf("save: %v", err)
	}
	out, err := skill.Load(dir, "rt")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if out.Name != in.Name || out.Description != in.Description || out.Content != in.Content {
		t.Errorf("round-trip mismatch: %+v vs %+v", out, in)
	}
	if !reflect.DeepEqual(out.Tags, in.Tags) {
		t.Errorf("tags round-trip: %v vs %v", out.Tags, in.Tags)
	}
}

func TestDelete_Idempotent(t *testing.T) {
	dir := t.TempDir()
	if err := skill.Delete(dir, "ghost"); err != nil {
		t.Errorf("deleting a missing skill should be a no-op: %v", err)
	}
	mustSave(t, dir, &skill.Skill{Name: "tmp", Description: "d", Content: "c"})
	if err := skill.Delete(dir, "tmp"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := skill.Load(dir, "tmp"); err == nil {
		t.Error("expected load to fail after delete")
	}
}

func TestNameTraversalRejected(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"../escape", "a/b", `a\b`, "..", ""} {
		if _, err := skill.Load(dir, bad); err == nil {
			t.Errorf("Load(%q) should reject", bad)
		}
		if err := skill.Delete(dir, bad); err == nil {
			t.Errorf("Delete(%q) should reject", bad)
		}
	}
}

func mustSave(t *testing.T, dir string, s *skill.Skill) {
	t.Helper()
	if err := skill.Save(dir, s); err != nil {
		t.Fatalf("save %q: %v", s.Name, err)
	}
}

package skill_test

import (
	"io/fs"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/redcarbon-dev/argus/pkg/skill"
)

// skillFile builds an fstest entry for fsys/<name>/SKILL.md with the given body.
func skillFile(name, body string) (string, *fstest.MapFile) {
	return name + "/SKILL.md", &fstest.MapFile{Data: []byte(body)}
}

func valid(name, desc string) string {
	return "---\nname: " + name + "\ndescription: " + desc + "\n---\n# " + name + "\n\nbody for " + name
}

func names(skills []*skill.Skill) []string {
	out := make([]string, len(skills))
	for i, s := range skills {
		out[i] = s.Name
	}
	sort.Strings(out)
	return out
}

func TestCatalog_NamePresentInOnlySource(t *testing.T) {
	builtinName, builtinFile := skillFile("only-builtin", valid("only-builtin", "from builtin"))
	userName, userFile := skillFile("only-user", valid("only-user", "from user"))

	cat := skill.NewCatalogFS(
		fstest.MapFS{builtinName: builtinFile},
		fstest.MapFS{userName: userFile},
	)

	skills, errs := cat.List()
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if got := names(skills); !equal(got, []string{"only-builtin", "only-user"}) {
		t.Errorf("List names = %v, want [only-builtin only-user]", got)
	}

	// Each resolves from its own source.
	for _, n := range []string{"only-builtin", "only-user"} {
		s, err := cat.Load(n)
		if err != nil {
			t.Errorf("Load(%q): %v", n, err)
			continue
		}
		if s.Name != n {
			t.Errorf("Load(%q).Name = %q", n, s.Name)
		}
	}
}

func TestCatalog_UserBeatsBuiltinByName(t *testing.T) {
	bName, bFile := skillFile("dup", valid("dup", "BUILTIN description"))
	uName, uFile := skillFile("dup", valid("dup", "USER description"))

	cat := skill.NewCatalogFS(
		fstest.MapFS{bName: bFile},
		fstest.MapFS{uName: uFile},
	)

	skills, errs := cat.List()
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(skills) != 1 {
		t.Fatalf("expected exactly one skill (the override collapses the duplicate), got %d", len(skills))
	}
	if skills[0].Description != "USER description" {
		t.Errorf("List should surface the user version, got %q", skills[0].Description)
	}

	s, err := cat.Load("dup")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.Description != "USER description" {
		t.Errorf("Load should resolve to the user version, got %q", s.Description)
	}
}

func TestCatalog_WholeBundleOverride(t *testing.T) {
	// The built-in carries a body AND a supporting file; the user override
	// carries only a body. The override must win the WHOLE bundle: the
	// built-in's body must not leak through.
	bBodyName, bBodyFile := skillFile("bundle", valid("bundle", "builtin body"))
	uBodyName, uBodyFile := skillFile("bundle", valid("bundle", "user body"))

	cat := skill.NewCatalogFS(
		fstest.MapFS{
			bBodyName:            bBodyFile,
			"bundle/template.md": {Data: []byte("BUILTIN TEMPLATE")},
		},
		fstest.MapFS{uBodyName: uBodyFile},
	)

	s, err := cat.Load("bundle")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strings.Contains(s.Content, "body for bundle") || s.Description != "user body" {
		t.Errorf("override body should come from the user source, got desc=%q content=%q", s.Description, s.Content)
	}
}

func TestCatalog_MalformedUserOverrideStillShadows(t *testing.T) {
	bName, bFile := skillFile("shadowed", valid("shadowed", "the built-in"))
	// User claims the name via directory presence, but its SKILL.md is broken.
	uName := "shadowed/SKILL.md"
	uFile := &fstest.MapFile{Data: []byte("---\nname: shadowed\n")} // no closing delimiter

	cat := skill.NewCatalogFS(
		fstest.MapFS{bName: bFile},
		fstest.MapFS{uName: uFile},
	)

	// List: the built-in must NOT resurface; the parse error is collected.
	skills, errs := cat.List()
	for _, s := range skills {
		if s.Name == "shadowed" {
			t.Errorf("built-in must not resurface behind a malformed user override; got %+v", s)
		}
	}
	if len(errs) == 0 {
		t.Error("expected the malformed override's parse error to be collected for humans")
	}

	// Load: must surface the parse error, NOT silently fall back to the built-in.
	if _, err := cat.Load("shadowed"); err == nil {
		t.Error("Load of a malformed override should error, not resurface the built-in")
	}
}

func TestCatalog_LoadRejectsTraversal(t *testing.T) {
	cat := skill.NewCatalogFS(fstest.MapFS{}, fstest.MapFS{})
	for _, bad := range []string{"../escape", "a/b", `a\b`, "..", ""} {
		if _, err := cat.Load(bad); err == nil {
			t.Errorf("Load(%q) should reject", bad)
		}
	}
}

func TestCatalog_DirWithoutSkillMdDoesNotClaim(t *testing.T) {
	// A user directory that holds no SKILL.md is not a skill and must not
	// shadow the built-in of the same name.
	bName, bFile := skillFile("present", valid("present", "the built-in"))
	cat := skill.NewCatalogFS(
		fstest.MapFS{bName: bFile},
		fstest.MapFS{"present/notes.txt": {Data: []byte("just a stray file")}},
	)

	s, err := cat.Load("present")
	if err != nil {
		t.Fatalf("Load should fall through to the built-in: %v", err)
	}
	if s.Description != "the built-in" {
		t.Errorf("expected the built-in, got %q", s.Description)
	}
}

// TestBuiltin_EveryEmbeddedSkillParses guards CI: a broken shipped skill fails
// here, not at runtime in front of a user.
func TestBuiltin_EveryEmbeddedSkillParses(t *testing.T) {
	fsys := skill.Builtin()
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		t.Fatalf("read builtin root: %v", err)
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := fs.ReadFile(fsys, e.Name()+"/"+skill.SkillFile)
		if err != nil {
			t.Errorf("builtin %q: missing %s: %v", e.Name(), skill.SkillFile, err)
			continue
		}
		s, err := skill.Parse(data)
		if err != nil {
			t.Errorf("builtin %q: SKILL.md does not parse: %v", e.Name(), err)
			continue
		}
		if s.Name != e.Name() {
			t.Errorf("builtin %q: frontmatter name %q must match directory name", e.Name(), s.Name)
		}
		count++
	}
	if count == 0 {
		t.Fatal("expected at least one embedded built-in skill")
	}
}

func TestBuiltin_ShipsExpectedSkills(t *testing.T) {
	cat := skill.NewCatalog(skill.Builtin(), t.TempDir())
	for _, want := range []string{"pr-quick-check", "secret-rotation-plan"} {
		s, err := cat.Load(want)
		if err != nil {
			t.Errorf("expected built-in %q to load: %v", want, err)
			continue
		}
		if s.Description == "" {
			t.Errorf("built-in %q has empty description", want)
		}
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

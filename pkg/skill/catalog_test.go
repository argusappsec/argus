package skill_test

import (
	"io/fs"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/argusappsec/argus/pkg/skill"
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

func TestCatalog_OpenFile_ReadsFromWinningSource(t *testing.T) {
	// The built-in carries a template; an unrelated user skill exists but does
	// not claim "bundle", so OpenFile reads the built-in's template.
	bName, bFile := skillFile("bundle", valid("bundle", "builtin body"))
	cat := skill.NewCatalogFS(
		fstest.MapFS{
			bName:                bFile,
			"bundle/template.md": {Data: []byte("BUILTIN TEMPLATE")},
		},
		fstest.MapFS{},
	)

	data, err := cat.OpenFile("bundle", "template.md")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if string(data) != "BUILTIN TEMPLATE" {
		t.Errorf("OpenFile = %q, want BUILTIN TEMPLATE", data)
	}
}

func TestCatalog_OpenFile_UserOverrideWinsWholeBundle(t *testing.T) {
	// Both sources claim "bundle" and both carry template.md. The user override
	// wins the whole bundle: OpenFile must read the user's file, never cross to
	// the built-in's.
	bName, bFile := skillFile("bundle", valid("bundle", "builtin body"))
	uName, uFile := skillFile("bundle", valid("bundle", "user body"))
	cat := skill.NewCatalogFS(
		fstest.MapFS{
			bName:                bFile,
			"bundle/template.md": {Data: []byte("BUILTIN TEMPLATE")},
		},
		fstest.MapFS{
			uName:                uFile,
			"bundle/template.md": {Data: []byte("USER TEMPLATE")},
		},
	)

	data, err := cat.OpenFile("bundle", "template.md")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if string(data) != "USER TEMPLATE" {
		t.Errorf("OpenFile = %q, want USER TEMPLATE (override wins the whole bundle)", data)
	}
}

func TestCatalog_OpenFile_NoCrossSourceFallback(t *testing.T) {
	// The user wins the name (its SKILL.md exists) but ships no template. The
	// built-in's template must NOT leak through — a file missing from the
	// winning bundle errors cleanly.
	bName, bFile := skillFile("bundle", valid("bundle", "builtin body"))
	uName, uFile := skillFile("bundle", valid("bundle", "user body"))
	cat := skill.NewCatalogFS(
		fstest.MapFS{
			bName:                bFile,
			"bundle/template.md": {Data: []byte("BUILTIN TEMPLATE")},
		},
		fstest.MapFS{uName: uFile},
	)

	if _, err := cat.OpenFile("bundle", "template.md"); err == nil {
		t.Error("OpenFile should error when the winning bundle lacks the file, not fall back to the built-in")
	}
}

func TestCatalog_OpenFile_SandboxRejectsTraversal(t *testing.T) {
	bName, bFile := skillFile("bundle", valid("bundle", "builtin body"))
	cat := skill.NewCatalogFS(
		fstest.MapFS{
			bName:                bFile,
			"bundle/template.md": {Data: []byte("ok")},
		},
		fstest.MapFS{},
	)

	// Bad skill names (path traversal in the name itself).
	for _, bad := range []string{"../escape", "a/b", `a\b`, "..", ""} {
		if _, err := cat.OpenFile(bad, "template.md"); err == nil {
			t.Errorf("OpenFile(%q, ...) should reject the name", bad)
		}
	}
	// Bad file paths: fs.ValidPath rejects "..", absolute, malformed, and empty.
	for _, bad := range []string{"../../etc/passwd", "/etc/passwd", "", ".", "a//b", "sub/../../escape"} {
		if _, err := cat.OpenFile("bundle", bad); err == nil {
			t.Errorf("OpenFile(bundle, %q) should reject the path", bad)
		}
	}
}

func TestCatalog_OpenFile_MissingFileErrors(t *testing.T) {
	bName, bFile := skillFile("bundle", valid("bundle", "builtin body"))
	cat := skill.NewCatalogFS(fstest.MapFS{bName: bFile}, fstest.MapFS{})

	if _, err := cat.OpenFile("bundle", "nope.md"); err == nil {
		t.Error("OpenFile of a missing file should error")
	}
}

func TestBuiltin_ThreatModelingShipsStrideTemplate(t *testing.T) {
	cat := skill.NewCatalog(skill.Builtin(), t.TempDir())

	s, err := cat.Load("threat-modeling")
	if err != nil {
		t.Fatalf("load threat-modeling: %v", err)
	}
	// The body must reference the template it pulls, so the agent knows to read it.
	if !strings.Contains(s.Content, "stride-template.md") {
		t.Error("threat-modeling body should reference stride-template.md")
	}

	data, err := cat.OpenFile("threat-modeling", "stride-template.md")
	if err != nil {
		t.Fatalf("open bundled STRIDE template: %v", err)
	}
	if !strings.Contains(string(data), "STRIDE") {
		t.Errorf("bundled template should be a STRIDE worksheet, got %q", data)
	}
}

func TestBuiltin_AuthzAuditShipsSelfTest(t *testing.T) {
	cat := skill.NewCatalog(skill.Builtin(), t.TempDir())

	s, err := cat.Load("authz-audit")
	if err != nil {
		t.Fatalf("load authz-audit: %v", err)
	}
	// The body must reference the self-test oracle by name so read_skill_file
	// can resolve it, and must warn against loading it during a real audit.
	if !strings.Contains(s.Content, "self-test-vampi.md") {
		t.Error("authz-audit body should reference self-test-vampi.md")
	}

	data, err := cat.OpenFile("authz-audit", "self-test-vampi.md")
	if err != nil {
		t.Fatalf("open bundled VAmPI self-test: %v", err)
	}
	if !strings.Contains(string(data), "VAmPI") {
		t.Errorf("bundled self-test should be the VAmPI oracle, got %q", data)
	}
}

func TestBuiltin_ShipsExpectedSkills(t *testing.T) {
	cat := skill.NewCatalog(skill.Builtin(), t.TempDir())
	for _, want := range []string{"authz-audit", "pr-quick-check", "secret-rotation-plan", "threat-modeling"} {
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

func TestCatalog_ListEntries_ClassifiesSource(t *testing.T) {
	bOnly, bOnlyFile := skillFile("only-builtin", valid("only-builtin", "from builtin"))
	bDup, bDupFile := skillFile("dup", valid("dup", "builtin dup"))
	uOnly, uOnlyFile := skillFile("only-user", valid("only-user", "from user"))
	uDup, uDupFile := skillFile("dup", valid("dup", "user dup"))

	cat := skill.NewCatalogFS(
		fstest.MapFS{bOnly: bOnlyFile, bDup: bDupFile},
		fstest.MapFS{uOnly: uOnlyFile, uDup: uDupFile},
	)

	entries, errs := cat.ListEntries()
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	got := make(map[string]skill.Source, len(entries))
	for _, e := range entries {
		got[e.Skill.Name] = e.Source
	}
	want := map[string]skill.Source{
		"only-builtin": skill.SourceBuiltin,
		"only-user":    skill.SourceUser,
		"dup":          skill.SourceUserOverride,
	}
	if len(got) != len(want) {
		t.Fatalf("ListEntries returned %d entries, want %d: %v", len(got), len(want), got)
	}
	for name, src := range want {
		if got[name] != src {
			t.Errorf("source of %q = %q, want %q", name, got[name], src)
		}
	}
}

func TestSource_String(t *testing.T) {
	cases := map[skill.Source]string{
		skill.SourceBuiltin:      "built-in",
		skill.SourceUser:         "user",
		skill.SourceUserOverride: "user (overrides built-in)",
	}
	for src, want := range cases {
		if got := src.String(); got != want {
			t.Errorf("Source(%d).String() = %q, want %q", src, got, want)
		}
	}
}

func TestCatalog_Locate(t *testing.T) {
	bName, bFile := skillFile("builtin-only", valid("builtin-only", "b"))
	bDup, bDupFile := skillFile("override", valid("override", "b"))
	uName, uFile := skillFile("user-only", valid("user-only", "u"))
	uDup, uDupFile := skillFile("override", valid("override", "u"))

	cat := skill.NewCatalogFS(
		fstest.MapFS{bName: bFile, bDup: bDupFile},
		fstest.MapFS{uName: uFile, uDup: uDupFile},
	)

	cases := []struct {
		name         string
		wantU, wantB bool
	}{
		{"builtin-only", false, true},
		{"user-only", true, false},
		{"override", true, true},
		{"missing", false, false},
	}
	for _, tc := range cases {
		u, b, err := cat.Locate(tc.name)
		if err != nil {
			t.Errorf("Locate(%q): %v", tc.name, err)
			continue
		}
		if u != tc.wantU || b != tc.wantB {
			t.Errorf("Locate(%q) = user=%v builtin=%v, want user=%v builtin=%v", tc.name, u, b, tc.wantU, tc.wantB)
		}
	}

	if _, _, err := cat.Locate("../escape"); err == nil {
		t.Error("Locate should reject a traversal name")
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

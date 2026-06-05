package tool_test

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/redcarbon-dev/argus/pkg/skill"
	"github.com/redcarbon-dev/argus/pkg/tool"
)

// userCatalog builds a Catalog whose only source is the user dir (the built-in
// source is empty), so these tests exercise the tools' formatting and error
// handling without depending on the shipped built-in skills.
func userCatalog(dir string) *skill.Catalog {
	return skill.NewCatalog(fstest.MapFS{}, dir)
}

func TestListSkills_EmptyWhenNoDir(t *testing.T) {
	ls := tool.NewListSkills(userCatalog(t.TempDir() + "/missing"))
	out, err := ls.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("missing dir should yield empty list, got %q", out)
	}
}

func TestListSkills_ListsNameDescriptionTagsSorted(t *testing.T) {
	dir := t.TempDir()
	if err := skill.Save(dir, &skill.Skill{Name: "zebra", Description: "Z skill", Content: "z"}); err != nil {
		t.Fatal(err)
	}
	if err := skill.Save(dir, &skill.Skill{Name: "alpha", Description: "A skill", Tags: []string{"x", "y"}, Content: "a"}); err != nil {
		t.Fatal(err)
	}

	out, err := tool.NewListSkills(userCatalog(dir)).Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out, "alpha — A skill [x, y]") {
		t.Errorf("expected alpha line with tags; got:\n%s", out)
	}
	if !strings.Contains(out, "zebra — Z skill") {
		t.Errorf("expected zebra line; got:\n%s", out)
	}
	// Sorted: alpha before zebra.
	if strings.Index(out, "alpha") > strings.Index(out, "zebra") {
		t.Errorf("skills should be sorted by name; got:\n%s", out)
	}
}

func TestReadSkill_ReturnsBody(t *testing.T) {
	dir := t.TempDir()
	if err := skill.Save(dir, &skill.Skill{Name: "demo", Description: "d", Content: "# Demo\nrun it"}); err != nil {
		t.Fatal(err)
	}
	out, err := tool.NewReadSkill(userCatalog(dir)).Execute(context.Background(), map[string]any{"name": "demo"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out, "run it") {
		t.Errorf("expected skill body, got %q", out)
	}
}

func TestReadSkill_MissingNameErrors(t *testing.T) {
	if _, err := tool.NewReadSkill(userCatalog(t.TempDir())).Execute(context.Background(), map[string]any{}); err == nil {
		t.Error("expected error when name is missing")
	}
}

func TestReadSkill_RejectsTraversalAndUnknown(t *testing.T) {
	rs := tool.NewReadSkill(userCatalog(t.TempDir()))
	for _, bad := range []string{"../etc/passwd", "a/b", "nope"} {
		if _, err := rs.Execute(context.Background(), map[string]any{"name": bad}); err == nil {
			t.Errorf("read_skill(%q) should error", bad)
		}
	}
}

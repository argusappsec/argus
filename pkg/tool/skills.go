package tool

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/redcarbon-dev/argus/pkg/skill"
)

// NewListSkills returns a `list_skills` tool that enumerates the user-curated
// skills available under dir (typically ~/.argus/skills/). The agent calls it
// to discover which reusable workflows it can load, paying no token cost for
// the skill bodies it doesn't need.
func NewListSkills(dir string) Tool { return &listSkills{dir: dir} }

type listSkills struct{ dir string }

func (l *listSkills) Name() string { return "list_skills" }

func (l *listSkills) Description() string {
	return "List the reusable skills (multi-step security workflows) available to load on demand. " +
		"Returns one skill per line as `name — description [tags]`. " +
		"Call read_skill(name) to fetch a skill's full instructions when its description matches the task at hand."
}

func (l *listSkills) Schema() map[string]any {
	return map[string]any{"type": "object", "properties": map[string]any{}}
}

func (l *listSkills) Execute(_ context.Context, _ map[string]any) (string, error) {
	// Malformed skills are skipped: surfacing parse errors to the LLM adds
	// noise. `argus skill ls` reports them to the human author instead.
	skills, _ := skill.LoadAll(l.dir)
	if len(skills) == 0 {
		return "", nil
	}
	sort.Slice(skills, func(i, j int) bool { return skills[i].Name < skills[j].Name })

	var b strings.Builder
	for i, s := range skills {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(s.Name)
		b.WriteString(" — ")
		b.WriteString(s.Description)
		if len(s.Tags) > 0 {
			fmt.Fprintf(&b, " [%s]", strings.Join(s.Tags, ", "))
		}
	}
	return b.String(), nil
}

// NewReadSkill returns a `read_skill` tool that returns the full markdown body
// of one skill by name. The agent follows the returned instructions in its
// normal reasoning loop — there is no separate skill VM or active/inactive
// state. The skill name is validated against path traversal by pkg/skill.
func NewReadSkill(dir string) Tool { return &readSkill{dir: dir} }

type readSkill struct{ dir string }

func (r *readSkill) Name() string { return "read_skill" }

func (r *readSkill) Description() string {
	return "Read the full instructions of one skill by name. " +
		"Use list_skills first to discover available names. " +
		"Returns the skill's markdown body; follow it as part of your normal reasoning."
}

func (r *readSkill) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{
				"type":        "string",
				"description": "Skill name (the directory handle, e.g. \"pr-quick-check\"). Must not contain path separators.",
			},
		},
		"required": []string{"name"},
	}
}

func (r *readSkill) Execute(_ context.Context, args map[string]any) (string, error) {
	name, _ := args["name"].(string)
	if strings.TrimSpace(name) == "" {
		return "", errors.New("read_skill: name required")
	}
	s, err := skill.Load(r.dir, name)
	if err != nil {
		return "", fmt.Errorf("read_skill: %w", err)
	}
	return s.Content, nil
}

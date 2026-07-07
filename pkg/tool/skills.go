package tool

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/argusappsec/argus/pkg/skill"
)

// NewListSkills returns a `list_skills` tool that enumerates the skills the
// agent can load, reading through the Catalog (built-in skills merged with
// user-curated ones, user winning by name). The agent calls it to discover
// which reusable workflows exist, paying no token cost for the bodies it
// doesn't need.
func NewListSkills(cat *skill.Catalog) Tool { return &listSkills{cat: cat} }

type listSkills struct{ cat *skill.Catalog }

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
	skills, _ := l.cat.List()
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
// of one skill by name, resolved through the Catalog (a user override wins over
// the built-in of the same name). The agent follows the returned instructions
// in its normal reasoning loop — there is no separate skill VM or
// active/inactive state. The skill name is validated against path traversal by
// pkg/skill.
func NewReadSkill(cat *skill.Catalog) Tool { return &readSkill{cat: cat} }

type readSkill struct{ cat *skill.Catalog }

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
	s, err := r.cat.Load(name)
	if err != nil {
		return "", fmt.Errorf("read_skill: %w", err)
	}
	return s.Content, nil
}

// NewReadSkillFile returns a `read_skill_file` tool that returns a supporting
// file bundled inside a skill (a template, example, or checklist its body
// references). Resolution goes through the Catalog, so the file is read from
// whichever source won the whole-bundle override (a user override wins body and
// files together). The path is sandboxed within the skill's own directory via
// fs.ValidPath — `..`, absolute paths, and malformed separators are rejected —
// and the skill name passes the same path-traversal validation as read_skill.
// There is deliberately no file-listing tool: supporting files are discovered
// only by reading the SKILL.md body, which names the files it wants.
func NewReadSkillFile(cat *skill.Catalog) Tool { return &readSkillFile{cat: cat} }

type readSkillFile struct{ cat *skill.Catalog }

func (r *readSkillFile) Name() string { return "read_skill_file" }

func (r *readSkillFile) Description() string {
	return "Read a supporting file bundled inside a skill (a template, example, or checklist the skill references). " +
		"Use it after read_skill, when the skill body names a file to load. " +
		"`skill` is the skill name; `path` is the file's location relative to the skill's own directory. " +
		"The path cannot escape that directory — `..` and absolute paths are rejected."
}

func (r *readSkillFile) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"skill": map[string]any{
				"type":        "string",
				"description": "Skill name (the directory handle, e.g. \"threat-modeling\"). Must not contain path separators.",
			},
			"path": map[string]any{
				"type":        "string",
				"description": "Path to the file within the skill's directory (e.g. \"stride-template.md\"). Relative only; \"..\" and absolute paths are rejected.",
			},
		},
		"required": []string{"skill", "path"},
	}
}

func (r *readSkillFile) Execute(_ context.Context, args map[string]any) (string, error) {
	name, _ := args["skill"].(string)
	if strings.TrimSpace(name) == "" {
		return "", errors.New("read_skill_file: skill required")
	}
	filePath, _ := args["path"].(string)
	if strings.TrimSpace(filePath) == "" {
		return "", errors.New("read_skill_file: path required")
	}
	data, err := r.cat.OpenFile(name, filePath)
	if err != nil {
		return "", fmt.Errorf("read_skill_file: %w", err)
	}
	return string(data), nil
}

// Package skill loads user-curated agent skills: markdown documents with a
// small YAML frontmatter (name, description, optional tags) plus a free-form
// body that describes a multi-step workflow the agent can follow.
//
// Skills are content, not code. The agent reads a skill's body and follows
// it; capabilities and RBAC are enforced at the Tool layer, never by a skill
// (a skill that references a Tool the caller cannot use simply fails on that
// call — no escalation). This mirrors the shape used by WildGecu.
//
// A skill lives in its own directory under the skills root:
//
//	~/.argus/skills/<name>/SKILL.md
//
// Built-in skills bundled into the binary via embed.FS are a planned addition
// layered on top of this same loader; see PLANNING.md stream F.
package skill

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// SkillFile is the standard filename for a skill definition.
const SkillFile = "SKILL.md"

// Skill is a domain-specific workflow document the agent can load on demand.
type Skill struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags"`
	Content     string   `yaml:"-"` // markdown body (everything after the frontmatter)
}

// Parse reads a skill from markdown-with-frontmatter:
//
//	---
//	name: pr-quick-check
//	description: Fast security pass over a pull request diff
//	tags: [pr, quick]
//	---
//	# PR Quick Check
//	...markdown body...
//
// name and description are required; tags are optional.
func Parse(data []byte) (*Skill, error) {
	content := string(data)

	if !strings.HasPrefix(content, "---\n") {
		return nil, fmt.Errorf("skill: missing frontmatter delimiter")
	}

	rest := content[4:] // skip opening "---\n"
	frontmatter, body, found := strings.Cut(rest, "\n---")
	if !found {
		return nil, fmt.Errorf("skill: missing closing frontmatter delimiter")
	}
	body = strings.TrimSpace(body)

	var s Skill
	if err := yaml.Unmarshal([]byte(frontmatter), &s); err != nil {
		return nil, fmt.Errorf("skill: parse frontmatter: %w", err)
	}
	if s.Name == "" {
		return nil, fmt.Errorf("skill: name is required")
	}
	if s.Description == "" {
		return nil, fmt.Errorf("skill: description is required")
	}

	s.Content = body
	return &s, nil
}

// Serialize writes a Skill back to frontmatter+body form.
func Serialize(s *Skill) ([]byte, error) {
	fm, err := yaml.Marshal(struct {
		Name        string   `yaml:"name"`
		Description string   `yaml:"description"`
		Tags        []string `yaml:"tags,omitempty"`
	}{Name: s.Name, Description: s.Description, Tags: s.Tags})
	if err != nil {
		return nil, fmt.Errorf("skill: marshal frontmatter: %w", err)
	}

	var buf bytes.Buffer
	buf.WriteString("---\n")
	buf.Write(fm)
	buf.WriteString("---\n")
	if s.Content != "" {
		buf.WriteString(s.Content)
		buf.WriteString("\n")
	}
	return buf.Bytes(), nil
}

// LoadAll loads every skill under dir. Each skill is a subdirectory holding a
// SKILL.md. Directories without a SKILL.md are skipped silently; malformed
// skills are collected into errs so one bad file never hides the good ones.
// A missing dir is not an error — it just yields no skills.
func LoadAll(dir string) ([]*Skill, []error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no skills dir yet = no skills, not an error
		}
		return nil, []error{fmt.Errorf("skill: list dir: %w", err)}
	}

	var skills []*Skill
	var errs []error
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name(), SkillFile))
		if err != nil {
			continue // no SKILL.md in this dir — not a skill
		}
		s, err := Parse(data)
		if err != nil {
			errs = append(errs, fmt.Errorf("skill %q: %w", e.Name(), err))
			continue
		}
		skills = append(skills, s)
	}
	return skills, errs
}

// Load loads a single skill by name from dir.
func Load(dir, name string) (*Skill, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, name, SkillFile))
	if err != nil {
		return nil, fmt.Errorf("skill: load %q: %w", name, err)
	}
	return Parse(data)
}

// Save writes s to dir/<name>/SKILL.md, creating directories as needed.
func Save(dir string, s *Skill) error {
	if err := validateName(s.Name); err != nil {
		return err
	}
	data, err := Serialize(s)
	if err != nil {
		return err
	}
	skillDir := filepath.Join(dir, s.Name)
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		return fmt.Errorf("skill: create dir: %w", err)
	}
	return os.WriteFile(filepath.Join(skillDir, SkillFile), data, 0o644)
}

// Delete removes a skill directory. Idempotent: no error if it doesn't exist.
func Delete(dir, name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(dir, name))
}

// validateName rejects skill names that are empty or could escape the skills
// root. A skill name is a flat directory handle, never a path. This matters
// because names can originate from the LLM (read_skill) or a user (/<name>).
func validateName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("skill: name is required")
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return fmt.Errorf("skill: invalid name %q: path separators and parent references are not allowed", name)
	}
	return nil
}

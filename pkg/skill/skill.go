// Package skill loads user-curated agent skills: markdown documents with a
// small YAML frontmatter (name, description, optional tags) plus a free-form
// body that describes a multi-step workflow the agent can follow.
//
// Skills are content, not code. The agent reads a skill's body and follows
// it; capabilities and RBAC are enforced at the Tool layer, never by a skill
// (a skill that references a Tool the caller cannot use simply fails on that
// call — no escalation). This mirrors the shape used by WildGecu.
//
// A skill is a directory bundle: a SKILL.md entry point plus optional
// supporting files the body references. User-curated skills live under the
// skills root on the daemon host:
//
//	~/.argus/skills/<name>/SKILL.md
//
// Built-in skills are bundled into the binary via embed.FS (see builtin.go).
// Both sources are merged by a Catalog (see catalog.go), which applies the
// whole-bundle override rule: a user <name>/ directory wins over the built-in
// of that name. The walk/parse path is unified over fs.FS so the two sources
// share one implementation. Design: ADR-0005 (revision 2026-06-05).
package skill

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
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

// walkEntry is one skill directory discovered while walking a source. A
// malformed SKILL.md yields skill == nil and a non-nil err; the directory is
// still recorded (its dir name claims the skill name) so an override decision
// can be made without the body parsing successfully.
type walkEntry struct {
	dir   string
	skill *Skill // nil when err != nil
	err   error  // non-nil when SKILL.md failed to parse
}

// walkSkills enumerates skill directories in fsys, returning one walkEntry per
// directory that contains a SKILL.md (parseable or not). Directories without a
// SKILL.md are skipped silently — they are not skills and do not claim a name.
// A missing source root is not an error; it just yields no entries. Entries are
// returned sorted by directory name (fs.ReadDir guarantees the ordering).
//
// This is the single walk/parse path shared by the user directory
// (os.DirFS) and the embedded built-in source, so both behave identically.
func walkSkills(fsys fs.FS) ([]walkEntry, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil // no skills source yet = no skills, not an error
		}
		return nil, fmt.Errorf("skill: list dir: %w", err)
	}

	var out []walkEntry
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := fs.ReadFile(fsys, path.Join(e.Name(), SkillFile))
		if err != nil {
			continue // no SKILL.md in this dir — not a skill
		}
		s, err := Parse(data)
		if err != nil {
			out = append(out, walkEntry{dir: e.Name(), err: fmt.Errorf("skill %q: %w", e.Name(), err)})
			continue
		}
		out = append(out, walkEntry{dir: e.Name(), skill: s})
	}
	return out, nil
}

// parseSkillAt reads and parses fsys/<name>/SKILL.md. name must already be
// validated when it originates from an untrusted source (callers use
// validateName); when it comes from walkSkills it is a real directory entry.
func parseSkillAt(fsys fs.FS, name string) (*Skill, error) {
	data, err := fs.ReadFile(fsys, path.Join(name, SkillFile))
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// LoadAll loads every skill under dir. Each skill is a subdirectory holding a
// SKILL.md. Directories without a SKILL.md are skipped silently; malformed
// skills are collected into errs so one bad file never hides the good ones.
// A missing dir is not an error — it just yields no skills.
func LoadAll(dir string) ([]*Skill, []error) {
	walks, err := walkSkills(os.DirFS(dir))
	if err != nil {
		return nil, []error{err}
	}
	var skills []*Skill
	var errs []error
	for _, w := range walks {
		if w.err != nil {
			errs = append(errs, w.err)
			continue
		}
		skills = append(skills, w.skill)
	}
	return skills, errs
}

// Load loads a single skill by name from dir.
func Load(dir, name string) (*Skill, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	s, err := parseSkillAt(os.DirFS(dir), name)
	if err != nil {
		return nil, fmt.Errorf("skill: load %q: %w", name, err)
	}
	return s, nil
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

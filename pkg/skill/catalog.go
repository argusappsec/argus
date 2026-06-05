package skill

import (
	"fmt"
	"io/fs"
	"os"
	"path"
)

// Catalog is the single source of truth for skill resolution. It merges a
// built-in source (the embedded fs.FS) with the user-curated directory and
// applies the whole-bundle override rule from ADR-0005:
//
//   - A user <name>/ directory claims the name and wins the entire bundle
//     (body and supporting files) over the built-in of that name. Override is
//     decided by directory presence, not by which body parses.
//   - A user override whose SKILL.md is malformed still shadows the built-in:
//     the built-in does NOT silently resurface. The parse error is collected
//     for humans (argus skill ls) and skipped for the agent (list_skills).
//
// list_skills / read_skill, the /<name> chat resolver, and the argus skill CLI
// all read through one Catalog so they never disagree about what is active.
// The write path (Save / Delete) stays user-dir-only: built-ins live in the
// binary and are immutable by construction.
type Catalog struct {
	builtin fs.FS
	user    fs.FS
}

// NewCatalog builds a Catalog over the embedded built-in source and the user
// skills directory. A missing user dir is fine — it just yields no user
// skills.
func NewCatalog(builtin fs.FS, userDir string) *Catalog {
	return NewCatalogFS(builtin, os.DirFS(userDir))
}

// NewCatalogFS builds a Catalog from two fs.FS sources directly. Production
// code uses NewCatalog (which wraps the user dir with os.DirFS); tests use this
// to inject in-memory or fixture sources.
func NewCatalogFS(builtin, user fs.FS) *Catalog {
	return &Catalog{builtin: builtin, user: user}
}

// List returns the merged set of skills the agent can load: every user skill,
// plus every built-in whose name no user directory claims. Malformed user
// overrides are omitted from the returned skills (they are not loadable) but
// their parse errors are collected so a human can find and fix them. The
// returned skills are not sorted; callers that present them order as they see
// fit (list_skills and argus skill ls both sort).
func (c *Catalog) List() ([]*Skill, []error) {
	userWalks, userErr := walkSkills(c.user)
	builtinWalks, builtinErr := walkSkills(c.builtin)

	var skills []*Skill
	var errs []error
	if userErr != nil {
		errs = append(errs, userErr)
	}

	// User entries first; every user directory claims its name, even when its
	// SKILL.md fails to parse.
	claimed := make(map[string]bool, len(userWalks))
	for _, w := range userWalks {
		claimed[w.dir] = true
		if w.err != nil {
			errs = append(errs, w.err)
			continue
		}
		skills = append(skills, w.skill)
	}

	// Built-ins fill in only the names no user override claims.
	for _, w := range builtinWalks {
		if claimed[w.dir] {
			continue // user override wins the whole bundle
		}
		if w.err != nil {
			errs = append(errs, w.err)
			continue
		}
		skills = append(skills, w.skill)
	}
	if builtinErr != nil {
		errs = append(errs, builtinErr)
	}

	return skills, errs
}

// Load resolves a single skill by name, honouring the whole-bundle override:
// if a user <name>/SKILL.md exists it is used (and a parse failure is returned
// rather than silently falling back to the built-in — the user owns the name);
// otherwise the built-in of that name is loaded. The winning source is decided
// by sourceFor, the same resolution OpenFile applies, so a skill's body and its
// supporting files always come from one source.
func (c *Catalog) Load(name string) (*Skill, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	s, err := parseSkillAt(c.sourceFor(name), name)
	if err != nil {
		return nil, fmt.Errorf("skill: load %q: %w", name, err)
	}
	return s, nil
}

// OpenFile returns the bytes of a supporting file from within a skill's bundle
// (a template, example, or checklist the SKILL.md body references). It honours
// the whole-bundle override: the file is read from whichever source won the
// name — a user <name>/ directory wins the entire bundle over the built-in, so
// a body and its supporting files never cross sources, and a file missing from
// the winning bundle errors cleanly rather than falling back to the other one.
//
// The lookup is sandboxed to the skill's own directory: name passes the usual
// flat-handle validation, and filePath must satisfy fs.ValidPath, which rejects
// "..", absolute paths, and malformed separators. Both guarantees come from the
// fs.FS contract rather than a hand-rolled path resolver.
func (c *Catalog) OpenFile(name, filePath string) ([]byte, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	if !fs.ValidPath(filePath) {
		return nil, fmt.Errorf("skill: invalid file path %q: must be a clean relative path within the skill directory", filePath)
	}

	src := c.sourceFor(name)
	data, err := fs.ReadFile(src, path.Join(name, filePath))
	if err != nil {
		return nil, fmt.Errorf("skill: open %q/%q: %w", name, filePath, err)
	}
	return data, nil
}

// sourceFor returns the fs.FS that won the override for name: the user source
// when a user <name>/SKILL.md exists (a user directory claims the whole bundle,
// even if its body is malformed), otherwise the built-in source. This mirrors
// the resolution Load and List apply, so OpenFile reads files from the same
// source whose body those return.
func (c *Catalog) sourceFor(name string) fs.FS {
	if _, err := fs.Stat(c.user, path.Join(name, SkillFile)); err == nil {
		return c.user
	}
	return c.builtin
}

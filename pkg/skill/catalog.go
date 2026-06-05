package skill

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
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
// otherwise the built-in of that name is loaded.
func (c *Catalog) Load(name string) (*Skill, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}

	s, err := parseSkillAt(c.user, name)
	if err == nil {
		return s, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		// A user SKILL.md exists but failed to parse (or another read error):
		// the user owns this name, so surface the error instead of resurfacing
		// the built-in.
		return nil, fmt.Errorf("skill: load %q: %w", name, err)
	}

	s, err = parseSkillAt(c.builtin, name)
	if err != nil {
		return nil, fmt.Errorf("skill: load %q: %w", name, err)
	}
	return s, nil
}

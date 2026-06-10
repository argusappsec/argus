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

// Source classifies where an active skill comes from, for human-facing
// listings (argus skill ls). The agent does not care — it only sees a resolved
// body — but an operator needs to know at a glance what is shipped, what they
// authored, and what they are shadowing.
type Source int

const (
	// SourceBuiltin ships in the binary and no user directory claims its name.
	SourceBuiltin Source = iota
	// SourceUser is user-curated with no built-in of the same name.
	SourceUser
	// SourceUserOverride is user-curated and shadows a built-in of the same name.
	SourceUserOverride
)

// String renders the source as the label argus skill ls prints in its SOURCE
// column.
func (s Source) String() string {
	switch s {
	case SourceBuiltin:
		return "built-in"
	case SourceUser:
		return "user"
	case SourceUserOverride:
		return "user (overrides built-in)"
	default:
		return "unknown"
	}
}

// Entry is one resolved skill paired with its Source, returned by ListEntries
// for the CLI. The agent-facing List drops the Source and returns bare skills.
type Entry struct {
	Skill  *Skill
	Source Source
}

// List returns the merged set of skills the agent can load: every user skill,
// plus every built-in whose name no user directory claims. Malformed user
// overrides are omitted from the returned skills (they are not loadable) but
// their parse errors are collected so a human can find and fix them. The
// returned skills are not sorted; callers that present them order as they see
// fit (list_skills and argus skill ls both sort).
func (c *Catalog) List() ([]*Skill, []error) {
	entries, errs := c.ListEntries()
	skills := make([]*Skill, len(entries))
	for i, e := range entries {
		skills[i] = e.Skill
	}
	return skills, errs
}

// ListEntries is List with each skill's Source attached, for argus skill ls.
// The merge, override, and error-collection behaviour is identical to List —
// the only addition is classifying each loadable skill as built-in, user, or
// user-override. A name present in both sources collapses to one entry (the
// user's) marked SourceUserOverride.
func (c *Catalog) ListEntries() ([]Entry, []error) {
	userWalks, userErr := walkSkills(c.user)
	builtinWalks, builtinErr := walkSkills(c.builtin)

	// Directory presence in the built-in source decides whether a user skill is
	// an override; a malformed built-in still claims its name for this purpose.
	builtinNames := make(map[string]bool, len(builtinWalks))
	for _, w := range builtinWalks {
		builtinNames[w.dir] = true
	}

	var entries []Entry
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
		src := SourceUser
		if builtinNames[w.dir] {
			src = SourceUserOverride
		}
		entries = append(entries, Entry{Skill: w.skill, Source: src})
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
		entries = append(entries, Entry{Skill: w.skill, Source: SourceBuiltin})
	}
	if builtinErr != nil {
		errs = append(errs, builtinErr)
	}

	return entries, errs
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
	if claims(c.user, name) {
		return c.user
	}
	return c.builtin
}

// Locate reports whether name is claimed by the user dir and/or the built-in
// source, by the same directory-presence rule the override uses (a <name>/
// holding a SKILL.md claims the name, even if that SKILL.md is malformed). The
// argus skill rm command uses it to pick among its three cases — pure built-in,
// override, user-only — without reaching into either fs.FS itself.
func (c *Catalog) Locate(name string) (user, builtin bool, err error) {
	if err := validateName(name); err != nil {
		return false, false, err
	}
	return claims(c.user, name), claims(c.builtin, name), nil
}

// claims reports whether fsys holds <name>/SKILL.md, i.e. whether that source
// claims the name. A bare directory with no SKILL.md does not claim it.
func claims(fsys fs.FS, name string) bool {
	_, err := fs.Stat(fsys, path.Join(name, SkillFile))
	return err == nil
}

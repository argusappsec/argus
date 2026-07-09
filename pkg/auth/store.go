package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"gopkg.in/yaml.v3"
)

// Store is the write side of the user table whose read side is Resolver
// (ADR 0003: storage is a hand-editable users.yaml; bootstrap and mutation
// are the local `argus user` CLI, never an HTTP API).
//
// Every mutation is read-modify-write of the whole file, persisted
// atomically via a temp file + rename in the same directory, so a concurrent
// Resolver.load never observes a half-written table — the freshness contract
// the daemon relies on (it re-reads on every Resolve, with no reload signal).
type Store struct {
	path string
	// now is injectable so tests get deterministic CreatedAt timestamps.
	now func() time.Time
}

// NewStore returns a Store over the users.yaml at path. The file need not
// exist yet; the first Add creates it.
func NewStore(path string) *Store {
	return &Store{path: path, now: func() time.Time { return time.Now().UTC() }}
}

// Person is the exported view of a person entry.
type Person struct {
	ID         string
	Email      string
	Role       Role
	Identities []string
	MCPTokens  []MCPTokenInfo
}

// MCPTokenInfo is the exported view of a stored MCP token (its hash, never
// the cleartext — that is shown once at creation and lost).
type MCPTokenInfo struct {
	Name      string
	SHA256    string
	CreatedAt time.Time
}

// SHA256Hex returns the lowercase hex SHA-256 of s. It is how a shared secret
// (an MCP token) is reduced to the hash stored in users.yaml — the same
// reduction ResolveMCPToken compares against.
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ValidPersonRole reports whether role is a role a Person may hold (ADR 0002).
func ValidPersonRole(role Role) bool {
	switch role {
	case RoleAdmin, RoleAnalyst, RoleViewer:
		return true
	}
	return false
}

// Persons returns the persons in the table.
func (s *Store) Persons() ([]Person, error) {
	uf, err := loadUsers(s.path)
	if err != nil {
		return nil, err
	}
	out := make([]Person, 0, len(uf.Persons))
	for _, p := range uf.Persons {
		out = append(out, toPerson(p))
	}
	return out, nil
}

// AddPerson adds a new person. The id must be unique and the role valid.
func (s *Store) AddPerson(p Person) error {
	if p.ID == "" {
		return fmt.Errorf("auth: person id is required")
	}
	if !ValidPersonRole(p.Role) {
		return fmt.Errorf("auth: invalid person role %q (want admin|analyst|viewer)", p.Role)
	}
	return s.mutate(func(uf *usersFile) error {
		if findPerson(uf, p.ID) >= 0 {
			return fmt.Errorf("auth: person %q already exists", p.ID)
		}
		uf.Persons = append(uf.Persons, personEntry{
			ID:         p.ID,
			Email:      p.Email,
			Role:       p.Role,
			Identities: p.Identities,
		})
		return nil
	})
}

// RemovePerson deletes a person by id.
func (s *Store) RemovePerson(id string) error {
	return s.mutate(func(uf *usersFile) error {
		i := findPerson(uf, id)
		if i < 0 {
			return fmt.Errorf("auth: person %q not found", id)
		}
		uf.Persons = append(uf.Persons[:i], uf.Persons[i+1:]...)
		return nil
	})
}

// AddIdentity grants an identity to an existing person, rejecting duplicates
// (including one already owned by another person — an identity resolves to at
// most one Principal).
func (s *Store) AddIdentity(personID, identity string) error {
	if identity == "" {
		return fmt.Errorf("auth: identity is required")
	}
	return s.mutate(func(uf *usersFile) error {
		i := findPerson(uf, personID)
		if i < 0 {
			return fmt.Errorf("auth: person %q not found", personID)
		}
		for pi := range uf.Persons {
			if slices.Contains(uf.Persons[pi].Identities, identity) {
				return fmt.Errorf("auth: identity %q already belongs to person %q", identity, uf.Persons[pi].ID)
			}
		}
		uf.Persons[i].Identities = append(uf.Persons[i].Identities, identity)
		return nil
	})
}

// AddMCPToken records a new MCP token hash under a person. The cleartext token
// is the caller's to generate and show once; only its hash is stored.
func (s *Store) AddMCPToken(personID, name, sha256hex string) error {
	if name == "" {
		return fmt.Errorf("auth: token name is required")
	}
	return s.mutate(func(uf *usersFile) error {
		i := findPerson(uf, personID)
		if i < 0 {
			return fmt.Errorf("auth: person %q not found", personID)
		}
		for _, t := range uf.Persons[i].MCPTokens {
			if t.Name == name {
				return fmt.Errorf("auth: person %q already has a token named %q", personID, name)
			}
		}
		uf.Persons[i].MCPTokens = append(uf.Persons[i].MCPTokens, mcpToken{
			Name:      name,
			SHA256:    sha256hex,
			CreatedAt: s.now(),
		})
		return nil
	})
}

// RemoveMCPToken revokes a named token from a person.
func (s *Store) RemoveMCPToken(personID, name string) error {
	return s.mutate(func(uf *usersFile) error {
		i := findPerson(uf, personID)
		if i < 0 {
			return fmt.Errorf("auth: person %q not found", personID)
		}
		toks := uf.Persons[i].MCPTokens
		for ti, t := range toks {
			if t.Name == name {
				uf.Persons[i].MCPTokens = append(toks[:ti], toks[ti+1:]...)
				return nil
			}
		}
		return fmt.Errorf("auth: person %q has no token named %q", personID, name)
	})
}

// mutate loads the table, applies fn, and writes the result atomically.
func (s *Store) mutate(fn func(*usersFile) error) error {
	uf, err := loadUsers(s.path)
	if err != nil {
		return err
	}
	if err := fn(uf); err != nil {
		return err
	}
	return saveUsers(s.path, uf)
}

// saveUsers serializes uf to path atomically: write a sibling temp file with
// 0600 perms, then rename over the target. The rename is atomic on the same
// filesystem, so a concurrent reader sees either the old or the new file,
// never a partial one.
func saveUsers(path string, uf *usersFile) error {
	b, err := yaml.Marshal(uf)
	if err != nil {
		return fmt.Errorf("auth: marshal users: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("auth: mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".users-*.yaml")
	if err != nil {
		return fmt.Errorf("auth: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("auth: chmod temp: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("auth: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("auth: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("auth: promote users.yaml: %w", err)
	}
	return nil
}

func findPerson(uf *usersFile, id string) int {
	for i, p := range uf.Persons {
		if p.ID == id {
			return i
		}
	}
	return -1
}

func toPerson(p personEntry) Person {
	toks := make([]MCPTokenInfo, 0, len(p.MCPTokens))
	for _, t := range p.MCPTokens {
		toks = append(toks, MCPTokenInfo(t))
	}
	return Person{
		ID:         p.ID,
		Email:      p.Email,
		Role:       p.Role,
		Identities: p.Identities,
		MCPTokens:  toks,
	}
}

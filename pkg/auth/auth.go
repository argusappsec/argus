// Package auth resolves inbound Identities to Principals against the user
// table (~/.argus/users.yaml, schema fixed by ADR 0003).
//
// The Resolver is strict and policy-free: identity in, Principal or
// ErrUnknownIdentity out. Trust policy belongs to the Channel that owns the
// transport — e.g. the UDS channel's implicit-admin fallback (ADR 0007) is
// implemented there, never here, so no future channel can inherit it by
// accident.
//
// The user table is re-read on every Resolve. The file is tiny and resolves
// are rare (one per inbound event), so this buys always-fresh semantics —
// `argus user add` / `remove` takes effect immediately, with no reload
// signal and no race against the CLI (which writes via rename).
package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"time"

	"gopkg.in/yaml.v3"
)

// Kind distinguishes the two Principal subtypes.
type Kind string

const (
	KindPerson  Kind = "person"
	KindService Kind = "service"
)

// Role is a named bundle of capabilities (ADR 0002).
type Role string

const (
	RoleAdmin   Role = "admin"
	RoleAnalyst Role = "analyst"
	RoleViewer  Role = "viewer"

	// RoleMirrorRead is a retired Service role (ADR 0003) kept only as sample
	// data in an MCP RBAC test; ci-trigger/mirror-read died when Services moved
	// to channel configuration (ADR 0015, CONTEXT.md) and Services now carry no
	// Role.
	RoleMirrorRead Role = "mirror-read"
)

// Principal is the resolved actor behind an inbound request. Audit records
// and RBAC checks reason about Principals, never raw Identities.
type Principal struct {
	ID   string // person/service id from users.yaml, or the identity itself when implicit
	Kind Kind
	Role Role

	// Identity is the concrete authentication surface that resolved to this
	// Principal (e.g. "local:davide", "slack:U123ABC").
	Identity string

	// Implicit is true when the Principal did not come from users.yaml but
	// from a channel's trust policy (the UDS implicit admin, ADR 0007).
	Implicit bool
}

// ImplicitAdmin builds the implicit admin Principal the UDS channel falls
// back to when a local identity is not in the user table (ADR 0007). It
// lives here so the shape is uniform, but *calling* it is the channel's
// decision alone.
func ImplicitAdmin(identity string) Principal {
	return Principal{
		ID:       identity,
		Kind:     KindPerson,
		Role:     RoleAdmin,
		Identity: identity,
		Implicit: true,
	}
}

// ErrUnknownIdentity is returned when an identity has no Person or Service
// entry. Channels translate it into their own polite, opaque rejection
// (ADR 0003: no operational detail leaks to strangers).
var ErrUnknownIdentity = errors.New("auth: unknown identity")

// usersFile mirrors the users.yaml schema from ADR 0003. It holds Persons
// only (ADR 0015): the user table is exactly the set of humans an admin
// manages. A Service Principal — the `github-app` installation — is no longer
// stored here; it is synthesized by the Channel that carries it. A legacy
// `services:` section left by an older Argus is an unknown key and silently
// ignored on load, so upgrading never blocks on runtime state.
type usersFile struct {
	Persons []personEntry `yaml:"persons"`
}

type personEntry struct {
	ID         string     `yaml:"id"`
	Email      string     `yaml:"email,omitempty"`
	Role       Role       `yaml:"role"`
	Identities []string   `yaml:"identities,omitempty"`
	MCPTokens  []mcpToken `yaml:"mcp_tokens,omitempty"`
}

type mcpToken struct {
	Name      string    `yaml:"name"`
	SHA256    string    `yaml:"sha256"`
	CreatedAt time.Time `yaml:"created_at,omitempty"`
}

// Resolver maps Identities to Principals by reading the user table.
type Resolver struct {
	path string
}

// NewResolver returns a Resolver over the users.yaml at path. The file may
// not exist yet — every identity is then unknown, which is the correct
// state for a fresh install (bootstrap is `argus user add`, ADR 0003).
func NewResolver(path string) *Resolver {
	return &Resolver{path: path}
}

// Resolve maps one identity string (e.g. "local:davide", "slack:U123ABC")
// to its Principal. Strict: an identity with no entry returns
// ErrUnknownIdentity, with no fallback of any kind.
func (r *Resolver) Resolve(identity string) (Principal, error) {
	uf, err := r.load()
	if err != nil {
		return Principal{}, err
	}
	for _, p := range uf.Persons {
		if slices.Contains(p.Identities, identity) {
			return Principal{
				ID:       p.ID,
				Kind:     KindPerson,
				Role:     p.Role,
				Identity: identity,
			}, nil
		}
	}
	return Principal{}, fmt.Errorf("%w: %s", ErrUnknownIdentity, identity)
}

// ResolveMCPToken maps an MCP bearer token to its owning Person. The token is
// never stored in cleartext: it is hashed and compared against the per-Person
// MCPTokens recorded by `argus user mcp-token create`. The resolved Identity is
// `mcp:<token-hash>` (CONTEXT.md), so the audit log attributes the action to the
// concrete token surface, not just the Person.
//
// The comparison is constant-time so a registered hash cannot be discovered by
// timing. An unmatched token returns ErrUnknownIdentity, like Resolve — there
// is no anonymous MCP access.
func (r *Resolver) ResolveMCPToken(token string) (Principal, error) {
	uf, err := r.load()
	if err != nil {
		return Principal{}, err
	}
	hash := SHA256Hex(token)
	for _, p := range uf.Persons {
		for _, t := range p.MCPTokens {
			if t.SHA256 == "" {
				continue
			}
			if subtle.ConstantTimeCompare([]byte(t.SHA256), []byte(hash)) == 1 {
				return Principal{
					ID:       p.ID,
					Kind:     KindPerson,
					Role:     p.Role,
					Identity: "mcp:" + hash,
				}, nil
			}
		}
	}
	return Principal{}, fmt.Errorf("%w: mcp token", ErrUnknownIdentity)
}

// load re-reads the user table from disk. A missing file yields an empty
// table, not an error.
func (r *Resolver) load() (*usersFile, error) { return loadUsers(r.path) }

// loadUsers reads and parses a users.yaml. A missing file yields an empty
// table, not an error — the correct state for a fresh install. Shared by the
// read-only Resolver and the read-modify-write Store.
func loadUsers(path string) (*usersFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &usersFile{}, nil
		}
		return nil, fmt.Errorf("auth: read %s: %w", path, err)
	}
	var uf usersFile
	if err := yaml.Unmarshal(b, &uf); err != nil {
		return nil, fmt.Errorf("auth: parse %s: %w", path, err)
	}
	return &uf, nil
}

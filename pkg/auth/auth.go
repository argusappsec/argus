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
	"errors"
	"fmt"
	"io/fs"
	"os"
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

	RoleCITrigger  Role = "ci-trigger"
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

// usersFile mirrors the users.yaml schema from ADR 0003.
type usersFile struct {
	Persons  []personEntry  `yaml:"persons"`
	Services []serviceEntry `yaml:"services"`
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

type serviceEntry struct {
	ID           string    `yaml:"id"`
	Role         Role      `yaml:"role"`
	Repo         string    `yaml:"repo,omitempty"`
	SecretSHA256 string    `yaml:"secret_sha256,omitempty"`
	CreatedAt    time.Time `yaml:"created_at,omitempty"`
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
		for _, id := range p.Identities {
			if id == identity {
				return Principal{
					ID:       p.ID,
					Kind:     KindPerson,
					Role:     p.Role,
					Identity: identity,
				}, nil
			}
		}
	}
	return Principal{}, fmt.Errorf("%w: %s", ErrUnknownIdentity, identity)
}

// load re-reads the user table from disk. A missing file yields an empty
// table, not an error.
func (r *Resolver) load() (*usersFile, error) {
	b, err := os.ReadFile(r.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &usersFile{}, nil
		}
		return nil, fmt.Errorf("auth: read %s: %w", r.path, err)
	}
	var uf usersFile
	if err := yaml.Unmarshal(b, &uf); err != nil {
		return nil, fmt.Errorf("auth: parse %s: %w", r.path, err)
	}
	return &uf, nil
}

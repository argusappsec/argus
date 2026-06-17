package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const sampleUsers = `persons:
  - id: davide
    email: davide.imola@redcarbon.ai
    role: admin
    identities:
      - slack:U123ABC
      - github:davideimola
      - local:davide
  - id: nicco
    role: analyst
    identities:
      - slack:U999XYZ
services:
  - id: ci-rc-guest-portal
    role: ci-trigger
    repo: github.com/redcarbon-dev/rc-guest-portal
    secret_sha256: deadbeef
`

func writeUsers(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolve_KnownIdentity(t *testing.T) {
	r := NewResolver(writeUsers(t, sampleUsers))

	p, err := r.Resolve("local:davide")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.ID != "davide" || p.Role != RoleAdmin || p.Kind != KindPerson {
		t.Errorf("got %+v, want davide/admin/person", p)
	}
	if p.Identity != "local:davide" {
		t.Errorf("Identity = %q, want the resolved surface", p.Identity)
	}
	if p.Implicit {
		t.Errorf("a users.yaml Principal must not be Implicit")
	}

	// A second identity of the same Person resolves to the same Principal ID.
	p2, err := r.Resolve("slack:U123ABC")
	if err != nil {
		t.Fatalf("Resolve slack: %v", err)
	}
	if p2.ID != "davide" {
		t.Errorf("slack identity resolved to %q, want davide", p2.ID)
	}
}

func TestResolve_UnknownIdentityIsStrict(t *testing.T) {
	r := NewResolver(writeUsers(t, sampleUsers))
	_, err := r.Resolve("slack:UNOBODY")
	if !errors.Is(err, ErrUnknownIdentity) {
		t.Fatalf("err = %v, want ErrUnknownIdentity", err)
	}
}

func TestResolve_MissingFileMeansEveryoneUnknown(t *testing.T) {
	r := NewResolver(filepath.Join(t.TempDir(), "users.yaml"))
	_, err := r.Resolve("local:anyone")
	if !errors.Is(err, ErrUnknownIdentity) {
		t.Fatalf("err = %v, want ErrUnknownIdentity", err)
	}
}

// The table is re-read on every call: an identity added after the Resolver
// was constructed must resolve without any reload step.
func TestResolve_RereadsFileEveryCall(t *testing.T) {
	path := writeUsers(t, `persons: []`)
	r := NewResolver(path)

	if _, err := r.Resolve("local:davide"); !errors.Is(err, ErrUnknownIdentity) {
		t.Fatalf("pre-add err = %v, want ErrUnknownIdentity", err)
	}
	if err := os.WriteFile(path, []byte(sampleUsers), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve("local:davide"); err != nil {
		t.Fatalf("post-add Resolve: %v", err)
	}
}

func TestImplicitAdmin(t *testing.T) {
	p := ImplicitAdmin("local:guest")
	if p.Role != RoleAdmin || !p.Implicit || p.Identity != "local:guest" || p.ID != "local:guest" {
		t.Errorf("got %+v", p)
	}
}

func TestResolve_MalformedYAMLSurfaces(t *testing.T) {
	r := NewResolver(writeUsers(t, "persons: [broken"))
	_, err := r.Resolve("local:davide")
	if err == nil || errors.Is(err, ErrUnknownIdentity) {
		t.Fatalf("err = %v, want a parse error distinct from unknown-identity", err)
	}
}

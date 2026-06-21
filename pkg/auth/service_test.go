package auth

import (
	"errors"
	"testing"
)

const serviceUsers = `services:
  - id: github-app
    role: ci-trigger
    kind: github-app
    secret_sha256: abc123def456
  - id: ci-legacy
    role: ci-trigger
    repo: github.com/redcarbon-dev/legacy
    secret_sha256: deadbeef
`

func TestResolveService_KnownSecret(t *testing.T) {
	r := NewResolver(writeUsers(t, serviceUsers))

	p, err := r.ResolveService("abc123def456")
	if err != nil {
		t.Fatalf("ResolveService: %v", err)
	}
	if p.ID != "github-app" || p.Kind != KindService || p.Role != RoleCITrigger {
		t.Errorf("got %+v, want github-app/service/ci-trigger", p)
	}
	if p.Identity != "service:github-app" {
		t.Errorf("Identity = %q", p.Identity)
	}
}

func TestResolveService_UnknownSecret(t *testing.T) {
	r := NewResolver(writeUsers(t, serviceUsers))
	if _, err := r.ResolveService("nope"); !errors.Is(err, ErrUnknownIdentity) {
		t.Errorf("err = %v, want ErrUnknownIdentity", err)
	}
}

func TestResolveService_EmptyHashNeverMatches(t *testing.T) {
	r := NewResolver(writeUsers(t, serviceUsers))
	// A service entry with no secret must not match an empty query.
	if _, err := r.ResolveService(""); !errors.Is(err, ErrUnknownIdentity) {
		t.Errorf("err = %v, want ErrUnknownIdentity for empty secret", err)
	}
}

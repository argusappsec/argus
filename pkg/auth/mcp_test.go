package auth

import (
	"errors"
	"testing"
)

// TestResolveMCPToken_RoundTripsThroughStore proves the write side (an MCP token
// provisioned by `argus user mcp-token create`, which stores only the hash) is
// readable by the resolver as the owning Person, with the `mcp:<token-hash>`
// identity the audit log attributes against.
func TestResolveMCPToken_RoundTripsThroughStore(t *testing.T) {
	store, path := newStore(t)
	if err := store.AddPerson(Person{ID: "davide", Role: RoleAnalyst}); err != nil {
		t.Fatalf("add person: %v", err)
	}
	const token = "s3cret-bearer-token"
	if err := store.AddMCPToken("davide", "laptop", SHA256Hex(token)); err != nil {
		t.Fatalf("add token: %v", err)
	}

	p, err := NewResolver(path).ResolveMCPToken(token)
	if err != nil {
		t.Fatalf("ResolveMCPToken: %v", err)
	}
	if p.ID != "davide" || p.Role != RoleAnalyst || p.Kind != KindPerson {
		t.Errorf("resolved %+v, want davide/analyst/person", p)
	}
	if want := "mcp:" + SHA256Hex(token); p.Identity != want {
		t.Errorf("Identity = %q, want %q", p.Identity, want)
	}
	if p.Implicit {
		t.Errorf("a users.yaml Principal must not be Implicit")
	}
}

func TestResolveMCPToken_UnknownTokenIsRejected(t *testing.T) {
	store, path := newStore(t)
	if err := store.AddPerson(Person{ID: "davide", Role: RoleAnalyst}); err != nil {
		t.Fatalf("add person: %v", err)
	}
	if err := store.AddMCPToken("davide", "laptop", SHA256Hex("the-real-token")); err != nil {
		t.Fatalf("add token: %v", err)
	}

	_, err := NewResolver(path).ResolveMCPToken("not-the-token")
	if !errors.Is(err, ErrUnknownIdentity) {
		t.Fatalf("err = %v, want ErrUnknownIdentity", err)
	}
}

func TestResolveMCPToken_MissingFileMeansEveryoneUnknown(t *testing.T) {
	store, path := newStore(t)
	_ = store // no writes: the file never gets created

	_, err := NewResolver(path).ResolveMCPToken("anything")
	if !errors.Is(err, ErrUnknownIdentity) {
		t.Fatalf("err = %v, want ErrUnknownIdentity", err)
	}
}

// TestResolveMCPToken_RevokedTokenStopsResolving proves revocation takes effect
// immediately (the resolver re-reads users.yaml on every call).
func TestResolveMCPToken_RevokedTokenStopsResolving(t *testing.T) {
	store, path := newStore(t)
	if err := store.AddPerson(Person{ID: "davide", Role: RoleAnalyst}); err != nil {
		t.Fatalf("add person: %v", err)
	}
	const token = "s3cret-bearer-token"
	if err := store.AddMCPToken("davide", "laptop", SHA256Hex(token)); err != nil {
		t.Fatalf("add token: %v", err)
	}
	r := NewResolver(path)
	if _, err := r.ResolveMCPToken(token); err != nil {
		t.Fatalf("pre-revoke resolve: %v", err)
	}

	if err := store.RemoveMCPToken("davide", "laptop"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := r.ResolveMCPToken(token); !errors.Is(err, ErrUnknownIdentity) {
		t.Fatalf("post-revoke err = %v, want ErrUnknownIdentity", err)
	}
}

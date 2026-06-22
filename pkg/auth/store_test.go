package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.yaml")
	return NewStore(path), path
}

func TestAddPerson_RoundTripsThroughResolver(t *testing.T) {
	store, path := newStore(t)
	if err := store.AddPerson(Person{
		ID:         "davide",
		Email:      "davide@redcarbon.ai",
		Role:       RoleAdmin,
		Identities: []string{"github:davideimola"},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}

	// The write side must be readable by the read side.
	p, err := NewResolver(path).Resolve("github:davideimola")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if p.ID != "davide" || p.Role != RoleAdmin || p.Kind != KindPerson {
		t.Errorf("resolved %+v", p)
	}
}

func TestAddPerson_RejectsDuplicateAndBadRole(t *testing.T) {
	store, _ := newStore(t)
	if err := store.AddPerson(Person{ID: "a", Role: RoleViewer}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := store.AddPerson(Person{ID: "a", Role: RoleViewer}); err == nil {
		t.Error("expected duplicate id to fail")
	}
	if err := store.AddPerson(Person{ID: "b", Role: Role("ci-trigger")}); err == nil {
		t.Error("expected invalid person role to fail")
	}
}

func TestAddIdentity_RejectsCrossPersonDuplicate(t *testing.T) {
	store, _ := newStore(t)
	mustAddPerson(t, store, "a", RoleAnalyst)
	mustAddPerson(t, store, "b", RoleAnalyst)
	if err := store.AddIdentity("a", "slack:U1"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := store.AddIdentity("b", "slack:U1"); err == nil {
		t.Error("expected an identity owned by another person to be rejected")
	}
}

func TestRemovePerson(t *testing.T) {
	store, path := newStore(t)
	mustAddPerson(t, store, "a", RoleViewer)
	if err := store.RemovePerson("a"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := NewResolver(path).Resolve("any"); err == nil {
		t.Error("expected no identities after removal")
	}
	if err := store.RemovePerson("a"); err == nil {
		t.Error("expected removing a missing person to fail")
	}
}

func TestMCPToken_AddAndRevoke(t *testing.T) {
	store, _ := newStore(t)
	mustAddPerson(t, store, "a", RoleAnalyst)
	if err := store.AddMCPToken("a", "laptop", SHA256Hex("secret-token")); err != nil {
		t.Fatalf("add token: %v", err)
	}
	if err := store.AddMCPToken("a", "laptop", SHA256Hex("x")); err == nil {
		t.Error("expected duplicate token name to fail")
	}
	persons, _ := store.Persons()
	if len(persons[0].MCPTokens) != 1 || persons[0].MCPTokens[0].SHA256 != SHA256Hex("secret-token") {
		t.Errorf("token not stored as hash: %+v", persons[0].MCPTokens)
	}
	if err := store.RemoveMCPToken("a", "laptop"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := store.RemoveMCPToken("a", "laptop"); err == nil {
		t.Error("expected revoking a missing token to fail")
	}
}

func TestAddService_GithubAppResolvesBySecretHash(t *testing.T) {
	store, path := newStore(t)
	secret := "webhook-secret"
	if err := store.AddService(Service{
		ID:           "argus-github-app",
		Role:         RoleCITrigger,
		Kind:         "github-app",
		SecretSHA256: SHA256Hex(secret),
	}); err != nil {
		t.Fatalf("add service: %v", err)
	}

	// The channel hashes the wire secret and asks the Resolver — the stored
	// hash must match that path.
	p, err := NewResolver(path).ResolveService(SHA256Hex(secret))
	if err != nil {
		t.Fatalf("resolve service: %v", err)
	}
	if p.ID != "argus-github-app" || p.Kind != KindService || p.Role != RoleCITrigger {
		t.Errorf("resolved %+v", p)
	}
}

func TestAddService_RejectsBadRoleAndDuplicate(t *testing.T) {
	store, _ := newStore(t)
	if err := store.AddService(Service{ID: "s", Role: RoleAdmin}); err == nil {
		t.Error("expected an admin role to be invalid for a service")
	}
	if err := store.AddService(Service{ID: "s", Role: RoleCITrigger, Repo: "github.com/x/y"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := store.AddService(Service{ID: "s", Role: RoleCITrigger}); err == nil {
		t.Error("expected duplicate service id to fail")
	}
}

func TestSaveUsers_AtomicPermissions(t *testing.T) {
	store, path := newStore(t)
	mustAddPerson(t, store, "a", RoleViewer)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("users.yaml perms = %o, want 600", perm)
	}
	// No leftover temp files in the directory.
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("expected only users.yaml, got %d entries", len(entries))
	}
}

func mustAddPerson(t *testing.T, s *Store, id string, role Role) {
	t.Helper()
	if err := s.AddPerson(Person{ID: id, Role: role}); err != nil {
		t.Fatalf("add person %s: %v", id, err)
	}
}

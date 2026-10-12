package daemon

import (
	"context"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/argusappsec/argus/pkg/provider"
	"github.com/argusappsec/argus/pkg/tool"
)

// These tests drive registry assembly — the one place the daemon decides which
// Tools exist — with the binary lookup injected, so what is "installed" is the
// test's choice and never the host's PATH (CI has no scanners). They assert on
// what a registry offers: which Tools resolve by name, and which are exposed.

// installed is a binary lookup that finds exactly the named binaries.
func installed(binaries ...string) func(string) (string, error) {
	return func(name string) (string, error) {
		if slices.Contains(binaries, name) {
			return "/usr/local/bin/" + name, nil
		}
		return "", exec.ErrNotFound
	}
}

func exposedNames(reg *tool.Registry) []string {
	var names []string
	for _, t := range reg.Exposed() {
		names = append(names, t.Name())
	}
	return names
}

// A scanner whose binary is on PATH is offered to the agent loop and, being a
// scanner, admitted onto the MCP surface too.
func TestRegistry_RegistersAndExposesAScannerWhoseBinaryIsInstalled(t *testing.T) {
	dc := testContext(t, nil, 4)
	dc.LookPath = installed("gitleaks")

	reg := dc.NewToolRegistry()

	if _, ok := reg.Get("run_gitleaks"); !ok {
		t.Fatal("run_gitleaks is installed but not registered")
	}
	if !slices.Contains(exposedNames(reg), "run_gitleaks") {
		t.Errorf("run_gitleaks is registered but not exposed; exposed = %v", exposedNames(reg))
	}
}

// A scanner whose binary is missing is not offered at all: the model must never
// be handed a capability the host cannot run, only to fail mid-review.
func TestRegistry_LeavesOutAScannerWhoseBinaryIsMissing(t *testing.T) {
	dc := testContext(t, nil, 4)
	dc.LookPath = installed("gitleaks")

	reg := dc.NewToolRegistry()

	for _, name := range []string{"run_semgrep", "run_osv_scanner"} {
		if _, ok := reg.Get(name); ok {
			t.Errorf("%s is registered although its binary is missing", name)
		}
		if slices.Contains(exposedNames(reg), name) {
			t.Errorf("%s is exposed although its binary is missing", name)
		}
	}
	// The Tools that need no binary are unaffected.
	for _, name := range []string{"read_file", "list_context"} {
		if _, ok := reg.Get(name); !ok {
			t.Errorf("%s needs no binary and must always be registered", name)
		}
	}
}

// recordingProvider ends every turn at once and keeps the first request it was
// sent, which carries the seed prompt.
type recordingProvider struct {
	mu    sync.Mutex
	first *provider.Request
}

func (p *recordingProvider) Generate(_ context.Context, req provider.Request) (provider.Response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.first == nil {
		p.first = &req
	}
	return textOnly("nothing to report"), nil
}

func (p *recordingProvider) seed(t *testing.T) string {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.first == nil {
		t.Fatal("the provider was never called")
	}
	for _, m := range p.first.Messages {
		if m.Role == "user" {
			return m.Content
		}
	}
	t.Fatal("the first request carries no user message")
	return ""
}

// The automatic PR review's seed prompt tells the agent which scanners to
// reach for. It names the ones registered in this Session and only those: a
// scanner the host lacks would be a call that cannot succeed.
func TestPRReviewSeed_NamesOnlyTheScannersRegisteredInTheSession(t *testing.T) {
	prov := &recordingProvider{}
	dc := testContext(t, prov, 4)
	dc.LookPath = installed("gitleaks")
	ctx := context.Background()

	s, _, err := dc.Sessions.GetOrCreate(ctx, "github", "github.com/o/r#1", principal(), SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer dc.Sessions.Release(s)
	_, _, err = s.HandlePRReview(ctx, PRReviewTarget{
		Repo: "github.com/o/r", Number: 1, SHA: "abc123", Path: t.TempDir(),
	}, RunCallbacks{})
	if err != nil {
		t.Fatalf("HandlePRReview: %v", err)
	}

	seed := prov.seed(t)
	if !strings.Contains(seed, "run_gitleaks") {
		t.Errorf("the seed must name the registered scanner run_gitleaks:\n%s", seed)
	}
	for _, absent := range []string{"run_semgrep", "run_osv_scanner"} {
		if strings.Contains(seed, absent) {
			t.Errorf("the seed names %s, which is not registered:\n%s", absent, seed)
		}
	}
}

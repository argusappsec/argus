package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/security"
	"github.com/argusappsec/argus/pkg/tool"
)

// These tests drive the trust filter of registry assembly (ADR 0018, ADR 0027):
// an automatic, Service-triggered review runs over a stranger's code, so its
// Session is offered only the scanners that are safe on untrusted input. A
// review a Person asked for gets every installed scanner.

// toolchainEntry is a catalogued Tool that drives a toolchain over the code
// under review — the shape gosec will have — built for these tests so the rule
// is exercised before any such Tool ships.
func toolchainEntry() security.Entry {
	return security.Entry{
		ID:       "fake-toolchain",
		Tool:     "run_fake_toolchain",
		Binaries: []security.Binary{{Name: "go", InstallHint: "install go"}},
		Trust:    security.TrustToolchain,
		New:      func(security.Deps) tool.Tool { return namedTool("run_fake_toolchain") },
	}
}

// catalogEntry returns the real Catalog entry with the given ID.
func catalogEntry(t *testing.T, id string) security.Entry {
	t.Helper()
	for _, e := range security.Catalog() {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("%s is not catalogued", id)
	return security.Entry{}
}

// withInstalled fixes the daemon's discovery to exactly these entries, as if
// discovery had found them on PATH at startup. It must run before the first
// registry is built: discovery happens once.
func withInstalled(dc *Context, entries ...security.Entry) {
	dc.toolsOnce.Do(func() { dc.tools = security.Discovery{Installed: entries} })
}

func service() auth.Principal {
	return auth.Principal{ID: "github-app", Kind: auth.KindService, Identity: "github-app:installation"}
}

type namedTool string

func (n namedTool) Name() string           { return string(n) }
func (n namedTool) Description() string    { return "test tool" }
func (n namedTool) Schema() map[string]any { return map[string]any{"type": "object"} }
func (n namedTool) Execute(context.Context, map[string]any) (string, error) {
	return "", nil
}

func newSession(t *testing.T, dc *Context, key string, p auth.Principal) *Session {
	t.Helper()
	s, _, err := dc.Sessions.GetOrCreate(context.Background(), "github", key, p, SessionOptions{})
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}
	t.Cleanup(func() { dc.Sessions.Release(s) })
	return s
}

// An automatic review never gets a Tool that drives a toolchain over the code;
// it still gets the scanners that only read it. A review a Person asked for
// gets both.
func TestRegistry_AutomaticReviewGetsOnlyToolsSafeOnUntrustedInput(t *testing.T) {
	dc := testContext(t, nil, 4)
	withInstalled(dc, catalogEntry(t, "gitleaks"), toolchainEntry())

	auto := newSession(t, dc, "github.com/o/r#1", service())
	if _, ok := auto.registry.Get("run_fake_toolchain"); ok {
		t.Error("an automatic review was offered a toolchain-driving Tool")
	}
	if _, ok := auto.registry.Get("run_gitleaks"); !ok {
		t.Error("an automatic review lost run_gitleaks, which is safe on untrusted input")
	}

	requested := newSession(t, dc, "github.com/o/r#2", principal())
	for _, name := range []string{"run_fake_toolchain", "run_gitleaks"} {
		if _, ok := requested.registry.Get(name); !ok {
			t.Errorf("a Person-requested review is missing %s", name)
		}
	}
}

// The MCP surface is never an automatic review: its registry is the full one.
func TestRegistry_TheMCPRegistryKeepsToolchainDrivingTools(t *testing.T) {
	dc := testContext(t, nil, 4)
	withInstalled(dc, toolchainEntry())

	if !slices.Contains(exposedNames(dc.NewToolRegistry()), "run_fake_toolchain") {
		t.Error("the MCP registry must keep a toolchain-driving Tool")
	}
}

// Inside an automatic review, osv-scanner is built in its automatic mode, so it
// does not run Go call analysis over the stranger's packages.
func TestRegistry_AutomaticReviewBuildsOSVScannerWithoutGoCallAnalysis(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    auth.Principal
		want bool
	}{
		{"automatic", service(), true},
		{"requested", principal(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dc := testContext(t, nil, 4)
			fr := &recordingRunner{}
			dc.Commands = fr
			withInstalled(dc, catalogEntry(t, "osv-scanner"))

			s := newSession(t, dc, "github.com/o/r#1", tc.p)
			s.SetToolRoot(t.TempDir())
			osv, ok := s.registry.Get("run_osv_scanner")
			if !ok {
				t.Fatal("run_osv_scanner is not registered")
			}
			_, _ = osv.Execute(context.Background(), map[string]any{})

			if got := slices.Contains(fr.args, "--no-call-analysis=go"); got != tc.want {
				t.Errorf("--no-call-analysis=go present = %v, want %v; args = %v", got, tc.want, fr.args)
			}
		})
	}
}

// recordingRunner keeps the last command's args and runs nothing.
type recordingRunner struct{ args []string }

func (r *recordingRunner) Run(_ context.Context, cmd security.Command) (string, error) {
	r.args = cmd.Args
	return "", errors.New("not run")
}

// The audit log records what an automatic review was denied, so an auditor can
// reconstruct what the review could and could not have done.
func TestAudit_RecordsTheToolsWithheldFromAnAutomaticReview(t *testing.T) {
	dc := testContext(t, nil, 4)
	withInstalled(dc, catalogEntry(t, "gitleaks"), toolchainEntry())

	auto := newSession(t, dc, "github.com/o/r#1", service())
	_ = newSession(t, dc, "github.com/o/r#2", principal())

	events := auditEvents(t, dc, "tools_withheld")
	if len(events) != 1 {
		t.Fatalf("tools_withheld events = %d, want exactly 1 (the automatic review's)", len(events))
	}
	e := events[0]
	if e["session_id"] != auto.ID() {
		t.Errorf("session_id = %v, want the automatic review's %s", e["session_id"], auto.ID())
	}
	tools, _ := e["tools"].([]any)
	if len(tools) != 1 || tools[0] != "fake-toolchain" {
		t.Errorf("tools = %v, want [fake-toolchain]", e["tools"])
	}
}

// An automatic review re-attaching to a live Session a Person opened on the
// same PR would inherit that Session's full registry. It is refused instead;
// the reverse — a Person's turn on the automatic review's Session — keeps the
// restricted registry, which can only take capabilities away.
func TestGetOrCreate_AnAutomaticReviewNeverReusesAPersonsSession(t *testing.T) {
	dc := testContext(t, nil, 4)
	withInstalled(dc, toolchainEntry())
	ctx := context.Background()

	_ = newSession(t, dc, "github.com/o/r#1", principal())
	if _, _, err := dc.Sessions.GetOrCreate(ctx, "github", "github.com/o/r#1", service(), SessionOptions{}); !errors.Is(err, ErrRunInProgress) {
		t.Fatalf("err = %v, want ErrRunInProgress", err)
	}

	auto := newSession(t, dc, "github.com/o/r#2", service())
	s, existing, err := dc.Sessions.GetOrCreate(ctx, "github", "github.com/o/r#2", principal(), SessionOptions{})
	if err != nil || !existing || s != auto {
		t.Fatalf("a Person's turn must re-attach to the automatic review's Session; existing=%v err=%v", existing, err)
	}
	if _, ok := s.registry.Get("run_fake_toolchain"); ok {
		t.Error("re-attaching must not widen the automatic review's registry")
	}
}

// auditEvents returns the data of every audit event of type typ.
func auditEvents(t *testing.T, dc *Context, typ string) []map[string]any {
	t.Helper()
	f, err := os.Open(filepath.Join(dc.Home, "audit.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e struct {
			Type string         `json:"type"`
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		if e.Type == typ {
			out = append(out, e.Data)
		}
	}
	return out
}

// tools.disabled applies to automatic reviews too: a disabled scanner that is
// safe on untrusted input is still left out of an automatic review's registry.
func TestRegistry_AutomaticReviewLeavesOutADisabledScanner(t *testing.T) {
	dc := testContext(t, nil, 4)
	dc.LookPath = installed("gitleaks", "semgrep")
	dc.DisabledTools = []string{"gitleaks"}

	auto := newSession(t, dc, "github.com/o/r#1", service())
	if _, ok := auto.registry.Get("run_gitleaks"); ok {
		t.Error("an automatic review was offered run_gitleaks, which is disabled")
	}
	if _, ok := auto.registry.Get("run_semgrep"); !ok {
		t.Error("an automatic review lost run_semgrep, which is installed and not disabled")
	}
}

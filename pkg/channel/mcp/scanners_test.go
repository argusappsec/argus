package mcp

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/argusappsec/argus/pkg/auth"
)

// The scanners are the capability nobody wires up on their own, and the reason
// a developer installs Argus rather than reaching for the binaries. These tests
// drive the real protocol and assert on what the calling AI receives: that the
// three are on a Provider-less daemon's surface, that a target on the daemon
// host is what they run against, that a target Argus cannot scan is refused by
// naming the problem, and that the scanner's own report comes back.
//
// No test here shells out to a real binary: the daemon Context's command Runner
// is stubbed, which is what moving it onto the Context was for.

// scannerTools is the slice of the deterministic surface this file carries.
var scannerTools = []string{"run_gitleaks", "run_osv_scanner", "run_semgrep"}

func TestToolsList_ToolboxServesTheScanners(t *testing.T) {
	s, _ := toolboxServer(t, auth.RoleAnalyst)
	names := listedTools(t, s)
	for _, want := range scannerTools {
		if !slices.Contains(names, want) {
			t.Errorf("a Toolbox must advertise %q — a scanner needs no Provider; got %v", want, names)
		}
	}
}

func TestToolCall_ScannerRunsAgainstAnAbsolutePathOnTheHost(t *testing.T) {
	// The caller names the directory, because in a Toolbox there is no review to
	// inherit a target from (ADR 0024: client and daemon are the same machine).
	s, _ := toolboxServer(t, auth.RoleAnalyst)
	runner := stubScanners(t, s, `{"results":[{"check_id":"sqli"}]}`)
	target := t.TempDir()

	res := callToolWith(t, s, "run_semgrep", `{"path":`+quote(target)+`}`)
	if res.IsError {
		t.Fatalf("run_semgrep must succeed against a readable directory: %s", toolText(res))
	}
	if !strings.Contains(toolText(res), "sqli") {
		t.Errorf("the scanner's own report must reach the caller: %q", toolText(res))
	}
	if got := runner.args(); !slices.Contains(got, target) {
		t.Errorf("semgrep was run as %v, want the caller's target %q among its arguments", got, target)
	}
}

func TestToolCall_EveryScannerScansTheCallersTarget(t *testing.T) {
	// One target argument, the same on all three: the calling AI learns the
	// convention once and uses whichever scanner the question needs.
	for _, name := range scannerTools {
		t.Run(name, func(t *testing.T) {
			s, _ := toolboxServer(t, auth.RoleAnalyst)
			runner := stubScanners(t, s, `{"findings":"lodash CVE"}`)
			target := t.TempDir()

			res := callToolWith(t, s, name, `{"path":`+quote(target)+`}`)
			if res.IsError {
				t.Fatalf("%s must succeed against a readable directory: %s", name, toolText(res))
			}
			if !strings.Contains(toolText(res), "lodash CVE") {
				t.Errorf("%s returned %q, want the scanner's own report", name, toolText(res))
			}
			if got := runner.args(); !slices.Contains(got, target) {
				t.Errorf("%s was run as %v, want the caller's target %q among its arguments", name, got, target)
			}
		})
	}
}

func TestToolCall_ScannerRejectsATargetThatDoesNotExist(t *testing.T) {
	s, _ := toolboxServer(t, auth.RoleAnalyst)
	runner := stubScanners(t, s, `{}`)
	missing := filepath.Join(t.TempDir(), "no-such-project")

	res := callToolWith(t, s, "run_semgrep", `{"path":`+quote(missing)+`}`)
	if !res.IsError {
		t.Fatalf("a target that does not exist must be refused, got %q", toolText(res))
	}
	if text := toolText(res); !strings.Contains(text, missing) || !strings.Contains(text, "does not exist") {
		t.Errorf("the refusal must name the problem and the path, got %q", text)
	}
	if runner.calls() != 0 {
		t.Error("a refused target must not reach the scanner binary")
	}
}

func TestToolCall_ScannerRejectsARelativeTarget(t *testing.T) {
	// The path is a path on the daemon host, so a client-relative one would
	// resolve against a directory the caller cannot see. Said, not guessed at.
	s, _ := toolboxServer(t, auth.RoleAnalyst)
	runner := stubScanners(t, s, `{}`)

	res := callToolWith(t, s, "run_semgrep", `{"path":"./src"}`)
	if !res.IsError {
		t.Fatalf("a relative target must be refused, got %q", toolText(res))
	}
	if text := toolText(res); !strings.Contains(text, "absolute") {
		t.Errorf("the refusal must say an absolute path is wanted, got %q", text)
	}
	if runner.calls() != 0 {
		t.Error("a refused target must not reach the scanner binary")
	}
}

func TestToolCall_ScannerRejectsATargetItCannotRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything, so there is no unreadable directory to test with")
	}
	s, _ := toolboxServer(t, auth.RoleAnalyst)
	runner := stubScanners(t, s, `{}`)
	target := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(target, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(target, 0o700) })

	res := callToolWith(t, s, "run_semgrep", `{"path":`+quote(target)+`}`)
	if !res.IsError {
		t.Fatalf("an unreadable target must be refused, got %q", toolText(res))
	}
	if text := toolText(res); !strings.Contains(text, "readable") {
		t.Errorf("the refusal must say the target is not readable, got %q", text)
	}
	if runner.calls() != 0 {
		t.Error("a refused target must not reach the scanner binary")
	}
}

func TestToolCall_ScannerWithNoTargetSaysWhatToPass(t *testing.T) {
	// A Toolbox has no review to inherit a target from, so an omitted path is
	// answered with what to pass rather than with an empty scan.
	s, _ := toolboxServer(t, auth.RoleAnalyst)
	stubScanners(t, s, `{}`)

	res := callToolWith(t, s, "run_semgrep", `{}`)
	if !res.IsError {
		t.Fatalf("a scan with no target must be refused, got %q", toolText(res))
	}
	if text := toolText(res); !strings.Contains(text, "path") {
		t.Errorf("the refusal must name the argument to pass, got %q", text)
	}
}

func TestToolCall_ViewerIsRefusedOnTheScanners(t *testing.T) {
	// Deliberately not a viewer read. A scan is a read of Argus's knowledge in
	// neither sense: it runs a binary on the daemon host against any directory
	// the caller names, and gitleaks reports the secrets it finds there. The
	// Channel's policy is fail-closed, and this is a capability it stays closed
	// on until somebody decides otherwise.
	s, _ := toolboxServer(t, auth.RoleViewer)
	runner := stubScanners(t, s, `{}`)

	res := callToolWith(t, s, "run_semgrep", `{"path":`+quote(t.TempDir())+`}`)
	if !res.IsError || !strings.Contains(toolText(res), "permission denied") {
		t.Fatalf("a viewer must be refused on run_semgrep, got %q", toolText(res))
	}
	if runner.calls() != 0 {
		t.Error("a refused caller must not reach the scanner binary")
	}
}

func TestToolCall_ScannerRunIsAuditedAndAttributed(t *testing.T) {
	s, auditPath := toolboxServer(t, auth.RoleAnalyst)
	stubScanners(t, s, `{"results":[]}`)
	callToolWith(t, s, "run_semgrep", `{"path":`+quote(t.TempDir())+`}`)

	e := findEvent(t, auditPath, "mcp_tool_call")
	if e == nil {
		t.Fatal("expected an mcp_tool_call audit event")
	}
	if e.Data["tool"] != "run_semgrep" {
		t.Errorf("audit tool = %v, want run_semgrep", e.Data["tool"])
	}
	if e.Data["principal"] != "davide" {
		t.Errorf("audit principal = %v, want the Person the bearer token resolved to", e.Data["principal"])
	}
}

// stubScanners replaces the daemon's command Runner with one that writes out as
// every scanner's report and never touches a real binary. This is the seam the
// prefactor opened: the Runner is the daemon Context's, so the MCP surface and
// a Session reach the same one and a test can substitute it.
func stubScanners(t *testing.T, s *Server, out string) *fakeRunner {
	t.Helper()
	fr := &fakeRunner{out: out}
	s.dc.Commands = fr
	return fr
}

// fakeRunner stands in for the scanner binaries. gitleaks and osv-scanner read
// their findings back from the report file they asked for, so the fake writes
// there too — otherwise those two would be exercised against an empty report.
type fakeRunner struct {
	out string

	mu       sync.Mutex
	nCalls   int
	lastArgs []string
}

func (f *fakeRunner) Run(_ context.Context, _ string, args ...string) (string, error) {
	f.mu.Lock()
	f.nCalls++
	f.lastArgs = args
	f.mu.Unlock()
	for i, a := range args {
		if (a == "--report-path" || a == "--output") && i+1 < len(args) {
			_ = os.WriteFile(args[i+1], []byte(f.out), 0o600)
		}
	}
	return f.out, nil
}

func (f *fakeRunner) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nCalls
}

func (f *fakeRunner) args() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastArgs
}

// quote renders a path as a JSON string, so a temp directory can be dropped
// into a raw arguments literal.
func quote(s string) string { return strconv.Quote(s) }

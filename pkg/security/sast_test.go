package security_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/security"
	"github.com/argusappsec/argus/pkg/session"
)

func init() {
	// nosem comments and .semgrepignore files are the pull request's; the
	// ruleset is Argus's own. opengrep is a semgrep fork and takes the same
	// switches (checked against the real opengrep 1.30.1).
	for _, engine := range engines {
		f := toolFixture{empty: `{"results":[],"errors":[]}`}
		f.repoConfig.switches = []string{"--disable-nosem", "--x-ignore-semgrepignore-files"}
		f.repoConfig.scratch = []string{"--config"}
		fixture(string(engine), f)
	}
}

func sessionAt(root string) *session.Session {
	s := session.New()
	s.SetRoot(root)
	return s
}

// engines is every binary the SAST Tool can run.
var engines = []security.Engine{security.EngineOpengrep, security.EngineSemgrep}

// The SAST Tool has one stable name whichever engine runs it, so Skills and MCP
// callers name the capability, never the binary.
func TestSAST_HasOneNameWhicheverEngineRuns(t *testing.T) {
	for _, e := range engines {
		s := security.NewSAST(sessionAt("/tmp"), &fakeRunner{}, e)
		if s.Name() != "run_sast" {
			t.Errorf("%s: name = %q, want run_sast", e, s.Name())
		}
		if !strings.Contains(s.Description(), string(e)) {
			t.Errorf("%s: the description must say which engine this host runs: %q", e, s.Description())
		}
	}
}

// The Tool runs the engine it was built over, and its output names that
// engine, so a reviewer can interpret rule ids and coverage.
func TestSAST_RunsItsEngineAndNamesItInTheOutput(t *testing.T) {
	for _, e := range engines {
		t.Run(string(e), func(t *testing.T) {
			fr := &fakeRunner{out: `{"results":[],"errors":[]}`}
			out, err := security.NewSAST(sessionAt(checkout(t)), fr, e).Execute(context.Background(), map[string]any{})
			if err != nil {
				t.Fatalf("execute: %v", err)
			}
			if len(fr.gotArgs) == 0 || fr.gotArgs[0] != string(e) {
				t.Errorf("ran %v, want the %s binary", fr.gotArgs, e)
			}
			var rep struct {
				Scanner string `json:"scanner"`
			}
			if err := json.Unmarshal([]byte(out), &rep); err != nil {
				t.Fatalf("output is not a findings report: %v\n%s", err, out)
			}
			if rep.Scanner != string(e) {
				t.Errorf("scanner = %q, want the engine that ran, %q", rep.Scanner, e)
			}
		})
	}
}

// semgrep sends usage metrics unless told not to. opengrep has no telemetry,
// and no --metrics flag: passing it makes opengrep refuse to start, which the
// real binary (1.30.1) does with "unknown option '--metrics'".
func TestSAST_SwitchesSemgrepMetricsOffAndNeverPassesTheFlagToOpengrep(t *testing.T) {
	fr := &fakeRunner{out: `{"results":[],"errors":[]}`}
	if _, err := security.NewSAST(sessionAt(checkout(t)), fr, security.EngineSemgrep).Execute(context.Background(), map[string]any{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if v, _ := optionValue(fr.gotArgs, "--metrics"); v != "off" {
		t.Errorf("semgrep must run with --metrics off, got %v", fr.gotArgs)
	}

	fr = &fakeRunner{out: `{"results":[],"errors":[]}`}
	if _, err := security.NewSAST(sessionAt(checkout(t)), fr, security.EngineOpengrep).Execute(context.Background(), map[string]any{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if slices.Contains(fr.gotArgs, "--metrics") {
		t.Errorf("opengrep has no --metrics flag and refuses to start with it: %v", fr.gotArgs)
	}
}

func TestSAST_PassesPathAndReturnsOutput(t *testing.T) {
	fr := &fakeRunner{out: `{"results": []}`}
	s := security.NewSAST(sessionAt("/repo"), fr, security.EngineSemgrep)
	out, err := s.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out, "findings") {
		t.Errorf("output = %q", out)
	}
	joined := strings.Join(fr.gotArgs, " ")
	if !strings.Contains(joined, "--json") {
		t.Errorf("expected --json in args: %v", fr.gotArgs)
	}
	if !strings.Contains(joined, "/repo") {
		t.Errorf("expected /repo in args: %v", fr.gotArgs)
	}
}

// With no review to inherit a target from — the Toolbox surface's Session — the
// caller names the directory and that is what gets scanned.
func TestSAST_ScansTheTargetTheCallerNamesWhenNoReviewPinnedOne(t *testing.T) {
	dir := t.TempDir()
	fr := &fakeRunner{out: `{"results": []}`}
	s := security.NewSAST(session.New(), fr, security.EngineOpengrep)
	if _, err := s.Execute(context.Background(), map[string]any{"path": dir}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if joined := strings.Join(fr.gotArgs, " "); !strings.Contains(joined, dir) {
		t.Errorf("expected the caller's target %q in args: %v", dir, fr.gotArgs)
	}
}

// A review pins the checkout, and from then on the scanners stay inside it like
// every other file-scoped Tool. This is what keeps the target argument from
// becoming a way for content inside a repository under review to talk the model
// into scanning the rest of the daemon's disk.
func TestSAST_RefusesATargetOutsideTheReviewCheckout(t *testing.T) {
	fr := &fakeRunner{out: `{"results": []}`}
	s := security.NewSAST(sessionAt(t.TempDir()), fr, security.EngineSemgrep)
	elsewhere := t.TempDir()

	_, err := s.Execute(context.Background(), map[string]any{"path": elsewhere})
	if err == nil {
		t.Fatal("a target outside the checkout under review must be refused")
	}
	if !strings.Contains(err.Error(), "review") {
		t.Errorf("the refusal must say the review is what scopes the scan: %v", err)
	}
	if fr.gotArgs != nil {
		t.Errorf("a refused target must not reach the binary: %v", fr.gotArgs)
	}
}

func TestSAST_AcceptsASubdirectoryOfTheReviewCheckout(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "services", "api")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	fr := &fakeRunner{out: `{"results": []}`}
	s := security.NewSAST(sessionAt(root), fr, security.EngineSemgrep)

	if _, err := s.Execute(context.Background(), map[string]any{"path": sub}); err != nil {
		t.Fatalf("narrowing a review's scan to a subdirectory must be allowed: %v", err)
	}
	if joined := strings.Join(fr.gotArgs, " "); !strings.Contains(joined, sub) {
		t.Errorf("expected the subdirectory %q in args: %v", sub, fr.gotArgs)
	}
}

func TestSAST_ErrorsWhenNoTargetSet(t *testing.T) {
	s := security.NewSAST(session.New(), &fakeRunner{}, security.EngineSemgrep)
	if _, err := s.Execute(context.Background(), map[string]any{}); err == nil {
		t.Error("expected error when session has no root set")
	}
}

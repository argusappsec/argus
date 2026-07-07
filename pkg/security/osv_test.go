package security_test

import (
	"context"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/security"
	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

func TestOSVScanner_ToolMetadata(t *testing.T) {
	o := security.NewOSVScanner(sessionAt("/tmp"), &fakeRunner{})
	if o.Name() != "run_osv_scanner" {
		t.Errorf("name = %q", o.Name())
	}
	if o.Description() == "" {
		t.Error("description empty")
	}
}

func TestOSVScanner_PassesPathAndReturnsOutput(t *testing.T) {
	fr := &fakeRunner{out: `{"results": []}`}
	o := security.NewOSVScanner(sessionAt("/repo"), fr)
	out, err := o.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out, "results") {
		t.Errorf("output = %q", out)
	}
	joined := strings.Join(fr.gotArgs, " ")
	if !strings.Contains(joined, "--format") || !strings.Contains(joined, "json") {
		t.Errorf("expected JSON output flags in args: %v", fr.gotArgs)
	}
	if !strings.Contains(joined, "/repo") {
		t.Errorf("expected /repo in args: %v", fr.gotArgs)
	}
}

func TestOSVScanner_ErrorsWhenNoTargetSet(t *testing.T) {
	o := security.NewOSVScanner(session.New(), &fakeRunner{})
	if _, err := o.Execute(context.Background(), map[string]any{}); err == nil {
		t.Error("expected error when session has no root set")
	}
}

// TestOSVScanner_TolerantOfExit1WhenReportPresent guards a real-world quirk:
// osv-scanner returns a non-zero exit code when it FINDS vulnerabilities
// (the expected outcome from our point of view). The wrapper must treat the
// written report as authoritative even if the binary errored.
func TestOSVScanner_TolerantOfExit1WhenReportPresent(t *testing.T) {
	fr := &fakeRunner{
		out: `{"results":[{"packages":[{"package":{"name":"lodash"}}]}]}`,
		err: errExit1{},
	}
	o := security.NewOSVScanner(sessionAt("/repo"), fr)
	out, err := o.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("execute should not error when a report is present, got: %v", err)
	}
	if !strings.Contains(out, "lodash") {
		t.Errorf("output should be the report content: %q", out)
	}
}

// TestOSVScanner_WritesReportToFileNotStdout: the wrapper must collect the
// report via --output to a real file, never parse the merged stdout/stderr
// stream (osv-scanner logs progress to stderr). Regression guard mirroring
// gitleaks's --report-path requirement.
func TestOSVScanner_WritesReportToFileNotStdout(t *testing.T) {
	fr := &fakeRunner{out: `{"results":[]}`}
	o := security.NewOSVScanner(sessionAt("/repo"), fr)
	if _, err := o.Execute(context.Background(), map[string]any{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	found := false
	for i, a := range fr.gotArgs {
		if a == "--output" && i+1 < len(fr.gotArgs) {
			path := fr.gotArgs[i+1]
			if path == "/dev/stdout" || path == "-" || path == "/dev/stderr" {
				t.Errorf("--output must be a real file, got %q", path)
			}
			found = true
		}
	}
	if !found {
		t.Error("osv-scanner invocation is missing --output")
	}
}

// TestOSVScanner_RealFailureSurfacesError: a run error with no report written
// (binary missing, bad flags) is a genuine failure the wrapper must surface
// rather than swallow.
func TestOSVScanner_RealFailureSurfacesError(t *testing.T) {
	fr := &fakeRunner{
		out:    `osv-scanner: command not found`,
		err:    errExit1{},
		noFile: true,
	}
	o := security.NewOSVScanner(sessionAt("/repo"), fr)
	if _, err := o.Execute(context.Background(), map[string]any{}); err == nil {
		t.Error("expected error when no report was written and the run failed")
	}
}

func TestOSVScanner_RequiresAdvertisesBinary(t *testing.T) {
	o := security.NewOSVScanner(sessionAt("/repo"), &fakeRunner{})
	req, ok := o.(tool.Requirer)
	if !ok {
		t.Fatal("osv-scanner tool must implement tool.Requirer")
	}
	reqs := req.Requires()
	if len(reqs) != 1 || reqs[0].Binary != "osv-scanner" {
		t.Errorf("Requires() = %+v, want one requirement for osv-scanner", reqs)
	}
	if reqs[0].InstallHint == "" {
		t.Error("install hint should not be empty")
	}
}

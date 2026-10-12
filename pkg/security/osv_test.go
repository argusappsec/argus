package security_test

import (
	"context"
	"path/filepath"
	"slices"
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
	if !strings.Contains(out, "findings") {
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
		out: `{"results":[{"source":{"path":"/repo/package-lock.json"},"packages":[{"package":{"name":"lodash","ecosystem":"npm"},"vulnerabilities":[{"id":"GHSA-p6mc-m468-83gw"}],"groups":[{"ids":["GHSA-p6mc-m468-83gw"]}]}]}]}`,
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

// osvFromCatalog builds run_osv_scanner the way the daemon does: from its
// Catalog entry, over the given dependencies.
func osvFromCatalog(t *testing.T, d security.Deps) tool.Tool {
	t.Helper()
	for _, e := range security.Catalog() {
		if e.ID == "osv-scanner" {
			return e.New(d)
		}
	}
	t.Fatal("osv-scanner is not catalogued")
	return nil
}

// With go on PATH, osv-scanner's Go call analysis loads the reviewed packages
// through the Go toolchain. On an automatic review the code is a stranger's, so
// call analysis is switched off; a review a Person asked for keeps it, because
// its reachability filtering is worth having when the code is trusted.
func TestOSVScanner_DisablesGoCallAnalysisOnAutomaticReviewsOnly(t *testing.T) {
	for _, tc := range []struct {
		name      string
		automatic bool
		want      bool
	}{
		{"automatic review", true, true},
		{"requested review", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fr := &fakeRunner{out: `{"results":[]}`}
			o := osvFromCatalog(t, security.Deps{Session: sessionAt("/repo"), Commands: fr, Automatic: tc.automatic})
			if _, err := o.Execute(context.Background(), map[string]any{}); err != nil {
				t.Fatalf("execute: %v", err)
			}
			got := slices.Contains(fr.gotArgs, "--no-call-analysis=go")
			if got != tc.want {
				t.Errorf("--no-call-analysis=go present = %v, want %v; args = %v", got, tc.want, fr.gotArgs)
			}
		})
	}
}

// Go call analysis drives the go command over the reviewed packages, exactly
// as gosec and govulncheck do, so where it runs (a review a Person asked for)
// it runs in the same hardened Go profile: whatever the daemon's own Go
// settings say, no toolchain download, no go.mod rewrite, no go.work, no cgo,
// the proxy only, no gopackagesdriver, and caches in the scratch directory.
func TestOSVScanner_RunsGoCallAnalysisInTheHardenedGoEnvironment(t *testing.T) {
	for k, v := range map[string]string{
		"GOTOOLCHAIN":      "auto",
		"GOFLAGS":          "-mod=mod",
		"GOWORK":           "/elsewhere/go.work",
		"CGO_ENABLED":      "1",
		"GOPROXY":          "https://proxy.golang.org,direct",
		"GOPACKAGESDRIVER": "/usr/local/bin/driver",
	} {
		t.Setenv(k, v)
	}
	fr := &fakeRunner{out: `{"results":[]}`}
	o := osvFromCatalog(t, security.Deps{Session: sessionAt(checkout(t)), Commands: fr})
	if _, err := o.Execute(context.Background(), map[string]any{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if slices.Contains(fr.gotArgs, "--no-call-analysis=go") {
		t.Fatalf("a requested review keeps call analysis; args = %v", fr.gotArgs)
	}
	home := filepath.Join(fr.gotCmd.Dir, "home")
	got := envMap(fr.gotCmd.Env)
	for k, v := range map[string]string{
		"GOTOOLCHAIN":      "local",
		"GOFLAGS":          "-mod=readonly",
		"GOWORK":           "off",
		"CGO_ENABLED":      "0",
		"GOPROXY":          "https://proxy.golang.org",
		"GOSUMDB":          "sum.golang.org",
		"GOENV":            "off",
		"GOPACKAGESDRIVER": "off",
		"GOPATH":           filepath.Join(home, "go"),
		"GOCACHE":          filepath.Join(home, ".cache", "go-build"),
	} {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

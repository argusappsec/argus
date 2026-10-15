package security_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/security"
)

func init() {
	// govulncheck has no config file, ignore file or in-code suppression to
	// switch off: it obeys nothing in the checkout.
	fixture("govulncheck", toolFixture{empty: `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.8.0","db":"https://vuln.go.dev","go_version":"go1.26.0","scan_level":"symbol","scan_mode":"source"}}
{"progress":{"message":"No vulnerabilities found."}}`})
}

// govulncheck reports the known vulnerabilities in a Go module's dependencies
// that its code can reach. It loads the reviewed packages through the go
// command, exactly as gosec does, so it needs go as well as govulncheck, it is
// withheld from automatic reviews, and the official image does not ship it.
func TestCatalog_GovulncheckIsGoSCAThatDrivesTheToolchain(t *testing.T) {
	i := slices.IndexFunc(security.Catalog(), func(e security.Entry) bool { return e.ID == "govulncheck" })
	if i < 0 {
		t.Fatal("govulncheck is not catalogued")
	}
	e := security.Catalog()[i]
	if e.Tool != "run_govulncheck" {
		t.Errorf("Tool = %q, want run_govulncheck", e.Tool)
	}
	if !slices.Equal(e.Finds, []security.Find{security.FindSCA}) || !slices.Equal(e.Reads, []security.Read{security.ReadGo}) {
		t.Errorf("govulncheck must be tagged sca and go; finds=%v reads=%v", e.Finds, e.Reads)
	}
	var bins []string
	for _, b := range e.Binaries {
		bins = append(bins, b.Name)
	}
	slices.Sort(bins)
	if !slices.Equal(bins, []string{"go", "govulncheck"}) {
		t.Errorf("Binaries = %v, want go and govulncheck", bins)
	}
	if e.Trust != security.TrustToolchain {
		t.Errorf("Trust = %q, want %q", e.Trust, security.TrustToolchain)
	}
	if e.Manifest {
		t.Error("govulncheck must not be in the Manifest: the official image ships no Go toolchain")
	}
	if e.License != "BSD-3-Clause" {
		t.Errorf("License = %q, want BSD-3-Clause", e.License)
	}
}

// govulncheck is registered only when both of its binaries resolve: in source
// mode it cannot load a package without go, and go alone is not a scanner.
func TestDiscover_GovulncheckNeedsBothGoAndGovulncheck(t *testing.T) {
	for _, tc := range []struct {
		name string
		bins []string
		want bool
	}{
		{"neither", nil, false},
		{"go only", []string{"go"}, false},
		{"govulncheck only", []string{"govulncheck"}, false},
		{"both", []string{"go", "govulncheck"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := security.Discover(func(name string) (string, error) {
				if slices.Contains(tc.bins, name) {
					return "/usr/local/bin/" + name, nil
				}
				return "", exec.ErrNotFound
			})
			if got := slices.Contains(entryIDs(d.Installed), "govulncheck"); got != tc.want {
				t.Errorf("govulncheck installed = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestGovulncheck_RunsInTheHardenedGoEnvironment: govulncheck loads the
// reviewed packages through the go command, with whatever environment it was
// given (it hands its own to go/packages). On the go command's defaults that
// means downloading a newer toolchain when go.mod asks for one, rewriting
// go.mod, honouring a go.work above the tree, compiling C through cgo,
// fetching modules from wherever go.mod points and running a gopackagesdriver
// found on PATH. Its environment is exactly the hardened Go profile over the
// scratch directory, the same as gosec's, with nothing else inherited.
func TestGovulncheck_RunsInTheHardenedGoEnvironment(t *testing.T) {
	for k, v := range map[string]string{
		"GOTOOLCHAIN":       "auto",
		"GOFLAGS":           "-mod=mod",
		"GOWORK":            "/elsewhere/go.work",
		"CGO_ENABLED":       "1",
		"GOPROXY":           "https://proxy.golang.org,direct",
		"GONOSUMDB":         "*",
		"GOPRIVATE":         "github.com/acme/*",
		"GOPACKAGESDRIVER":  "/usr/local/bin/driver",
		"GITHUB_TOKEN":      "ghp_should-never-reach-govulncheck",
		"ANTHROPIC_API_KEY": "sk-should-never-reach-govulncheck",
	} {
		t.Setenv(k, v)
	}

	fr := &fakeRunner{out: emptyReport("govulncheck")}
	if _, err := security.NewGovulncheck(sessionAt(checkout(t)), fr).Execute(context.Background(), map[string]any{}); err != nil {
		t.Fatalf("execute: %v", err)
	}

	scratch := fr.gotCmd.Dir
	home := filepath.Join(scratch, "home")
	want := map[string]string{
		"PATH":            os.Getenv("PATH"),
		"HOME":            home,
		"TMPDIR":          filepath.Join(scratch, "tmp"),
		"XDG_CACHE_HOME":  filepath.Join(home, ".cache"),
		"XDG_CONFIG_HOME": filepath.Join(home, ".config"),
		"XDG_DATA_HOME":   filepath.Join(home, ".local", "share"),

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
	}
	got := envMap(fr.gotCmd.Env)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	for k, v := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("%s=%s is not part of the hardened Go environment", k, v)
		}
	}
	if len(fr.gotCmd.Env) != len(got) {
		t.Errorf("a variable is set twice, so which value wins is up to the child: %v", fr.gotCmd.Env)
	}
}

// TestGovulncheck_ScansEveryPackageOfTheTargetInSourceMode: govulncheck runs
// from the scratch directory, so it is pointed at the target with -C and told
// to analyse every package under it. Its output is the JSON stream, which
// carries the call traces, and the vulnerability database is named rather
// than left to a default.
func TestGovulncheck_ScansEveryPackageOfTheTargetInSourceMode(t *testing.T) {
	root := checkout(t)
	fr := &fakeRunner{out: emptyReport("govulncheck")}
	if _, err := security.NewGovulncheck(sessionAt(root), fr).Execute(context.Background(), map[string]any{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(fr.gotArgs) == 0 || fr.gotArgs[0] != "govulncheck" {
		t.Fatalf("ran %v, want govulncheck", fr.gotArgs)
	}
	if v, _ := optionValue(fr.gotArgs, "-C"); v != root {
		t.Errorf("-C = %q, want the target %q: %v", v, root, fr.gotArgs)
	}
	if fr.gotArgs[len(fr.gotArgs)-1] != "./..." {
		t.Errorf("the last argument must be the ./... pattern: %v", fr.gotArgs)
	}
	if v, _ := optionValue(fr.gotArgs, "-format"); v != "json" {
		t.Errorf("govulncheck must report JSON, got %v", fr.gotArgs)
	}
	if v, _ := optionValue(fr.gotArgs, "-db"); v != "https://vuln.go.dev" {
		t.Errorf("-db = %q, want the Go vulnerability database", v)
	}
	if v, ok := optionValue(fr.gotArgs, "-mode"); ok && v != "source" {
		t.Errorf("govulncheck must run in source mode, got -mode %s", v)
	}
}

// TestGovulncheck_ReportsCallTracesForTheVulnerabilitiesTheCodeReaches: the
// recorded report is govulncheck v1.8.0 over a module that calls into a
// vulnerable golang.org/x/text (trimmed to the advisories the test names).
// govulncheck streams a module-level, a package-level and any symbol-level
// finding for each advisory; Argus reports each advisory once, at the deepest
// level reached. One the code calls points at the call site in the checkout
// and carries every call trace, from the code's own function down to the
// vulnerable symbol: that trace is why the vulnerability is reachable.
func TestGovulncheck_ReportsCallTracesForTheVulnerabilitiesTheCodeReaches(t *testing.T) {
	rep := scan(t, "govulncheck")
	if rep.Scanner != "govulncheck" {
		t.Errorf("scanner = %q, want govulncheck", rep.Scanner)
	}
	var ids []string
	for _, f := range rep.Findings {
		ids = append(ids, f.RuleID)
	}
	// Called first, then imported, then required; by id within a level.
	if want := []string{"GO-2021-0113", "GO-2022-1059", "GO-2026-4602", "GO-2026-5970"}; !slices.Equal(ids, want) {
		t.Fatalf("findings = %v, want one per advisory: %v", ids, want)
	}

	called := byRule(t, rep, "GO-2021-0113")
	if called.File != "internal/tags/tags.go" || called.Line != 8 {
		t.Errorf("a called vulnerability must point at the call site in the checkout, got %s:%d", called.File, called.Line)
	}
	if called.Title != "Out-of-bounds read in golang.org/x/text/language" {
		t.Errorf("title = %q, want the advisory's summary", called.Title)
	}
	for k, want := range map[string]any{
		"reachability":  "called",
		"module":        "golang.org/x/text",
		"version":       "v0.3.5",
		"fixed_version": "v0.3.7",
	} {
		if called.Details[k] != want {
			t.Errorf("details[%s] = %v, want %v", k, called.Details[k], want)
		}
	}
	if aliases := fmt.Sprint(called.Details["aliases"]); !strings.Contains(aliases, "CVE-2021-38561") {
		t.Errorf("aliases = %v, want the advisory's CVE", aliases)
	}
	want := [][]string{
		{"example.com/vulnfixture/internal/tags.Normalise (internal/tags/tags.go:8)", "golang.org/x/text/language.ParseAcceptLanguage"},
		{"example.com/vulnfixture/internal/tags.One (internal/tags/tags.go:17)", "golang.org/x/text/language.Parse"},
	}
	if got := traces(t, called); !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("call traces = %q, want %q", got, want)
	}

	imported := byRule(t, rep, "GO-2026-4602")
	if imported.Details["reachability"] != "imported" || imported.Details["package"] != "os" || imported.Details["module"] != "stdlib" {
		t.Errorf("a vulnerable package the code imports but does not call is reported as imported: %+v", imported)
	}
	if imported.Details["call_traces"] != nil {
		t.Errorf("an uncalled vulnerability has no call trace: %+v", imported)
	}
	required := byRule(t, rep, "GO-2026-5970")
	if required.Details["reachability"] != "required" || required.File != "go.mod" || required.Line != 0 {
		t.Errorf("a vulnerable module only required is reported against go.mod: %+v", required)
	}
}

// TestGovulncheck_NamesFilesRelativeToTheCheckoutWhenScanningASubdirectory:
// govulncheck names files relative to the module root, which is not the
// directory it was pointed at when the target is a package inside the module.
// Findings still name files relative to the checkout under review.
func TestGovulncheck_NamesFilesRelativeToTheCheckoutWhenScanningASubdirectory(t *testing.T) {
	root, report := recorded(t, "govulncheck")
	out, err := security.NewGovulncheck(sessionAt(root), &fakeRunner{out: report}).
		Execute(context.Background(), map[string]any{"path": filepath.Join(root, "internal")})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	var rep security.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("output is not a findings report: %v\n%s", err, out)
	}
	if f := byRule(t, rep, "GO-2021-0113"); f.File != "internal/tags/tags.go" {
		t.Errorf("file = %q, want internal/tags/tags.go", f.File)
	}
	if f := byRule(t, rep, "GO-2026-5970"); f.File != "go.mod" {
		t.Errorf("file = %q, want the module's go.mod", f.File)
	}
}

// TestGovulncheck_ReportsAFailedScanAsAnError: govulncheck stops with an error
// when it cannot load the code (no go.mod, a go.mod asking for a newer Go than
// the host's, a dependency missing from go.sum). That is no result at all, and
// the model is told why, never handed an empty findings list.
func TestGovulncheck_ReportsAFailedScanAsAnError(t *testing.T) {
	fr := &fakeRunner{
		out: "govulncheck: loading packages: go: go.mod requires go >= 1.99 (running go 1.26.0; GOTOOLCHAIN=local)\n",
		err: errors.New("exit status 1"),
	}
	_, err := security.NewGovulncheck(sessionAt(checkout(t)), fr).Execute(context.Background(), map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "GOTOOLCHAIN=local") {
		t.Errorf("err = %v, want govulncheck's own reason", err)
	}
}

// byRule finds the one finding for an advisory.
func byRule(t *testing.T, rep security.Report, id string) security.Finding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.RuleID == id {
			return f
		}
	}
	t.Fatalf("no %s finding in %+v", id, rep.Findings)
	return security.Finding{}
}

// traces reads a finding's call traces back from the decoded JSON.
func traces(t *testing.T, f security.Finding) [][]string {
	t.Helper()
	raw, ok := f.Details["call_traces"].([]any)
	if !ok {
		t.Fatalf("call_traces = %#v, want a list of traces", f.Details["call_traces"])
	}
	var out [][]string
	for _, tr := range raw {
		var frames []string
		for _, fr := range tr.([]any) {
			frames = append(frames, fr.(string))
		}
		out = append(out, frames)
	}
	return out
}

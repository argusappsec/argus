package security_test

import (
	"context"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/security"
)

// entryIDs returns the IDs of entries, in order.
func entryIDs(entries []security.Entry) []string {
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.ID)
	}
	return ids
}

// The Catalog lists the scanners Argus wraps today, whatever the host has
// installed, in a stable order.
func TestCatalog_ListsEveryScannerInIDOrder(t *testing.T) {
	got := entryIDs(security.Catalog())
	want := []string{"gitleaks", "gosec", "govulncheck", "osv-scanner", "sast", "trivy", "zizmor"}
	if !slices.Equal(got, want) {
		t.Errorf("Catalog IDs = %v, want %v", got, want)
	}
}

// Every Entry carries what the docs, doctor and the startup log render, and
// builds the Tool it names — the registry tells scanners apart by that name.
func TestCatalog_EveryEntryIsCompleteAndBuildsTheToolItNames(t *testing.T) {
	for _, e := range security.Catalog() {
		t.Run(e.ID, func(t *testing.T) {
			for field, v := range map[string]string{
				"Name": e.Name, "Purpose": e.Purpose, "Why": e.Why,
				"DocsURL": e.DocsURL, "InstallURL": e.InstallURL, "License": e.License,
			} {
				if v == "" {
					t.Errorf("%s is empty", field)
				}
			}
			for _, u := range []string{e.DocsURL, e.InstallURL} {
				if !strings.HasPrefix(u, "https://") {
					t.Errorf("link %q must be absolute https", u)
				}
			}
			if len(e.Finds) == 0 || len(e.Reads) == 0 {
				t.Errorf("an Entry is tagged on both axes; finds=%v reads=%v", e.Finds, e.Reads)
			}
			for _, b := range e.Binaries {
				if b.Name == "" || b.InstallHint == "" {
					t.Errorf("binary %+v needs a name and an install hint", b)
				}
			}
			built := e.New(security.Deps{Session: sessionAt("/repo"), Commands: &fakeRunner{}})
			if built.Name() != e.Tool {
				t.Errorf("New builds %q, Entry names %q", built.Name(), e.Tool)
			}
			if want := "/guide/scanners/" + e.ID + "/"; e.URL() != want {
				t.Errorf("URL = %q, want %q", e.URL(), want)
			}
		})
	}
}

// Discovery splits the Catalog by whether every binary of an Entry resolves.
func TestDiscover_SplitsTheCatalogByWhatResolvesOnPath(t *testing.T) {
	lookPath := func(name string) (string, error) {
		if name == "gitleaks" {
			return "/bin/gitleaks", nil
		}
		return "", exec.ErrNotFound
	}

	d := security.Discover(lookPath)

	if got := entryIDs(d.Installed); !slices.Equal(got, []string{"gitleaks"}) {
		t.Errorf("Installed = %v, want [gitleaks]", got)
	}
	if got := entryIDs(d.Missing); !slices.Equal(got, []string{"gosec", "govulncheck", "osv-scanner", "sast", "trivy", "zizmor"}) {
		t.Errorf("Missing = %v, want [gosec govulncheck osv-scanner sast trivy zizmor]", got)
	}
}

// gosec is Go SAST that loads the reviewed packages through the go command, so
// it needs go as well as gosec, it is withheld from automatic reviews, and the
// official image does not ship it: Go organizations are told to add both.
func TestCatalog_GosecIsGoSASTThatDrivesTheToolchain(t *testing.T) {
	i := slices.IndexFunc(security.Catalog(), func(e security.Entry) bool { return e.ID == "gosec" })
	if i < 0 {
		t.Fatal("gosec is not catalogued")
	}
	e := security.Catalog()[i]
	if e.Tool != "run_gosec" {
		t.Errorf("Tool = %q, want run_gosec", e.Tool)
	}
	if !slices.Equal(e.Finds, []security.Find{security.FindSAST}) || !slices.Equal(e.Reads, []security.Read{security.ReadGo}) {
		t.Errorf("gosec must be tagged sast and go; finds=%v reads=%v", e.Finds, e.Reads)
	}
	var bins []string
	for _, b := range e.Binaries {
		bins = append(bins, b.Name)
	}
	slices.Sort(bins)
	if !slices.Equal(bins, []string{"go", "gosec"}) {
		t.Errorf("Binaries = %v, want go and gosec", bins)
	}
	if e.Trust != security.TrustToolchain {
		t.Errorf("Trust = %q, want %q", e.Trust, security.TrustToolchain)
	}
	if e.Manifest {
		t.Error("gosec must not be in the Manifest: the official image ships no Go toolchain")
	}
	if e.License != "Apache-2.0" {
		t.Errorf("License = %q, want Apache-2.0", e.License)
	}
}

// gosec is registered only when both of its binaries resolve: gosec without go
// cannot load a package, and go alone is not a scanner.
func TestDiscover_GosecNeedsBothGoAndGosec(t *testing.T) {
	for _, tc := range []struct {
		name string
		bins []string
		want bool
	}{
		{"neither", nil, false},
		{"go only", []string{"go"}, false},
		{"gosec only", []string{"gosec"}, false},
		{"both", []string{"go", "gosec"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := security.Discover(func(name string) (string, error) {
				if slices.Contains(tc.bins, name) {
					return "/usr/local/bin/" + name, nil
				}
				return "", exec.ErrNotFound
			})
			if got := slices.Contains(entryIDs(d.Installed), "gosec"); got != tc.want {
				t.Errorf("gosec installed = %v, want %v", got, tc.want)
			}
		})
	}
}

// The catalog pages tell an operator whether the official image already ships
// a Tool. The official image has always carried the three scanners Argus has
// always wrapped.
func TestCatalog_TheExistingScannersAreInTheManifest(t *testing.T) {
	for _, id := range []string{"gitleaks", "osv-scanner", "sast"} {
		i := slices.IndexFunc(security.Catalog(), func(e security.Entry) bool { return e.ID == id })
		if i < 0 {
			t.Fatalf("%s is not catalogued", id)
		}
		if !security.Catalog()[i].Manifest {
			t.Errorf("%s: Manifest = false, want true: the official image ships it", id)
		}
	}
}

// The three scanners Argus has always wrapped only read files: none drives a
// toolchain or package manager over the code under review, so all of them stay
// in an automatic review's registry (ADR 0018, ADR 0027).
func TestCatalog_TheExistingScannersAreSafeOnUntrustedInput(t *testing.T) {
	for _, id := range []string{"gitleaks", "osv-scanner", "sast"} {
		i := slices.IndexFunc(security.Catalog(), func(e security.Entry) bool { return e.ID == id })
		if i < 0 {
			t.Fatalf("%s is not catalogued", id)
		}
		if got := security.Catalog()[i].Trust; got != security.TrustSafe {
			t.Errorf("%s trust = %q, want %q", id, got, security.TrustSafe)
		}
	}
}

// sastEntry is the one SAST Entry in the Catalog.
func sastEntry(t *testing.T) security.Entry {
	t.Helper()
	for _, e := range security.Catalog() {
		if e.ID == "sast" {
			return e
		}
	}
	t.Fatal("sast is not catalogued")
	return security.Entry{}
}

// One SAST Entry lists both engines, opengrep first: it is the preferred one
// (ADR 0027). Either is enough to run the Tool.
func TestCatalog_OneSASTEntryListsBothEnginesOpengrepFirst(t *testing.T) {
	e := sastEntry(t)
	if e.Tool != "run_sast" {
		t.Errorf("Tool = %q, want run_sast", e.Tool)
	}
	var names []string
	for _, b := range e.Binaries {
		names = append(names, b.Name)
	}
	if !slices.Equal(names, []string{"opengrep", "semgrep"}) {
		t.Errorf("Binaries = %v, want [opengrep semgrep]", names)
	}
	if !e.Alternatives {
		t.Error("the engines are alternatives: either one must be enough")
	}
}

// Discovery installs the SAST Entry when either engine resolves, and records
// which did, in the Entry's order of preference, so the Tool is built over the
// preferred one.
func TestDiscover_InstallsTheSASTEntryWhenEitherEngineResolves(t *testing.T) {
	cases := []struct {
		name      string
		onPath    []string
		installed bool
		found     []string
	}{
		{"opengrep only", []string{"opengrep"}, true, []string{"opengrep"}},
		{"semgrep only", []string{"semgrep"}, true, []string{"semgrep"}},
		{"both", []string{"semgrep", "opengrep"}, true, []string{"opengrep", "semgrep"}},
		{"neither", nil, false, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := security.Discover(onPath(c.onPath...))
			i := slices.IndexFunc(d.Installed, func(e security.Entry) bool { return e.ID == "sast" })
			if (i >= 0) != c.installed {
				t.Fatalf("sast installed = %v, want %v (installed: %v)", i >= 0, c.installed, entryIDs(d.Installed))
			}
			if i >= 0 && !slices.Equal(d.Installed[i].Found, c.found) {
				t.Errorf("Found = %v, want %v", d.Installed[i].Found, c.found)
			}
		})
	}
}

// The SAST Tool is built over the first engine discovery found: opengrep when
// it is there, semgrep otherwise.
func TestCatalog_TheSASTEntryBuildsOverThePreferredEngineFound(t *testing.T) {
	for _, c := range []struct {
		found []string
		want  string
	}{
		{[]string{"opengrep", "semgrep"}, "opengrep"},
		{[]string{"opengrep"}, "opengrep"},
		{[]string{"semgrep"}, "semgrep"},
	} {
		installed := security.Discover(onPath(c.found...)).Installed
		i := slices.IndexFunc(installed, func(e security.Entry) bool { return e.ID == "sast" })
		if i < 0 {
			t.Fatalf("found %v: sast is not installed", c.found)
		}
		e := installed[i]
		if e.Engine() != c.want {
			t.Errorf("found %v: Engine = %q, want %q", c.found, e.Engine(), c.want)
		}
		fr := &fakeRunner{out: `{"results":[],"errors":[]}`}
		built := e.New(security.Deps{Session: sessionAt(checkout(t)), Commands: fr, Engine: e.Engine()})
		if _, err := built.Execute(context.Background(), map[string]any{}); err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(fr.gotArgs) == 0 || fr.gotArgs[0] != c.want {
			t.Errorf("found %v: ran %v, want %s", c.found, fr.gotArgs, c.want)
		}
	}
}

// An Entry whose binaries are not alternatives still needs every one of them.
func TestEntry_ResolveNeedsEveryBinaryUnlessTheyAreAlternatives(t *testing.T) {
	both := []security.Binary{{Name: "go"}, {Name: "gosec"}}
	required := security.Entry{Binaries: both}
	if found, ok := required.Resolve(onPath("gosec")); ok {
		t.Errorf("installed with only gosec on PATH (found %v); go is required too", found)
	}
	if found, ok := required.Resolve(onPath("go", "gosec")); !ok || !slices.Equal(found, []string{"go", "gosec"}) {
		t.Errorf("Resolve = %v, %v; want [go gosec], true", found, ok)
	}
	alternatives := security.Entry{Binaries: both, Alternatives: true}
	if found, ok := alternatives.Resolve(onPath("gosec")); !ok || !slices.Equal(found, []string{"gosec"}) {
		t.Errorf("Resolve = %v, %v; want [gosec], true", found, ok)
	}
}

// onPath is a binary lookup that finds exactly the named binaries.
func onPath(names ...string) func(string) (string, error) {
	return func(name string) (string, error) {
		if slices.Contains(names, name) {
			return "/bin/" + name, nil
		}
		return "", exec.ErrNotFound
	}
}

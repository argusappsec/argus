package security_test

import (
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
	want := []string{"gitleaks", "gosec", "osv-scanner", "semgrep"}
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
	if got := entryIDs(d.Missing); !slices.Equal(got, []string{"gosec", "osv-scanner", "semgrep"}) {
		t.Errorf("Missing = %v, want [gosec osv-scanner semgrep]", got)
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
	for _, id := range []string{"gitleaks", "osv-scanner", "semgrep"} {
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
	for _, id := range []string{"gitleaks", "osv-scanner", "semgrep"} {
		i := slices.IndexFunc(security.Catalog(), func(e security.Entry) bool { return e.ID == id })
		if i < 0 {
			t.Fatalf("%s is not catalogued", id)
		}
		if got := security.Catalog()[i].Trust; got != security.TrustSafe {
			t.Errorf("%s trust = %q, want %q", id, got, security.TrustSafe)
		}
	}
}

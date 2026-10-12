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
	want := []string{"gitleaks", "osv-scanner", "semgrep"}
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
	if got := entryIDs(d.Missing); !slices.Equal(got, []string{"osv-scanner", "semgrep"}) {
		t.Errorf("Missing = %v, want [osv-scanner semgrep]", got)
	}
}

// The catalog pages tell an operator whether a Tool is safe to point at an
// untrusted pull request and whether the official image already ships it, so
// every Entry declares both. The three scanners Argus has always wrapped only
// read files, and the official image has always carried them.
func TestCatalog_ExistingScannersAreSafeAndInTheManifest(t *testing.T) {
	for _, e := range security.Catalog() {
		if e.Trust != security.TrustSafe {
			t.Errorf("%s: Trust = %q, want %q", e.ID, e.Trust, security.TrustSafe)
		}
		if !e.Manifest {
			t.Errorf("%s: Manifest = false, want true: the official image ships it", e.ID)
		}
	}
}

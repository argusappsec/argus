package catalogdocs_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/argusappsec/argus/internal/catalogdocs"
	"github.com/argusappsec/argus/pkg/security"
)

// committedDir is the committed pages, from this package's directory.
var committedDir = filepath.Join("..", "..", filepath.FromSlash(catalogdocs.Dir))

func renderCatalog(t *testing.T) map[string][]byte {
	t.Helper()
	pages, err := catalogdocs.Render(security.Catalog())
	if err != nil {
		t.Fatalf("Render(Catalog): %v", err)
	}
	return pages
}

// The committed catalog pages are exactly what the Catalog renders to. When
// this fails, a catalog Entry changed without regenerating: run `make docs`
// and commit the result.
func TestCommittedPagesMatchTheCatalog(t *testing.T) {
	drift, err := catalogdocs.Drift(committedDir, renderCatalog(t))
	if err != nil {
		t.Fatalf("Drift: %v", err)
	}
	for _, d := range drift {
		t.Errorf("%s/%s — run `make docs` and commit the result", catalogdocs.Dir, d)
	}
}

// Drift notices every way the committed pages can fall behind the Catalog: an
// Entry whose wording changed, a Tool added without a page, and a page left
// behind by a Tool that was removed.
func TestDrift_ReportsChangedMissingAndStalePages(t *testing.T) {
	dir := t.TempDir()
	before, err := catalogdocs.Render([]security.Entry{entry("alpha"), entry("beta")})
	if err != nil {
		t.Fatal(err)
	}
	if err := catalogdocs.Write(dir, before); err != nil {
		t.Fatal(err)
	}
	if drift, err := catalogdocs.Drift(dir, before); err != nil || drift != nil {
		t.Fatalf("freshly written pages drift: %v, %v", drift, err)
	}

	changed := entry("alpha")
	changed.Why = "A reworded reason."
	after, err := catalogdocs.Render([]security.Entry{changed, entry("gamma")})
	if err != nil {
		t.Fatal(err)
	}
	drift, err := catalogdocs.Drift(dir, after)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(drift, "\n")
	for _, want := range []string{
		"alpha.md: differs from the Catalog",
		"gamma.md: missing",
		"beta.md: not generated from the Catalog",
		"index.md: differs from the Catalog",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("drift lacks %q; got:\n%s", want, got)
		}
	}

	// Regenerating brings the directory back in line, removing the stale page.
	if err := catalogdocs.Write(dir, after); err != nil {
		t.Fatal(err)
	}
	if drift, err := catalogdocs.Drift(dir, after); err != nil || drift != nil {
		t.Errorf("regenerated pages still drift: %v, %v", drift, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "beta.md")); !os.IsNotExist(err) {
		t.Errorf("stale beta.md survived regeneration: %v", err)
	}
}

var (
	mdLink   = regexp.MustCompile(`\]\(([^)]*)\)`)
	orderKey = regexp.MustCompile(`(?m)^sidebar:\n  order: \d+$`)
)

// The pages follow the user guide's rules: every page has a title, a
// description and a sidebar order; every link is either an external https URL
// or a site-absolute /guide/…/ path, so none leaves the guide's folder; and
// nothing points at the source tree or the design records.
func TestRender_CatalogPagesFollowTheGuideConventions(t *testing.T) {
	for name, content := range renderCatalog(t) {
		page := string(content)
		t.Run(name, func(t *testing.T) {
			front, _, ok := strings.Cut(strings.TrimPrefix(page, "---\n"), "\n---\n")
			if !strings.HasPrefix(page, "---\n") || !ok {
				t.Fatalf("no front matter:\n%s", page)
			}
			for _, key := range []string{"\ntitle: ", "\ndescription: "} {
				if !strings.Contains("\n"+front, key) {
					t.Errorf("front matter lacks %q:\n%s", strings.TrimSpace(key), front)
				}
			}
			if !orderKey.MatchString(front) {
				t.Errorf("front matter lacks sidebar.order:\n%s", front)
			}
			for _, m := range mdLink.FindAllStringSubmatch(page, -1) {
				target := m[1]
				path, _, _ := strings.Cut(target, "#") // a section anchor follows the page path
				internal := strings.HasPrefix(path, "/guide/") && strings.HasSuffix(path, "/")
				if !internal && !strings.HasPrefix(target, "https://") {
					t.Errorf("link %q is neither https nor an absolute /guide/…/ path", target)
				}
			}
			for _, banned := range []string{"docs/adr", "ADR ", "CONTEXT.md", "pkg/", "github.com/argusappsec"} {
				if strings.Contains(page, banned) {
					t.Errorf("page mentions %q, which the guide must not reference", banned)
				}
			}
		})
	}
}

// The catalog URL doctor and the startup log print for a Tool is the URL the
// guide serves that Tool's generated page at: docs/guide/<path>.md is served
// at /guide/<path>/.
func TestCatalogURLsResolveToGeneratedPages(t *testing.T) {
	pages := renderCatalog(t)
	section := "/guide/" + strings.TrimPrefix(catalogdocs.Dir, "docs/guide/") + "/"
	if section != security.CatalogPath {
		t.Fatalf("pages are served under %q, catalog URLs point at %q", section, security.CatalogPath)
	}
	for _, e := range security.Catalog() {
		slug := strings.TrimSuffix(strings.TrimPrefix(e.URL(), section), "/")
		if _, ok := pages[slug+".md"]; !ok {
			t.Errorf("%s: URL %s has no generated page %s.md", e.ID, e.URL(), slug)
		}
	}
}

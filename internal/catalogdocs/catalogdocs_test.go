package catalogdocs_test

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/argusappsec/argus/internal/catalogdocs"
	"github.com/argusappsec/argus/pkg/security"
)

// entry is a complete, hand-written catalog Entry, so the rendering tests do
// not move every time the real Catalog gains a Tool.
func entry(id string) security.Entry {
	return security.Entry{
		ID:         id,
		Tool:       "run_" + id,
		Name:       strings.ToUpper(id[:1]) + id[1:],
		Purpose:    "Finds " + id + " problems.",
		Why:        "Because " + id + " problems hurt.",
		Finds:      []security.Find{security.FindSAST},
		Reads:      []security.Read{security.ReadMultiLanguage},
		DocsURL:    "https://example.com/" + id + "/docs",
		InstallURL: "https://example.com/" + id + "/install",
		License:    "MIT",
		Trust:      security.TrustSafe,
		Manifest:   true,
		Binaries:   []security.Binary{{Name: id, InstallHint: "brew install " + id}},
	}
}

func render(t *testing.T, entries ...security.Entry) map[string]string {
	t.Helper()
	pages, err := catalogdocs.Render(entries)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := map[string]string{}
	for name, b := range pages {
		out[name] = string(b)
	}
	return out
}

// The generator writes the catalog index and exactly one page per catalogued
// Tool, named by the Tool's ID — the slug its catalog URL is built from.
func TestRender_WritesAnIndexAndOnePagePerTool(t *testing.T) {
	pages := render(t, entry("alpha"), entry("beta"))

	got := slices.Sorted(maps.Keys(pages))
	want := []string{"alpha.md", "beta.md", "index.md"}
	if !slices.Equal(got, want) {
		t.Errorf("pages = %v, want %v", got, want)
	}
}

// A Tool page answers what an operator needs to decide whether to install the
// Tool: its purpose, why it is useful, its licence, its trust level, whether
// the official image ships it, and where the official docs and install guide
// are.
func TestRender_ToolPageCarriesWhatAnOperatorDecidesOn(t *testing.T) {
	alpha := entry("alpha")
	alpha.License = "Apache-2.0"
	page := render(t, alpha)["alpha.md"]

	for _, want := range []string{
		"title: Alpha\n",
		"description: Finds alpha problems.\n",
		"## Why install it\n\nBecause alpha problems hurt.",
		"| Licence | [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) |",
		"| Trust level | Safe on untrusted input |",
		"| Official image | Included |",
		"| Finds | SAST |",
		"| Argus tool | `run_alpha` |",
		"- `alpha`: `brew install alpha`",
		"[official install guide](https://example.com/alpha/install)",
		"[Official documentation](https://example.com/alpha/docs)",
		":::tip[Safe on untrusted input]",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q:\n%s", want, page)
		}
	}
}

// A toolchain-driving Tool says so prominently, and a Tool outside the
// Manifest tells the operator it is theirs to install.
func TestRender_ToolPageWarnsAboutToolchainsAndToolsOutsideTheImage(t *testing.T) {
	gamma := entry("gamma")
	gamma.Trust = security.TrustToolchain
	gamma.Manifest = false
	page := render(t, gamma)["gamma.md"]

	for _, want := range []string{
		":::caution[Drives a toolchain]",
		"| Trust level | Drives a toolchain |",
		"| Official image | Not included |",
		"The official Argus container image does not ship Gamma.",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q:\n%s", want, page)
		}
	}
}

// A Tool over alternative engines asks for one of them, not all, and says the
// first one listed is preferred.
func TestRender_ToolPageOverAlternativeEnginesAsksForOneOfThem(t *testing.T) {
	sast := entry("sast")
	sast.Binaries = []security.Binary{
		{Name: "opengrep", InstallHint: "install opengrep"},
		{Name: "semgrep", InstallHint: "install semgrep"},
	}
	sast.Alternatives = true
	page := render(t, sast)["sast.md"]

	for _, want := range []string{
		"install one of these binaries on the daemon host",
		"Argus runs the first one listed that it finds",
		"- `opengrep`: `install opengrep`",
		"- `semgrep`: `install semgrep`",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, "every one of these binaries") {
		t.Errorf("the engines are alternatives; the page must not ask for every one:\n%s", page)
	}
}

// The index tabulates every Tool's tags, trust level and Manifest membership,
// and recommends Tools by the stack an operator recognises, leaving out
// stacks nothing in the Catalog reads.
func TestRender_IndexTabulatesToolsAndRecommendsByStack(t *testing.T) {
	gosec := entry("gosec")
	gosec.Name = "gosec"
	gosec.Reads = []security.Read{security.ReadGo}
	gosec.Trust = security.TrustToolchain
	gosec.Manifest = false
	zizmor := entry("zizmor")
	zizmor.Name = "zizmor"
	zizmor.Finds = []security.Find{security.FindCICD}
	zizmor.Reads = []security.Read{security.ReadGitHubActions}
	index := render(t, entry("alpha"), gosec, zizmor)["index.md"]

	for _, want := range []string{
		"title: Scanners\n",
		"- **Every repository:** [Alpha](/guide/scanners/alpha/)\n",
		"- **You write Go:** [gosec](/guide/scanners/gosec/)\n",
		"- **You use GitHub Actions:** [zizmor](/guide/scanners/zizmor/)\n",
		"| [Alpha](/guide/scanners/alpha/) | SAST | Any language | Safe on untrusted input | Included |",
		"| [gosec](/guide/scanners/gosec/) | SAST | Go | Drives a toolchain | Not included |",
		"| [zizmor](/guide/scanners/zizmor/) | CI/CD | GitHub Actions | Safe on untrusted input | Included |",
	} {
		if !strings.Contains(index, want) {
			t.Errorf("index lacks %q:\n%s", want, index)
		}
	}
	if strings.Contains(index, "Terraform") {
		t.Errorf("index recommends for a stack nothing reads:\n%s", index)
	}
}

// A tag or trust level the renderer has no wording for fails the generator,
// rather than leaking a raw identifier into the guide.
func TestRender_RefusesATagOrTrustLevelWithoutWording(t *testing.T) {
	untagged := entry("alpha")
	untagged.Finds = []security.Find{"quantum"}
	if _, err := catalogdocs.Render([]security.Entry{untagged}); err == nil {
		t.Error("Render accepted a find tag with no label")
	}
	untrusted := entry("alpha")
	untrusted.Trust = ""
	if _, err := catalogdocs.Render([]security.Entry{untrusted}); err == nil {
		t.Error("Render accepted an Entry with no trust level")
	}
}

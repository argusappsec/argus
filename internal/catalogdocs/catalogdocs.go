// Package catalogdocs renders the Tool Catalog into the user guide: an index
// of every catalogued scanner with recommendations by stack, and one page per
// Tool at the stable URL doctor and the startup log link to (ADR 0027).
//
// The pages are generated, never hand-edited. Regenerate them with
//
//	make docs
//
// after any change to a catalog Entry; TestCommittedPagesMatchTheCatalog fails
// until you do. The output follows the guide's rules (ADR 0022): front matter
// on every page, site-absolute /guide/… links, and nothing that points at the
// source tree or the ADRs.
package catalogdocs

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/argusappsec/argus/pkg/security"
)

// Dir is where the pages live, relative to the repository root. The guide
// serves docs/guide/<path>.md at /guide/<path>/, so this directory is what
// security.CatalogPath points into.
const Dir = "docs/guide/scanners"

// The scanners section sits after Skills (50) and before the deployment pages
// (59 and up) in the guide's sidebar. Inside it, the index comes first and the
// Tools follow in Catalog order.
const (
	indexOrder     = 55
	firstToolOrder = 56
)

// The hand-written guide page on the official image, and its section on
// building a custom image on top of it. The pages link there wherever an
// operator meets a Tool the image does not ship.
const (
	officialImageURL = "/guide/deployment/official-image/"
	customImageURL   = officialImageURL + "#build-your-own-image"
)

// header is the comment every generated page starts with. Starlight does not
// render it; it is there for whoever opens the file to edit it.
const header = "<!-- Generated from the Tool Catalog. Do not edit by hand: run `make docs`. -->\n\n"

// findLabels and readLabels are how the catalog's tags read on the page. A tag
// added to the vocabulary without a label here fails Render, so it cannot
// reach the guide as a raw identifier.
var findLabels = map[security.Find]string{
	security.FindSAST:        "SAST",
	security.FindSCA:         "Dependencies",
	security.FindSecrets:     "Secrets",
	security.FindIaC:         "IaC misconfiguration",
	security.FindContainer:   "Container images",
	security.FindCICD:        "CI/CD",
	security.FindSupplyChain: "Supply chain",
}

var readLabels = map[security.Read]string{
	security.ReadGo:            "Go",
	security.ReadPython:        "Python",
	security.ReadRuby:          "Ruby",
	security.ReadGitHubActions: "GitHub Actions",
	security.ReadDockerfile:    "Dockerfile",
	security.ReadTerraform:     "Terraform",
	security.ReadKubernetes:    "Kubernetes",
	security.ReadMultiLanguage: "Any language",
}

// stacks are the recommendations on the index, in the order they are listed:
// each names a stack in the reader's words and recommends every Tool that
// reads it. A stack with no catalogued Tool is left out.
var stacks = []struct {
	read  security.Read
	label string
}{
	{security.ReadMultiLanguage, "Every repository"},
	{security.ReadGo, "You write Go"},
	{security.ReadPython, "You write Python"},
	{security.ReadRuby, "You write Ruby"},
	{security.ReadGitHubActions, "You use GitHub Actions"},
	{security.ReadDockerfile, "You build container images"},
	{security.ReadTerraform, "You manage infrastructure with Terraform"},
	{security.ReadKubernetes, "You deploy to Kubernetes"},
}

// trustLabels are the short trust levels of the index table and Tool pages.
var trustLabels = map[security.Trust]string{
	security.TrustSafe:      "Safe on untrusted input",
	security.TrustToolchain: "Drives a toolchain",
}

// Render returns the catalog pages for entries, keyed by file name within Dir:
// index.md and one <ID>.md per Entry. Entries are rendered in the order given;
// pass security.Catalog() for the real pages.
func Render(entries []security.Entry) (map[string][]byte, error) {
	pages := map[string][]byte{}
	for i, e := range entries {
		page, err := toolPage(e, firstToolOrder+i)
		if err != nil {
			return nil, fmt.Errorf("catalogdocs: %s: %w", e.ID, err)
		}
		pages[e.ID+".md"] = page
	}
	index, err := indexPage(entries)
	if err != nil {
		return nil, fmt.Errorf("catalogdocs: index: %w", err)
	}
	pages["index.md"] = index
	return pages, nil
}

func indexPage(entries []security.Entry) ([]byte, error) {
	var b bytes.Buffer
	frontMatter(&b, "Scanners",
		"Every scanner Argus can drive, what each one finds, and which to install for your stack.", indexOrder)

	b.WriteString(`Argus does not scan code by itself: it drives real scanners and reasons over
what they find. These pages list every scanner Argus knows how to drive, what
each one is for, and how to install it.

Argus offers a scanner to reviews only when every binary it needs is on ` + "`PATH`" + `
when the daemon starts. Install the ones that fit your stack on the daemon host,
then restart Argus. The startup log and ` + "`argus doctor`" + ` list each scanner as
installed or not installed, and link a missing one to its page here.

## Recommendations

`)
	for _, s := range stacks {
		var links []string
		for _, e := range entries {
			if slices.Contains(e.Reads, s.read) {
				links = append(links, link(e))
			}
		}
		if len(links) > 0 {
			fmt.Fprintf(&b, "- **%s:** %s\n", s.label, strings.Join(links, ", "))
		}
	}

	b.WriteString(`
## All scanners

| Scanner | Finds | Reads | Trust level | Official image |
| --- | --- | --- | --- | --- |
`)
	for _, e := range entries {
		finds, reads, err := tags(e)
		if err != nil {
			return nil, err
		}
		trust, err := trustLabel(e)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.ID, err)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
			link(e), cell(finds), cell(reads), trust, imageLabel(e))
	}

	b.WriteString(`
## Trust levels

A review can be about code nobody has vetted yet: a pull request from outside
your organization, opened on purpose to attack whatever reviews it. Every
scanner declares how safe it is to run over that code.

- **Safe on untrusted input:** the scanner only reads files. Every review can
  run it.
- **Drives a toolchain:** the scanner runs a toolchain or package manager over
  the code under review, which loads or builds that code. Automatic reviews
  never run it; reviews you ask for, and calls over MCP, do.

Whatever its trust level, Argus runs every scanner outside the checkout, with a
minimal environment, and ignores any configuration or suppression file the
repository carries. A finding the code marks as suppressed is still reported,
marked as such: a pull request cannot silence its own findings unseen.

## Official image

Scanners marked **Included** ship in the official Argus container image, which
guarantees they are installed. Any other scanner is yours to add: install it on
the daemon host, or [build your own image](` + customImageURL + `) on top of
the [official one](` + officialImageURL + `).
`)
	return b.Bytes(), nil
}

func toolPage(e security.Entry, order int) ([]byte, error) {
	finds, reads, err := tags(e)
	if err != nil {
		return nil, err
	}
	trust, err := trustLabel(e)
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	frontMatter(&b, e.Name, e.Purpose, order)

	fmt.Fprintf(&b, "%s\n\n## Why install it\n\n%s\n\n", e.Purpose, e.Why)

	switch e.Trust {
	case security.TrustSafe:
		fmt.Fprintf(&b, ":::tip[Safe on untrusted input]\n%s only reads files, so every review can run it, including automatic reviews of pull requests from outside your organization.\n:::\n\n", e.Name)
	case security.TrustToolchain:
		fmt.Fprintf(&b, ":::caution[Drives a toolchain]\n%s runs a toolchain or package manager over the code under review, which loads or builds that code. Automatic reviews never run it; reviews you ask for, and calls over MCP, do.\n:::\n\n", e.Name)
	}

	b.WriteString("## At a glance\n\n| | |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| Finds | %s |\n", cell(finds))
	fmt.Fprintf(&b, "| Reads | %s |\n", cell(reads))
	fmt.Fprintf(&b, "| Trust level | %s |\n", trust)
	fmt.Fprintf(&b, "| Official image | %s |\n", imageLabel(e))
	fmt.Fprintf(&b, "| Licence | [%s](https://spdx.org/licenses/%s.html) |\n", e.License, e.License)
	fmt.Fprintf(&b, "| Argus tool | `%s` |\n", e.Tool)

	b.WriteString("\n## Install\n\n")
	if e.Manifest {
		fmt.Fprintf(&b, "The official Argus container image already ships %s. Anywhere else, install ", e.Name)
	} else {
		fmt.Fprintf(&b, "The official Argus container image does not ship %s: add it by [building your own image](%s) on top of the official one, or install ", e.Name, customImageURL)
	}
	switch {
	case len(e.Binaries) == 1:
		b.WriteString("this binary on the daemon host:\n\n")
	case e.Alternatives:
		b.WriteString("one of these binaries on the daemon host. Argus runs the first one listed that it finds:\n\n")
	default:
		b.WriteString("every one of these binaries on the daemon host:\n\n")
	}
	for _, bin := range e.Binaries {
		fmt.Fprintf(&b, "- `%s`: `%s`\n", bin.Name, bin.InstallHint)
	}
	fmt.Fprintf(&b, `
For other platforms, follow the [official install guide](%s). Argus looks for scanners once, when the daemon starts: restart it after installing, and `+"`argus doctor`"+` shows %s as installed.

## Learn more

- [Official documentation](%s)
- [Every scanner Argus can drive](%s)
`, e.InstallURL, e.Name, e.DocsURL, security.CatalogPath)
	return b.Bytes(), nil
}

func frontMatter(b *bytes.Buffer, title, description string, order int) {
	fmt.Fprintf(b, "---\ntitle: %s\ndescription: %s\nsidebar:\n  order: %d\n---\n\n%s",
		yamlString(title), yamlString(description), order, header)
}

// yamlString quotes s when YAML could misread it as anything but a plain
// string. It errs on the side of quoting.
func yamlString(s string) string {
	if s == "" || strings.ContainsAny(s, ":#'\"{}[]&*!|>%@`\\") || strings.ContainsAny(s[:1], "-?, ") {
		return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
	}
	return s
}

func link(e security.Entry) string { return fmt.Sprintf("[%s](%s)", e.Name, e.URL()) }

func tags(e security.Entry) (finds, reads []string, err error) {
	for _, f := range e.Finds {
		l, ok := findLabels[f]
		if !ok {
			return nil, nil, fmt.Errorf("no label for find tag %q", f)
		}
		finds = append(finds, l)
	}
	for _, r := range e.Reads {
		l, ok := readLabels[r]
		if !ok {
			return nil, nil, fmt.Errorf("no label for read tag %q", r)
		}
		reads = append(reads, l)
	}
	return finds, reads, nil
}

func trustLabel(e security.Entry) (string, error) {
	l, ok := trustLabels[e.Trust]
	if !ok {
		return "", fmt.Errorf("unknown trust level %q", e.Trust)
	}
	return l, nil
}

func imageLabel(e security.Entry) string {
	if e.Manifest {
		return "Included"
	}
	return "Not included"
}

// cell joins values for a Markdown table cell.
func cell(values []string) string {
	return strings.ReplaceAll(strings.Join(values, ", "), "|", `\|`)
}

// Write makes dir hold exactly pages: it writes every page and removes any
// other Markdown file, so a Tool dropped from the Catalog loses its page.
func Write(dir string, pages map[string][]byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	stale, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		return err
	}
	for _, path := range stale {
		if _, keep := pages[filepath.Base(path)]; !keep {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
	}
	for name, content := range pages {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// Drift compares dir with pages and describes every difference: a page that
// is missing, a page whose content differs, and a Markdown file no Tool
// generates. It returns nil when dir holds exactly pages.
func Drift(dir string, pages map[string][]byte) ([]string, error) {
	var drift []string
	existing, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		return nil, err
	}
	for _, path := range existing {
		if _, ok := pages[filepath.Base(path)]; !ok {
			drift = append(drift, filepath.Base(path)+": not generated from the Catalog")
		}
	}
	for _, name := range slices.Sorted(maps.Keys(pages)) {
		got, err := os.ReadFile(filepath.Join(dir, name))
		switch {
		case os.IsNotExist(err):
			drift = append(drift, name+": missing")
		case err != nil:
			return nil, err
		case !bytes.Equal(got, pages[name]):
			drift = append(drift, name+": differs from the Catalog")
		}
	}
	return drift, nil
}

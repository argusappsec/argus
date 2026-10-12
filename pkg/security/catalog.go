package security

import (
	"fmt"
	"slices"
	"strings"

	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

// The Catalog is every scanner Tool Argus knows how to wrap, with what an
// operator needs to decide whether to install it (ADR 0027). It is static and
// always complete: being catalogued is not being usable. A catalogued Tool is
// *registered* only when every binary it requires resolves on PATH at daemon
// start, and *exposed* according to its admission (ADR 0023).
//
// Each Tool declares its own Entry next to its implementation and adds it with
// catalogue from an init function, so adding a scanner means adding a file —
// registration, doctor and the generated docs all follow from the Entry — and
// never editing a shared list.

// Find is a tag on the "what it finds" axis.
type Find string

// The controlled vocabulary of the "what it finds" axis.
const (
	FindSAST        Find = "sast"
	FindSCA         Find = "sca"
	FindSecrets     Find = "secrets"
	FindIaC         Find = "iac"
	FindContainer   Find = "container"
	FindCICD        Find = "ci-cd"
	FindSupplyChain Find = "supply-chain"
)

// Read is a tag on the "what it reads" axis.
type Read string

// The controlled vocabulary of the "what it reads" axis.
const (
	ReadGo            Read = "go"
	ReadPython        Read = "python"
	ReadRuby          Read = "ruby"
	ReadGitHubActions Read = "github-actions"
	ReadDockerfile    Read = "dockerfile"
	ReadTerraform     Read = "terraform"
	ReadKubernetes    Read = "kubernetes"
	ReadMultiLanguage Read = "multi-language"
)

// Trust is what a catalogued Tool does with the code under review, which
// decides whether an automatic review may run it (ADR 0018, ADR 0027). An
// automatic review is started by a Service over a stranger's pull request, so
// its code is hostile.
type Trust string

const (
	// TrustSafe is a Tool that only reads the files under review. Hostile input
	// can make it report nonsense, but never make it run that input.
	TrustSafe Trust = "safe"

	// TrustToolchain is a Tool that drives a toolchain or package manager over
	// the code under review (loading, building or resolving its packages), so
	// hostile input can reach code execution. Automatic reviews never get it.
	TrustToolchain Trust = "toolchain-driving"
)

// Binary is one executable a catalogued Tool requires on PATH.
type Binary struct {
	Name        string // command name as it appears on PATH (e.g. "gitleaks")
	InstallHint string // a terminal one-liner (e.g. "brew install gitleaks")
}

// Deps is what a catalogued Tool is built from. It is a struct rather than a
// parameter list so a later dependency (the kind of review, the engine found
// at discovery) is one new field, not an edit to every constructor.
type Deps struct {
	Session  *session.Session // the tool state the Tool resolves its target against
	Commands Runner           // what the Tool shells out through

	// Automatic is set when the Tool is built for an automatic,
	// Service-triggered review. The code is untrusted, so a TrustSafe Tool
	// with a mode that drives a toolchain (osv-scanner's Go call analysis)
	// switches that mode off.
	Automatic bool
}

// Entry is one catalogued Tool.
type Entry struct {
	// ID is the stable identifier: the docs slug, and the name an operator
	// writes in argus.yaml. It never changes once published.
	ID string

	// Tool is the name of the Tool New builds — what the model and MCP callers
	// see — so callers can tell a scanner apart in a registry without building
	// one.
	Tool string

	Name    string // display name
	Purpose string // one line: what it finds
	Why     string // one paragraph: why an operator would install it

	Finds []Find
	Reads []Read

	DocsURL    string // the tool's official documentation (absolute)
	InstallURL string // the tool's official install guide (absolute)
	License    string // SPDX identifier

	// Binaries are every executable the Tool needs. All of them must resolve
	// on PATH for the Tool to be registered. They are also doctor's single
	// source of truth for which scanner binaries to check.
	Binaries []Binary

	// Trust says whether the Tool is safe on untrusted input. Automatic reviews
	// register only TrustSafe Tools. It is required: every Tool has to decide.
	Trust Trust

	// New builds the Tool over its dependencies.
	New func(Deps) tool.Tool
}

// CatalogPath is where the user guide publishes the catalog: one page per
// Tool under it, at a URL that is stable because it is the Entry's ID. The
// guide's links are site-absolute, so this is too.
const CatalogPath = "/guide/scanners/"

// URL is the Tool's catalog page, which doctor and the startup log point an
// operator at to install a missing Tool.
func (e Entry) URL() string { return CatalogPath + e.ID + "/" }

// catalog holds every Entry, added by the Tools' own init functions.
var catalog []Entry

// catalogue adds e to the Catalog. It panics on a malformed or duplicate entry:
// the Catalog is fixed at compile time, so a bad entry is a programming error
// that must fail the test suite, never a running daemon.
func catalogue(e Entry) {
	if e.ID == "" || e.Tool == "" || e.New == nil || len(e.Binaries) == 0 {
		panic(fmt.Sprintf("security: catalogue %q: ID, Tool, New and Binaries are required", e.ID))
	}
	if e.Trust != TrustSafe && e.Trust != TrustToolchain {
		panic(fmt.Sprintf("security: catalogue %q: Trust must be TrustSafe or TrustToolchain", e.ID))
	}
	for _, c := range catalog {
		if c.ID == e.ID || c.Tool == e.Tool {
			panic(fmt.Sprintf("security: catalogue %q: duplicate ID or Tool name", e.ID))
		}
	}
	catalog = append(catalog, e)
}

// Catalog returns every catalogued Tool, ordered by ID. The order is stable so
// everything rendered from it — doctor rows, the startup log, generated docs —
// is too.
func Catalog() []Entry {
	out := slices.Clone(catalog)
	slices.SortFunc(out, func(a, b Entry) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// Discovery is the Catalog split by what the host can run: the result of
// looking every catalogued Tool's binaries up on PATH, once.
type Discovery struct {
	Installed []Entry // every required binary resolved: these get registered
	Missing   []Entry // at least one binary did not resolve
	Disabled  []Entry // switched off by the operator (tools.disabled), installed or not
}

// Disable moves the Tools whose IDs are listed out of Installed and Missing and
// into Disabled: the operator's deny-list (tools.disabled in argus.yaml) wins
// over what the host can run, so a disabled Tool is never registered, and it is
// reported as disabled rather than as missing. Every half keeps the Catalog's
// order. Unknown IDs are ignored here; config validation rejects them earlier.
func (d Discovery) Disable(ids []string) Discovery {
	if len(ids) == 0 {
		return d
	}
	var out Discovery
	for _, e := range d.Installed {
		if slices.Contains(ids, e.ID) {
			out.Disabled = append(out.Disabled, e)
		} else {
			out.Installed = append(out.Installed, e)
		}
	}
	for _, e := range d.Missing {
		if slices.Contains(ids, e.ID) {
			out.Disabled = append(out.Disabled, e)
		} else {
			out.Missing = append(out.Missing, e)
		}
	}
	out.Disabled = append(out.Disabled, d.Disabled...)
	slices.SortFunc(out.Disabled, func(a, b Entry) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// Discover looks every catalogued Tool's binaries up with lookPath (exec.LookPath
// in production, a fake under test) and splits the Catalog accordingly. Both
// halves keep the Catalog's order.
func Discover(lookPath func(string) (string, error)) Discovery {
	var d Discovery
	for _, e := range Catalog() {
		if e.resolves(lookPath) {
			d.Installed = append(d.Installed, e)
		} else {
			d.Missing = append(d.Missing, e)
		}
	}
	return d
}

func (e Entry) resolves(lookPath func(string) (string, error)) bool {
	for _, b := range e.Binaries {
		if _, err := lookPath(b.Name); err != nil {
			return false
		}
	}
	return true
}

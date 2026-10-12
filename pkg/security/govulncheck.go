package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

// govulnDB is the vulnerability database govulncheck queries: the Go team's.
// It is named on every run rather than left to govulncheck's default, so the
// source of the advisories is Argus's choice, not something a flag default or
// a future environment variable can move.
const govulnDB = "https://vuln.go.dev"

// NewGovulncheck returns a `run_govulncheck` tool that runs govulncheck in
// source mode over the Go module the Session's current target belongs to.
func NewGovulncheck(s *session.Session, r Runner) tool.Tool {
	return &govulncheck{sess: s, runner: r}
}

type govulncheck struct {
	sess   *session.Session
	runner Runner
}

func (g *govulncheck) Name() string { return "run_govulncheck" }

func (g *govulncheck) Description() string {
	return "Run govulncheck, the Go team's vulnerability scanner, over the Go module a directory on the machine " +
		"Argus runs on belongs to (the directory must contain a go.mod or sit under one). Returns one finding " +
		"per known vulnerability (rule_id is the Go advisory id, e.g. GO-2021-0113) with its reachability: " +
		"\"called\" means the code calls a vulnerable function, and call_traces shows each path from the " +
		"code's own function down to it; \"imported\" and \"required\" mean the vulnerable package or module " +
		"is in the build but no vulnerable function is called, so prioritise \"called\". Findings in module " +
		"\"stdlib\" are about the Go toolchain installed next to Argus, which may not be the one the project " +
		"builds with. Overlaps with run_osv_scanner's Go results: govulncheck adds the call traces."
}

func (g *govulncheck) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": targetSchemaProperty(),
		},
	}
}

func init() {
	catalogue(Entry{
		ID:      "govulncheck",
		Tool:    "run_govulncheck",
		Name:    "govulncheck",
		Purpose: "Known vulnerabilities in a Go module's dependencies, with the call path that reaches them.",
		Why: "govulncheck checks a Go module against the Go vulnerability database and then follows " +
			"the code's call graph, so it can tell a vulnerable dependency the code actually calls from " +
			"one that only sits in go.mod, and it shows the call path from your function down to the " +
			"vulnerable one. It overlaps with osv-scanner: when go is installed, osv-scanner runs the " +
			"same call analysis (it is built on govulncheck's library) to tell reachable Go " +
			"vulnerabilities from unreachable ones, in reviews you ask for. What govulncheck adds is " +
			"the call trace, which explains why a vulnerability is reachable and is what a reviewer " +
			"needs to judge it. Install it if you write Go and want that explanation; osv-scanner's " +
			"verdict alone may be enough otherwise.",
		Finds:      []Find{FindSCA},
		Reads:      []Read{ReadGo},
		DocsURL:    "https://go.dev/doc/tutorial/govulncheck",
		InstallURL: "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck",
		License:    "BSD-3-Clause",
		// The official image ships no Go toolchain, and source mode cannot
		// run without one (ADR 0027): Go organizations add both themselves.
		Manifest: false,
		Binaries: []Binary{
			goBinary,
			{Name: "govulncheck", InstallHint: "go install golang.org/x/vuln/cmd/govulncheck@latest"},
		},
		// govulncheck loads and type-checks the reviewed packages through the
		// go command, which resolves their modules: a toolchain over hostile
		// code, however hardened its environment (see goEnv).
		Trust: TrustToolchain,
		New:   func(d Deps) tool.Tool { return NewGovulncheck(d.Session, d.Commands) },
	})
}

func (g *govulncheck) Execute(ctx context.Context, args map[string]any) (string, error) {
	root, err := scanTarget(g.sess, args)
	if err != nil {
		return "", err
	}
	sc, err := newScratch("govulncheck")
	if err != nil {
		return "", err
	}
	defer sc.remove()

	// The scratch allow-list plus the hardened Go profile, nothing inherited:
	// govulncheck passes its own environment on to the go command it loads
	// the packages through, so this is what the go command sees too.
	env := append(sc.xdg(), sc.goEnv()...)
	out, runErr := g.runner.Run(ctx, sc.command(env, "govulncheck",
		// The JSON stream is the only format that carries every call trace
		// (-show traces is text-only), and with it govulncheck exits 0
		// whatever it finds, so a non-zero exit is a failed scan.
		"-format", "json",
		"-db", govulnDB,
		// Source mode over every package of the target. govulncheck reads no
		// config or ignore file, from the checkout or anywhere else, so there
		// is nothing in the repository to switch off.
		"-C", root,
		"./...",
	))
	// govulncheck writes the stream to stdout and its errors to stderr, which
	// the Runner merges: tell them apart.
	msgs, text := splitGovulncheckStream(out)
	if runErr != nil {
		if text == "" {
			return "", fmt.Errorf("govulncheck failed: %w", runErr)
		}
		return "", fmt.Errorf("govulncheck failed: %s", text)
	}
	return parseGovulncheck(msgs, openCheckout(g.sess, root), root)
}

// govulnMessage is one message of govulncheck's JSON stream, of which Argus
// reads the run's config, the advisories and the findings.
type govulnMessage struct {
	Config *struct {
		ScannerVersion string `json:"scanner_version"`
	} `json:"config"`
	OSV *struct {
		ID      string   `json:"id"`
		Aliases []string `json:"aliases"`
		Summary string   `json:"summary"`
	} `json:"osv"`
	Finding *struct {
		OSV          string        `json:"osv"`
		FixedVersion string        `json:"fixed_version"`
		Trace        []govulnFrame `json:"trace"`
	} `json:"finding"`
}

// govulnFrame is one frame of a finding's trace. Frames run from the
// vulnerable symbol up to the entry point in the scanned code; a module-level
// finding has one frame with only the module, a package-level one adds the
// package. Positions name files relative to their module's root.
type govulnFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Receiver string `json:"receiver"`
	Position *struct {
		Filename string `json:"filename"`
		Line     int    `json:"line"`
	} `json:"position"`
}

// splitGovulncheckStream separates the JSON messages in govulncheck's output
// from any plain text (its error report on stderr) mixed in with them.
func splitGovulncheckStream(out string) (msgs []govulnMessage, text string) {
	var lines []string
	rest := out
	for {
		rest = strings.TrimLeft(rest, " \t\r\n")
		if rest == "" {
			break
		}
		if rest[0] == '{' {
			dec := json.NewDecoder(strings.NewReader(rest))
			var m govulnMessage
			if err := dec.Decode(&m); err == nil {
				msgs = append(msgs, m)
				rest = rest[dec.InputOffset():]
				continue
			}
		}
		line, after, _ := strings.Cut(rest, "\n")
		lines = append(lines, strings.TrimSpace(line))
		rest = after
	}
	return msgs, strings.Join(lines, "\n")
}

// The reachability of an advisory: how deep govulncheck traced it into the
// code. Only a called vulnerability is reachable through the code's own calls.
const (
	govulnCalled   = "called"   // the code calls a vulnerable function
	govulnImported = "imported" // it imports a vulnerable package, calls nothing in it known to be vulnerable
	govulnRequired = "required" // a vulnerable module is in its build, no vulnerable package imported
)

// parseGovulncheck turns the stream into one finding per advisory, at the
// deepest level govulncheck reached: it emits a module-level, a package-level
// and any number of symbol-level findings for the same advisory as it goes.
// govulncheck has no in-code or in-repository suppression, so nothing is ever
// marked suppressed_in_repo.
func parseGovulncheck(msgs []govulnMessage, files *checkoutFiles, target string) (string, error) {
	defer files.close()
	moduleDir := govulnModuleDir(files, target)
	readable := false
	type advisory struct {
		aliases []string
		summary string
	}
	advisories := map[string]advisory{}
	type found struct {
		level  string
		frame  govulnFrame // the vulnerable module (and package) as govulncheck traced it
		fixed  string
		traces []govulnTrace
	}
	byID := map[string]*found{}
	for _, m := range msgs {
		switch {
		case m.Config != nil:
			readable = true
		case m.OSV != nil:
			advisories[m.OSV.ID] = advisory{m.OSV.Aliases, m.OSV.Summary}
		case m.Finding != nil && len(m.Finding.Trace) > 0:
			fd := m.Finding
			level := govulnRequired
			switch {
			case fd.Trace[0].Function != "":
				level = govulnCalled
			case fd.Trace[0].Package != "":
				level = govulnImported
			}
			f := byID[fd.OSV]
			if f == nil {
				f = &found{}
				byID[fd.OSV] = f
			}
			if govulnDepth(level) > govulnDepth(f.level) {
				f.level, f.frame, f.fixed = level, fd.Trace[0], fd.FixedVersion
			}
			if level == govulnCalled {
				f.traces = append(f.traces, newGovulnTrace(fd.Trace, moduleDir))
			}
		}
	}
	if !readable {
		return "", errors.New("govulncheck: unreadable report: no config message")
	}

	// Called first, then imported, then required: the order a reviewer
	// should read them in.
	ids := slices.Collect(maps.Keys(byID))
	slices.SortFunc(ids, func(a, b string) int {
		if da, db := govulnDepth(byID[a].level), govulnDepth(byID[b].level); da != db {
			return db - da
		}
		return strings.Compare(a, b)
	})
	gomod := joinSlash(moduleDir, "go.mod")
	rep := Report{Scanner: "govulncheck"}
	for _, id := range ids {
		f := byID[id]
		details := map[string]any{
			"reachability": f.level,
			"module":       f.frame.Module,
			"version":      f.frame.Version,
		}
		if f.frame.Package != "" {
			details["package"] = f.frame.Package
		}
		if f.fixed != "" {
			details["fixed_version"] = f.fixed
		}
		if a := advisories[id].aliases; len(a) > 0 {
			details["aliases"] = a
		}
		finding := Finding{RuleID: id, Title: advisories[id].summary, File: gomod, Details: details}
		if f.level == govulnCalled {
			slices.SortFunc(f.traces, func(a, b govulnTrace) int { return a.compare(b) })
			f.traces = slices.CompactFunc(f.traces, func(a, b govulnTrace) bool { return slices.Equal(a.frames, b.frames) })
			if f.traces[0].file != "" {
				finding.File, finding.Line = f.traces[0].file, f.traces[0].line
			}
			var traces [][]string
			for _, t := range f.traces {
				traces = append(traces, t.frames)
			}
			details["call_traces"] = traces
		}
		rep.Findings = append(rep.Findings, finding)
	}
	return rep.encode()
}

func govulnDepth(level string) int {
	switch level {
	case govulnCalled:
		return 3
	case govulnImported:
		return 2
	case govulnRequired:
		return 1
	}
	return 0
}

// govulnTrace is one call path to a vulnerable symbol, for the model: frames
// from the scanned code's own function down to the vulnerable symbol, each
// frame in the checkout naming the line of the call, plus where the path
// leaves the checkout (the call site to point the finding at).
type govulnTrace struct {
	frames []string
	file   string
	line   int
}

func (t govulnTrace) compare(o govulnTrace) int {
	if c := strings.Compare(t.file, o.file); c != 0 {
		return c
	}
	if t.line != o.line {
		return t.line - o.line
	}
	return slices.Compare(t.frames, o.frames)
}

// newGovulnTrace reads a symbol-level trace. govulncheck lists it from the
// vulnerable symbol up to the entry point, which is always in the scanned
// module; it is reversed here, so it reads as the code calling down into the
// vulnerability.
func newGovulnTrace(trace []govulnFrame, moduleDir string) govulnTrace {
	scanned := trace[len(trace)-1].Module
	var t govulnTrace
	for i := len(trace) - 1; i >= 0; i-- {
		fr := trace[i]
		name := fr.Package + "." + fr.Function
		if fr.Receiver != "" {
			name = fr.Package + "." + strings.TrimPrefix(fr.Receiver, "*") + "." + fr.Function
		}
		if fr.Module == scanned && fr.Position != nil && fr.Position.Line > 0 {
			file := joinSlash(moduleDir, fr.Position.Filename)
			name += fmt.Sprintf(" (%s:%d)", file, fr.Position.Line)
			// The deepest frame in the scanned code is where it calls out
			// towards the vulnerability.
			t.file, t.line = file, fr.Position.Line
		}
		t.frames = append(t.frames, name)
	}
	return t
}

// govulnModuleDir is the checkout-relative directory of the Go module target
// belongs to: govulncheck names the scanned module's files relative to its
// root, which is the nearest directory at or above the target holding a
// go.mod. When none is found inside the checkout, the target stands in.
func govulnModuleDir(files *checkoutFiles, target string) string {
	start, ok := files.rel(target)
	if !ok {
		return "."
	}
	for dir := start; ; dir = path.Dir(dir) {
		if _, found := files.read(joinSlash(dir, "go.mod")); found {
			return dir
		}
		if dir == "." || dir == "/" {
			return start
		}
	}
}

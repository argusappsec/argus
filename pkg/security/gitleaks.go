package security

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

// gitleaksConfig is the config Argus hands gitleaks: the built-in rules and
// nothing else. Passing any --config at all is what stops gitleaks from
// loading (target)/.gitleaks.toml, whose allowlists a pull request controls.
const gitleaksConfig = "[extend]\nuseDefault = true\n"

// NewGitleaks returns a `run_gitleaks` tool that scans the Session's current
// target directory for committed secrets.
func NewGitleaks(s *session.Session, r Runner) tool.Tool {
	return &gitleaks{scanner{name: gitleaksTool, binary: "gitleaks", sess: s, runner: r}}
}

const gitleaksTool = "run_gitleaks"

type gitleaks struct{ scanner }

func (g *gitleaks) Description() string {
	return "Run gitleaks to detect committed secrets in a directory on the machine Argus runs on. " +
		"Returns its findings (where each secret is, never the secret itself). A finding marked " +
		"suppressed_in_repo carries a gitleaks:allow comment or a .gitleaksignore entry in the code: it is " +
		"still a finding, and the attempt to silence it is itself worth a look."
}

func init() {
	catalogue(Entry{
		ID:      "gitleaks",
		Tool:    gitleaksTool,
		Name:    "Gitleaks",
		Purpose: "Detects secrets committed to a repository: API keys, tokens, passwords and private keys.",
		Why: "A leaked credential is exploitable the moment it is pushed, whatever language the code is " +
			"in. Gitleaks recognises hundreds of credential formats and high-entropy strings, so a " +
			"review catches the secret before it reaches a public branch.",
		Finds:      []Find{FindSecrets},
		Reads:      []Read{ReadMultiLanguage},
		DocsURL:    "https://github.com/gitleaks/gitleaks#readme",
		InstallURL: "https://github.com/gitleaks/gitleaks#installing",
		License:    "MIT",
		Manifest:   true,
		Binaries: []Binary{{
			Name:        "gitleaks",
			InstallHint: "brew install gitleaks",
		}},
		Trust: TrustSafe, // a `dir` scan: reads the files under the target; runs nothing
		New:   func(d Deps) tool.Tool { return NewGitleaks(d.Session, d.Commands) },
	})
}

func (g *gitleaks) Execute(ctx context.Context, args map[string]any) (string, error) {
	return g.scan(ctx, args, g.run, parseGitleaks)
}

func (g *gitleaks) run(ctx context.Context, sc *scratch, root string) ([]byte, error) {
	// gitleaks insists on a file for --report-path. Passing "/dev/stdout"
	// works on some setups but breaks under the bubbletea TUI (where stdout
	// is bound to a pseudoterminal that gitleaks can't open for write).
	// Use a file in the run's scratch directory and read it back — always
	// works, OS-independent.
	config, err := sc.write("gitleaks.toml", []byte(gitleaksConfig))
	if err != nil {
		return nil, fmt.Errorf("gitleaks: %w", err)
	}

	// The repository's say over the scan, and how each is switched off:
	//   - (target)/.gitleaks.toml: an explicit --config wins over it;
	//   - .gitleaksignore in the working directory: the working directory and
	//     --gitleaks-ignore-path are the scratch directory;
	//   - `gitleaks:allow` comments: --ignore-gitleaks-allow.
	// gitleaks also always loads (target)/.gitleaksignore, with no flag to
	// stop it. Its entries are fingerprints, `file:rule:line`, and in a `dir`
	// scan the file is the absolute path gitleaks walked, which includes the
	// checkout's location on the Argus host, so an entry written into the
	// repository cannot name it. In a git-history scan the file would be
	// repository-relative and the entry would match, which is why this is a
	// `dir` scan. Entries are still read below and reported as suppression
	// attempts.
	// gitleaks needs nothing beyond the base allow-list.
	return g.runForReport(ctx, sc, nil, "gitleaks", "dir",
		"--no-banner",
		"--report-format", "json",
		"--report-path", sc.file(reportFile),
		"--config", config,
		"--gitleaks-ignore-path", sc.dir,
		"--ignore-gitleaks-allow",
		root,
	)
}

// gitleaksFinding is the part of a gitleaks JSON finding Argus reads. The
// Secret and Match fields are deliberately absent: they are the secret.
type gitleaksFinding struct {
	RuleID      string   `json:"RuleID"`
	Description string   `json:"Description"`
	File        string   `json:"File"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	Commit      string   `json:"Commit"`
	Tags        []string `json:"Tags"`
}

func parseGitleaks(body []byte, target string, files *checkoutFiles) (Report, error) {
	var out []gitleaksFinding
	if err := json.Unmarshal(body, &out); err != nil {
		return Report{}, fmt.Errorf("gitleaks: unreadable report: %w", err)
	}
	ignored := gitleaksIgnored(files, target)
	rep := Report{Scanner: "gitleaks"}
	for _, r := range out {
		file, inCheckout := files.rel(r.File)
		f := Finding{
			RuleID:  r.RuleID,
			File:    file,
			Line:    r.StartLine,
			EndLine: r.EndLine,
			Title:   r.Description,
		}
		if len(r.Tags) > 0 {
			f.Details = map[string]any{"tags": r.Tags}
		}
		if inCheckout {
			lines := files.lines(file, r.StartLine, max(r.EndLine, r.StartLine))
			switch {
			case anyLine(lines, func(l string) bool { return strings.Contains(l, "gitleaks:allow") }):
				f.suppressed("gitleaks:allow comment in the code")
			case ignored.matches(file, r.RuleID, r.StartLine):
				f.suppressed(".gitleaksignore entry in the repository")
			}
		}
		rep.Findings = append(rep.Findings, f)
	}
	return rep, nil
}

// gitleaksIgnore is the set of fingerprints a repository's .gitleaksignore
// lists, as (file, rule, line) with the file as written.
type gitleaksIgnore []struct {
	file, rule string
	line       int
}

// gitleaksIgnored reads the .gitleaksignore gitleaks itself would load: the
// one at the root of the scanned directory.
func gitleaksIgnored(files *checkoutFiles, target string) gitleaksIgnore {
	dir, ok := files.rel(target)
	if !ok {
		return nil
	}
	body, ok := files.read(joinSlash(dir, ".gitleaksignore"))
	if !ok {
		return nil
	}
	var out gitleaksIgnore
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		entry := strings.TrimSpace(sc.Text())
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		parts := strings.Split(entry, ":")
		if len(parts) == 4 { // commit:file:rule:line
			parts = parts[1:]
		}
		if len(parts) != 3 {
			continue
		}
		line, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		out = append(out, struct {
			file, rule string
			line       int
		}{strings.ReplaceAll(parts[0], `\`, "/"), parts[1], line})
	}
	return out
}

// matches reports whether an entry names this finding. An entry's file may be
// written relative to the repository or to any directory above the file, so
// it matches when it is the finding's path or a trailing part of it.
func (ig gitleaksIgnore) matches(file, rule string, line int) bool {
	for _, e := range ig {
		if e.rule != rule || e.line != line {
			continue
		}
		entry := path.Clean(strings.TrimPrefix(e.file, "/"))
		if file == entry || strings.HasSuffix(file, "/"+entry) || strings.HasSuffix(e.file, "/"+file) {
			return true
		}
	}
	return false
}

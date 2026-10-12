package security_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/security"
)

// recorded loads a scanner fixture: a small checkout under
// testdata/<tool>/checkout and the report the real binary produced over it
// with Argus's flags (testdata/<tool>/report.json). The checkout path was
// replaced by $CHECKOUT when the report was recorded, so it is put back here.
func recorded(t *testing.T, tool string) (root, report string) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("testdata", tool, "checkout"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join("testdata", tool, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	return root, strings.ReplaceAll(string(body), "$CHECKOUT", root)
}

// scan runs one scanner over its recorded fixture and decodes what the model
// is handed.
func scan(t *testing.T, tool string) security.Report {
	t.Helper()
	root, report := recorded(t, tool)
	out, err := scanners[tool](sessionAt(root), &fakeRunner{out: report}).Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	var rep security.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("output is not a findings report: %v\n%s", err, out)
	}
	return rep
}

// at finds the one finding on file:line.
func at(t *testing.T, rep security.Report, file string, line int) security.Finding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.File == file && f.Line == line {
			return f
		}
	}
	t.Fatalf("no finding at %s:%d in %+v", file, line, rep.Findings)
	return security.Finding{}
}

// TestSemgrep_ReportsNosemgrepFindingsAsSuppressedInRepo: semgrep runs with
// nosem disabled, so a `nosemgrep` comment the pull request added no longer
// hides the hit. The finding still says someone tried to silence it, whether
// the comment sits on the line or on the line above.
func TestSemgrep_ReportsNosemgrepFindingsAsSuppressedInRepo(t *testing.T) {
	rep := scan(t, "semgrep")
	if rep.Scanner != "semgrep" {
		t.Errorf("scanner = %q, want semgrep", rep.Scanner)
	}
	if len(rep.Findings) != 3 {
		t.Fatalf("got %d findings, want the 3 in the recorded report: %+v", len(rep.Findings), rep.Findings)
	}
	inline := at(t, rep, "app.py", 6)
	if !inline.SuppressedInRepo || inline.RuleID != "argus.python.subprocess-shell-true" {
		t.Errorf("an inline nosemgrep finding must be reported as suppressed in the repo: %+v", inline)
	}
	if above := at(t, rep, "app.py", 11); !above.SuppressedInRepo {
		t.Errorf("a nosemgrep comment on the line above must mark the finding: %+v", above)
	}
	if plain := at(t, rep, "app.py", 15); plain.SuppressedInRepo || plain.Suppression != "" {
		t.Errorf("a finding nobody tried to silence must not be marked: %+v", plain)
	}
}

// TestSAST_ReportsOpengrepSuppressionCommentsAsSuppressedInRepo: opengrep
// honours `noopengrep` as well as semgrep's `nosemgrep`. It runs with nosem
// disabled too, so neither hides a hit, and both mark it. The report was
// recorded from the real opengrep 1.30.1 with Argus's flags and ruleset.
func TestSAST_ReportsOpengrepSuppressionCommentsAsSuppressedInRepo(t *testing.T) {
	rep := scan(t, "opengrep")
	if rep.Scanner != "opengrep" {
		t.Errorf("scanner = %q, want opengrep", rep.Scanner)
	}
	if len(rep.Findings) != 3 {
		t.Fatalf("got %d findings, want the 3 in the recorded report: %+v", len(rep.Findings), rep.Findings)
	}
	if inline := at(t, rep, "app.py", 6); !inline.SuppressedInRepo || !strings.Contains(inline.Suppression, "noopengrep") {
		t.Errorf("an inline noopengrep finding must be reported as suppressed in the repo: %+v", inline)
	}
	if above := at(t, rep, "app.py", 11); !above.SuppressedInRepo {
		t.Errorf("a nosemgrep comment on the line above must mark the finding: %+v", above)
	}
	if plain := at(t, rep, "app.py", 15); plain.SuppressedInRepo || plain.Suppression != "" {
		t.Errorf("a finding nobody tried to silence must not be marked: %+v", plain)
	}
}

// TestGitleaks_ReportsAllowCommentsAndIgnoreEntriesAsSuppressedInRepo:
// gitleaks runs with its allow comments ignored and with Argus's own config, so
// `gitleaks:allow`, a `.gitleaksignore` entry and a `.gitleaks.toml` allowlist
// committed by the pull request hide nothing. The first two are reported as
// suppression attempts.
func TestGitleaks_ReportsAllowCommentsAndIgnoreEntriesAsSuppressedInRepo(t *testing.T) {
	rep := scan(t, "gitleaks")
	if len(rep.Findings) != 3 {
		t.Fatalf("got %d findings, want the 3 in the recorded report: %+v", len(rep.Findings), rep.Findings)
	}
	if plain := at(t, rep, "settings.py", 3); plain.SuppressedInRepo {
		t.Errorf("a finding nobody tried to silence must not be marked: %+v", plain)
	}
	if allow := at(t, rep, "settings.py", 4); !allow.SuppressedInRepo || !strings.Contains(allow.Suppression, "gitleaks:allow") {
		t.Errorf("a gitleaks:allow finding must be reported as suppressed in the repo: %+v", allow)
	}
	if ignored := at(t, rep, "settings.py", 5); !ignored.SuppressedInRepo || !strings.Contains(ignored.Suppression, ".gitleaksignore") {
		t.Errorf("a .gitleaksignore entry must be reported as a suppression: %+v", ignored)
	}
}

// TestGitleaks_KeepsTheSecretValueOutOfTheReport: the model needs to know a
// secret is there and where, not the secret itself, which would otherwise ride
// along into the transcript and any posted review.
func TestGitleaks_KeepsTheSecretValueOutOfTheReport(t *testing.T) {
	root, report := recorded(t, "gitleaks")
	out, err := security.NewGitleaks(sessionAt(root), &fakeRunner{out: report}).Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if strings.Contains(out, "Zx8Qp2Lr7Vt4Nb6Hc1Jm9Kd3Fs5Gw0Ye") {
		t.Errorf("the secret value reached the model: %s", out)
	}
}

// TestOSVScanner_ReportsIgnoredVulnsAsSuppressedInRepo: osv-scanner runs with
// Argus's empty config, so an `IgnoredVulns` entry in an osv-scanner.toml the
// pull request committed hides nothing. The vulnerability it named (here by
// its CVE alias) is reported as a suppression attempt.
func TestOSVScanner_ReportsIgnoredVulnsAsSuppressedInRepo(t *testing.T) {
	rep := scan(t, "osv-scanner")
	if len(rep.Findings) != 4 {
		t.Fatalf("got %d findings, want one per vulnerability group in the recorded report: %+v", len(rep.Findings), rep.Findings)
	}
	var ids []string
	for _, f := range rep.Findings {
		ids = append(ids, f.RuleID)
		if f.File != "svc/go.mod" {
			t.Errorf("%s: file = %q, want the lockfile it was found in, relative to the checkout", f.RuleID, f.File)
		}
		switch f.RuleID {
		case "GO-2021-0113":
			if !f.SuppressedInRepo || !strings.Contains(f.Suppression, "osv-scanner.toml") {
				t.Errorf("an IgnoredVulns entry must be reported as a suppression: %+v", f)
			}
		default:
			if f.SuppressedInRepo {
				t.Errorf("a vulnerability nobody tried to ignore must not be marked: %+v", f)
			}
		}
	}
	if !slices.Contains(ids, "GO-2022-1059") {
		t.Errorf("findings %v are missing GO-2022-1059 from the recorded report", ids)
	}
}

// TestScanners_RefuseAReportTheyCannotRead: a scanner whose output is not the
// report Argus expects (a crash banner, a format change) must fail loudly. An
// empty findings list would read as "the code is clean".
func TestScanners_RefuseAReportTheyCannotRead(t *testing.T) {
	for name, build := range scanners {
		t.Run(name, func(t *testing.T) {
			fr := &fakeRunner{out: `not json at all`}
			if _, err := build(sessionAt(checkout(t)), fr).Execute(context.Background(), map[string]any{}); err == nil {
				t.Error("an unreadable report must be an error, not an empty result")
			}
		})
	}
}

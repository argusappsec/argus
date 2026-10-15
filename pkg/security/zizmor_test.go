package security_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/security"
)

func init() {
	f := toolFixture{empty: `[]`}
	// zizmor.yml (wherever zizmor would discover it) is not loaded, and
	// `# zizmor: ignore[...]` comments and config ignores are not honoured.
	// --collect=all also audits workflows a committed .gitignore lists: by
	// default zizmor skips them, which is a way to hide one (checked against
	// the real zizmor 1.30.1).
	f.repoConfig.switches = []string{"--no-config", "--no-ignores", "--collect=all"}
	fixture("zizmor", f)
}

// zizmor audits GitHub Actions workflows (and Dependabot and pre-commit
// config). It parses YAML and runs nothing it reads, so automatic reviews may
// run it, and it is a single binary the official image ships.
func TestCatalog_ZizmorAuditsGitHubActionsAndShipsInTheImage(t *testing.T) {
	i := slices.IndexFunc(security.Catalog(), func(e security.Entry) bool { return e.ID == "zizmor" })
	if i < 0 {
		t.Fatal("zizmor is not catalogued")
	}
	e := security.Catalog()[i]
	if e.Tool != "run_zizmor" {
		t.Errorf("Tool = %q, want run_zizmor", e.Tool)
	}
	if !slices.Equal(e.Finds, []security.Find{security.FindCICD}) ||
		!slices.Equal(e.Reads, []security.Read{security.ReadGitHubActions}) {
		t.Errorf("zizmor must be tagged ci-cd and github-actions; finds=%v reads=%v", e.Finds, e.Reads)
	}
	if len(e.Binaries) != 1 || e.Binaries[0].Name != "zizmor" {
		t.Errorf("Binaries = %+v, want zizmor alone", e.Binaries)
	}
	if e.Trust != security.TrustSafe {
		t.Errorf("Trust = %q, want %q", e.Trust, security.TrustSafe)
	}
	if !e.Manifest {
		t.Error("zizmor is in the Manifest: the official image ships it")
	}
	if e.License != "MIT" {
		t.Errorf("License = %q, want MIT", e.License)
	}
}

// TestZizmor_NeverGoesOnline: zizmor switches to online audits, calling the
// GitHub API, as soon as it finds a token in its environment, and the daemon's
// environment holds the organization's GitHub credentials. zizmor gets none of
// them, nor a GitHub host or a config path, and is told --offline explicitly,
// so a token that slipped through would still not take it online.
func TestZizmor_NeverGoesOnline(t *testing.T) {
	for k, v := range map[string]string{
		"GH_TOKEN":            "ghp_should-never-reach-zizmor",
		"GITHUB_TOKEN":        "ghs_should-never-reach-zizmor",
		"ZIZMOR_GITHUB_TOKEN": "ghp_should-never-reach-zizmor",
		"GH_HOST":             "github.example.com",
		"ZIZMOR_CONFIG":       "/etc/zizmor.yml",
		"ZIZMOR_OFFLINE":      "false",
	} {
		t.Setenv(k, v)
	}

	fr := &fakeRunner{out: emptyReport("zizmor")}
	if _, err := security.NewZizmor(sessionAt(checkout(t)), fr).Execute(context.Background(), map[string]any{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(fr.gotArgs) == 0 || fr.gotArgs[0] != "zizmor" {
		t.Fatalf("ran %v, want zizmor", fr.gotArgs)
	}
	for k, v := range envMap(fr.gotCmd.Env) {
		if strings.HasPrefix(k, "GH_") || strings.HasPrefix(k, "GITHUB_") || strings.HasPrefix(k, "ZIZMOR_") {
			t.Errorf("%s=%s must not reach zizmor", k, v)
		}
	}
	if !slices.Contains(fr.gotArgs, "--offline") {
		t.Errorf("zizmor must be told --offline: %v", fr.gotArgs)
	}
	if slices.ContainsFunc(fr.gotArgs, func(a string) bool { return strings.HasPrefix(a, "--gh-token") }) {
		t.Errorf("zizmor must never be handed a token: %v", fr.gotArgs)
	}
}

// TestZizmor_ReportsItsVersionedJSONOverTheTarget: zizmor's JSON format is
// versioned; Argus names the version it parses, so a later default cannot
// change the shape under it. Exit codes that encode the worst severity are
// switched off: finding something is a successful audit.
func TestZizmor_ReportsItsVersionedJSONOverTheTarget(t *testing.T) {
	root := checkout(t)
	fr := &fakeRunner{out: emptyReport("zizmor")}
	if _, err := security.NewZizmor(sessionAt(root), fr).Execute(context.Background(), map[string]any{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if v, _ := optionValue(fr.gotArgs, "--format"); v != "json-v1" {
		t.Errorf("--format = %q, want json-v1: %v", v, fr.gotArgs)
	}
	if !slices.Contains(fr.gotArgs, "--no-exit-codes") {
		t.Errorf("missing --no-exit-codes: %v", fr.gotArgs)
	}
	if fr.gotArgs[len(fr.gotArgs)-1] != root {
		t.Errorf("the last argument must be the target %q: %v", root, fr.gotArgs)
	}
}

// TestZizmor_ParsesItsRecordedReportIntoFindings: the recorded report is
// zizmor 1.30.1 over a workflow with a pull_request_target trigger, an
// unpinned action and two template injections, run with Argus's flags. One
// injection carries a `# zizmor: ignore[...]` comment and the unpinned action
// is listed under `ignore:` in the repository's .github/zizmor.yml: zizmor ran
// with both switched off, so both come back, marked suppressed_in_repo. A
// workflow zizmor could not parse is reported as an error: coverage is partial.
func TestZizmor_ParsesItsRecordedReportIntoFindings(t *testing.T) {
	rep := scan(t, "zizmor")
	if rep.Scanner != "zizmor" {
		t.Errorf("scanner = %q, want zizmor", rep.Scanner)
	}
	var rules []string
	for _, f := range rep.Findings {
		rules = append(rules, f.RuleID)
		if f.File != ".github/workflows/ci.yml" {
			t.Errorf("%s: file = %q, want the workflow relative to the checkout", f.RuleID, f.File)
		}
	}
	want := []string{"artipacked", "excessive-permissions", "dangerous-triggers", "template-injection", "template-injection", "unpinned-uses"}
	if !slices.Equal(rules, want) {
		t.Fatalf("findings = %v, want %v", rules, want)
	}

	trigger := at(t, rep, ".github/workflows/ci.yml", 3)
	if trigger.RuleID != "dangerous-triggers" || trigger.Severity != "high" || trigger.EndLine != 4 {
		t.Errorf("dangerous-triggers: %+v", trigger)
	}
	if trigger.Title != "use of fundamentally insecure workflow trigger" ||
		trigger.Description != "pull_request_target is almost always used insecurely" {
		t.Errorf("title and description must be zizmor's: %+v", trigger)
	}
	if trigger.Details["confidence"] != "medium" || trigger.Details["url"] != "https://docs.zizmor.sh/audits/#dangerous-triggers" {
		t.Errorf("details = %v", trigger.Details)
	}
	if trigger.SuppressedInRepo {
		t.Errorf("a finding nobody tried to silence must not be marked: %+v", trigger)
	}

	// The job spans lines 7-16; zizmor's end point is the start of line 17.
	if job := ruleAt(t, rep, "excessive-permissions", 7); job.EndLine != 16 {
		t.Errorf("excessive-permissions ends on line %d, want 16 (the job's last line)", job.EndLine)
	}

	inline := at(t, rep, ".github/workflows/ci.yml", 16)
	if inline.RuleID != "template-injection" || !inline.SuppressedInRepo || !strings.Contains(inline.Suppression, "zizmor: ignore") {
		t.Errorf("an ignore comment in the workflow must be reported as a suppression: %+v", inline)
	}
	if plain := at(t, rep, ".github/workflows/ci.yml", 14); plain.SuppressedInRepo {
		t.Errorf("the other injection carries no comment and must not be marked: %+v", plain)
	}
	unpinned := ruleAt(t, rep, "unpinned-uses", 10)
	if !unpinned.SuppressedInRepo || !strings.Contains(unpinned.Suppression, "zizmor.yml") {
		t.Errorf("an ignore entry in the repository's zizmor.yml must be reported as a suppression: %+v", unpinned)
	}
	if other := ruleAt(t, rep, "artipacked", 10); other.SuppressedInRepo {
		t.Errorf("the zizmor.yml entry names unpinned-uses only, not another audit on the same line: %+v", other)
	}

	if len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0], "failed to parse input") {
		t.Errorf("errors = %q, want the workflow zizmor could not parse", rep.Errors)
	}
}

// TestZizmor_ReportsARuleTheRepositoryDisabledAsSuppressed: `disable: true`
// in a committed zizmor.yml would switch an audit off for the whole
// repository. zizmor ran without the file, so the audit's findings are there,
// each marked with the attempt.
func TestZizmor_ReportsARuleTheRepositoryDisabledAsSuppressed(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("zizmor.yaml", "rules:\n  dangerous-triggers:\n    disable: true\n")
	write(".github/workflows/x.yml", "on: pull_request_target\njobs: {}\n")
	out := `[{"ident":"dangerous-triggers","desc":"d","url":"u","determinations":{"confidence":"Medium","severity":"High"},` +
		`"locations":[{"symbolic":{"key":{"Local":{"verbatim_path":"` + filepath.Join(root, ".github/workflows/x.yml") + `"}},` +
		`"annotation":"a","kind":"Primary"},"concrete":{"location":{"start_point":{"row":0,"column":0},"end_point":{"row":0,"column":23}}}}],` +
		`"ignored":false}]`

	got, err := security.NewZizmor(sessionAt(root), &fakeRunner{out: out}).Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	rep := decodeReport(t, got)
	f := at(t, rep, ".github/workflows/x.yml", 1)
	if !f.SuppressedInRepo || !strings.Contains(f.Suppression, "zizmor.yaml") {
		t.Errorf("a rule the repository disabled must be reported as a suppression: %+v", f)
	}
}

// TestZizmor_ATreeWithNothingToAuditIsAnEmptyReport: zizmor exits non-zero
// with "no inputs collected" when a tree has no workflows, actions or
// Dependabot or pre-commit config. For a review that is a clean answer, not a
// failed scan.
func TestZizmor_ATreeWithNothingToAuditIsAnEmptyReport(t *testing.T) {
	fr := &fakeRunner{
		out: "fatal: no audit was performed\nerror: no inputs collected\n  |\n  = help: collection yielded no auditable inputs\n",
		err: errors.New("exit status 3"),
	}
	got, err := security.NewZizmor(sessionAt(checkout(t)), fr).Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("nothing to audit must not be an error: %v", err)
	}
	if rep := decodeReport(t, got); len(rep.Findings) != 0 || rep.Scanner != "zizmor" {
		t.Errorf("report = %+v, want zizmor with no findings", rep)
	}
}

// TestZizmor_AFailedRunIsAnError: any other non-zero exit means zizmor did
// not audit the tree, which must not read as a clean result.
func TestZizmor_AFailedRunIsAnError(t *testing.T) {
	fr := &fakeRunner{out: "fatal: no audit was performed\ninvalid input: /nope\n", err: errors.New("exit status 1")}
	_, err := security.NewZizmor(sessionAt(checkout(t)), fr).Execute(context.Background(), map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "invalid input") {
		t.Errorf("err = %v, want zizmor's own explanation", err)
	}
}

// ruleAt finds the one finding of rule on line.
func ruleAt(t *testing.T, rep security.Report, rule string, line int) security.Finding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.RuleID == rule && f.Line == line {
			return f
		}
	}
	t.Fatalf("no %s finding on line %d in %+v", rule, line, rep.Findings)
	return security.Finding{}
}

// decodeReport decodes what a scanner Tool hands the model.
func decodeReport(t *testing.T, out string) security.Report {
	t.Helper()
	var rep security.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("output is not a findings report: %v\n%s", err, out)
	}
	return rep
}

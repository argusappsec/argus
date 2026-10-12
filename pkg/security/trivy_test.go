package security_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/security"
)

// runTrivy runs the trivy Tool over a fresh checkout with a fake runner that
// writes trivy's "nothing found" report, and returns what it was asked to run.
func runTrivy(t *testing.T) *fakeRunner {
	t.Helper()
	fr := &fakeRunner{out: emptyReport["trivy"]}
	if _, err := security.NewTrivy(sessionAt(checkout(t)), fr).Execute(context.Background(), map[string]any{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	return fr
}

// TestTrivy_RunsOnlyTheMisconfigurationScanners: trivy's default scanners
// look for vulnerabilities (which needs its database, downloaded on first use)
// and secrets (gitleaks' job). Argus runs it for misconfiguration only, and
// only over the four kinds of file the Catalog promises: other misconfig
// scanners (Ansible, CloudFormation, Azure ARM, Terraform plans) are not part
// of what it was reviewed for.
func TestTrivy_RunsOnlyTheMisconfigurationScanners(t *testing.T) {
	fr := runTrivy(t)
	if len(fr.gotArgs) < 2 || fr.gotArgs[0] != "trivy" || fr.gotArgs[1] != "fs" {
		t.Errorf("trivy must run its filesystem scan, got %v", fr.gotArgs)
	}
	if v, ok := optionValue(fr.gotArgs, "--scanners"); !ok || v != "misconfig" {
		t.Errorf("--scanners = %q, want misconfig alone (args %v)", v, fr.gotArgs)
	}
	v, ok := optionValue(fr.gotArgs, "--misconfig-scanners")
	got := strings.Split(v, ",")
	slices.Sort(got)
	if !ok || !slices.Equal(got, []string{"dockerfile", "helm", "kubernetes", "terraform"}) {
		t.Errorf("--misconfig-scanners = %q, want dockerfile, helm, kubernetes and terraform", v)
	}
	if v, _ := optionValue(fr.gotArgs, "--format"); v != "json" {
		t.Errorf("trivy must report JSON, got %v", fr.gotArgs)
	}
}

// TestTrivy_StaysOfflineAndQuiet: trivy phones home on its defaults. It sends
// usage telemetry to Aqua, checks for a newer version and announcements, and
// downloads its vulnerability database, its Java index and a fresh checks
// bundle from container registries. Every one of those is switched off on
// every run: the checks that run are the ones built into the pinned binary.
func TestTrivy_StaysOfflineAndQuiet(t *testing.T) {
	fr := runTrivy(t)
	for _, sw := range []string{
		"--offline-scan",
		"--disable-telemetry",
		"--skip-version-check",
		"--skip-check-update",
		"--skip-db-update",
		"--skip-java-db-update",
	} {
		if !slices.Contains(fr.gotArgs, sw) {
			t.Errorf("missing %s in %v", sw, fr.gotArgs)
		}
	}
	cache, ok := optionValue(fr.gotArgs, "--cache-dir")
	if !ok || !inside(fr.gotCmd.Dir, cache) {
		t.Errorf("--cache-dir = %q, want a directory in the run's scratch %q", cache, fr.gotCmd.Dir)
	}
}

// TestTrivy_UsesAnEmptyConfigAndAnEmptyIgnoreFile: the config Argus hands
// trivy sets nothing and the ignore file ignores nothing, so neither a
// trivy.yaml nor a .trivyignore can change what it reports.
func TestTrivy_UsesAnEmptyConfigAndAnEmptyIgnoreFile(t *testing.T) {
	fr := runTrivy(t)
	for _, opt := range []string{"--config", "--ignorefile"} {
		path, _ := optionValue(fr.gotArgs, opt)
		if body, ok := fr.gotFiles[path]; !ok || strings.TrimSpace(body) != "" {
			t.Errorf("%s %q = %q, want an empty file", opt, path, body)
		}
	}
}

// TestTrivy_CannotReachTheNetwork: --offline-scan does not stop trivy's
// Terraform scanner from fetching the remote modules a .tf file names (checked
// against trivy 0.75.0: it runs `git clone` for a git:: source and an HTTP GET
// for an https:// one), and there is no flag that does. So a pull request
// could make the Argus host contact a server of its choosing. The environment
// closes that door: every HTTP client trivy and git use goes through a proxy
// that does not exist, git may use no transport at all, and the cloud metadata
// endpoints that would hand an s3:: or gcs:: fetch the host's credentials are
// switched off.
func TestTrivy_CannotReachTheNetwork(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	t.Setenv("HTTPS_PROXY", "http://corporate-proxy.example:3128")
	fr := runTrivy(t)

	env := envMap(fr.gotCmd.Env)
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy"} {
		if env[k] != "http://127.0.0.1:9" {
			t.Errorf("%s = %q, want the unreachable proxy http://127.0.0.1:9", k, env[k])
		}
	}
	for _, k := range []string{"NO_PROXY", "no_proxy"} {
		if v, ok := env[k]; ok {
			t.Errorf("%s=%s would let a host bypass the proxy", k, v)
		}
	}
	if env["GIT_ALLOW_PROTOCOL"] != "none" {
		t.Errorf("GIT_ALLOW_PROTOCOL = %q, want none: git must not clone a module", env["GIT_ALLOW_PROTOCOL"])
	}
	if env["AWS_EC2_METADATA_DISABLED"] != "true" {
		t.Errorf("AWS_EC2_METADATA_DISABLED = %q, want true", env["AWS_EC2_METADATA_DISABLED"])
	}
	if env["GCE_METADATA_HOST"] != "127.0.0.1:9" {
		t.Errorf("GCE_METADATA_HOST = %q, want the unreachable 127.0.0.1:9", env["GCE_METADATA_HOST"])
	}
	if len(fr.gotCmd.Env) != len(env) {
		t.Errorf("a variable is set twice, so which value wins is up to the child: %v", fr.gotCmd.Env)
	}
}

// trivyEntry is trivy's Entry in the Catalog.
func trivyEntry(t *testing.T) security.Entry {
	t.Helper()
	i := slices.IndexFunc(security.Catalog(), func(e security.Entry) bool { return e.ID == "trivy" })
	if i < 0 {
		t.Fatal("trivy is not catalogued")
	}
	return security.Catalog()[i]
}

// trivy is catalogued for what Argus runs it for: infrastructure-as-code
// misconfiguration in Terraform, Kubernetes manifests (Helm charts included)
// and Dockerfiles. It only parses files, so automatic reviews run it, and the
// official image ships it.
func TestCatalog_TrivyIsAnIaCScannerInTheManifest(t *testing.T) {
	e := trivyEntry(t)
	if e.Tool != "run_trivy" {
		t.Errorf("Tool = %q, want run_trivy", e.Tool)
	}
	if !slices.Equal(e.Finds, []security.Find{security.FindIaC}) {
		t.Errorf("Finds = %v, want [iac]", e.Finds)
	}
	wantReads := []security.Read{security.ReadTerraform, security.ReadKubernetes, security.ReadDockerfile}
	if !slices.Equal(e.Reads, wantReads) {
		t.Errorf("Reads = %v, want %v", e.Reads, wantReads)
	}
	if len(e.Binaries) != 1 || e.Binaries[0].Name != "trivy" {
		t.Errorf("Binaries = %+v, want trivy alone", e.Binaries)
	}
	if e.Trust != security.TrustSafe {
		t.Errorf("Trust = %q, want %q", e.Trust, security.TrustSafe)
	}
	if !e.Manifest {
		t.Error("trivy is in the Manifest: the official image ships it")
	}
	if e.License != "Apache-2.0" {
		t.Errorf("License = %q, want Apache-2.0", e.License)
	}
}

// findingFor finds the one finding for rule on file.
func findingFor(t *testing.T, rep security.Report, rule, file string) security.Finding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.RuleID == rule && f.File == file {
			return f
		}
	}
	t.Fatalf("no %s finding on %s in %+v", rule, file, rep.Findings)
	return security.Finding{}
}

// TestTrivy_ParsesItsRecordedReportIntoFindings: the report was recorded from
// the real trivy 0.75.0 with Argus's flags over testdata/trivy/checkout: a
// Dockerfile, a Terraform module and a Kubernetes Deployment. Each failed
// check is one finding, at the file and lines trivy points at, with trivy's
// severity and the resource it is about. Passed checks are not findings.
func TestTrivy_ParsesItsRecordedReportIntoFindings(t *testing.T) {
	rep := scan(t, "trivy")
	if rep.Scanner != "trivy" {
		t.Errorf("scanner = %q, want trivy", rep.Scanner)
	}

	ssh := findingFor(t, rep, "AWS-0107", "infra/main.tf")
	if ssh.Line != 7 || ssh.EndLine != 7 || ssh.Severity != "HIGH" {
		t.Errorf("AWS-0107 = line %d-%d severity %q, want 7-7 HIGH", ssh.Line, ssh.EndLine, ssh.Severity)
	}
	if !strings.Contains(ssh.Title, "unrestricted ingress") || ssh.Description == "" {
		t.Errorf("AWS-0107 must carry trivy's title and description: %+v", ssh)
	}
	if ssh.Details["resource"] != "aws_security_group_rule.ssh" {
		t.Errorf("AWS-0107 details = %v, want the resource it is about", ssh.Details)
	}
	if ssh.SuppressedInRepo {
		t.Errorf("a finding nobody tried to silence must not be marked: %+v", ssh)
	}

	privileged := findingFor(t, rep, "KSV-0017", "k8s/deploy.yaml")
	if privileged.Line != 9 || privileged.EndLine != 13 {
		t.Errorf("KSV-0017 = lines %d-%d, want the container, 9-13", privileged.Line, privileged.EndLine)
	}
	// A check about the whole file has no line.
	if healthcheck := findingFor(t, rep, "DS-0026", "Dockerfile"); healthcheck.Line != 0 {
		t.Errorf("DS-0026 = line %d, want none", healthcheck.Line)
	}

	var reported int
	for _, f := range rep.Findings {
		if f.Severity != "" {
			reported++
		}
	}
	if reported != 19 {
		t.Errorf("got %d findings with a severity, want the 19 failed checks in the recorded report", reported)
	}
}

// TestTrivy_ReportsIgnoreFileEntriesAsSuppressedInRepo: trivy runs with
// Argus's empty ignore file, so a .trivyignore or .trivyignore.yaml the pull
// request committed hides nothing. A finding one of them names is reported as
// a suppression attempt, whichever spelling of the check id it uses
// (KSV-0017, AVD-KSV-0001). A YAML entry limited to other paths names nothing
// here.
func TestTrivy_ReportsIgnoreFileEntriesAsSuppressedInRepo(t *testing.T) {
	rep := scan(t, "trivy")
	if f := findingFor(t, rep, "KSV-0017", "k8s/deploy.yaml"); !f.SuppressedInRepo || !strings.Contains(f.Suppression, ".trivyignore") {
		t.Errorf("a .trivyignore entry must be reported as a suppression: %+v", f)
	}
	if f := findingFor(t, rep, "KSV-0001", "k8s/deploy.yaml"); !f.SuppressedInRepo || !strings.Contains(f.Suppression, ".trivyignore.yaml") {
		t.Errorf("a .trivyignore.yaml entry for this path must be reported as a suppression: %+v", f)
	}
	if f := findingFor(t, rep, "KSV-0020", "k8s/deploy.yaml"); f.SuppressedInRepo {
		t.Errorf("a .trivyignore.yaml entry for another path must not mark this finding: %+v", f)
	}
}

// TestTrivy_ReportsInlineIgnoreCommentsAsSuppressedInRepo: a `trivy:ignore`
// comment on a finding's lines marks it, for the check it names only.
func TestTrivy_ReportsInlineIgnoreCommentsAsSuppressedInRepo(t *testing.T) {
	rep := scan(t, "trivy")
	if f := findingFor(t, rep, "KSV-0014", "k8s/deploy.yaml"); !f.SuppressedInRepo || !strings.Contains(f.Suppression, "trivy:ignore") {
		t.Errorf("a trivy:ignore comment naming the check must be reported as a suppression: %+v", f)
	}
	if f := findingFor(t, rep, "KSV-0012", "k8s/deploy.yaml"); f.SuppressedInRepo {
		t.Errorf("a comment naming another check must not mark this finding: %+v", f)
	}
}

// TestTrivy_ReportsTheChecksAnInlineCommentHid: trivy honours trivy:ignore
// and tfsec:ignore comments in Terraform, Helm templates and Dockerfiles, and
// has no switch to stop (checked against trivy 0.75.0): the finding such a
// comment covers never reaches the report. So the comment itself is reported,
// as a suppressed entry naming the check and where it sits, for the reviewer
// to read the code under it. In the fixture the comment above the rdp rule hid
// AWS-0107 and the one above `USER root` hid DS-0002.
func TestTrivy_ReportsTheChecksAnInlineCommentHid(t *testing.T) {
	rep := scan(t, "trivy")
	for _, want := range []struct {
		rule, file string
		line       int
	}{
		{"AVD-AWS-0107", "infra/main.tf", 10},
		{"aws-ec2-no-public-ingress-sgr", "infra/main.tf", 26},
		{"DS-0002", "Dockerfile", 4},
	} {
		f := at(t, rep, want.file, want.line)
		if f.RuleID != want.rule || !f.SuppressedInRepo || !strings.Contains(f.Suppression, "ignore comment") {
			t.Errorf("%s:%d = %+v, want a suppressed entry for %s", want.file, want.line, f, want.rule)
		}
		if f.Severity != "" {
			t.Errorf("%s:%d: trivy never reported this check, so it has no severity: %+v", want.file, want.line, f)
		}
	}
	// KSV-0014's comment is in a Kubernetes manifest, where trivy reported the
	// finding anyway: it marks that finding and is not reported twice.
	for _, f := range rep.Findings {
		if f.File == "k8s/deploy.yaml" && f.Line == 12 {
			t.Errorf("the comment on a reported finding must not also be reported on its own: %+v", f)
		}
	}
}

package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

// NewTrivy returns a `run_trivy` tool that runs trivy's misconfiguration
// scanners over the Session's current target directory.
func NewTrivy(s *session.Session, r Runner) tool.Tool {
	return &trivy{scanner{name: trivyTool, binary: "trivy", sess: s, runner: r}}
}

const trivyTool = "run_trivy"

type trivy struct{ scanner }

func (t *trivy) Description() string {
	return "Run trivy's misconfiguration checks over a directory on the machine Argus runs on: Terraform, " +
		"Kubernetes manifests, Helm charts and Dockerfiles (no vulnerability or secret scanning). Returns one " +
		"finding per failed check (rule_id is trivy's check id, e.g. AWS-0107 or KSV-0017) with the file, " +
		"lines, severity and the resource it is about. A finding marked suppressed_in_repo is named by a " +
		".trivyignore file or a trivy:ignore comment in the code: it is still a finding, and the attempt to " +
		"silence it is itself worth a look. trivy obeys trivy:ignore comments in Terraform, Helm and " +
		"Dockerfiles regardless, so each such comment that hid a check is reported as a suppressed entry " +
		"with no severity, at the comment's line: read the code there."
}

func init() {
	catalogue(Entry{
		ID:      "trivy",
		Tool:    trivyTool,
		Name:    "Trivy",
		Purpose: "Finds insecure settings in Terraform, Kubernetes manifests, Helm charts and Dockerfiles.",
		Why: "Infrastructure code decides who can reach a service and with which privileges: a " +
			"security group open to the internet, a privileged container or an image that runs as " +
			"root ships the weakness as surely as a code bug. Trivy checks Terraform, Kubernetes " +
			"manifests, Helm charts and Dockerfiles against hundreds of built-in rules in one binary, " +
			"covering what tfsec, hadolint and kube-linter each cover in part. Argus runs only its " +
			"misconfiguration scanners, offline, with the checks built into the binary, and never " +
			"lets it fetch the remote Terraform modules a pull request names. Trivy obeys " +
			"`trivy:ignore` comments in Terraform, Helm charts and Dockerfiles and cannot be told " +
			"not to, so Argus reports every such comment as a suppression attempt, with the check it " +
			"names and where it sits.",
		Finds:      []Find{FindIaC},
		Reads:      []Read{ReadTerraform, ReadKubernetes, ReadDockerfile},
		DocsURL:    "https://trivy.dev/docs/latest/",
		InstallURL: "https://trivy.dev/docs/latest/getting-started/installation/",
		License:    "Apache-2.0",
		Manifest:   true,
		Binaries: []Binary{{
			Name:        "trivy",
			InstallHint: "brew install trivy",
		}},
		// trivy parses the files and evaluates its checks over them; it
		// builds nothing and runs nothing from the checkout.
		Trust: TrustSafe,
		New:   func(d Deps) tool.Tool { return NewTrivy(d.Session, d.Commands) },
	})
}

func (t *trivy) Execute(ctx context.Context, args map[string]any) (string, error) {
	return t.scan(ctx, args, t.run, parseTrivy)
}

func (t *trivy) run(ctx context.Context, sc *scratch, root string) ([]byte, error) {
	// trivy reads trivy.yaml and .trivyignore from its working directory unless
	// it is told which files to use. It is told: Argus's own, both empty.
	config, err := sc.write("trivy.yaml", nil)
	if err != nil {
		return nil, fmt.Errorf("trivy: %w", err)
	}
	ignore, err := sc.write("trivyignore", nil)
	if err != nil {
		return nil, fmt.Errorf("trivy: %w", err)
	}

	env := append(sc.xdg(), trivyNetworkLockout()...)
	return t.runForReport(ctx, sc, env, "trivy", "fs",
		// Misconfiguration only, over the file kinds the Catalog promises.
		"--scanners", "misconfig",
		"--misconfig-scanners", trivyMisconfigScanners,
		// Nothing leaves the host: no dependency lookups, no telemetry, no
		// version or announcement check, no database or checks downloads.
		// The checks that run are the ones embedded in the pinned binary.
		"--offline-scan",
		"--disable-telemetry",
		"--skip-version-check",
		"--skip-check-update",
		"--skip-db-update",
		"--skip-java-db-update",
		"--config", config,
		"--ignorefile", ignore,
		"--cache-dir", sc.file("cache"),
		"--format", "json",
		"--output", sc.file(reportFile),
		"--no-progress",
		root,
	)
}

// trivyMisconfigScanners are trivy's misconfiguration scanners Argus runs:
// the file kinds its Catalog Entry promises, and no others.
const trivyMisconfigScanners = "dockerfile,helm,kubernetes,terraform"

// trivyNoProxy is a proxy address nothing listens on: every HTTP request sent
// through it fails at once.
const trivyNoProxy = "127.0.0.1:9"

// trivyNetworkLockout is the environment that keeps trivy off the network
// where its flags cannot.
//
// trivy's Terraform scanner fetches the remote modules a .tf file names, with
// go-getter: `git clone` for a git:: source, an HTTP GET for an https:// one,
// the registry protocol for a registry address, and the cloud SDKs for s3::
// and gcs::. --offline-scan does not stop it and no flag does (checked against
// trivy 0.75.0). A pull request could otherwise make the Argus host contact a
// server of its choosing, so:
//   - every HTTP client honours the proxy variables, and they point at a
//     proxy that does not exist. NO_PROXY is never set, so no host bypasses it.
//     (Go sends requests for loopback addresses direct, whatever the proxy.)
//   - GIT_ALLOW_PROTOCOL names no real transport, so git refuses every one,
//     ssh:// and git:// included, which a proxy would not cover.
//   - the AWS and GCP metadata endpoints, which would hand an s3:: or gcs::
//     fetch the host's own cloud credentials, are switched off.
func trivyNetworkLockout() []string {
	proxy := "http://" + trivyNoProxy
	return []string{
		"HTTPS_PROXY=" + proxy, "HTTP_PROXY=" + proxy, "ALL_PROXY=" + proxy,
		"https_proxy=" + proxy, "http_proxy=" + proxy, "all_proxy=" + proxy,
		"GIT_ALLOW_PROTOCOL=none",
		"AWS_EC2_METADATA_DISABLED=true",
		"GCE_METADATA_HOST=" + trivyNoProxy,
	}
}

// trivyReport is the part of trivy's JSON report Argus reads. A Result is one
// file (or Terraform module) trivy scanned, with the checks it failed.
type trivyReport struct {
	SchemaVersion int `json:"SchemaVersion"`
	Results       []struct {
		Target            string         `json:"Target"`
		Type              string         `json:"Type"`
		Misconfigurations []trivyMisconf `json:"Misconfigurations"`
	} `json:"Results"`
}

type trivyMisconf struct {
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Message     string `json:"Message"`
	Resolution  string `json:"Resolution"`
	Severity    string `json:"Severity"`
	PrimaryURL  string `json:"PrimaryURL"`
	Status      string `json:"Status"`
	Cause       struct {
		Resource  string `json:"Resource"`
		StartLine int    `json:"StartLine"`
		EndLine   int    `json:"EndLine"`
	} `json:"CauseMetadata"`
}

func parseTrivy(body []byte, target string, files *checkoutFiles) (Report, error) {
	var out trivyReport
	// Every trivy JSON report carries its schema version, findings or not.
	if err := json.Unmarshal(body, &out); err != nil || out.SchemaVersion == 0 {
		return Report{}, errors.New("trivy: unreadable report")
	}
	ignored := trivyIgnored(files, target)
	comments := trivyComments{files: files, seen: map[string][]trivyComment{}}
	// What is left of the inline comments once the reported findings have
	// claimed theirs: the files in which trivy honours them, in report order.
	var honouring []string
	rep := Report{Scanner: "trivy"}
	for _, res := range out.Results {
		// Targets are relative to the scanned directory.
		file, inCheckout := files.rel(filepath.Join(target, filepath.FromSlash(res.Target)))
		if inCheckout && trivyHonoursInlineIgnores[res.Type] {
			honouring = append(honouring, comments.sources(file)...)
		}
		for _, m := range res.Misconfigurations {
			if m.Status != "FAIL" {
				continue
			}
			f := Finding{
				RuleID:      m.ID,
				Severity:    m.Severity,
				File:        file,
				Line:        m.Cause.StartLine,
				EndLine:     m.Cause.EndLine,
				Title:       m.Title,
				Description: m.Description,
				Details:     map[string]any{"type": res.Type},
			}
			for k, v := range map[string]string{
				"resource":   m.Cause.Resource,
				"message":    m.Message,
				"resolution": m.Resolution,
				"url":        m.PrimaryURL,
			} {
				if v != "" {
					f.Details[k] = v
				}
			}
			if inCheckout {
				switch {
				case comments.claim(file, m.ID, m.Cause.StartLine, m.Cause.EndLine):
					f.suppressed("trivy:ignore comment in the code")
				default:
					if how := ignored.names(m.ID, res.Target); how != "" {
						f.suppressed(how + " entry in the repository")
					}
				}
			}
			rep.Findings = append(rep.Findings, f)
		}
	}
	rep.Findings = append(rep.Findings, comments.unclaimed(honouring)...)
	return rep, nil
}

// trivyHonoursInlineIgnores are the trivy file types whose scanners obey
// inline trivy:ignore and tfsec:ignore comments, with no switch to turn that
// off (trivy 0.75.0: the Terraform, Helm and Dockerfile scanners; the
// Kubernetes one ignores them).
var trivyHonoursInlineIgnores = map[string]bool{
	"terraform":  true,
	"helm":       true,
	"dockerfile": true,
}

// trivyIgnoreComment is an inline ignore comment, `trivy:ignore:<check>` or
// tfsec's older `tfsec:ignore:<check>`, optionally followed by more
// `:`-separated conditions (an expiry, a workspace) Argus does not need.
var trivyIgnoreComment = regexp.MustCompile(`(?:trivy|tfsec):ignore:([A-Za-z0-9_.*-]+)`)

// trivyCheckIDPattern splits a check id into its letters and its number.
var trivyCheckIDPattern = regexp.MustCompile(`^([A-Z]+(?:-[A-Z]+)*?)-?0*([0-9]+)$`)

// trivyCheckID reduces a check id to the form every spelling of it shares.
// trivy reports AWS-0107 and KSV-0017, and accepts AVD-AWS-0107, KSV017 and
// ksv-17 for them in ignore files and comments. A check's short name
// (aws-ec2-no-public-ingress-sgr) is not in trivy's report, so it only ever
// matches itself.
func trivyCheckID(id string) string {
	id = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(id)), "AVD-")
	if m := trivyCheckIDPattern.FindStringSubmatch(id); m != nil {
		return m[1] + "-" + m[2]
	}
	return id
}

// sameCheck reports whether an id written in the repository names check.
func sameCheck(written, check string) bool {
	return written == "*" || trivyCheckID(written) == trivyCheckID(check)
}

// trivyComment is one check an inline ignore comment names.
type trivyComment struct {
	line    int
	check   string
	claimed bool
}

// trivyComments finds the inline ignore comments in checkout files, reading
// each file once.
type trivyComments struct {
	files *checkoutFiles
	seen  map[string][]trivyComment // by checkout-relative file
}

func (c *trivyComments) of(file string) []trivyComment {
	if got, ok := c.seen[file]; ok {
		return got
	}
	var out []trivyComment
	if body, ok := c.files.read(file); ok {
		for i, l := range strings.Split(string(body), "\n") {
			for _, m := range trivyIgnoreComment.FindAllStringSubmatch(l, -1) {
				out = append(out, trivyComment{line: i + 1, check: m[1]})
			}
		}
	}
	c.seen[file] = out
	return out
}

// claim reports whether a comment on the finding's lines, or alone on the line
// above them, names its check, and marks that comment as accounted for.
func (c *trivyComments) claim(file, check string, from, to int) bool {
	if from < 1 {
		return false
	}
	found := false
	for i, cm := range c.of(file) {
		if cm.line >= from-1 && cm.line <= max(to, from) && sameCheck(cm.check, check) {
			c.seen[file][i].claimed = true
			found = true
		}
	}
	return found
}

// sources lists the files a Result's target stands for: the file itself, or,
// for a Terraform module, the .tf files in its directory.
func (c *trivyComments) sources(target string) []string {
	if _, ok := c.files.read(target); ok {
		return []string{target}
	}
	var out []string
	for _, name := range c.files.list(target) {
		if strings.HasSuffix(name, ".tf") || strings.HasSuffix(name, ".tf.json") {
			out = append(out, joinSlash(target, name))
		}
	}
	return out
}

// unclaimed reports every inline ignore comment in files that trivy obeys
// them in and that no reported finding accounts for. trivy dropped whatever
// such a comment covers before writing its report, so the comment is the only
// trace of it: it is reported as suppressed, naming the check, at its line.
func (c *trivyComments) unclaimed(files []string) []Finding {
	var out []Finding
	done := map[string]bool{}
	for _, file := range files {
		if done[file] {
			continue
		}
		done[file] = true
		for _, cm := range c.of(file) {
			if cm.claimed {
				continue
			}
			f := Finding{
				RuleID: cm.check,
				File:   file,
				Line:   cm.line,
				Title:  "An inline ignore comment hides trivy check " + cm.check + " here",
				Description: "trivy obeys trivy:ignore and tfsec:ignore comments in Terraform, Helm and " +
					"Dockerfiles and cannot be told not to, so whatever this comment covers is not in the " +
					"report. Read the code it sits on or above to see what it silences.",
			}
			f.suppressed("trivy:ignore comment in the code")
			out = append(out, f)
		}
	}
	return out
}

// trivyIgnore is what the repository's ignore files name: .trivyignore check
// ids, and .trivyignore.yaml misconfiguration entries with their paths.
type trivyIgnore []struct {
	file, check string
	paths       []string
}

// trivyIgnored reads the ignore files trivy would load when run from the
// repository: at the checkout's root and at the scanned directory.
func trivyIgnored(files *checkoutFiles, target string) trivyIgnore {
	var out trivyIgnore
	dirs := []string{""}
	if dir, ok := files.rel(target); ok && dir != "." && dir != "" {
		dirs = append(dirs, dir)
	}
	for _, dir := range dirs {
		if body, ok := files.read(joinSlash(dir, ".trivyignore")); ok {
			for _, l := range strings.Split(string(body), "\n") {
				fields := strings.Fields(l)
				if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
					continue
				}
				out = append(out, struct {
					file, check string
					paths       []string
				}{".trivyignore", fields[0], nil})
			}
		}
		for _, name := range []string{".trivyignore.yaml", ".trivyignore.yml"} {
			body, ok := files.read(joinSlash(dir, name))
			if !ok {
				continue
			}
			var doc struct {
				Misconfigurations []struct {
					ID    string   `yaml:"id"`
					Paths []string `yaml:"paths"`
				} `yaml:"misconfigurations"`
			}
			if yaml.Unmarshal(body, &doc) != nil {
				continue
			}
			for _, e := range doc.Misconfigurations {
				out = append(out, struct {
					file, check string
					paths       []string
				}{name, e.ID, e.Paths})
			}
		}
	}
	return out
}

// names returns which ignore file names check on target (trivy's own path for
// the file, relative to the scanned directory), or "".
func (ig trivyIgnore) names(check, target string) string {
	for _, e := range ig {
		if !sameCheck(e.check, check) {
			continue
		}
		if len(e.paths) == 0 {
			return e.file
		}
		for _, p := range e.paths {
			if ok, _ := path.Match(p, target); ok || p == target {
				return e.file
			}
		}
	}
	return ""
}

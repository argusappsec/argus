# Optional scanner Tools: which security and Go tools Argus should wrap, and what each one costs

**Question.** Argus wraps three external scanners today (semgrep, gitleaks, osv-scanner) and ships
them in its official image. The maintainer wants to wrap more security and Go tools as Tools, make
every external-binary Tool **optional** (Argus registers only the ones installed on `PATH`), and
publish a catalog in the docs: for each tool, what it does, why it is useful, tags, and links to the
official docs and install guide, so operators choose what to install. Which candidates are worth
wrapping, in what order, and what does making Tools optional change in Argus?

**Researched 2026-10-09.** Every claim about a tool is cited inline to a primary source: the
official repository (pinned to a release tag, so line numbers stay valid), official docs, release
notes, security advisories, or `gh api` metadata. Claims about Argus cite files in this repo.
Sections and sentences marked **Judgement** are my assessment. Everything else is meant to be
checkable fact. Where I could not verify something from a primary source, the text says so, and
§11 collects those gaps.

Pinned sources (tag → commit, commit date, from `gh api repos/<repo>/commits/<tag>`):

| Tool | Version looked at | Source pin |
| --- | --- | --- |
| govulncheck | `v1.8.0` (2026-09-08) | [`golang/vuln@v1.8.0`](https://github.com/golang/vuln/tree/v1.8.0) (`7090154`) |
| gosec | `v2.29.0` (2026-08-25) | [`securego/gosec@v2.29.0`](https://github.com/securego/gosec/tree/v2.29.0) (`deb5446`) |
| staticcheck | `2026.2.1` (2026-08-21) | [`dominikh/go-tools@2026.2.1`](https://github.com/dominikh/go-tools/tree/2026.2.1) (`1285a6a`) |
| capslock | `v0.3.3` (2026-08-25, tag only, no GitHub release) | [`google/capslock@v0.3.3`](https://github.com/google/capslock/tree/v0.3.3) (`15dddbd`) |
| golangci-lint | `v2.14.0` (2026-09-24) | [`golangci/golangci-lint@v2.14.0`](https://github.com/golangci/golangci-lint/tree/v2.14.0) (`114493f`) |
| go-licenses | `v2.0.1` (2025-09-08) | [`google/go-licenses@v2.0.1`](https://github.com/google/go-licenses/tree/v2.0.1) (`3e084b0`) |
| zizmor | `v1.30.1` (2026-09-09) | [`zizmorcore/zizmor@v1.30.1`](https://github.com/zizmorcore/zizmor/tree/v1.30.1) (`99a054e`) |
| actionlint | `v1.7.12` (2026-03-30) | [`rhysd/actionlint@v1.7.12`](https://github.com/rhysd/actionlint/tree/v1.7.12) (`914e7df`) |
| poutine | `v1.1.6` (2026-05-22) | [`boostsecurityio/poutine@v1.1.6`](https://github.com/boostsecurityio/poutine/tree/v1.1.6) (`8918c66`) |
| OpenSSF Scorecard | `v5.5.0` (2026-04-23) | [`ossf/scorecard@v5.5.0`](https://github.com/ossf/scorecard/tree/v5.5.0) (`c395761`) |
| trivy | `v0.75.0` (2026-10-01) | [`aquasecurity/trivy@v0.75.0`](https://github.com/aquasecurity/trivy/tree/v0.75.0) (`591e979`) |
| tfsec | `v1.28.14` (2025-05-02) | [`aquasecurity/tfsec@v1.28.14`](https://github.com/aquasecurity/tfsec/tree/v1.28.14) (`b692c20`) |
| grype | `v0.120.1` (2026-10-06) | [`anchore/grype@v0.120.1`](https://github.com/anchore/grype/tree/v0.120.1) (`6f8d854`) |
| syft | `v1.54.1` (2026-10-06) | [`anchore/syft@v1.54.1`](https://github.com/anchore/syft/tree/v1.54.1) (`b254e6d`) |
| osv-scalibr | `v0.5.3` (2026-09-22) | [`google/osv-scalibr@v0.5.3`](https://github.com/google/osv-scalibr/tree/v0.5.3) (`c421bee`) |
| checkov | `3.3.26` (2026-10-07) | [`bridgecrewio/checkov@3.3.26`](https://github.com/bridgecrewio/checkov/tree/3.3.26) (`e5f995a`) |
| KICS | `v2.2.0` (2026-09-17) | [`Checkmarx/kics@v2.2.0`](https://github.com/Checkmarx/kics/tree/v2.2.0) (`453066a`) |
| hadolint | `v2.15.1` (2026-07-31) | [`hadolint/hadolint@v2.15.1`](https://github.com/hadolint/hadolint/tree/v2.15.1) (`2eece55`) |
| kube-linter | `v0.8.3` (2026-03-10) | [`stackrox/kube-linter@v0.8.3`](https://github.com/stackrox/kube-linter/tree/v0.8.3) (`10ae003`) |
| kubescape | `v4.0.15` (2026-09-29) | [`kubescape/kubescape@v4.0.15`](https://github.com/kubescape/kubescape/tree/v4.0.15) (`16cfe10`) |
| trufflehog | `v3.99.2` (2026-10-08) | [`trufflesecurity/trufflehog@v3.99.2`](https://github.com/trufflesecurity/trufflehog/tree/v3.99.2) (`e76dff8`) |
| bandit | `1.9.4` (2026-02-23) | [`PyCQA/bandit@1.9.4`](https://github.com/PyCQA/bandit/tree/1.9.4) (`92ae8b8`) |
| ruff (flake8-bandit `S` rules) | `0.16.10` (2026-10-01) | [`astral-sh/ruff@0.16.10`](https://github.com/astral-sh/ruff/tree/0.16.10) (`3265ed1`) |
| pip-audit | `v2.10.1` (2026-06-10) | [`pypa/pip-audit@v2.10.1`](https://github.com/pypa/pip-audit/tree/v2.10.1) (`8894eb8`) |
| brakeman | `v8.1.0` (2026-09-30) | [`presidentbeef/brakeman@v8.1.0`](https://github.com/presidentbeef/brakeman/tree/v8.1.0) (`c778164`) |
| njsscan | `1.0.1` (2026-09-21) | [`ajinabraham/njsscan@1.0.1`](https://github.com/ajinabraham/njsscan/tree/1.0.1) (`4137df3`) |
| eslint-plugin-security | `v4.2.0` (2026-10-01) | [`eslint-community/eslint-plugin-security@eslint-plugin-security-v4.2.0`](https://github.com/eslint-community/eslint-plugin-security/tree/eslint-plugin-security-v4.2.0) (`a204dfb`) |
| npm audit | npm `v12.2.0` (2026-09-30) | [`npm/cli@v12.2.0`](https://github.com/npm/cli/tree/v12.2.0) (`c276cad`); docs [npm-audit (v11)](https://docs.npmjs.com/cli/v11/commands/npm-audit) |
| cargo-audit | `v0.22.2` (2026-06-05) | [`rustsec/rustsec@cargo-audit/v0.22.2`](https://github.com/rustsec/rustsec/tree/cargo-audit/v0.22.2) (`281452c`) |
| OWASP dependency-check | `v13.0.0` (2026-08-03) | [`dependency-check/DependencyCheck@v13.0.0`](https://github.com/dependency-check/DependencyCheck/tree/v13.0.0) (`4aacdb1`) |
| licensee | `v10.1.0` (2026-08-07) | [`licensee/licensee@v10.1.0`](https://github.com/licensee/licensee/tree/v10.1.0) (`fb924e7`) |
| Bearer CLI | `v2.1.1` (2026-08-24) | [`Bearer/bearer@v2.1.1`](https://github.com/Bearer/bearer/tree/v2.1.1) (`600e551`) |
| opengrep | `v1.30.2` (2026-10-07) | [`opengrep/opengrep@v1.30.2`](https://github.com/opengrep/opengrep/tree/v1.30.2) (`062fc87`) |
| CodeQL CLI | `v2.27.2` (2026-10-07) | [`github/codeql-cli-binaries@v2.27.2`](https://github.com/github/codeql-cli-binaries/tree/v2.27.2) (`be2e13d`) |
| *Existing:* semgrep | `v1.180.0` (2026-10-07); image pins `1.168.0` | [`semgrep/semgrep@v1.180.0`](https://github.com/semgrep/semgrep/tree/v1.180.0) (`a35fe83`) |
| *Existing:* gitleaks | `v8.30.1` (2026-03-12) | [`gitleaks/gitleaks@v8.30.1`](https://github.com/gitleaks/gitleaks/tree/v8.30.1) (`83d9cd6`) |
| *Existing:* osv-scanner | `v2.6.0` (2026-09-14); image pins `v2.4.0` | [`google/osv-scanner@v2.6.0`](https://github.com/google/osv-scanner/tree/v2.6.0) (`e840a6e`) |
| Go toolchain behaviour | — | [go.dev/doc/toolchain](https://go.dev/doc/toolchain), [go.dev/ref/mod](https://go.dev/ref/mod), [go.dev/doc/security/decisions](https://go.dev/doc/security/decisions), [cmd/cgo](https://pkg.go.dev/cmd/cgo), [go/packages](https://pkg.go.dev/golang.org/x/tools/go/packages) |

---

## TL;DR

- **Step 0, before any new Tool: harden how scanners are executed.** Today every scanner runs with
  its working directory set to the scanned checkout and with Argus's whole process environment
  ([`pkg/security/exec.go:22-23`](../../pkg/security/exec.go); the daemon loads `.env` into that
  environment at [`pkg/daemon/daemon.go:144`](../../pkg/daemon/daemon.go)). Several candidates
  load configuration from the working directory or the scanned tree, and some of that
  configuration can disable rules, hide findings, or load code (§2). Trivy's own docs warn about
  exactly this: "Running Trivy from a repository checkout can therefore load configuration supplied
  by that repository"
  ([configuration/index.md:46](https://github.com/aquasecurity/trivy/blob/v0.75.0/docs/guide/configuration/index.md#L46)).
  Each Tool should run with a cwd outside the checkout, an explicit environment allowlist, and
  explicit "ignore repo config" flags. This applies to the three existing scanners too.
  **Judgement.**
- **Go first, as asked, but behind a "Go toolchain profile" and not on automatic reviews of
  untrusted PRs until ADR 0019 Phase 2.** Every useful Go analyzer (govulncheck, gosec, capslock,
  staticcheck, golangci-lint) loads packages through `golang.org/x/tools/go/packages`, whose
  default build tool is the `go` command
  ([go/packages](https://pkg.go.dev/golang.org/x/tools/go/packages)). So the Go toolchain becomes a
  runtime dependency, and with it the toolchain's own behaviour on untrusted code: automatic
  toolchain downloads (`GOTOOLCHAIN=auto` is the default,
  [go.dev/doc/toolchain](https://go.dev/doc/toolchain)), module downloads, cgo, and the Go team's
  stated position that building attacker code "may produce output which contains the contents of
  arbitrary local files", which is "not in our threat model"
  ([go.dev/doc/security/decisions](https://go.dev/doc/security/decisions)). Environment pins
  (`GOTOOLCHAIN=local`, `GOFLAGS=-mod=readonly`, `CGO_ENABLED=0`, `GOWORK=off`, a proxy-only or
  `off` `GOPROXY`) close the code-execution and download vectors; only a sandbox closes the
  local-file-disclosure one (§8.3). **Judgement.**
  1. **gosec**: Go SAST with type information and taint rules (`G7xx`), JSON and SARIF, with a
     flag to ignore in-code `#nosec`
     ([README:228-230, 541, 608-611](https://github.com/securego/gosec/blob/v2.29.0/README.md#L608-L611)).
     This is the clearest Go value-add over semgrep. Note that it has an opt-in "AI fix" feature
     keyed on `GOSEC_AI_API_KEY` (README:391-425): the env allowlist must exclude it.
  2. **govulncheck**: reachability-aware Go vulnerability scanning, JSON/SARIF/OpenVEX
     ([doc.go:65-73](https://github.com/golang/vuln/blob/v1.8.0/cmd/govulncheck/doc.go#L65-L73)).
     **But** osv-scanner, which Argus already runs, does Go call analysis by default with the
     govulncheck library whenever `go` is on `PATH`
     ([scan-source.md:148-157](https://github.com/google/osv-scanner/blob/v2.6.0/docs/scan-source.md#L148-L157)).
     Installing `go` therefore already upgrades `run_osv_scanner`; a separate govulncheck Tool adds
     call traces, binary mode and the Go-curated database. Decide whether that is worth a second
     Tool (§10, Q2). **Judgement.**
  3. **capslock** (later): reports what privileged capabilities (files, network, exec, unsafe…)
     a Go package reaches transitively
     ([README:3-6](https://github.com/google/capslock/blob/v0.3.3/README.md#L3-L6)), with a JSON
     and a `compare` output mode
     ([capslock.go:36](https://github.com/google/capslock/blob/v0.3.3/cmd/capslock/capslock.go#L36)).
     It is a good fit for "this PR bumps a dependency" reviews, but it has no release binaries
     (no GitHub releases at all, only tags; install is `go install`, README:35-37).
  4. **Not** staticcheck as a separate Tool (its checks are correctness/style; almost none are
     security checks, §3.3), **not** golangci-lint (an aggregator whose repo config is discovered
     from the analyzed path upward and can load Go plugins, §3.5), **not** go-licenses
     (osv-scanner already does license checks, §3.6).
- **Then, for non-Go coverage: zizmor first, then trivy restricted to misconfiguration.**
  - **zizmor** audits GitHub Actions workflows, Dependabot and pre-commit configs. It is offline
    unless a GitHub token is in the environment, has a versioned JSON format plus SARIF, and has
    `--no-config` and `--no-ignores` ([docs](https://docs.zizmor.sh/usage/),
    [configuration](https://docs.zizmor.sh/configuration/)). It installs with `pip`
    ([installation](https://docs.zizmor.sh/installation/)), so it fits the existing
    `python:3.x-slim` image with no new runtime. Workflows are both inside PRs and a common attack
    surface, and Argus covers none of it today. **Judgement: highest value per unit of risk.**
  - **trivy** (`--scanners misconfig` only): one static Go binary that covers Terraform,
    CloudFormation, Kubernetes, Helm and Dockerfile misconfiguration, which is what tfsec,
    hadolint, kube-linter, checkov and KICS each cover in part. tfsec's own README tells users to
    move to trivy ([README:13-24](https://github.com/aquasecurity/tfsec/blob/v1.28.14/README.md#L13-L24)).
    Two caveats: it needs `--config ""`, `--ignorefile ""`, `--disable-telemetry`,
    `--skip-version-check` and `--offline-scan` to stay inside Argus's posture
    (§4.1); and trivy's release pipeline was compromised in March 2026, when a malicious `v0.69.4`
    was published ([GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)).
    Pin it by digest and verify signatures. **Judgement.**
- **Later, as operator-installed options:** actionlint (correctness plus some workflow security,
  overlaps zizmor), poutine (CI/CD supply chain, but auto-loads repo config that can add custom
  Rego rules and phones home once a day), hadolint and kube-linter (only if trivy is not chosen),
  bandit or ruff's `S` rules for Python, brakeman for Rails (its license forbids "commercial"
  use, so it must never be bundled in the image, §6.3), and opengrep (§4.5) as a possible
  replacement for semgrep that would remove the image's need for Python.
- **Not at all:** grype and osv-scalibr (they duplicate osv-scanner), syft (produces SBOMs, not
  findings), tfsec (deprecated in favour of trivy), checkov (Python ≤3.12 per its README; repo
  config is auto-loaded and can point at Python custom checks; Helm and Kustomize scans run
  `helm template --dependency-update` and `kustomize build` with remote fetches allowed by
  default), KICS (no release binaries), kubescape (overlap; network-dependent artifacts),
  trufflehog (AGPL-3.0, overlaps gitleaks, and by default sends found credentials to third-party
  APIs to verify them), OpenSSF Scorecard (scores a hosted repository through the GitHub API with
  a token; it does not review a PR), pip-audit and npm audit (they resolve or submit dependency
  trees through package managers; pip-audit's own advice is "If you wouldn't `pip install` it,
  you should not `pip audit` it"), njsscan and eslint-plugin-security (njsscan is built on
  semgrep; ESLint loads a JavaScript config file from the repo), cargo-audit and OWASP
  dependency-check (osv-scanner covers them; dependency-check needs a JVM and an NVD API key),
  go-licenses and licensee (license, not security), Bearer (Elastic License 2.0 forbids
  providing it "as a hosted or managed service"), CodeQL (its license only permits analysis of
  OSI-licensed codebases). **Judgement.**
- **DAST is out of scope** (nuclei, ZAP and similar): Argus reviews code and repositories, it does
  not probe live targets, and scanning a target the PR names would turn a review into outbound
  attack traffic chosen by the PR author.
- **"Optional" changes ADR 0013's contract, and the docs catalog needs a static list.** If Tools
  are registered only when their binary is on `PATH`, then `argus doctor --binaries`, which
  derives its list from the registry
  ([`pkg/doctor/doctor.go:131-150`](../../pkg/doctor/doctor.go)), would pass vacuously for any
  missing binary. The fix is to separate a static **catalog** (every Tool Argus knows, with its
  metadata) from the live **registry** (the Tools present on this host), and to give the image
  its own manifest (§8.1, §8.2). **Judgement.**

---

## 1. What Argus has today

### 1.1 How a scanner Tool is built

| Part | Where | What it does |
| --- | --- | --- |
| `Requirement`, `Requirer` | [`pkg/tool/requires.go:9-19`](../../pkg/tool/requires.go) | `Requirement{Binary, InstallHint}`; a Tool that shells out implements `Requires()` so `argus doctor` can check `PATH`. |
| Runner | [`pkg/security/exec.go:11-29`](../../pkg/security/exec.go) | `exec.CommandContext` with `cmd.Dir = dir` and no `cmd.Env`, so the child inherits the full process environment. Combined stdout+stderr. |
| Target | [`pkg/security/target.go:34-74`](../../pkg/security/target.go) | Resolves the scan directory: the Session root, or an absolute caller-supplied `path` inside it. |
| `run_semgrep` | [`pkg/security/semgrep.go:49-58`](../../pkg/security/semgrep.go) | `semgrep --config <config> --json --quiet <root>`, cwd `root`; `config` is model-supplied and defaults to `auto`. |
| `run_gitleaks` | [`pkg/security/gitleaks.go:47-85`](../../pkg/security/gitleaks.go) | `gitleaks detect --source <root> --report-format json --report-path <tmp>`, cwd `root`. |
| `run_osv_scanner` | [`pkg/security/osv.go:49-86`](../../pkg/security/osv.go) | `osv-scanner --format json --output <tmp> --recursive <root>`, cwd `root`. |
| Registration | [`pkg/daemon/session.go:470-490`](../../pkg/daemon/session.go) | All three are `Expose`d unconditionally, whether or not the binary is installed. |
| doctor | [`pkg/doctor/doctor.go:251-297`](../../pkg/doctor/doctor.go), [`cmd/doctor.go:158-172`](../../cmd/doctor.go) | Tool-derived binaries are `SeverityOptional` (doctor.go:280); `--binaries` promotes every one to required (doctor.go:144-149). `doctorRegistry` is a separate hand-maintained list. |
| Image | [`Dockerfile:6-9, 35-48`](../../Dockerfile) | `python:3.13-slim`; semgrep via pip; gitleaks and osv-scanner copied from their official images. |

### 1.2 Constraints from the ADRs

1. **Fixed surface, no free flags** ([ADR 0006](../adr/0006-no-generic-shell-tool.md)). Each new
   Tool exposes structured arguments, validated in Go. That rules out "pass-through flags" Tools,
   and it is also why config files matter (§2.1): a config file is a flag bundle the Tool did not
   choose.
2. **Batteries-included image** ([ADR 0013](../adr/0013-batteries-included-runtime-image.md)).
   Inside the official image "optional" does not exist; `doctor --binaries` gates CI
   ([`.github/workflows/ci.yml:61-62`](../../.github/workflows/ci.yml)) and release
   ([`.github/workflows/release.yml:68-69`](../../.github/workflows/release.yml)).
3. **Controlled egress** ([ADR 0017](../adr/0017-full-context-in-controlled-egress-out.md)).
   Scanner output enters the model's context and is untrusted content.
4. **Isolation for untrusted code** ([ADR 0019](../adr/0019-untrusted-code-review-filesystem-isolation.md)).
   Phase 1: fixed trusted semgrep ruleset, no `auto`. Phase 2: read-only checkout, no `~/.argus`,
   no network, resource limits. Observed while reading: `run_semgrep` still defaults to `auto`
   ([`semgrep.go:54-57`](../../pkg/security/semgrep.go)), and semgrep refuses `auto` unless
   metrics are on
   ([`scan.py:960-963`](https://github.com/semgrep/semgrep/blob/v1.180.0/cli/src/semgrep/commands/scan.py#L960-L963)).
5. **Automatic reviews are least-privilege** ([ADR 0018](../adr/0018-automatic-reviews-are-least-privilege.md)).
   There is already precedent for a Service-triggered review getting a smaller tool set (no
   `write_context`).
6. **Credentials stay where they are** ([ADR 0024](../adr/0024-credentials-do-not-cross-the-network.md)).
   Tools that need a GitHub token (Scorecard, zizmor online mode, poutine `analyze_repo`) collide
   with this unless the token is the daemon's own.
7. **The guide is Starlight source** ([ADR 0022](../adr/0022-user-guide-is-self-contained-starlight-source.md)).
   A generated catalog page lives in `docs/guide/`, may link to third-party docs with absolute
   URLs, and must not link into this repo's source or ADRs.

---

## 2. Cross-cutting findings (apply to every tool, existing ones included)

### 2.1 Repo-supplied configuration and in-code suppressions

Many scanners read configuration from the working directory or the scanned tree. Argus sets the
working directory to the scanned tree ([`exec.go:23`](../../pkg/security/exec.go)), so the PR
author controls that configuration. Most also honour inline "ignore" comments, which the PR author
also writes.

| Tool | Auto-loaded repo config | Inline suppression | Override that exists |
| --- | --- | --- | --- |
| semgrep *(existing)* | `.semgrepignore` in "repository's root directory or your project's working directory" ([docs](https://docs.semgrep.dev/ignoring-files-folders-code)) | `nosemgrep` | `--disable-nosem` ([scan.py:243](https://github.com/semgrep/semgrep/blob/v1.180.0/cli/src/semgrep/commands/scan.py#L243)) |
| gitleaks *(existing)* | `(target path)/.gitleaks.toml`; `.gitleaksignore` (default `.`) | `gitleaks:allow` | `--config`, `--gitleaks-ignore-path`, `--ignore-gitleaks-allow` ([README:161-173](https://github.com/gitleaks/gitleaks/blob/v8.30.1/README.md#L161-L173)) |
| osv-scanner *(existing)* | `osv-scanner.toml` next to each scanned lockfile, e.g. `IgnoredVulns` | — | `--config=/path` overrides all of them ([configuration.md:9, 23](https://github.com/google/osv-scanner/blob/v2.6.0/docs/configuration.md#L9-L23)) |
| gosec | none auto-loaded (`-conf` is explicit) | `#nosec`, `//gosec:disable` | `-nosec=true` ([README:534-541](https://github.com/securego/gosec/blob/v2.29.0/README.md#L534-L541)) |
| staticcheck | `staticcheck.conf` per package subtree, merged downward ([docs](https://staticcheck.dev/docs/configuration/)) | `//lint:ignore`, `//lint:file-ignore` | not verified |
| golangci-lint | `.golangci.{yml,yaml,toml,json}` from the first analyzed path up to the root ([docs](https://golangci-lint.run/docs/configuration/file/)) | `//nolint` | not verified |
| zizmor | `.github/zizmor.yml`, `zizmor.yml`; can disable rules and ignore findings ([docs](https://docs.zizmor.sh/configuration/)) | `# zizmor: ignore[rule]` | `--no-config`, `--no-ignores` |
| actionlint | `.github/actionlint.yaml` ([config.md:12](https://github.com/rhysd/actionlint/blob/v1.7.12/docs/config.md#L12)); `paths.*.ignore` regexes (config.md:52-59) | — | `-config-file` ([command.go:141](https://github.com/rhysd/actionlint/blob/v1.7.12/command.go#L141)) |
| poutine | `.poutine.yml` (cwd) or `.github/poutine.yml`; can `include` custom Rego rules ([README:133-140](https://github.com/boostsecurityio/poutine/blob/v1.1.6/README.md#L133-L140)) | — | `--config` |
| trivy | `trivy.yaml` from cwd; `.trivyignore`; `trivy-secret.yaml` | — | `--config ""`, `--ignorefile ""`, `--secret-config ""` ([configuration/index.md:28-46](https://github.com/aquasecurity/trivy/blob/v0.75.0/docs/guide/configuration/index.md#L28-L46)) |
| grype / syft | `./.grype.yaml`, `./.syft.yaml` (cwd) ([grype](https://oss.anchore.com/docs/reference/grype/configuration/), [syft](https://oss.anchore.com/docs/reference/syft/configuration/)) | — | explicit `-c` |
| checkov | `.checkov.yaml` in the scanned directory, then cwd ([README:409-416](https://github.com/bridgecrewio/checkov/blob/3.3.26/README.md#L409-L416)) | `checkov:skip` | `--config-file` |
| KICS | `kics.config` in the project root ([configuration-file.md:87-89](https://github.com/Checkmarx/kics/blob/v2.2.0/docs/configuration-file.md#L87-L89)) | yes (not checked) | `--config` |
| hadolint | `$PWD/.hadolint.yaml` ([README:213-217](https://github.com/hadolint/hadolint/blob/v2.15.1/README.md#L213-L217)) | `# hadolint ignore=` (README:357-363) | `--config`; not verified for inline |
| kube-linter | `.kube-linter.yaml` in cwd; can set `doNotAutoAddDefaults` ([configuring-kubelinter.md:8-14, 33-40](https://github.com/stackrox/kube-linter/blob/v0.8.3/docs/configuring-kubelinter.md#L8-L40)) | annotations (not checked) | `--config` |
| bandit | `.bandit` with `-r` ([main.py:57-70](https://github.com/PyCQA/bandit/blob/1.9.4/bandit/cli/main.py#L57-L70)) | `# nosec` | `--ignore-nosec` (main.py:333) |
| ruff | closest `pyproject.toml` / `ruff.toml` per file ([docs](https://docs.astral.sh/ruff/configuration/)) | `# noqa` | `--isolated` ("Ignore all configuration files") |
| brakeman | `./config/brakeman.yml`; `config/brakeman.ignore` ([OPTIONS.md:182, 248](https://github.com/presidentbeef/brakeman/blob/v8.1.0/OPTIONS.md#L182-L250)) | — | `-c`, `-i` |
| cargo-audit | `.cargo/audit.toml`, including the advisory DB `url` and `ignore` ([audit.toml.example](https://github.com/rustsec/rustsec/blob/cargo-audit/v0.22.2/cargo-audit/audit.toml.example)) | — | not verified |
| npm | project `.npmrc`, which can set the registry audit data is POSTed to ([npmrc docs](https://docs.npmjs.com/cli/v11/configuring-npm/npmrc)) | — | not verified |
| ESLint | `eslint.config.{js,mjs,cjs,ts}` searched from each linted file upward ([docs](https://eslint.org/docs/latest/use/configure/configuration-files)) | `eslint-disable` | `--no-config-lookup` ([CLI](https://eslint.org/docs/latest/use/command-line-interface)) |

**Judgement.** Two kinds of harm come from this, and they need different answers:

- **Config that changes what runs** (checkov `external-checks-dir` → Python policies; poutine
  `include` → Rego; ESLint's config is a JavaScript module the tool imports; golangci-lint's Go
  plugins; cargo-audit's DB `url`; npm's registry). On an untrusted PR this must never be loaded.
  Every Tool should pass the "ignore repo config" flag unconditionally, and a tool without one
  should run with a cwd outside the checkout.
- **Config and comments that hide findings** (`IgnoredVulns`, `#nosec`, `rules.*.disable`). On a
  trusted repo they are the team's legitimate triage. On an untrusted PR they are attacker
  input. **Suggestion:** ignore them on Service-triggered reviews (ADR 0018) and honour them for a
  Person's review. Either way, report them as a signal: a PR that *adds* a suppression next to
  the code it changes deserves attention.

### 2.2 Environment inheritance

`ExecRunner` sets no `cmd.Env` ([`exec.go:22-24`](../../pkg/security/exec.go)), so each scanner
inherits the daemon's environment, which includes everything in `~/.argus/.env`
([`daemon.go:140-144`](../../pkg/daemon/daemon.go)). Concretely:

- zizmor switches to online mode if `GH_TOKEN`, `GITHUB_TOKEN` or `ZIZMOR_GITHUB_TOKEN` is set
  ([usage](https://docs.zizmor.sh/usage/)).
- gosec calls an external LLM for fix suggestions when `GOSEC_AI_API_KEY` / `GOSEC_AI_PROVIDER`
  are set ([README:391-425](https://github.com/securego/gosec/blob/v2.29.0/README.md#L391-L425)).
- gitleaks reads its config from `GITLEAKS_CONFIG` / `GITLEAKS_CONFIG_TOML` before the repo file
  ([README:161-165](https://github.com/gitleaks/gitleaks/blob/v8.30.1/README.md#L161-L165)).
- semgrep reads `SEMGREP_SEND_METRICS`
  ([scan.py:134-138](https://github.com/semgrep/semgrep/blob/v1.180.0/cli/src/semgrep/commands/scan.py#L134-L138)).
- Go tools obey `GOTOOLCHAIN`, `GOFLAGS`, `GOPROXY`, `CGO_ENABLED`, `GOPACKAGESDRIVER` (§8.3).

A scanner binary that is itself compromised (§4.1) would also read the LLM API keys and the
GitHub App key path from that environment. **Judgement:** give each Tool an explicit environment:
`PATH`, `HOME` pointed at a scratch directory, `TMPDIR`, plus a per-Tool allowlist of the
variables it legitimately needs (for example the Go profile in §8.3).

### 2.3 Network and telemetry defaults

| Tool | Default network at scan time | How to turn it off |
| --- | --- | --- |
| semgrep *(existing)* | `--config auto` fetches the registry and requires metrics | fixed local ruleset (ADR 0019 Phase 1) |
| osv-scanner *(existing)* | queries the OSV API | `--offline --download-offline-databases` ([README:101-106](https://github.com/google/osv-scanner/blob/v2.6.0/README.md#L101-L106)) |
| govulncheck | vuln.go.dev, sending "only module paths with vulnerabilities already known to the database" ([doc.go:10-16](https://github.com/golang/vuln/blob/v1.8.0/cmd/govulncheck/doc.go#L10-L16)) | `-db file:///…` (a local mirror) |
| Go-based tools | module downloads through `GOPROXY`, toolchain downloads | §8.3 |
| zizmor | none without a token | `--offline` / `ZIZMOR_OFFLINE` |
| poutine | once-a-day version check that "reports the current poutine version, an anonymous instance identifier … and a count of CLI invocations" ([README:125-129](https://github.com/boostsecurityio/poutine/blob/v1.1.6/README.md#L125-L129)) | `--disable-version-check` / `POUTINE_DISABLE_VERSION_CHECK=1` |
| trivy | DB pulls from `mirror.gcr.io` / `ghcr.io`; Maven repositories, including ones declared in the scanned `pom.xml`; usage telemetry; `check.trivy.dev` | `--skip-db-update`, `--skip-java-db-update`, `--offline-scan`, `--disable-telemetry`, `--skip-version-check` (§4.1) |
| grype / syft | DB update and app update checks on by default; grype `search-maven-upstream: true` | `GRYPE_DB_AUTO_UPDATE`, `GRYPE_CHECK_FOR_APP_UPDATE`, … ([grype config](https://oss.anchore.com/docs/reference/grype/configuration/)) |
| trufflehog | verifies every candidate secret against its provider's API | `--no-verification`; `--no-update` ([README:474, 490](https://github.com/trufflesecurity/trufflehog/blob/v3.99.2/README.md#L474-L490)) |
| checkov | Prisma Cloud downloads when keyed; Helm and Kustomize remote fetches | `--skip-download`; `CHECKOV_HELM_ALLOWED_REMOTE_REPOS`, `CHECKOV_KUSTOMIZE_ALLOWED_REMOTE_PREFIXES` |
| npm audit | always: POSTs the dependency tree to the configured registry | none |

**Judgement.** ADR 0019 Phase 2 says "no network". Every vulnerability scanner needs a database,
so Phase 2 implies a DB-management story (pre-fetched, read-only DBs mounted into the sandbox and
refreshed by the daemon outside it). That is worth deciding before adding more DB-backed tools.

### 2.4 The scanners' own supply chain

Trivy's advisory GHSA-69fq-xp46-6x23 (published 2026-03-21) reports that on 2026-03-19 "a threat
actor used compromised credentials to publish a malicious Trivy v0.69.4 release" and to
force-push 76 of 77 `trivy-action` tags to "credential-stealing malware", followed by malicious
Docker Hub images `v0.69.5`/`v0.69.6` on 2026-03-22. Images referenced by digest, binaries built
from source, and the official Homebrew formula were not affected
([advisory](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)).
Several candidates publish signatures (`.sigstore.json` bundles in gosec, poutine and kube-linter
releases; cosign instructions for trufflehog,
[README:144-178](https://github.com/trufflesecurity/trufflehog/blob/v3.99.2/README.md#L144-L178);
`.sig`/`.cert` for opengrep; from `gh api …/releases/tags/<tag>`).

**Judgement.** The Dockerfile pins tags (`ghcr.io/gitleaks/gitleaks:${GITLEAKS_VERSION}`,
[`Dockerfile:14-15`](../../Dockerfile)), not digests. For a catalog of operator-installed tools,
the install guidance should point to each project's verification instructions, and the image
should move to digest pins with signature verification in CI.

---

## 3. Go tools

### 3.1 govulncheck

- **Purpose.** "Govulncheck reports known vulnerabilities that affect Go code. It uses static
  analysis of source code or a binary's symbol table to narrow down reports to only those that
  could affect the application"
  ([doc.go:6-8](https://github.com/golang/vuln/blob/v1.8.0/cmd/govulncheck/doc.go#L6-L8)).
  Source mode needs a `go.mod` ([source.go:28-30](https://github.com/golang/vuln/blob/v1.8.0/internal/scan/source.go#L28-L30)).
  Binary mode analyses a compiled Go binary (doc.go:48-58).
- **License, steward, status.** BSD-3-Clause; the Go team (`golang/vuln`); `v1.8.0` tagged
  2026-09-08. GitHub *releases* stop at `v1.1.4` (2025-01-13); later versions are tags only
  (`gh api`).
- **Distribution.** No release binaries. Install with
  `go install golang.org/x/vuln/cmd/govulncheck@latest`
  ([pkg.go.dev](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)). Source mode needs a Go
  toolchain at runtime: "that configuration is the Go version specified by the 'go' command found
  on the PATH" (doc.go:18-22), and it shells out to `go env GOVERSION`
  ([run.go:95](https://github.com/golang/vuln/blob/v1.8.0/internal/scan/run.go#L95)). Packages are
  loaded with `go/packages` (source.go:31-37). **Image fit:** needs a full Go distribution added
  to `python:3.x-slim`.
- **Output.** `-format` takes `text`, `json`, `sarif`, `openvex`
  ([flags.go:46](https://github.com/golang/vuln/blob/v1.8.0/internal/scan/flags.go#L46)). JSON is
  streaming, and its schema lives in an `internal/` package (doc.go:65), so it carries no stated
  stability promise. With `json`, `sarif` or `openvex`, govulncheck exits 0 regardless of findings
  (doc.go:77-80), which suits Argus's Runner.
- **Network.** Default DB `https://vuln.go.dev` (flags.go:42); `-db` points at any database
  implementing the published spec (doc.go:14-16). Module downloads go through the Go toolchain
  (§8.3).
- **Untrusted-PR risk: high without the Go profile.** Everything in §8.3 applies. Mitigations
  work because govulncheck passes `cfg.env` through to `packages.Config.Env` (source.go:35), so
  the Tool controls the environment.
- **Overlap.** osv-scanner already runs Go call analysis with the govulncheck library by default
  when `go` is on `PATH`
  ([scan-source.md:148-157](https://github.com/google/osv-scanner/blob/v2.6.0/docs/scan-source.md#L148-L157)),
  and the OSV database includes the Go vulnerability database's entries (**not verified in this
  pass**). govulncheck's distinct value is call traces (`-show traces`), binary mode, and OpenVEX.
- **Links.** Docs: [go.dev/doc/tutorial/govulncheck](https://go.dev/doc/tutorial/govulncheck),
  [pkg.go.dev command docs](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck). Install: same
  pkg.go.dev page (`go install`), and [go.dev/doc/install](https://go.dev/doc/install) for the
  toolchain.
- **Tags.** `sca`, `go`.

### 3.2 gosec

- **Purpose.** Go security checker over the Go AST and type information, with rule families
  including `G7xx` "taint analysis rules (SQL injection, command injection, path traversal, SSRF,
  XSS, log, SMTP injection…)"
  ([README:214-230](https://github.com/securego/gosec/blob/v2.29.0/README.md#L214-L230); full list
  in [RULES.md](https://github.com/securego/gosec/blob/v2.29.0/RULES.md)).
- **License, steward, status.** Apache-2.0; `securego` org; `v2.29.0` released 2026-08-26, last
  push 2026-10-09 (`gh api`).
- **Distribution.** "gosec requires Go 1.25 or newer" and installs with `go install`
  ([README:179-185](https://github.com/securego/gosec/blob/v2.29.0/README.md#L179-L185)). Release
  archives exist for linux/darwin/windows on amd64/arm64 with sigstore bundles, and a GHCR image
  `ghcr.io/securego/gosec` (README:45; `gh api …/releases/tags/v2.29.0`). The binary is static,
  but it loads packages with `go/packages` and the default load mode includes
  `NeedCompiledGoFiles`, `NeedTypes`, `NeedTypesInfo` and `NeedModule`
  ([analyzer.go:42, 55-63](https://github.com/securego/gosec/blob/v2.29.0/analyzer.go#L55-L63)),
  so it needs the `go` command at runtime. It also uses `go list` to read the module's Go version
  (README:340-346). **Image fit:** binary copy plus the Go toolchain.
- **Output.** `text`, `json`, `yaml`, `csv`, `junit-xml`, `html`, `sonarqube`, `golint`, `sarif`
  (README:608-611). Exit 1 on findings unless `-no-fail` (README:200-204).
- **Network.** None for analysis, apart from module downloads by the toolchain. The opt-in AI fix
  feature calls Atlas Cloud, Gemini, Claude, OpenAI or a custom base URL when configured through
  flags or `GOSEC_AI_*` variables (README:391-425).
- **Untrusted-PR risk: high without the Go profile** (§8.3). README:348-358 also suggests
  `go mod tidy` / `go mod download` when dependencies are missing. The Tool must not do that on an
  untrusted tree. `-nosec=true` makes the scan ignore in-code `#nosec` (README:534-541).
- **Overlap.** semgrep's Go rules cover some of the same patterns. gosec's type-aware taint rules
  are the reason to add it. **Not verified:** a rule-by-rule comparison with the semgrep ruleset
  Argus will pin under ADR 0019 Phase 1.
- **Links.** Docs: [README](https://github.com/securego/gosec#readme),
  [RULES.md](https://github.com/securego/gosec/blob/master/RULES.md). Install:
  [README "Local Installation"](https://github.com/securego/gosec#local-installation).
- **Tags.** `sast`, `go`.

### 3.3 staticcheck (security-relevant checks only)

- **Purpose.** A Go linter whose check categories are `SA` (correctness), `S` (simplifications),
  `ST` (style), `QF` (quick fixes) ([checks](https://staticcheck.dev/docs/checks/)). Reading the
  check titles, the only ones with a plausible security angle are SA1019 (deprecated APIs),
  SA4030 ("Ineffective attempt at generating random number"), SA9002 (non-octal `os.FileMode`),
  SA1006 (`Printf` with dynamic first argument), SA1005 (invalid first argument to
  `exec.Command`), and SA9007 (deleting a directory that shouldn't be deleted). That is my
  title-level reading, not a classification staticcheck makes.
- **License, steward, status.** MIT; Dominik Honnef (personal account); `2026.2.1` released
  2026-08-21.
- **Distribution.** `go install honnef.co/go/tools/cmd/staticcheck@latest` or release binaries
  ([getting started](https://staticcheck.dev/docs/getting-started/)). It works "much like `go
  build` or `go vet`", so it needs the Go toolchain at runtime.
- **Output.** The docs list `text`, `stylish`, `json`
  ([formatters](https://staticcheck.dev/docs/running-staticcheck/cli/formatters/)). The source
  also accepts `sarif` and `binary`
  ([lintcmd/cmd.go:457, 692-702](https://github.com/dominikh/go-tools/blob/2026.2.1/lintcmd/cmd.go#L457)).
  No stability statement for JSON.
- **Untrusted-PR risk.** The same as the other Go tools (§8.3), plus `staticcheck.conf` files
  anywhere in the package tree change which checks run.
- **Overlap.** gosec and semgrep cover the security-relevant subset better.
- **Links.** Docs: [staticcheck.dev/docs](https://staticcheck.dev/docs/). Install:
  [getting started](https://staticcheck.dev/docs/getting-started/).
- **Tags.** `sast`, `go`. **Judgement: do not wrap.**

### 3.4 capslock

- **Purpose.** "A capability analysis CLI for Go packages that informs users of which privileged
  operations a given package can access", by following transitive calls into privileged standard
  library operations ([README:3-6](https://github.com/google/capslock/blob/v0.3.3/README.md#L3-L6)).
  The caveats document that `os/exec`, `plugin`, `unsafe`, `reflect` and `go:linkname` are
  reported as capabilities of their own because they cannot be followed
  ([caveats.md](https://github.com/google/capslock/blob/v0.3.3/docs/caveats.md)).
- **License, steward, status.** BSD-3-Clause; Google; tag `v0.3.3` (2026-08-25), no GitHub
  releases; pre-1.0.
- **Distribution.** `go install github.com/google/capslock/cmd/capslock@latest` only
  (README:35-37). Needs the Go toolchain (it loads packages with `go/packages`,
  [capslock.go:236-245](https://github.com/google/capslock/blob/v0.3.3/cmd/capslock/capslock.go#L236-L245)).
- **Output.** `-output` = `json`, `m`, `package`, `v`, `graph`, `compare` (capslock.go:36). The
  JSON follows a protobuf definition in the repo (**not verified for stability**).
- **Network.** If the requested packages are not in the current module, it creates a temporary
  module and `go get`s them (capslock.go:165-188), which is network plus downloads. A
  `-force_local_module` flag disables that (capslock.go:49).
- **Untrusted-PR risk: high without the Go profile** (§8.3).
- **Overlap.** None among Argus's tools. It answers a different question ("what can this
  dependency do?", not "is it known-vulnerable?").
- **Links.** Docs: [README](https://github.com/google/capslock#readme),
  [docs/](https://github.com/google/capslock/tree/main/docs). Install: README (`go install`).
- **Tags.** `supply-chain`, `go`. **Judgement: later.** Most valuable as "capability diff between
  base and head when `go.mod` changes", which needs two analyses per review.

### 3.5 golangci-lint

- **Purpose.** A Go linter runner that aggregates many linters (gosec and staticcheck among them).
- **License, status.** GPL-3.0; `golangci` org; `v2.14.0` released 2026-09-24.
- **Config.** It looks for `.golangci.{yml,yaml,toml,json}` and "searches for config files in all
  directories from the directory of the first analyzed path up to the root", falling back to the
  home directory ([config file docs](https://golangci-lint.run/docs/configuration/file/)). The
  config can load Go plugins: `linters.settings.custom.<name>.path: /example.so`
  ([Go plugins](https://golangci-lint.run/docs/plugins/go-plugins/)). How a relative `path` is
  resolved is **not stated** on that page.
- **Untrusted-PR risk: high.** A repo-supplied config that loads a native plugin would be code
  execution. Whether a relative path to a `.so` committed in the PR would load is **not verified**.
- **Links.** Docs: [golangci-lint.run](https://golangci-lint.run/). Install:
  [local install](https://golangci-lint.run/docs/welcome/install/local/).
- **Tags.** `sast`, `go`. **Judgement: do not wrap.** Wrap the specific linters instead.

### 3.6 go-licenses

- **Purpose.** Reports the licenses of a Go binary's dependencies as CSV
  ([README:39-90](https://github.com/google/go-licenses/blob/v2.0.1/README.md#L39-L90)). "This is
  not an officially supported Google product" (README:3).
- **License, status.** Apache-2.0; `v2.0.1` released 2025-09-08.
- **Distribution.** `go install` (README:33); needs the Go toolchain.
- **Overlap.** osv-scanner does license scanning with deps.dev data (`--licenses`,
  [README:87-98](https://github.com/google/osv-scanner/blob/v2.6.0/README.md#L87-L98)).
- **Tags.** `license`, `go`. **Judgement: do not wrap.**

---

## 4. Multi-language scanners

### 4.1 trivy

- **Purpose.** Targets include filesystems and repositories; scanners cover dependencies (SBOM),
  CVEs, "IaC issues and misconfigurations", secrets and licenses
  ([README:14-31](https://github.com/aquasecurity/trivy/blob/v0.75.0/README.md#L14-L31)).
- **License, steward, status.** Apache-2.0; Aqua Security; `v0.75.0` released 2026-10-01.
  Telemetry is documented as an Aqua product: "Trivy is an Aqua Security product and adheres to
  the company's privacy policy"
  ([telemetry.md:29](https://github.com/aquasecurity/trivy/blob/v0.75.0/docs/guide/advanced/telemetry.md#L29)).
- **Distribution.** Static Go binary; `brew install trivy`, `docker run aquasec/trivy`, release
  binaries (README:41-46). **Image fit:** `COPY --from` like gitleaks, pinned by digest.
- **Output.** Table, JSON, SARIF 2.1.0, templates, CycloneDX/SPDX
  ([reporting.md:3-8, 262, 455-466](https://github.com/aquasecurity/trivy/blob/v0.75.0/docs/guide/configuration/reporting.md#L455-L466)).
- **Network.** Vulnerability DB, Java DB and checks bundle are OCI images pulled from
  `mirror.gcr.io/aquasec` then `ghcr.io/aquasecurity`
  ([db.md:26-28, 41-42](https://github.com/aquasecurity/trivy/blob/v0.75.0/docs/guide/configuration/db.md#L41-L42)),
  skippable with `--skip-db-update` / `--skip-java-db-update` (db.md:84-85). The checks bundle is
  also embedded as a fallback ([air-gap docs](https://trivy.dev/docs/latest/advanced/air-gap/)).
  Usage telemetry is on by default and disabled with `--disable-telemetry`, but "Trivy still
  connects to `check.trivy.dev` … unless the `--skip-version-check` flag is specified as well"
  (telemetry.md:3, 33, 41-43).
- **Untrusted-PR risk: medium.** Trivy parses files and does not build or run code. Three
  repo-controlled inputs matter:
  1. `trivy.yaml` loaded from cwd "independently of the scan target" (configuration/index.md:28,
     46). It can name Rego checks and data (`--config-check`, `--config-data`,
     [config-file.md:506-511](https://github.com/aquasecurity/trivy/blob/v0.75.0/docs/guide/references/configuration/config-file.md#L506-L511)).
     Pass `--config ""`.
  2. For `pom.xml`, trivy fetches missing artifacts from "repositories from pom files" and Maven
     Central ([java.md:62-80](https://github.com/aquasecurity/trivy/blob/v0.75.0/docs/guide/coverage/language/java.md#L62-L80)),
     so a PR can make the Argus host contact a URL it chooses. `--offline-scan` disables this.
  3. Ignore files (`.trivyignore`, `.trivyignore.yaml`). Pass `--ignorefile ""`.

  Separately, GHSA-mcj4-mphf-j9ff (2026-06-15) is "Path traversal via a crafted vulnerability
  database or other downloaded artifacts" (`gh api …/security-advisories`). That is another reason
  to control where DBs come from.
- **Overlap.** `vuln` overlaps osv-scanner, `secret` overlaps gitleaks, `license` overlaps
  osv-scanner `--licenses`. `misconfig` overlaps nothing Argus has today.
- **Links.** Docs: [trivy.dev/docs/latest](https://trivy.dev/docs/latest/). Install:
  [installation](https://trivy.dev/docs/latest/getting-started/installation/).
- **Tags.** `iac`, `container`, `kubernetes`, `terraform`, `dockerfile` (and `sca`, `secrets`,
  `license` if more scanners are enabled). **Judgement:** wrap as `run_trivy_config` with
  `--scanners misconfig` fixed in Go, plus the five "off" flags above.

### 4.2 grype

- **Purpose.** Vulnerability scanner for images, filesystems and SBOMs
  ([README](https://github.com/anchore/grype/blob/v0.120.1/README.md#L38-L82)).
- **License, status.** Apache-2.0; Anchore; `v0.120.1` released 2026-10-06.
- **Distribution.** Install script, Homebrew, Docker
  ([README:38-42](https://github.com/anchore/grype/blob/v0.120.1/README.md#L38-L42)). Static Go
  binary (inferred from the Go repo; not checked in release assets).
- **Output.** The config docs list `table, template, json, cyclonedx`; the source also has a
  `sarif` presenter (`grype/presenter/sarif` at the pinned tag).
- **Network.** DB auto-update from `https://grype.anchore.io/databases` and an app-update check,
  both on by default; Maven upstream search on by default
  ([configuration](https://oss.anchore.com/docs/reference/grype/configuration/)).
- **Untrusted-PR risk.** Low to medium: file parsing, plus `./.grype.yaml` from cwd.
- **Overlap.** Same job as osv-scanner, with a different database.
- **Tags.** `sca`, `multi-language`. **Judgement: do not wrap.** Two SCA scanners with different
  databases mostly produce disagreements for the model to reconcile.

### 4.3 syft

- **Purpose.** Generates SBOMs (CycloneDX, SPDX, Syft JSON) from images, filesystems and archives
  ([README:22-26](https://github.com/anchore/syft/blob/v1.54.1/README.md#L22-L26)).
- **License, status.** Apache-2.0; Anchore; `v1.54.1` released 2026-10-06.
- **Network.** App-update check on by default; remote license lookups present but blank by default
  in the sample config ([configuration](https://oss.anchore.com/docs/reference/syft/configuration/)).
- **Tags.** `sbom`. **Judgement: do not wrap.** An inventory is not a finding, and osv-scanner
  already extracts inventories.

### 4.4 osv-scalibr

- **Purpose.** Google's "Software Composition Analysis Library"; osv-scanner is its CLI front-end
  ([osv-scanner README:16, 26](https://github.com/google/osv-scanner/blob/v2.6.0/README.md#L16-L26)).
  A wrapper binary exists (`go install …/binary/scalibr@latest`), and "Not all OSV-SCALIBR
  functionality is available via OSV-Scanner yet"
  ([scalibr README:29-47](https://github.com/google/osv-scalibr/blob/v0.5.3/README.md#L29-L47)).
- **License, status.** Apache-2.0; `v0.5.3` released 2026-09-22; pre-1.0.
- **Tags.** `sca`. **Judgement: do not wrap.** Use osv-scanner, and upgrade the pinned version
  (`v2.4.0` in the image vs `v2.6.0` current).

### 4.5 opengrep (a semgrep fork)

- **Purpose.** "A fork of Semgrep, under the LGPL 2.1 license", forked from Semgrep v1.100.0,
  "Compatible with Semgrep rules", JSON and SARIF output
  ([README:12, 25-26, 278](https://github.com/opengrep/opengrep/blob/v1.30.2/README.md#L12-L26)).
- **Distribution.** "Self-contained binaries via Nuitka (no Python required)" (README:48). Release
  assets include `opengrep_manylinux_{x86,aarch64}` and `opengrep_musllinux_*` with `.sig`/`.cert`
  (`gh api …/releases/tags/v1.30.2`).
- **License, status.** LGPL-2.1; `opengrep` org; `v1.30.2` released 2026-10-07.
- **Overlap.** It replaces semgrep rather than adding to it.
- **Links.** Docs: [opengrep.dev](https://opengrep.dev/). Install:
  [README "Installation"](https://github.com/opengrep/opengrep#installation).
- **Tags.** `sast`, `multi-language`. **Judgement: not a new Tool, but a candidate for the
  existing `run_semgrep` slot.** ADR 0013 chose a Python base image *because* semgrep is "only
  through Python channels". A static opengrep would remove that reason. Whether its rule
  compatibility holds for the ruleset Argus pins (ADR 0019 Phase 1) is **not verified**.

---

## 5. CI/CD and repository posture

### 5.1 zizmor

- **Purpose.** "A static analysis tool for your CI/CD" that finds and fixes security issues in
  "GitHub Actions, Dependabot, and pre-commit" ([docs](https://docs.zizmor.sh/)).
- **License, steward, status.** MIT; `zizmorcore` org; `v1.30.1` released 2026-09-09, pushed
  2026-10-09.
- **Distribution.** `pip install zizmor`, `pipx`, `uv`, Homebrew, `cargo install --locked
  zizmor`, `ghcr.io/zizmorcore/zizmor`. Prebuilt binaries are "best-effort"
  ([installation](https://docs.zizmor.sh/installation/)). Release assets include
  `zizmor-x86_64-unknown-linux-gnu.tar.gz` and an aarch64 Linux build (`gh api`). **Image fit:**
  one `pip install` line next to semgrep.
- **Output.** `plain`, `json` (= `json-v1`), `sarif`, `github`. "The JSON format is versioned",
  with a deprecation policy. Exit codes 11-14 encode the highest severity and are suppressed with
  SARIF or `--no-exit-codes` ([usage](https://docs.zizmor.sh/usage/)).
- **Network.** Offline unless `GH_TOKEN` / `GITHUB_TOKEN` / `ZIZMOR_GITHUB_TOKEN` is set;
  `--offline` / `ZIZMOR_OFFLINE` force offline (usage).
- **Untrusted-PR risk: low.** It parses YAML. Repo `zizmor.yml` can disable rules or ignore
  findings, and inline `# zizmor: ignore[...]` exists; `--no-config` and `--no-ignores` neutralise
  both ([configuration](https://docs.zizmor.sh/configuration/)).
- **Overlap.** Partly actionlint's expression-injection check and Scorecard's
  Dangerous-Workflow / Token-Permissions / Pinned-Dependencies. Nothing in Argus today.
- **Links.** Docs: [docs.zizmor.sh](https://docs.zizmor.sh/). Install:
  [installation](https://docs.zizmor.sh/installation/).
- **Tags.** `ci-cd`, `github-actions`. **Judgement: add first among non-Go tools.**

### 5.2 actionlint

- **Purpose.** A linter for GitHub Actions workflows: syntax, expression types, and security
  checks including "Script injection by potentially untrusted inputs", "Hardcoded credentials"
  and "Permissions"
  ([checks.md:21-37, 1034](https://github.com/rhysd/actionlint/blob/v1.7.12/docs/checks.md#L1034)).
- **License, steward, status.** MIT; `rhysd` (personal account); `v1.7.12` released 2026-03-30.
- **Distribution.** Static Go release archives (linux/darwin/freebsd/windows; `gh api`).
  The official Docker image bundles shellcheck and pyflakes
  ([usage.md:269-270](https://github.com/rhysd/actionlint/blob/v1.7.12/docs/usage.md#L269-L270)).
- **Output.** Go-template `-format`; `{{json .}}` gives JSON (usage.md:52-55); SARIF via a
  template file in the repo's testdata (usage.md:113-120). There is no first-class schema.
- **Network.** None documented.
- **Untrusted-PR risk: low.** It runs `shellcheck` and `pyflakes` on `run:` scripts when they are
  on `PATH`; `-shellcheck= -pyflakes=` disables them (usage.md:37-42). Repo
  `.github/actionlint.yaml` can filter errors by regex (config.md:12, 52-59); override with
  `-config-file`.
- **Overlap.** zizmor on the security checks.
- **Links.** Docs: [usage](https://github.com/rhysd/actionlint/blob/main/docs/usage.md),
  [checks](https://github.com/rhysd/actionlint/blob/main/docs/checks.md). Install:
  [install.md](https://github.com/rhysd/actionlint/blob/main/docs/install.md).
- **Tags.** `ci-cd`, `github-actions`. **Judgement: later.**

### 5.3 poutine

- **Purpose.** "Detects misconfigurations and vulnerabilities in the build pipelines of a
  repository" for GitHub Actions and GitLab CI
  ([README:13](https://github.com/boostsecurityio/poutine/blob/v1.1.6/README.md#L13)).
  `analyze_local` scans a checkout; `analyze_repo` / `analyze_org` need a token (README:82-102).
- **License, steward, status.** Apache-2.0; BoostSecurity; `v1.1.6` released 2026-05-22.
- **Distribution.** Homebrew, Docker, release archives with sigstore bundles (README:44-51; `gh api`).
- **Output.** `pretty`, `json`, `sarif` (README:108-109).
- **Network.** Daily version check with an anonymous instance ID and invocation count
  (README:125-129).
- **Untrusted-PR risk: medium.** `.poutine.yml` / `.github/poutine.yml` are auto-discovered, and
  they can `include` custom Rego rules (README:133-152). Pass `--config` to a trusted file and
  `--disable-version-check`.
- **Overlap.** zizmor, largely; poutine adds GitLab CI.
- **Links.** Docs: [boostsecurityio.github.io/poutine](https://boostsecurityio.github.io/poutine/).
  Install: [README](https://github.com/boostsecurityio/poutine#installation).
- **Tags.** `ci-cd`, `github-actions`, `supply-chain`. **Judgement: later**, mostly for GitLab users.

### 5.4 OpenSSF Scorecard

- **Purpose.** Scores a project's security practices (Branch-Protection, Code-Review,
  Dangerous-Workflow, Pinned-Dependencies, Token-Permissions, …)
  ([README:545-566](https://github.com/ossf/scorecard/blob/v5.5.0/README.md#L545-L566)).
- **License, status.** Apache-2.0; OpenSSF; `v5.5.0` released 2026-04-23.
- **Network and credentials.** Uses the GitHub API and needs a token in `GITHUB_AUTH_TOKEN`,
  `GITHUB_TOKEN`, `GH_AUTH_TOKEN` or `GH_TOKEN` (README:273-289). A `--local` flag ("local folder
  to check") exists ([options/flags.go:32-33, 118-120](https://github.com/ossf/scorecard/blob/v5.5.0/options/flags.go#L32-L33)).
  Which checks work in local mode is **not verified**.
- **Output.** `default` and `json` (README:532-534).
- **Tags.** `supply-chain`, `ci-cd`. **Judgement: do not wrap as a scanner.** It assesses a hosted
  repository's settings, not a change. Its workflow checks overlap zizmor, and the token conflicts
  with ADR 0024 unless it is the App's own installation token.

---

## 6. Language-specific SAST

### 6.1 bandit (Python)

- **Purpose.** Python AST security linter.
- **License, steward, status.** Apache-2.0; PyCQA; `1.9.4` released 2026-02-25.
- **Distribution.** `pip install bandit`; SARIF needs the `sarif` extra (`sarif-om`,
  `jschema-to-python`, [setup.cfg:42-44](https://github.com/PyCQA/bandit/blob/1.9.4/setup.cfg#L42-L44)).
  **Image fit:** pip, like semgrep.
- **Output.** `csv`, `custom`, `html`, `json`, `sarif`, `screen`, `text`, `xml`, `yaml`
  ([formatters](https://bandit.readthedocs.io/en/latest/formatters/index.html)).
- **Untrusted-PR risk: low.** It parses and does not import the target. `.bandit` is read with
  `-r` (main.py:57-70); `# nosec` is honoured unless `--ignore-nosec` (main.py:333). YAML/TOML
  config is only read with `-c` ([config](https://bandit.readthedocs.io/en/latest/config.html)).
- **Overlap.** semgrep's Python rules; ruff's `S` rules re-implement many bandit checks
  ([ruff rules, flake8-bandit (S)](https://docs.astral.sh/ruff/rules/#flake8-bandit-s)).
- **Links.** Docs: [bandit.readthedocs.io](https://bandit.readthedocs.io/en/latest/). Install:
  [getting started](https://bandit.readthedocs.io/en/latest/start.html).
- **Tags.** `sast`, `python`. **Judgement: later; prefer ruff `--select S --isolated`** if a
  single static binary matters more than bandit's exact rule set.

### 6.2 ruff (flake8-bandit `S` rules)

- **Purpose.** A Rust Python linter; the `S` family re-implements flake8-bandit rules (e.g. S102
  `exec-builtin`, S105 `hardcoded-password-string`) ([rules](https://docs.astral.sh/ruff/rules/)).
- **License, status.** MIT; Astral; `0.16.10` released 2026-10-01.
- **Output.** Includes `json`, `json-lines`, `sarif`
  ([configuration](https://docs.astral.sh/ruff/configuration/)).
- **Untrusted-PR risk: low** with `--isolated`.
- **Links.** Docs: [rules](https://docs.astral.sh/ruff/rules/). Install:
  [installation](https://docs.astral.sh/ruff/installation/).
- **Tags.** `sast`, `python`.

### 6.3 brakeman (Ruby on Rails)

- **Purpose.** Static analysis for Rails applications.
- **License.** The "Brakeman Public Use License" (Synopsys): "Commercial Uses … require a
  commercial, non-free license". Commercial use includes "Using the Software to provide
  commercial managed/Software-as-a-Service services", "Distributing the Software as a commercial
  product or as part of one" and "Using the Software as a component of a value-added
  service/product". "Using the Software to analyze Licensee's software" is listed as
  non-commercial
  ([LICENSE.md:11, 25-38](https://github.com/presidentbeef/brakeman/blob/v8.1.0/LICENSE.md#L25-L38)).
  GitHub reports the license as `NOASSERTION`.
- **Status.** `v8.1.0` released 2026-09-30.
- **Distribution.** Ruby gem (`gem install brakeman`,
  [install docs](https://brakemanscanner.org/docs/install/)). It needs a Ruby runtime the image
  does not have.
- **Output.** `text`, `html`, `tabs`, `json`, `junit`, `markdown`, `csv`, `codeclimate`, `github`,
  `sarif`, `sonar`; `--compare` diffs two JSON reports
  ([OPTIONS.md:106, 170-174](https://github.com/presidentbeef/brakeman/blob/v8.1.0/OPTIONS.md#L106)).
- **Untrusted-PR risk: low to medium.** It parses Ruby. `./config/brakeman.yml` and
  `config/brakeman.ignore` are read from the app (OPTIONS.md:182, 248).
- **Tags.** `sast`, `ruby`. **Judgement:** catalog it as operator-installed only, with a license
  note; never bundle it in the image. Whether an operator scanning their own code through Argus is
  "analyzing Licensee's software" is a legal question I cannot answer.

### 6.4 njsscan (Node.js)

- **Purpose.** Node.js SAST "using simple pattern matcher from libsast and … semgrep"
  ([README:2](https://github.com/ajinabraham/njsscan/blob/1.0.1/README.md#L2)).
- **License, status.** LGPL-3.0; personal account; `1.0.1` released 2026-09-21.
- **Output.** `--json`, `--sarif` (README:30-38).
- **Tags.** `sast`, `javascript`. **Judgement: do not wrap.** It is a semgrep ruleset with a
  wrapper. If its rules are wanted, add them to the pinned semgrep ruleset.

### 6.5 eslint-plugin-security (JavaScript)

- **Purpose.** ESLint rules for Node security; Apache-2.0; `v4.2.0` released 2026-10-01.
- **Runtime.** Node.js + ESLint + the plugin from npm.
- **Untrusted-PR risk: high unless `--no-config-lookup`.** ESLint config files are
  `eslint.config.{js,mjs,cjs,ts}` that "export an array of configuration objects", found by
  searching from each linted file upward
  ([configuration files](https://eslint.org/docs/latest/use/configure/configuration-files)).
  Loading an exported JS module means running it; that is my inference, and the ESLint page
  carries no warning either way. `--no-config-lookup` "Disables use of configuration from files"
  ([CLI](https://eslint.org/docs/latest/use/command-line-interface)).
- **Tags.** `sast`, `javascript`. **Judgement: do not wrap.** It needs a Node runtime, and semgrep
  covers JS/TS.

### 6.6 Bearer CLI

- **Purpose.** SAST with a privacy/data-flow focus.
- **License.** Elastic License 2.0: "You may not provide the software to third parties as a hosted
  or managed service, where the service provides users with access to any substantial set of the
  features or functionality of the software"
  ([LICENSE.txt:16-20](https://github.com/Bearer/bearer/blob/v2.1.1/LICENSE.txt#L16-L20)).
- **Tags.** `sast`. **Judgement: do not wrap.** Argus's Toolbox exposes scanners to other people's
  agents over MCP ([ADR 0023](../adr/0023-mcp-surface-conditioned-on-reasoning.md)), which is
  close enough to the licence's restriction to stay away.

### 6.7 CodeQL CLI

- **License.** The CodeQL terms permit analysis of "Open Source Codebase[s]" and academic
  research, and say the Software "may not be used … in connection with any codebase that is not
  an Open Source Codebase (e.g., code in a private repo in GitHub)"
  ([LICENSE.md:18-61](https://github.com/github/codeql-cli-binaries/blob/v2.27.2/LICENSE.md#L52-L61)).
- **Judgement: exclude.** Argus reviews private repositories, and CodeQL also builds the code for
  compiled languages.

---

## 7. Dependency, IaC, container and secrets tools

### 7.1 pip-audit

- **Purpose.** Audits Python environments and requirement files against PyPI or OSV advisories;
  Apache-2.0; PyPA; `v2.10.1` released 2026-06-10.
- **Untrusted-PR risk: high by default.** Its security model: "**If you wouldn't `pip install` it,
  you should not `pip audit` it.**" It "cannot guarantee that arbitrary dependency resolutions
  occur statically"
  ([README:574-596](https://github.com/pypa/pip-audit/blob/v2.10.1/README.md#L574-L596)).
  `--no-deps` / `--require-hashes` skip resolution for fully pinned inputs (README:476-488), and
  `--locked` audits `pyproject.toml` / `pylock.*.toml` lock files (README:300-305).
- **Overlap.** osv-scanner reads the same lockfiles without resolving anything.
- **Tags.** `sca`, `python`. **Judgement: do not wrap.**

### 7.2 npm audit

- **Purpose and network.** npm POSTs "the name and list of versions of each package in the tree"
  to the configured registry's `/-/npm/v1/security/advisories/bulk`, falling back to a Quick
  Audit endpoint that receives "The full package tree"; by default it requires a lockfile
  ([npm-audit](https://docs.npmjs.com/cli/v11/commands/npm-audit)). A project `.npmrc` "will set
  config values specific to this project"
  ([npmrc](https://docs.npmjs.com/cli/v11/configuring-npm/npmrc)), so a PR can redirect that POST
  (my inference: the docs do not spell out the combination).
- **License.** GitHub reports `NOASSERTION` for `npm/cli`; the license file was not checked in this pass.
- **Tags.** `sca`, `javascript`. **Judgement: do not wrap** (needs Node, needs network, PR controls
  the destination, and osv-scanner covers `package-lock.json`).

### 7.3 cargo-audit

- **Purpose.** Audits `Cargo.lock` against the RustSec advisory DB; `Apache-2.0 OR MIT`
  ([Cargo.toml](https://github.com/rustsec/rustsec/blob/cargo-audit/v0.22.2/cargo-audit/Cargo.toml)); `v0.22.2`
  (2026-06-05). Install via `cargo install`, distro packages or Homebrew
  ([README:20-50](https://github.com/rustsec/rustsec/blob/cargo-audit/v0.22.2/cargo-audit/README.md#L20-L50)).
- **Network.** `git fetch` of the advisory DB before auditing by default; the project-root
  `.cargo/audit.toml` can change the DB `url` and `ignore` advisories
  ([audit.toml.example](https://github.com/rustsec/rustsec/blob/cargo-audit/v0.22.2/cargo-audit/audit.toml.example)).
- **Tags.** `sca`, `rust`. **Judgement: do not wrap.** osv-scanner covers `Cargo.lock`. Note that
  osv-scanner's *Rust* call analysis "will execute build scripts (`build.rs`)" and is opt-in
  ([scan-source.md:158-177](https://github.com/google/osv-scanner/blob/v2.6.0/docs/scan-source.md#L158-L177)).
  Argus must never enable it.

### 7.4 OWASP dependency-check

- **Status.** The `jeremylong/DependencyCheck` repo is archived; the project lives at
  `dependency-check/DependencyCheck` (`v13.0.0`, 2026-08-03; `gh api`). Apache-2.0.
- **Runtime and network.** "Java 11 is now required"; an NVD API key is "highly" encouraged, and
  "Without an NVD API Key dependency-check's updates will be **extremely slow**"
  ([README:21, 35-39](https://github.com/dependency-check/DependencyCheck/blob/v13.0.0/README.md#L35-L39)).
- **Tags.** `sca`, `java`. **Judgement: do not wrap** (JVM, key, overlap).

### 7.5 tfsec

- **Status.** Aqua is "consolidating all of our scanning-related efforts" into trivy and
  encourages "the tfsec community to transition over to Trivy"; "tfsec will continue to remain
  available for the time being"
  ([README:13-24](https://github.com/aquasecurity/tfsec/blob/v1.28.14/README.md#L13-L24)). Last
  release `v1.28.14` on 2025-05-02. MIT.
- **Judgement: do not wrap; trivy replaces it.**

### 7.6 checkov

- **Purpose.** IaC misconfiguration across Terraform, CloudFormation, Kubernetes, Helm,
  Kustomize, Dockerfile, Bicep, ARM and CI pipelines, plus SCA
  ([README:16-20, 45-46](https://github.com/bridgecrewio/checkov/blob/3.3.26/README.md#L45-L46)).
  Apache-2.0; Bridgecrew / Palo Alto Networks (Prisma Cloud, README:22); `3.3.26` released
  2026-10-07.
- **Distribution.** pip or Homebrew (README:74-98). The README says "Python >= 3.9, <=3.12"
  (README:69), while PyPI metadata for 3.3.26 says `requires_python >=3.9` (from
  `pypi.org/pypi/checkov/3.3.26/json`). The image runs Python 3.13
  ([`Dockerfile:6`](../../Dockerfile)), so compatibility is **unverified**.
- **Output.** CLI, CycloneDX, JSON, JUnit XML, CSV, SARIF, GitHub markdown (README:54).
- **Untrusted-PR risk: high by default.**
  - `.checkov.yaml` is read from the scanned directory first, then the cwd; the README itself says
    the config should come "from a trusted source composed by a verified identity, so that
    scanned files, check ids and loaded custom checks are as desired" (README:409-416). Custom
    checks come from `--external-checks-dir`
    ([CLI reference:18](https://github.com/bridgecrewio/checkov/blob/3.3.26/docs/2.Basics/CLI%20Command%20Reference.md))
    and can be Python classes
    ([Python Custom Policies](https://github.com/bridgecrewio/checkov/blob/3.3.26/docs/3.Custom%20Policies/Python%20Custom%20Policies.md)).
    That a repo config pointing at a repo directory would import Python from the PR is my
    inference from those two facts; I did not test it.
  - Helm scans use the `helm` binary, and "By default, Checkov runs `helm template
    --dependency-update`" with remote repositories allowed
    ([Helm.md:35-36, 115](https://github.com/bridgecrewio/checkov/blob/3.3.26/docs/7.Scan%20Examples/Helm.md)).
    Kustomize scans run `kustomize build` with remote URLs allowed by default
    ([Kustomize.md:23, 97](https://github.com/bridgecrewio/checkov/blob/3.3.26/docs/7.Scan%20Examples/Kustomize.md)).
  - `--download-external-modules` fetches Terraform modules (CLI reference:44).
- **Tags.** `iac`, `kubernetes`, `terraform`, `dockerfile`, `ci-cd`. **Judgement: do not wrap.**
  trivy covers the same frameworks without a Python version question or executing helm/kustomize.

### 7.7 KICS

- **Purpose.** IaC scanner (Checkmarx); Apache-2.0; `v2.2.0` released 2026-09-17.
- **Distribution.** Docker images, or build from source with Go
  ([getting-started.md:5-58](https://github.com/Checkmarx/kics/blob/v2.2.0/docs/getting-started.md#L5-L58)).
  The `v2.2.0` release has no binary assets (`gh api …/releases/tags/v2.2.0`).
- **Output.** `asff`, `codeclimate`, `csv`, `cyclonedx`, `glsast`, `html`, `json`, `junit`,
  `pdf`, `sarif`, `sonarqube`
  ([commands.md:71](https://github.com/Checkmarx/kics/blob/v2.2.0/docs/commands.md#L71)).
- **Judgement: do not wrap.** There is no binary to put on `PATH`, and trivy overlaps it.

### 7.8 hadolint

- **Purpose.** Dockerfile linter (best practice plus a few security rules), with ShellCheck
  rules for `RUN`.
- **License, status.** GPL-3.0; `hadolint` org; `v2.15.1` released 2026-07-31.
- **Distribution.** Static release binaries `hadolint-linux-{x86_64,arm64}` (`gh api`), Homebrew,
  Docker ([README:80-119](https://github.com/hadolint/hadolint/blob/v2.15.1/README.md#L80-L119)).
- **Output.** `tty`, `json`, `checkstyle`, `codeclimate`, `gitlab_codeclimate`, `gnu`, `codacy`,
  `sonarqube`, `sarif`, `junit` (README:180-182).
- **Untrusted-PR risk: low.** `$PWD/.hadolint.yaml` is auto-loaded; inline `# hadolint ignore=`
  exists (README:213-217, 357-363).
- **Overlap.** trivy and checkov Dockerfile checks.
- **Links.** Docs: [hadolint.github.io/hadolint](https://hadolint.github.io/hadolint/). Install:
  [README](https://github.com/hadolint/hadolint#install).
- **Tags.** `container`, `dockerfile`. **Judgement: later, only if trivy is not chosen.** GPL-3.0
  is fine for an operator-installed binary; bundling it means meeting GPL distribution terms
  (not legal advice).

### 7.9 kube-linter

- **Purpose.** Checks Kubernetes YAML, Helm charts and Kustomize manifests "with a focus on
  production readiness and security"
  ([README:8-10](https://github.com/stackrox/kube-linter/blob/v0.8.3/README.md#L8-L10)).
  Apache-2.0; StackRox; `v0.8.3` released 2026-03-10.
- **Distribution.** `go install`, Homebrew, Docker (README:28-50); static release binaries with
  sigstore bundles (`gh api`).
- **Output.** JSON and SARIF (README:203-214).
- **Untrusted-PR risk: low.** `.kube-linter.yaml` in cwd can set `doNotAutoAddDefaults`
  (configuring-kubelinter.md:8-14, 33-40).
- **Tags.** `iac`, `kubernetes`. **Judgement: later, only if trivy is not chosen.**

### 7.10 kubescape

- **Purpose.** Kubernetes security posture (clusters, manifests, images); CNCF incubating, created
  by ARMO ([README:28](https://github.com/kubescape/kubescape/blob/v4.0.15/README.md#L28));
  Apache-2.0; `v4.0.15` released 2026-09-29.
- **Network.** It has a `kubescape download` command for offline / air-gapped artifacts
  (README:146), which implies online fetching by default. What it fetches at scan time was **not
  verified**.
- **Output.** JSON, JUnit, SARIF, HTML, PDF, CSV (README:214-230).
- **Judgement: do not wrap.** Its strength is live clusters, which Argus does not review; for
  manifests, trivy or kube-linter suffice.

### 7.11 trufflehog

- **Purpose.** Secret scanning over git, filesystems, buckets, images and more, with "over 700
  credential detectors that support active verification against their respective APIs"
  ([README:45, 416](https://github.com/trufflesecurity/trufflehog/blob/v3.99.2/README.md#L416)).
- **License, steward, status.** AGPL-3.0; Truffle Security; `v3.99.2` released 2026-10-08.
- **Distribution.** Homebrew, Docker, install script with optional cosign verification
  (README:82-178).
- **Output.** `--json` and `--sarif` (README:221-236).
- **Network.** Verification is on unless `--no-verification` (README:474). "A verified result
  means TruffleHog confirmed the credential is valid by testing it against the service's API"
  (README:406, 422-433). Some verification hosts are taken from the scanned content: the
  Artifactory detector matches `*.jfrog.io` hosts in the data and requests
  `https://<match>/artifactory/api/system/ping` with the found token
  ([artifactory.go:35, 119](https://github.com/trufflesecurity/trufflehog/blob/v3.99.2/pkg/detectors/artifactory/artifactory.go#L119)).
  `--no-update` disables update checks (README:490).
- **Untrusted-PR risk: medium with verification on.** Argus would send credentials found in
  somebody's PR to third parties, from the Argus host.
- **Overlap.** gitleaks (existing).
- **Tags.** `secrets`. **Judgement: do not wrap.** Verification is its main advantage over
  gitleaks, and it is exactly the egress Argus should not do on untrusted input. Bundling
  AGPL-3.0 software also brings distribution obligations (not legal advice).

### 7.12 licensee

- Ruby gem that detects a project's *own* license; MIT; `v10.1.0` (2026-08-07, `gh api`).
- **Judgement: out of scope.** It is not a security tool.

---

## 8. Implications for Argus

### 8.1 "Optional tools" vs ADR 0013's batteries-included image

**What changes.** Today registration is unconditional
([`session.go:483-485`](../../pkg/daemon/session.go)) and `doctor` derives its binary list from a
separate hand-written registry ([`cmd/doctor.go:158-172`](../../cmd/doctor.go)). Moving to
"register only what is on `PATH`" has three effects:

1. **The image gate goes vacuous.** `--binaries` asks the registry which binaries are owed
   ([`doctor.go:144-149, 265-283`](../../pkg/doctor/doctor.go)). If a missing binary means an
   unregistered Tool, a Dockerfile edit that drops gitleaks would pass CI.
2. **The model's tool list varies by host.** That is fine for the agent loop, but the Toolbox MCP
   surface ([ADR 0023](../adr/0023-mcp-surface-conditioned-on-reasoning.md)) and the guide's
   fixed table of three scanners
   ([`docs/guide/channels/mcp.md:59-66, 78-82`](../guide/channels/mcp.md)) become host-dependent.
3. **ADR 0013's "everything the image promises is owed" still holds**, but "what the image
   promises" must become an explicit list rather than "every Tool Argus has".

**Judgement — proposal:**

- Keep one batteries-included image whose **manifest** is a declared subset of the catalog: today's
  three, plus zizmor (pip) and trivy (static) if adopted. `doctor --binaries` checks the manifest,
  not the registry.
- Everything else in the catalog is **operator-installed**. `doctor` reports each as present or
  absent (Info, not Fail) with the catalog's install link.
- The Go toolchain is the hard case: it is big, and it turns on osv-scanner's Go call analysis
  for every review. Ship it in the image only after §8.3's profile exists. Until then, Go Tools
  are operator-installed.
- This amends ADR 0013's "no slim variant" reasoning only in what it counts; it does not need a
  second image. It deserves a short ADR.

### 8.2 Extending `tool.Requirement` into catalog metadata

**Judgement — proposal.** A Tool can need several binaries (govulncheck needs `govulncheck` and
`go`), while the catalog is per Tool. So keep `Requirement` per binary and add a per-Tool entry:

```go
// pkg/tool/catalog.go (sketch)
type Requirement struct {
    Binary      string
    InstallHint string
    VersionArgs []string // e.g. {"--version"}, so doctor can print what it found
}

type CatalogEntry struct {
    Name       string   // stable Tool name, e.g. "run_zizmor"
    Purpose    string   // one line: what it finds
    Why        string   // one paragraph: why an operator would install it
    Tags       []string // from the controlled vocabulary below
    DocsURL    string   // official docs (absolute)
    InstallURL string   // official install guide (absolute)
    License    string   // SPDX id, or "LicenseRef-…" with a note
    Runtime    Runtime  // Static | Python | GoToolchain | Ruby | Node | JVM
    Network    Network  // Offline | DatabaseFetch | Always
    Trust      Trust    // AnyReview | TrustedOnly — gates Service-triggered reviews (ADR 0018)
    InImage    bool     // part of the official image manifest (§8.1)
    Requires   []Requirement
}

type Cataloged interface{ Catalog() CatalogEntry }
```

- A package-level `security.Catalog()` lists every entry, **statically**, independent of `PATH`.
  The daemon builds the registry by filtering the catalog with `exec.LookPath`. `doctor` iterates
  the catalog. A generator (`go run ./internal/gen/toolcatalog`) writes
  `docs/guide/scanners.md` with Starlight frontmatter (`title`, `description`, `sidebar.order`)
  and only absolute external links, as ADR 0022 requires.
- The generator can fail CI when the generated page is stale, just as the image gate fails when a
  binary is missing.
- `InstallHint` already exists ([`requires.go:11`](../../pkg/tool/requires.go)); `InstallURL`
  complements rather than replaces it (a hint for the terminal, a link for the guide).

**Proposed controlled tag vocabulary** (two axes; traits like "needs network" are derived from
`Network`/`Runtime`, not hand-tagged):

| Axis | Tags |
| --- | --- |
| What it finds | `sast`, `sca`, `secrets`, `iac`, `container`, `ci-cd`, `supply-chain`, `license`, `sbom` |
| What it reads | `go`, `python`, `ruby`, `javascript`, `rust`, `java`, `github-actions`, `terraform`, `kubernetes`, `dockerfile`, `multi-language` |

### 8.3 Go-toolchain-based Tools and ADR 0019

What the Go toolchain does on an untrusted module, and what each pin buys:

| Vector | Default behaviour | Mitigation | Does it work? |
| --- | --- | --- | --- |
| Toolchain switching | "The default `GOTOOLCHAIN` setting is `auto`", which downloads newer toolchains as modules via `GOPROXY` when `go.mod`'s `go`/`toolchain` line asks for them ([toolchain](https://go.dev/doc/toolchain)) | `GOTOOLCHAIN=local` in the process environment, which has the highest precedence ([toolchain](https://go.dev/doc/toolchain)) | Yes. A module needing a newer Go then fails: toolchains "refuse to run in workspaces or modules that require newer Go versions". The operator must keep `go` current. |
| Module downloads | Default `GOPROXY` is the Go module proxy with `direct` fallback (**not re-verified in this pass**) | `GOPROXY=off` ("no communication should be attempted", [ref/mod](https://go.dev/ref/mod)) or a proxy-only `GOPROXY` without `direct` | `off` works only for vendored modules or a warm cache, and type-checking fails without dependencies. Downloads themselves do not run code: "neither fetching nor building code will let that code execute" ([Go blog, 2022-03-31](https://go.dev/blog/supply-chain)). |
| `go.mod` rewrite | `-mod=readonly` unless a `vendor/` directory exists (then `-mod=vendor`) ([ref/mod](https://go.dev/ref/mod)) | `GOFLAGS=-mod=readonly`, or leave the default to pick `vendor` | Yes. Note that the brief's `-mod=mod` is the **opposite**: it tells the `go` command "to automatically update `go.mod`". |
| Workspace files | `go.work` is searched in the cwd and its parents | `GOWORK=off` ([ref/mod](https://go.dev/ref/mod)) | Yes. |
| cgo | "enabled by default for native builds on systems where it is expected to work", off when no C compiler is found; `#cgo` flags are restricted to an allowlist "for security reasons" ([cmd/cgo](https://pkg.go.dev/cmd/cgo)) | `CGO_ENABLED=0` | Yes. Files importing `"C"` are then excluded, which can leave packages less complete. Whether `python:3.13-slim` ships a C compiler was **not verified**. |
| Package driver | `GOPACKAGESDRIVER` replaces `go list` with another program ([go/packages](https://pkg.go.dev/golang.org/x/tools/go/packages)) | Not in the Tool's env allowlist | Yes (§2.2). |
| Local file disclosure | "Building an attacker-controlled program may produce output which contains the contents of arbitrary local files", and "Data exfiltration is not in our threat model" ([security decisions](https://go.dev/doc/security/decisions)) | ADR 0019 Phase 2 (no `~/.argus` visible) | **Only the sandbox.** Scanner output goes into the model's context, so a PR could pull local file contents into it. ADR 0017's grounding limits what gets *posted*, not what the model reads. |
| Build code execution | The Go team treats "A malicious module can cause 'go build' to execute arbitrary code" as a vulnerability (security decisions) | Keep the toolchain patched | It is a bug class, not a design property; a sandbox is the defence in depth the same page recommends ("builds of untrusted code also be performed in an unprivileged sandbox environment"). |

None of govulncheck, gosec, staticcheck or capslock runs `go test` or the program under analysis.
They use `go list` through `go/packages` (which can type-check and compile export data: `go list
-export` produces "the build ID of the compiled package", [cmd/go](https://pkg.go.dev/cmd/go)).

**Judgement — proposal:**

1. A single **Go profile** in `pkg/security`, applied by every Go-based Tool: `GOTOOLCHAIN=local`,
   `GOFLAGS=-mod=readonly` (or nothing when `vendor/` exists), `GOWORK=off`, `CGO_ENABLED=0`,
   `GOPROXY` = proxy-only (or `off` when a module cache is pre-populated), `GOENV` and caches
   pointed at a per-run scratch directory, cwd outside the checkout, env allowlisted. Whether
   `GOENV=off` disables the user config file was **not verified** here; pointing `GOENV` at an
   empty file is the conservative choice.
2. Mark Go Tools `Trust: TrustedOnly` and withhold them from **Service-triggered** reviews (the ADR
   0018 precedent) until ADR 0019 Phase 2 lands. A Person's `start_review_local` or a Toolbox call
   on a local path may use them.
3. Apply the same profile to `run_osv_scanner`, or pass `--no-call-analysis=go` whenever `go` is on
   `PATH` but the profile is not in force. Otherwise installing `go` for govulncheck silently
   changes what osv-scanner does on every review.

---

## 9. Summary comparison

Risk levels: **low** = parses files only and has an override for repo config; **medium** = parses
only, but network lookups or repo config can be steered by the PR; **high** = invokes a
toolchain or package manager on the repo, or loads code or plugins named by repo config.

| Tool | License (SPDX) | Distribution | Output | Network at scan | Untrusted-PR risk | Tags | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- |
| govulncheck | BSD-3-Clause | `go install`; needs Go | JSON, SARIF, OpenVEX | vuln.go.dev + modules | high (§8.3) | sca, go | Go #2 |
| gosec | Apache-2.0 | static + needs Go | JSON, SARIF, … | modules (AI opt-in) | high (§8.3) | sast, go | **Go #1** |
| staticcheck | MIT | static + needs Go | text, JSON (SARIF in source) | modules | high (§8.3) | sast, go | no |
| capslock | BSD-3-Clause | `go install`; needs Go | JSON, compare | modules; `go get` fallback | high (§8.3) | supply-chain, go | later |
| golangci-lint | GPL-3.0 | static + needs Go | many | modules | high (plugins via config) | sast, go | no |
| go-licenses | Apache-2.0 | `go install`; needs Go | CSV | modules | high (§8.3) | license, go | no |
| zizmor | MIT | pip / static (best-effort) / brew | JSON v1, SARIF | none w/o token | low | ci-cd, github-actions | **first non-Go** |
| actionlint | MIT | static | template JSON / SARIF | none | low | ci-cd, github-actions | later |
| poutine | Apache-2.0 | static | JSON, SARIF | daily version check | medium (Rego via config) | ci-cd, supply-chain | later |
| Scorecard | Apache-2.0 | static | JSON | GitHub API + token | n/a (repo settings) | supply-chain | no |
| trivy | Apache-2.0 | static | JSON, SARIF | DBs, Maven, telemetry (all switchable) | medium | iac, container, kubernetes, terraform, dockerfile | **yes, misconfig only** |
| grype | Apache-2.0 | static | JSON, SARIF | DB + update checks | low–medium | sca | no (dup) |
| syft | Apache-2.0 | static | SBOM formats | update check | low | sbom | no |
| osv-scalibr | Apache-2.0 | `go install` | proto/JSON | deps | low | sca | no (inside osv-scanner) |
| opengrep | LGPL-2.1 | static (Nuitka) | JSON, SARIF | not checked | low with fixed rules | sast | replace semgrep? (Q4) |
| checkov | Apache-2.0 | pip (Python ≤3.12 per README) | JSON, SARIF, … | Prisma, helm/kustomize remotes | high | iac | no |
| KICS | Apache-2.0 | Docker / source only | JSON, SARIF, … | not checked | medium | iac | no |
| hadolint | GPL-3.0 | static | JSON, SARIF | none documented | low | container, dockerfile | if no trivy |
| kube-linter | Apache-2.0 | static | JSON, SARIF | none documented | low | iac, kubernetes | if no trivy |
| kubescape | Apache-2.0 | static | JSON, SARIF | artifacts (not verified) | medium | iac, kubernetes | no |
| trufflehog | AGPL-3.0 | static | JSON, SARIF | verification on by default | medium | secrets | no |
| bandit | Apache-2.0 | pip | JSON, SARIF (extra) | none | low | sast, python | later |
| ruff (`S`) | MIT | static / pip | JSON, SARIF | none | low (`--isolated`) | sast, python | later |
| brakeman | Brakeman Public Use License | Ruby gem | JSON, SARIF | none documented | low–medium | sast, ruby | operator-only |
| njsscan | LGPL-3.0 | pip (+ semgrep) | JSON, SARIF | — | low | sast, javascript | no |
| eslint-plugin-security | Apache-2.0 | npm (+ Node, ESLint) | JSON | — | high w/o `--no-config-lookup` | sast, javascript | no |
| Bearer | Elastic-2.0 | static | — | — | — | sast | no (license) |
| CodeQL | proprietary terms | static bundle | SARIF | — | builds code | sast | no (license) |
| pip-audit | Apache-2.0 | pip | JSON, CycloneDX | PyPI/OSV + pip resolution | high by default | sca, python | no |
| npm audit | not checked | npm | JSON | always (registry from `.npmrc`) | high | sca, javascript | no |
| cargo-audit | Apache-2.0 OR MIT | cargo / distro | JSON | `git fetch` DB (URL from repo config) | medium | sca, rust | no |
| dependency-check | Apache-2.0 | JVM | JSON, SARIF (not checked) | NVD API | low–medium | sca, java | no |
| tfsec | MIT | static | — | — | low | iac | no (deprecated) |
| licensee | MIT | Ruby gem | JSON | — | low | license | no |

---

## 10. Open questions for the maintainer

- **Q1. Go toolchain in the image.** Ship `go` in the official image (bigger image; turns on
  osv-scanner's Go call analysis for every review), or keep Go Tools operator-installed until the
  Go profile and ADR 0019 Phase 2 exist?
- **Q2. govulncheck vs osv-scanner's Go call analysis.** Is a separate `run_govulncheck` worth it
  for traces, binary mode and OpenVEX, or is "install `go` and let osv-scanner do reachability"
  enough?
- **Q3. Suppressions.** Should Argus honour in-repo suppressions (`#nosec`, `IgnoredVulns`,
  `zizmor.yml`) on a Person's review and ignore them on Service-triggered ones, as §2.1 suggests?
  Or ignore them always and report them as signal?
- **Q4. semgrep → opengrep.** Is replacing semgrep with opengrep's static binary on the table? It
  would remove ADR 0013's reason for a Python base image (but zizmor/bandit via pip would then
  prefer the static builds).
- **Q5. Databases under Phase 2.** Who refreshes vulnerability DBs when the review sandbox has no
  network: the daemon, outside the sandbox, mounting them read-only?
- **Q6. Licences in the image.** Is GPL-3.0 (hadolint, golangci-lint) or AGPL-3.0 (trufflehog)
  acceptable inside the official image, or should the manifest be permissive-only with the rest
  operator-installed?
- **Q7. Catalog location.** One generated `docs/guide/scanners.md` page, or one page per tool under
  `docs/guide/scanners/`? This affects public URLs, which ADR 0022 says are expensive to change.
- **Q8. Existing debt.** `run_semgrep` still defaults to `--config auto` despite ADR 0019 Phase 1,
  and all three existing scanners run with cwd inside the checkout. Fix these first, in the same
  change that introduces the catalog?

---

## 11. Could not verify, or not checked

- **semgrep / gosec rule overlap for Go**: no rule-by-rule comparison was done.
- **OSV includes all Go vulndb entries**: widely stated; not confirmed from a primary source in
  this pass.
- **Default `GOPROXY` value and `GOENV=off` semantics**: not re-read from `go help environment`
  (the `cmd/go` page was truncated in the fetch).
- **Whether `python:3.13-slim` contains a C compiler**: not checked; it decides whether cgo is on
  by default inside the image.
- **golangci-lint**: how a relative plugin `path` resolves, and whether a `--no-config` flag
  exists in v2.
- **checkov**: Python 3.13 compatibility (README says ≤3.12; PyPI says ≥3.9 with no upper bound);
  that a repo `.checkov.yaml` with `external-checks-dir` imports Python from the PR (inferred, not
  tested).
- **kubescape**: what it downloads at scan time, and telemetry.
- **KICS**: inline suppression syntax and any scan-time network calls.
- **hadolint, actionlint, kube-linter**: "no network" is the absence of documented network
  access, not a source audit.
- **Scorecard `--local`**: which checks run without the GitHub API.
- **capslock JSON stability, staticcheck JSON stability**: no stated policy found.
- **npm/cli license**: GitHub reports `NOASSERTION`; the file was not read.
- **Legal readings** (brakeman "commercial use", Elastic License "hosted service", GPL/AGPL in the
  image): quoted, not interpreted. They need a lawyer, not this note.

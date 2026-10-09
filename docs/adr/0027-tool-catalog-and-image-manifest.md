# ADR 0027 — A Tool Catalog: Argus offers what the host can run; the image ships a manifest

**Status:** Proposed
**Date:** 2026-10-09
**Builds on:** [ADR 0006](0006-no-generic-shell-tool.md),
[ADR 0015](0015-integrations-declared-in-configuration.md),
[ADR 0018](0018-automatic-reviews-are-least-privilege.md),
[ADR 0019](0019-untrusted-code-review-filesystem-isolation.md),
[ADR 0022](0022-user-guide-is-self-contained-starlight-source.md)
**Amends:** [ADR 0013](0013-batteries-included-runtime-image.md) (what
"batteries-included" counts, the base image, and what `doctor --binaries` gates)
**Research:** [optional-scanner-tools.md](../research/optional-scanner-tools.md)

## Context

Argus wraps three scanners (semgrep, gitleaks, osv-scanner) and wants many more:
Go analyzers, GitHub Actions auditing, IaC misconfiguration. The research surveys
37 candidates. No single set suits every organization, and each new binary has a
cost: image size, a licence, and a risk profile on **untrusted review content**.
Some tools only read files; others drive a toolchain over the reviewed code.

Today every Tool is always registered. A missing binary shows up only as a failed
call mid-review. ADR 0013 made the official image carry every scanner and declared
that inside it "optional does not exist". That rule worked for three tools. It
does not scale to a catalog of dozens.

The research also found three problems in how the existing scanners run. Any new
Tool would inherit them:

- They run with the working directory inside the checkout
  ([`pkg/security/exec.go:22-23`](../../pkg/security/exec.go)). As a result,
  `.gitleaks.toml`, `.gitleaksignore` and `osv-scanner.toml` from the PR under
  review are honoured, and a PR can suppress its own findings.
- They inherit the daemon's whole environment, `.env` included
  ([`pkg/daemon/daemon.go:144`](../../pkg/daemon/daemon.go)).
- `run_semgrep` still defaults to `--config auto`
  ([`pkg/security/semgrep.go:56`](../../pkg/security/semgrep.go)), despite
  ADR 0019 Phase 1.

## Decision

**A Tool is catalogued, registered or exposed.** The **Catalog** is every Tool
Argus knows how to wrap, with its metadata:
- what it is for, and why it is useful;
- tags;
- links to the official docs and the official install guide;
- licence;
- the binaries and runtimes it requires;
- whether it is safe on untrusted input.

A catalogued Tool is **registered** only when its binaries resolve on `PATH` at
daemon start and the operator has not disabled it. **Exposed** keeps its ADR 0023
meaning. Argus offers what the host can run, and the operator chooses what to
install from the Catalog. "Optional Tool" is not a term: optionality is a
consequence of these three levels.

- **Discovery happens once, at startup.** The registry is fixed for the life of
  the process. The startup log lists what was registered, and what is catalogued
  but missing, with its install link. Installing a tool means a restart.
- **Operators can switch tools off.** `argus.yaml` gets a deny-list of installed
  Tools to keep unregistered (`tools.disabled`). Everything installed is on by
  default, so a tool newly added to the image is not silently off. An allow-list
  was rejected for exactly that reason. `doctor` reports a disabled Tool as
  disabled, not as missing.
- **Every Tool declares its trust level on untrusted input.** Reading files is
  safe. Driving a toolchain or package manager over the reviewed code is not.
  Automatic reviews register only Tools that are safe on hostile input
  (ADR 0018). The same rule applies within one Tool when it has two modes. With
  `go` on `PATH`, osv-scanner turns on Go call analysis by default, which loads
  the reviewed packages through the Go toolchain. Automatic reviews therefore run
  it with `--no-call-analysis=go`
  ([scan-source.md:148](https://github.com/google/osv-scanner/blob/v2.6.0/docs/scan-source.md)).
  Reviews requested by a Person, and calls over MCP, keep call analysis.
- **In-repo suppressions are ignored, always.** Every Tool:
  - runs with its working directory outside the checkout;
  - gets an explicit environment allow-list;
  - passes its "ignore repository config" flags.

  `#nosec`, `.gitleaksignore`, `osv-scanner.toml`, `zizmor.yml` and the like are
  untrusted review content: data, not instructions. When a finding is marked
  suppressed in the code, Argus reports that as a signal. An organization's real
  suppressions live in its own knowledge (the `known-fps` CONTEXT document),
  where a PR cannot write them. This applies to every review, whoever started
  it. A rule that depends on who started the review was rejected as a second
  behaviour to reason about.
- **One SAST capability, two engines.** opengrep is preferred and semgrep stays
  supported. When both are installed, one SAST Tool is registered and runs
  opengrep. The Tool's name is stable, so Skills and MCP callers name the
  capability, not the binary. The output says which engine ran.
- **The official image ships an explicit manifest.** It is a default chosen to
  suit most organizations, not everything in the Catalog. Criteria:
  - a permissive or weak-copyleft licence;
  - a static binary, or a clean install without a language runtime;
  - safe on untrusted input;
  - useful on almost any repository.

  The manifest is git, **opengrep**, gitleaks, osv-scanner, **zizmor** and
  **trivy**, with trivy restricted to misconfiguration scanning, plus whatever
  the Tools in the manifest require. `doctor --binaries` gates the manifest,
  not the registry, so a binary dropped from the Dockerfile still fails CI.
- **Go is a recommended prerequisite, not part of the image.** gosec, govulncheck
  and capslock require the `go` command. The `go` command loads and type-checks
  the reviewed code, which makes it the largest attack surface in the Catalog.
  Without it, Go repositories are still covered:
  - osv-scanner reads `go.mod`;
  - opengrep has Go rules;
  - gitleaks does not depend on the language.

  With it, they also get reachability and type-aware SAST. The Catalog recommends
  `go` with gosec to organizations that write Go. Wherever it is installed, it
  runs in a hardened environment: `GOTOOLCHAIN=local`, `GOFLAGS=-mod=readonly`,
  `GOWORK=off`, `CGO_ENABLED=0` and a restricted `GOPROXY`. gosec is built first.
  govulncheck follows, for its call traces, binary mode and OpenVEX, since
  osv-scanner already covers Go reachability with the same library.
- **The Catalog page is generated from the Catalog.** The metadata lives next to
  each Tool in Go, the way `tool.Requirer` already feeds `doctor`. A generator
  writes the Starlight pages under `docs/guide/scanners/`:
  - an index with tags and recommendations ("you write Go → …", "you use GitHub
    Actions → …");
  - one page per Tool, so `doctor` and the startup log can link to a stable URL
    (ADR 0022).

  CI fails when the generated pages drift from the code. A separate page explains
  the image: what the manifest contains and why, and how to build a custom image
  `FROM ghcr.io/argusappsec/argus` that adds tools. Go plus gosec is the worked
  example.
- **The existing debt is fixed in the same change.** That covers working
  directory, environment, config flags and `--config auto` for the scanners
  already there. These rules are what every catalogued Tool must follow, so they
  are established once, with the Catalog.

## Consequences

- **The image can drop Python.** Semgrep was the only reason ADR 0013 chose a
  `python:3.x-slim` base ("only through Python channels"). Two things need
  settling while implementing:
  - **opengrep** ships static Nuitka builds
    ([README:48](https://github.com/opengrep/opengrep/blob/v1.30.2/README.md)).
    Whether it is compatible with the ruleset Argus pins is not yet verified.
  - **zizmor's** prebuilt binaries are "best-effort"
    ([installation](https://docs.zizmor.sh/installation/)). The image can build
    it with `cargo` in a build stage instead.

  If neither works, the base stays as it is. That changes nothing else in this
  decision.
- **Semgrep remains a supported engine** for operators who install it. It
  leaves only the official image.
- **"Batteries-included" now means a curated default, not everything.** ADR
  0013's single image stays. No second variant is introduced, and anything beyond
  the default is a custom image.
- **A Skill can no longer assume a binary is present.** Skills name capabilities,
  and must degrade when one is not registered.
- **A tool installed while the daemon runs stays invisible until a restart.**
- **trivy needs extra care.** Its release pipeline was compromised in March 2026
  (GHSA-69fq-xp46-6x23), so it is pinned by digest with its signature verified.

## Alternatives considered

- **Keep every Tool always registered (today).** A missing binary fails
  mid-review, and the model is offered capabilities the host does not have.
- **A minimal image where every scanner is optional.** Argus would be useless
  out of the box, which is the failure ADR 0013 was written to fix.
- **Ship `go` in the image, and keep Go Tools out of automatic reviews.** The
  largest attack surface would ship to every organization, including those
  without Go. It would also silently change osv-scanner's risk profile.
- **Two Tools, `run_opengrep` and `run_semgrep`.** The model would have to choose
  between them, and findings would be duplicated when both are installed.
- **Honour in-repo suppressions on reviews requested by a Person.** That
  behaviour would depend on who started the review. The organization's
  suppressions already have a home that a PR cannot write to.
- **A hand-written catalog page.** It would drift from the code, and a Tool could
  ship without documentation.

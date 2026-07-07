# ADR 0013 — Batteries-included runtime image: one image that carries its own scanners

**Status:** Accepted
**Date:** 2026-07-07
**Builds on:** [ADR 0006](0006-no-generic-shell-tool.md),
[ADR 0009](0009-pr-review-scans-whole-tree.md),
[ADR 0012](0012-kubernetes-deployment.md)
**Amends:** [ADR 0012](0012-kubernetes-deployment.md) (the "distroless static
base" consequence)

## Context

Argus Tools shell out **in-process** to external binaries
(`exec.CommandContext` in `pkg/security/exec.go`): `git` (required — cloning
repositories), `semgrep` (SAST), `gitleaks` (secrets), `osv-scanner`
(dependency vulns). The binaries must therefore be on the PATH *inside the
daemon's own container* — a sidecar cannot help without adding RPC, which
would break the ADR 0006 tool model (Go functions with a fixed surface).

The Dockerfile shipped with ADR 0012 used `distroless/static` and contained
only the `argus` binary. In-cluster the daemon could not clone (git is a
*required* dependency) nor scan: the GitHub PR-review channel — the thesis of
the product — was dead in the official image. `argus doctor` correctly
reported all of this, but nothing ran it against the image.

Semgrep constrains the base image choice: it is distributed **only through
Python channels**. The pip wheel bundles the native `semgrep-core` but the
CLI is Python; the Homebrew formula depends on `python@3.14`; GitHub releases
ship **no binary assets** (verified v1.164–v1.168). Extracting
`semgrep-core`/`osemgrep` from the wheel is experimental and unsupported.

Pinning tool versions does *not* freeze security coverage: semgrep fetches
rules from its registry at runtime (`--config auto`) and osv-scanner queries
the OSV.dev API live. Only gitleaks compiles its rules in, and those change
slowly.

## Decision

Ship **one official image, batteries-included**: `argus` + `git` + `semgrep`
+ `gitleaks` + `osv-scanner`. No slim variant, no tools-on-volume.

- **Base:** `python:3.x-slim` (Debian/glibc — no musl risk with semgrep
  wheels). `semgrep` installed via pip, `git` via apt; `gitleaks` and
  `osv-scanner` are static Go binaries copied with `COPY --from` from their
  official images. The build stage for `argus` itself is unchanged.
- **Pinning:** every tool version is an `ARG` at the top of the Dockerfile,
  pinned exactly; bumps are manual commits (automation like Renovate can
  hook the ARGs later). Reproducible builds; the image changelog is the git
  log.
- **uid 65532:** the runtime user is recreated with the same uid as the old
  distroless `nonroot`, so the `securityContext.fsGroup: 65532` guidance in
  ADR 0012 and the hosting guide stays valid — no manifest changes.
- **The contract is enforced, not hoped:** `argus doctor --binaries` runs
  only the binary checks and treats **every** binary as blocking — inside
  the official image, "optional" does not exist; everything the image
  promises is owed. The check list derives from the tool registry via
  `tool.Requirer`, so a new tool that declares `Requires()` extends the gate
  automatically. CI builds the image and gates every PR on it; the release
  pipeline runs it per-architecture before pushing.
- **Publishing:** `ghcr.io/argusappsec/argus`. Git tags `v*` → semver tags +
  `latest`; every push to `main` → `edge` (continuous dogfooding on a real
  cluster). Multi-arch `linux/amd64` + `linux/arm64` (semgrep publishes
  aarch64 wheels). Provenance + SBOM attestations are generated at build
  time — an attested image is coherence for a security tool, not vanity.

## Consequences

- **We lose distroless.** A shell, pip and apt now live inside a security
  tool's image; the attack surface and size grow (hundreds of MB, dominated
  by the Python runtime semgrep needs). Accepted as the direct price of the
  batteries-included contract: a security bot whose official image cannot
  scan is broken out of the box, and image size is paid once per deploy —
  Argus is a per-org daemon, not a high-churn CLI.
- `argus doctor` gains an image-contract mode (`--binaries`) alongside its
  operator-environment mode; severities are reinterpreted for the context.
- The Kubernetes guide stops instructing operators to build the image
  themselves and points at the official one.
- Anyone editing the Dockerfile who drops a scanner breaks CI on the PR,
  not production.

## Alternatives considered

- **Keep distroless, accept degraded functionality.** Rejected: `git` is
  required — the image could not even clone, let alone review PRs.
- **Two images (`slim`/`full`).** Rejected: a double maintenance and test
  matrix to save megabytes no Kubernetes operator cares about.
- **Minimal image + tools delivered on a volume by an init container.**
  Works only for the static Go binaries; semgrep still needs a Python
  runtime in the image, so the scheme is fragile exactly on the most
  important tool (SAST).
- **`semgrep/semgrep` upstream image as base.** Alpine/musl, third-party
  entrypoint, layout and uid — inheriting someone else's decisions in our
  own house, and our fsGroup guidance would break.
- **Extract `semgrep-core`/`osemgrep` from the wheel.** Experimental and
  unsupported; the first upstream wheel reorganization breaks the image
  silently.
- **Sidecar container with the scanners.** Incompatible with the ADR 0006
  in-process tool model without introducing RPC between containers.

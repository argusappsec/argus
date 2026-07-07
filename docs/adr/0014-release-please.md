# ADR 0014 — Release management: release-please cuts versions, the pipeline ships them

**Status:** Accepted
**Date:** 2026-07-07
**Builds on:** [ADR 0013](0013-batteries-included-runtime-image.md)

## Context

ADR 0013 gave Argus a release pipeline: a `v*` tag publishes the
batteries-included image with semver tags, `:latest`, provenance and SBOM.
But nothing *creates* those tags. There is no tag in the repo, no GitHub
Release, no changelog, and no stated policy for how versions bump. For a
project heading to a public audience, a curated CHANGELOG.md and regular
releases are part of the signal that the project is alive.

Two facts shape the solution. First, the repo already speaks conventional
commits: PRs are squash-merged and their titles are `feat:`/`fix:`/`docs:`
lines, so the changelog and the semver bump are mechanically derivable.
Second, the maintainer is one person: automation should remove the mechanical
work (changelog assembly, version arithmetic) without removing control over
*when* a release happens.

## Decision

**release-please** (manifest mode, `release-type: go`) owns versioning,
changelog and GitHub Releases:

- Every push to `main` updates a standing **release PR** that accumulates
  CHANGELOG.md entries from conventional commits and proposes the next
  semver bump. **Merging that PR is the release gesture** — release-please
  tags `vX.Y.Z` and creates the GitHub Release.
- Division of labor: release-please decides *what version*; the ADR 0013
  pipeline, unchanged in role, decides *what artifact*.
- **Dispatch, not tag trigger.** Tags created with the workflow's
  `GITHUB_TOKEN` don't fire `on: push: tags` (GitHub's recursion guard), so
  `release-please.yml` explicitly dispatches `release.yml` on the fresh tag —
  `workflow_dispatch` is exempt from the guard, and no extra secret or
  GitHub App is needed. Hand-pushed tags still work through the push trigger.
- **Pre-1.0 policy:** `bump-minor-pre-major` — a breaking change bumps the
  minor (0.x → 0.(x+1)) instead of jumping to 1.0.0. Going 1.0 is a
  deliberate act, not the side effect of a `!` commit. `feat` bumps minor,
  `fix` bumps patch (defaults).
- **Bootstrap:** `.release-please-manifest.json` starts at `0.0.1` — the
  manifest records the *last released* version, and the `feat` commits in
  history bump it to a first release of **v0.1.0** whose changelog carries
  the full feature history. Not `0.0.0`: release-please treats that one
  value as "never released" and falls back to its default initial version,
  1.0.0 (upstream issue #2087), ignoring the pre-major flags. The tag
  `v0.0.1` never existed; the only artifact of the lie is a dead compare
  link in the first changelog entry.

## Consequences

- CHANGELOG.md appears at the repo root and is bot-owned: corrections happen
  by editing the release PR before merging, not the file after.
- Squash-merge discipline becomes load-bearing: the PR title is the
  conventional commit that decides the bump and the changelog line. A
  mistitled PR mis-versions the release. Titles were already the convention;
  now they have teeth.
- A release PR is always open between releases. That is a feature, not
  noise: it is a live answer to "what would ship if I released now".
- Merging the release PR is itself a push to `main`, so the `:edge` image
  rebuilds alongside the semver publish — cache-warm and harmless.
- If binaries are later attached to releases (GoReleaser), it must run in
  `keep-existing` mode: release-please owns Release creation.

## Alternatives considered

- **Manual tagging + hand-written changelog.** The mechanical parts —
  semver arithmetic, changelog assembly — are exactly what rots first under
  a solo maintainer.
- **semantic-release.** Releases on every push to `main`; removes the human
  checkpoint on *when*, which is the one piece of control worth keeping.
- **GoReleaser's changelog at tag time.** No standing release PR, so
  nothing shows what is pending; version arithmetic stays manual.
- **A GitHub App / PAT so tags fire triggers naturally.** Works, but means
  provisioning and rotating a secret forever to avoid one dispatch job.

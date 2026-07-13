# ADR 0019 — Reviewing untrusted code runs under filesystem isolation (phased)

**Status:** Accepted (phased: patch now, sandbox later)
**Date:** 2026-07-13
**Builds on:** [ADR 0006](0006-no-generic-shell-tool.md), [ADR 0008](0008-github-channel-as-github-app.md), [ADR 0017](0017-full-context-in-controlled-egress-out.md)

## Context

The file-scoped tools (`read_file`, `list_files`, `grep`) and the scanners
(`run_semgrep`, `run_gitleaks`, `run_osv_scanner`) operate on a checkout of
attacker-controlled code. Two holes let that code read beyond its own tree:

- **Symlink escape.** `resolveWithinRoot` validates paths **lexically only**
  (`filepath.Clean` + prefix check, no `EvalSymlinks`/`Lstat`). A PR that
  commits a symlink lexically inside the root but pointing outside — e.g.
  `docs/leak → /home/argus/.argus/users.yaml`, the App private key, the webhook
  secret, `~/.ssh/…` — passes the check, and `os.ReadFile` follows it. This is
  arbitrary host-filesystem read for anyone who can open a PR, and it also
  **defeats grounding** ([ADR 0017](0017-full-context-in-controlled-egress-out.md)):
  the leaked content appears to come from "a file in the checkout", so the
  provenance check would accept posting it. It reaches the crown jewels the
  daemon must hold (the GitHub App private key).
- **Attacker-influenced scanner config.** `run_semgrep`'s `config` is model-
  supplied (default `auto`, which also reaches the semgrep registry over the
  network); an injection can point it at a repo-local ruleset.

## Decision

**Isolate the filesystem (and eventually the whole runtime) of an
untrusted-code review, in two phases.**

- **Phase 1 — deterministic patch (before public/OSS exposure).**
  - `resolveWithinRoot` resolves symlinks (`EvalSymlinks` on both the candidate
    and the root, re-check containment) or refuses to traverse them
    (`Lstat` + reject `ModeSymlink`). Grounding keys on the real resolved path.
  - `run_semgrep` uses a **fixed, trusted ruleset**: no repo-local config path,
    and not `auto` (no network call to the registry).
- **Phase 2 — systemic sandbox (durable posture).** The whole review runs
  sandboxed: checkout mounted read-only, **no access to `~/.argus`**, **no
  network**, and CPU/RAM/wall-clock limits (container, or namespaces +
  seccomp). This closes symlinks, malicious scanner config, resource-abuse DoS,
  and any *future* tool that shells out — without re-auditing each one.

## Consequences

- Phase 1 is a few lines and ships first; Phase 2 is a larger milestone with
  runtime dependencies, tracked as its own PRD. The phasing is deliberate:
  close the concrete arbitrary-read vector immediately, adopt the durable
  isolation on its own timeline.
- A read-only, no-`~/.argus`, no-network sandbox is the strongest guarantee
  precisely because the daemon holds the GitHub App private key on the same
  host (ADR 0008) — defense in depth around the highest-value secret.
- Fixing the scanner ruleset trades a little agent flexibility (it can no
  longer choose a semgrep config) for a closed input; on-demand ruleset choice
  can return later behind the Phase 2 sandbox.

## Alternatives considered

- **Trust `filepath.Clean` alone** (status quo). Rejected: it is a lexical
  check, blind to symlinks — the actual escape.
- **Sandbox only, skip the patch.** Rejected: the sandbox is real work and the
  arbitrary-read hole is live now; the cheap patch should not wait for it.

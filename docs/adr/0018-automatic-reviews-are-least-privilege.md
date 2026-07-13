# ADR 0018 — Automatic, Service-triggered reviews are least-privilege

**Status:** Accepted (implementation phased) — **supersedes the `auto_enroll`
default** set in [ADR 0008](0008-github-channel-as-github-app.md)
**Date:** 2026-07-13
**Builds on:** [ADR 0003](0003-user-table-and-bootstrap.md), [ADR 0008](0008-github-channel-as-github-app.md)

## Context

An automatic PR review is triggered by **anyone** who opens a PR on an enrolled
repo; it runs as the `github-app` **Service** (no Role) over untrusted
third-party code (CONTEXT § *Untrusted review content*). Two facts about the
current implementation made that far more powerful than the Service model
promises:

1. **It can write the shared knowledge base.** `write_context` is in the shared
   tool registry with no Role check, and the memory curator runs on every
   review session (`runReviewTarget` counts a user message; the GitHub session
   is not ephemeral). So an injection in reviewed code could poison
   `~/.argus/context/*.md` and `MEMORY.md` — which are loaded into **every
   future session on the daemon, private repos included**. A public-repo
   attacker could thus silently steer reviews of the org's private code (e.g.
   "these finding types are known false positives"). This directly contradicts
   CONTEXT.md, which states a Service's capabilities are "always narrower than
   any Person's" and that it "never edits SOUL and never manages Principals".

2. **Anyone can trigger it by default.** `auto_enroll` unset defaulted to
   `true` (ADR 0008), so installing the App org-wide auto-reviews every repo,
   public ones included — maximal exposure to injection attempts and to LLM
   budget exhaustion (a stranger spamming PRs can DoS legitimate reviews; there
   is no per-author rate limit, only a global budget cap).

## Decision

**The automatic, Service-triggered review is least-privilege in both what it
can *do* and what can *trigger* it.**

- **Read-only on the knowledge base.** A Service-triggered review does not get
  `write_context` (nor any knowledge-write tool), and its session is marked
  **ephemeral** so the memory curator never runs on it. Knowledge is persisted
  only by a **Person (analyst+)** — through the existing, Role-gated
  `suppress_finding → AppendMemory` path on comments, or admin edits via
  TUI/chat. A run driven by untrusted code can inform its own report but can
  never durably teach the organization.
- **Opt-in enrollment.** `auto_enroll` unset now defaults to **`false`**: an
  Argus admin explicitly enrolls the repos to be auto-reviewed. The global
  budget cap remains the hard spend backstop; per-author / per-repo rate
  limiting is a later phase.

## Consequences

- **Breaking change to the default**, taken deliberately now: per project
  policy there is no installed base before the talk, so defaults are free to
  change and a missing enrollment should fail loud, not silently review the
  world.
- Automatic reviews do **not** self-learn. This is intended: autonomous
  learning from anonymous PR content is exactly the poisoning vector. The
  trusted learning paths (analyst+ on comments, admin edits) are unaffected.
- Enforcing "no knowledge-write for a Service" is the first concrete instance
  of the tool-layer RBAC that CONTEXT.md anticipates ("RBAC is enforced at the
  Tool layer") for the automatic path.

## Alternatives considered

- **Harden the curator / `write_context` against injection instead of removing
  them from the Service path.** Rejected: it re-introduces the unsolvable
  "detect injection in free text" problem, when the deterministic fix (the
  untrusted path simply has no write capability) is cheap and total.
- **Keep `auto_enroll: true` default, add public/private awareness** (auto-
  enroll private, opt-in public). Deferred: it needs the repo-visibility field
  we do not yet parse from the webhook; opt-in-everywhere is simpler and safe
  now, and the visibility-aware default can refine it later.

# ADR 0009 — A PR review scans the whole tree; relevance is judged by the agent

**Status:** Accepted
**Date:** 2026-06-21
**Builds on:** [ADR 0006](0006-no-generic-shell-tool.md), [ADR 0008](0008-github-channel-as-github-app.md)

## Context

A PR review must answer "what's wrong with *this change*", not dump every
pre-existing issue in the repo onto the author. The obvious shortcut —
run the scanners only over the changed files/lines — is cheaper but wrong
in the cases the feature most needs to catch: a diff that calls an insecure
function defined elsewhere, or bumps a dependency to a version with a CVE.
The dangerous code isn't in the diff; only its *activation* is.

This also has to fit Argus's standing posture (ADR 0006): tools return raw
output, the **agent** is the analyst that interprets it.

## Decision

**Scan the whole tree at the PR head; let the agent judge PR-relevance.**

- The repo is checked out at the head SHA and `semgrep`, `gitleaks` and
  `osv-scanner` run over the full tree, so they keep the cross-file context
  that makes them accurate.
- The agent learns the changed files and patch hunks from a `pr_diff` tool
  backed by the GitHub API (`pulls/{n}/files`), **not** from a local git
  diff.
- The agent reports a finding when it is on a changed line **or** causally
  tied to the change. Relevance is a judgement in the loop, not a mechanical
  line filter applied afterwards.
- Findings on changed lines become inline review comments; causal off-diff
  findings go in the summary body (GitHub inline comments can only attach to
  the diff).

## Consequences

- We accept the cost of scanning the whole tree on every review rather than
  just the diff. For the repo sizes Argus targets this buys correctness that
  a line filter cannot.
- "Relevance" is non-deterministic — two runs may surface slightly different
  causal findings. Acceptable: the audit log and the persisted Report record
  what was actually reported, and accepted false positives flow forward via
  MEMORY.
- The `pr_diff` tool makes the agent depend on GitHub API availability for
  relevance, not just on the checkout.

## Alternatives considered

- **Scan only the diff.** Rejected: misses activated-by-diff vulnerabilities
  and supply-chain CVEs, and semgrep on partial files is less reliable.
- **Mechanical post-filter to changed lines.** Rejected: deterministic but
  drops exactly the causal findings (insecure call, vulnerable dependency)
  that justify a security review of a change. Un-idiomatic here — it moves
  the analyst's judgement out of the agent and into a `grep` on line numbers.
- **Whole-repo review with no diff awareness.** Rejected for PRs: floods the
  author with pre-existing findings unrelated to their change. (It remains
  the right shape for the `argus review` *repo review*.)

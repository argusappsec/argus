# ADR 0016 — A review is requested through a Channel; the `argus review` verb retires

**Status:** Accepted
**Date:** 2026-07-09
**Builds on:** [ADR 0011](0011-mcp-channel-as-consultable-colleague.md),
[ADR 0015](0015-integrations-declared-in-configuration.md)
**Amends:** [ADR 0011](0011-mcp-channel-as-consultable-colleague.md) (the
MCP `review` surface)

## Context

`argus review <github-url>` sent a structured review target over the local
socket; the daemon cloned and drove the agent, with a `--headless` "CI
mode". Three things aged badly. The clone was anonymous, so the CLI could
only review public repos while the webhook path reviewed private ones. The
headless mode presupposes socket access — being *on* the daemon host —
which in the server deployment means a CI running `kubectl exec`; no real
CI works that way (the mode is a leftover of the laptop era). And a
dedicated scanner verb fights the product thesis: Argus is a colleague you
*ask* — through GitHub events, MCP, or chat — not a scanner you execute.

## Decision

**The `argus review` command is removed. Repo review remains a first-class
capability, reachable through channels:**

- **Conversationally** (chat today, Slack tomorrow): the agent invokes the
  review tool on request.
- **Over MCP:** the `review` capability accepts **two target forms** —
  caller-supplied files (Snapshot review, unchanged) or a codehost repo
  reference (`repo` + `ref` → Repo review). The repo form requires a
  configured codehost and fails with a clear error otherwise. Same tool,
  no `review_repo` twin: the MCP surface stays deliberately coarse.
- Every clone goes through the CodeHost's credentials (ADR 0015), so
  private repos work from any trigger.
- **PR review stays event-born** (webhook only). If on-demand PR re-review
  is ever wanted, it is a `repo`+`pr` target extension of `review`, not a
  new capability.

## Consequences

- No deterministic review trigger from a terminal: a chat-requested review
  depends on the model calling the tool. The structured dispatch itself
  survives (webhook and the MCP repo target use it), so a `/review`
  slash-skill can restore terminal determinism later if wanted.
- Headless CI reviews are dropped without an immediate replacement.
  Scheduled reviews will arrive as a config-declared trigger inside the
  daemon — consistent with ADR 0015's config-declared Services — not as a
  CLI loop.
- The local MCP-only install keeps working with snapshot targets alone;
  configuring a codehost switches on repo targets with no new endpoint.
- `consult` and review RBAC (review = analyst+, consult = viewer too) are
  untouched.

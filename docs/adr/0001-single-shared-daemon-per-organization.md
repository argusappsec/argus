# ADR 0001 — Single shared daemon per organization

**Status:** Accepted
**Date:** 2026-05-16

## Context

Argus has multiple plausible deployment shapes:

- **A.** Single shared daemon per organization (one `argus.redcarbon.ai`-style
  instance, all employees connect through Slack / MCP / webhook).
- **B.** Per-developer daemon (every engineer runs their own on laptop or
  personal VM; no shared knowledge, no inbound integrations).
- **C.** Hybrid: per-developer for exploration plus a shared production
  instance for CI / PR / team usage.

The choice cascades into every other major design (RBAC, Slack vs personal
notifications, webhooks possible at all, where SOUL/MEMORY/CONTEXT live,
audit semantics, identity model).

## Decision

We deploy Argus as a **single shared daemon per organization**.

- One production instance per company that owns it (RedCarbon runs its own,
  another company would run its own).
- Production state (SOUL.md, MEMORY.md, CONTEXT/, audit log, reports) is
  shared across all employees of that organization.
- Production identity is the organization's, not any individual's.

Importantly, this does NOT exclude the local development loop. The same
binary still supports `argus chat` / `argus review` on a developer's laptop
with a personal `~/.argus/` directory. Local mode is for exploration and
debugging; the shared instance is what the team / webhooks / Slack workspace
talk to.

## Consequences

- RBAC is mandatory. Multiple humans + service principals (webhooks, cron)
  must be distinguishable in the audit log and gated by permission.
- The daemon must expose multiple authentication surfaces: Slack (Socket
  Mode for outbound, OAuth user_id for actor mapping), MCP HTTP (bearer
  tokens), GitHub webhooks (HMAC signature + actor extracted from payload).
- The MCP server is a first-class transport, not a v0.7 nicety. A primary
  user story is "developer in Claude Code asks Argus via MCP for security
  review; Argus brings the organization's full SOUL/MEMORY/CONTEXT that
  Claude Code itself cannot see locally".
- Org-scoped knowledge: SOUL.md captures *the organization's* identity, not
  an individual operator's. Editing SOUL/CONTEXT becomes a privileged
  operation.
- Multi-tenancy in a SaaS sense is explicitly **not a goal**. Each
  organization self-hosts its own instance. We don't attempt to serve
  multiple companies from one daemon.
- Operational footprint: one always-on process, one socket/HTTP listener,
  one disk volume. Backups, deploy, observability all become real concerns
  (deferred until the implementation lands).

## Alternatives considered

- **B (per-developer)** was rejected because it makes Slack-as-team-channel,
  webhooks, and shared CONTEXT either impossible or pointless — i.e. it
  forecloses the features that motivate this project at RedCarbon.
- **C (hybrid)** was rejected as premature: two deploy pipelines and a
  divergent-state risk for a 2-person team. We can adopt it later if a
  concrete need emerges (e.g. air-gapped local dev that can't reach the
  shared instance).

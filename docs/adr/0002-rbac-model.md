# ADR 0002 — RBAC model: three Person roles + scoped Service principals

**Status:** Accepted — amended by
[ADR 0021](0021-cost-controls-removed.md): the "global budget cap" this ADR
invokes as an `admin` power and as the guardrail on `viewer` chat spend was
never built; nothing bounds spend
**Date:** 2026-05-16
**Builds on:** [ADR 0001](0001-single-shared-daemon-per-organization.md)

## Context

Now that Argus is a single shared daemon per organization
([ADR 0001](0001-single-shared-daemon-per-organization.md)), multiple
people — and several automated systems (GitHub webhooks, cron) —
authenticate against the same instance. We need a small, predictable
permission model that:

- Distinguishes humans from systems in the audit log.
- Prevents marketing/sales/etc. members of the Slack workspace from
  reading security findings just because they can @-mention the bot.
- Keeps overhead low for a 2-person team without painting us into a corner
  if the team grows to 5–10.

We rejected per-identity RBAC (Slack handle ≠ same as the GitHub handle ≠
same as the MCP token, each with its own permission row) in favour of
per-Person modelling (see CONTEXT.md → Principal / Person / Identity).
This ADR fixes the role set.

## Decision

Three Person roles, two Service roles. No anonymous/guest tier.

### Person roles

- **admin** — full power. Edits SOUL, manages other Principals,
  configures providers and webhooks, manages cron jobs. (This list also
  read "overrides budget"; there is no budget to override — see
  [ADR 0021](0021-cost-controls-removed.md).)
  Reads the audit log by reading the file directly via shell access:
  audit-log access is **not** a capability, it is filesystem access
  reserved to whoever owns the box. Expected count: 1–2.
- **analyst** — developer or security engineer. Triggers reviews, opens
  chat, writes CONTEXT, reads everything. Cannot edit SOUL or manage
  Principals.
- **viewer** — read-only consumer (CISO, PM, exec). Reads reports;
  may chat with the agent to ask questions about existing findings.
  Cannot trigger fresh reviews or write any state. Chat spend is
  gated by nothing: this entry originally read "gated by the global
  budget cap, not by role", and no such cap was ever wired up — see
  [ADR 0021](0021-cost-controls-removed.md).

### Service roles

- **ci-trigger** — issued per repo. Can trigger one review on its bound
  repo only. The agent writes findings during the review it spawned;
  the Service Principal itself never posts findings directly. The
  capability "generate report" is implicit in "trigger review on this
  repo".
- **mirror-read** — read-only on reports, for downstream exporters
  (publish to S3, push to GitHub Issues, etc.). Reserved for future
  integrations; no concrete consumer yet.

### Unrecognised Principal

Inbound identities that do not resolve to a Person or Service entry
in the user table are rejected with a polite "I don't recognise you;
ask an admin to add you" message. There is no implicit access, no
guest tier, no "first-Slack-user-wins" bootstrap.

## Consequences

- Slack workspace members from non-security teams (marketing, sales)
  cannot read security findings simply by being in the workspace. They
  must be explicitly mapped to a Person — they won't be by default.
- Audit log access is intentionally not a permission. Anyone with SSH
  to the daemon host can `tail audit.log.jsonl`. This matches reality:
  if you own the box, you see the logs. Trying to encode this in RBAC
  produces complexity for no protection.
- ci-trigger Service Principals are scoped at provisioning (one
  webhook secret = one repo). Reviewing a different repo requires a
  different secret. Cross-repo escalation requires admin action.
- viewer can chat. **The decision stands** — letting a CISO ask "explain
  finding #3" is a feature, not a bug — but the compensating control it
  rested on does not exist. This bullet originally read "the budget cap
  is the guardrail against runaway token spend, not the role boundary".
  No budget cap was ever constructed
  ([ADR 0021](0021-cost-controls-removed.md)), so the clause naming what
  bounds a viewer's token spend named nothing: this ADR let `viewer` chat
  against a guardrail that was never there. The role boundary above is
  the whole of it — the Role is read-only on *state*, and **nothing
  bounds what a viewer costs.** The two limits that do exist bound
  concurrency and runaway loops, not spend: `max_concurrent_sessions`
  caps how many Sessions run at once, and the agent's turn ceiling (50 by
  default) ends a single `agent.Run` with `agent.ErrMaxTurnsExceeded` —
  one run, not a Session's total and not a day's. Whether the Role should
  carry a real spend control is a separate and still-open question; see
  ADR 0021.

## Alternatives considered

- **More granular capabilities** (separate the role into atomic verbs:
  `read.reports`, `write.context`, `trigger.review`, …). Rejected as
  premature: 2-person team, three coarse roles cover every realistic
  combination. We can decompose later if we hit a real conflict.
- **Audit-viewer as a separate role**. Rejected because the audit log
  is a file and the daemon host is admin-owned; encoding it as a
  capability is theater.
- **Guest tier with restricted chat access**. Rejected: lets unknown
  Slack workspace members consume tokens and probe the bot. Better to
  reject upfront.

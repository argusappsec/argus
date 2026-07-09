# ADR 0015 — Integrations are declared in configuration: codehosts, channels, one HTTP front door

**Status:** Accepted
**Date:** 2026-07-09
**Builds on:** [ADR 0004](0004-single-process-channel-goroutines.md),
[ADR 0008](0008-github-channel-as-github-app.md),
[ADR 0010](0010-codehost-interface-one-implementation.md),
[ADR 0011](0011-mcp-channel-as-consultable-colleague.md)
**Supersedes in part:** [ADR 0003](0003-user-table-and-bootstrap.md) (Service
provisioning), [ADR 0008](0008-github-channel-as-github-app.md) (Service model)

## Context

Three problems surfaced together while reviewing how a deployed daemon is
configured:

1. **The `github-app` Service row was derived data.** The webhook secret
   lives in `argus.yaml` (as an `env()` reference); its SHA-256 had to be
   duplicated as a Service row in `users.yaml` only so the channel could
   look up its own identity after verifying the HMAC against the very same
   secret. In an injected deployment (ConfigMap + empty PVC) the row is
   missing and verified events are silently dropped
   (`github_event_unattributed`); on secret rotation the two copies drift.
   `ResolveService` had exactly one caller: the GitHub channel resolving
   itself.
2. **The `github:` section mixed two credential directions.** The webhook
   secret authenticates *inbound* deliveries (a Channel concern); the App
   id + private key authenticate *outbound* clones and API calls (a
   CodeHost concern). The outbound half was wired only into the webhook
   channel — the daemon-wide cloner used by chat-triggered reviews was
   anonymous, so the same private repo was reviewable via webhook but not
   on demand.
3. **`installation_id` pinned the daemon to a single org**, even though a
   GitHub App is multi-installation by construction: events carry
   `installation.id`, and API tokens are minted per installation.

## Decision

**Configuration declares the full integration surface; runtime state holds
Persons only.**

- `argus.yaml` gains two typed, named maps mirroring `providers:`:
  - **`codehosts:`** — one entry = one platform instance + one App
    identity (outbound credentials: `app_id`, `private_key_path`).
    Consumed by *every* channel that needs to clone or call the API.
  - **`channels:`** — one entry = one inbound transport binding
    (`type: github` with `webhook_secret` and the enrolment policy;
    `type: mcp`).
- **Services are config-declared, not provisioned.** Configuring the
  GitHub channel *is* what brings the `github-app` Service Principal into
  existence: the channel synthesizes it. `ResolveService`, the
  `services:` section of `users.yaml`, and the `argus service` command
  are removed; `users.yaml` holds Persons only. The Service roles
  `ci-trigger` and `mirror-read` retire with them.
- **`installation_id` is derived, never configured** — from the webhook
  event, or per repo (`GET /repos/{owner}/{repo}/installation`) for
  on-demand reviews. Multi-org support = installing the same App on more
  organizations; zero config change.
- **One HTTP front door.** The daemon owns a single listener
  (`daemon.http_addr`, default `:8080`); HTTP channels bind fixed paths
  (`/webhooks/github`, `/mcp`) instead of ports, and `/healthz` serves
  probes. Per-channel `addr` fields are removed. Exposure control is the
  reverse proxy's job: route `/webhooks/github` publicly, don't route
  `/mcp`.
- **Cardinality:** the schema is plural (named maps) so a second entry of
  a type (GitHub Enterprise Server, a second App) needs no migration, but
  the runtime enforces **one codehost and one channel per type** for now,
  with an explicit error. A channel carries no `codehost:` cross-reference
  until two codehosts of its type can exist.
- **Migration is a hard error.** The old keys (`github:`, `mcp:`) fail
  startup with a message naming their replacement. No dual-read and no
  migration guide: the tool has no installed base to keep compatible.

## Consequences

- An injected `argus.yaml` + empty PVC is a fully working deployment: no
  post-boot `kubectl exec` bootstrap for the webhook, no secret hash to
  keep in sync, and secret rotation touches one place.
- Private-repo reviews work from every channel — the shared cloner
  authenticates through the codehost.
- ADR 0004 is amended, not violated: a Channel owns its transport (Unix
  socket, future Slack WS) *or* registers a path on the front door.
  Per-request panic isolation for HTTP channels is already provided by
  `net/http`; restart-with-backoff remains for loop-owning channels.
- ADR 0012's manifests change: one container port, one Service port,
  probes on `/healthz`, and the GitHub App webhook URL moves to
  `/webhooks/github`.
- `argus init` and `argus doctor` drop the service-row checks (secret-hash
  match no longer exists) and learn the new sections.

## Alternatives considered

- **Daemon auto-upserts the `github-app` row at boot.** Fixes the empty
  bootstrap, keeps the duplication, adds a second writer to `users.yaml`
  (until now CLI-only), and leaves stale rows behind when the config is
  removed.
- **A single `github:` block carrying both credential sets.** One entry
  per external system reads nicely, but it makes "clone private repos
  without exposing a webhook" inexpressible and buries the
  inbound/outbound boundary the glossary already draws between Channel
  and CodeHost.
- **Per-channel listeners (status quo).** Gives L4 isolation per channel
  at the cost of one port + one ingress rule + one doc section per future
  channel. Rejected: path-level routing at the reverse proxy gives the
  same practical control with one port, and MCP remains bearer-token
  authenticated regardless.

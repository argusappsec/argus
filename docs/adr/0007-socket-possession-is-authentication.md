# ADR 0007 — Unix-socket possession is authentication; the Resolver stays strict

**Status:** Accepted
**Date:** 2026-06-12
**Builds on:** [ADR 0002](0002-rbac-model.md), [ADR 0003](0003-user-table-and-bootstrap.md),
[ADR 0004](0004-single-process-channel-goroutines.md)

## Context

ADR 0002 and ADR 0003 establish "no implicit access": any inbound identity
that does not resolve to a Person or Service in `users.yaml` is rejected.
The daemon's local TUI channel (`argus chat` / `argus review` over a Unix
domain socket) puts that rule under tension:

- The socket lives at `<home>/argusd.sock` with mode 0600. Anyone who can
  connect to it can also read `.env` (provider secrets), edit `users.yaml`,
  and tail the audit log. Rejecting them protects nothing — they can grant
  themselves access in one `vim` command.
- The zero-friction local loop promised by ADR 0001 (fresh laptop,
  `argus chat`, no setup) would break: an empty `users.yaml` would lock the
  owner out of their own daemon.

We also had to decide *where* such a trust exception lives: inside
`auth.Resolver`, or inside the channel.

## Decision

**Possession of the Unix socket is the authentication for the local TUI
channel.** Concretely:

- The channel derives the identity `local:<username>` from the kernel's
  peer credentials (`SO_PEERCRED` / `LOCAL_PEERCRED`), never from a frame
  the client sends.
- The channel still calls `auth.Resolve` with that identity. If it resolves
  to a Person, actions are attributed to that Person with their Role — so
  on a shared host the audit log says "davide", not "local:davide".
- If it does **not** resolve, the caller becomes an **implicit admin
  Principal** instead of being rejected. This is the single exception to
  the no-implicit-access rule, and it exists only on this channel.

**`auth.Resolver` stays strict and policy-free**: identity in, Principal or
"unknown" out. The implicit-admin fallback is implemented in the UDS
channel, not in the Resolver. Slack, MCP and webhook use the same Resolver
with no fallback of any kind.

## Consequences

- The local development loop works on a fresh machine with no `users.yaml`,
  and the in-process fallback daemon needs no bootstrap step.
- The trust boundary is the filesystem, same as ADR 0002's stance on audit
  log access: "if you own the box, you see the logs" extends to "if you own
  the socket, you own the daemon". Hardening the socket's directory
  permissions is the operator's lever, not RBAC.
- Remote channels cannot inherit this path by accident: the fallback is
  code in `pkg/channel/uds`, not a Resolver feature a new channel could
  enable by mistake.
- A multi-user daemon host where shell users should NOT all be admins is
  explicitly unsupported. If that ever becomes real, the fix is socket
  group permissions plus mandatory `users.yaml` entries — revisit this ADR.

## Alternatives considered

- **Strict resolution everywhere** (local identities must be in
  `users.yaml`). Rejected as security theater: whoever reaches a 0600
  socket inside `~/.argus/` can already edit the user table. It breaks
  the fresh-laptop flow for zero protection.
- **Fallback inside the Resolver** (e.g. a `ResolveOrLocal` mode). Rejected:
  trust policy would become ambient and reusable by future channels, which
  is exactly the mistake the strict Resolver exists to prevent. Only the
  transport justifies the trust, so only the channel owns it.
- **Client-declared identity in the hello frame.** Rejected: trivially
  spoofable by any process that can open the socket; the kernel already
  gives us the true peer uid.

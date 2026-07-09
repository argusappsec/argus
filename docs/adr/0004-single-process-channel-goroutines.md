# ADR 0004 — Single-process daemon with one goroutine per Channel

**Status:** Accepted — amended by
[ADR 0015](0015-integrations-declared-in-configuration.md): HTTP channels
bind paths on the daemon's shared front door instead of owning ports
**Date:** 2026-05-16
**Builds on:** [ADR 0001](0001-single-shared-daemon-per-organization.md)

## Context

We need to decide the internal shape of the daemon: how do the four
inbound transports (CLI / Slack / MCP / webhook) coexist? Choices range
from a single process with goroutines to a microservices-style
multi-process deployment. The decision determines deploy complexity,
recovery semantics, and the parallel-work contract between team members.

## Decision

**One process. One goroutine per Channel. Shared in-memory state via a
`DaemonContext`.**

```
                ┌────────────────────────────────────────────┐
                │            argusd (one process)            │
                │                                            │
                │  DaemonContext (built once, shared r/o)   │
                │    Provider, Registry, Soul, Auth,        │
                │    Audit, SessionManager, Reports         │
                │                                            │
                │  ┌──────────┐ ┌────────┐ ┌─────┐ ┌──────┐ │
                │  │ CLI/UDS  │ │ Slack  │ │ MCP │ │ HOOK │ │   goroutines
                │  │ listener │ │ WS     │ │ HTTP│ │ HTTP │ │
                │  └────┬─────┘ └───┬────┘ └──┬──┘ └──┬───┘ │
                │       │           │         │       │     │
                │       └───────────┴─────────┴───────┘     │
                │             auth.Resolve(identity)        │
                │             SessionManager.GetOrCreate    │
                │             agent.Run(Options{…})         │
                └────────────────────────────────────────────┘
```

### Channel contract

Every Channel implements:

```go
type Channel interface {
    Name() string
    Start(ctx context.Context) error  // blocks until ctx cancelled
}
```

Channels never construct Provider, Soul, Registry, Auth, etc. — they
receive a `*DaemonContext` at construction. This is the contract that
lets two team members write two Channels in parallel without colliding.

### Concurrency

- N Sessions can run in flight simultaneously. Each Session owns its own
  `agent.Run`, its own ConvoWriter, its own per-session token budget.
- Shared writers (audit logger, MEMORY.md updates from the curator,
  `write_context`, `users.yaml` though that's CLI-only) sit behind a
  mutex.
- Hard ceiling: `max_concurrent_sessions` in `argus.yaml`. Above it,
  the SessionManager refuses new Sessions with a polite "try again
  later" routed back through the Channel.

### Crash recovery

- Each Channel goroutine wraps its body in `defer recover()`. A panic
  inside a Channel is captured, logged, audited as `channel_panic`,
  and the Channel is restarted with exponential backoff. Other
  Channels keep serving.
- A panic in `agent.Run` is recovered by the dispatching Channel and
  surfaced to the caller as an error; the daemon stays up.
- A panic in core code outside a Channel's recover scope is uncaught,
  the process exits, and systemd (or whatever supervises the binary)
  restarts it. State on disk (conversations, audit, reports) survives.

## Consequences

- Deploy is one binary, one systemd unit, one volume. Backup = snapshot
  the volume. Operationally minimal.
- Two team members can implement two Channels in parallel without
  merge conflicts beyond `cmd/daemon.go` (where Channels are
  instantiated) and `pkg/channel/<name>/`.
- A misbehaving Slack lib can take down Slack but never MCP/webhook.
  Best-effort isolation by goroutine; not the same as process
  isolation (which we explicitly do not want).
- The shared state is mostly read-only at run time. Mutation hot
  spots are exactly three files (`MEMORY.md`, `audit.log.jsonl`,
  one CONTEXT/*.md at a time). Each is guarded by a single mutex.
- `agent.Run` can be called concurrently because today's code is
  effectively pure given its Options (Provider is concurrent-safe,
  tools are constructed per call). One per Session is the natural
  pattern.

## Alternatives considered

- **Multi-process (canale-per-processo)** with gRPC/IPC between them
  was rejected: 4× operational overhead (4 systemd units, healthcheck
  per, IPC schema) and the shared state (SOUL/MEMORY/CONTEXT)
  becomes a distributed system on one host. Pathological for the
  problem we have.
- **Core + plugin via Unix domain socket** (the hybrid) inherits the
  complexity of multi-process with half the isolation benefit.
  Rejected.
- **No `Channel` interface**, just inline goroutines per transport.
  Rejected because it makes parallel implementation harder: the
  colleague writing Slack needs to know what shape a Channel is.
  An interface formalises the contract.

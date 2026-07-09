# ADR 0012 — Kubernetes deployment: single-replica StatefulSet, PVC-owned state, declarative config

**Status:** Accepted — amended by
[ADR 0015](0015-integrations-declared-in-configuration.md): one HTTP port,
probes on `/healthz`, webhook URL at `/webhooks/github`, no service
bootstrap step
**Date:** 2026-06-30
**Builds on:** [ADR 0001](0001-single-shared-daemon-per-organization.md),
[ADR 0004](0004-single-process-channel-goroutines.md),
[ADR 0007](0007-socket-possession-is-authentication.md)

## Context

Argus is trivial to host on a VPS: `make build`, drop the binary, run
`argus daemon` under systemd. But an organization that already runs a
dedicated cluster for its bots / AI / ops tooling wants Argus to live there
too, for operational uniformity — one place to manage deploys, secrets,
ingress and TLS.

Kubernetes here buys **self-healing, declarative deploys and managed
secrets/ingress** — *not* scaling or HA. ADR 0001 (one daemon per org) and
ADR 0004 (single process, one goroutine per Channel) combined with the
100% file-based state (`SOUL.md`, `MEMORY.md`, `users.yaml`,
`audit.log.jsonl`, `reports/`, `cache/`), mutated with non-concurrent
read-modify-write via `temp+rename`, mean **at most one instance may ever
be active**. Two pods writing the same files would corrupt state. There is
no distributed lock and no shared database to make active/active possible.

`argus init` is interactive-only (a `huh`/`bubbletea` interview); there is
no non-interactive bootstrap. The daemon strictly requires only
`argus.yaml`; `SOUL.md` and `users.yaml` are optional at startup.

## Decision

Run Argus as a **`StatefulSet` with `replicas: 1`**, never scaled. We pick a
StatefulSet over a Deployment specifically because `replicas: 1` on a
StatefulSet with a `volumeClaimTemplate` *documents the single-instance
invariant in the manifest itself* — the next operator is far less likely to
bump replicas "for safety" and corrupt state. (A `Deployment` with
`strategy: Recreate` is an acceptable fallback; a `RollingUpdate` Deployment
is **not** — it would run two writers during rollout.)

State is split by a single rule — **is it mutated at runtime?**

- **Declarative config — `argus.yaml`, `SOUL.md`.** Stored in a
  **ConfigMap**, managed in Git (GitOps/Flux), copied onto the PVC by an
  **init container** that **overwrites on every boot**. This is safe because
  both files are read once at daemon start and never written at runtime:
  `write_soul` is registered only in the `argus init` interview
  (`cmd/init.go`), never in the daemon's tool registry. Changing `SOUL.md`
  therefore requires a pod restart to take effect.
- **Secrets — provider API keys, GitHub App id/secret/webhook secret.**
  Stored in a **K8s Secret** and injected as **environment variables**
  (`envFrom`). The `env(VAR_NAME)` indirection in `argus.yaml` resolves them
  from the process environment (`os.Getenv`), so **no `.env` file is needed
  in the pod**. The one exception is the GitHub App **private key (PEM)**,
  which `private_key_path` reads from disk: it is a Secret mounted as a
  **file**.
- **Runtime state — `users.yaml`, `MEMORY.md`, `context/`,
  `audit.log.jsonl`, `reports/`, `cache/`.** Lives on a **`ReadWriteOnce`
  PVC** mounted at `ARGUS_HOME`. Never overwritten by the init container.

**Bootstrap and administration.** We never run `argus init` in-cluster.
`users.yaml` starts empty; the first operator administers the daemon
(`argus user add`, MCP token provisioning) via **`kubectl exec`** onto the
local socket, which is implicit admin per ADR 0007. The real access gate is
Kubernetes RBAC over who may `exec` into the namespace — the same trust
boundary as "who can SSH the VPS", relocated.

**Networking.** The two HTTP Channels keep **separate servers** (ADR 0004 —
one Channel owns one transport): GitHub webhook on `:8080`, MCP on `:8090`.
A "single endpoint" is achieved at the **Ingress**, not in the application:
one host, one TLS cert, path routing (`/webhook` → `:8080`, `/mcp` →
`:8090`). This preserves each Channel's distinct auth (HMAC vs bearer) and
lets each surface carry its own network policy — the public webhook can sit
behind a GitHub IP allowlist while MCP can stay internal. Liveness uses a
`tcpSocket` probe (there is no `/health` endpoint).

**Durability.** A PVC is not a backup. We require `reclaimPolicy: Retain` on
the StorageClass and rely on **off-cluster backups** (Velero or scheduled
CSI VolumeSnapshots), prioritizing the append-only `audit.log.jsonl`.
GitOps shrinks the blast radius: after a PVC loss, `argus.yaml` and
`SOUL.md` return from Git and secrets from the secret store, so backups only
need to protect the genuinely irreplaceable accumulated state.

## Consequences

- **No HA, no scaling.** A node/zone failure means downtime until the pod
  reschedules and re-binds its volume; every deploy incurs a few seconds of
  downtime (Recreate semantics). Accepted — Argus serves bots and webhooks,
  not latency-critical user traffic.
- **`kubectl exec` is the only administration channel.** There is no
  declarative user management; `users.yaml` is runtime state, not config.
  Securing the deployment means securing `exec` rights via K8s RBAC.
- **A container image is required.** The repo ships a multi-stage
  `Dockerfile`; the runtime image carries the scanner toolchain — see
  [ADR 0013](0013-batteries-included-runtime-image.md), which supersedes the
  distroless/static base originally shipped with this ADR (it could neither
  clone nor scan). The image still runs nonroot (uid 65532), so the PVC must
  be mounted with `securityContext.fsGroup`.
- **MCP exposure is a deploy-time toggle** (public behind bearer+TLS for
  remote developers, or ClusterIP-only for VPN/in-cluster clients), not an
  architectural decision.

## Alternatives considered

- **Deployment with `replicas: 1`** (the OpenClaw pattern). Works with
  `strategy: Recreate`, but does not encode the single-instance invariant as
  loudly as a StatefulSet, and the default `RollingUpdate` is an active
  foot-gun (two writers). Kept as an acceptable fallback, not the default.
- **`users.yaml` managed declaratively** (ConfigMap/Secret, GitOps).
  Rejected: it is mutated at runtime by `argus user`, so a read-only mount
  breaks administration and contradicts ADR 0003. Runtime state belongs on
  the PVC.
- **Merging the GitHub and MCP servers into one in-process HTTP server** to
  expose a single port. Rejected: it couples two Channels with different
  auth and exposure needs onto one transport, against ADR 0004. The same
  "single endpoint" goal is met at the Ingress with no architectural cost.
- **Running `argus init` in-cluster** (e.g. an interactive `kubectl exec -it`
  or a Job). Rejected as the bootstrap default because it is interactive and
  not reproducible; SOUL is authored once locally and shipped declaratively.

# Hosting Argus on Kubernetes

This guide shows how to run Argus on a Kubernetes cluster. It is meant as a
solid starting point you adapt to your cluster — not a turnkey production
chart.

> **The one rule that shapes everything:** Argus runs as **exactly one
> instance**. Its state is file-based with non-concurrent read-modify-write;
> two active pods would corrupt it. There is no HA or horizontal scaling.
> Kubernetes here gives you self-healing, declarative deploys and managed
> secrets/ingress — not scale. See
> [ADR 0012](../adr/0012-kubernetes-deployment.md) for the reasoning.

If you just want the simplest possible host, a VPS with the binary under
systemd is easier. Reach for Kubernetes when you already run a cluster and
want Argus to live alongside your other bots and ops tooling.

## Architecture on Kubernetes

| Concern | Choice |
| --- | --- |
| Workload | `StatefulSet`, `replicas: 1` (never scaled) |
| State | one `ReadWriteOnce` PVC mounted at `ARGUS_HOME` |
| Config (`argus.yaml`, `SOUL.md`) | `ConfigMap`, seeded onto the PVC by an init container |
| Secrets (API keys, GitHub App) | `Secret` → env vars; the App **PEM** mounted as a file |
| User table (`users.yaml`) | lives on the PVC, managed via `kubectl exec` |
| Networking | two servers, merged at the `Ingress` by path |

### What lives where, and why

Argus splits its files by a single question — *is it mutated at runtime?*

- **Declarative config — `argus.yaml`, `SOUL.md`.** Read once at boot, never
  written at runtime. Keep them in Git, ship them via a `ConfigMap`, and let
  the init container copy them onto the PVC (overwrite on every boot).
  Changing `SOUL.md` requires a **pod restart** to reload.
- **Secrets.** Provider keys and GitHub App credentials go in a `Secret` and
  are injected as **environment variables**. `argus.yaml` references them
  with the `env(VAR_NAME)` syntax, which resolves from the process
  environment — so **you do not need a `.env` file in the pod**. The GitHub
  App **private key** is the exception: `private_key_path` reads a file, so
  mount it from a `Secret`.
- **Runtime state — `users.yaml`, `MEMORY.md`, `context/`,
  `audit.log.jsonl`, `reports/`, `cache/`.** Owned by the PVC. The init
  container never overwrites these.

## Prerequisites

- A Kubernetes cluster (a single-node cluster is fine).
- An Ingress controller (e.g. ingress-nginx) and TLS — **the GitHub webhook
  must be reachable on a public HTTPS URL**. [cert-manager](https://cert-manager.io)
  is the easy path to certificates.
- A container image for Argus. The repo ships a multi-stage
  [`Dockerfile`](../../Dockerfile) that builds a static binary onto a
  distroless `nonroot` base:

  ```sh
  docker build -t ghcr.io/your-org/argus:latest .
  docker push  ghcr.io/your-org/argus:latest
  ```

  The image runs as nonroot (uid `65532`) and exposes `:8080` (GitHub) and
  `:8090` (MCP). If you want the optional scanner binaries (`semgrep`,
  `gitleaks`, `osv-scanner`) available to the agent, add them to a derived
  image or run them in a sidecar — the daemon starts fine without them.

## Step 1 — Author the seed config locally

`argus init` is interactive, so run it **on your laptop** (the local loop is
supported) to produce `argus.yaml` and `SOUL.md`:

```sh
argus init           # pick provider, enter the API key, run the SOUL interview
```

Keep the generated `argus.yaml` and `SOUL.md`, but make `argus.yaml` point at
env vars rather than inline secrets:

```yaml
# argus.yaml (the version you ship to the cluster)
default_model: gemini-2.5-pro
providers:
  gemini:
    type: gemini
    api_key: env(GEMINI_API_KEY)
daemon:
  socket: ~/.argus/argusd.sock
  max_concurrent_sessions: 4
github:
  app_id: env(GITHUB_APP_ID)
  installation_id: env(GITHUB_INSTALLATION_ID)
  webhook_secret: env(GITHUB_SECRET_WH)
  private_key_path: /etc/argus/github_app.pem
  addr: :8080
  auto_enroll: true
mcp:
  addr: :8090
```

## Step 2 — ConfigMap (seed) and Secrets

```sh
# Declarative config seed (versioned in Git, GitOps-friendly)
kubectl create configmap argus-seed \
  --from-file=argus.yaml=./argus.yaml \
  --from-file=SOUL.md=./SOUL.md \
  --dry-run=client -o yaml > argus-seed.configmap.yaml

# Secrets injected as env vars
kubectl create secret generic argus-secrets \
  --from-literal=GEMINI_API_KEY=... \
  --from-literal=GITHUB_APP_ID=... \
  --from-literal=GITHUB_INSTALLATION_ID=... \
  --from-literal=GITHUB_SECRET_WH=...

# GitHub App private key, mounted as a file
kubectl create secret generic argus-github-pem \
  --from-file=github_app.pem=./github_app.pem
```

> For GitOps, encrypt these with [Sealed Secrets](https://sealed-secrets.netlify.app)
> or wire up [External Secrets](https://external-secrets.io) instead of
> committing them.
>
> `SOUL.md` carries org details (stack, infra, escalation contact). If you
> would rather not have it in a ConfigMap, put it in a `Secret` and mount
> `/seed` from there — the mechanism is identical.

## Step 3 — StatefulSet, Service, Ingress

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: argus
spec:
  serviceName: argus
  replicas: 1                       # never scale — see ADR 0012
  selector:
    matchLabels: { app: argus }
  template:
    metadata:
      labels: { app: argus }
    spec:
      securityContext:
        fsGroup: 65532              # let the nonroot image write the PVC
      initContainers:
        - name: seed
          image: busybox:1.37        # just needs sh + cp + test
          command: ["/bin/sh", "-c"]
          args:
            - |
              mkdir -p "$ARGUS_HOME"
              # config is declarative → always re-applied from the ConfigMap
              cp /seed/argus.yaml "$ARGUS_HOME/argus.yaml"
              cp /seed/SOUL.md    "$ARGUS_HOME/SOUL.md"
              # users.yaml is runtime state → never seeded here
          env:
            - { name: ARGUS_HOME, value: /data/.argus }
          volumeMounts:
            - { name: data, mountPath: /data/.argus }
            - { name: seed, mountPath: /seed, readOnly: true }
      containers:
        - name: argus
          image: ghcr.io/your-org/argus:latest
          args: ["daemon"]
          env:
            - { name: ARGUS_HOME, value: /data/.argus }
          envFrom:
            - secretRef: { name: argus-secrets }
          ports:
            - { name: github, containerPort: 8080 }
            - { name: mcp,    containerPort: 8090 }
          livenessProbe:
            tcpSocket: { port: github }   # no /health endpoint; probe the port
            initialDelaySeconds: 10
          readinessProbe:
            tcpSocket: { port: github }
          volumeMounts:
            - { name: data, mountPath: /data/.argus }
            - { name: pem,  mountPath: /etc/argus, readOnly: true }
      volumes:
        - name: seed
          configMap: { name: argus-seed }
        - name: pem
          secret:
            secretName: argus-github-pem
            items:
              - { key: github_app.pem, path: github_app.pem }
  volumeClaimTemplates:
    - metadata: { name: data }
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: retain-sc       # a StorageClass with reclaimPolicy: Retain
        resources:
          requests: { storage: 10Gi }
---
apiVersion: v1
kind: Service
metadata:
  name: argus
spec:
  clusterIP: None
  selector: { app: argus }
  ports:
    - { name: github, port: 8080, targetPort: github }
    - { name: mcp,    port: 8090, targetPort: mcp }
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: argus
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt
spec:
  tls:
    - hosts: [argus.example.com]
      secretName: argus-tls
  rules:
    - host: argus.example.com
      http:
        paths:
          - path: /webhook            # GitHub App webhook → must be public
            pathType: Prefix
            backend: { service: { name: argus, port: { name: github } } }
          - path: /mcp                # drop this path to keep MCP internal
            pathType: Prefix
            backend: { service: { name: argus, port: { name: mcp } } }
```

Point the GitHub App's webhook URL at `https://argus.example.com/webhook`.
Keep MCP internal by omitting its Ingress path and reaching it via the
in-cluster Service or a port-forward.

## Step 4 — Bootstrap users

`users.yaml` starts empty. Possession of the local socket is admin
(see [ADR 0007](../adr/0007-socket-possession-is-authentication.md)), so the
first operator administers the daemon over `kubectl exec`:

```sh
kubectl exec -it argus-0 -- argus user add davide --role admin --email davide@example.com
kubectl exec -it argus-0 -- argus user mcp-token add davide
```

> **Security:** in this model, anyone who can `kubectl exec` into the pod is
> an Argus admin. Lock down `exec` with Kubernetes RBAC the same way you
> would protect SSH to a host.

## Step 5 — Backups

A PVC is **not** a backup — a disk or zone failure loses it. Protect the
runtime state off-cluster:

- Use `reclaimPolicy: Retain` on the StorageClass so deleting the PVC does
  not destroy the underlying disk.
- Schedule **off-cluster backups** with [Velero](https://velero.io) or CSI
  `VolumeSnapshot`s. Prioritize `audit.log.jsonl` (append-only, compliance).
- Do **not** mount the `ReadWriteOnce` PVC from a second backup pod on
  another node — it conflicts with the daemon. Use storage-layer snapshots
  or an in-pod sidecar.

Because `argus.yaml` and `SOUL.md` come from Git and secrets from your secret
store, a PVC loss only costs the accumulated state (`users.yaml`, memory,
context, audit log, reports) — which is exactly what the backups cover.

## Updating configuration

- **`argus.yaml` / `SOUL.md`:** edit in Git, re-apply the ConfigMap, and
  **restart the pod** (`kubectl rollout restart statefulset/argus`). With
  Flux, a ConfigMap-hash annotation or [Reloader](https://github.com/stakater/Reloader)
  rolls the pod automatically.
- **Secrets:** update the `Secret` and restart the pod.
- **Users:** `kubectl exec` as in Step 4 — no restart needed.

# Getting started

Argus runs as a single long-lived daemon per organization. The CLI is
deliberately scoped to **setup and administration** — you talk to Argus
through its channels (TUI chat, GitHub, MCP), you don't execute it as a
scanner.

## Install

### From source

Requirements: **Go 1.26+**. The repo pins its toolchain with
[mise](https://mise.jdx.dev) (see `.mise.toml`):

```sh
git clone https://github.com/argusappsec/argus.git && cd argus
mise install     # optional: pins go + golangci-lint versions
make build       # builds the ./argus binary
```

Scanner binaries (`semgrep`, `gitleaks`, `osv-scanner`) are optional but
recommended — install them on the daemon host and run `argus doctor` to check
what's available.

### Container image

The official image is **batteries-included**: the scanners ship inside, on
both `linux/amd64` and `linux/arm64`.

```sh
docker run -it -v argus-data:/data -p 8080:8080 ghcr.io/argusappsec/argus
```

- `ghcr.io/argusappsec/argus:latest` — latest release
- `ghcr.io/argusappsec/argus:edge` — every push to `main`

State lives under `ARGUS_HOME` (defaults to `/data/.argus` in the image), so
mount a volume at `/data` to keep it. Port `8080` is the single HTTP front
door (webhooks + MCP). The image's entrypoint runs `argus daemon`; for the
interactive setup commands below, exec into the container or run them with
the same volume mounted.

For running on a cluster, see [Kubernetes deployment](deployment/kubernetes.md).

## Bootstrap

```sh
./argus init     # interactive: provider, API key, instance name, guided SOUL
./argus doctor   # verify dependencies and configuration
./argus          # opens the chat (same as `argus chat`)
```

`init` walks you through:

1. **Provider** — currently Google Gemini; the API key can live inline in the
   config or come from the environment (`GEMINI_API_KEY`).
2. **Instance name** — how you'll address Argus ("Argus" by default, or a
   persona of your own — even multi-word).
3. **SOUL** — a guided interview that captures your organization's profile,
   stack, and risk tolerance. Every model call carries it, so reviews reflect
   *your* context. Answer briefly; every line should be able to change a
   decision.

You don't need to start a daemon before chatting: if no daemon is listening
on the socket, the TUI spawns one inside its own process and tears it down on
exit. For a permanent, multi-channel instance, run `argus daemon` (or the
container image, whose default command is exactly that).

## Connect channels

- **GitHub** — `./argus codehost setup` onboards a GitHub App and webhook
  channel; pull-request reviews then fire automatically. See
  [GitHub channel](channels/github.md).
- **MCP** — mint a token with `argus user mcp-token create` and point your
  AI tool at the daemon's `/mcp` endpoint. See [MCP channel](channels/mcp.md).

## Command reference

| Command | Description |
| --- | --- |
| `argus` | Opens the interactive chat (default UX) |
| `argus chat` | Open an interactive chat with the Argus agent |
| `argus init` | Interactive bootstrap: provider, API key, instance name, and `SOUL.md` |
| `argus codehost setup` | Onboard a GitHub code host + webhook channel |
| `argus doctor` | Check that dependencies and configuration are ready |
| `argus user add/ls/rm/grant` | Manage the Person table (`~/.argus/users.yaml`) |
| `argus user mcp-token create/revoke` | Manage MCP bearer tokens |
| `argus skill ls` / `argus skill rm <name>` | Manage agent skills |
| `argus daemon` | Run the Argus daemon (`argusd`) |

## Where state lives

Everything is file-based under `~/.argus/` (or `ARGUS_HOME`):

| Path | Purpose |
| --- | --- |
| `argus.yaml` | Configuration — see [Configuration](configuration.md) |
| `SOUL.md` | Organization identity, injected into every model call |
| `MEMORY.md` | Curated cross-session summary |
| `context/*.md` | Topical knowledge base, loaded on demand |
| `skills/<name>/SKILL.md` | User-curated skill bundles |
| `users.yaml` | The Person table and role grants |
| `argusd.sock` | The daemon's Unix socket |

> Argus runs as **exactly one instance** per organization: its state is
> file-based with non-concurrent read-modify-write, so never run two daemons
> against the same `ARGUS_HOME`.

## Upgrading from 0.2.x

Configuration moved to v2: the legacy top-level `github:` / `mcp:` keys,
`installation_id`, and per-channel `addr` now **fail startup** with an error
naming the replacement (`codehosts:` / `channels:`, and the single HTTP front
door). Operators with an existing GitHub App must also change its webhook URL
from `/webhook` to `/webhooks/github`.

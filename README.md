<p align="center">
  <img src="brand/argus.svg" alt="Argus — peacock feather with an eyespot" width="140">
</p>

# Argus

> An LLM-driven security review agent for GitHub repositories.

Argus is a security review agent that reasons about code the way an analyst
does: it runs scanners, reads findings, consults organizational context, and
talks back to you in plain language. It runs as a single long-lived daemon per
organization and reaches its users through multiple channels — a local TUI, a
Slack bot, an MCP server, and signed GitHub webhooks — all sharing one trust
model, one audit log, and one knowledge base.

## Highlights

- **Conversational reviews.** Ask for a review in chat or over MCP and get
  findings explained, not just dumped; pull-request reviews fire automatically
  from GitHub webhook events.
- **Real scanners, no shell escape.** Argus wraps tools like
  [`semgrep`](https://semgrep.dev), [`gitleaks`](https://github.com/gitleaks/gitleaks)
  and [`osv-scanner`](https://github.com/google/osv-scanner)
  as structured, code-reviewed Go tools. There is deliberately no generic
  `bash`/`exec` tool exposed to the model (see [ADR 0006](docs/adr/0006-no-generic-shell-tool.md)).
- **Organization identity (SOUL).** Company profile, stack, compliance posture,
  and persona are loaded into every model call so reviews reflect *your* risk
  tolerance.
- **Persistent memory & context.** A curated `MEMORY.md` carries session
  continuity forward; topical `context/*.md` documents form an on-demand
  knowledge base.
- **Skills.** Multi-step workflows bundled as `SKILL.md` directories, built-in
  or user-curated, triggerable with `/<name>` in chat.
- **RBAC + audit.** Every action is attributed to a Principal (Person or
  Service) with a Role, and recorded in an append-only audit log.

## Architecture at a glance

Argus runs as **one shared daemon per organization** (`argusd`). Every channel
is a goroutine inside that single process, sharing a common `DaemonContext`
(provider, tool registry, SOUL, MEMORY, auth, audit logger).

| Channel | Transport | Identity |
| --- | --- | --- |
| **TUI** | local Unix socket | `local:$USER` (socket possession = auth) |
| **Slack** | Socket Mode bot | `slack:<user_id>` |
| **MCP** | HTTP (Model Context Protocol) | `mcp:<token-hash>` |
| **Webhook** | signed GitHub HTTP events | bound Service principal |

The full domain vocabulary lives in [CONTEXT.md](CONTEXT.md); design decisions
are recorded as ADRs under [docs/adr/](docs/adr/).

## Requirements

- **Go 1.26+**
- A supported LLM provider API key (currently **Google Gemini** via
  `google.golang.org/genai`)
- Optional scanner binaries on the daemon host: `semgrep`, `gitleaks`, `osv-scanner`
  (run `argus doctor` to check what's installed)

This repo uses [mise](https://mise.jdx.dev) to pin toolchain versions
(see [`.mise.toml`](.mise.toml)). With mise installed:

```sh
mise install
```

## Build

```sh
make build      # builds the ./argus binary
make test       # go test -race ./...
make lint       # golangci-lint run ./...
make tidy       # go mod tidy
```

## Getting started

```sh
# 1. Bootstrap: pick a provider, set the API key, create SOUL.md
./argus init

# 2. Verify dependencies and configuration
./argus doctor

# 3. (optional) Onboard a GitHub code host and webhook channel
./argus codehost setup

# 4. Talk to the agent (running `argus` with no args opens chat)
./argus chat
```

Reviews are requested **through a channel**, not a CLI verb: ask for one
conversationally in chat, or call the MCP `review` capability (with
caller-supplied files for a snapshot review, or a `repo` + `ref` for a full
repo review). Pull-request reviews are triggered automatically by GitHub
webhook events. See [ADR 0016](docs/adr/0016-review-requested-through-channels.md).

### Commands

The CLI is deliberately scoped to setup and administration — you talk to Argus
through channels, you don't execute it as a scanner ([ADR 0016](docs/adr/0016-review-requested-through-channels.md)).

| Command | Description |
| --- | --- |
| `argus` | Opens the interactive chat (default UX) |
| `argus chat` | Open an interactive chat with the Argus agent |
| `argus init` | Interactive bootstrap: provider, API key, and `SOUL.md` |
| `argus codehost setup` | Onboard a GitHub code host + webhook channel (writes `codehosts:` / `channels:`) |
| `argus doctor` | Check that dependencies and configuration are ready |
| `argus user ...` | Manage the Person table and MCP tokens |
| `argus skill ls` / `argus skill rm <name>` | Manage agent skills |
| `argus daemon` | Run the Argus daemon (`argusd`) |

## Configuration

User preferences live in `~/.argus/argus.yaml`:

```yaml
default_model: gemini-2.5-pro
providers:
  gemini:
    type: gemini
    api_key: env(GEMINI_API_KEY)   # or set inline
daemon:
  socket: ~/.argus/argusd.sock
  http_addr: :8080                 # single HTTP front door
  max_concurrent_sessions: 4
```

Integrations are declared in config (v2, [ADR 0015](docs/adr/0015-integrations-declared-in-configuration.md)):
`codehosts:` holds the outbound App identity every channel clones and calls the
API with; `channels:` holds the inbound transport bindings. There is no
`installation_id` — the acting installation is derived per event and per repo —
and no per-channel `addr`: the daemon serves every HTTP channel on the one
front door (`/webhooks/github`, `/mcp`, plus `/healthz`).

```yaml
codehosts:
  github:
    type: github
    app_id: env(GITHUB_APP_ID)
    private_key_path: /secrets/github-app.pem
channels:
  github:
    type: github
    webhook_secret: env(GITHUB_WEBHOOK_SECRET)
    auto_enroll: true              # + enabled_repos, an explicit allow-list
  mcp:
    type: mcp
```

> **Upgrading from 0.2.x:** the legacy top-level `github:` / `mcp:` keys,
> `installation_id`, and per-channel `addr` now **fail startup** with an error
> naming the replacement. Operators with an existing GitHub App must also
> change its webhook URL from `/webhook` to `/webhooks/github`.

Runtime state lives under `~/.argus/`:

- `SOUL.md` — organization identity, injected into every model call
- `MEMORY.md` — curated cross-session summary
- `context/*.md` — topical knowledge base
- `skills/<name>/SKILL.md` — user-curated skill bundles

> **Note:** the API key can be provided via the `GEMINI_API_KEY` environment
> variable (e.g. a local `.env`, which is git-ignored). Never commit live keys.

## Project layout

```
argus.go            # entrypoint
cmd/                # cobra command tree (chat, init, codehost, doctor, user, skill, daemon)
pkg/
  agent/            # agent run loop, dispatch, system prompt assembly
  auth/             # principal/identity resolution, RBAC
  audit/            # append-only audit log
  config/           # argus.yaml + env handling
  daemon/           # daemon, session manager, channel runner
  provider/         # LLM provider abstraction
  security/         # semgrep, gitleaks, osv-scanner tool wrappers
  skill/            # skill catalog (user-curated + built-in via embed.FS)
  soul/             # SOUL.md loading
  memory/           # MEMORY.md curation
  report/           # findings + stable finding IDs
  tool/             # tool interfaces (Requirer, skills tools)
docs/
  adr/              # architecture decision records
  agents/           # agent conventions (issue tracker, triage, domain)
```

## Documentation

- [CONTEXT.md](CONTEXT.md) — canonical domain glossary
- [docs/adr/](docs/adr/) — architecture decision records
- [docs/deployment/kubernetes.md](docs/deployment/kubernetes.md) — hosting Argus on Kubernetes
- [AGENTS.md](AGENTS.md) — agent instructions and conventions

## License

Argus is licensed under the [Apache License 2.0](LICENSE). The Argus logo and
brand assets are licensed under [CC BY 4.0](brand/LICENSE).

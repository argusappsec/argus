# Configuration

All configuration lives in one file: `~/.argus/argus.yaml` (or
`$ARGUS_HOME/argus.yaml`). Secrets never need to be inline — any value can be
deferred to the environment with the `env(NAME)` syntax.

## Full example

```yaml
# Which model the agent uses by default.
default_model: gemini-2.5-pro

# LLM providers. Today: Google Gemini.
providers:
  gemini:
    type: gemini
    api_key: env(GEMINI_API_KEY)   # or set inline
    # url: ...                     # optional endpoint override

# How you address the instance ("Argus" by default). Multi-word names work:
# they are matched as a vocative ("Ercole il Guardiano, guarda qui").
persona:
  name: Argus

daemon:
  socket: ~/.argus/argusd.sock     # Unix socket for the local TUI
  http_addr: :8080                 # single HTTP front door (webhooks + MCP)
  max_concurrent_sessions: 4

# Outbound code-host identities: the App the channels act as.
codehosts:
  github:
    type: github
    app_id: env(GITHUB_APP_ID)
    private_key_path: /secrets/github-app.pem

# Inbound transport bindings.
channels:
  github:
    type: github
    webhook_secret: env(GITHUB_WEBHOOK_SECRET)
    auto_enroll: false             # review only repos in enabled_repos
    enabled_repos:
      - my-org/payments-api
  mcp:
    type: mcp
```

## The codehosts / channels split

- **`codehosts:`** holds the *outbound* identity — the GitHub App every
  channel clones and calls the API with. There is no `installation_id`: the
  acting installation is derived per event and per repo.
- **`channels:`** holds the *inbound* transports. HTTP channels have no
  per-channel `addr`: the daemon serves them all on the one front door
  (`daemon.http_addr`) at fixed paths — `/webhooks/github`, `/mcp`, plus
  `/healthz`.

`argus codehost setup` writes both sections for you — see the
[GitHub channel](channels/github.md) guide.

## Key reference

| Key | Meaning |
| --- | --- |
| `default_model` | Model used by the agent unless a session overrides it |
| `providers.<name>.type` | Provider kind (`gemini`) |
| `providers.<name>.api_key` | API key, inline or `env(...)` |
| `providers.<name>.url` | Optional endpoint override |
| `persona.name` | The instance's name; used as the vocative on GitHub threads |
| `daemon.socket` | Unix socket path for the local TUI |
| `daemon.http_addr` | Bind address of the single HTTP front door |
| `daemon.max_concurrent_sessions` | Cap on concurrently running sessions |
| `codehosts.github.app_id` | GitHub App ID |
| `codehosts.github.private_key_path` | Path to the App's private key PEM |
| `channels.github.webhook_secret` | Secret used to verify webhook signatures |
| `channels.github.auto_enroll` | Review every installed repo (`true`, current default) or only `enabled_repos` |
| `channels.github.enabled_repos` | Explicit `owner/repo` allow-list when `auto_enroll: false` |
| `channels.mcp` | Enables the MCP channel on the front door |

> **Recommendation:** set `auto_enroll: false` with an explicit
> `enabled_repos` allow-list. On public repos, `auto_enroll: true` means
> anyone who can open a PR can trigger a review (and spend your budget). The
> default is moving to opt-in
> ([ADR 0018](../adr/0018-automatic-reviews-are-least-privilege.md)).

## Legacy keys fail loudly

Argus is pre-1.0 and config schemas change between minors — but never
silently. The v1 keys (top-level `github:` / `mcp:`, `installation_id`,
per-channel `addr`) abort startup with an error naming their replacement.

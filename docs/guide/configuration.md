---
title: Configuration
description: The full argus.yaml reference — providers, code hosts, channels, and the keys that matter.
sidebar:
  order: 20
---

All configuration lives in one file: `~/.argus/argus.yaml` (or
`$ARGUS_HOME/argus.yaml`). Secrets never need to be inline — any value can be
deferred to the environment with the `env(NAME)` syntax.

## Full example

```yaml
# Which model the agent uses by default. Bare, or qualified as
# `<provider-name>/<model-id>` when more than one provider could serve it.
default_model: gemini-2.5-pro

# LLM providers. A `type` names a protocol, not a vendor.
providers:
  gemini:
    type: gemini
    api_key: env(GEMINI_API_KEY)   # or set inline
    # url: ...                     # optional endpoint override
  local:
    type: openai-compatible        # any server speaking the OpenAI protocol
    url: http://localhost:11434/v1 # a local runtime needs no api_key

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
[GitHub channel](/guide/channels/github/) guide.

## LLM providers

Each entry under `providers:` is one model backend, keyed by a **logical name
you choose**. The name is what a model id qualifies against, so a short one is
worth picking.

A provider's `type` names a **protocol, not a vendor**. There are two:

| `type` | What it speaks |
| --- | --- |
| `gemini` | Google's Gemini API |
| `openai-compatible` | The OpenAI chat-completions protocol — any server that implements it |

`openai-compatible` covers hosted services (OpenAI, OpenRouter, Groq, Together,
DeepSeek, Mistral, Cerebras) and local runtimes (Ollama, vLLM, LM Studio,
llama.cpp) alike. A local runtime is **not** a type of its own: it's a server
that speaks this protocol, reached as a base URL.

Argus implements the protocol and certifies nobody's server, so read
[LLM providers](/guide/llm-providers/) for what Argus requires from a model, and run
`argus doctor` to verify your own endpoint meets it.

### Per-provider keys

| Key | Required | Meaning |
| --- | --- | --- |
| `type` | yes | `gemini` or `openai-compatible`. An unknown value is an error naming the supported types |
| `api_key` | in practice | The secret, inline or `env(...)`. See below |
| `url` | no | Base URL. Empty means the provider's default endpoint. `openai-compatible` only — a `gemini` entry ignores it |
| `max_output_tokens` | no | Client-side cap on response length. Omitted means no ceiling is sent. `openai-compatible` only — on a `gemini` entry a non-zero value is an error |

**`api_key`** is not a schema requirement — no key is a valid configuration, and
for `openai-compatible` it is a **useful** one: a local runtime that
authenticates nobody needs none, and when the key is empty Argus sends no
`Authorization` header at all rather than an empty bearer token. Against a
hosted endpoint, omitting it just means the endpoint rejects you. Prefer the
`env(NAME)` form — `argus init` writes it that
way, and the secret then lives in `~/.argus/.env` instead of in this file. A
referenced variable that is unset or empty is a startup error, not a silent
fallback.

**`url`** accepts `env(NAME)` too. Empty means the provider's own default
endpoint — for `openai-compatible` that's `https://api.openai.com/v1`, so
pointing at OpenAI itself needs no `url`. Take the base URL from `argus init`'s
preset list rather than from memory: **the `/v1` suffix is this protocol's
sharpest footgun**, and services disagree about it. It is honoured by
`openai-compatible` only: the Gemini client takes no endpoint, so a `url` on a
`gemini` entry is resolved and then **dropped** — it changes nothing, and
nothing warns you it didn't. Don't read it as a way to route Gemini traffic
through a proxy of your own: it isn't one.

```yaml
providers:
  openai:
    type: openai-compatible
    api_key: env(OPENAI_API_KEY)
    # no url: https://api.openai.com/v1 is the default
  openrouter:
    type: openai-compatible
    api_key: env(OPENROUTER_API_KEY)
    url: https://openrouter.ai/api/v1     # not the domain root
  groq:
    type: openai-compatible
    api_key: env(GROQ_API_KEY)
    url: https://api.groq.com/openai/v1   # not the domain root
  deepseek:
    type: openai-compatible
    api_key: env(DEEPSEEK_API_KEY)
    url: https://api.deepseek.com         # served at the domain root: no /v1
  local:
    type: openai-compatible
    url: http://localhost:11434/v1        # Ollama; no api_key needed
```

`argus init` offers these as presets (plus Together, Mistral and Cerebras, and
a custom entry for anything else) and fills in the URL for you. It also
pre-fills from `OPENAI_API_KEY` and `OPENAI_BASE_URL` if you already export
them.

**`max_output_tokens`** exists as a lever against a *silent* failure. Some
self-hosted configurations cap output low, and a Report that runs past that cap
comes back **truncated mid-write — a mutilated file, not an error**. The run
succeeds and the last section simply isn't there. You cannot change a hosted
server's default, so raising the ceiling from the client side is the only fix
available. Omitting the key sends no ceiling at all, which is both the default
and the ecosystem norm. It too is honoured by `openai-compatible` only — but
here a non-zero value on a `gemini` entry is an **error**, not an ignored
setting: the Gemini client accepts no output ceiling, and a lever that quietly
does nothing hands you the very truncated Report the key exists to prevent.
(That's the one asymmetry with `url` above, which is dropped instead of refused:
an endpoint that is never read corrupts nothing on the way past.) Zero stays
valid everywhere, so simply omit the key on `gemini` entries.

### Model ids and which provider serves them

`default_model` and any per-session `argus chat --model` override resolve to
exactly one configured provider. The canonical form is
`<provider-name>/<model-id>`, split on the **first slash only** — so an id that
already contains a slash still qualifies unambiguously:

```yaml
# provider "openrouter"; the model id "anthropic/claude-sonnet-4.5"
# keeps its own slash and travels to the wire whole.
default_model: openrouter/anthropic/claude-sonnet-4.5
```

Qualification is optional. Resolution runs in this order:

1. **Qualified form** — the segment before the first slash names a configured
   provider. The rest is the model id, sent verbatim.
2. **Exactly one provider configured** — any bare id belongs to it, including
   one containing a slash. This is why the common case needs no ceremony.
3. **Name-or-type prefix match** — a bare id that equals a provider's *name* or
   *type*, or begins with it followed by a hyphen (`gemini-2.5-flash` → the
   `gemini` provider). This is how single-provider Gemini configurations
   written before qualification existed keep working untouched.

Anything else is an error, and each one says what to write instead:

- **Ambiguous** — a bare id that several providers could serve. The message
  names every candidate and shows the qualified form to write, picking the
  first alphabetically as the example so it reads the same on every run.
- **No match** — no provider matches and none was named. The message lists the
  configured providers.
- **Malformed** — an empty id, or a qualification with nothing after the slash.

### Cost visibility

Argus reports **token counts and no dollar figure**.

In the chat TUI the running counts sit in the status line, and `/cost` prints
them as `tokens in:<n> out:<n>`. They are cumulative per session.

A per-model price table cannot survive a world where any base URL is a valid
endpoint: prices change per vendor on their own schedule, and the same model id
costs different amounts behind different gateways. An incomplete table doesn't
decline to answer — it reports **zero**, and a false zero is worse than no
number, because it's a number you have no reason to distrust. An operator who
wants a cost figure has their provider's pricing page and an accurate token
count.

Token counts are correct for every model on every endpoint, including a local
runtime where the marginal cost isn't measured in dollars at all.

Nothing bounds spend. The only runaway guard anywhere in Argus is the agent's
**turn ceiling** — 50 turns per message by default, overridable with
`argus chat --max-turns` — which bounds one agent run, not a session in
aggregate.

## Key reference

| Key | Meaning |
| --- | --- |
| `default_model` | Model used by the agent unless a session overrides it; bare or `<provider>/<model-id>` |
| `providers.<name>.type` | Protocol the provider speaks (`gemini`, `openai-compatible`) |
| `providers.<name>.api_key` | API key, inline or `env(...)`; optional for `openai-compatible` |
| `providers.<name>.url` | Base URL; empty means the provider's default endpoint; ignored on a `gemini` entry |
| `providers.<name>.max_output_tokens` | Client-side cap on response length; omitted sends no ceiling; a non-zero value is an error on a `gemini` entry |
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

:::caution[Set an explicit allow-list]
Prefer `auto_enroll: false` with an explicit `enabled_repos` list. On public
repos, `auto_enroll: true` means anyone who can open a pull request can trigger
a review — and every review spends tokens on your account. **Nothing bounds that
spend:** Argus reports token counts and enforces no cap, no ceiling, and nothing
anywhere that will refuse a call. The allow-list is the control. The default is
moving to opt-in.
:::

## Legacy keys fail loudly

Argus is pre-1.0 and config schemas change between minors — but never
silently. The v1 keys (top-level `github:` / `mcp:`, `installation_id`,
per-channel `addr`) abort startup with an error naming their replacement.

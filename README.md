<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/argus-banner-dark.svg">
    <img src="brand/argus-banner-light.svg" alt="Argus — application security agent" width="460">
  </picture>
</p>

<h3 align="center">Security reviews that reason like an analyst.</h3>

<p align="center">
  <a href="https://github.com/argusappsec/argus/actions/workflows/ci.yml"><img src="https://github.com/argusappsec/argus/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/argusappsec/argus/releases"><img src="https://img.shields.io/github/v/release/argusappsec/argus" alt="Latest release"></a>
  <a href="https://github.com/argusappsec/argus/pkgs/container/argus"><img src="https://img.shields.io/badge/ghcr.io-argusappsec%2Fargus-0E6E63?logo=docker&logoColor=white" alt="Container image"></a>
  <a href="go.mod"><img src="https://img.shields.io/github/go-mod/go-version/argusappsec/argus" alt="Go version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/argusappsec/argus" alt="License"></a>
</p>

Argus is an open-source **application security agent**. It reviews code the
way an analyst does: it runs real scanners, reads their findings, weighs them
against your organization's context, and talks back in plain language. One
long-lived daemon per organization — reached through the places your team
already works: a terminal chat, GitHub pull requests, and MCP from your own
AI tools.

## Why Argus

Deterministic scanners are precise but shallow — a missing ownership check
has no signature to pattern-match. Language models can read and reason about
code, but on their own they drown the signal in false positives. Argus pairs
the two and adds the missing third ingredient: **your organization**. Scanners
are wrapped as structured tools, the model is disciplined by curated
methodology, and every review is grounded in your company's stack, risk
tolerance, and accumulated knowledge — so the answer isn't "here are 400
findings", it's a conversation with a colleague who knows your codebase.

## Quick start

```sh
git clone https://github.com/argusappsec/argus.git && cd argus
make build

./argus init     # pick a provider, set the API key, shape your org's SOUL
./argus doctor   # verify scanners and configuration
./argus          # chat with your security engineer
```

Prefer containers? The batteries-included image ships with `semgrep`,
`gitleaks`, and `osv-scanner` preinstalled:

```sh
docker run -it -v argus-data:/data -p 8080:8080 ghcr.io/argusappsec/argus
```

To review pull requests, connect a GitHub App with `./argus codehost setup`
and open a PR: the review arrives on its own, and you can answer back right
on the thread — *"Argus, is this finding real?"*.

New here? Start with **[Getting started](docs/guide/getting-started.md)**.

## Features

- **Reviews you can talk to.** Ask in chat, call over MCP, or let GitHub
  webhooks trigger them automatically — then discuss the findings instead of
  grepping a SARIF file.
- **Real scanners, no shell escape.** `semgrep`, `gitleaks`, and
  `osv-scanner` run as structured, code-reviewed Go tools; the model is
  deliberately given no generic `bash`/`exec`.
- **Knows your organization.** A SOUL file (company profile, stack,
  compliance posture, persona) rides along in every model call; curated
  memory and a topical knowledge base carry context across sessions.
- **Skills.** Multi-step methodologies bundled as markdown, triggered with
  `/<name>` — four built-ins included, bring your own with a `SKILL.md`.
- **One trust model.** Every action across every channel is attributed to a
  principal with a role and recorded in an append-only audit log.
- **Hardened against prompt injection.** Reviewed code is data, never
  instructions: automatic reviews run least-privilege, file access is confined
  to the checkout, and confidentiality is enforced on what Argus posts.

## How it works

Argus runs as **one shared daemon per organization** (`argusd`). Every channel
is a goroutine inside that single process, sharing one provider, one tool
registry, one knowledge base, and one audit log.

| Channel | Transport | Identity |
| --- | --- | --- |
| **TUI** | local Unix socket | `local:$USER` (socket possession = auth) |
| **MCP** | HTTP (Model Context Protocol) | `mcp:<token-hash>` |
| **GitHub** | signed webhook events | Service principal (webhooks), `github:<login>` (comments) |
| **Slack** *(planned)* | Socket Mode bot | `slack:<user_id>` |

## Built-in skills

| Skill | What it does |
| --- | --- |
| `authz-audit` | White-box hunt for broken authorization (BOLA/IDOR, BFLA) — validated at 100% recall / 100% precision on VAmPI |
| `pr-quick-check` | Fast security pass over a pull request diff |
| `secret-rotation-plan` | Find committed secrets and draft a prioritized rotation plan |
| `threat-modeling` | Build a STRIDE threat model of a codebase |

## Documentation

- **[Getting started](docs/guide/getting-started.md)** — install, bootstrap, first chat
- **[Configuration](docs/guide/configuration.md)** — the full `argus.yaml` reference
- **[GitHub channel](docs/guide/channels/github.md)** — automatic PR reviews and talking to Argus on threads
- **[MCP channel](docs/guide/channels/mcp.md)** — Argus as a consultable colleague for your AI tools
- **[Skills](docs/guide/skills.md)** — using, writing, and overriding skills
- **[Kubernetes deployment](docs/guide/deployment/kubernetes.md)** — hosting Argus on a cluster

Curious how it's designed? The domain vocabulary lives in
[CONTEXT.md](CONTEXT.md), every architectural decision is recorded under
[docs/adr/](docs/adr/), and deeper design rationale under
[docs/design/](docs/design/).

## Status

Argus is **pre-1.0** and moving fast. Defaults and configuration schemas may
change between minor versions — always loudly, with startup errors that name
their replacement, never silently.

## License

Argus is licensed under the [Apache License 2.0](LICENSE). The Argus logo and
brand assets are licensed under [CC BY 4.0](brand/LICENSE).

---
title: Deployment shapes
description: Toolbox and colleague — what Argus does without a model configured, what it does with one, and how the shape is decided.
sidebar:
  order: 5
---

Argus runs in one of two shapes, and there is no setting that picks between
them. The shape is **derived from one fact**: whether an LLM provider is
configured.

| Shape | When | What Argus is |
| --- | --- | --- |
| **Toolbox** | No provider configured | Real scanners, your organization's knowledge, its memory and its security methodologies, served to whatever AI tool you already use. **Your** agent does the reasoning. |
| **Colleague** | At least one provider configured | All of the above, plus Argus reasoning on its own behalf: reviews, consultations, automatic pull-request reviews. |

The startup log names the shape it derived, and so does `argus doctor`. Neither
reports a toolbox as broken for having no provider — that is the shape, not a
fault.

## The toolbox is the floor

A colleague is a **storey above a toolbox, not a different building**. Every
capability a toolbox serves, a colleague serves too — the same scanners, the
same knowledge, the same memory, the same skills, through the same endpoint,
behaving identically. A colleague adds; it never replaces.

That is worth saying plainly because the toolbox is not a trial, a preview or a
crippled mode. It is a complete answer to a real problem, and for many people it
is the only shape they will ever need.

## Why run a toolbox

Most developers who would benefit from Argus already pay for a coding agent —
Claude Code, Codex, opencode and the rest — and are not looking for a second,
per-token bill on top of it.

That subscription cannot be handed to Argus. It is authenticated in a CLI on
your own machine, under your own name: it is not an endpoint a daemon can be
pointed at, and one shared daemon holding one such login would attribute
everybody's work to one person's account.

So the toolbox puts the two halves where they belong. **The reasoning stays
where your subscription already is** — in your agent, on your machine,
authenticated as you. Argus supplies everything around it, which is the part
that is tedious to build and impossible to improvise:

- **The scanners** — Semgrep, Gitleaks and OSV-Scanner — invoked correctly and
  returned as findings your agent can reason over, instead of three integrations
  you write once and then maintain.
- **Your organization's knowledge** — its security identity, your context
  documents, and past review reports — readable over MCP (Model Context
  Protocol), the standard your AI tool already speaks.
- **Memory across sessions**, so what was settled once does not have to be
  settled again in the next conversation, in another repository, from another
  client.
- **Your security methodologies** as skills, offered in your client's own prompt
  menu, so you invoke the organization's workflow by picking it from a list.

A small team gets one more thing: **one Argus everyone points their own agent
at**. The knowledge and the memory are shared; each person's reasoning is paid
for by their own subscription. Scanning is the part that stays close to the
code — it runs on the daemon's own filesystem, as the note below explains.

## Running Argus as a toolbox

Install Argus as described in [Getting started](/guide/getting-started/), then
skip `argus init` — it exists to choose a model, and you are not choosing one.
Write `~/.argus/argus.yaml` yourself instead:

```yaml
daemon:
  http_addr: :8080     # the single HTTP front door

channels:
  mcp:
    type: mcp
```

No `providers:`, no `default_model`. Then mint a credential for yourself and
start the daemon:

```sh
argus user add alice --role analyst               # analyst can scan and write; viewer only reads
argus user mcp-token create alice --name laptop   # prints the token once, stores only its hash
argus daemon                                      # starts, and names the shape it derived
```

That is the whole daemon side. Point your AI tool at `/mcp` on the front door
with that token as a bearer credential — the
[MCP channel](/guide/channels/mcp/) page has the client-side details, and what
you get tool by tool.

`argus doctor` reports the shape it derived and which scanner binaries are
installed; run it once the daemon is up and it checks the front door too.

:::caution[An exported `GEMINI_API_KEY` counts as a provider]
An installation with no `providers:` block but a `GEMINI_API_KEY` in its
environment (or in `~/.argus/.env`) has a usable model, so Argus derives
**colleague** — that fallback predates the two shapes and is kept so nobody's
working setup degrades under them. It also means such a daemon then insists on a
`default_model` and refuses to start without one. If you meant to run a toolbox,
unset the variable; `argus doctor` tells you which shape you actually have.
:::

:::note[Run it on the machine your code is on]
A toolbox scans code **on the host Argus runs on**: your agent names an absolute
path there, and Argus scans it. Client and daemon on one machine is what this is
built for today — a laptop, or a home server you also check code out on.
:::

:::tip[Your organization's identity is optional here]
`SOUL.md` — the identity every model call carries in a colleague — is written by
`argus init`'s guided interview, which needs a model. A toolbox runs perfectly
well without one; until you have it, anything you and your agent work out can be
written to a context document instead, and read back by every later session.
:::

## What a toolbox does not do

Four things are unavailable, and they are all the same thing:

- **Review** — Argus running a full security review itself.
- **Consult** — asking Argus a question and getting Argus's answer.
- **Automatic pull-request reviews** on GitHub.
- **`argus chat`**, and any conversational turn with Argus.

Each of these is *Argus's own agent loop*: Argus reading, scanning, judging and
writing over many turns, on its own behalf. That loop needs a model of its own,
and a toolbox has none. This is not a feature held back — there is nothing there
to hold back.

The limit is honest about itself rather than hidden:

- The capabilities that need reasoning are **absent from the tool listing**, not
  present and failing. Your agent never offers you something that would fail.
- Naming one anyway gets **an explanation** — what is missing, and that
  configuring a provider is what brings it back — rather than an unknown-tool
  error.
- `argus chat` still opens, since holding the socket is how you administer the
  daemon. A conversational turn comes back with the same explanation rather than
  an obscure failure.
- A channel that cannot work at all without reasoning **fails at startup**,
  naming the reason. That is the [GitHub channel](/guide/channels/github/)
  whenever automatic reviews are on — which they are unless you turn them off
  explicitly. A configured integration is never silently dead.

Nothing is lost by the absence in day-to-day use: your own agent is what reads
the code and weighs the findings, and it does that well. What Argus adds is the
apparatus and the memory, not a second opinion.

## Adding a provider later

Configuring a provider is an **upgrade to a running installation, not a
migration**. There is nothing to export, nothing to re-import and nothing to
reinstall:

1. Add a provider and a `default_model` to `argus.yaml` — see
   [LLM providers](/guide/llm-providers/) for what Argus needs from a model. Or
   run `argus init`, which writes both for you and can run the guided interview
   that produces `SOUL.md`; it leaves your channels, people and tokens alone.
2. Restart the daemon.

Your knowledge, memory, context documents, skills, people and tokens are
untouched — they were never provider-specific. What the MCP channel offers is
decided per request, from the shape as it is at that moment, so your AI tool sees
the larger set the next time it connects — no change to its own configuration,
no re-registering the server.

What appears:

- **Review and consult** over MCP, and `argus chat` in your terminal.
- **Automatic pull-request reviews**, once you connect the
  [GitHub channel](/guide/channels/github/).
- **A memory curator** — at the end of each session Argus rewrites what it
  remembers, keeping what earned its place, instead of memory only ever growing
  by what a caller appended.

:::caution[A broken provider is still an error]
No provider is a shape. A provider that is *misconfigured* — an unresolvable
model id, an `env(...)` reference that is unset — fails at startup, loudly. The
alternative would be a daemon that looks like a healthy toolbox until the first
review fails.
:::

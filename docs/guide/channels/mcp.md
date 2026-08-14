---
title: MCP channel
description: Connect Claude Code, Cursor and your own AI tools to Argus — its scanners, your organization's knowledge, its memory and its skills.
sidebar:
  order: 41
---

Argus exposes an MCP (Model Context Protocol) server so that *other* AI
tools — Claude Code, Claude Desktop, Cursor, your own agents — can use it. It is
one endpoint, and what it offers depends on the
[deployment shape](/guide/deployment-shapes/):

- **A toolbox** (no LLM provider configured) serves the deterministic
  capabilities: the scanners, your organization's knowledge, its memory and its
  skills. Your AI tool does the reasoning.
- **A colleague** (a provider configured) serves all of that *and* Argus's own
  judgement — a review or a consultation your tool can delegate and get an
  answer back from.

Either way the organization's knowledge — its identity, what Argus remembers
across sessions, and your context documents — is **kept in one place**, on the
Argus host, behind one set of people and roles. Reads are attributed and
audited. What a client reads does travel into that client's own model, which is
the point: a toolbox works by putting your organization's context in front of
the agent you already trust with your code.

## Setup

The channel is served on the HTTP front door at `/mcp`. Enable it and mint a
token:

```yaml
# argus.yaml
channels:
  mcp:
    type: mcp
```

```sh
argus user add alice --role analyst
argus user mcp-token create alice --name laptop   # prints the cleartext once, stores only its hash
```

Point your MCP client at the endpoint with the token as a bearer credential:

```
URL:            https://argus.your-company.example/mcp
Authorization:  Bearer <token>
```

Every call is attributed to the **Person** who owns the token — the human Argus
recognizes behind the identity `mcp:<token-hash>` — with their role and audit
trail. Revoke anytime with `argus user mcp-token revoke`.

## What's exposed

### Scanners

Three tools run the real scanners on the Argus host and hand your agent their
findings to reason over:

| Tool | Looks for |
| --- | --- |
| `run_semgrep` | Code-level vulnerability patterns |
| `run_gitleaks` | Secrets committed to the tree |
| `run_osv_scanner` | Known vulnerabilities in dependencies |

Each takes a `path`: **an absolute path to a directory on the machine Argus runs
on**. Argus scans code it can already see locally — it is not sent your files.
During a review started by Argus itself the target is inherited and `path` may
be omitted.

A path that is missing, unreadable or not a directory is refused by name. That
is deliberate: a scan that silently found nothing because it ran against the
wrong directory is the worst answer available.

:::note[Install the scanners on the daemon host]
The scanners are separate binaries — `semgrep`, `gitleaks`, `osv-scanner`. Run
`argus doctor` to see which are present. The official container image ships all
three.
:::

### Your organization's knowledge

| Tool | What it does |
| --- | --- |
| `list_context` | List the context documents this organization keeps |
| `read_context` | Read one of them |
| `write_context` | Write one — what you and your agent worked out, available to every later session |

The same knowledge is also readable as **resources**, for clients that pull
context directly rather than through tools: your organization's identity, each
context document, what Argus remembers (`argus://memory`), and recent review
reports.

### Memory

| Tool | What it does |
| --- | --- |
| `save_memory` | Remember one thing across sessions — a preference, a convention, a decision |
| `mark_false_positive` | Record that a finding was judged a false positive here, with the reason |

Memory is what makes installing Argus worth more than wiring three scanners into
your own agent for an afternoon: it is the one thing a fresh session cannot
reconstruct for itself.

What `mark_false_positive` records is **advisory, not a mute**. Whoever reads
memory next — Argus in a later review, your own agent in a later session — takes
it as context and re-judges the same pattern per situation, so the same finding
somewhere genuinely vulnerable can still be flagged. Give the reason — it is
what makes the record re-judgeable instead of a rule nobody can revisit.

:::caution[Memory is bounded — 8 KiB]
Memory exists to be present in *every* conversation, so everything in it is a
recurring cost rather than a one-off: Argus carries it in every model call it
makes, and your own agent pulls it at the start of a session. Past **8 KiB** a
write still succeeds — nothing is truncated and nothing is dropped — and the
answer carries a signal saying memory is full, how large it now is, and that
material should move into a context document with `write_context`.

Act on it rather than ignoring it. That is the boundary between the two:
**memory is paid for on every call; a context document is paid for only when it
is read.** Keep one-line facts in memory and put the long material where it can
be looked up.
:::

### Skills

Your [skills](/guide/skills/) — the security methodologies Argus follows —
reach a client two ways:

- **As prompts.** Every skill appears in your client's own prompt menu. Pick
  one and its instructions go to your AI tool, which follows them with Argus's
  capabilities alongside its own. You never need to know a tool name.
- **As tools** — `list_skills`, `read_skill`, `read_skill_file` — for an agent
  that goes looking on its own, or needs a skill's supporting files.

### Argus's own judgement

Served by a **colleague** only:

- **`review`** — a security review Argus runs itself. Two targets:
  - *snapshot*: the caller supplies the files to review;
  - *repo*: a `repo` + `ref` on a connected code host, which Argus checks
    out and reviews in full.
- **`consult`** — ask a question against the organization's knowledge and get
  Argus's answer.

On a toolbox they are simply not in the listing, so your agent never offers you
something that cannot work — and naming one anyway gets an explanation rather
than a bare unknown-tool error. See
[deployment shapes](/guide/deployment-shapes/#adding-a-provider-later) for what
configuring a provider adds.

## What's deliberately absent

**File reading, grepping and listing.** Your own agent has those already, and
better: they are local to it, they cost it one hop, and routing the same content
through Argus would make your client pay for it twice. Argus offers what your
agent cannot get anywhere else.

**Generic security Q&A** ("what is path traversal?"). Your AI tool answers that
on its own. This surface exists for what only Argus can do: real scanners,
grounded in your organization's context and history.

## Roles

The role on the token is enforced here, on every call:

| Role | Can |
| --- | --- |
| **viewer** | Read — context documents, skills, resources — and `consult`, which asks a question and changes nothing |
| **analyst**, **admin** | All of the above, plus the scanners, the writes (`write_context`, `save_memory`, `mark_false_positive`) and `review` |

A refused call comes back naming the capability and the role it needs, so your
agent can tell you what to ask your administrator for. Read-only means the same
thing on every surface: a viewer following a skill that writes is simply refused
at that step.

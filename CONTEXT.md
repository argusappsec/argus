# Argus — Domain Glossary

This file is the canonical vocabulary for Argus. Implementation details
belong in code or ADRs, not here. Each entry is one short paragraph that
fixes the meaning of a term to one specific thing.

Add entries as concepts solidify during architecture discussions. If a term
becomes ambiguous in conversation, that's the signal to come back here.

---

## Identity model

### Principal

Anything that can act on Argus: a person (via Slack, MCP, CLI) or a service
(webhook, cron, CI bot). Every action recorded in the audit log is
attributed to exactly one Principal. Subtypes: **Person**, **Service**.

### Person

A subtype of Principal representing a human being. A Person owns zero or
more **Identities** (the actual login surfaces) and has exactly one
**Role**. Audit records and RBAC checks reason about Persons, not
Identities — so "Davide" appears in the audit log whether he came in via
Slack, MCP, or the CLI.

### Service

A subtype of Principal representing a non-human actor: GitHub webhook,
cron job, CI integration. A Service has a fixed scoped Role assigned at
provisioning time and is bound to a specific resource (e.g. one webhook
secret is bound to one repo). Services never edit SOUL or manage other
Principals.

### Identity

One concrete authentication surface owned by a Person. Examples:
`slack:U123ABC`, `github:davideimola`, `mcp-token:abc…12`, `email:
davide@redcarbon.ai`. Multiple Identities can resolve to the same Person.
The mapping is stored in the daemon's user file.

### Role

A named bundle of capabilities. Each Person has exactly one Role.

**Person Roles**:
- **admin** — full power. Edits SOUL, manages Persons + Services, manages
  cron + webhooks, configures providers, overrides budget caps. Reads the
  audit log directly off disk (it's a file). Expected count: 1–2.
- **analyst** — developer / security engineer. Triggers reviews, opens
  chat, writes CONTEXT, reads everything. Cannot edit SOUL or manage
  other Principals.
- **viewer** — read-only consumer (CISO, PM, exec). Can read reports and
  ask the agent questions via chat (consuming tokens, gated by the
  global budget cap). Cannot trigger reviews from scratch, write context,
  or modify any state.

**Service Roles**:
- **ci-trigger** — bound to one repo at provisioning. Can trigger a
  review on that repo only. The agent writes findings during the review
  it spawned; the Service itself never posts findings directly.
- **mirror-read** — read-only on reports for downstream export
  integrations (e.g. publish to S3, push to GitHub Issues).

**Unrecognised principal** — any inbound request whose identity does NOT
resolve to a Person or Service entry is rejected with a polite
"contact your administrator" message. There is no implicit / guest /
anonymous access. This is not a Role: it's the absence of one.

---

## Knowledge

### SOUL

`~/.argus/SOUL.md` on the daemon host. The *organization's* identity:
company name, industry, data sensitivity, stack, infra, compliance, risk
tolerance, escalation contact, plus a free-form persona paragraph. Loaded
into every LLM call as part of the system prompt. Editable only by Persons
with the right Role.

### MEMORY

`~/.argus/MEMORY.md`. Curated cross-session summary written automatically
by the **memory curator** subagent at the end of each session. Read by the
main agent at the start of every session, so prior context (preferences,
accepted false positives, recent decisions) flows forward. Distinct from
SOUL: MEMORY is fast-moving session continuity, SOUL is slow-moving
identity.

### CONTEXT

`~/.argus/context/*.md`. Topical knowledge base documents the agent
consults on demand. Each file is one topic (architecture, threat-model,
known-fps, auth-conventions, ...). Discovered via `list_context`, read via
`read_context`, written via `write_context`. Grows organically as agents
and humans learn things.

---

## Capabilities

### Tool

A Go-implemented function the LLM can call. Has a Name, Description (which
the LLM reads to decide when to call it), Schema (JSON Schema of args), and
Execute (the actual implementation). Lives in `pkg/tool/` or domain
packages (`pkg/security/`). When a Tool shells out to a binary it
additionally implements `tool.Requirer` so `argus doctor` can verify the
binary is installed.

**No generic shell escape.** A Tool always has a fixed surface — explicit
args, explicit semantics, written in Go and reviewed in code. We do NOT
expose a `bash` / `exec` / `run_arbitrary_command` tool. Wrapping a
specific binary like `semgrep` with structured args is a Tool;
forwarding an arbitrary command string from the LLM to the OS shell is
not. See ADR 0006.

### Skill

A **directory bundle**: a `SKILL.md` (frontmatter — `name`, `description`,
optional `tags` — plus a free-form body describing a multi-step workflow)
together with optional supporting files (templates, examples) the body may
reference. Skills are **content, not state**: the agent reads the body and
follows the instructions. There is no active / inactive mode, no per-skill
tool whitelist, no `finalize_skill`. Supporting files are discovered only
by reading the body — there is no automatic file listing; the body names
the files it wants, the agent pulls them on demand.

- **User-curated** — files under `~/.argus/skills/<name>/SKILL.md` on the
  daemon host. This is the implemented surface (`pkg/skill`).
- **Built-in** — bundled with the binary via `embed.FS` in
  `pkg/skill/builtin/<name>/SKILL.md`. Planned (PLANNING stream F); when
  present, a user-curated skill overrides the built-in of the same name.

Skills compose existing Tools; they never define new ones. If a skill
references a Tool that isn't registered, the agent simply doesn't have
that capability and adapts. RBAC is enforced at the Tool layer, not in
the skill: a skill cannot escalate the caller's permissions.

Override is **whole-bundle**: a user-curated skill that owns a name wins the
entire directory (body *and* supporting files) over the built-in of that
name — never a per-file mix.

LLM-facing surface:

- `list_skills` — returns one `name — description [tags]` line per skill.
- `read_skill(name)` — returns the full markdown body.
- `read_skill_file(skill, path)` — returns a supporting file from a skill's
  bundle, sandboxed within that skill's directory (built-in or user-curated,
  transparent to the caller).

User-explicit trigger: `/<name>` in chat. When the token is not a built-in
client command, Argus loads that skill and dispatches its body directly to
the agent as one turn — deterministic, with no dependence on the model
choosing to call `read_skill`. The body enters the conversation, so it
stays in context for follow-up turns.

Skills are an analyst+ capability (viewers can't use them), enforced at the
Tool layer once channel auth (stream A) lands.

---

## Channels

A way for a Principal to talk to Argus. Each Channel is one transport
binding. All Channels coexist as goroutines inside the single daemon
process (see ADR 0004) and share a `DaemonContext` with the common
state (Provider, Registry, SOUL, MEMORY, Auth, audit logger, …).

### Channel interface

```go
type Channel interface {
    Name() string
    Start(ctx context.Context) error  // blocks until ctx is cancelled
}
```

Each implementation:
1. Listens on its own transport (Slack WS, HTTP, Unix socket).
2. Extracts an Identity from the inbound event.
3. Resolves it to a Principal via `auth.Resolve` — rejects strangers.
4. Allocates or retrieves a Session via `SessionManager`.
5. Dispatches to `agent.Run` with the right Options.
6. Streams responses back through its own transport.

### Channels in scope

- **TUI** — local Unix socket (the `argus chat` / `argus review` CLI on
  the operator's laptop). Auth = filesystem permissions on the socket;
  Identity = `local:$USER`.
- **Slack** — Socket Mode bot. Identity = `slack:user_id` extracted from
  Slack events.
- **MCP** — HTTP server exposing Resources + Tools per the Model Context
  Protocol. Identity = `mcp:<token-hash>` from the bearer token.
- **Webhook** — HTTP endpoint receiving signed GitHub events. The
  webhook secret resolves to a Service Principal; the Person who
  authored the triggering PR is recorded as metadata in the audit
  event, not as the actor.

## Session

One running conversation between a Principal and the agent. Has an `id`,
a `principal`, a `channel`, a (possibly empty) target repo, a conversation
log file, and a budget counter. A Session may produce multiple agent runs
in sequence (one per user message).

Key shapes:
- A Slack thread is **one long-lived Session**: subsequent replies in the
  thread re-attach to the same Session, the agent keeps context.
- A webhook event is **one one-shot Session**: created on the inbound,
  destroyed when `agent.Run` returns.
- An MCP connection is **one Session for the duration of the connection**.

## SessionManager

Daemon-internal component that allocates Sessions, keys them by
`session-id = hash(channel, conversation-key)`, and enforces the
`max_concurrent_sessions` soft cap configured in `argus.yaml`. Above
the cap, new requests are queued or politely rejected.

When a Channel needs a Session for an inbound event it calls
`SessionManager.GetOrCreate(channel, conversation-key, principal)`.
This is the single point where session identity is decided.

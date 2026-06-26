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

Single exception: the **local TUI channel**. Possession of the Unix
socket implies ownership of the daemon host — the same trust that lets
an admin read the audit log off disk — so a `local:$USER` identity that
does not resolve becomes an implicit admin instead of being rejected.
When it *does* resolve, actions are attributed to that Person with their
Role. Remote channels (Slack, MCP, Webhook) have no such exception.

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

Accepted false positives recorded here are **advisory, not a global mute**:
the agent reads them as context and re-judges per situation, so the same
finding ID (rule + snippet) in a genuinely vulnerable context elsewhere can
still be flagged. This is deliberate — a content-stable ID matching is not
sufficient grounds to silently drop a finding. Deterministic suppression
("ignore this, it's a false positive") applies only to the **current** PR
review where it was requested; cross-PR/-repo carryover is the soft,
re-judged kind.

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

User-explicit trigger: `/<name>` in chat. Client-side commands (`/help`,
`/quit`, …) never leave the client; any other `/<name>` travels raw and
is resolved **on the daemon**, against the organization's catalog — the
same on every Channel. When the token is not a built-in client command,
Argus loads that skill and dispatches its body directly to
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
   The Resolver is strict and policy-free; any trust policy (e.g. the
   local socket's implicit admin) belongs to the Channel that owns the
   transport, because only the transport justifies it.
4. Allocates or retrieves a Session via `SessionManager`.
5. Dispatches to `agent.Run` with the right Options. Dispatch accepts
   either a conversational user message or a **structured review
   target** (repo + ref): starting a review is deterministic, never
   dependent on the model choosing to call a tool. The webhook channel
   relies on this; `argus review` exercises it.
6. Streams responses back through its own transport.

### Channels in scope

- **TUI** — local Unix socket (the `argus chat` / `argus review` CLI on
  the operator's laptop). Auth = filesystem permissions on the socket;
  Identity = `local:$USER`.
- **Slack** — Socket Mode bot. Identity = `slack:user_id` extracted from
  Slack events.
- **MCP** — HTTP server exposing Resources + Tools per the Model Context
  Protocol. Identity = `mcp:<token-hash>` from the bearer token. The MCP
  client is an *external generalist AI* (Claude Desktop, Cursor, …) for whom
  Argus is a **consultable colleague**, not a toolbox: the surface is a few
  coarse capabilities (a security `review`, an org-knowledge `consult`) plus
  Resources over the org knowledge (SOUL, CONTEXT, recent reports), never the
  low-level scanner tools. So the external AI delegates and Argus runs its own
  org-aware loop — SOUL/MEMORY/CONTEXT stay inside Argus. **Non-goal:** generic
  security Q&A ("what is path traversal?") the external AI already answers on
  its own; the exposed surface is deliberately limited to what needs Argus's
  unique value (the org's shared knowledge + the real scanners).
- **GitHub** — a GitHub App (installation) receiving signed events for the
  repos it is installed on. One transport, two event paths:
  - **`pull_request` opened/synchronize** → an automatic review. The
    triggering principal is a **Service** representing the App
    installation (one webhook secret for the whole App, not per-repo); the
    Person who authored the PR is recorded as metadata, not as the actor.
    Which installed repos get reviewed is gated by the `github.auto_enroll`
    policy in `argus.yaml` (see ADR 0008).
  - **comment events** (`issue_comment`, `pull_request_review_comment`)
    that contain the mention token `@argus` → a conversational turn. The
    actor is the **Person** resolved from the commenter's
    `github:<login>` Identity. The App receives every comment event for
    installed repos and parses the body itself — it does not depend on
    GitHub's native mention resolution. Argus replies as the `argus[bot]`
    account.

  Channel-specific trust policy (overrides the global "reject with a
  message" rule, the same way the local socket has its own): a comment
  whose `github:<login>` does **not** resolve to a Person, or that omits
  the `@argus` mention, is **silently ignored** — no reply. Replying
  "contact your administrator" to every passer-by on a public PR would be
  noise and an abuse surface.

## Session

One running conversation between a Principal and the agent. Has an `id`,
a `principal`, a `channel`, a (possibly empty) target repo, a conversation
log file, and a budget counter. A Session may produce multiple agent runs
in sequence (one per user message).

Key shapes:
- A TUI connection is **one Session**: created at connect, destroyed at
  disconnect. An in-flight agent run dies with its connection. Resuming
  a previous Session is a future capability, not a current one.
- A Slack thread is **one long-lived Session**: subsequent replies in the
  thread re-attach to the same Session, the agent keeps context.
- A GitHub PR is **one Session with a stable identity but one-shot
  execution**: the session-id is keyed by `(github, repo + PR number)`,
  so the automatic review (on `pull_request`) and every later `@argus`
  comment map to the same Session. The live object is re-hydrated from
  the conversation log on each event, runs one `agent.Run`, and is
  released when the run returns — it does **not** hold a slot between
  events. Continuity comes from the on-disk log, not from a resident
  in-memory session.
- An MCP connection is **one Session for the duration of the connection**.

## SessionManager

Daemon-internal component that allocates Sessions, keys them by
`session-id = hash(channel, conversation-key)`, and enforces the
`max_concurrent_sessions` cap configured in `argus.yaml`. Above the
cap, new Sessions are politely rejected — never queued. If queueing
ever becomes necessary it belongs to the Channel that needs it (e.g.
webhook dedup), not to the SessionManager.

When a Channel needs a Session for an inbound event it calls
`SessionManager.GetOrCreate(channel, conversation-key, principal)`.
This is the single point where session identity is decided.

---

## Review

### Review

One agent-driven security analysis of a code target, producing a Report.
The word alone is ambiguous, so we always qualify the target:

- **Repo review** — the whole checkout at a single SHA. The `argus review`
  CLI and the existing `agent.Target{Repo, SHA, Path}` shape. No notion of
  a diff.
- **PR review** — a diff-aware review of a Pull Request (see below). Same
  scanners, run over the whole tree at the PR head for context, but the
  findings are filtered to those relevant to the PR.
- **Snapshot review** — a review of **caller-supplied content** rather than a
  repo Argus clones. Born on the MCP channel: the external AI hands Argus the
  changed files/diff from the developer's working tree (which Argus, possibly
  remote/self-hosted, cannot read itself). It is **collaborative, not
  one-shot** — Argus may answer "to judge this I also need `auth/middleware.go`
  and the dependency manifest" and the external AI supplies them on a follow-up
  call. This is what preserves Argus's cross-file reasoning (the authz-audit
  skill resolves helpers/middleware by reading them, not by name; osv-scanner
  needs the manifest) when it does not possess the repo.

_Avoid_ using bare "review" when the target matters.

### Pull Request (PR)

The review target on the GitHub channel: a `base…head` proposed change on
a GitHub repository. A PR keys exactly one GitHub Session (by repo + PR
number) and is the unit the automatic review and all `@argus` comment
turns attach to. Argus learns its changed files and patch hunks from the
GitHub API (`pulls/{n}/files`), not from a local diff.

### PR-relevant finding

A Finding that Argus surfaces on a PR. Relevance is **judged by the
agent**, not by a mechanical line filter: a finding qualifies when it sits
on a changed line, **or** when it is causally tied to the change (the diff
calls an insecure function defined elsewhere, bumps a dependency to a
version with a CVE, etc.). Findings on changed lines become inline review
comments; causal off-diff findings go in the summary body, since GitHub
inline comments can only attach to the diff.

### CodeHost

The platform hosting the code under review. A small Go interface
(`pkg/codehost`) over the few operations the GitHub channel and agent
need — parse a repo/PR URL, clone with auth, fetch a PR's changed files
and patch hunks, post a review and inline comments, resolve a commenter's
Identity. **GitHub** is the only implementation today; the interface
exists so a second host (GitLab, …) can slot in later without rewriting
the channel. _Avoid_: "codesource", "provider" (that word is taken by the
LLM Provider). Note the vocabulary gap a second host will expose: GitLab's
equivalent of a PR is a **Merge Request**, and it authenticates with a
token rather than an App. See ADR 0010.

### GitHub App

The installation-based GitHub identity Argus runs as on the GitHub
channel. It receives signed webhook events, clones private repos and calls
the API with an installation token, and posts back as the `argus[bot]`
account. Required permissions: `contents: read` (clone), `pull_requests:
write` (read changed files, post the review + inline comments), and the
mandatory `metadata: read`. Chosen over a bare webhook receiver (cannot
write back) and a personal access token (not per-install, not scoped to an
org's repos). See ADR 0008.

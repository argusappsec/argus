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

A subtype of Principal representing a non-human actor — today the GitHub
App installation. A Service is **not provisioned**: it is declared by the
configuration of the Channel that carries it (configuring the GitHub
channel is what brings the `github-app` Service into existence; removing
that configuration removes the Service). It has no operator-assigned Role:
its capabilities are fixed by the channel type and are always narrower
than any Person's — a Service never edits SOUL, never manages Principals,
and **never writes to the knowledge base**: an automatic, Service-triggered
review is *read-only* on org knowledge — it does not write CONTEXT and does
not trigger MEMORY curation. Knowledge is persisted only by a Person
(analyst+); a run driven by untrusted third-party code can inform the
current report but can never durably teach the organization. The concept
exists so the audit log can attribute non-human actions to exactly one
actor. _Avoid_: treating a Service as an entry in the user file —
`users.yaml` holds Persons only.

### Identity

One concrete authentication surface owned by a Person. Examples:
`slack:U123ABC`, `github:davideimola`, `mcp-token:abc…12`, `email:
davide@redcarbon.ai`. Multiple Identities can resolve to the same Person.
The mapping is stored in the daemon's user file.

### Role

A named bundle of capabilities. Each Person has exactly one Role.

**Person Roles**:
- **admin** — full power. Edits SOUL, manages Persons, manages
  cron + webhooks, configures providers, overrides budget caps. Reads the
  audit log directly off disk (it's a file). Expected count: 1–2.
- **analyst** — developer / security engineer. Triggers reviews, opens
  chat, writes CONTEXT, reads everything. Cannot edit SOUL or manage
  other Principals.
- **viewer** — read-only consumer (CISO, PM, exec). Can read reports and
  ask the agent questions via chat (consuming tokens, gated by the
  global budget cap). Cannot trigger reviews from scratch, write context,
  or modify any state.

Roles apply to **Persons only**. A Service has no Role — its capabilities
are fixed by the channel type that declares it. (Retired terms:
**ci-trigger** and **mirror-read** were Service roles under the ADR 0003
model, where services were provisioned rows in the user table; they died
when services moved to channel configuration.)

**Unrecognised principal** — any inbound request whose identity does NOT
resolve to a known Principal is rejected with a polite
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
tolerance, output language, non-negotiable severity rules, plus a free-form
persona body (mission + conduct). Loaded into every LLM call as part of the
system prompt. Editable only by Persons with the right Role. Schema rule: a
field earns its place here only if it changes an agent decision on every
call — anything else belongs in CONTEXT/ or MEMORY.

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
binding — a transport of its own (Unix socket, Slack WS) or a path on the
daemon's single HTTP front door (`/webhooks/github`, `/mcp`); a Channel
never owns a port of its own. All Channels coexist as goroutines inside
the single daemon process (see ADR 0004) and share a `DaemonContext` with
the common state (Provider, Registry, SOUL, MEMORY, Auth, audit logger, …).

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
   and the MCP repo-target `review` rely on this.
6. Streams responses back through its own transport.

### Channels in scope

- **TUI** — local Unix socket (the `argus chat` CLI on the operator's
  laptop). Auth = filesystem permissions on the socket;
  Identity = `local:$USER`.
- **Slack** — Socket Mode bot. Identity = `slack:user_id` extracted from
  Slack events.
- **MCP** — HTTP server exposing Resources + Tools per the Model Context
  Protocol. Identity = `mcp:<token-hash>` from the bearer token. The MCP
  client is an *external generalist AI* (Claude Desktop, Cursor, …) for whom
  Argus is a **consultable colleague**, not a toolbox: the surface is a few
  coarse capabilities (a security `review` — whose target is either
  caller-supplied files, a Snapshot review, or a codehost repo reference,
  a Repo review — and an org-knowledge `consult`) plus
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
    Which installed repos get reviewed is gated by the GitHub channel's
    `auto_enroll` policy in `argus.yaml` (see ADR 0008).
  - **comment events** (`issue_comment`, `pull_request_review_comment`)
    addressed to the instance → a conversational turn. Two accepted
    forms: the bare instance name opening the comment ("Argus, explain
    this" / "Ercole guarda qui") — the canonical form, because `@argus`
    on github.com belongs to an unrelated real user whom a tag on a
    public repo would ping — or an `@argus`/`@<persona>` handle anywhere
    in the body, kept as an alias for habit. The actor is the **Person**
    resolved from the commenter's `github:<login>` Identity. The App
    receives every comment event for installed repos and parses the body
    itself — it does not depend on GitHub's native mention resolution.
    Argus replies as the `argus[bot]` account.

  Channel-specific trust policy (overrides the global "reject with a
  message" rule, the same way the local socket has its own): a comment
  whose `github:<login>` does **not** resolve to a Person, or that is
  not addressed to Argus (no opening name, no @-handle), is **silently
  ignored** — no reply. Replying "contact your administrator" to every
  passer-by on a public PR would be noise and an abuse surface.

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
  so the automatic review (on `pull_request`) and every later comment
  addressed to Argus map to the same Session. The live object is re-hydrated from
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

- **Repo review** — the whole tree at a single SHA, cloned from the
  CodeHost with its credentials (private repos included). Requested on
  demand through a conversational channel (chat) or over MCP with a repo
  target — there is no dedicated CLI verb. No notion of a diff.
- **PR review** — a diff-aware review of a Pull Request (see below). Same
  scanners, run over the whole tree at the PR head for context, but the
  findings are filtered to those relevant to the PR.
- **Snapshot review** — an org-aware review of caller-supplied code over the
  MCP channel (ADR 0011). A remote/self-hosted Argus cannot read the
  developer's working tree, so the external AI hands over the changed files as
  `{path, content}` pairs; Argus materializes them into a scratch workspace
  (`pkg/snapshot`) and runs its own agent loop (SOUL/MEMORY, real scanners)
  pointed at it as `agent.Target{Path}` with empty `Repo`/`SHA`. It is
  **collaborative**: when the agent reads a file the caller did not supply, that
  is not an error — the workspace records the miss, and at the end of the run the
  misses surface as a structured **`files_needed`** request. The AI fetches those
  paths and calls `review` again on the same MCP session, where the workspace
  **accumulates** the new files (no resend) so cross-file reasoning works even
  though Argus does not own the repo. No `request_files` tool exists — the
  ordinary file-scoped tools drive the collaboration implicitly.

_Avoid_ using bare "review" when the target matters.

### Untrusted review content

The code, diff, and scanner output of the target under review. Authored by a
potentially hostile third party — on a public repo, anyone who can open a Pull
Request — it is **data to be analyzed, never instructions to be followed**. It
never becomes a knowledge-base write (see **Service**), and it reaches the
public review output argus[bot] posts only when **grounded** in the target
itself (a posted snippet must exist in the checked-out tree; a location must
exist in the diff). Org knowledge (SOUL, MEMORY, CONTEXT) is loaded in full so
the review stays org-aware, but the confidentiality boundary is enforced on the
*output*, not by starving the *input*. _Avoid_: treating reviewed code as
trusted input, or as commands addressed to the agent.

### Consult

An org-knowledge Q&A turn over the MCP channel (ADR 0011): the external AI asks
Argus a security question that needs the **organization's** context to answer
("does this CVE affect us?", "what are our auth conventions?"), and Argus answers
from SOUL/MEMORY and the CONTEXT documents by running an agent turn with **no
code target** — there is nothing to scan, so the agent answers in prose rather
than recording findings, and no report file is written (the answer is transient).
It is **read-only**, so a viewer may consult even though they cannot request a
review. The boundary against generic security education ("what is a path
traversal?") is the **tool description**, not a runtime gatekeeper: that question
is simply not what `consult` advertises, and the developer's own AI already
covers it.

### Pull Request (PR)

The review target on the GitHub channel: a `base…head` proposed change on
a GitHub repository. A PR keys exactly one GitHub Session (by repo + PR
number) and is the unit the automatic review and all addressed comment
turns attach to. A PR review is born from webhook events only — it is not
requestable on demand (if that ever changes, it is a `repo`+`pr` target
extension of `review`, not a new capability). Argus learns its changed files and patch hunks from the
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
the channel. A CodeHost is **one platform instance plus one App
identity**: it owns the outbound credentials used to clone and call the
API, on behalf of *any* channel. Inbound authentication (the webhook
secret) is not its concern — that belongs to the Channel. GitHub
organizations are not CodeHosts: they are installations of the same App
on the same CodeHost. _Avoid_: "codesource", "provider" (that word is taken by the
LLM Provider). Note the vocabulary gap a second host will expose: GitLab's
equivalent of a PR is a **Merge Request**, and it authenticates with a
token rather than an App. See ADR 0010.

### GitHub App

The installation-based GitHub identity Argus runs as on the GitHub
channel. It receives signed webhook events, clones private repos and calls
the API with an installation token, and posts back as the `argus[bot]`
account. One App spans many organizations — one installation per org; the
installation acting at any moment is derived from the webhook event or the
target repo, never a fixed property of the deployment. Required permissions: `contents: read` (clone), `pull_requests:
write` (read changed files, post the review + inline comments), and the
mandatory `metadata: read`. Chosen over a bare webhook receiver (cannot
write back) and a personal access token (not per-install, not scoped to an
org's repos). See ADR 0008.

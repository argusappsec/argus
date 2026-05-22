# ADR 0005 — Skill shape: stateless markdown content, no whitelist, no active state

**Status:** Accepted
**Date:** 2026-05-16
**Builds on:** [ADR 0002](0002-rbac-model.md)

## Context

Skills are the surface by which non-Go contributors extend Argus. Their
shape affects who can contribute (markdown authors vs Go engineers), how
RBAC enforces safety, how the loop discovers and uses them at runtime,
and how user-explicit invocation maps to LLM behaviour.

WildGecu loads skills with YAML frontmatter declaring a curated tool
subset, an explicit lifecycle (active / inactive), and a system-prompt
override. Claude's own skill convention is much lighter: a two-key
frontmatter (`name`, `description`) plus free-form prose, no whitelist,
no lifecycle. The agent loads a skill on demand by reading its content.

We need to pick one model and live with it: changing the loading and
discovery contract later breaks every skill authored by a colleague.

## Decision

We follow the **Claude-style minimal model**, with one twist for
override semantics.

### Skill format

A skill is a directory containing a `SKILL.md` file. The file has a
two-key frontmatter and a free-form body:

```yaml
---
name: <unique identifier, kebab-case>
description: <one-sentence, LLM-readable: when to use this>
---

# <Title>

<Free-form prose: workflow, examples, things to remember.>
```

No other frontmatter fields are required or recognised. In particular:

- **No `tools:` whitelist.** RBAC at the Tool layer already constrains
  what the caller can do. A skill that orchestrates tools the caller
  cannot use simply fails on those tool calls, no escalation possible.
- **No `prompt_extension:`** distinct from the body. The body IS the
  prompt extension when injected via `read_skill`.
- **No `when_to_use:`** distinct from `description`. They are the same.

### Loading model

- **Built-in skills** live in `pkg/skill/builtin/<name>/SKILL.md` and
  are bundled into the binary via `embed.FS`.
- **User-curated skills** live in `~/.argus/skills/<name>/SKILL.md` on
  the daemon host. They override the built-in of the same name.
- Skills are loaded **lazily** at the moment the agent calls
  `read_skill(name)`. No active / inactive flag. No "skill stack".
  The skill body returned as a tool result IS the activation.

### Tools the LLM uses to discover and load skills

- `list_skills` — returns `[{name, description}, …]` for the merged
  set (user-curated overlaying built-ins).
- `read_skill(name)` — returns the body of the resolved SKILL.md.

### Trigger paths

- **LLM-decided**: the agent calls `list_skills` to discover, then
  `read_skill(name)` when it judges a skill is appropriate for the
  current task.
- **User-explicit**: `/skill <name>` (or just `/<name>`) in chat is
  intercepted client-side and rewritten as a user message:
  *"Use the <name> skill for this task."* The agent then calls
  `read_skill` itself. The slash command does NOT bypass the agent —
  it stays in the LLM's reasoning loop.

### RBAC

- `list_skills` and `read_skill` are gated behind the **analyst** role.
  Viewer Persons cannot enumerate or read skills. Skills are most
  useful during active planning / review workflows, which viewers
  don't run.
- A skill cannot grant capabilities the caller doesn't already have.
  If a skill says "use `write_soul`", an analyst trying to follow it
  hits a Tool-level RBAC rejection: `write_soul` is admin-only
  regardless of the skill suggesting it.

## Consequences

- Skill authoring is markdown-only. A colleague contributes by adding a
  directory under `~/.argus/skills/<name>/` or by PR-ing a new directory
  into `pkg/skill/builtin/`.
- No special skill VM, no skill-internal state, no per-skill prompts to
  manage. Skills are content, and the agent's normal reasoning loop is
  what "runs" them.
- Skills naturally degrade when they reference Tools not registered or
  not authorized for the caller — no warning system needed.
- The override rule (user-curated beats built-in by name) lets a team
  fork a built-in skill, tweak it for their context, and keep both
  forks running — own a name, win.
- Hot reload is deferred. Editing a skill on disk requires a daemon
  restart to take effect. This keeps the loading model trivially
  consistent across concurrent Sessions (`embed.FS` for built-ins
  is read-only and frozen at compile time anyway).

## Alternatives considered

- **No frontmatter at all** (`name` = directory basename, `description`
  = first paragraph). Rejected: renaming a directory renames the skill;
  listing requires parsing the prose. The two-line frontmatter is the
  Claude convention and pays for itself.
- **Rich frontmatter with `tools:` whitelist and `prompt_extension:`**
  (WildGecu-style). Rejected: tool gating belongs to RBAC, not to a
  YAML field the skill author controls. Letting a skill author
  whitelist tools creates a parallel permission system that can
  contradict the RBAC layer.
- **Active / inactive skill state with `finalize_skill`**. Rejected:
  unnecessary state. The body is loaded into the LLM's context and
  followed; the natural end of the workflow IS the skill ending. No
  framework support needed.
- **Hot reload of edits to disk**. Rejected for v1: consistency across
  concurrent Sessions is fiddly. Restart-to-reload is the trade-off.

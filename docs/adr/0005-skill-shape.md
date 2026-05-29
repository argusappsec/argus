# ADR 0005 — Skill shape: stateless markdown content, no whitelist, no active state

**Status:** Accepted — revised 2026-05-29
**Date:** 2026-05-16
**Builds on:** [ADR 0002](0002-rbac-model.md)

## Revision (2026-05-29)

This ADR originally described WildGecu's skill model as "heavy" — a `tools:`
whitelist, an active/inactive lifecycle, a system-prompt override. Re-reading
WildGecu's actual code, none of that is true: its skills are markdown with a
`name`/`description`/`tags` frontmatter and a body, loaded via `list_skills` /
`read_skill` — essentially the minimal model this ADR chose. The
characterisation below is corrected, and three points of the decision are
amended to match what Argus actually builds (following WildGecu's real shape):

1. **Frontmatter is three keys** — `name`, `description`, and an optional
   `tags` list (was: exactly two keys).
2. **Built-in skills are sequenced**, not in the first slice. v1 ships the
   user-curated loader only (`~/.argus/skills/<name>/SKILL.md`); the
   `embed.FS` built-in source and user-overrides-built-in resolution land
   with the built-in content (PLANNING stream F).
3. **`/<name>` injects the skill body directly** as one agent turn, rather
   than synthesising "use the <name> skill" and relying on the model to call
   `read_skill`.

RBAC (analyst+) still belongs at the Tool layer; it is a no-op today because
channel auth (stream A) is not yet built, and becomes real when it is.

## Context

Skills are the surface by which non-Go contributors extend Argus. Their
shape affects who can contribute (markdown authors vs Go engineers), how
RBAC enforces safety, how the loop discovers and uses them at runtime,
and how user-explicit invocation maps to LLM behaviour.

Two reference points exist. WildGecu loads skills as markdown with a small
`name`/`description`/`tags` frontmatter and a body, discovered via
`list_skills` and loaded via `read_skill` — no tool whitelist, no
active/inactive lifecycle, no system-prompt override. (An earlier draft of
this ADR described WildGecu as the heavy option; that was wrong — see the
Revision note above.) Claude's own skill convention is the same minimal
shape: a small frontmatter plus free-form prose, loaded on demand.

We need to pick one model and live with it: changing the loading and
discovery contract later breaks every skill authored by a colleague.

## Decision

We follow the **Claude-style minimal model**, with one twist for
override semantics.

### Skill format

A skill is a directory containing a `SKILL.md` file. The file has a small
frontmatter and a free-form body:

```yaml
---
name: <unique identifier, kebab-case>
description: <one-sentence, LLM-readable: when to use this>
tags: [optional, list, of, keywords]   # optional
---

# <Title>

<Free-form prose: workflow, examples, things to remember.>
```

`name` and `description` are required; `tags` is optional and helps the
agent pick the right skill. No other frontmatter fields are recognised. In
particular:

- **No `tools:` whitelist.** RBAC at the Tool layer already constrains
  what the caller can do. A skill that orchestrates tools the caller
  cannot use simply fails on those tool calls, no escalation possible.
- **No `prompt_extension:`** distinct from the body. The body IS the
  prompt extension.
- **No `when_to_use:`** distinct from `description`. They are the same.

### Loading model

- **User-curated skills** live in `~/.argus/skills/<name>/SKILL.md` on
  the daemon host. This is the v1 surface (`pkg/skill` loader).
- **Built-in skills** (bundled via `embed.FS` in `pkg/skill/builtin/`)
  are sequenced — they land with the built-in skill content in PLANNING
  stream F. When present, a user-curated skill overrides the built-in of
  the same name.
- Skills are loaded **lazily** at the moment the agent calls
  `read_skill(name)` (or the user types `/<name>`). No active / inactive
  flag. No "skill stack". The skill body IS the activation.

### Tools the LLM uses to discover and load skills

- `list_skills` — returns `[{name, description}, …]` for the merged
  set (user-curated overlaying built-ins).
- `read_skill(name)` — returns the body of the resolved SKILL.md.

### Trigger paths

- **LLM-decided**: the agent calls `list_skills` to discover, then
  `read_skill(name)` when it judges a skill is appropriate for the
  current task.
- **User-explicit**: `/<name>` in chat is intercepted client-side; when it
  is not a built-in client command, the named skill is loaded and its body
  is dispatched directly to the agent as one user turn (*"Use the <name>
  skill … "* followed by the body). One round-trip, deterministic — it does
  not depend on the model choosing to call `read_skill`. The body enters the
  conversation, so it stays in context for follow-up turns.

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

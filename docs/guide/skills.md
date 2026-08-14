---
title: Skills
description: Using, writing and overriding the security methodologies Argus follows.
sidebar:
  order: 50
---

A **skill** is a security methodology bundled as markdown: a directory with a
`SKILL.md` (frontmatter `name` / `description` / optional `tags`, plus a
free-form body the agent reads and follows) and optional supporting files the
body pulls on demand. Skills are content, not code — they compose the tools
Argus already has, and they cannot escalate the caller's permissions (RBAC is
enforced at the tool layer).

## Using skills

Three ways a skill gets used, equivalent in outcome:

- **You invoke it**: type `/<name>` in chat (e.g. `/authz-audit`). The body
  is injected into the conversation as one agent turn and stays in context
  for follow-ups.
- **The agent finds it**: the agent lists the catalog, judges a skill
  relevant from its description, and loads it on its own.
- **Your own AI tool invokes it**: connect a coding agent to Argus over the
  [MCP channel](/guide/channels/mcp/) and every skill appears in that client's
  own prompt menu. Picking one hands its instructions to your agent, which
  follows them using Argus's capabilities alongside its own — you never need
  to know a tool name.

Reading a skill is open to anyone Argus recognizes; *acting* on one is not. A
skill can never do more than the person following it could do themselves — the
permission check sits on each capability it reaches for, so a read-only user
following a skill that writes simply gets refused at that step.

## Managing skills

```sh
argus skill ls          # list the catalog (built-in + user-curated)
argus skill rm <name>   # remove a user-curated skill
```

User-curated skills live on the daemon host at:

```
~/.argus/skills/<name>/SKILL.md
```

A user-curated bundle with the same name as a built-in **overrides it
whole-bundle** — claim a built-in's name to replace it with your own version,
tuned to your context:

```sh
mkdir -p ~/.argus/skills/authz-audit
$EDITOR ~/.argus/skills/authz-audit/SKILL.md   # your own body, under the built-in's name
# restart the daemon to pick it up (no hot reload)
```

The frontmatter `name` must match the directory name, and the `description`
doubles as the when-to-use hint the agent sees in the catalog.

## Built-in skills

Built-ins ship inside the binary:

| Skill | What it does |
| --- | --- |
| `authz-audit` | White-box detection of broken authorization — BOLA/IDOR, BFLA, access-control logic flaws |
| `pr-quick-check` | Fast security pass over a pull request diff — scanners plus a targeted grep for risky patterns |
| `secret-rotation-plan` | Find committed secrets and draft a prioritized, step-by-step rotation plan saved to context |
| `threat-modeling` | Build a STRIDE threat model of a codebase from its structure and code |

## Spotlight: `authz-audit`

Broken authorization (BOLA/IDOR — OWASP API1:2023) is a *semantic* bug: the
defect is the **absence** of an ownership check, judged against the app's
own, usually undocumented, authorization model. Pattern-based scanners
structurally can't find it, and a naive "LLM, find IDORs" pass drowns in
false positives (Semgrep measured ~88% FPs). `authz-audit` encodes the
discipline that makes the LLM approach work:

1. **Enumerate before judging** — first reconstruct the app's ground model
   (framework, routing, principal accessor, ownership/tenancy), then judge
   handlers against it.
2. **Self-refute before reporting** — a verification gate asks "which guard
   might I have missed?"; the rule is *never flag a call-chain you did not
   read*.

Findings land in the standard report pipeline with rule IDs under `authz/*`
(e.g. `authz/bola-mutation-unscoped` → critical,
`authz/bola-missing-owner-predicate` → high) and stable, content-derived
finding IDs — a remediated finding auto-resolves. Low-precision classes
(race/TOCTOU, rate-limiting, business-flow abuse) are emitted as `info`
*hypotheses*, never as high-severity findings.

**Validation.** On [VAmPI](https://github.com/erev0s/VAmPI) — whose
`vulnerable=1/0` toggle yields a labeled dataset — three genuinely blind runs
scored **100% recall with zero canonical false positives**: both BOLA bugs
found at the exact sink with correct severity, both secure decoy branches
cleared. The skill is static and read-only — safe to run pre-merge, no
running target needed.

## Writing your own

Start from a built-in as a template. Keep the `description` sharp (it is the
routing signal), keep heavyweight reference material in supporting files the
body loads on demand, and iterate against a real repository before trusting
the results — that is how the built-ins earned their place.

:::note[Write for two readers]
A skill body reaches two kinds of agent. One is Argus, following it with the
tools Argus has. The other is your own coding agent, which picks the skill out
of its prompt menu and follows it with *its* tools plus the ones Argus offers
it — a different set, on a different machine, with no `read_file` or `grep`
coming from Argus at all.

So a skill can never assume that every tool it names is present. Write the
workflow as steps and judgement, and name a tool as the best way to carry a
step out rather than the only one. An agent missing one adapts and gets there
another way; an agent told to stop unless it has a particular tool just stops.
:::

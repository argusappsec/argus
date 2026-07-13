# Skills

A **skill** is a security methodology bundled as markdown: a directory with a
`SKILL.md` (frontmatter `name` / `description` / optional `tags`, plus a
free-form body the agent reads and follows) and optional supporting files the
body pulls on demand. Skills are content, not code — they compose the tools
Argus already has, and they cannot escalate the caller's permissions (RBAC is
enforced at the tool layer).

## Using skills

Two ways a skill gets used, equivalent in outcome:

- **You invoke it**: type `/<name>` in chat (e.g. `/authz-audit`). The body
  is injected into the conversation as one agent turn and stays in context
  for follow-ups.
- **The agent finds it**: the agent lists the catalog, judges a skill
  relevant from its description, and loads it on its own.

Skills are an **analyst+** capability: viewers can't enumerate or run them.

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
whole-bundle** — fork a built-in to tune it for your context without losing
the upstream version:

```sh
mkdir -p ~/.argus/skills/authz-audit
cp pkg/skill/builtin/authz-audit/SKILL.md ~/.argus/skills/authz-audit/
# edit, then restart the daemon (no hot reload)
```

The frontmatter `name` must match the directory name, and the `description`
doubles as the when-to-use hint the agent sees in the catalog.

## Built-in skills

Built-ins ship inside the binary (`pkg/skill/builtin/`):

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

Full design rationale, the tool landscape it was measured against, and the
validation protocol live in
[docs/design/authz-skill-design.md](../design/authz-skill-design.md).

## Writing your own

Start from a built-in as a template. Keep the `description` sharp (it is the
routing signal), keep heavyweight reference material in supporting files the
body loads on demand, and iterate against a real repository before trusting
the results — that is how the built-ins earned their place.

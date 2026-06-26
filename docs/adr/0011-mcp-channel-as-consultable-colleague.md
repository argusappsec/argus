# ADR 0011 — The MCP channel exposes Argus as a consultable colleague, not a toolbox

**Status:** Accepted
**Date:** 2026-06-26
**Builds on:** [ADR 0004](0004-single-process-channel-goroutines.md), [ADR 0006](0006-no-generic-shell-tool.md)

## Context

MCP is the next channel after TUI and GitHub. The protocol is, literally, a way
to expose *tools* and *resources* to an external AI — so the obvious, almost
default, move is to publish Argus's actual capabilities (`run_semgrep`,
`run_gitleaks`, `run_osv`, the `authz-audit` skill, the report tools) as MCP
tools and let the calling AI (Claude Desktop, Cursor, …) orchestrate them.

That default is wrong for Argus. The thing that makes Argus more than a thin
wrapper over scanners is the **organization knowledge loaded into every model
call**: SOUL (company, stack, infra, compliance, risk tolerance), MEMORY
(accepted false positives, prior decisions), and CONTEXT (auth conventions,
threat model). If the external AI drives the low-level tools itself, *that*
context never enters its system prompt — it would run our scanners with none of
the reasoning that makes the output org-specific. The result is a worse generic
scanner, not "the security engineer that knows your company".

There is also a non-goal worth recording: a generalist AI already answers
generic security questions ("what is a path traversal?") perfectly well on its
own. Exposing Argus for those wastes a round-trip and dilutes the value
proposition.

## Decision

**The MCP channel presents Argus as a consultable colleague: a small set of
coarse capabilities, not the underlying tools.** Concretely:

- **`review`** — an org-aware security review of caller-supplied code (a
  **Snapshot review**, see CONTEXT.md). The external AI hands over the changed
  files/diff from the developer's working tree (which a remote/self-hosted Argus
  cannot read itself); Argus runs its **own** agent loop — SOUL/MEMORY/CONTEXT
  in the system prompt, real scanners, skills — and returns findings.
- **`consult`** — Q&A that requires the organization's security knowledge
  ("does this CVE apply to us?", "what are our auth conventions?"). Its surface
  area, by description, is what needs Argus's unique context — **not** generic
  security education.
- **Resources** over the org knowledge (SOUL, CONTEXT documents, recent
  reports) so the external AI can pull them as context directly.

The low-level scanner/skill tools are **not** exposed over MCP. This keeps the
no-generic-shell ethos (ADR 0006) intact at the MCP boundary — the surface is a
fixed set of high-level, code-reviewed capabilities — and keeps org-awareness
inside Argus where the context lives.

**The Snapshot review is collaborative, not one-shot.** Argus may answer "to
judge this I also need `auth/middleware.go` and the dependency manifest" and the
external AI supplies them on a follow-up call. This is deliberate: Argus's
differentiator over a diff linter is cross-file reasoning (the `authz-audit`
skill resolves helpers/middleware by reading them, not by name; `osv-scanner`
needs the manifest), and a content-only one-shot call would throw exactly that
away.

The **non-goal** — generic security Q&A — is enforced *by the tool descriptions
the external AI reads to decide when to call*, not by a runtime gatekeeper.
Consistent with ADR 0006, the boundary is the shape of the exposed surface, not
a guard that inspects each request.

## Consequences

- The MCP surface is small and stable, which is good because external clients
  bind to it: changing the capability shape later is a breaking change for every
  connected AI. The coarseness is what makes that surface cheap to keep stable.
- `review` needs to operate on content with no repo checkout: materialize the
  supplied files into a scratch tree, run the scanners there, and drive the
  collaborative "I need more files" exchange. This is genuinely new machinery,
  distinct from the existing Repo/PR review paths.
- The collaborative protocol needs a response channel for "here is what else I
  need" that the external AI can act on. Its exact schema is an implementation
  detail, deferred.
- MVP ordering for the September talk: `review` first (the differentiating
  demo), `consult` as a fast-follow reusing the same loop, Resources last.

## Alternatives considered

- **Expose the low-level tools (a toolbox the external AI drives).** Rejected:
  the external AI's loop has no SOUL/MEMORY/CONTEXT, so the org-awareness that
  justifies Argus is lost; it also widens the MCP surface into per-tool RBAC and
  re-opens the spirit of the shell-escape problem (ADR 0006).
- **One-shot Snapshot review (front-load all content, no follow-up).** Rejected:
  loses cross-file reasoning when Argus doesn't own the repo, reducing Argus to
  a diff linter — precisely the capability that distinguishes it.
- **A runtime gatekeeper that declines generic questions.** Rejected: adds logic
  and a paternalistic failure mode; the tool-description boundary is the
  native-MCP, lower-friction way to keep generic Q&A out.

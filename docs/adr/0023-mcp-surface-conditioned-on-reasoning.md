# ADR 0023 — Without a Provider, Argus is a toolbox: the MCP surface is conditioned on reasoning

**Status:** Accepted
**Date:** 2026-08-14
**Amends:** [ADR 0011](0011-mcp-channel-as-consultable-colleague.md) — its
non-goal ("not a toolbox") holds only where Argus reasons
**Builds on:** [ADR 0001](0001-single-shared-daemon-per-organization.md),
[ADR 0020](0020-openai-compatible-provider.md),
[ADR 0024](0024-credentials-do-not-cross-the-network.md)

## Context

Argus cannot start without an LLM Provider, so the first thing it asks of anyone
evaluating it is a token-billed plan. [ADR 0020](0020-openai-compatible-provider.md)
widened *which* endpoint that can be, and that helped an organization with an
existing vendor or its own GPU. It did nothing for the much larger group whose
budget is already spent: developers who pay for a coding-agent subscription
(Claude Max, and the equivalents behind `codex` and `opencode`) and cannot
justify a second, per-token plan on top of it.

That subscription is not an endpoint Argus can be pointed at. It is
authenticated **on the developer's machine, in a CLI, under a named user**.
Three shapes for reaching it were considered:

- **Provider CLI** — shell the agent CLI once per turn with its own tools
  disabled, and have it emit tool calls as text. Argus keeps the loop.
- **Runner delegated** — hand the whole run to the agent CLI on the daemon host,
  passing Argus's tools to it over MCP. The CLI keeps the loop.
- **Toolbox** — the agent CLI is the **client's**, on the client's machine,
  already authenticated as that person. Argus exposes tools and knowledge over
  MCP and never generates at all.

The first two both run the agent CLI on the **daemon host**, which is the same
place the problem started: one machine, one authenticated CLI, one named user.
Delegating the loop moves who reasons; it does not move where the credential
lives. Only the third does, and it does so by not needing a credential of its
own — see [ADR 0024](0024-credentials-do-not-cross-the-network.md).

[ADR 0011](0011-mcp-channel-as-consultable-colleague.md) rejected exactly this
third shape, and its argument was right at the time: if the external AI drives
the low-level tools itself, SOUL/MEMORY/CONTEXT never enter a system prompt, and
what you get is "a worse generic scanner, not the security engineer that knows
your company".

What that argument silently assumes is that **there is an Argus system prompt to
load the knowledge into**. With no Provider configured there is none. The choice
is no longer *org-aware review* versus *generic scanning*; it is *generic
scanning through Argus* versus *nothing at all* — and the knowledge is still
reachable, pulled by the client through `read_context`, Resources and Skills
rather than pushed by Argus into its own prompt. Worse than the colleague,
decisively better than the absence.

## Decision

**Whether the MCP channel presents a colleague or a toolbox is *derived* from
whether a Provider is configured. It is not a separate setting.**

- **No Provider configured** → Argus is a **toolbox**: deterministic tools and
  knowledge over MCP. `review`, `consult` and `start_review_*` do not exist.
- **At least one Provider configured** → Argus is a **colleague**, which uses
  the toolbox as well.

### The toolbox is the floor, the colleague is a storey above it

These are not two alternative modes and Argus is not two products. Every
deterministic tool is present in both; the colleague adds reasoning on top of
the same floor. One binary, one MCP endpoint, one surface whose extent depends
on one condition that already exists in the configuration.

The commercial shape follows from the architectural one: a user enters at the
floor with what they already pay for, and a Provider is the upgrade — not a
prerequisite for the first run.

### Admission rule: expose only what the client does not already have

The toolbox surface is governed by one rule, inherited from
[ADR 0011](0011-mcp-channel-as-consultable-colleague.md) rather than invented
here.

In the toolbox:

- the scanners (`semgrep`, `gitleaks`, `osv`) — nobody else has them wired up;
- `list_context` / `read_context` / `write_context` — the organization's
  knowledge is half the value, and in the toolbox it is *pulled* by the client;
- `save_memory` and `mark_false_positive` — see **MEMORY** below;
- `list_skills` / `read_skill` / `read_skill_file`, plus Skills exposed as MCP
  prompts.

Not in the toolbox:

- `read_file` / `grep` / `list_files` — the calling agent has these already, and
  better; routing them through Argus pays for the content twice in the client's
  own context;
- `review` / `consult` / `start_review_local` / `start_review_github` — they
  start Argus's agent loop, which does not exist without a Provider.

[ADR 0011](0011-mcp-channel-as-consultable-colleague.md) excluded generic
security Q&A because the external AI answers it already. This is the same rule
applied to tools instead of knowledge. The conclusion is reversed because the
scenario changed — the caller now holds the code and lacks the scanners, where
0011's caller held neither the knowledge nor the loop — but the rule is the one
that was already there.

### Recursion is impossible by construction

An MCP surface that contained both the low-level tools and `review` would let a
reasoning client re-enter Argus through its own front door and loop. It cannot
happen here, and not because anything guards against it: in the deployment with
no Provider, the capabilities that re-enter Argus **are not on the surface at
all**. The absence of the Provider removes them.

### MEMORY has one mechanism and two callers

The toolbox is worth downloading because Argus remembers; but the memory curator
is a subagent, so a Provider-less Argus cannot write memory the way it does
today. Rather than give the toolbox a second, weaker memory, the write becomes
**deterministic in both deployments**: `save_memory` and `mark_false_positive`
are ordinary tools, called either by the external AI over MCP or by Argus's own
agent when there is one. The curator stops being *the* way memory is written and
becomes *one of two callers* of the same mechanism.

## Consequences

- Argus starts and serves without a Provider. Configuration validation,
  `argus doctor` and the first-run interview must all stop treating a missing
  Provider as an error and start treating it as a deployment shape.
- The MCP tool listing becomes conditional on daemon configuration. A client
  that connects to a Provider-less daemon must not be told about capabilities it
  cannot use; the tool list is the only place that boundary is expressed.
- **Automatic reviews do not exist in the toolbox**, by construction rather than
  by omission: nothing can reason when nobody has asked. PR review therefore
  remains a colleague capability, and any future local trigger presupposes a
  Provider.
- Skills acquire a second consumer. A Skill body may now be read by an agent
  that has the client's tools and Argus's MCP tools, rather than Argus's
  registry — so a Skill can no longer assume the tools it names are present.
- **The promise forks even though the code does not.** There are now two ways to
  answer "what is Argus?", and the risk this decision carries is editorial, not
  architectural: documentation, positioning and the first-run experience have to
  hold both without making either sound like a degraded version of the other.
- MEMORY written by an external client is unbounded where the curator's was
  self-pruning. That is what forces the size ceiling recorded in `CONTEXT.md`;
  without it, a deterministic append-only MEMORY becomes a fixed token cost on
  every call.

## Alternatives considered

- **Provider CLI (`claude -p` as a `provider.Provider`).** Rejected. It fits the
  existing abstraction, and that is its only virtue: it spends a full agent to
  impersonate a completions endpoint, loses native tool calling, re-sends the
  conversation every turn, and still leaves the credential on the daemon host.
  Its one remaining use — reasoning with no human present on a personal machine
  — depends on automatic local triggers, which this decision does not introduce.
- **Runner delegated.** Rejected. It pays the full architectural price (Argus
  stops reasoning) for a benefit it does not deliver (remote deployment), for
  the reason given in Context.
- **A third-party proxy exposing a subscription as an `openai-compatible`
  endpoint.** Not rejected — it already works, with no code, under
  [ADR 0020](0020-openai-compatible-provider.md). It is deliberately **not
  implemented, not documented and not publicised**: its standing under the
  subscription terms is not ours to assert on a user's behalf.
- **An explicit `mode:` setting.** Rejected: it would let a user configure a
  contradiction (toolbox with a Provider, colleague without), and the condition
  that actually determines the answer is already in the file.
- **Two separate products.** Rejected outright: two codebases doing nearly the
  same thing, one of which also reasons.
- **Dropping MEMORY from the toolbox.** Rejected. Memory is the reason to
  install Argus rather than wire three scanners into your own agent in an
  afternoon; removing it guts the entry point.

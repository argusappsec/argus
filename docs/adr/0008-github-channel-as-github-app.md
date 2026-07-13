# ADR 0008 — The GitHub channel runs as a GitHub App (absorbing the Webhook channel)

**Status:** Accepted — the Service model section is superseded by
[ADR 0015](0015-integrations-declared-in-configuration.md) (Services are
config-declared; the listener moves to the shared front door at
`/webhooks/github`); the mention form is broadened by the
[2026-07-13 amendment](#amendment-2026-07-13--the-bare-name-vocative-is-the-canonical-mention)
below (bare-name vocative preferred over `@argus`)
**Date:** 2026-06-21
**Builds on:** [ADR 0002](0002-rbac-model.md), [ADR 0003](0003-user-table-and-bootstrap.md), [ADR 0004](0004-single-process-channel-goroutines.md), [ADR 0007](0007-socket-possession-is-authentication.md)

## Context

CONTEXT.md originally listed a narrow **Webhook** channel: an HTTP endpoint
receiving signed GitHub events, resolving to a Service Principal, running a
one-shot review with the PR author recorded only as metadata.

We want more than that. The valuable product is a *communicative* agent on
the PR: it reviews automatically when a PR opens, but it also answers
`@argus` comments — explaining findings, accepting false positives,
re-scoping the analysis. A receiver that only ingests events cannot do this:
replying on the PR, posting an inline review, and re-reading changed files
all require **writing to the GitHub API**, which a bare webhook secret does
not grant.

## Decision

**The GitHub channel is a GitHub App installation**, and it absorbs the old
"Webhook" entry — one channel, one transport, two event paths:

- `pull_request` opened/synchronize → an automatic **PR review** (see
  [ADR 0009](0009-pr-review-scans-whole-tree.md)). Triggering principal is
  the **Service** (the installation — see Service model below); the PR
  author is metadata.
- `issue_comment` / `pull_request_review_comment` containing `@argus` → a
  conversational turn. The actor is the **Person** resolved from
  `github:<login>`.

Concretely:

- The App authenticates API calls and clones (including private repos) with
  a short-lived **installation token**. This replaces the anonymous-HTTPS
  clone path for GitHub targets.
- Required permissions: `contents: read`, `pull_requests: write`,
  `metadata: read`. It posts back as `argus[bot]`.
- "Mention" does not rely on GitHub's native mention resolution: the App
  receives every comment event on installed repos and **parses the body**
  for the `@argus` token itself.
- **Channel-specific trust policy.** A comment whose `github:<login>` does
  not resolve to a Person, or that omits `@argus`, is **silently ignored** —
  not rejected with a message. As in ADR 0007, the trust policy lives in the
  channel, not in `auth.Resolver`, which stays strict and policy-free.

### Service model (evolves ADR 0003)

ADR 0003 modelled a `ci-trigger` Service **bound to one repo** with a
**per-repo** webhook secret. A GitHub App has **one** webhook secret for
the whole installation and can cover many repos, so that shape no longer
fits. Instead:

- The App installation is represented as **one Service** (one webhook
  secret hash = the App's secret). The auto-review runs as that Service;
  the audit log records "GitHub App installation" as the trigger actor.
- The set of enabled repos is **the installation's repositories, read from
  the GitHub API** — Argus does not maintain a second hand-edited
  allow-list. The App's "selected repositories" setting already *is* an
  explicit, admin-controlled allow-list; duplicating it in `users.yaml`
  would be toil and a drift hazard.
- A single daemon-side policy `github.auto_enroll` (in `argus.yaml`)
  governs whether an installed repo is reviewed automatically. This exists
  because Argus roots trust in *daemon-host ownership* (ADR 0007), not in
  GitHub-org ownership: when the App administrator and the Argus operator
  are **not** the same entity, install-implies-enabled would let a
  GitHub-org admin spend Argus's LLM budget and expose its SOUL on repos
  the Argus operator never chose. `auto_enroll: true` (the default for the
  common single-owner deployment) makes installation sufficient;
  `auto_enroll: false` requires an Argus admin to enable a repo before the
  first review runs.

## Consequences

- The PR session is keyed by `(github, repo + PR number)` with stable
  identity but one-shot execution (CONTEXT § Session): the auto-review and
  later comments rehydrate the same conversation log without holding a
  `max_concurrent_sessions` slot between events.
- Operators must create and install a GitHub App and store its private key
  and webhook secret on the daemon host — heavier setup than a PAT, but it
  is per-install, org-scoped, and posts under its own bot identity.
- `argus doctor` gains a check that the App credentials are present and the
  installation token can be minted.

## Alternatives considered

- **Bare webhook receiver + no write-back** (the original CONTEXT entry).
  Rejected: it cannot post reviews or answer comments, which is the whole
  point of the feature.
- **Personal access token (PAT).** Rejected: tied to a human account, not
  per-installation, awkward to scope to an org's repos, and would post under
  that human's name instead of `argus[bot]`.
- **OAuth App / GitHub Action.** Rejected: an Action runs in the customer's
  CI and cannot host the long-lived daemon, multi-channel shared state, or
  audit log that ADR 0001/0004 require; OAuth is for acting *as a user*, not
  as an autonomous installation.

## Amendment (2026-07-13) — the bare-name vocative is the canonical mention

`@argus` on github.com belongs to an unrelated real user: on a public repo,
every `@argus` comment pings a stranger. Since this channel already parses
the body itself (GitHub's native mention resolution was never involved), the
`@` sign buys nothing. A comment now addresses the instance in either of two
forms:

- **Vocative (canonical, documented):** the bare instance name — brand or
  persona — as the **opening word(s)** of the comment: "Argus, explain this",
  "Ercole guarda qui". Opening position is what separates talking *to* Argus
  from talking *about* it ("I think argus is wrong here" stays ignored). A
  comment that opens with the name but addresses other humans ("Argus is
  wrong about this") does trigger a reply; that residual false positive is
  accepted — the reply is harmless, actions still require a resolved Person.
- **@-handle (alias):** `@argus` / `@<persona>` anywhere in the body, kept
  because people type it out of habit and a bot that ignores its own tag is
  worse UX than the spurious ping (which happens regardless of what Argus
  accepts).

A consequence for the persona name (`persona.name`): it no longer must be a
single word. A multi-word name ("Ercole il Guardiano") forms no @handle but
works in full as a vocative. Deliberately rejected: matching only the first
word of a multi-word name (a persona like "The Guardian" would trigger on
"The"), and `/argus` slash commands (robust but off-register for a
conversational agent with a persona).

# ADR 0010 — A minimal CodeHost interface now, with GitHub as the only implementation

**Status:** Accepted
**Date:** 2026-06-21
**Builds on:** [ADR 0008](0008-github-channel-as-github-app.md)

## Context

GitHub is the first code platform Argus integrates, but it should not be the
last (GitLab, Bitbucket, …). The repo already hints at this: the cloner
lives under `pkg/codehost/github`, not `pkg/github`. The question is *how
much* abstraction to commit to while only GitHub exists.

A single-implementation interface usually picks the wrong seams: GitLab's
analogue of a PR is a **Merge Request**, it authenticates with an access
token rather than an App installation, and its webhook signatures and
comment APIs differ. Designing the perfect multi-host abstraction now, with
no second implementation to check it against, tends to need rewriting the
moment host #2 lands.

## Decision

**Define a minimal `CodeHost` interface scoped to what the channel and agent
actually use, implemented only by GitHub.** The seams are the concrete
operations already in hand — parse a repo/PR URL, clone with auth, fetch a
PR's changed files and patch hunks, post a review with inline comments,
resolve a commenter's Identity — not a speculative model of "any forge".

The channel stays the concrete **GitHub channel** for now (ADR 0008); we do
*not* build a generic "CodeHost channel" yet, because webhook transport and
signature handling are host-specific and there is no second host to factor
against. The interface marks the intent and contains GitHub's API surface
behind one package; refining it is explicitly deferred to when the second
host arrives.

## Consequences

- Host-specific code is funnelled through `pkg/codehost`, so the agent and
  channel depend on the interface, not on GitHub types directly.
- The second host is still a real piece of work: it will both add an
  implementation *and* reshape the interface where GitHub-isms leaked in.
  That reshaping is expected, not a failure of this ADR.
- Vocabulary will need a neutral term for "PR / Merge Request" when host #2
  lands; until then the glossary keeps "PR" and notes the gap.

## Alternatives considered

- **Stay fully concrete on GitHub, extract later.** Rejected (narrowly):
  two real implementations give the best seams, but with `pkg/codehost`
  already in place the marginal cost of a thin interface now is low and it
  keeps GitHub types from leaking across the codebase in the meantime.
- **Full multi-host abstraction now.** Rejected: high risk of guessing the
  abstraction wrong with zero feedback from a second host, plus immediate
  maintenance surface for code paths nothing exercises yet.

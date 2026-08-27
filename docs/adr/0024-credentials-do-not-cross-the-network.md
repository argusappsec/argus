# ADR 0024 — Credentials do not cross the network: whoever holds one does the work

**Status:** Accepted
**Date:** 2026-08-14
**Builds on:** [ADR 0001](0001-single-shared-daemon-per-organization.md),
[ADR 0010](0010-codehost-interface-one-implementation.md),
[ADR 0020](0020-openai-compatible-provider.md)

## Context

Argus's deployment model assumes the daemon holds every credential it needs:
an LLM API key, a GitHub App private key. That works because those credentials
are *organizational* — issued to the deployment, not to a person, and equally
valid for anyone the daemon serves.

Two independent pieces of work broke that assumption in the same way.

Reaching a developer's **coding-agent subscription** (see
[ADR 0023](0023-mcp-surface-conditioned-on-reasoning.md)) is not a matter of
copying a key into the daemon's `.env`. The subscription is authenticated in a
CLI on that person's machine under a **named user**. A shared daemon holding one
such login would have every employee's work attributed to one person's account.

Reaching **private repositories from a personal Argus** looked like a different
problem and turns out to be the same one. Making every individual create and
install a GitHub App to review their own code is a barrier out of proportion to
the task — and meanwhile the machine already has `git` authenticated against
the host, because that is how the person works every day.

In both cases the reflex is to move the credential to the daemon. In both cases
that reflex is what breaks: it collapses distinct people into one identity, and
it demands a credential the user already possesses somewhere else.

## Decision

**A credential stays on the machine that holds it. Argus arranges for the work
to happen where the credential already is, rather than moving the credential to
where the work was going to happen.**

Two consequences fall out immediately, and a third governs the future.

### Reasoning happens where the subscription is

An agent CLI authenticated as a person runs on that person's machine, so the
loop runs there too and Argus is the toolbox it calls. This is the whole reason
the toolbox shape is remotely deployable and shareable while the two rejected
shapes in [ADR 0023](0023-mcp-surface-conditioned-on-reasoning.md) were not:
they moved the loop but left the credential on the daemon host, which is the
part that mattered.

### Reading code happens where the git identity is

A personal Argus reads private repositories through the **local `git` CLI,
already authenticated by whoever runs the daemon** — not through an App the user
must first create. Argus never handles the token; `git` does, exactly as it does
for every other command that person runs.

Three properties follow, and they are the point rather than the price:

- **Read-only.** Argus clones, checks out and diffs. It never writes.
- **Host-agnostic.** Speaking the protocol rather than an API means GitLab,
  Gitea, Bitbucket and a bare repository on a NAS work on the day this ships,
  without an integration each. A first-class GitLab CodeHost remains necessary
  later, but only for what the protocol cannot express — receiving events and
  posting automatic reviews.
- **Blind to the platform.** No Pull Requests, no changed-files API, no review
  comments. A CodeHost built on `git` implements the read half of the interface
  in [ADR 0010](0010-codehost-interface-one-implementation.md) and cannot
  implement the rest.

Writing back with a personal identity — `gh pr comment` and the like — is
explicitly **not** adopted. It would publish agent-authored content under a
human's name and avatar, indistinguishable from what that human wrote. Harmless
on a personal repository, and not harmless on the customer repository the same
build reaches. Argus posts as `argus[bot]`
([ADR 0008](0008-github-channel-as-github-app.md)) or it does not post.

### Where the work cannot move, the code moves instead

When Argus runs on a server and the code is on a laptop, no credential can fix
the distance. Two answers exist and both are already built: the **Snapshot
review**, where the client sends `{path, content}` over MCP, and
`start_review_local` for a tree the daemon can already see. They trade the same
way: Snapshot costs nothing to set up and spends the *client's* context on file
contents; a server-side clone costs a configured git identity and spends none.

The v1 toolbox therefore requires **client and daemon on the same machine**, and
the `git`-based CodeHost is a second step for the server deployment — not a
prerequisite for the first.

## Consequences

- The `CodeHost` interface acquires its first partial implementation. The
  interface was inferred from GitHub; a `git`-only host implements the read
  operations and must fail explicitly, not silently, on the rest.
- Argus gains a dependency on `git` on the daemon host, verifiable through
  `tool.Requirer` and `argus doctor` like `semgrep` and `gitleaks` already are.
  It shells out to a binary, which is what Argus does with scanners — it does
  not put a shell in front of the model, so
  [ADR 0006](0006-no-generic-shell-tool.md) is untouched.
- The credential Argus reads code with is now, in this deployment, a **person's**
  rather than an installation's. Whoever runs the daemon grants it their own
  reach: possession of the host already implied that
  ([ADR 0007](0007-socket-possession-is-authentication.md)), but it is now
  load-bearing rather than incidental, and the guide has to say so.
- Support for hosts nobody integrated becomes real but shallow: users on GitLab
  can review code today and cannot get automatic reviews. That gap has to be
  stated where the capability is announced, or it reads as a bug.
- The principle is a standing constraint on future design. Any proposal that
  works by collecting a user's personal credential into the daemon — a CLI
  session, an OAuth token, a subscription cookie — is answered by this record
  before it is designed.

## Alternatives considered

- **Holding one agent-CLI login on the daemon.** Rejected: it attributes the
  work of everyone the daemon serves to a single named account.
- **A GitHub App per individual.** Rejected as the entry path: creating and
  installing an App to review your own repository is out of proportion to the
  task, and it is exactly the friction the personal deployment exists to remove.
- **`gh` instead of `git`.** Rejected as the basis. `gh` knows what a Pull
  Request is, which is genuinely more capable — and it is GitHub-only, which
  forfeits the property that made this worth doing. It remains available later
  as an addition to a `git` baseline, never as its replacement.
- **Read-write with the user's identity.** Rejected for the attribution reason
  above. If it is ever adopted it needs a mandatory marker on every posted
  comment, and it should be decided on that basis rather than inherited from the
  convenience of a CLI that happens to be logged in.
- **Requiring a server-side clone for the toolbox from the start.** Rejected:
  Snapshot review and `start_review_local` already cover the same-machine case,
  which is the entry case, and neither needs a credential configured.

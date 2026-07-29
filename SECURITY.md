# Security Policy

Argus is an application security agent. It reads code it has no reason to
trust, holds your organization's knowledge in a model context, and writes what
it concludes into places other people read. We take reports about that
machinery seriously.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Use either channel:

- **Email**: [security@argusappsec.com](mailto:security@argusappsec.com)
- **GitHub**: [private vulnerability reporting](https://github.com/argusappsec/argus/security/advisories/new)
  on this repository

A useful report includes:

- the affected release or commit, and how Argus was deployed (binary built
  from source, container image tag, Kubernetes);
- which channel is involved (TUI, MCP, GitHub) and which principal role is
  required to trigger it;
- a reproduction. For prompt-injection or exfiltration issues, the smallest
  repository content or PR diff that demonstrates it;
- the impact you believe it has, and any suggested fix.

You'll get an acknowledgement within **3 business days** and an initial
assessment (in scope / out of scope, severity, intended fix window) within
**10 business days**. If a report stays quiet past that, resend it; assume mail
was lost rather than ignored.

## Supported versions

Argus is **pre-1.0**. Security fixes land on the latest release only; there are
no backports to earlier minors. Run a recent version.

| Version | Supported |
| --- | --- |
| latest `0.x` release | ✅ |
| older `0.x` releases | ❌ (upgrade) |

## Scope

Argus's trust boundaries are documented, not implied. The relevant ones are
[CONTEXT.md § *Untrusted review content*](CONTEXT.md), the RBAC model
([ADR 0002](docs/adr/0002-rbac-model.md)), the absence of a generic shell tool
([ADR 0006](docs/adr/0006-no-generic-shell-tool.md)), output-side
confidentiality ([ADR 0017](docs/adr/0017-full-context-in-controlled-egress-out.md)),
least-privilege automatic reviews
([ADR 0018](docs/adr/0018-automatic-reviews-are-least-privilege.md)), and
filesystem isolation while reviewing untrusted code
([ADR 0019](docs/adr/0019-untrusted-code-review-filesystem-isolation.md)).

**A vulnerability is anything that crosses one of those boundaries.** For
example:

- **Exfiltration.** Content of SOUL, MEMORY, or CONTEXT reaching readers who
  aren't entitled to it. Severity scales with the audience: on a public repo
  that's the whole internet and anyone can open the PR that triggers the
  review, while on a private repo it's your contributors. The boundary holds in
  both cases, because whoever can open a PR isn't automatically cleared for
  everything in your org knowledge. Bypassing grounding counts too: getting
  Argus to post a snippet or a location that doesn't exist in the target.
- **Knowledge-base poisoning.** Untrusted reviewed code causing a write to
  `CONTEXT`/`MEMORY`, which then rides along in every later session.
- **Filesystem escape.** Reading or writing outside the checkout under review:
  symlink escapes, path traversal, following a link to `users.yaml`, the GitHub
  App private key, the webhook secret, or `~/.ssh`.
- **Privilege escalation.** Acting with a role the principal doesn't hold,
  spoofing a principal, forging or replaying a webhook, or bypassing MCP token
  or Unix-socket authentication.
- **Sandbox escape.** Reaching arbitrary command execution on the host through
  the structured tools or scanner wrappers.
- **Secret disclosure.** API keys, tokens, or App private keys leaking into
  logs, the audit log, model calls that shouldn't carry them, or error output.
- **Audit integrity.** Performing an attributable action without the
  append-only audit log recording it.

### Out of scope

These are real concerns but not security reports. Please open a normal
[issue](https://github.com/argusappsec/argus/issues) instead:

- **Review quality.** False positives, missed vulnerabilities, wrong severity,
  or unhelpful advice. Argus being a mediocre analyst on some codebase is a bug
  in methodology, not a vulnerability in Argus.
- **Model behaviour that stays inside the boundary.** Hallucinations,
  refusals, or a prompt injection that only makes Argus write something silly
  in a review it was already entitled to write.
- **Vulnerabilities in the scanners themselves** (`semgrep`, `gitleaks`,
  `osv-scanner`) or in Go dependencies: report those upstream. Do tell us if
  Argus pins a version with a known, exploitable CVE.
- **Anything requiring an existing Admin principal or host-level access.**
  Admins are trusted by design; so is whoever can read the daemon's data
  directory or possess its Unix socket
  ([ADR 0007](docs/adr/0007-socket-possession-is-authentication.md)).
- **Deployment misconfiguration**: exposing the MCP port without a token,
  running the container as root, world-readable config. Say so anyway if our
  documentation or defaults led you there; a bad default *is* in scope.
- **Cost or resource exhaustion** driven by legitimate use (a huge repository
  burning model tokens), absent an amplification a stranger can trigger.

## Disclosure

We work to coordinated disclosure. We'll agree a timeline with you, aiming to
ship a fix and publish a GitHub Security Advisory within **90 days** of the
report, and sooner for anything actively exploitable. Please hold public
details until the advisory is out.

Reporters are credited in the advisory and the release notes unless you'd
rather stay anonymous. There is no bug bounty: Argus is an open-source project
and we can offer thanks and credit, not money.

## Safe harbour

We won't pursue or support legal action against research that follows this
policy in good faith: testing only against your own installation and
repositories, no access to or modification of other people's data, no
degradation of anyone else's service, and no disclosure of what you find
before the coordinated date. If you're unsure whether something is in bounds,
ask at [security@argusappsec.com](mailto:security@argusappsec.com) first.

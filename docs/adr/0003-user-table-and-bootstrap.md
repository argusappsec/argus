# ADR 0003 — User table in YAML, CLI bootstrap, opaque rejection of strangers

**Status:** Accepted
**Date:** 2026-05-16
**Builds on:** [ADR 0001](0001-single-shared-daemon-per-organization.md),
[ADR 0002](0002-rbac-model.md)

## Context

Argus needs to store Persons and Services
([ADR 0002](0002-rbac-model.md)) somewhere, and create the first admin
without any chicken-and-egg authentication problem. Decisions about
storage and bootstrap are sticky (migrating from one to another later is
real work), so we capture them here.

## Decision

### Storage

The user table lives in `~/.argus/users.yaml` on the daemon host. Human-
editable, file-based, coherent with the rest of the project's "no DB"
filosofia.

```yaml
persons:
  - id: davide
    email: davide.imola@redcarbon.ai
    role: admin
    identities:
      - slack:U123ABC
      - github:davideimola
    mcp_tokens:
      - name: davide-laptop
        sha256: <hex>
        created_at: 2026-05-16T10:00:00Z
services:
  - id: ci-rc-guest-portal
    role: ci-trigger
    repo: github.com/redcarbon-dev/rc-guest-portal
    secret_sha256: <hex>
    created_at: 2026-05-16T10:00:00Z
```

The file is NOT committed to git (the `.argus/` directory is already
gitignored, and we do not carve out an exception). It stays on the
daemon host. Backup is the responsibility of whoever operates the
host (snapshot the volume, sync to a private bucket, etc.).

### Bootstrap

The first admin is created on the box, via CLI, by whoever has shell
access (= whoever provisioned the daemon):

```
argus user add davide --role admin \
    --email davide.imola@redcarbon.ai \
    --slack U123ABC --github davideimola
```

Subsequent Principals are added the same way, either by SSH-ing to the
host or — in future versions — by an existing admin via a privileged
operation (CLI today; conversational only when we're confident it can't
escalate).

### CLI surface

```
argus user add <id> --role admin|analyst|viewer [identity flags]
argus user list
argus user remove <id>
argus user grant <id> --identity slack:U999
argus user mcp-token <id> create --name "<friendly>"   # prints token, stores hash
argus user mcp-token <id> revoke --name "<friendly>"

argus service add <id> --role ci-trigger --repo github.com/X/Y
argus service list
argus service remove <id>
```

All commands are local cobra subcommands operating directly on
`~/.argus/users.yaml`. They do NOT go through the running daemon
process — so no HTTP user-management API exists. The attack surface
for "add a backdoor admin" reduces to "have shell access".

### Reaction to unrecognised principals

Any inbound request whose identity does not resolve to a Person or
Service receives a polite rejection in the requester's own language
(Slack reply, MCP error, webhook 403). The rejection states that the
caller lacks permission and to contact the Argus administrator. It
does NOT mention CLI commands, configuration paths, or any other
operational detail — these would leak implementation knowledge to a
random workspace member.

## Consequences

- Operational simplicity: one file, plain text, editable in an emergency.
- Backup is the volume snapshot; no extra job needed.
- Concurrent edits are not a concern (the daemon is a single process,
  and `argus user …` CLI commands run when the daemon is not modifying
  the same file).
- The file holds *hashes* of MCP tokens and HMAC secrets, never the
  cleartext. Cleartext is shown once at creation and lost.
- Cannot self-onboard via Slack. Anyone unknown is bounced. Adding a
  new colleague requires admin action.
- No HTTP user-management API — significant attack-surface reduction.

## Alternatives considered

- **SQLite** for relational queries / future scale. Rejected as premature
  for <100 users; trivially migratable later if it becomes necessary.
- **External IdP (Okta, Google SSO, SCIM)** federation. Rejected as
  disproportionate for a 2-person team and as breaking offline operation.
- **Versioned users.yaml in git** for audit-by-history. Rejected: the
  file holds secret hashes; committing them is needless oracle-attack
  surface. The `.argus/` directory is gitignored — we do not carve an
  exception.
- **Self-claim bootstrap** (first Slack user → admin). Rejected as
  unsafe in any non-trivial workspace.
- **Magic-token bootstrap** (first start prints a one-shot token).
  Rejected: token in plaintext in logs, racey, weaker than "have shell".
- **Stranger reply mentions the CLI command**. Rejected: leaks
  implementation details to unknown identities. The reply is opaque
  beyond "contact the administrator".

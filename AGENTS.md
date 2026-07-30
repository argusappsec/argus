# AGENTS.md

Agent instructions for the Argus repo. Skills loaded via Claude Code / agentic tools
should follow the conventions documented here.

## Agent skills

### Issue tracker

Issues live on GitHub (`argusappsec/argus`) and are managed via the `gh` CLI.
See `docs/agents/issue-tracker.md`.

### Triage labels

Canonical defaults (`needs-triage`, `needs-info`, `ready-for-agent`,
`ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout: one `CONTEXT.md` + `docs/adr/` at the repo root.
See `docs/agents/domain.md`. Research notes — findings gathered from primary
sources, with citations — go under `docs/research/`.

### Public docs

`docs/guide/` is **self-contained source for an external Starlight site**, not
documentation to be read on GitHub. No relative link may leave that folder, and
nothing inside it may reference ADRs, `CONTEXT.md`, design documents or source
paths — explain the *why* in the reader's own language, or leave it out. Every
page carries `title`, `description` and `sidebar.order`; internal links are
absolute site paths under `/guide/…`; callouts are Starlight asides. See
[ADR 0022](docs/adr/0022-user-guide-is-self-contained-starlight-source.md).

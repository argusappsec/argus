# AGENTS.md

Agent instructions for the Argus repo. Skills loaded via Claude Code / agentic tools
should follow the conventions documented here.

## Agent skills

### Issue tracker

Issues live on GitHub (`redcarbon-dev/argus`) and are managed via the `gh` CLI.
See `docs/agents/issue-tracker.md`.

### Triage labels

Canonical defaults (`needs-triage`, `needs-info`, `ready-for-agent`,
`ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout: one `CONTEXT.md` + `docs/adr/` at the repo root.
See `docs/agents/domain.md`.

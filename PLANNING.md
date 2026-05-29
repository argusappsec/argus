# Argus — Work Streams

This file is the team-facing planning view. Each stream is a coarse unit of
work that can be picked up and progressed mostly independently. The
**SCOPE** lines are intentionally loose — they describe the outcome, not
every implementation step. Whoever owns a stream is trusted to make the
detail-level decisions, consulting ADRs in `docs/adr/` for the cross-cutting
ones (deployment shape, RBAC, channel contract, skill shape, etc.).

## Streams

### A — Channel infrastructure (the contract)

**Scope.** Turn the current single-process CLI into a long-running daemon
(`argusd`). Define and implement the `Channel` interface. Build the
`SessionManager`, the `auth.Resolver` over `users.yaml`, and the wiring
that all other channels will plug into.

**Outcome.** A daemon process exists, exposes a Unix socket for local CLI,
auth resolves Identities to Persons/Services correctly. No new transport
yet — just the foundation.

**Touches.** `cmd/daemon.go` (new), `pkg/channel/` (interface + local UDS
impl), `pkg/auth/`, `pkg/session/` (extend with SessionManager), `pkg/users/`
(parser for users.yaml + the CLI subcommands).

**Depends on.** Nothing new. Builds on the existing agent loop.

**Unblocks.** B, C, D.

---

### B — Slack channel

**Scope.** Socket-Mode bot that listens to DMs + mentions, resolves the
Slack `user_id` to an Argus Person, dispatches to `agent.Run`, streams
responses back. Implement the slash command surface for `/skill` and
friends. Reject unrecognised identities politely (per ADR 0003).

**Outcome.** A team member can DM the bot or `@argus` in a channel and
get a full agent interaction, attributed to their Person.

**Touches.** `pkg/channel/slack/`, `cmd/daemon.go` (registration).

**Depends on.** Stream A.

**Unblocks.** Real team use beyond shell-attached operators.

---

### C — MCP channel

**Scope.** HTTP server inside the daemon implementing the MCP protocol
surface (Resources for reports, Tools for trigger / diff / query). Bearer-
token auth resolving to a Person or Service.

**Outcome.** Claude Code (or any MCP client) can ask Argus for a security
review and gets it with full org context that the client doesn't itself
have.

**Touches.** `pkg/channel/mcp/`, `cmd/daemon.go`.

**Depends on.** Stream A.

**Unblocks.** Dev-IDE integrations.

---

### D — Webhook channel + GitHub App

**Scope.** GitHub App registration. HTTP endpoint receiving signed events,
verified against a per-repo Service Principal. PR comments posted back via
the App's installation token. Persistent queue when load exceeds
`max_concurrent_sessions`.

**Outcome.** A PR on a monitored repo automatically gets a security review
comment, attributed to the `ci-trigger:<repo>` Service Principal.

**Touches.** `pkg/channel/webhook/`, `pkg/codehost/github/app.go`,
`cmd/daemon.go`.

**Depends on.** Stream A. One-time admin setup (App registration in the
GitHub org) — not a coding dependency but a coordination one.

**Unblocks.** Stream I.

---

### E — Skill foundation  ✅ user-curated slice landed (2026-05-29)

**Scope (done).** `pkg/skill` loader (parse/load/save/delete of
`~/.argus/skills/<name>/SKILL.md`; frontmatter `name`/`description`/`tags`,
path-traversal-guarded). Tools `list_skills` + `read_skill(name)` in
`pkg/tool/skills.go`. The `/<name>` chat trigger (loads the skill and injects
its body as one agent turn). `argus skill ls|rm`.

**Sequenced into stream F.** The `embed.FS` built-in source under
`pkg/skill/builtin/` and user-overrides-built-in resolution — they land with
the built-in skill content, since shipping empty plumbing has no value. The
RBAC gate (analyst+) is deferred until stream A wires channel auth; it is a
Tool-layer no-op until then.

**Outcome.** A user writes `~/.argus/skills/<name>/SKILL.md` and runs it with
`/<name>`; the agent can also discover and load skills on its own.

**Touches.** `pkg/skill/`, `pkg/tool/skills.go`, `pkg/channel/tui/`,
`cmd/skill.go`, `cmd/runtime.go`.

**Depends on.** Nothing new — the Tool registry already exists.

**Unblocks.** Stream F.

---

### F — Built-in skills (content + `embed.FS` plumbing)

**Scope.** Add the `embed.FS` built-in source and override resolution
(user-curated beats built-in by name) to `pkg/skill`, then write the first 5
markdown skills under `pkg/skill/builtin/`: `pr-quick-check`,
`threat-modeling`, `dep-audit-deep`, `release-readiness`,
`secret-rotation-plan`. Iterate by trying each one against a real repo.

**Outcome.** Out-of-the-box, Argus knows how to do the common security
workflows without anyone having to teach it each time.

**Touches.** `pkg/skill/` (embed.FS + override),
`pkg/skill/builtin/<name>/SKILL.md`.

**Depends on.** Stream E (the loader + tools landed).

**Unblocks.** Demonstrates the skill model to future contributors.

---

### G — Security tool expansion

**Scope.** Wrap `trivy`, `trufflehog`, `govulncheck`, `osv-scanner` as
session-aware Go Tools following the existing `pkg/security/semgrep.go`
pattern. One file per binary, one tool per file, `Requires()` method so
`argus doctor` picks them up automatically.

**Outcome.** The agent has multi-language CVE coverage (Go, Python, JS,
Rust, …), better secret detection, SBOM-driven workflows.

**Touches.** `pkg/security/<binary>.go`, `pkg/security/<binary>_test.go`,
`cmd/runtime.go` (registration).

**Depends on.** Nothing — orthogonal to everything else.

**Unblocks.** Skills that reference these tools (Stream F).

---

### H — HTML renderer + `argus serve`

**Scope.** A `pkg/render/` package that reads markdown reports and emits
HTML (Chart.js for trend, severity badges, drill-down on findings).
`argus serve` exposes the HTML over HTTP locally; the daemon serves the
same routes when running. Bearer-token auth on the daemon variant.

**Outcome.** A CISO with no shell access can read reports by visiting a
URL. Slack messages embed deep links to the right report.

**Touches.** `pkg/render/`, `cmd/serve.go` (standalone), HTTP handlers in
`cmd/daemon.go` (daemon variant).

**Depends on.** Nothing — report files already exist on disk.

**Unblocks.** Team-wide visibility of reports without shell access.

---

### I — Org-level multi-repo review

**Scope.** Enumerate all repos in a GitHub org via the App. Drive a batch
of reviews, aggregate findings into an org-level report. Cross-repo
reasoning: identify shared dependencies, attack-path chains between
microservices, etc.

**Outcome.** "Argus, give me a security state-of-the-org" produces a
real document, not a hand-collated PDF.

**Touches.** `pkg/codehost/github/org.go`, new agent flow for org-level
review, `pkg/render/` cross-repo views.

**Depends on.** Stream D (GitHub App) and Stream H (rendering).

**Unblocks.** The CISO use case.

---

## Dependency graph

```
                       (existing v0.2.x baseline)
                                  │
                                  ▼
                ┌───────────────────────────────┐
                │  A — Channel infrastructure   │
                └─────────────┬─────────────────┘
                              │
              ┌───────────────┼─────────────────┐
              ▼               ▼                 ▼
         ┌─────────┐    ┌─────────┐       ┌─────────┐
         │ B Slack │    │ C MCP   │       │ D Webhook│
         └─────────┘    └─────────┘       └────┬────┘
                                               │
                                               ▼
                                          ┌─────────┐
                                          │ I Org   │
                                          └────┬────┘
                                               │
   ┌──────────────────────┐                    │
   │ E Skill foundation   │                    │
   └────────┬─────────────┘                    │
            │                                  │
            ▼                                  │
   ┌──────────────────────┐                    │
   │ F Built-in skills    │                    │
   └──────────────────────┘                    │
                                               │
   ┌──────────────────────┐                    │
   │ G Security tools     │ (orthogonal)       │
   └──────────────────────┘                    │
                                               │
   ┌──────────────────────┐                    │
   │ H HTML renderer      │────────────────────┘
   └──────────────────────┘
```

## Recommended allocation (today: 2 people)

- **Davide (Go + agent depth)** — Stream A first (everything depends on
  it). Then E. Then D when the team need surfaces.
- **Colleague (security domain, learning Go)** — Stream G in parallel
  from day one (orthogonal, existing pattern to copy). Then F (markdown,
  zero Go) once E lands.

When the next 1–2 people join, natural next streams:

- Stream B (Slack) — Go + Slack API; no security-domain expertise needed.
- Stream C (MCP) — HTTP / REST experience; no security-domain expertise.
- Stream H (HTML renderer) — frontend-leaning Go engineer.

Each of B / C / H can be started independently the moment Stream A is in
`main` (they all plug into the same Channel contract, and don't conflict
with each other).

## Anti-goals

To keep the planning honest, things we are explicitly NOT doing in this
horizon:

- Multi-tenant SaaS (one daemon serves one organization; see ADR 0001).
- Live SOUL/CONTEXT editing via API (CLI only; ADR 0003).
- Generic shell tool (ADR 0006).
- External SSO / Okta federation (ADR 0003).
- Hot-reload of skills (restart-to-reload; ADR 0005).

Each anti-goal corresponds to an explicit "rejected alternative" in an
ADR. If a use case forces a revisit, write a new ADR — don't drift.

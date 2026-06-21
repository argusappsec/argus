# authz-audit — white-box authorization review skill

> Companion documentation for the `authz-audit` skill. This file documents
> *around* the skill: what it is, why it exists, how to install/run/validate it,
> and how its findings land in Argus. The skill's actual instructions live in
> the `SKILL.md` body — this README does not duplicate them.
>
> Source design: [`docs/authz-skill-design.md`](../../authz-skill-design.md)
> (Italian nuance copy: [`docs/authz-skill-design.it.md`](../../authz-skill-design.it.md)).
> Shape governed by [ADR 0005](../../adr/0005-skill-shape.md) and
> [ADR 0006](../../adr/0006-no-generic-shell-tool.md). Domain terms in
> [`CONTEXT.md`](../../../CONTEXT.md).

---

## 1. Purpose — the one-line problem

**BOLA (Broken Object Level Authorization, OWASP API1:2023) is a *semantic*
bug, not a *syntactic* one.** The defect is the *absence* of an ownership check
that should be there, judged against the application's own — usually
undocumented — authorization model. There is no dangerous sink to pattern-match
and no high-entropy string to flag. A handler that reads
`Book.query.filter_by(book_title=...)` is perfectly safe in one app and a
data-leak in another; the difference is whether the surrounding code constrains
the row to the current principal.

That single fact decides the whole strategy: pattern-based scanners
structurally cannot find these, and an LLM that *reads and reasons about the
call-chain* is the right instrument — provided it is disciplined enough not to
drown the signal in false positives. `authz-audit` is the markdown skill that
encodes that discipline.

It covers **BOLA / IDOR**, **BFLA** (broken function-level authorization), and
generic **access-control logic flaws** (fail-open, client-trusted role,
check-then-use mismatch). It deliberately stays out of the injection/secrets
lane, which the deterministic tools own.

---

## 2. Scope

| In scope (this skill owns it) | Adjacent (emit as `info`, defer) | Out of scope (delegate to a Tool) |
|---|---|---|
| **BOLA / IDOR** — missing per-object ownership predicate (API1 / A01) | **BOPLA / mass-assignment / excessive data exposure** (API3) → future `object-property-audit` skill. The skill *trips over* these (e.g. a self-grant `admin` field) and notes them; it does not own them. | **Injection** (SQLi / command / SSTI), **path traversal** → `run_semgrep` |
| **BFLA** — privileged function missing the role-gate its peers enforce (API5) | | **Hardcoded secrets** → `run_gitleaks` |
| **Access-control logic flaws** — fail-open, client-trusted role, post-authz path normalization (A01) | | **Dependency CVEs / SBOM / misconfig** → Stream-G tools (trivy, govulncheck, osv-scanner, trufflehog) |
| **Low-precision absence-based classes** — race/TOCTOU, missing rate-limiting, business-flow abuse — emitted as `info` *hypotheses* only, candidates for dynamic proof | | |

Staying in lane is a **feature**, not a limitation: it is what keeps precision
high and token cost down. If a deterministic tool catches something reliably,
this skill's job is at most to *triage* that tool's output — never to
rediscover it at worse precision and higher cost.

---

## 3. Where it fits in Argus

A **Skill** in Argus is a markdown `SKILL.md` (frontmatter `name` /
`description` / optional `tags`, plus a free-form body) that the agent reads and
follows. It is *content, not state* — there is no active/inactive lifecycle and
no `finalize_skill`. See [`CONTEXT.md` → Skill](../../../CONTEXT.md).

### 3.1 Shipped as a built-in (plus user-curated override)

- **Built-in.** `authz-audit` ships in the `argus` binary at
  `pkg/skill/builtin/authz-audit/SKILL.md`, embedded via `embed.FS`
  (`//go:embed all:builtin`) and merged by the `skill.Catalog` alongside the
  other built-ins (`pr-quick-check`, `secret-rotation-plan`, `threat-modeling`).
  No install step — it is available out of the box after a rebuild. Invokable
  via `/authz-audit` or discoverable by the agent through `list_skills` /
  `read_skill`. (Promoted to built-in after the VAmPI validation in §6 passed
  100% recall / 100% precision — *iterate against a real repo before baking it
  in*.)
- **User-curated override.** A directory at `~/.argus/skills/authz-audit/` on
  the daemon host **overrides the built-in by name** — whole-bundle, per ADR
  0005 — so a team can fork-and-tweak for their context without losing the
  upstream version. This is also the path for fast local iteration.

### 3.2 Relationship to the ADRs

- **ADR 0005 (skill shape, revised 2026-06-05).** A skill is a **directory
  bundle**: a `SKILL.md` (frontmatter exactly `name` / `description` / optional
  `tags`) plus optional supporting files the body pulls on demand via
  `read_skill_file("authz-audit", "<file>")`. The frontmatter `name` **must
  match the directory name** (`authz-audit`) — CI enforces this
  (`TestBuiltin_EveryEmbeddedSkillParses`). **No `tools:` whitelist** (RBAC is
  enforced at the Tool layer; a skill cannot escalate the caller's permissions).
  **No `when_to_use:`** field — the `description` *is* the when-to-use.
  `authz-audit` ships as a bundle: `SKILL.md` plus `self-test-vampi.md`, a
  maintainer validation oracle the body pulls via
  `read_skill_file("authz-audit", "self-test-vampi.md")` — kept out of the body
  so it never bloats a real run and never leaks answers into one (the same
  bundle pattern `threat-modeling` uses for `stride-template.md`).
- **ADR 0006 (no generic shell tool).** The skill **composes existing Tools
  only**. There is no `bash` / `exec` / generic shell escape to lean on. Route
  enumeration, id-tracing, and guard-resolution are all done with the Tools
  Argus already registers.

### 3.3 Tools the skill composes

Findings are emitted through the two **control tools** the agent loop handles
directly ([`pkg/agent/agent.go`](../../../pkg/agent/agent.go)): the skill body
instructs the agent to call **`add_finding` once per confirmed finding**, then
**`finalize_report(summary)`** exactly once to terminate and persist the report.
`add_finding`'s schema requires `severity`, `rule_id`, and `snippet`; `file`,
`line`, `title`, `description`, and `remediation` are optional. The Tools in
play:

| Tool | Role in the methodology |
|---|---|
| `read_file` | Read handlers, middleware, base repositories, policies, schema/migrations — the cross-file guard resolution is mostly this. |
| `grep` | Locate route declarations, id accessors, data-access sinks, authz helpers. |
| `list_files` | Inventory the project layout, find the OpenAPI spec / migrations / route modules. |
| `list_context` / `read_context` | Pull the org's `auth-conventions` from CONTEXT if present. |
| `write_context` | Optionally record the reconstructed ownership model back to CONTEXT for reuse. |
| `run_semgrep` / `run_gitleaks` | *Out-of-lane* delegation: the skill points injection/secret concerns at these rather than reporting them itself. |
| `list_skills` / `read_skill` | Self-discovery; the agent can find and load this skill on its own. |
| `add_finding` *(control tool)* | Append one confirmed finding to the report. Called once per finding. |
| `finalize_report` *(control tool)* | The agent's terminal call that persists the report and summarizes it. |

---

## 4. Install & invoke

### Install

`authz-audit` is a **built-in** — compiled into the `argus` binary, so there is
nothing to install: rebuild (`make` / `go build ./...`) and it is available. To
**override** it locally (fork-and-tweak), drop a bundle at the user-curated
path:

```sh
mkdir -p ~/.argus/skills/authz-audit
cp pkg/skill/builtin/authz-audit/SKILL.md ~/.argus/skills/authz-audit/SKILL.md
# edit it, then restart the daemon to pick it up (no hot-reload — ADR 0005).
```

### Invoke

Three paths, all equivalent in outcome:

1. **User-explicit slash command.** Type `/authz-audit` in the TUI. The client
   intercepts the token, loads `SKILL.md`, and injects its body directly into
   the conversation as one agent turn — deterministic, no dependence on the
   model deciding to read the skill. The body stays in context for follow-up
   turns.
2. **Agent-decided discovery.** The agent calls `list_skills` (sees the
   `authz-audit — <description> [tags]` line), judges it relevant, and calls
   `read_skill("authz-audit")` to load the body itself.
3. **Override-aware.** The built-in ships in the binary; a user-curated
   `~/.argus/skills/authz-audit/` bundle shadows it by name (whole-bundle
   override, ADR 0005).

> RBAC note: skills are an **analyst+** capability (viewers cannot enumerate or
> run them). This is a Tool-layer no-op until channel auth (Stream A) lands, at
> which point it becomes real automatically.

---

## 5. How findings surface

### 5.1 Mapping onto `report.Finding`

`report.Finding` (in [`pkg/report/report.go`](../../../pkg/report/report.go)) is
a **flat** struct:

```go
type Finding struct {
    ID, Severity, RuleID, File string
    Line                       int
    Snippet, Title, Description, Remediation string
}
```

The `ID` is **content-derived** — `sha256(rule_id + normalized snippet)`,
truncated to 12 hex chars (`ComputeFindingID`). The snippet is lowercased and
whitespace-collapsed before hashing, so the ID survives reformatting and
line-movement but **changes when the fix adds an owner predicate to the
vulnerable line** — i.e. a remediated finding auto-resolves.

Each confirmed finding is emitted with one `add_finding` call whose arguments
populate these fields (`severity`/`rule_id`/`snippet` required; the rest
optional). A BOLA finding is intrinsically richer than this flat shape (it has
*two* locations — the id-source and the data-access sink — plus a confidence and
a BOLA/BFLA classification). The skill maps the richer concept onto the flat
struct like so:

| Finding concept | Goes into | Why |
|---|---|---|
| The fix site (the data-access call missing the owner check) | `Line` + `File` | `Line` is single, so it points at the **sink** — the actionable place to add the predicate. |
| The vulnerable data-access line itself | `Snippet` | It is the **stable-ID anchor**: when the fix changes it, the finding resolves. |
| Id-source location (path/query/body/header/GraphQL arg) + the route + **confidence** + **classification** (BOLA vs BFLA, horizontal/vertical) + what could not be resolved | `Description` | The flat struct has no confidence or classification field; these are prose until/unless an ADR adds them (§8). |
| One-line human-readable headline | `Title` | |
| The concrete fix (add `filter_by(user=current)`, call the policy, scope the base repo) | `Remediation` | |

### 5.2 RuleID taxonomy and severity rubric (reference)

| RuleID | Class | Typical severity | When |
|---|---|---|---|
| `authz/bola-mutation-unscoped` | BOLA, mutating | **critical** | An update/delete/write reaches an object identified by request input with no per-principal/tenant constraint. |
| `authz/bola-missing-owner-predicate` | BOLA, read | **high** | A read of sensitive owned data with no ownership predicate (and no post-fetch ownership comparison). |
| `authz/bfla-missing-role-gate` | BFLA | **high** / **medium** | A privileged function (admin endpoint, role-restricted action) lacks the role-gate its sibling endpoints enforce. |
| `authz/access-control-fail-open` | Access-control logic | **medium** / **high** | Fail-open default, client-trusted role claim, check-then-use mismatch, post-authz path normalization. |
| `authz/bopla-mass-assignment-adjacent` | BOPLA / mass-assignment (adjacent, API3) | **info** | A request body binds a privileged/ownership property the caller must not set (self-grant `admin`, set `owner_id`), or a serializer over-exposes another principal's fields. Always `info`; deferred to a future `object-property-audit`. |

Severity rubric (the closed enum is `critical|high|medium|low|info`):

- **critical** — unscoped mutation/delete of another principal's object.
- **high** — read of sensitive owned data with no ownership check.
- **medium** — weak or partial check (present but bypassable / incomplete).
- **info** — low-precision, absence-based *hypotheses* (race, rate-limit,
  business-flow) and **adjacent** classes (mass-assignment / BOPLA).

Each `add_finding` call appends one finding to the in-progress report;
`finalize_report(summary)` then persists the assembled `Report` through the
standard pipeline, so authz findings sit alongside semgrep/gitleaks output with
the same stable IDs, severity buckets, and report/audit surfaces.

---

## 6. Validation — VAmPI

[VAmPI](https://github.com/erev0s/VAmPI) (`erev0s/vampi`, Flask + Connexion) is
the first target because its `vulnerable=1/0` toggle yields a **free labeled
dataset**: every `if vuln: … else: …` is an aligned (vulnerable, secure) pair
in source, so we measure recall and precision from the *same* code.

### 6.0 Result — genuinely blind (3 runs)

> **Methodology note.** An initial validation embedded the VAmPI worked-example
> *inside* `SKILL.md`, so the "blind" runners actually had the answers — the
> 100% it reported was not trustworthy. The worked-example was moved to the
> bundle's `self-test-vampi.md` oracle (runners are forbidden to read it) and
> the validation re-run **genuinely blind**: each runner saw only the
> methodology in `SKILL.md` plus the target source, and confirmed it never
> opened the oracle or any ground-truth doc.

| Run | In-scope (BOLA) | Adjacent (`info`) | Canonical FPs | Secure-`else` flagged |
|---|---|---|---|---|
| 1 | 2/2 | register self-grant (+1 soft lane-bleed) | 0 | no |
| 2 | 2/2 | register self-grant | 0 | no |
| 3 | 2/2 | — | 0 | no |

**Recall 100%, zero canonical false positives, no regression** from the
contaminated run — proving the score comes from the *methodology*, not a
memorized key. All three runs independently reconstructed the ground model from
source (`Book.user_id` FK ownership, `resp['sub']` principal, the `vuln` toggle)
and found both BOLA bugs at the exact sink (`books.py:51` high, `users.py:187`
critical) with the correct `rule_id`/severity, while clearing both decoys —
`update_email` (keys on `resp['sub']` in *both* branches) and `delete_user`
(admin-gated, BFLA-secure). The register self-grant was emitted as
`authz/bopla-mass-assignment-adjacent` `info`. **Only blemish:** Run 1 emitted
the `_debug` excessive-data-exposure under that same `info` rule_id instead of
leaving it out-of-lane; the skill's scope rule was then tightened to reserve
that rule_id for *write* mass-assignment only (read over-serialization stays
out-of-lane), matching the precision-perfect Runs 2 & 3.

### 6.1 Ground truth (authz-relevant)

| Endpoint / handler | Bug | Expected finding |
|---|---|---|
| `GET /books/v1/{book_title}` → `books.get_by_title` | vuln branch `Book.query.filter_by(book_title=...)` reads another user's `secret_content` (no owner). secure `else` scopes `filter_by(user=user, book_title=...)`. | **BOLA read, high** (`authz/bola-missing-owner-predicate`) |
| `PUT /users/v1/{username}/password` → `users.update_password` | vuln branch `User.query.filter_by(username=username)` uses the URL param, not `resp['sub']` → changes any user's password. | **BOLA mutation, critical** (`authz/bola-mutation-unscoped`) |
| `POST /users/v1/register` → `users.register_user` | self-grants `admin` (no `additionalProperties:false`). | **mass-assignment → info** (adjacent, API3) |

Framework facts the skill must internalize for this target:

- **Routing is the OpenAPI spec.** PASS 1 must parse
  `openapi_specs/openapi3.yml` — under Connexion the spec *is* the router; there
  are no route decorators to grep for.
- **Principal accessor** = `resp = token_validator(request.headers.get('Authorization'))`;
  identity = `resp['sub']`.
- **VAmPI has no authorization layer at all** — only authentication — so PASS 0
  should record "no centralized authz layer" and *raise* the BOLA prior.
- **Stay out of the SQLi lane**: `users.get_user`'s f-string in `text()` is
  `run_semgrep`'s job, not this skill's.

### 6.2 The two metrics (both from the toggle)

- **Recall** — does the skill find the **2 BOLA-class endpoints**
  (`get_by_title`, `update_password`)?
- **Precision / no-FP** — does it correctly mark the secure `else:` branches
  (which scope on `resp['sub']`) as **SAFE**? Flagging an `else` branch is the
  **canonical false positive** — this is the credibility test that the
  verification gate exists to pass.

### 6.3 Target roadmap after VAmPI

[crAPI](https://github.com/OWASP/crAPI) (realistic microservices, BOLA + BFLA)
→ [Damn Vulnerable RESTaurant](https://github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game)
(modern FastAPI, roles + ownership) →
[RailsGoat](https://github.com/OWASP/railsgoat) (executable RSpec IDOR exploit
spec as ground truth). Each step adds a framework family and a richer
ownership/role model.

---

## 7. Limitations & false-positive posture

The blunt evidence that shapes everything here: Semgrep's 2025 *"Can LLMs detect
IDORs"* study measured a Claude Code **LLM-only baseline at ~22% precision /
~88% false positives** on IDOR — and that **dropped to ~0% true positives on
multi-file RBAC and middleware-enforced authorization**. A naive "ask the model
to find IDORs" pass is not just noisy; it is *blind* exactly where real apps put
their authorization (middleware, base repositories, policies).

So the skill is anchored to two things the naive baseline lacks:

1. **Deterministic enumeration before judgement.** The 6-pass method
   (encoded in the body) builds the authorization *context* — framework, route
   declaration mechanism, principal accessor, ownership/tenancy model, the
   project's actual authz vocabulary — in PASS 0, *before* judging any handler.
   This is what converts 88% FPs into a usable signal.
2. **A verification gate (self-refutation).** Borrowed from Trail of Bits'
   `fp-check` and the Anthropic verification pattern: before emitting, the agent
   runs a skeptical pass — *"what guard might I have missed? did I actually
   **read** the middleware / base-repo / policy, or just its name?"* The default
   is **NOT to report** when a guard chain is unresolved. The discipline rule is
   explicit: *never flag a call-chain you did not read.* "I can't find a guard in
   this file" means "go read the call chain", not "emit a finding".

### Posture

- **Human-in-the-loop.** Because authz is semantic, the skill produces a
  *credible, confidence-stated triage*, not a verdict. Findings carry their
  confidence and unresolved-chain notes in `Description` so a reviewer can
  judge.
- **Low-precision classes are `info` hypotheses.** Race/TOCTOU, rate-limiting,
  and business-flow abuse never become `critical`/`high` findings; they are
  advisory `info` entries, candidates to hand to a **dynamic prover** (e.g. the
  `shannon` skill) on a running target. The skill is the broad, cheap, *static*
  net; dynamic proof is applied only to the handful of hypotheses worth the
  cost.
- **Static by construction.** It reads code; it does not execute exploits. Safe
  to run pre-merge on every PR, no running target, no blast radius.

---

## 8. Why we built our own

Every verified off-the-shelf option is one of: pattern-based and blind to authz
logic, accurate-ish but **paywalled**, or capable but **dynamic and expensive**.
None is a cheap, static, org-aware, BOLA-specialized pass that integrates with
Argus's report/MEMORY and runs on Argus's own provider budget. The table below
is the **verified** landscape (each entry confirmed at a real URL/license); it
is grouped by kind. We do not claim more than we checked.

### 8.1 Generalist white-box reviewers (authz is one section; adoptable as templates, not specialized)

| Name | What it does | Honest limitation | URL / license |
|---|---|---|---|
| `anthropics/claude-code-security-review` | GitHub Action + `/security-review` slash command; general security review of a diff. | Generalist, diff-scoped; no BOLA-specific methodology or ownership-model reconstruction. | github.com/anthropics/claude-code-security-review — MIT |
| `scholarly360/owasp-top10-web-skills` (broken-access-control skill) | OWASP Top-10 skill bundle, installable via `npx skills add`. | Broad checklist coverage, not a deep cross-file authz tracer. | github.com/scholarly360/owasp-top10-web-skills — MIT |
| `netresearch/security-audit-skill` | Security audit skill. | Generalist audit; authz is one topic among many. | github.com/netresearch/security-audit-skill — code MIT / content CC-BY-SA-4.0 |
| `Security-Phoenix-demo/security-skills-claude-code` | Security skills collection for Claude Code. | Generalist; not authz-specialized. | github.com/Security-Phoenix-demo/security-skills-claude-code — MIT |

### 8.2 Best structural template (zero authz content)

| Name | What it does | Honest limitation | URL / license |
|---|---|---|---|
| `trailofbits/skills` | High-quality skill patterns — **differential-review**, **variant-analysis**, and especially the **`fp-check` verification-gate** pattern we borrow. | Contains **no authz content** at all; it is a structural/discipline template, not a detector. | github.com/trailofbits/skills — CC-BY-SA-4.0 |

### 8.3 Authz-named but dynamic (need a running target — wrong shape for static review)

| Name | What it does | Honest limitation | URL / license |
|---|---|---|---|
| `davila7/claude-code-templates` (security/idor-testing) | IDOR *testing* template. | Dynamic — assumes a live target; not a static source pass. | github.com/davila7/claude-code-templates |
| `elementalsouls/Claude-BugHunter` | Agentic bug hunter. | Dynamic / exploit-oriented. | github.com/elementalsouls/Claude-BugHunter |
| `zm2231/z-audit` | Audit tooling. | Dynamic-leaning; wrong shape for cheap static triage. | github.com/zm2231/z-audit |
| BOLABuster (Unit 42) | BOLA discovery research. | **Unreleased.** | Palo Alto Unit 42 (research, no public release) |
| BACFuzz | Broken-access-control fuzzer. | Dynamic fuzzing, needs a running target. | research / fuzzer |
| `peerigon/access-control-testing` | Access-control test harness. | Dynamic testing harness. | github.com/peerigon/access-control-testing |

### 8.4 Capable but paid / closed (cannot adopt)

| Name | Note |
|---|---|
| ZeroPath; Corgea (BLAST / PolicyIQ); Semgrep AI-Powered Detection (private beta); Endor Labs AI SAST; DryRun; Aikido; Almanax | Paid / closed — not adoptable. Semgrep's AI path is the best of these (~61% precision in their writeup) but requires a Pro/Assistant license. |
| Snyk Code (DeepCode); GitHub CodeQL + Copilot Autofix; Amazon CodeGuru | Generic SAST with a **documented object-authz blind spot** — CodeQL's IDOR rule is medium-precision and floods FPs when authz lives in middleware/attributes (github/codeql#16327). |

### 8.5 Best adaptable open seed

| Name | What it does | Honest limitation | URL / license |
|---|---|---|---|
| `GitHubSecurityLab/seclab-taskflows` | Open YAML taskflows; **IDOR was the #1 finding category** in their results. | A **Copilot-licensed agent framework**, not a drop-in Claude/Argus skill — adaptable seed, not an import. | github.com/GitHubSecurityLab/seclab-taskflows |

**Net.** We borrow the *structure* from Trail of Bits (the `fp-check`
verification gate, differential and variant analysis), the *target-selection
discipline* from VAmPI's toggle, and the *evidence* from Semgrep's 22%/88%
study — and supply the one thing none of the above gives us: a cheap, static,
org-aware, BOLA-specialized pass that lands findings in Argus's own
`report.Finding` pipeline on Argus's own budget.

---

## 9. Decisions (resolved)

Resolved by the genuinely-blind VAmPI validation (§6.0); full rationale in
[`docs/authz-skill-design.md` §8](../../authz-skill-design.md).

1. **Flat `Finding`, no `Confidence` field — RESOLVED.** Confidence,
   classification, and the id-source stay in `Description` prose. The bar for a
   first-class `Confidence` field was *a measurable FP reduction from it*;
   validation hit **zero canonical false positives** without it, so the field
   isn't warranted — precision comes from the PASS-0 ground model and the
   verification gate, not a metadata column. No ADR.
2. **Strict scope — RESOLVED.** BOLA/BFLA/access-control owned; *write*
   mass-assignment emitted as `info` (`authz/bopla-mass-assignment-adjacent`) →
   future `object-property-audit`; *read* excessive-data-exposure stays
   out-of-lane (note only, no `authz/*` rule_id).
3. **Finding vs hypothesis — RESOLVED.** BOLA/BFLA high-confidence → full
   findings; low-precision/absence-based classes → `info` hypotheses for a
   dynamic prover. Ties to the FP-aversion tracked in MEMORY.

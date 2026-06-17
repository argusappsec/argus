# White-box authorization skill — landscape, gaps, and design

> Status: **implemented** — the design landed as the built-in `authz-audit`
> skill (`pkg/skill/builtin/authz-audit/`), validated 100% recall / 100%
> precision on VAmPI (see [`skills/authz-audit/README.md`](skills/authz-audit/README.md)).
> This document keeps the rationale: what to build for white-box detection of
> authorization-logic bugs (BOLA / IDOR / BFLA), why the off-the-shelf options
> don't cover it, and how an Argus-native skill does.
>
> Companion material: `CONTEXT.md` (Tool/Skill definitions), ADR 0005 (skill
> shape — directory-bundle model), ADR 0006 (no generic shell tool),
> and the skill's own [`README.md`](skills/authz-audit/README.md).

---

## 1. The problem in one line

BOLA (Broken Object Level Authorization, OWASP **API1:2023**) is a **semantic**
bug, not a **syntactic** one. The defect is *the absence of an ownership check
that should be there*, measured against the application's own — usually
undocumented — authorization model. There is no dangerous sink to match and no
high-entropy string to flag. That single fact decides everything below:
pattern-based tools structurally cannot find it, and an LLM that *reads and
reasons about the code* is the right instrument.

Evidence we collected (sources in §9):

- Semgrep's own writeup: a naive LLM pass on real apps yields **78–88% false
  positives** on IDOR/BOLA.
- CodeQL's `cs/web/insecure-direct-object-reference` is rated only **medium
  precision**, with documented false-positive floods from authorization that
  lives in middleware / attributes / call-chains (github/codeql#16327).
- Both Semgrep and CodeQL tell users the only reliable static route is
  **hand-written, app-specific rules** — which "few teams have the time,
  resources, or expertise" to author.

---

## 2. The dividing line: pattern → tool, semantic → skill

This is the spine of the whole strategy. It tells us which problems justify a
skill and which we must *not* reimplement as one.

| Vulnerability class | OWASP | Detect by | Owner |
|---|---|---|---|
| **BOLA / IDOR** | API1 / A01 | semantic | **Skill** |
| **BFLA** (admin function, no role-gate) | API5 | semantic | **Skill** |
| **Access-control logic** (fail-open, trust-client) | A01 | semantic | **Skill** |
| **BOPLA** (mass-assignment / excessive exposure) | API3 | hybrid | **Skill** |
| Broken auth (alg=none, guessable reset token) | API2 | hybrid | Tool + Skill |
| SSRF | API7/A10 | hybrid | Tool (sink) + Skill (bypass) |
| Insecure deserialization | A08 | hybrid | Tool (sink) + Skill (gadget) |
| Race / TOCTOU, rate-limiting, business-flow abuse | API4/API6 | semantic | Skill (as *hypotheses*) |
| **Injection (SQLi/cmd), path traversal, secrets, misconfig** | A03/A05 | pattern | **Tool — do not build a skill** |

**Rule of thumb:** if a deterministic tool (semgrep, gitleaks, and the
Stream-G additions trivy/trufflehog/govulncheck/osv-scanner) catches it
reliably, the skill's only job is to *triage/confirm* the tool's output — never
to rediscover it at worse precision and higher token cost.

---

## 3. Public / off-the-shelf options — what they do and where they fall short

"Public" here means: skills already loadable in a Claude Code session, plus the
common third-party static analyzers. The recurring defects are **cost**,
**generality** (no authz method), and **integration** (no access to the org's
authorization model or to Argus's report/MEMORY).

### 3.1 Claude Code skills available in-session

| Skill | What it does | Defects for our use case |
|---|---|---|
| **`shannon`** | Autonomous AI pentester. Analyzes source, picks attack vectors, and **executes real exploits** to *prove* vulnerabilities (web apps + APIs). | **Cost**: autonomous multi-step agent loop → heavy token spend, needs a capable/expensive Claude tier and runs on *your* CC plan. **Needs a running target**: it proves bugs dynamically, so it's DAST-on-top-of-source, not a cheap static pre-merge pass. **Non-deterministic** breadth. → Excellent as the *confirmation* stage for a specific hypothesis; wrong tool for broad, cheap, static BOLA triage across a repo. |
| **`/security-review`** (built-in) | Security review of the pending **branch diff**. | **Diff-scoped** (not whole-repo authz enumeration). **Generalist**: no BOLA-specific methodology, no ownership-model reconstruction. Runs on your CC plan, findings don't land in Argus's report/MEMORY. |
| **`/review`, `/code-review`, `/simplify`** | PR review / correctness bugs / cleanups. | Aimed at **correctness and quality**, not authorization logic. No authz reasoning. |
| **`code-review-graph` plugin** | Tree-sitter knowledge graph: impact/blast-radius, flows, hub/bridge nodes. | Not a vuln hunter — it's **structure/impact**. But it is a strong *feeder*: route/flow/affected-flow enumeration can hand a BOLA skill its PASS-1 route table. Needs a graph build step. |
| `diagnose`, `verify`, `tdd`, `deep-research`, … | Debugging / verification / research. | Out of scope for authz detection. |

**Key structural defect shared by all of these:** they run inside *your* Claude
Code session, on *your* CC subscription, with **no access to the
organization's authorization conventions** (Argus's SOUL/CONTEXT) and **no path
into Argus's report/MEMORY**. They are general-purpose and context-blind to the
target org.

### 3.2 Third-party static analyzers

| Tool | Defect for BOLA specifically |
|---|---|
| **Semgrep community / OSS rules** | No reliable generic IDOR/BOLA rule. Semgrep's docs say generic detection is infeasible; you must write custom app-specific rules. |
| **CodeQL default suites** | `insecure-direct-object-reference` / `missing-function-level-access-control` are medium-precision, C#-centric, and flood with FPs when authz is in middleware/attributes (issue #16327). |
| **Semgrep Pro / Assistant (AI IDOR)** | Best of the bunch (~61% precision, ~8× more true positives than LLM-only) — **but requires a paid Pro/Assistant license** and still needs human triage. A cost + lock-in dependency. |
| **gitleaks / trufflehog** | Out of scope entirely — secrets via entropy/regex; no model of routes, handlers, or authorization. |

**Net:** every public option is either (a) pattern-based and blind to authz
logic, (b) accurate-ish but **paywalled** (Semgrep Pro), or (c) capable but
**expensive and dynamic** (shannon). None is a cheap, static, org-aware,
BOLA-specialized pass that integrates with Argus.

---

## 4. What we can build ourselves — and why it's better *here*

A **white-box authorization skill native to Argus**: pure markdown content (no
new Go tool needed), composing the tools Argus already has
(`read_file`, `grep`, `list_files`, `list_context`/`read_context`), emitting
findings through the existing `add_finding` / `finalize_report` control tools.

Why an Argus-native skill beats leaning on the public options:

1. **Cost.** It runs on **Argus's own provider and budget** (`pkg/provider`,
   incl. the Gemini backend; capped by `pkg/budget`), not on a separate
   expensive Claude Code subscription. No per-developer CC plan, no Semgrep Pro
   license. The model tier is our choice, governed by the org budget cap.
2. **Specialization.** It encodes the 6-pass authz methodology (§6) that
   off-the-shelf tools explicitly *don't* have. This is the difference between
   78% FPs and a usable signal.
3. **Org-awareness.** It can read the organization's **authorization
   conventions** from `CONTEXT` (`auth-conventions.md`) and respect
   accepted-false-positives from **MEMORY** — context no public skill has.
4. **Integration.** Findings land in the same `report.Finding` pipeline as
   semgrep/gitleaks output, with content-derived stable IDs, severity buckets,
   and the daemon's audit/report surfaces.
5. **Safety.** It is **static** — it reads code, it does not execute exploits.
   No running target, no blast radius, safe to run pre-merge on every PR. (It
   *hands off* to `shannon` only when a hypothesis needs dynamic proof — §7.)
6. **Composability with the public tools, not competition.** It *ingests*
   semgrep output for hybrid classes and *feeds* shannon for confirmation. It
   fills the one gap the public tools leave open.

This is exactly the Stream-F thesis ("Argus knows the common security workflows
out of the box") applied to the one workflow that most needs a human-like
reading of the code.

---

## 5. Architecture of the skill

### 5.1 Where it lives

- **Built-in:** `pkg/skill/builtin/authz-audit/SKILL.md`, embedded via `embed.FS`
  (`//go:embed all:builtin`) and resolved by the `skill.Catalog` next to the
  other built-ins. Invokable via `/authz-audit` or discovered by the agent
  through `list_skills`/`read_skill`. Per the revised ADR 0005 a skill is a
  **directory bundle** (`SKILL.md` + optional supporting files read via
  `read_skill_file`); `authz-audit` currently ships as a single `SKILL.md`.
- **User-curated override:** a `~/.argus/skills/authz-audit/` bundle overrides
  the built-in by name (whole-bundle), so a team can fork-and-tweak and iterate
  cheaply without losing the upstream version.

The skill was validated against a real repo (VAmPI) *before* being baked in as a
built-in — iterate against a real target first.

### 5.2 Shape (per ADR 0005)

```
---
name: authz-audit
description: White-box detection of broken authorization (BOLA/IDOR/BFLA) by
  reconstructing the app's ownership model and finding access paths that skip
  the per-object/per-role check their peers enforce.
tags: [authorization, bola, idor, bfla, access-control, white-box]
---
# body: the 6-pass methodology (§6), the finding contract (§6.2),
# and the discipline rules (don't report until the call-chain was read).
```

- No `tools:` whitelist (ADR 0005 — RBAC is enforced at the Tool layer).
- The body is the prompt extension; `/authz-audit` injects it as one agent turn.
- It **composes existing tools only** (ADR 0006 — no shell escape): route
  enumeration via `grep`/`list_files`/`read_file`; no new binary.

### 5.3 Output contract — mapping onto `report.Finding`

`report.Finding` is a **flat** struct (`Severity, RuleID, File, Line, Snippet,
Title, Description, Remediation`; ID is `sha256(rule_id + normalized snippet)`).
It has **no** confidence field, **no** classification field, and a **single**
`Line`. A BOLA finding is intrinsically richer (two locations — the id-source
and the data-access sink — plus a confidence and a BOLA/BFLA classification).
Design decisions:

- **`RuleID` taxonomy** (also the stable-ID anchor):
  `authz/bola-missing-owner-predicate`, `authz/bola-mutation-unscoped`,
  `authz/bfla-missing-role-gate`, `authz/access-control-fail-open`.
- **`Line`** points at the **data-access sink** (the actionable fix site); the
  **id-source** location + the route are written into `Description`.
- **`Snippet`** = the vulnerable data-access line (stable ID anchor; when the
  fix adds the owner predicate, the snippet changes → the finding auto-resolves).
- **Confidence + classification** are encoded in `Description` until/unless we
  decide they earn first-class fields (open decision §8.1).
- **`Severity`** rubric (closed enum): mutation/delete unscoped → `critical`;
  read of sensitive owned data → `high`; weak/partial check → `medium`;
  low-precision absence-based hypotheses → `info`.

Emission uses the agent loop's two **control tools** (`pkg/agent/agent.go`): the
body instructs the agent to call `add_finding` once per confirmed finding
(`severity`/`rule_id`/`snippet` required; `file`/`line`/`title`/`description`/
`remediation` optional), then `finalize_report(summary)` once. No *new* tool is
needed — the skill is **pure content**.

---

## 6. Methodology and surface

### 6.1 The 6-pass method (what the body encodes)

The pass order exists to **build authorization context before judging any
handler** — this is what defeats the 78%-FP trap.

0. **Ground model (cache it).** Detect framework + how it declares routes
   (decorators? OpenAPI spec? annotations?). Find the **authenticated-principal
   accessor**. Map the **ownership/tenancy model** from schema/migrations
   (`owner_id`/`tenant_id`/FKs). Inventory the project's **actual authz
   vocabulary** (guards, policies, `assertOwner`-style helpers). Pull
   `auth-conventions` from CONTEXT if present.
1. **Enumerate** routes → handler → method into a table.
2. **Filter** to handlers taking an **object identifier from request input**
   (path/query/body/header/GraphQL arg).
3. **Trace** each id to its **data-access sink**; tag read vs mutation.
4. **Guard check, cross-file.** Between request entry and the object being
   returned/mutated, is access constrained to the current principal/tenant
   (query predicate / post-fetch comparison / policy call / base-repo scope /
   DB RLS)? **Resolve helpers and middleware by reading them, not by name.**
5. **Classify / disambiguate.** BOLA (right endpoint, wrong object) vs BFLA
   (wrong endpoint entirely); horizontal vs vertical; drop intentionally-public
   resources.
6. **Rank** by exploitability and emit the finding.

**Discipline (in the body, verbatim intent):** *never flag a handler until
PASS 0 + PASS 4 actually read the relevant middleware/base-repo/policy.* Treat
"I can't find a guard in this file" as "go read the call chain", not as a
finding. State confidence and what could not be resolved.

### 6.2 Surface coverage — explicit in/out of scope

**In scope (this skill owns it):**
- BOLA / IDOR — missing per-object ownership predicate (API1 / A01).
- BFLA — privileged function missing the role-gate its peers have (API5).
- Generic access-control logic flaws — fail-open, client-trusted role,
  check-then-use mismatch, post-authz path normalization (A01).

**Adjacent (flagged as `info`, deferred to a sibling skill):**
- BOPLA / mass-assignment / excessive data exposure (API3) → future
  `object-property-audit`. The skill will *trip over* these (e.g. a self-grant
  `admin` field) and should note them, not own them.

**Out of scope (belongs to deterministic tools):**
- Injection (SQLi/command/SSTI), path traversal, hardcoded secrets, most
  misconfig — `run_semgrep` / `run_gitleaks` / Stream-G tools. Staying in lane
  here is a *feature*: it keeps precision and cost down.

**Low-precision, emitted as hypotheses (`info`):**
- Race/TOCTOU, missing rate-limiting, business-flow abuse — advisory only,
  candidates for dynamic proof (§7).

---

## 7. Operational chain — static find → dynamic prove

```
   semgrep / gitleaks ──(pattern hits, hybrid input)──┐
   code-review-graph ──(route/flow table for PASS 1)──┤
                                                       ▼
                                          ┌────────────────────────┐
                                          │  authz-audit (SKILL)   │  static, cheap,
                                          │  6-pass, org-aware     │  org-aware, safe
                                          └───────────┬────────────┘
                              high-confidence finding │ low-confidence hypothesis
                                          ┌────────────┴────────────┐
                                          ▼                         ▼
                                   report.Finding            shannon (or manual)
                                   + finalize_report         dynamic exploit proof
                                                             (running target, costly)
```

`authz-audit` is the broad, cheap, static net; `shannon` is the precise,
expensive, dynamic confirmer used **only** on the handful of hypotheses worth
proving. This is how we get coverage without paying shannon's cost on every
endpoint.

---

## 8. Open design decisions

1. **Report model.** Stay within the flat `Finding` struct (encode confidence /
   classification / id-source in `Description`) — works today, pure content —
   *or* open an ADR to add a `Confidence` field (and maybe a second location).
   **Recommendation:** start flat; open the ADR only if VAmPI validation shows a
   measurable FP-reduction from first-class confidence. Don't add fields ahead
   of data.
2. **Scope boundary.** Strict BOLA/BFLA/access-control vs an "authz+" skill that
   also reports mass-assignment privilege escalation (API3).
   **Recommendation:** strict; emit adjacent findings as `info` pointing at a
   future `object-property-audit`.
3. **Finding vs hypothesis.** Whether low-precision/absence-based classes enter
   the report at all. **Recommendation:** BOLA/BFLA high-confidence → full
   findings; everything low-precision → `info` hypotheses, candidates for
   shannon. Ties to the FP-aversion already tracked in MEMORY.

---

## 9. Validation plan (target: VAmPI)

VAmPI (`erev0s/vampi`, Flask + Connexion) is the chosen first target because its
`vulnerable=1/0` toggle gives a **free labeled dataset**: every `if vuln: … else:
…` is an aligned (vulnerable, secure) pair in source.

**Ground truth (authz-relevant), derived from the real code:**

| Endpoint / handler | Bug | Expected finding |
|---|---|---|
| `GET /books/v1/{book_title}` → `books.get_by_title` | reads another user's `secret_content` (query `filter_by(book_title=…)`, no owner) | BOLA read, **high** |
| `PUT /users/v1/{username}/password` → `users.update_password` | changes any user's password (`filter_by(username=…)` from URL, not `resp['sub']`) | BOLA mutation, **critical** |
| `POST /users/v1/register` → `users.register_user` | self-grants `admin` (no `additionalProperties:false`) | mass-assignment → `info` (adjacent, API3) |

**Two metrics, both from the toggle:**
- **Recall:** does the skill find the 2 BOLA-class endpoints?
- **Precision / no-FP:** does it correctly mark the secure `else:` branches
  (which scope on `resp['sub']`) as **SAFE**? Flagging the `else` is the
  canonical false positive — the credibility test.

**Notes the framework forces (generalizable lessons):**
- PASS 1 must **parse `openapi_specs/openapi3.yml`** (Connexion: the spec *is*
  the router; there are no route decorators).
- Principal = `resp['sub']` from `token_validator(request.headers.get(...))`.
- VAmPI has **no authorization helper at all** — only authn — so PASS 0 should
  record "no centralized authz layer" and raise the BOLA prior.
- The skill must **stay out of the SQLi lane** (`users.get_user` f-string in
  `text()`): that's `run_semgrep`'s job, not authz-audit's.

**Target roadmap after VAmPI:** crAPI (realistic microservices, BOLA+BFLA) →
Damn Vulnerable RESTaurant (modern FastAPI, roles+ownership) → RailsGoat
(executable RSpec IDOR exploit spec as ground truth).

---

## 10. References

- OWASP API Security Top 10 (2023): API1 BOLA, API3 BOPLA, API5 BFLA —
  <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>
- OWASP IDOR Prevention Cheat Sheet & WSTG Authorization Testing.
- PortSwigger Web Security Academy — Access control / IDOR.
- Semgrep: "Can LLMs detect IDORs" (2025) and AI-powered detection blog; Semgrep
  IDOR docs (generic detection infeasible).
- CodeQL `cs/web/insecure-direct-object-reference`; github/codeql#16327 (FP
  reports for call-chain/attribute authz).
- Targets: `github.com/erev0s/VAmPI`, `github.com/OWASP/crAPI`,
  `github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game`,
  `github.com/OWASP/railsgoat`.

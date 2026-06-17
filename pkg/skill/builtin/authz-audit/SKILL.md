---
name: authz-audit
description: White-box detection of broken authorization (BOLA/IDOR, BFLA, access-control logic flaws) in an API or web codebase. Use when asked to audit authorization, hunt IDOR/BOLA, check object-level or function-level access control, or verify that handlers scope data access to the current principal/tenant. Reconstructs the app's ownership model first, then finds access paths that skip the per-object/per-role check their peers enforce. Static, read-only; delegates injection/secrets/path-traversal to run_semgrep/run_gitleaks.
tags: [authorization, bola, idor, bfla, access-control, white-box, owasp-api1, owasp-api5]
---

# authz-audit — find broken authorization by reading the code

You are auditing this repository for **broken authorization**: places where an
authenticated caller can reach an object or a function that should be denied to
them. This is a **semantic** bug — the *absence* of an ownership/role check that
should be there — so there is no dangerous sink to grep for and no high-entropy
string to flag. A naive "looks like an IDOR" pass measures at **78–88% false
positives**; an LLM-only baseline scored ~22% precision and dropped to ~0% true
positives on middleware-enforced authorization. You beat that number in exactly
one way: **build the authorization context first, then read every guard chain
end-to-end before you judge a handler.** Follow the passes in order. Do not skip
PASS 0. Do not skip the verification gate.

You work **only** with the tools you already have: `read_file`, `grep`,
`list_files`, `list_context`, `read_context`, and optionally `run_semgrep`
output as a hybrid input. There is no shell. You emit findings with
`add_finding` (one call per confirmed issue) and end with `finalize_report`.

## Scope — stay in your lane

**You own (emit as full findings):**

- **BOLA / IDOR** (OWASP API1 / A01): a handler reads or mutates an object
  identified by request input without constraining it to the caller's
  ownership/tenant.
- **BFLA** (API5): a privileged function is reachable without the role-gate its
  sibling endpoints enforce.
- **Access-control logic flaws** (A01): fail-open guards, role trusted from
  client input, check-then-use mismatch, authorization done before a path/ID is
  normalized.

**Adjacent — emit as `info` only, do not own:**

- **Mass-assignment** (API3 BOPLA, **write**): a request body binds a privileged
  property the caller must not set — e.g. a registration body that self-grants
  `admin`, or a payload that sets `owner_id`. You will *trip over* these while
  tracing. **Emit each as a single `add_finding` with
  `rule_id=authz/bopla-mass-assignment-adjacent` and `severity=info`** — do not
  bury it in the final summary, and do not reuse a BOLA `rule_id` — then point
  at a future `object-property-audit` skill.
- **Excessive data exposure** (API3, **read**): a serializer over-returns
  another principal's private fields (e.g. an endpoint that dumps `password`).
  The access itself isn't bypassed — too much just comes back — so this is **out
  of lane**: record it in your out-of-lane notes, do **not** give it an
  `authz/*` `rule_id`. Record these, don't chase them.

**Out of scope — delegate, do not rediscover:**

- Injection (SQLi / command / SSTI), path traversal, hardcoded secrets, most
  misconfiguration. These are deterministic and belong to `run_semgrep` /
  `run_gitleaks`. If you see an f-string SQL query while tracing a sink, that is
  **not your finding** — note "out of scope, run_semgrep" and move on. Staying
  in lane is what keeps your precision and token cost down.

**Low-precision classes — emit as `info` hypotheses only:**

- Race/TOCTOU, missing rate-limiting, business-flow abuse. You cannot confirm
  these statically with confidence; emit them as `info` advisories that a
  dynamic confirmer (e.g. `shannon`) could prove.

***

## PASS 0 — Ground the model (do this before anything else)

You cannot judge a guard until you know what a guard *looks like in this repo*.
Produce a short ground-model note (keep it in your working context) answering
all five questions below. If a question is genuinely unanswerable, write
"UNKNOWN" — that itself raises the prior that authorization is missing.

1. **Framework + how routes are declared.** This decides your PASS 1 strategy.
   `grep` and `list_files` for the tell-tales:
   - Decorators / macros: Flask `@app.route`/`@bp.route`, FastAPI
     `@router.get`, Django `urls.py` `path(...)`, Spring `@GetMapping`/
     `@RequestMapping`, NestJS `@Get()`/`@Controller`, Express
     `app.get(...)`/`router.post(...)`, Rails `config/routes.rb`, Go
     `mux.HandleFunc`/`r.Get`/`e.GET`.
   - **OpenAPI/Connexion case (no decorators):** if you find an
     `openapi*.yml`/`.yaml`/`.json` spec and a `connexion` import, **the spec
     IS the router**. Routes live as `paths:` → `operationId:` mappings; the
     `operationId` (e.g. `users.update_password`) names the Python function.
     Enumerate routes from the spec, not from decorators. The same applies to
     other spec-first stacks — when in doubt, look for a spec before assuming
     decorators exist.

2. **The authenticated-principal accessor.** How does a handler learn *who is
   calling*? This is the right-hand side of every ownership comparison you will
   make. Find the one canonical expression, e.g. `request.user`,
   `current_user`, `ctx.Value(userKey)`, `req.auth.sub`,
   `g.user.id`, a decoded-JWT `sub`/`uid` claim, or
   `resp = token_validator(request.headers.get('Authorization')); resp['sub']`.
   `grep` for `Authorization`, `token`, `jwt`, `session`, `current_user`,
   `request.user`, `getPrincipal`, `Principal`, `claims`. Write down the exact
   accessor — flag mismatches against it later.

3. **The ownership / tenancy model.** Read the schema/migrations/models. Which
   tables carry an owner or tenant key? `grep` for `owner_id`, `user_id`,
   `account_id`, `tenant_id`, `org_id`, `team_id`, and foreign-key
   declarations (`ForeignKey`, `references`, `belongs_to`, `@ManyToOne`,
   `relationship(`). The presence of `owner_id`/`tenant_id` on a table tells
   you what predicate a correct query *must* contain.

4. **The project's actual authz vocabulary.** What does a check look like
   *here*? Inventory the real helpers/guards/policies — do not assume generic
   names. `grep` for `authorize`, `can?`, `policy`, `Policy`, `Pundit`,
   `CanCan`, `@PreAuthorize`, `permission`, `require_role`, `ensure_owner`,
   `assertOwner`, `is_owner`, `check_access`, `Guard`, `@UseGuards`,
   middleware names, base-repository scoping (`scoped`, `for_user`,
   `default_scope`), and DB row-level security (`RLS`, `CREATE POLICY`,
   `current_setting`). Record each as "a guard named X lives in file Y" — you
   will resolve these by reading them, never by name.

5. **Org conventions, if recorded.** Call `list_context`; if an
   `auth-conventions` (or similar) topic exists, `read_context` it. It may
   document the canonical principal accessor, the approved guard helpers, and
   resources that are intentionally public. Honor it. Also respect any
   accepted-false-positives the project has already recorded.

> If PASS 0 finds **no centralized authorization layer at all** (only
> authentication), say so explicitly and **raise the BOLA prior**: every
> handler is then individually responsible for its own ownership check, and
> omissions are likely.

## PASS 1 — Enumerate routes → handler → method

Build a route table: `(HTTP method, path, handler function, file:line)`.

- **Decorator/macro stacks:** `grep` the route decorators/registrations from
  PASS 0 and resolve each to its handler function.
- **OpenAPI/Connexion stacks:** `read_file` the spec; for each `paths:` entry,
  read `<method>:` → `operationId:` → resolve the dotted `operationId` to its
  module + function, then `grep`/`read_file` that function.
- If a `code-review-graph` route/flow table is available to you as input, use it
  to seed this table rather than re-deriving it.

Do not editorialize yet. Just get the complete handler inventory.

## PASS 2 — Filter to object-identifier handlers

Keep only handlers that take an **object identifier from request input**:

- path parameter (`/books/{book_title}`, `/users/<int:id>`),
- query string (`?id=`, `?account=`),
- request body field (`{"order_id": ...}`),
- header, cookie, or GraphQL argument.

Discard handlers that operate only on the caller's own implicit identity
(e.g. `GET /me`, `GET /profile` keyed solely on `current_user`) — there is no
*foreign* object to confuse, so no BOLA surface. For each kept handler, note the
**id-source** precisely: which parameter, from where (path/query/body/header).
An id that comes **from the request body** is a stronger signal than a path
param (easier to tamper, often unvalidated).

## PASS 3 — Trace each id to its data-access sink

For each kept handler, follow the identifier from entry to the line that
actually touches the datastore — the **sink**. Tag the sink **read** vs
**mutation**:

- **read:** `.query.filter_by(...)`, `.findByPk(...)`, `.get(id)`,
  `Model.objects.get(...)`, `findOne`, `SELECT`, `repo.FindByID`.
- **mutation:** `.save()`, `.update(...)`, `.delete()`, `INSERT`/`UPDATE`/
  `DELETE`, `repo.Save`, `db.Create`.

Common primary-key-only access patterns that are BOLA-prone because they fetch
*by id alone* with **no owner predicate**:

- SQLAlchemy: `Model.query.get(id)`, `Model.query.filter_by(id=id)`
- Django ORM: `Model.objects.get(pk=id)`
- Sequelize: `Model.findByPk(id)`
- ActiveRecord: `Model.find(params[:id])`
- TypeORM/Prisma: `repo.findOne({ where: { id } })`, `prisma.x.findUnique({ where: { id } })`
- GORM: `db.First(&x, id)`

Record `file:line` of the sink — this is the location your finding will point
at, because it is the fix site.

## PASS 4 — Guard check, CROSS-FILE (the heart of it)

Between request entry and the object being returned/mutated, is access
**constrained to the current principal/tenant**? A correct handler enforces this
in at least one of these ways — look for each:

- **Query predicate**: the sink itself filters by owner, e.g.
  `filter_by(user_id=current_user.id, id=id)`, `where owner_id = ?`,
  `.scoped_to(current_user)`. The owner key (from PASS 0) appears in the
  WHERE clause alongside the id.
- **Post-fetch comparison**: fetch by id, then `if obj.owner_id !=
  current_user.id: deny`. Confirm the comparison *denies* (returns 403/404 /
  raises) and is not dead/fall-through.
- **Policy / guard call**: `authorize(obj)`, `policy(obj).show?`,
  `@PreAuthorize(...)`, `can?(:read, obj)`, a custom `assertOwner(obj, user)`.
  **Open the helper and read it.** A call named `authorize` that does nothing,
  or checks the wrong subject, is a fail-open.
- **Base-repository / default scope**: the repo or ORM base class injects a
  tenant/owner filter automatically (`default_scope`, a `ScopedRepository`,
  Hibernate `@Filter`). **Read the base class** to confirm the scope applies to
  this query and was not bypassed by a raw query.
- **Middleware**: an auth/tenant middleware sets context or rejects before the
  handler. **Read the middleware** and confirm it actually covers this route
  (mounting order, path prefix, not skipped by an allow-list).
- **DB row-level security**: a `CREATE POLICY` / `current_setting('app.user')`
  RLS rule enforces it at the database. Confirm the connection sets the session
  variable.

**The discipline rule (non-negotiable):** *resolve helpers and middleware by
reading them, not by name.* "I can't find a guard in this file" is **not a
finding** — it is an instruction to go read the call chain (the decorator stack,
the base repository, the middleware, the policy). A handler is only a candidate
finding when you have **actually read** the chain and the owner/role constraint
is provably absent across all of it.

## PASS 5 — Classify and disambiguate

For each handler where the guard is provably absent or broken, classify:

- **BOLA vs BFLA.** BOLA = *right endpoint, wrong object* (the caller may use
  this endpoint, but can reach an object that isn't theirs). BFLA = *wrong
  endpoint entirely* (the caller's role should not reach this function at all,
  e.g. a non-admin hitting an admin-only handler that lacks the role-gate its
  admin siblings have).
- **Horizontal vs vertical.** Horizontal = same privilege level, other user's
  object (classic BOLA). Vertical = privilege escalation across levels (often
  BFLA, or BOLA that crosses a role boundary).
- **Drop intentionally-public resources.** If PASS 0 / CONTEXT marks a resource
  public (a published article, a health check, a login endpoint), it is **not**
  a finding. Do not flag the absence of a guard on something meant to be open.

## PASS 6 — Rank by exploitability, then run the verification gate, then emit

Rank candidates so the most dangerous, most certain ones surface first:

- **mutation/delete > read** (changing/destroying others' data beats viewing).
- **sequential/guessable id > UUID** (enumerable ids are trivially exploited).
- **sensitive/regulated data** (credentials, PII, financial) raises severity.
- **id-from-body > id-from-path** (easier to tamper, often skips validation).

### Verification gate (skeptical self-refutation — run before EVERY emit)

For each candidate, before you call `add_finding`, answer honestly:

1. **What guard might I have missed?** Did I read the decorator stack, the
   middleware, the base repository/default scope, the policy helper, and any DB
   RLS — or did I stop at the handler file?
2. **Did I confirm the principal accessor matches?** Is the id compared against
   the *real* authenticated principal from PASS 0, or did I assume?
3. **Is this resource intentionally public?** (PASS 5 / CONTEXT)
4. **Is the "secure" sibling branch actually secure?** If the code has paired
   branches (e.g. a `vulnerable` toggle, or an `if/else`), the branch that
   scopes on the principal is **SAFE — do not flag it.** Flagging a correctly
   scoped branch is the canonical false positive.

**Default to NOT reporting if any guard chain is unresolved.** If you could not
finish reading a relevant middleware/policy/base-repo, do not emit a confident
finding — either resolve it or downgrade to an `info` hypothesis that names the
unresolved chain. Under-reporting a maybe beats flooding with false positives;
that is the entire reason this skill exists.

***

## Output contract — how to fill `add_finding`

Emit one `add_finding` call per confirmed issue, then call
`finalize_report(summary)` exactly once to write the report and end. The finding
ID is derived automatically from `rule_id` + the normalized `snippet`, so a fix
that adds the owner predicate changes the snippet and auto-resolves the finding
— make the snippet the *vulnerable line itself*.

Field-by-field:

- **`rule_id`** (required) — pick from this closed taxonomy:
  - `authz/bola-missing-owner-predicate` — read sink fetches an object by id
    with no owner/tenant predicate.
  - `authz/bola-mutation-unscoped` — write/update/delete sink mutates an object
    identified by request input without scoping to the principal.
  - `authz/bfla-missing-role-gate` — privileged function reachable without the
    role-gate its siblings enforce.
  - `authz/access-control-fail-open` — a guard exists but is ineffective
    (fail-open, wrong subject, client-trusted role, check-then-use mismatch).
  - `authz/bopla-mass-assignment-adjacent` — **info-only, adjacent (API3, not
    owned):** a request body binds a privileged/ownership **write** property the
    caller must not set (self-granting `admin`, setting `owner_id`). **Always
    `severity=info`.** Use THIS rule_id for every adjacent *write* mass-assignment
    so the label is deterministic across runs; note it for a future
    `object-property-audit` skill. **Scope guard:** reserve this rule_id strictly
    for attacker-controlled privileged *writes*. Excessive-data-exposure (a READ
    that over-serializes another principal's fields, e.g. dumping `password`) is
    **not** this finding and gets **no** `authz/*` rule_id — record it only in
    your out-of-lane notes.
- **`severity`** (required) — closed enum, by this rubric:
  - `critical` — **unscoped mutation/delete** of another principal's object
    (e.g. change anyone's password, delete anyone's record).
  - `high` — **read of sensitive owned data** belonging to another principal.
  - `medium` — a **weak or partial** check (present but bypassable, or guards
    only some methods).
  - `info` — **low-precision hypotheses** (race/TOCTOU, rate-limit, business
    flow) and **adjacent** BOPLA/mass-assignment observations (the latter
    always with `rule_id=authz/bopla-mass-assignment-adjacent`).
- **`file`** + **`line`** — point at the **data-access SINK** (the fix site),
  not the route declaration; use a **repo-relative path** (note the scan root
  once in the summary). This is where a reviewer adds the owner predicate.
- **`snippet`** (required) — the **vulnerable data-access line** verbatim (the
  stable-ID anchor). One line where possible.
- **`title`** — short, e.g. `BOLA: book lookup not scoped to owner`.
- **`description`** — carry the richness the flat struct can't: include the
  **route** (`GET /books/v1/{book_title}`), the **id-source**
  (`book_title from path parameter`), the **classification**
  (`BOLA, horizontal, read`), your **confidence** (`high — guard chain fully
  read; no owner predicate in query, no middleware covers this route`), and the
  **unresolved items** if any (`could not locate a base-repository scope`).
- **`remediation`** — concrete, e.g. `Add the owner predicate:
  Book.query.filter_by(user=current_user, book_title=book_title).first()`, or
  `Gate the handler with the same @require_admin used by sibling admin routes.`

When done, call `finalize_report` with a 1–3 sentence summary (how many routes
enumerated, how many confirmed findings by class, what you could not resolve).

***

## Self-test (maintainer validation)

A worked example with full ground truth against `erev0s/vampi` (Flask +
Connexion) ships in this bundle as `self-test-vampi.md`. It is a **validation
oracle for maintainers**, not analysis input.

- Load it with `read_skill_file("authz-audit", "self-test-vampi.md")` **only**
  when deliberately validating this skill against VAmPI.
- **Do NOT load it during a real audit.** It contains the answers; reading it
  would contaminate a genuine review (and any blind self-test). The skill must
  find bugs from the methodology above, not from a cheat sheet.

A maintainer validates by running the passes on VAmPI and confirming: both BOLA
endpoints found (recall), both secure branches left unflagged (precision), the
register self-grant emitted as `info`
(`authz/bopla-mass-assignment-adjacent`), and the SQLi left to `run_semgrep`.

# authz-audit self-test — VAmPI ground truth

> **Maintainer validation oracle. Not analysis input.** This file contains the
> answers for the VAmPI target. Load it (`read_skill_file("authz-audit",
> "self-test-vampi.md")`) only when validating the skill. Reading it during a
> real audit — or during a *blind* self-test — contaminates the result: the
> skill must find these bugs from the methodology, not from this cheat sheet.

Target: [`erev0s/vampi`](https://github.com/erev0s/VAmPI) (Flask + Connexion).
Its `vulnerable=1/0` toggle gives an aligned secure/vulnerable pair per
endpoint, so it exercises both **recall** (find the bugs) and **precision**
(leave the secure branches unflagged).

## Expected ground model (PASS 0)

- **Router = `openapi_specs/openapi3.yml`** — Connexion: the spec *is* the
  router, **no route decorators**. Enumerate from `paths:` → `operationId:`.
- **Principal accessor** = `resp = token_validator(request.headers.get('Authorization'))`;
  identity is `resp['sub']`.
- **No centralized authz helper** — only authentication. Raise the BOLA prior:
  each handler is individually responsible for scoping.
- Ownership lives on the `User` / `Book` models (`Book.user_id` FK).

## Recall — the skill MUST find these two

| Route → handler | Vulnerable sink | Expected finding |
|---|---|---|
| `GET /books/v1/{book_title}` → `books.get_by_title` | `Book.query.filter_by(book_title=book_title).first()` — no owner predicate, returns another user's `secret_content` | `rule_id=authz/bola-missing-owner-predicate`, `severity=high`; classification *BOLA, horizontal, read*; id-source path param |
| `PUT /users/v1/{username}/password` → `users.update_password` | `User.query.filter_by(username=username)` keyed on the **URL param**, not `resp['sub']` — changes any user's password | `rule_id=authz/bola-mutation-unscoped`, `severity=critical`; classification *BOLA, mutation, account takeover* |

## Precision — the skill MUST NOT flag these

- The secure `else:` branches that scope on the principal:
  `Book.query.filter_by(user=user, book_title=book_title)` and the password
  update keyed on `resp['sub']`. Flagging a correctly scoped branch is the
  **canonical false positive** (verification-gate question 4 exists to catch it).
- **Hard near-misses** (correctly judged SAFE):
  - `PUT /users/v1/{username}/email` → `update_email`: takes `{username}` but
    **both** branches key on `resp['sub']` — the path param is dead. Not BOLA.
  - `DELETE /users/v1/{username}` → `delete_user`: gated by `if user.admin:` —
    the role-gate is present. BFLA-secure.

## Adjacent — emit as `info`

- `POST /users/v1/register` → `users.register_user` self-grants `admin` because
  the schema lacks `additionalProperties: false`. Mass-assignment (API3), **not
  BOLA** → `rule_id=authz/bopla-mass-assignment-adjacent`, `severity=info`.

## Out of lane — delegate, do not emit

- `users.get_user` builds SQL with an f-string in `text(...)` → SQLi. Note
  "out of scope, `run_semgrep`" and do **not** emit it as an authz finding.
- Weak JWT signing key and ReDoS in the email regex — out-of-lane, note only.
- The unauthenticated `_debug` password dump is **excessive data exposure** (a
  *read* over-serialization, API3): record it in out-of-lane notes with **no**
  `authz/*` rule_id — it is **not** `authz/bopla-mass-assignment-adjacent`
  (that rule_id is for privileged *write* mass-assignment like the register
  self-grant), and **not** a BOLA/BFLA finding.

## Pass/fail criteria

A run **passes** when: both BOLA endpoints are found at the correct sink with
the correct `rule_id`/severity (recall); no secure branch and neither near-miss
is flagged (precision); the register self-grant is emitted as
`authz/bopla-mass-assignment-adjacent` `info`; and the SQLi is left to the
tools.

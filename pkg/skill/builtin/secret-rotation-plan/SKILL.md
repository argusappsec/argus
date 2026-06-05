---
name: secret-rotation-plan
description: Find committed secrets and draft a prioritised, step-by-step rotation plan saved to context.
tags: [secrets, gitleaks, remediation, incident]
---

# Secret Rotation Plan

When secrets have been committed to a repository, finding them is only half the
job — each one must be rotated, and rotation has an order and a blast radius.
This skill turns a `gitleaks` scan into an actionable, prioritised plan and
records it so the work survives the current session.

## Steps

1. **Scan for secrets.** Run `run_gitleaks` over the repository. It reports each
   finding with its rule, file, line, and a redacted snippet.

2. **Classify each finding.** For every secret, determine:
   - **Type** — cloud key, database password, OAuth/API token, private key, …
   - **Scope** — what it grants access to, and how widely.
   - **Exposure** — how long it has been in history, whether the repo is public,
     whether it appears in more than one place.
   Use `read_file` to inspect surrounding code where the snippet alone is
   ambiguous (e.g. to see which service a token talks to).

3. **Prioritise.** Order rotation by blast radius and exposure: production
   credentials and anything in a public repo first; low-scope or already-expired
   secrets last. A leaked production database password outranks a dev-only token.

4. **Draft the plan.** For each secret, write concrete steps: where to rotate it
   (which console / secret manager), what to update afterwards (env vars, CI
   secrets, deployments), how to invalidate the old value, and how to confirm
   nothing still depends on it. Remember that *rotating* a secret and *purging
   it from git history* are two separate tasks — note both.

5. **Persist the plan.** Save it with `write_context` (e.g. under a name like
   `secret-rotation-plan`) so it outlives this session and a teammate can pick
   it up. Use `read_context` / `list_context` first to check whether a prior
   plan already exists and should be updated rather than duplicated.

6. **Report.** Summarise the count and severity of findings, the rotation order,
   and where the full plan was saved.

## Notes

- Never print full secret values back to the user; keep them redacted, exactly
  as the scanner does.
- `gitleaks` scans the working tree the Session is pointed at — secrets that
  were force-pushed away but linger in forks or backups are out of its reach;
  say so when relevant.

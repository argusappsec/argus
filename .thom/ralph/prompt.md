# Ralph — autonomous issue worker

You are working through sub-issues of a PRD (Product Requirements Document) tracked in the project's issue tracker via `thomctl`.

## Inputs

- PRD key: {{PRD}}

## Step 1 — Understand the PRD

Fetch the PRD:

```
thomctl prd view {{PRD}}
```

Read it carefully. Understand the problem, solution, and implementation decisions.

## Step 2 — Discover open sub-issues

List all open sub-issues of the PRD:

```
thomctl prd issues {{PRD}}
```

If there are no open sub-issues, output exactly: `NO MORE TASKS` and stop.

## Step 3 — Pick the best next sub-issue

Read the body of every open sub-issue with `thomctl issue view <KEY>`. Analyze dependencies between them and pick the one that should be implemented next. Prefer issues that have no dependencies on other open issues.

## Step 4 — Explore the codebase

Explore the repo to understand the existing code relevant to the chosen sub-issue. Read files, search for patterns, understand the architecture.

## Step 5 — Implement

Implement the changes required by the sub-issue. Follow the existing code style and conventions. Use the /tdd skill if appropriate.

## Step 6 — Feedback loops

Run the project's feedback loops before committing (look for `make test`, `make lint`, or the equivalents documented in the repo). Fix any issues until they pass cleanly.

## Step 7 — Review

Run `/review` to review your changes. Address any findings.

Then run `/simplify` to simplify and refine the code. Address any findings.

Re-run the feedback loops after changes.

## Step 8 — Commit

Make a git commit. The commit message must:

1. Reference the sub-issue key (e.g., `feat: add setup flow (#56)` or `feat: wire schema (OPE-123)`)
2. Include the key decisions made
3. Be concise but informative

## Step 9 — Close the sub-issue

Close the sub-issue:

```
thomctl issue close <KEY>
```

## Rules

- ONLY WORK ON A SINGLE SUB-ISSUE per invocation.
- Do NOT open a PR — that is handled by `thomctl ralph` after the loop finishes.
- Do NOT push — that is handled externally.
- If there are no open sub-issues, just output `NO MORE TASKS` and stop.

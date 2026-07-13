# MCP channel

Argus exposes an MCP (Model Context Protocol) server so that *other* AI
tools — Claude Code, Claude Desktop, Cursor, your own agents — can consult it
as a **colleague, not a toolbox**. The external AI delegates a question or a
review; Argus runs its own org-aware loop with its own scanners and returns
the result. Your organization's knowledge (SOUL, MEMORY, context) never
leaves Argus.

## Setup

The channel is served on the HTTP front door at `/mcp`. Enable it and mint a
token:

```yaml
# argus.yaml
channels:
  mcp:
    type: mcp
```

```sh
argus user add alice
argus user mcp-token create alice    # prints the cleartext once, stores only its hash
```

Point your MCP client at the endpoint with the token as a bearer credential:

```
URL:            https://argus.your-company.example/mcp
Authorization:  Bearer <token>
```

Every call is attributed to the Person who owns the token (identity
`mcp:<token-hash>`), with their role and audit trail. Revoke anytime with
`argus user mcp-token revoke`.

## What's exposed

The surface is deliberately small — a few coarse capabilities, never the
low-level scanner tools:

- **`review`** — a security review. Two targets:
  - *snapshot*: the caller supplies the files to review;
  - *repo*: a `repo` + `ref` on a connected code host, which Argus checks
    out and reviews in full.
- **`consult`** — ask a question against the organization's knowledge
  (SOUL, curated context, recent findings).
- **Resources** — read-only org knowledge: SOUL, CONTEXT documents, recent
  reports.

## What it's *not*

Generic security Q&A ("what is path traversal?") is a non-goal — your AI
tool already answers that on its own. The MCP surface exists for what only
Argus can do: reviews with real scanners, grounded in your organization's
context and history.

---
title: Argus user guide
description: Install, configure and run Argus — the open-source application security agent that reviews code the way an analyst does.
sidebar:
  order: 0
---

Argus is an open-source **application security agent** that reviews code the way
an analyst does: it runs real scanners, reads their findings, weighs them against
your organization's context, and tells you in plain language what actually
matters. Then you argue back — Argus answers.

It runs as one long-lived daemon per organization, reached where your team
already works: a terminal chat, GitHub pull requests, and MCP from your own AI
tools.

These pages are task-oriented — how to install Argus, configure it, connect it,
and host it.

- [Getting started](/guide/getting-started/) — install, bootstrap, first chat
- [Configuration](/guide/configuration/) — the full `argus.yaml` reference
- [LLM providers](/guide/llm-providers/) — what Argus requires from a model, and how to verify yours
- [GitHub channel](/guide/channels/github/) — automatic pull-request reviews and talking to Argus on threads
- [MCP channel](/guide/channels/mcp/) — Argus as a consultable colleague for your AI tools
- [Skills](/guide/skills/) — using, writing, and overriding skills
- [Kubernetes deployment](/guide/deployment/kubernetes/) — hosting Argus on a cluster

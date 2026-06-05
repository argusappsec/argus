---
name: threat-modeling
description: Build a STRIDE threat model of a codebase from its structure and code, using the bundled template.
tags: [threat-model, stride, architecture, design]
---

# Threat Modeling (STRIDE)

Produce a structured threat model of the repository under review. The goal is
not to find every bug — the scanners do that — but to reason about *what could
go wrong by design*: where trust boundaries sit, what an attacker would target,
and which classes of threat each component is exposed to. STRIDE
(Spoofing, Tampering, Repudiation, Information disclosure, Denial of service,
Elevation of privilege) is the lens.

## Steps

1. **Load the template.** Call
   `read_skill_file("threat-modeling", "stride-template.md")` to fetch the
   STRIDE worksheet that structures the output. Fill it in as you work — do not
   reinvent the format inline.

2. **Map the system.** Use `list_files` and `read_file` to understand the
   architecture: entry points (HTTP handlers, CLIs, message consumers),
   external dependencies, data stores, and where untrusted input enters. Use
   `grep` to locate the boundaries quickly — route registrations, `main`
   functions, deserialization, auth checks.

3. **Identify trust boundaries.** Mark every place data crosses from a
   less-trusted zone to a more-trusted one (network → process, user → admin,
   tenant → tenant). These boundaries are where threats concentrate.

4. **Apply STRIDE per element.** For each component and boundary, walk the six
   STRIDE categories and ask whether that threat applies. Record the concrete
   scenario, not the abstract category — "an unauthenticated caller can replay
   the reset token" beats "Spoofing: yes".

5. **Rate and prioritise.** For each identified threat, note impact and
   likelihood, and whether an existing control mitigates it. Surface the
   unmitigated, high-impact threats first.

6. **Report.** Deliver the filled-in template: the system overview, the trust
   boundaries, the per-element STRIDE findings, and a prioritised list of the
   threats that most need a mitigation.

## Notes

- This is a *design-level* analysis. Pair it with `pr-quick-check` or the
  scanners for code-level findings; they answer different questions.
- A threat you cannot tie to a concrete component or data flow is usually too
  vague to act on — keep findings anchored to the code you read.

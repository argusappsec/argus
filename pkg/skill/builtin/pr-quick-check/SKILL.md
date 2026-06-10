---
name: pr-quick-check
description: Fast security pass over a pull request diff — scanners plus a targeted grep for risky patterns.
tags: [pr, review, quick, security]
---

# PR Quick Check

A fast, repeatable security pass over the changes under review. Use it when
someone asks for a quick read on a pull request or a set of local changes
before a deeper review. It favours signal over completeness: run the scanners,
skim for the usual footguns, report what matters.

## Steps

1. **Frame the change.** Use `list_files` and `read_file` to understand what
   the diff touches — which packages, which entry points, whether secrets,
   auth, or input handling are involved. Keep this lightweight; you are
   orienting, not auditing every line.

2. **Run the static scanners.**
   - `run_semgrep` for code-level vulnerability patterns (injection, unsafe
     deserialization, weak crypto, path traversal, …).
   - `run_gitleaks` for committed secrets — API keys, tokens, private keys.

3. **Grep for risky patterns the scanners miss.** Use `grep` to look for
   anything that warrants a human eye, for example:
   - `TODO|FIXME|HACK|XXX` near security-relevant code
   - `eval|exec|os/exec|subprocess` (command execution)
   - `password|secret|api[_-]?key|token` in source (hardcoded credentials)
   - `http://` URLs (cleartext transport)
   - disabled TLS verification (`InsecureSkipVerify`, `verify=False`)

4. **Triage.** For each finding, decide: is it introduced by this change, or
   pre-existing? Is it exploitable, or noise? Prefer reporting a handful of
   real issues over a long list of low-confidence hits.

5. **Report.** Summarise: a one-line verdict (safe to merge / needs changes /
   blocked), then the findings that drove it, each with file, line, severity,
   and a concrete fix. Note explicitly if a scanner could not run.

## Notes

- This is a *quick* check, not a full review. Call out where you stopped so the
  reader knows what was and was not covered.
- Every tool here is sandboxed to the repository under review; you cannot reach
  outside it, and you should not try.

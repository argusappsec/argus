---
title: SAST (Opengrep or Semgrep)
description: Pattern-based static analysis (SAST) for insecure code across many languages.
sidebar:
  order: 59
---

<!-- Generated from the Tool Catalog. Do not edit by hand: run `make docs`. -->

Pattern-based static analysis (SAST) for insecure code across many languages.

## Why install it

Opengrep and Semgrep match rules against the syntax of the code rather than its text, so they find injection, unsafe deserialization, weak cryptography and similar flaws in most mainstream languages without building the project. This is the baseline SAST pass of a review. Opengrep is an open-source fork of Semgrep that reads the same rules. Argus runs Opengrep when it is installed and Semgrep otherwise, with the same built-in ruleset, and the report says which one ran.

:::tip[Safe on untrusted input]
SAST (Opengrep or Semgrep) only reads files, so every review can run it, including automatic reviews of pull requests from outside your organization.
:::

## At a glance

| | |
| --- | --- |
| Finds | SAST |
| Reads | Any language |
| Trust level | Safe on untrusted input |
| Official image | Included |
| Licence | [LGPL-2.1-only](https://spdx.org/licenses/LGPL-2.1-only.html) |
| Argus tool | `run_sast` |

## Install

The official Argus container image already ships SAST (Opengrep or Semgrep). Anywhere else, install one of these binaries on the daemon host. Argus runs the first one listed that it finds:

- `opengrep`: `curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash`
- `semgrep`: `brew install semgrep  (or pip install semgrep)`

For other platforms, follow the [official install guide](https://github.com/opengrep/opengrep#installation). Argus looks for scanners once, when the daemon starts: restart it after installing, and `argus doctor` shows SAST (Opengrep or Semgrep) as installed.

## Learn more

- [Official documentation](https://github.com/opengrep/opengrep#readme)
- [Every scanner Argus can drive](/guide/scanners/)

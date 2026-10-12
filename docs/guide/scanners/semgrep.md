---
title: Semgrep
description: Pattern-based static analysis for insecure code across many languages.
sidebar:
  order: 59
---

<!-- Generated from the Tool Catalog. Do not edit by hand: run `make docs`. -->

Pattern-based static analysis for insecure code across many languages.

## Why install it

Semgrep matches rules against the syntax of the code rather than its text, so it finds injection, unsafe deserialization, weak cryptography and similar flaws in most mainstream languages without building the project. It is the baseline SAST pass of a review.

:::tip[Safe on untrusted input]
Semgrep only reads files, so every review can run it, including automatic reviews of pull requests from outside your organization.
:::

## At a glance

| | |
| --- | --- |
| Finds | SAST |
| Reads | Any language |
| Trust level | Safe on untrusted input |
| Official image | Included |
| Licence | [LGPL-2.1-only](https://spdx.org/licenses/LGPL-2.1-only.html) |
| Argus tool | `run_semgrep` |

## Install

The official Argus container image already ships Semgrep. Anywhere else, install this binary on the daemon host:

- `semgrep`: `brew install semgrep  (or pip install semgrep)`

For other platforms, follow the [official install guide](https://semgrep.dev/docs/getting-started/cli). Argus looks for scanners once, when the daemon starts: restart it after installing, and `argus doctor` shows Semgrep as installed.

## Learn more

- [Official documentation](https://semgrep.dev/docs/)
- [Every scanner Argus can drive](/guide/scanners/)

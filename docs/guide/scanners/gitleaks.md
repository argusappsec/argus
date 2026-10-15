---
title: Gitleaks
description: "Detects secrets committed to a repository: API keys, tokens, passwords and private keys."
sidebar:
  order: 56
---

<!-- Generated from the Tool Catalog. Do not edit by hand: run `make docs`. -->

Detects secrets committed to a repository: API keys, tokens, passwords and private keys.

## Why install it

A leaked credential is exploitable the moment it is pushed, whatever language the code is in. Gitleaks recognises hundreds of credential formats and high-entropy strings, so a review catches the secret before it reaches a public branch.

:::tip[Safe on untrusted input]
Gitleaks only reads files, so every review can run it, including automatic reviews of pull requests from outside your organization.
:::

## At a glance

| | |
| --- | --- |
| Finds | Secrets |
| Reads | Any language |
| Trust level | Safe on untrusted input |
| Official image | Included |
| Licence | [MIT](https://spdx.org/licenses/MIT.html) |
| Argus tool | `run_gitleaks` |

## Install

The official Argus container image already ships Gitleaks. Anywhere else, install this binary on the daemon host:

- `gitleaks`: `brew install gitleaks`

For other platforms, follow the [official install guide](https://github.com/gitleaks/gitleaks#installing). Argus looks for scanners once, when the daemon starts: restart it after installing, and `argus doctor` shows Gitleaks as installed.

## Learn more

- [Official documentation](https://github.com/gitleaks/gitleaks#readme)
- [Every scanner Argus can drive](/guide/scanners/)

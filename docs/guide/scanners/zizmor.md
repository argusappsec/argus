---
title: zizmor
description: Audits GitHub Actions workflows for template injection, dangerous triggers, over-broad permissions and unpinned actions.
sidebar:
  order: 61
---

<!-- Generated from the Tool Catalog. Do not edit by hand: run `make docs`. -->

Audits GitHub Actions workflows for template injection, dangerous triggers, over-broad permissions and unpinned actions.

## Why install it

A workflow runs with the repository's secrets and a token that can write to it, and a pull request can change the workflow itself. zizmor knows how GitHub Actions expands expressions and which triggers run untrusted code with privileges, so a review catches the injectable `run:` step or the `pull_request_target` job before it merges. It also checks Dependabot and pre-commit config.

:::tip[Safe on untrusted input]
zizmor only reads files, so every review can run it, including automatic reviews of pull requests from outside your organization.
:::

## At a glance

| | |
| --- | --- |
| Finds | CI/CD |
| Reads | GitHub Actions |
| Trust level | Safe on untrusted input |
| Official image | Included |
| Licence | [MIT](https://spdx.org/licenses/MIT.html) |
| Argus tool | `run_zizmor` |

## Install

The official Argus container image already ships zizmor. Anywhere else, install this binary on the daemon host:

- `zizmor`: `brew install zizmor  (or pipx install zizmor)`

For other platforms, follow the [official install guide](https://docs.zizmor.sh/installation/). Argus looks for scanners once, when the daemon starts: restart it after installing, and `argus doctor` shows zizmor as installed.

## Learn more

- [Official documentation](https://docs.zizmor.sh/)
- [Every scanner Argus can drive](/guide/scanners/)

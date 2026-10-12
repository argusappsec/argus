---
title: OSV-Scanner
description: Finds dependencies with known vulnerabilities by reading lockfiles and manifests.
sidebar:
  order: 59
---

<!-- Generated from the Tool Catalog. Do not edit by hand: run `make docs`. -->

Finds dependencies with known vulnerabilities by reading lockfiles and manifests.

## Why install it

Most exploitable flaws in an application live in its dependencies. OSV-Scanner reads the lockfiles of every major ecosystem and matches them against the OSV database, so a review reports a vulnerable version the moment a change introduces it.

:::tip[Safe on untrusted input]
OSV-Scanner only reads files, so every review can run it, including automatic reviews of pull requests from outside your organization.
:::

## At a glance

| | |
| --- | --- |
| Finds | Dependencies |
| Reads | Any language |
| Trust level | Safe on untrusted input |
| Official image | Included |
| Licence | [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) |
| Argus tool | `run_osv_scanner` |

## Install

The official Argus container image already ships OSV-Scanner. Anywhere else, install this binary on the daemon host:

- `osv-scanner`: `brew install osv-scanner  (or go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest)`

For other platforms, follow the [official install guide](https://google.github.io/osv-scanner/installation/). Argus looks for scanners once, when the daemon starts: restart it after installing, and `argus doctor` shows OSV-Scanner as installed.

## Learn more

- [Official documentation](https://google.github.io/osv-scanner/)
- [Every scanner Argus can drive](/guide/scanners/)

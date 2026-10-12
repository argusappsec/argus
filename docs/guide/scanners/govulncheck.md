---
title: govulncheck
description: "Known vulnerabilities in a Go module's dependencies, with the call path that reaches them."
sidebar:
  order: 58
---

<!-- Generated from the Tool Catalog. Do not edit by hand: run `make docs`. -->

Known vulnerabilities in a Go module's dependencies, with the call path that reaches them.

## Why install it

govulncheck checks a Go module against the Go vulnerability database and then follows the code's call graph, so it can tell a vulnerable dependency the code actually calls from one that only sits in go.mod, and it shows the call path from your function down to the vulnerable one. It overlaps with osv-scanner: when go is installed, osv-scanner runs the same call analysis (it is built on govulncheck's library) to tell reachable Go vulnerabilities from unreachable ones, in reviews you ask for. What govulncheck adds is the call trace, which explains why a vulnerability is reachable and is what a reviewer needs to judge it. Install it if you write Go and want that explanation; osv-scanner's verdict alone may be enough otherwise.

:::caution[Drives a toolchain]
govulncheck runs a toolchain or package manager over the code under review, which loads or builds that code. Automatic reviews never run it; reviews you ask for, and calls over MCP, do.
:::

## At a glance

| | |
| --- | --- |
| Finds | Dependencies |
| Reads | Go |
| Trust level | Drives a toolchain |
| Official image | Not included |
| Licence | [BSD-3-Clause](https://spdx.org/licenses/BSD-3-Clause.html) |
| Argus tool | `run_govulncheck` |

## Install

The official Argus container image does not ship govulncheck: add it by [building your own image](/guide/deployment/official-image/#build-your-own-image) on top of the official one, or install every one of these binaries on the daemon host:

- `go`: `brew install go  (or see https://go.dev/doc/install)`
- `govulncheck`: `go install golang.org/x/vuln/cmd/govulncheck@latest`

For other platforms, follow the [official install guide](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck). Argus looks for scanners once, when the daemon starts: restart it after installing, and `argus doctor` shows govulncheck as installed.

## Learn more

- [Official documentation](https://go.dev/doc/tutorial/govulncheck)
- [Every scanner Argus can drive](/guide/scanners/)

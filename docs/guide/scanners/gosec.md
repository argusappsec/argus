---
title: gosec
description: Go security analysis with type information and taint tracking.
sidebar:
  order: 57
---

<!-- Generated from the Tool Catalog. Do not edit by hand: run `make docs`. -->

Go security analysis with type information and taint tracking.

## Why install it

gosec understands Go's types, so it follows untrusted input into SQL queries, shell commands, file paths and outgoing requests, and flags weak cryptography and unsafe defaults that pattern matching alone misses. For an organization that writes Go it is the deepest SAST pass Argus can run.

:::caution[Drives a toolchain]
gosec runs a toolchain or package manager over the code under review, which loads or builds that code. Automatic reviews never run it; reviews you ask for, and calls over MCP, do.
:::

## At a glance

| | |
| --- | --- |
| Finds | SAST |
| Reads | Go |
| Trust level | Drives a toolchain |
| Official image | Not included |
| Licence | [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) |
| Argus tool | `run_gosec` |

## Install

The official Argus container image does not ship gosec. Install every one of these binaries on the daemon host:

- `go`: `brew install go  (or see https://go.dev/doc/install)`
- `gosec`: `go install github.com/securego/gosec/v2/cmd/gosec@latest  (or brew install gosec)`

For other platforms, follow the [official install guide](https://github.com/securego/gosec#local-installation). Argus looks for scanners once, when the daemon starts: restart it after installing, and `argus doctor` shows gosec as installed.

## Learn more

- [Official documentation](https://github.com/securego/gosec#readme)
- [Every scanner Argus can drive](/guide/scanners/)

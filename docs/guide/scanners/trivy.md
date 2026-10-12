---
title: Trivy
description: Finds insecure settings in Terraform, Kubernetes manifests, Helm charts and Dockerfiles.
sidebar:
  order: 61
---

<!-- Generated from the Tool Catalog. Do not edit by hand: run `make docs`. -->

Finds insecure settings in Terraform, Kubernetes manifests, Helm charts and Dockerfiles.

## Why install it

Infrastructure code decides who can reach a service and with which privileges: a security group open to the internet, a privileged container or an image that runs as root ships the weakness as surely as a code bug. Trivy checks Terraform, Kubernetes manifests, Helm charts and Dockerfiles against hundreds of built-in rules in one binary, covering what tfsec, hadolint and kube-linter each cover in part. Argus runs only its misconfiguration scanners, offline, with the checks built into the binary, and never lets it fetch the remote Terraform modules a pull request names. Trivy obeys `trivy:ignore` comments in Terraform, Helm charts and Dockerfiles and cannot be told not to, so Argus reports every such comment as a suppression attempt, with the check it names and where it sits.

:::tip[Safe on untrusted input]
Trivy only reads files, so every review can run it, including automatic reviews of pull requests from outside your organization.
:::

## At a glance

| | |
| --- | --- |
| Finds | IaC misconfiguration |
| Reads | Terraform, Kubernetes, Dockerfile |
| Trust level | Safe on untrusted input |
| Official image | Included |
| Licence | [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) |
| Argus tool | `run_trivy` |

## Install

The official Argus container image already ships Trivy. Anywhere else, install this binary on the daemon host:

- `trivy`: `brew install trivy`

For other platforms, follow the [official install guide](https://trivy.dev/docs/latest/getting-started/installation/). Argus looks for scanners once, when the daemon starts: restart it after installing, and `argus doctor` shows Trivy as installed.

## Learn more

- [Official documentation](https://trivy.dev/docs/latest/)
- [Every scanner Argus can drive](/guide/scanners/)

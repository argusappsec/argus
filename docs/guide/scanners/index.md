---
title: Scanners
description: Every scanner Argus can drive, what each one finds, and which to install for your stack.
sidebar:
  order: 55
---

<!-- Generated from the Tool Catalog. Do not edit by hand: run `make docs`. -->

Argus does not scan code by itself: it drives real scanners and reasons over
what they find. These pages list every scanner Argus knows how to drive, what
each one is for, and how to install it.

Argus offers a scanner to reviews only when every binary it needs is on `PATH`
when the daemon starts. Install the ones that fit your stack on the daemon host,
then restart Argus. The startup log and `argus doctor` list each scanner as
installed or not installed, and link a missing one to its page here.

## Recommendations

- **Every repository:** [Gitleaks](/guide/scanners/gitleaks/), [OSV-Scanner](/guide/scanners/osv-scanner/), [SAST (Opengrep or Semgrep)](/guide/scanners/sast/)
- **You write Go:** [gosec](/guide/scanners/gosec/), [govulncheck](/guide/scanners/govulncheck/)
- **You build container images:** [Trivy](/guide/scanners/trivy/)
- **You manage infrastructure with Terraform:** [Trivy](/guide/scanners/trivy/)
- **You deploy to Kubernetes:** [Trivy](/guide/scanners/trivy/)

## All scanners

| Scanner | Finds | Reads | Trust level | Official image |
| --- | --- | --- | --- | --- |
| [Gitleaks](/guide/scanners/gitleaks/) | Secrets | Any language | Safe on untrusted input | Included |
| [gosec](/guide/scanners/gosec/) | SAST | Go | Drives a toolchain | Not included |
| [govulncheck](/guide/scanners/govulncheck/) | Dependencies | Go | Drives a toolchain | Not included |
| [OSV-Scanner](/guide/scanners/osv-scanner/) | Dependencies | Any language | Safe on untrusted input | Included |
| [SAST (Opengrep or Semgrep)](/guide/scanners/sast/) | SAST | Any language | Safe on untrusted input | Included |
| [Trivy](/guide/scanners/trivy/) | IaC misconfiguration | Terraform, Kubernetes, Dockerfile | Safe on untrusted input | Included |

## Trust levels

A review can be about code nobody has vetted yet: a pull request from outside
your organization, opened on purpose to attack whatever reviews it. Every
scanner declares how safe it is to run over that code.

- **Safe on untrusted input:** the scanner only reads files. Every review can
  run it.
- **Drives a toolchain:** the scanner runs a toolchain or package manager over
  the code under review, which loads or builds that code. Automatic reviews
  never run it; reviews you ask for, and calls over MCP, do.

Whatever its trust level, Argus runs every scanner outside the checkout, with a
minimal environment, and ignores any configuration or suppression file the
repository carries. A finding the code marks as suppressed is still reported,
marked as such: a pull request cannot silence its own findings unseen.

## Official image

Scanners marked **Included** ship in the official Argus container image, which
guarantees they are installed. Any other scanner is yours to add: install it on
the daemon host, or build your own image on top of the official one.

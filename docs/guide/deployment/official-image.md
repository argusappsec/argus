---
title: The official image
description: What the official Argus container image ships and why, how it guarantees it, and how to build your own image on top of it.
sidebar:
  order: 59
---

The official Argus container image, `ghcr.io/argusappsec/argus`, is the
supported way to run Argus anywhere containers run: a laptop, a VM, or a
[Kubernetes cluster](/guide/deployment/kubernetes/). This page explains what is
inside it and why, how a release proves it still ships what it promises, and
how to build your own image on top of it when your organization needs a scanner
the official one leaves out.

For the tags it is published under and a first `docker run`, see
[Getting started](/guide/getting-started/).

## What it ships: the Manifest

Argus does not scan code by itself: it drives real scanners and reasons over
what they find. The image ships a fixed, curated set of them, called the
**Manifest**, so that Argus is useful out of the box for most organizations
without anyone installing anything.

| Binary | Why it is there |
| --- | --- |
| `git` | Required. Argus clones the repositories it reviews. |
| `opengrep` | Pattern-based static analysis across most languages. Argus drives it as its [SAST scanner](/guide/scanners/sast/). |
| `gitleaks` | Finds committed secrets: keys, tokens, passwords. See [Gitleaks](/guide/scanners/gitleaks/). |
| `osv-scanner` | Finds dependencies with known vulnerabilities, in any ecosystem. See [OSV-Scanner](/guide/scanners/osv-scanner/). |
| `zizmor` | Audits GitHub Actions workflows for injection and privilege mistakes. See [zizmor](/guide/scanners/zizmor/). |
| `trivy` | Finds misconfigurations in Terraform, Kubernetes manifests, Helm charts and Dockerfiles. Only its misconfiguration scanners are used. See [Trivy](/guide/scanners/trivy/). |

Every binary is published for both `linux/amd64` and `linux/arm64`. The
[scanner catalog](/guide/scanners/) marks each scanner as **Included** or **Not
included** in the image, and each scanner's page says how to install it
yourself.

A scanner makes the Manifest only when it meets all of these:

- **It is useful to most organizations.** Secrets, vulnerable dependencies and
  common code flaws matter whatever your stack is. Language-specific scanners
  are left to the organizations that write that language.
- **It is safe on untrusted input.** Every scanner in the Manifest only reads
  files. None of them builds, installs or runs the code it scans, so all of
  them can run on an automatic review of a pull request nobody has vetted yet.
  Scanners that drive a toolchain, such as `gosec` with Go, are never in the
  Manifest.
- **Its licence is permissive or weak copyleft.** Redistributing the image, or
  an image built on top of it, raises no licence questions.

Each scanner is pinned to an exact release, either as the project's own
container image or as its release binary. A release binary must match a
recorded checksum, and a signed one, such as Opengrep's, must carry a signature
issued to that project's own release pipeline, so a tampered or swapped
download fails the build instead of reaching your cluster. Version bumps are
deliberate, reviewed changes, never a side effect of a rebuild.

The image runs as an unprivileged user, `nonroot` (uid and gid `65532`), keeps
its state under `/data/.argus`, and serves every channel on port `8080`.

:::note[What the base is, and why not to rely on it]
Today the image is built on a slim Debian base (glibc). The base is an
implementation detail: what the image promises is the Manifest, not whatever
else the base happens to carry, such as a Python runtime, a shell or a package
manager. Future releases may move to a smaller base. The recipe below only
copies files into the image, so it keeps working when the base changes.
:::

## How the image proves it: `argus doctor --binaries`

`argus doctor` checks that Argus's dependencies and configuration are ready. It
lists every scanner Argus knows about as installed or not installed, and a
scanner that is not installed is information, not a failure: you only install
the ones that fit your stack.

`argus doctor --binaries` is stricter and narrower. It checks only `git` and the
Manifest, treats every one of them as required, and exits with status `1` if
any is missing:

```sh
docker run --rm ghcr.io/argusappsec/argus:latest doctor --binaries
```

```text
  ✓  git           cloning repositories
  ✓  gitleaks      installed — run_gitleaks tool
  ✓  osv-scanner   installed — run_osv_scanner tool
  ✓  sast          installed — run_sast tool, running opengrep
  …
```

Every image Argus builds runs this check, on each architecture, before it is
published. A change to how the image is built cannot silently drop a scanner:
the release fails instead. When you upgrade, the Manifest you relied on is
still there.

## Build your own image

The official image deliberately leaves out scanners that only some
organizations need. To add one, build a small image `FROM` the official one.
The worked example below adds [gosec](/guide/scanners/gosec/), Go's
type-aware static analyser, together with the Go toolchain it needs.

### Why Go is not in the official image

gosec does not just read files. It loads the code under review through the Go
toolchain, which resolves and downloads the module's dependencies, so it
belongs to the scanners that drive a toolchain. Argus runs those only on
reviews you ask for and on calls over MCP, never on automatic pull-request
reviews. Shipping Go to everyone would also add several hundred megabytes for
organizations that do not write Go, and would pick a Go version for you. The Go
version matters: Argus never lets a review download a different toolchain, so
the Go in your image must be at least as new as the `go` line in the
`go.mod` files you review.

### The recipe

Save this as `Dockerfile`:

```dockerfile
# syntax=docker/dockerfile:1

# ---- pinned versions: bump them on purpose, in a reviewable commit ----
# The official Argus image to extend. Pin the release you run.
ARG ARGUS_IMAGE=ghcr.io/argusappsec/argus:latest
# The Go toolchain, from the official golang image pinned by digest.
ARG GO_IMAGE=golang:1.26.9@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89
ARG GOSEC_VERSION=v2.29.0

# ---- build gosec, checked against the Go checksum database ----
FROM ${GO_IMAGE} AS gosec
ARG GOSEC_VERSION
RUN CGO_ENABLED=0 GOTOOLCHAIN=local GOBIN=/out \
    go install github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}

FROM ${GO_IMAGE} AS go

# ---- the custom image: the official one, plus Go and gosec ----
FROM ${ARGUS_IMAGE}
COPY --from=go /usr/local/go /usr/local/go
COPY --from=gosec /out/gosec /usr/local/bin/gosec
ENV PATH=/usr/local/go/bin:${PATH}
```

Build it, for one architecture or both:

```sh
docker build -t my-argus .
docker buildx build --platform linux/amd64,linux/arm64 -t registry.example.com/my-argus:1 --push .
```

What each choice is for:

- **Everything is pinned.** The Argus release, the Go toolchain (by image
  digest, so the tag cannot be moved under you) and gosec are fixed versions in
  one block at the top. Replace `latest` with the exact Argus release you run,
  as you would for the official image. A rebuild produces the same image until
  you change a line there.
- **Every download is verified.** The Go toolchain comes from the official
  `golang` image, and its digest is checked when it is pulled. `go install`
  checks every module it fetches, gosec included, against Go's public checksum
  database, and fails the build on a mismatch. `GOTOOLCHAIN=local` stops the
  build from fetching a different Go than the one you pinned.
- **The build tools stay out of the image.** gosec is built in a separate stage
  and only its binary is copied in. `CGO_ENABLED=0` makes it a static binary
  that runs on whatever base the official image uses.
- **The image still runs as `nonroot`.** The recipe never switches user: it only
  copies files, which needs no root. Your image keeps uid `65532`, so the
  volume ownership and security settings you use for the official image apply
  unchanged.
- **Go is on `PATH`.** Argus finds scanners and the binaries they need on
  `PATH` when the daemon starts; gosec needs `go`.

:::caution[Keep Go and gosec in step]
gosec reads type information produced by the Go toolchain, and a gosec release
only understands the Go versions that existed when it was released. Paired
with a newer Go, gosec reports type errors for every package and silently
misses the findings that need type information, which are its best ones. Bump
Go and gosec together, to a Go version that the gosec release supports. The pair
above was tested together.
:::

:::tip[govulncheck in the same image]
[govulncheck](/guide/scanners/govulncheck/) needs the same Go toolchain. Add a
second `go install golang.org/x/vuln/cmd/govulncheck@<version>` line to the
`gosec` stage and copy `/out/govulncheck` into `/usr/local/bin/` as well.
:::

### Check that Argus sees gosec

Run `argus doctor` in your image. gosec is now listed as installed, next to the
scanners the official image ships:

```sh
docker run --rm my-argus doctor
```

```text
  ✓  git           cloning repositories
  ✓  gitleaks      installed — run_gitleaks tool
  ✓  gosec         installed — run_gosec tool
  ℹ  govulncheck   not installed, so run_govulncheck is not offered — …
  ✓  osv-scanner   installed — run_osv_scanner tool
  ✓  sast          installed — run_sast tool, running opengrep
  …
```

`argus doctor --binaries` still passes in your image, which tells you that you
kept the Manifest intact. It does not check gosec, because gosec is not part of
the Manifest. To make your own build fail when gosec goes missing, check the
`doctor` output in your pipeline:

```sh
docker run --rm my-argus doctor --binaries
docker run --rm my-argus doctor | grep -E '✓ +gosec '
```

Argus looks for scanners once, when the daemon starts, so deploy the new image
by restarting the daemon on it. On Kubernetes, point the StatefulSet's `image:`
at your image; nothing else in the [Kubernetes deployment](/guide/deployment/kubernetes/)
changes.

:::note[What gosec needs at review time]
To load the code it reviews, the Go toolchain downloads that module's
dependencies. Argus allows it to use only the public Go module proxy,
`proxy.golang.org`, verified against `sum.golang.org`, and never fetches from a
repository host directly. The daemon therefore needs outbound access to both.
A module without a `go.sum` file cannot have its dependencies downloaded, and
those load errors come back in gosec's results. Modules that are only available
from a private proxy are not supported yet.
:::

The same pattern adds any other scanner from the [catalog](/guide/scanners/):
fetch a pinned, verified binary in a build stage, copy it into the official
image, and confirm with `argus doctor` that Argus sees it.

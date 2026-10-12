# syntax=docker/dockerfile:1

# ---- pinned third-party versions (the Manifest, ADR 0013 and ADR 0027) ----
# The image ships the Manifest: the catalogued scanners whose Catalog Entry
# says `Manifest: true`, plus git. Each is pinned exactly here, and every
# download is integrity-checked before it reaches the runtime stage. Bumps are
# manual, reviewable commits; the image changelog is the git log.
#
# Adding a scanner to the image is three edits: its version (and checksum or
# digest) in this block, one fetch-and-verify stage below, and one COPY into the
# runtime stage. Then set `Manifest: true` on its Catalog Entry, so
# `argus doctor --binaries` owes it and CI fails if the image drops it.
ARG PYTHON_VERSION=3.13
ARG GITLEAKS_VERSION=v8.30.1
ARG OSV_SCANNER_VERSION=v2.6.0

# opengrep (the SAST engine) is a release binary. Its sha256 per architecture
# pins the exact bytes; a version bump must update both checksums or the
# build fails. The signature is checked as well (see the opengrep stage).
ARG OPENGREP_VERSION=v1.30.1
ARG OPENGREP_SHA256_AMD64=d3195b9d8d5ae93179f6aa5f5daaba6a920a5a09d38c5d5ae5e60924050210c4
ARG OPENGREP_SHA256_ARM64=a730f6fdce1e978ea29e610a2e0503bfe1ec31fce08979a9a84e3699f03e16ee

# trivy (misconfiguration only) is a release archive. Its release pipeline was
# compromised in March 2026 (GHSA-69fq-xp46-6x23: a malicious v0.69.4 and
# rogue v0.69.5/v0.69.6 images), so the bytes are pinned by their sha256 digest
# per architecture and the Sigstore signature is verified (see the trivy
# stage). v0.75.0 is an immutable GitHub release published 2026-10-01, after
# the incident, and carries the fixes for every advisory trivy has published
# since (latest: GHSA-8rc5-4fr6-64pw, fixed in v0.72.0).
ARG TRIVY_VERSION=0.75.0
ARG TRIVY_SHA256_AMD64=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
ARG TRIVY_SHA256_ARM64=a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3

# cosign verifies keyless (Sigstore) signatures on release binaries. It only
# runs at build time and is not in the runtime image. Pinned by digest.
ARG COSIGN_IMAGE=ghcr.io/sigstore/cosign/cosign:v2.6.5@sha256:ad281047f85c5e1fc6ffbc30c2b55be3b07b4032bef715a12122ce5829619aca

# ---- scanner binary sources ----
# gitleaks and osv-scanner are static Go binaries; copy them straight from
# their official images pinned by tag rather than fetching release archives.
FROM ghcr.io/gitleaks/gitleaks:${GITLEAKS_VERSION} AS gitleaks
FROM ghcr.io/google/osv-scanner:${OSV_SCANNER_VERSION} AS osv-scanner
FROM ${COSIGN_IMAGE} AS cosign

# opengrep publishes one glibc (manylinux) binary per architecture, each with a
# Sigstore signature and certificate, and no checksum file. The download is
# pinned by the checksum above (ADD fails on a mismatch); one stage per
# architecture because each has its own asset name and checksum.
FROM scratch AS opengrep-download-amd64
ARG OPENGREP_VERSION
ARG OPENGREP_SHA256_AMD64
ADD --checksum=sha256:${OPENGREP_SHA256_AMD64} \
    https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_x86 /opengrep
ADD https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_x86.sig /opengrep.sig
ADD https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_x86.cert /opengrep.cert

FROM scratch AS opengrep-download-arm64
ARG OPENGREP_VERSION
ARG OPENGREP_SHA256_ARM64
ADD --checksum=sha256:${OPENGREP_SHA256_ARM64} \
    https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_aarch64 /opengrep
ADD https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_aarch64.sig /opengrep.sig
ADD https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_aarch64.cert /opengrep.cert

FROM opengrep-download-${TARGETARCH} AS opengrep-download

# Verify the signature: the certificate must have been issued to opengrep's
# own release workflow, on the release branch of exactly this version.
# Verification reaches Sigstore's public trust root and transparency log, so
# it needs the network at build time, like the downloads themselves.
FROM golang:1.26 AS opengrep
ARG OPENGREP_VERSION
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign
COPY --from=opengrep-download / /opengrep/
RUN cosign verify-blob \
        --certificate /opengrep/opengrep.cert \
        --signature /opengrep/opengrep.sig \
        --certificate-identity "https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/release-${OPENGREP_VERSION}" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        /opengrep/opengrep \
    && chmod 0755 /opengrep/opengrep

# trivy publishes one archive per architecture, each with a Sigstore bundle
# (signature, certificate and transparency-log entry in one file). The
# archive is pinned by the digest above (ADD fails on a mismatch).
FROM scratch AS trivy-download-amd64
ARG TRIVY_VERSION
ARG TRIVY_SHA256_AMD64
ADD --checksum=sha256:${TRIVY_SHA256_AMD64} \
    https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz /trivy.tar.gz
ADD https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz.sigstore.json /trivy.tar.gz.sigstore.json

FROM scratch AS trivy-download-arm64
ARG TRIVY_VERSION
ARG TRIVY_SHA256_ARM64
ADD --checksum=sha256:${TRIVY_SHA256_ARM64} \
    https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz /trivy.tar.gz
ADD https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz.sigstore.json /trivy.tar.gz.sigstore.json

FROM trivy-download-${TARGETARCH} AS trivy-download

# Verify the signature before unpacking: the certificate must have been issued
# to trivy's own release workflow, for exactly this version's tag. Then take
# the one static binary out of the archive. Its misconfiguration checks are
# embedded in it, so nothing else is needed offline.
FROM golang:1.26 AS trivy
ARG TRIVY_VERSION
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign
COPY --from=trivy-download / /trivy/
RUN cosign verify-blob \
        --bundle /trivy/trivy.tar.gz.sigstore.json \
        --new-bundle-format \
        --certificate-identity "https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v${TRIVY_VERSION}" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        /trivy/trivy.tar.gz \
    && tar -xzf /trivy/trivy.tar.gz -C /trivy trivy \
    && chmod 0755 /trivy/trivy

# ---- build stage ----
FROM golang:1.26 AS build
WORKDIR /src

# Download modules first so they cache independently of the source tree.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
# CGO_ENABLED=0 → a fully static argus binary that runs anywhere on the base.
# -trimpath strips local paths; -s -w drops debug info to shrink the binary.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/argus .

# ---- runtime stage ----
# Debian-based python:*-slim (glibc). opengrep's release binary is built for
# glibc (manylinux). Python itself is no longer needed by any Manifest tool;
# dropping it for a smaller base is tracked separately.
FROM python:${PYTHON_VERSION}-slim

# git (a required dependency — cloning repositories) via apt. Every binary
# the Manifest promises lives on the PATH, so `argus doctor --binaries`
# reports a healthy toolchain inside the image (the CI image-contract gate).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=opengrep /opengrep/opengrep /usr/local/bin/opengrep
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=osv-scanner /osv-scanner /usr/local/bin/osv-scanner
COPY --from=trivy /trivy/trivy /usr/local/bin/trivy
COPY --from=build /out/argus /usr/local/bin/argus

# Recreate the distroless `nonroot` uid (65532) so the
# `securityContext.fsGroup: 65532` guidance in ADR 0012 and the hosting guide
# keeps working with no manifest changes. /data is owned by nonroot so the
# daemon (and `argus doctor`) can write ARGUS_HOME with no mounted volume —
# the anonymous VOLUME below inherits this ownership for plain `docker run`.
RUN groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --create-home --home-dir /home/nonroot nonroot \
    && mkdir -p /data \
    && chown 65532:65532 /data

# State directory. On Kubernetes this is a PVC mounted at /data; ARGUS_HOME
# points the daemon at it. The image runs as nonroot (uid 65532), so mount
# the volume with `securityContext.fsGroup: 65532` to keep it writable.
ENV ARGUS_HOME=/data/.argus
VOLUME ["/data"]

# GitHub webhook channel (:8080) and MCP channel (:8090).
EXPOSE 8080 8090

USER 65532:65532
ENTRYPOINT ["argus"]
CMD ["daemon"]

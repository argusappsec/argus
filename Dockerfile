# syntax=docker/dockerfile:1

# ---- pinned third-party versions (batteries-included runtime, ADR 0013) ----
# Every tool Argus shells out to is carried in the image and pinned exactly.
# Bumps are manual, reviewable commits; the image changelog is the git log.
ARG PYTHON_VERSION=3.13
ARG SEMGREP_VERSION=1.168.0
ARG GITLEAKS_VERSION=v8.30.1
ARG OSV_SCANNER_VERSION=v2.4.0

# ---- scanner binary sources ----
# gitleaks and osv-scanner are static Go binaries; copy them straight from
# their official images pinned by tag rather than fetching release archives.
FROM ghcr.io/gitleaks/gitleaks:${GITLEAKS_VERSION} AS gitleaks
FROM ghcr.io/google/osv-scanner:${OSV_SCANNER_VERSION} AS osv-scanner

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
# Debian-based python:*-slim (glibc): semgrep is distributed only through
# Python channels and ships manylinux (glibc) wheels — no musl. See ADR 0013.
FROM python:${PYTHON_VERSION}-slim
ARG SEMGREP_VERSION

# git (a required dependency — cloning repositories) via apt; semgrep (SAST)
# via pip pinned exactly. gitleaks and osv-scanner are copied below. Every
# binary the Tools promise lives on the PATH, so `argus doctor --binaries`
# reports a healthy toolchain inside the image (the CI image-contract gate).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}"

COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=osv-scanner /osv-scanner /usr/local/bin/osv-scanner
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

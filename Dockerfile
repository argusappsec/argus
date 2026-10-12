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

# zizmor (GitHub Actions audits) is a release tarball per architecture, built
# by zizmor's own release workflow for glibc Linux. Its sha256 per architecture
# pins the exact bytes; a version bump must update both checksums or the build
# fails. Its signed build provenance is checked as well (see the zizmor stage).
ARG ZIZMOR_VERSION=v1.30.1
ARG ZIZMOR_SHA256_AMD64=e65324f4430c2717591937edcec90ccbefaf14c174f8ec9415e03ca875b46e1a
ARG ZIZMOR_SHA256_ARM64=7ff1dce33bdd18fd2a4affe63bdd47efcccca97b2cec1c1863ec26e9e2647540

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

# zizmor publishes no signature files next to its tarballs. Its release
# workflow records a GitHub artifact attestation instead: SLSA build provenance
# signed with Sigstore, which the GitHub API serves by the tarball's sha256.
# The download is pinned by the checksum above, and the attestation is fetched
# by the same checksum. One stage per architecture, as for opengrep.
FROM scratch AS zizmor-download-amd64
ARG ZIZMOR_VERSION
ARG ZIZMOR_SHA256_AMD64
ADD --checksum=sha256:${ZIZMOR_SHA256_AMD64} \
    https://github.com/zizmorcore/zizmor/releases/download/${ZIZMOR_VERSION}/zizmor-x86_64-unknown-linux-gnu.tar.gz /zizmor.tar.gz
ADD https://api.github.com/repos/zizmorcore/zizmor/attestations/sha256:${ZIZMOR_SHA256_AMD64} /attestations.json

FROM scratch AS zizmor-download-arm64
ARG ZIZMOR_VERSION
ARG ZIZMOR_SHA256_ARM64
ADD --checksum=sha256:${ZIZMOR_SHA256_ARM64} \
    https://github.com/zizmorcore/zizmor/releases/download/${ZIZMOR_VERSION}/zizmor-aarch64-unknown-linux-gnu.tar.gz /zizmor.tar.gz
ADD https://api.github.com/repos/zizmorcore/zizmor/attestations/sha256:${ZIZMOR_SHA256_ARM64} /attestations.json

FROM zizmor-download-${TARGETARCH} AS zizmor-download

# Verify the provenance: it must be signed for zizmor's own binary release
# workflow at exactly this version's tag, and name this tarball as what it
# built. The API returns every attestation for the digest; provenance.go picks
# out the SLSA provenance bundle for cosign. Then unpack the binary.
FROM golang:1.26 AS zizmor
ARG ZIZMOR_VERSION
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign
COPY --from=zizmor-download / /zizmor/
COPY <<'EOF' /zizmor/provenance.go
package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
)

// Reads the GitHub attestations API response on stdin and writes the SLSA
// provenance bundle to stdout; exits 1 when there is none.
func main() {
	var res struct {
		Attestations []struct{ Bundle json.RawMessage } `json:"attestations"`
	}
	if json.NewDecoder(os.Stdin).Decode(&res) != nil {
		os.Exit(1)
	}
	for _, a := range res.Attestations {
		var b struct{ DsseEnvelope struct{ Payload string } }
		_ = json.Unmarshal(a.Bundle, &b)
		payload, _ := base64.StdEncoding.DecodeString(b.DsseEnvelope.Payload)
		var st struct{ PredicateType string }
		if json.Unmarshal(payload, &st) == nil && st.PredicateType == "https://slsa.dev/provenance/v1" {
			_, _ = os.Stdout.Write(a.Bundle)
			return
		}
	}
	os.Exit(1)
}
EOF
WORKDIR /zizmor
RUN go run provenance.go < attestations.json > provenance.sigstore.json \
    && cosign verify-blob-attestation \
        --bundle provenance.sigstore.json \
        --new-bundle-format \
        --type slsaprovenance1 \
        --certificate-identity "https://github.com/zizmorcore/zizmor/.github/workflows/release-binaries.yml@refs/tags/${ZIZMOR_VERSION}" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        zizmor.tar.gz \
    && tar -xzf zizmor.tar.gz zizmor \
    && chmod 0755 zizmor

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
# glibc (manylinux), and so is zizmor's (glibc 2.34 or later, libgcc_s).
# Python itself is no longer needed by any Manifest tool;
# dropping it for a smaller base is tracked separately.
FROM python:${PYTHON_VERSION}-slim

# git (a required dependency — cloning repositories) via apt. Every binary
# the Manifest promises lives on the PATH, so `argus doctor --binaries`
# reports a healthy toolchain inside the image (the CI image-contract gate).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=opengrep /opengrep/opengrep /usr/local/bin/opengrep
COPY --from=zizmor /zizmor/zizmor /usr/local/bin/zizmor
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

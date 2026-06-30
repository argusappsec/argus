# syntax=docker/dockerfile:1

# ---- build stage ----
FROM golang:1.26 AS build
WORKDIR /src

# Download modules first so they cache independently of the source tree.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
# CGO_ENABLED=0 → a fully static binary that runs on a distroless/static base.
# -trimpath strips local paths; -s -w drops debug info to shrink the binary.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/argus .

# ---- runtime stage ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/argus /usr/local/bin/argus

# State directory. On Kubernetes this is a PVC mounted at /data; ARGUS_HOME
# points the daemon at it. The image runs as nonroot (uid 65532), so mount
# the volume with `securityContext.fsGroup: 65532` to keep it writable.
ENV ARGUS_HOME=/data/.argus
VOLUME ["/data"]

# GitHub webhook channel (:8080) and MCP channel (:8090).
EXPOSE 8080 8090

ENTRYPOINT ["argus"]
CMD ["daemon"]

# syntax=docker/dockerfile:1.7
#
# BoarNet sensor agent — multi-arch container image.
#
# Built by GitHub Actions on every tag push; pushed to
# ghcr.io/bino97/boarnet-sensor. Pure-Go build (modernc.org/sqlite, no
# cgo) so we can cross-compile for linux/amd64 + linux/arm64 from a
# single builder stage.

ARG GO_VERSION=1.23

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/boarnet ./cmd/boarnet

# Alpine runtime over distroless: we want a real uid/gid with a writable
# /data the sensor can use for its encrypted buffer + pepper key, plus
# ca-certificates for TLS to the ingest endpoint.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tini \
 && addgroup -S -g 1000 boarnet \
 && adduser -S -u 1000 -G boarnet -H -s /sbin/nologin boarnet \
 && mkdir -p /data \
 && chown -R boarnet:boarnet /data
COPY --from=builder /out/boarnet /usr/local/bin/boarnet

USER boarnet:boarnet
WORKDIR /data
VOLUME ["/data"]
EXPOSE 2222/tcp 8443/tcp

# Sensible defaults that the operator can override at `docker run`.
# --token and --ingest-url must be supplied; everything else sane.
ENV BOARNET_DATA_DIR=/data

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/boarnet"]
CMD ["--data-dir=/data", "--ssh-port=2222", "--tls-port=8443", "--fleet=mesh"]

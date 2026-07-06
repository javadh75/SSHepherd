# syntax=docker/dockerfile:1

# ---- build stage ------------------------------------------------------------
FROM golang:1.26-alpine AS build
WORKDIR /src

# Download modules first so this layer caches independently of source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
# Reproducible, fully static binary (CGO off) so it runs on a minimal base.
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/sshepherd ./cmd/sshepherd

# ---- runtime stage ----------------------------------------------------------
FROM alpine:3.24

# Essential tools only — TLS roots, the OpenSSH client family (ssh, ssh-keygen,
# ssh-keyscan), and tini as PID 1 for correct signal handling. Add nothing else.
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates openssh-client tini \
 && adduser -D -u 65532 sshepherd

COPY --from=build /out/sshepherd /usr/local/bin/sshepherd

USER 65532
ENTRYPOINT ["/sbin/tini", "--", "sshepherd"]

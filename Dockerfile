# syntax=docker/dockerfile:1

# ---- build stage ------------------------------------------------------------
# Base images are pinned by digest (tag kept for readability); Dependabot bumps both.
FROM golang:1.26.9-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS build
WORKDIR /src

# Build with the pinned image's Go — never silently download another toolchain
# because go.mod asks for a newer patch release; fail loudly instead.
ENV GOTOOLCHAIN=local

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
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

# Essential tools only — TLS roots, the OpenSSH client family (ssh, ssh-keygen,
# ssh-keyscan), and tini as PID 1 for correct signal handling. Add nothing else.
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates openssh-client tini \
 && adduser -D -u 65532 sshepherd

COPY --from=build /out/sshepherd /usr/local/bin/sshepherd

USER 65532
ENTRYPOINT ["/sbin/tini", "--", "sshepherd"]

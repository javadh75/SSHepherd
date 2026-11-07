# syntax=docker/dockerfile:1

# ---- build stage ------------------------------------------------------------
# Base images are pinned by digest (tag kept for readability); Dependabot bumps both.
FROM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS build
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
# Distroless static, nonroot variant: TLS roots, /etc/passwd with uid 65532
# ("nonroot", HOME /home/nonroot) and nothing else — no shell, no package
# manager, no ssh tools. sshepherd speaks SSH natively (golang.org/x/crypto/ssh)
# and needs none of them; run ssh-keygen/ssh-keyscan on the host. No init
# either: sshepherd handles SIGINT/SIGTERM itself, including as PID 1 (a second
# signal exits explicitly — see watchSignals in cmd/sshepherd/run.go).
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329

COPY --from=build /out/sshepherd /usr/local/bin/sshepherd

USER 65532
ENTRYPOINT ["/usr/local/bin/sshepherd"]

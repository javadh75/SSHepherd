# Integration-test sshd (busybox userland), built by scripts/integration.sh.
# OpenSSH is installed at build time so runs need no network; host keys are
# generated at container start, never in the image.
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN apk add --no-cache openssh

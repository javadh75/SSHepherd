# Integration-test sshd (busybox userland), built by scripts/integration.sh.
# OpenSSH is installed at build time so runs need no network; host keys are
# generated at container start, never in the image.
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache openssh

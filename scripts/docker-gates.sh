#!/usr/bin/env bash
# Runtime gates for a built image — shared by `make smoke` and CI so the two
# can never disagree: the binary runs (--version, --help), the image stays
# under the size budget, and it does not run as root.
set -euo pipefail

IMAGE="${IMAGE:?set IMAGE to the image to check}"
SIZE_BUDGET_MB="${SIZE_BUDGET_MB:-30}"

docker run --rm "$IMAGE" --version
docker run --rm "$IMAGE" --help >/dev/null
echo "ok: --version and --help run"

# Measure the unpacked root filesystem (export of a never-started container):
# `docker image inspect .Size` means different things under the classic and
# containerd image stores, so it can't back a portable budget.
cid=$(docker create "$IMAGE")
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
size=$(docker export "$cid" | wc -c | tr -d ' ')
budget=$((SIZE_BUDGET_MB * 1000 * 1000))
if [ "$size" -ge "$budget" ]; then
  echo "FAIL: image is $size bytes, over the ${SIZE_BUDGET_MB} MB budget" >&2
  exit 1
fi
echo "ok: image is $size bytes (budget ${SIZE_BUDGET_MB} MB)"

user=$(docker image inspect -f '{{.Config.User}}' "$IMAGE")
case "$user" in
  "" | root | 0 | root:* | 0:*)
    echo "FAIL: image runs as root (Config.User='$user')" >&2
    exit 1
    ;;
esac
echo "ok: image runs as non-root user '$user'"

# Signals as PID 1: the image has no init, so sshepherd is PID 1, where the
# kernel ignores default signal actions. Block it on an open, empty stdin
# (reading the manifest), then send two SIGTERMs: the first only cancels, the
# second must exit explicitly with 128+15 — within a few seconds, not after a
# SIGKILL timeout.
sig=$(docker run -d -i "$IMAGE" apply --dry-run --config /dev/stdin)
trap 'docker rm -f "$cid" "$sig" >/dev/null 2>&1 || true' EXIT
sleep 1
docker kill -s TERM "$sig" >/dev/null
sleep 1
docker kill -s TERM "$sig" >/dev/null
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [ "$(docker inspect -f '{{.State.Running}}' "$sig")" = false ] && break
  sleep 0.5
done
code=$(docker inspect -f '{{.State.ExitCode}}' "$sig")
if [ "$(docker inspect -f '{{.State.Running}}' "$sig")" != false ] || [ "$code" != 143 ]; then
  echo "FAIL: a second SIGTERM did not stop the container as PID 1 (running=$(docker inspect -f '{{.State.Running}}' "$sig"), exit=$code; want exit 143)" >&2
  exit 1
fi
echo "ok: a second SIGTERM stops sshepherd as PID 1 (exit 143)"

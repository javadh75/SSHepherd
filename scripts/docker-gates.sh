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

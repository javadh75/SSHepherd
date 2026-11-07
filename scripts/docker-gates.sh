#!/usr/bin/env bash
# Runtime gates for a built image, shared by `make smoke`, CI and the release
# workflow so they can never disagree: the binary is built for the image's
# platform, runs (--version, --help), the image stays under the size budget,
# does not run as root, and stops on a second SIGTERM as PID 1.
#
# Usage: docker-gates.sh [--platform OS/ARCH] [--pull] [IMAGE]
#   IMAGE defaults to $IMAGE. --platform picks one variant of a multi-arch
#   image (default: the daemon's own platform). --pull fetches that variant
#   first, for registry refs such as ghcr.io/javadh75/sshepherd@sha256:….
set -euo pipefail

platform="" pull=false
while [ $# -gt 0 ]; do
  case "$1" in
    --platform) platform="${2:?--platform needs OS/ARCH}"; shift 2 ;;
    --platform=*) platform="${1#--platform=}"; shift ;;
    --pull) pull=true; shift ;;
    -h | --help) sed -n '2,10p' "$0"; exit 0 ;;
    -*) echo "docker-gates.sh: unknown option $1" >&2; exit 2 ;;
    *) IMAGE="$1"; shift ;;
  esac
done
IMAGE="${IMAGE:?pass an image ref or set IMAGE}"
SIZE_BUDGET_MB="${SIZE_BUDGET_MB:-30}"
BIN=/usr/local/bin/sshepherd

native="linux/$(docker version -f '{{.Server.Arch}}')"
platform="${platform:-$native}"
plat=(--platform "$platform")
# An emulated (QEMU) variant starts slower: give the PID-1 gate more time.
settle=1 polls=10
if [ "$platform" != "$native" ]; then settle=5 polls=40; fi

cid="" sig=""
cleanup() {
  local ids=()
  if [ -n "$cid" ]; then ids+=("$cid"); fi
  if [ -n "$sig" ]; then ids+=("$sig"); fi
  if [ "${#ids[@]}" -gt 0 ]; then docker rm -f "${ids[@]}" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

if $pull; then docker pull -q "${plat[@]}" "$IMAGE" >/dev/null; fi

# Architecture first: with a cross-compiling Dockerfile, a lost GOARCH puts a
# build-host binary in a foreign-labelled image, and on a host of the binary's
# own arch it would still run. So read the ELF e_machine (offset 18; LE hosts)
# instead of trusting --version.
case "$platform" in
  linux/amd64) want=62 ;;  # EM_X86_64
  linux/arm64) want=183 ;; # EM_AARCH64
  *) echo "FAIL: no ELF machine known for platform $platform" >&2; exit 1 ;;
esac
cid=$(docker create "${plat[@]}" "$IMAGE")
got=$(docker cp "$cid:$BIN" - | tar -xOf - | { od -An -t u2 -j 18 -N 2; cat >/dev/null; } | tr -d ' ')
if [ "$got" != "$want" ]; then
  echo "FAIL: $BIN is ELF machine $got, want $want for $platform" >&2
  exit 1
fi
echo "ok: $BIN is built for $platform"

docker run --rm "${plat[@]}" "$IMAGE" --version
docker run --rm "${plat[@]}" "$IMAGE" --help >/dev/null
echo "ok: --version and --help run"

# Measure the unpacked root filesystem (export of a never-started container):
# `docker image inspect .Size` means different things under the classic and
# containerd image stores, so it can't back a portable budget.
size=$(docker export "$cid" | wc -c | tr -d ' ')
budget=$((SIZE_BUDGET_MB * 1000 * 1000))
if [ "$size" -ge "$budget" ]; then
  echo "FAIL: image is $size bytes, over the ${SIZE_BUDGET_MB} MB budget" >&2
  exit 1
fi
echo "ok: image is $size bytes (budget ${SIZE_BUDGET_MB} MB)"

# The container's config, not `image inspect`: unambiguous for one variant.
user=$(docker inspect -f '{{.Config.User}}' "$cid")
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
# second must exit explicitly with 128+15, within a few seconds and not after
# a SIGKILL timeout.
sig=$(docker run -d -i "${plat[@]}" "$IMAGE" apply --dry-run --config /dev/stdin)
sleep "$settle"
docker kill -s TERM "$sig" >/dev/null
sleep 1
docker kill -s TERM "$sig" >/dev/null
for _ in $(seq "$polls"); do
  [ "$(docker inspect -f '{{.State.Running}}' "$sig")" = false ] && break
  sleep 0.5
done
running=$(docker inspect -f '{{.State.Running}}' "$sig")
code=$(docker inspect -f '{{.State.ExitCode}}' "$sig")
if [ "$running" != false ] || [ "$code" != 143 ]; then
  echo "FAIL: a second SIGTERM did not stop the container as PID 1 (running=$running, exit=$code; want exit 143)" >&2
  exit 1
fi
echo "ok: a second SIGTERM stops sshepherd as PID 1 (exit 143)"

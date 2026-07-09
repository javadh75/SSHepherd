#!/usr/bin/env bash
# Spins up a throwaway sshd container, seeds keys, starts a dedicated
# ssh-agent, and runs the build-tagged integration tests against it.
set -euo pipefail

PORT="${SSHEPHERD_IT_PORT:-42222}"
CONTAINER=sshepherd-it
WORKDIR="$(mktemp -d)"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  [ -n "${SSH_AGENT_PID:-}" ] && kill "$SSH_AGENT_PID" >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N '' -f "$WORKDIR/id_ed25519"
chmod 644 "$WORKDIR/id_ed25519.pub"

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" \
  -p "127.0.0.1:$PORT:22" \
  -v "$WORKDIR/id_ed25519.pub:/seed/key.pub:ro" \
  alpine:3.24 sh -c '
    set -e
    apk add --no-cache openssh >/dev/null
    ssh-keygen -A
    for u in present absent; do
      adduser -D -s /bin/sh "$u"
      sed -i "s|^$u:!|$u:*|" /etc/shadow   # unlock for pubkey login
      mkdir -p "/home/$u/.ssh"
    done
    cp /seed/key.pub /home/present/.ssh/authorized_keys
    cp /seed/key.pub /home/absent/.ssh/authorized_keys2   # default file stays absent
    for u in present absent; do
      chown -R "$u:$u" "/home/$u/.ssh"
      chmod 700 "/home/$u/.ssh"
      chmod 600 "/home/$u/.ssh/"authorized_keys* 2>/dev/null || true
    done
    # Alpine ships an active "AuthorizedKeysFile .ssh/authorized_keys" line;
    # OpenSSH keeps the first occurrence of a directive, so appending a second
    # one is silently ignored. Replace it in place instead.
    sed -i "s|^AuthorizedKeysFile.*|AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2|" /etc/ssh/sshd_config
    exec /usr/sbin/sshd -D -e
  '

echo "waiting for sshd on 127.0.0.1:$PORT ..."
for _ in $(seq 1 60); do
  if ssh-keyscan -p "$PORT" 127.0.0.1 >"$WORKDIR/known_hosts" 2>/dev/null \
     && [ -s "$WORKDIR/known_hosts" ]; then
    break
  fi
  sleep 1
done
if [ ! -s "$WORKDIR/known_hosts" ]; then
  echo "sshd never came up; container logs:" >&2
  docker logs "$CONTAINER" >&2
  exit 1
fi

eval "$(ssh-agent -s)" >/dev/null
ssh-add "$WORKDIR/id_ed25519" 2>/dev/null

SSHEPHERD_IT_HOST=127.0.0.1 \
SSHEPHERD_IT_PORT="$PORT" \
SSHEPHERD_IT_KNOWN_HOSTS="$WORKDIR/known_hosts" \
  go test -race -tags=integration -run TestIntegration -v ./internal/sshread/

#!/usr/bin/env bash
# Spins up a throwaway sshd container, seeds keys, starts a dedicated
# ssh-agent, and runs the build-tagged integration tests against it.
set -euo pipefail

PORT="${SSHEPHERD_IT_PORT:-42222}"
CONTAINER=sshepherd-it
WORKDIR="$(mktemp -d)"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  # Kill only the agent WE started — never an agent inherited from the shell.
  [ -n "${OUR_AGENT_PID:-}" ] && kill "$OUR_AGENT_PID" >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N '' -f "$WORKDIR/id_ed25519"
chmod 644 "$WORKDIR/id_ed25519.pub"
ssh-keygen -q -t ed25519 -N '' -f "$WORKDIR/stale"
chmod 644 "$WORKDIR/stale.pub"

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" \
  -p "127.0.0.1:$PORT:22" \
  -v "$WORKDIR/id_ed25519.pub:/seed/key.pub:ro" \
  -v "$WORKDIR/stale.pub:/seed/stale.pub:ro" \
  alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 sh -c '
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
    for u in writer virgin sym e2e cas locked verifyfail drop lockout unparse; do
      adduser -D -s /bin/sh "$u"
      sed -i "s|^$u:!|$u:*|" /etc/shadow   # unlock for pubkey login
      mkdir -p "/home/$u/.ssh"
    done
    # cas/locked/verifyfail/drop/lockout: the agent key alone (write-path
    # refusal and failure cases); unparse: plus a line apply cannot parse.
    for u in cas locked verifyfail drop lockout; do
      cp /seed/key.pub "/home/$u/.ssh/authorized_keys"
    done
    { cat /seed/key.pub; echo "this line is not a key"; } > /home/unparse/.ssh/authorized_keys
    # writer + e2e: drifted seed (agent key + a stale key apply must remove).
    cat /seed/key.pub /seed/stale.pub > /home/writer/.ssh/authorized_keys
    cat /seed/key.pub /seed/stale.pub > /home/e2e/.ssh/authorized_keys
    # virgin: logs in via authorized_keys2; the default file stays absent
    # until apply creates it (first-contact case).
    cp /seed/key.pub /home/virgin/.ssh/authorized_keys2
    # sym: authorized_keys is a symlink — apply must refuse, sshd still reads
    # through it for login.
    cp /seed/key.pub /home/sym/.ssh/authorized_keys_real
    ln -s authorized_keys_real /home/sym/.ssh/authorized_keys
    for u in writer virgin sym e2e cas locked verifyfail drop lockout unparse; do
      chown -R "$u:$u" "/home/$u/.ssh"
      chmod 700 "/home/$u/.ssh"
      chmod 600 "/home/$u/.ssh/"authorized_keys* 2>/dev/null || true
    done
    # Alpine ships an active "AuthorizedKeysFile .ssh/authorized_keys" line;
    # OpenSSH keeps the first occurrence of a directive, so appending a second
    # one is silently ignored. Replace it in place instead — and fail loudly if
    # a future base image stops shipping the directive active.
    grep -q "^AuthorizedKeysFile" /etc/ssh/sshd_config || {
      echo "sshd_config has no active AuthorizedKeysFile line; fix the sed below" >&2
      exit 1
    }
    sed -i "s|^AuthorizedKeysFile.*|AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2|" /etc/ssh/sshd_config
    exec /usr/sbin/sshd -D -e
  '

echo "waiting for sshd on 127.0.0.1:$PORT ..."
# 180s: the container installs openssh from the network first (apk add), which
# alone can take >60s on a cold mirror; the old 60s window flaked locally.
for _ in $(seq 1 180); do
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
OUR_AGENT_PID="$SSH_AGENT_PID"
ssh-add "$WORKDIR/id_ed25519"

SSHEPHERD_IT_HOST=127.0.0.1 \
SSHEPHERD_IT_PORT="$PORT" \
SSHEPHERD_IT_KNOWN_HOSTS="$WORKDIR/known_hosts" \
SSHEPHERD_IT_PUB="$WORKDIR/id_ed25519.pub" \
  go test -race -tags=integration -run 'TestIntegration|TestE2E' -v \
  ./internal/sshread/ ./internal/sshwrite/ ./cmd/sshepherd/

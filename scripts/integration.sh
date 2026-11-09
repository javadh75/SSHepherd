#!/usr/bin/env bash
# Spins up two throwaway sshd containers from ci/images/sshd-<distro>.Dockerfile
# (A: the full fixture on the default AuthorizedKeysFile; B: one user whose
# sshd reads ~/.ssh/fleet_keys), seeds keys, starts a dedicated ssh-agent, and
# runs the build-tagged integration tests against them.
#
# Usage: scripts/integration.sh [alpine|debian|rocky]   (default: alpine, or
# $IT_DISTRO, which `make integration IT_DISTRO=…` exports)
#
# Every run gets unique container names (SSHEPHERD_IT_NAME, default
# sshepherd-it-<pid>) and Docker-picked ports (SSHEPHERD_IT_PORT pins A's), so
# parallel runs from several worktrees never collide.
set -euo pipefail

DISTRO="${1:-${IT_DISTRO:-alpine}}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
case "$DISTRO" in
  '' | *[!a-z0-9-]*) echo "invalid distro name: '$DISTRO'" >&2; exit 2 ;;
esac
DOCKERFILE="ci/images/sshd-$DISTRO.Dockerfile"
if [ ! -f "$DOCKERFILE" ]; then
  echo "unknown distro '$DISTRO': no $DOCKERFILE (have: $(cd ci/images && ls sshd-*.Dockerfile | sed 's/^sshd-//; s/\.Dockerfile$//' | tr '\n' ' '))" >&2
  exit 2
fi
IMAGE="sshepherd-it-sshd:$DISTRO"
RUN_ID="${SSHEPHERD_IT_NAME:-sshepherd-it-$$}"
CA="$RUN_ID-a"
CB="$RUN_ID-b"
WORKDIR="$(mktemp -d)"

cleanup() {
  docker rm -f "$CA" "$CB" >/dev/null 2>&1 || true
  # Kill only the agent WE started — never an agent inherited from the shell.
  [ -n "${OUR_AGENT_PID:-}" ] && kill "$OUR_AGENT_PID" >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "building $IMAGE from $DOCKERFILE ..."
docker build -q -t "$IMAGE" -f "$DOCKERFILE" ci/images >/dev/null

ssh-keygen -q -t ed25519 -N '' -f "$WORKDIR/id_ed25519"
chmod 644 "$WORKDIR/id_ed25519.pub"
ssh-keygen -q -t ed25519 -N '' -f "$WORKDIR/stale"
chmod 644 "$WORKDIR/stale.pub"
# Headless --identity keys (never added to the agent): ci_old unencrypted,
# ci_new and enc encrypted (passphrase files mode 0600, as the tool requires).
ssh-keygen -q -t ed25519 -N '' -f "$WORKDIR/ci_old"
ssh-keygen -q -t ed25519 -N 'ci-new-passphrase' -a 16 -f "$WORKDIR/ci_new"
ssh-keygen -q -t ed25519 -N 'enc-passphrase' -a 16 -f "$WORKDIR/enc"
printf '%s\n' 'ci-new-passphrase' >"$WORKDIR/ci_new.pass"
printf '%s\n' 'enc-passphrase' >"$WORKDIR/enc.pass"
chmod 600 "$WORKDIR/ci_new.pass" "$WORKDIR/enc.pass"
chmod 644 "$WORKDIR/ci_old.pub" "$WORKDIR/ci_new.pub" "$WORKDIR/enc.pub"

# Portable prelude for both containers (busybox, dash and bash as /bin/sh).
# Host keys are generated here, at container start, so A and B differ and
# per-host known_hosts is real.
PRELUDE='
    set -e
    mkuser() { if command -v useradd >/dev/null 2>&1; then useradd -m -s /bin/sh "$1"; else adduser -D -s /bin/sh "$1"; fi; unlock "$1"; }
    unlock() { sed -i "s|^$1:[^:]*:|$1:*:|" /etc/shadow; }   # !, !! and * all become * (pubkey login allowed)
    # Effective-config edit: OpenSSH keeps the FIRST occurrence and Debian/Rocky
    # Include sshd_config.d/*.conf at the top, so prepend, then prove with sshd -T.
    sshd_set() { { printf "%s\n" "$@"; cat /etc/ssh/sshd_config; } > /tmp/c && cat /tmp/c > /etc/ssh/sshd_config && rm -f /tmp/c; }
    sshd_expect() { sshd -T -C user=nobody,host=x,addr=127.0.0.1 | grep -Eqix "$1" || { echo "sshd -T lacks: $1" >&2; exit 1; }; }
    ssh-keygen -A
'

# Container A: every sshwrite/sshread/E2E fixture user, plus fleet (agent key
# + a stale key in ~/.ssh/authorized_keys) for the two-host fan-out E2E.
FIXTURE_A='
    for u in present absent; do
      mkuser "$u"
      mkdir -p "/home/$u/.ssh"
    done
    cp /seed/key.pub /home/present/.ssh/authorized_keys
    cp /seed/key.pub /home/absent/.ssh/authorized_keys2   # default file stays absent
    for u in present absent; do
      chown -R "$u:$u" "/home/$u/.ssh"
      chmod 700 "/home/$u/.ssh"
      chmod 600 "/home/$u/.ssh/"authorized_keys* 2>/dev/null || true
    done
    for u in writer virgin sym e2e cas locked verifyfail drop lockout unparse idaudit idenc rotate e2eh rotatecmd trima trimb overlap fdir ffile fanc rootvictim probecmd probefrom probeok fleet nra nrb stala stalb handed maxauth e2eroll loose e2eloose; do
      mkuser "$u"
      mkdir -p "/home/$u/.ssh"
    done
    # cas/locked/verifyfail/drop/lockout: the agent key alone (write-path
    # refusal and failure cases); trima/trimb/overlap: the agent key alone
    # (revoke --from-server and rotate --keep-old E2E); stala/stalb/handed: the
    # agent key alone (revocation-memory E2E); unparse: plus a line apply
    # cannot parse.
    for u in cas locked verifyfail drop lockout trima trimb overlap fdir ffile fanc probecmd probefrom probeok stala stalb handed maxauth loose e2eloose; do
      cp /seed/key.pub "/home/$u/.ssh/authorized_keys"
    done
    { cat /seed/key.pub; echo "this line is not a key"; } > /home/unparse/.ssh/authorized_keys
    # Headless --identity users: only key files log in here, never the agent key.
    cp /seed/ci_old.pub /home/idaudit/.ssh/authorized_keys
    cp /seed/enc.pub /home/idenc/.ssh/authorized_keys
    cp /seed/ci_old.pub /home/rotate/.ssh/authorized_keys
    cp /seed/ci_old.pub /home/rotatecmd/.ssh/authorized_keys
    cat /seed/ci_old.pub /seed/stale.pub > /home/e2eh/.ssh/authorized_keys
    # writer + e2e + fleet: drifted seed (agent key + a stale key apply must remove).
    cat /seed/key.pub /seed/stale.pub > /home/writer/.ssh/authorized_keys
    cat /seed/key.pub /seed/stale.pub > /home/e2e/.ssh/authorized_keys
    cat /seed/key.pub /seed/stale.pub > /home/fleet/.ssh/authorized_keys
    # nra/nrb: the agent key + the stale key, found by the opening adopt of
    # TestE2ERevokeNoResurrect (revocation-memory E2E).
    cat /seed/key.pub /seed/stale.pub > /home/nra/.ssh/authorized_keys
    cat /seed/key.pub /seed/stale.pub > /home/nrb/.ssh/authorized_keys
    # e2eroll: the agent key + the stale key the rollback E2E revokes.
    cat /seed/key.pub /seed/stale.pub > /home/e2eroll/.ssh/authorized_keys
    # virgin: logs in via authorized_keys2; the default file stays absent
    # until apply creates it (first-contact case).
    cp /seed/key.pub /home/virgin/.ssh/authorized_keys2
    # sym: authorized_keys is a symlink — apply must refuse, sshd still reads
    # through it for login.
    cp /seed/key.pub /home/sym/.ssh/authorized_keys_real
    ln -s authorized_keys_real /home/sym/.ssh/authorized_keys
    for u in writer virgin sym e2e cas locked verifyfail drop lockout unparse idaudit idenc rotate e2eh rotatecmd trima trimb overlap fdir ffile fanc rootvictim probecmd probefrom probeok fleet nra nrb stala stalb handed maxauth e2eroll loose e2eloose; do
      chown -R "$u:$u" "/home/$u/.ssh"
      chmod 700 "/home/$u/.ssh"
      chmod 600 "/home/$u/.ssh/"authorized_keys* 2>/dev/null || true
    done
    # loose: logs in through its 0700 ~/.ssh; the managed override sits below
    # a 0775 ~/loose (posture finding), which sshd never reads.
    # e2eloose: the same, for the E2E that tightens the mode and re-audits.
    for u in loose e2eloose; do
      mkdir -p "/home/$u/loose" && cp /seed/key.pub "/home/$u/loose/keys"
      chown -R "$u:$u" "/home/$u/loose" && chmod 775 "/home/$u/loose" && chmod 600 "/home/$u/loose/keys"
    done
    # Ownership-refusal fixtures (TST-1). StrictModes in sshd accepts each
    # one (root may own ~/.ssh or authorized_keys of a user), so the user
    # can still log in. The write script must refuse each one with exit 48.
    # fdir: ~/.ssh owned by root. Refused at the directory check (root not exempt).
    chown root:root /home/fdir/.ssh && chmod 755 /home/fdir/.ssh
    # ffile: authorized_keys owned by root. Refused at the file check under the lock.
    chown root:root /home/ffile/.ssh/authorized_keys && chmod 644 /home/ffile/.ssh/authorized_keys
    # fanc: an authorized_keys_file override below ~/shared, which nobody owns
    # (owner only: the group is nobody on Alpine/Rocky but nogroup on Debian).
    mkdir -p /home/fanc/shared/keys
    chown nobody /home/fanc/shared && chmod 755 /home/fanc/shared
    chown fanc:fanc /home/fanc/shared/keys && chmod 700 /home/fanc/shared/keys
    # root logs in with the agent key. The authorized_keys of rootvictim is
    # the target root must never write through.
    mkdir -p /root/.ssh && cp /seed/key.pub /root/.ssh/authorized_keys
    chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys
    unlock root
    cp /seed/stale.pub /home/rootvictim/.ssh/authorized_keys
    chown rootvictim:rootvictim /home/rootvictim/.ssh/authorized_keys && chmod 600 /home/rootvictim/.ssh/authorized_keys
    # Both key files (virgin and absent log in via authorized_keys2); root
    # login for the ownership fixture only. OpenSSH 9.8+ penalizes a source
    # address after failed logins and then drops its handshakes. The lockout
    # and from= probe tests fail logins on purpose (twice each, shuffled), so
    # the penalty would refuse later tests.
    sshd_set "AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2" "PermitRootLogin prohibit-password" "PerSourcePenalties no"
    sshd_expect "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2"
    sshd_expect "permitrootlogin (prohibit-password|without-password)"
    sshd_expect "persourcepenalties no"
    # maxauth: refuses after two failed keys, for the MaxAuthTries login-check
    # test. A Match block must end the file, so it is appended (sshd_set
    # prepends).
    printf "Match User maxauth\n  MaxAuthTries 2\n" >> /etc/ssh/sshd_config
    sshd -T -C user=maxauth,host=x,addr=127.0.0.1 | grep -Eqix "maxauthtries 2" || { echo "sshd -T lacks MaxAuthTries 2 for maxauth" >&2; exit 1; }
    exec /usr/sbin/sshd -D -e
'

# Container B: a custom AuthorizedKeysFile, so the fan-out E2E proves apply
# writes the manifest's authorized_keys_file override, not the default path.
FIXTURE_B='
    mkuser fleet
    mkdir -p /home/fleet/.ssh
    cat /seed/key.pub /seed/stale.pub > /home/fleet/.ssh/fleet_keys
    chown -R fleet:fleet /home/fleet/.ssh
    chmod 700 /home/fleet/.ssh && chmod 600 /home/fleet/.ssh/fleet_keys
    sshd_set "AuthorizedKeysFile .ssh/fleet_keys" "PerSourcePenalties no"
    sshd_expect "authorizedkeysfile .ssh/fleet_keys"
    exec /usr/sbin/sshd -D -e
'

docker rm -f "$CA" "$CB" >/dev/null 2>&1 || true
docker run -d --name "$CA" --label sshepherd-it=1 \
  -p "127.0.0.1:${SSHEPHERD_IT_PORT:-}:22" \
  -v "$WORKDIR/id_ed25519.pub:/seed/key.pub:ro" \
  -v "$WORKDIR/stale.pub:/seed/stale.pub:ro" \
  -v "$WORKDIR/ci_old.pub:/seed/ci_old.pub:ro" \
  -v "$WORKDIR/enc.pub:/seed/enc.pub:ro" \
  "$IMAGE" sh -c "$PRELUDE$FIXTURE_A" >/dev/null
docker run -d --name "$CB" --label sshepherd-it=1 \
  -p "127.0.0.1::22" \
  -v "$WORKDIR/id_ed25519.pub:/seed/key.pub:ro" \
  -v "$WORKDIR/stale.pub:/seed/stale.pub:ro" \
  "$IMAGE" sh -c "$PRELUDE$FIXTURE_B" >/dev/null

port_of() { docker port "$1" 22/tcp | sed -n 's/^127\.0\.0\.1://p' | head -n1; }
PORT_A="$(port_of "$CA")"
PORT_B="$(port_of "$CB")"
running() { [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ]; }
dump_logs() {
  for c in "$CA" "$CB"; do
    echo "--- docker logs $c ---" >&2
    docker logs "$c" >&2 || true
  done
}

KH="$WORKDIR/known_hosts"
echo "waiting for $DISTRO sshd on 127.0.0.1:$PORT_A (A) and 127.0.0.1:$PORT_B (B) ..."
# The images carry OpenSSH already; the wait covers container A's fixture
# setup (dozens of users), which runs before sshd starts.
for _ in $(seq 1 180); do
  { ssh-keyscan -p "$PORT_A" 127.0.0.1; ssh-keyscan -p "$PORT_B" 127.0.0.1; } >"$KH" 2>/dev/null || true
  if grep -q "^\[127.0.0.1\]:$PORT_A " "$KH" && grep -q "^\[127.0.0.1\]:$PORT_B " "$KH"; then
    break
  fi
  running "$CA" && running "$CB" || break
  sleep 1
done
if ! { [ "$(grep -c "^\[127.0.0.1\]:$PORT_A " "$KH")" -gt 0 ] && [ "$(grep -c "^\[127.0.0.1\]:$PORT_B " "$KH")" -gt 0 ]; }; then
  echo "sshd never came up on both containers; container logs:" >&2
  dump_logs
  exit 1
fi

eval "$(ssh-agent -s)" >/dev/null
OUR_AGENT_PID="$SSH_AGENT_PID"
ssh-add "$WORKDIR/id_ed25519"

export SSHEPHERD_IT_HOST=127.0.0.1 \
  SSHEPHERD_IT_PORT="$PORT_A" \
  SSHEPHERD_IT_PORT_B="$PORT_B" \
  SSHEPHERD_IT_DISTRO="$DISTRO" \
  SSHEPHERD_IT_KNOWN_HOSTS="$KH" \
  SSHEPHERD_IT_PUB="$WORKDIR/id_ed25519.pub" \
  SSHEPHERD_IT_KEYS="$WORKDIR"
# sshwrite's write tests mutate shared container users. Shuffled and run
# twice, they prove each test reseeds its own starting state (go test
# prints the -test.shuffle seed so a failure reproduces).
go test -race -tags=integration -run 'TestIntegration' -shuffle=on -count=2 -v ./internal/sshwrite/
go test -race -tags=integration -run 'TestIntegration|TestE2E' -v ./internal/sshread/ ./cmd/sshepherd/

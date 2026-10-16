# SSHepherd

[![CI](https://github.com/javadh75/SSHepherd/actions/workflows/ci.yml/badge.svg)](https://github.com/javadh75/SSHepherd/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Manage SSH `authorized_keys` across a fleet of servers from a single source of truth.**

Declare who should have access to which machines in one YAML manifest. SSHepherd
reads every server, tells you exactly how reality differs from the manifest, and
converges the fleet — adding keys, revoking keys, and rotating credentials without
hand-editing `authorized_keys` or losing track of who can log in where.

```console
$ sshepherd audit
web-1 (deploy@10.0.0.1:22)
  ✓  alice (alice@sshepherd)  SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8  ssh-ed25519  present & authorized
  ✗  bob                      SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  authorized but MISSING
  ⚠  (unknown)                SHA256:doxiASlJnKSD9j+JpVoWpfEFHjUrsF9ZYr+cir4FYjo  ssh-ed25519  installed but UNAUTHORIZED
  ⚠ line 3: unparseable entry
  → 2 authorized · 1 present · 1 missing · 1 unauthorized

web-2 (deploy@10.0.0.2:22)  ERROR: dial tcp 10.0.0.2:22: connection refused

Summary: 0/2 servers compliant · 1 with drift (0 critical) · 1 unreachable  → exit 1
```

---

## Why

Managing SSH keys by hand across many servers is error-prone and hard to audit.
You SSH into each box to edit `authorized_keys`, you lose track of who has access
to what, and revoking a departed colleague's access reliably is painful.
SSHepherd centralizes and automates this:

- **Central source of truth** — users, keys, and grants live in one manifest.
- **Audit** — answer "who can log into which server?" at any time, in text or JSON.
- **Apply** — make every server match the manifest, atomically and reversibly.
- **Revoke / rotate** — edit the manifest, run `apply`. That's the whole workflow.
- **Adopt / import** — bootstrap the manifest from a fleet you already run, or from
  your existing `~/.ssh/config`.

It is a **single static binary**, **agentless** (nothing to install on the servers),
and speaks SSH natively via `golang.org/x/crypto/ssh` — no dependency on a host
`ssh` binary.

## Status

Early development, but the core loop works end to end: **adopt → apply → audit**.

| Command  | State | What it does |
| -------- | ----- | ------------ |
| `audit`  | ✅ | Read-only drift report (text + `--json`, monitoring exit codes) |
| `import` | ✅ | Convert an OpenSSH client config into a starter manifest (`--merge` supported) |
| `adopt`  | ✅ | Read the live fleet and generate a manifest that accounts for every installed key (`--merge` supported) |
| `apply`  | ✅ | The write path: plan → confirm → guarded atomic write → verify → login probe |
| `revoke` / `rotate` | — | Not separate commands: both reduce to a manifest edit plus `apply` |

`audit`, `adopt` and `apply` authenticate with the SSH agent, `--identity` key
files, or both — so they also run headless in CI, cron and containers (see
[Authentication](#authentication)).

## Install

**From source** (Go 1.26+):

```console
$ go install github.com/javadh75/SSHepherd/cmd/sshepherd@latest
```

**Build locally** — produces a reproducible static binary at `bin/sshepherd`:

```console
$ make build
```

**Docker** — minimal Alpine image, non-root (UID 65532), `tini` as PID 1:

```console
$ make docker
$ docker run --rm sshepherd:dev --version
```

To run against a fleet from the container, mount your manifest and `known_hosts`
and forward your SSH agent (or mount a key file and use `--identity` — see
[Container usage](#container-usage)):

```console
$ docker run --rm \
    -v "$PWD/sshepherd.yaml:/work/sshepherd.yaml:ro" \
    -v "$HOME/.ssh/known_hosts:/work/known_hosts:ro" \
    -v "$SSH_AUTH_SOCK:/ssh-agent" -e SSH_AUTH_SOCK=/ssh-agent \
    -w /work sshepherd:dev audit --known-hosts /work/known_hosts
```

## Requirements

SSHepherd deliberately has a narrow, strict connection posture:

- **Credentials:** an SSH agent (`SSH_AUTH_SOCK`) holding the key(s) that log into
  the fleet, and/or private key files passed with `--identity` (headless runs: CI,
  cron, containers). Without `--identity` the agent is required, exactly as before;
  see [Authentication](#authentication).
- **A populated `known_hosts`** (default `~/.ssh/known_hosts`). Host-key checking is
  **strict, with no TOFU**: an unknown host is an error, not a prompt.
- **Direct reachability.** Every server is dialed directly. Hosts reachable only
  through a bastion (`ProxyJump`/`ProxyCommand`) are not supported yet; `import`
  warns about them, and a failed dial says so.
- **For `apply`, a POSIX userland on each server:** `/bin/sh` plus `id`, `ls`,
  `mkdir`, `dirname`, `cat`, `head`, `wc`, `mv`, `rm` and `cksum` (all present in
  busybox, coreutils and BSD userlands). Every remote command runs as
  `exec /bin/sh -c '…'`, so accounts whose login shell is fish, csh or tcsh work too.
  Accounts that cannot run that command are not supported: a restricted shell
  (`rbash` forbids `/` in command names), or a `ForceCommand`/`command=` wrapper that
  only allows specific commands.

## Quick start

### 1. Get a manifest

Bootstrap from the fleet you already run — `adopt` connects to every server, reads
the real `authorized_keys`, and writes a manifest in which every installed key is
accounted for:

```console
$ sshepherd adopt --config sshepherd.yaml -o adopted.yaml
```

Or bootstrap from your local SSH client config — `import` resolves each concrete
`Host` to the host/port/user `ssh` would use and derives users from the `.pub` files
next to each `IdentityFile`:

```console
$ sshepherd import ~/.ssh/config -o sshepherd.yaml
```

Both commands only ever *emit* a manifest — review it before you trust it. Neither
modifies the input file.

### 2. See the drift

```console
$ sshepherd audit
```

Read-only. Nothing is written to any server.

### 3. Converge the fleet

```console
$ sshepherd apply --dry-run   # preview the plan
$ sshepherd apply             # plan, confirm once, then write
```

```console
$ sshepherd apply
db-1 (deploy@10.0.0.9:22)  REFUSED: 1 keys installed but manifest grants none — refusing to wipe

web-1 (deploy@10.0.0.1:22)
  +  bob                 SHA256:zbv/nU7iZdO0fB0DalMI70dP6/yFD8sctXvvW4+OokY  ssh-ed25519  add (authorized, missing)
  -  (unknown)           SHA256:doxiASlJnKSD9j+JpVoWpfEFHjUrsF9ZYr+cir4FYjo  ssh-ed25519  remove (unauthorized)
  ~  alice (alice@work)  SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  rewrite comment: "alice@old" → "alice@work"
  ~  (formatting)                                                                         normalize: removing 1 non-key lines (comments/blank)
  → 2 keys desired · 1 add · 1 remove · 1 rewrite

web-2 (deploy@10.0.0.2:22)  converged (no changes)

web-3 (deploy@10.0.0.3:22)  ERROR: dial tcp 10.0.0.3:22: connection refused

apply 1 of 4 servers? [y/N]
```

Without a TTY and without `--yes`, `apply` refuses rather than assuming consent —
so a CI job that forgot `--yes` fails instead of writing unattended.

### 4. Offboard someone

Delete their `users:` entry (or just the keys they no longer own) from the
manifest, then:

```console
$ sshepherd apply --server web-1   # canary one host first
$ sshepherd apply                  # then the rest of the fleet
```

## The manifest

One YAML file — by default `sshepherd.yaml` — with three sections. Unknown fields
are **rejected**, so a typo like `commment:` fails loudly instead of being silently
ignored. The file must be a **single YAML document**: a `---` separator (even a
trailing empty one) or concatenated files fail with
`manifest contains multiple YAML documents`.

```yaml
users:
  - name: alice
    description: platform team          # documentation only, never sent to a server
    comment: alice@corp                 # written as the key comment by apply
    keys:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... alice@laptop

  - name: ops-root
    operator: true                      # fleet-wide, protected key (see below)
    keys:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...

servers:
  - name: web-1
    description: frontend
    host: 10.0.0.1
    port: 22                            # optional, defaults to 22
    user: deploy
    authorized_keys_file: /etc/ssh/keys/deploy   # optional override, see below

  - name: ci
    host: ci.internal
    port: 2222
    user: git

access:
  - user: alice
    servers: [web-1, ci]

  - user: bob
    servers: ["*"]                      # every server, including ones added later
    except: [ci]                        # … minus these
```

### Operator users

`operator: true` grants a user **every** server implicitly — no `access:` entry
needed — and marks their keys as protected management keys:

- `audit` renders a missing operator key as **CRITICAL** (exit code 2), because that
  is the drift class that threatens your ability to reach the fleet at all.
- `apply` writes operator keys **first** in every rendered file.
- `import --operator <key-file>` marks a key's owner as an operator at import time.

### Wildcard access

`servers: ["*"]` grants every server currently in the manifest *and* every server
added later, minus anything listed in `except:`. Use it for people (or automation)
whose access should not need updating each time the fleet grows.

### Per-server `authorized_keys_file`

For servers whose sshd reads keys from somewhere other than the default
`~/.ssh/authorized_keys`. The value is the **resolved path** of the file to manage —
sshd's `%u`/`%h`/`%%` tokens are *not* expanded, so `%` is rejected (write
`/etc/ssh/authorized_keys/deploy`, not `/etc/ssh/authorized_keys/%u`). It must be
absolute (`/...`) or home-relative with an explicit `~/` prefix, must name a file
(a trailing `/` is rejected), and may not contain control, format or line-separator
characters. It is POSIX-single-quote escaped before it reaches a remote shell.

When the effective path is the default, `audit` also checks whether
`~/.ssh/authorized_keys2` — OpenSSH's compiled-in second `AuthorizedKeysFile` —
exists and is non-empty, and reports it as drift. SSHepherd never reads its keys;
`apply` moves it aside to `~/.ssh/authorized_keys2.sshepherd.disabled` whenever it
writes that server (see [Safety model](#safety-model)), so a revoked key cannot keep
logging in from it. Other sshd `AuthorizedKeysFile` layouts (a custom list in
`sshd_config`, `AuthorizedKeysCommand`) are not detected — point
`authorized_keys_file` at the file sshd actually reads.

### Validation rules

The loader fails the whole manifest (exit 3) on any of these:

- **Key lines** must parse as `authorized_keys` entries, and the declared type token
  must match the key material (`ssh-rsa <ed25519 blob>` is rejected — sshd ignores
  such a line too).
- **Key options** must be real OpenSSH options: `agent-forwarding`, `cert-authority`,
  `command`, `environment`, `expiry-time`, `from`, `no-agent-forwarding`,
  `no-port-forwarding`, `no-pty`, `no-touch-required`, `no-user-rc`,
  `no-X11-forwarding`, `permitlisten`, `permitopen`, `port-forwarding`, `principals`,
  `pty`, `restrict`, `tunnel`, `user-rc`, `verify-required`, `X11-forwarding`. Names
  are case-insensitive. Valued options need `name="..."` (double-quoted, as sshd
  requires); flag options must not carry a value. Errors read e.g.
  `user "alice" key 1: option "no-ptty" is not a recognized authorized_keys option`.
- **Server `name`, `host` and `user`** may not contain whitespace or control, format
  or line-separator characters (U+2028/U+2029 included).
- **One entry per remote file.** Two servers that resolve to the same host
  (case-insensitive), port, user and effective `authorized_keys` path are an error:
  `servers "A" and "B" both target user@host:port path; merge them into one entry`.
  An explicit `~/.ssh/authorized_keys` counts as the same target as unset. Different
  spellings of one machine (an IP vs. a hostname) cannot be detected. Manifests from
  older `import` runs that emitted one server per alias of a `Host a a.example.com`
  line now fail this check; merge those entries.
- **Access entries** must grant something: a non-wildcard entry with `servers: []` or
  no `servers:` key fails with `servers is empty (grants no servers)`.
- **Names and comments** (user names, `comment:`, inline key comments) may not
  contain control or format characters, the Unicode line/paragraph separators
  U+2028/U+2029, or leading/trailing whitespace; option values may not contain the
  same control, format or separator characters. Non-ASCII letters are fine.

### Comment policy

The comment SSHepherd writes on each key line is resolved in this order:

1. the user's `comment:` field, if set;
2. the key line's own inline comment;
3. the user's `name`.

Setting `comment:` on a user with multiple keys is legal — it deliberately
normalizes every key to the same comment — but the manifest loader warns about it,
so it stays a conscious choice. `audit --comments` reports comment drift on present
keys; it is informational and never affects the exit code.

## Commands

Global flags on every command: `-v/--verbose` (debug logging), `-q/--quiet`
(errors only), `--color auto|always|never`. Reports go to **stdout**; logs,
warnings, and the confirmation prompt go to **stderr** — so `sshepherd apply > plan.txt`
captures exactly the report.

### `sshepherd audit`

Report drift between the manifest and each server's `authorized_keys`. Read-only.

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--config` | `sshepherd.yaml` | Path to the manifest |
| `--known-hosts` | `~/.ssh/known_hosts` | `known_hosts` path (strict checking) |
| `--parallel` | `32` | Max concurrent server audits |
| `--json` | off | Machine-readable report on stdout (schema 1) |
| `--comments` | off | Also report comment drift on present keys (informational) |
| `--identity PATH` | none | Private key file to authenticate with, in addition to `ssh-agent` (repeatable); `~/` expands from `$HOME` |
| `--identity-passphrase-file FILE` | none | Default passphrase file for any encrypted `--identity` key |
| `--identity-passphrase KEY=FILE` | none | Passphrase file for one `--identity` key (repeatable); split at the **first** `=` — a key path containing `=` is unsupported |

**Drift classes.** Besides missing, unauthorized and unparseable entries, three
security-relevant classes make a server non-compliant (exit 1), always on:

- a matched key whose **options differ** from the manifest's (e.g. the server lost a
  `from=` or `command=` restriction);
- a **duplicate entry** — one key on several lines, where sshd tries each line and
  the least restricted copy wins;
- a non-empty, unmanaged **`~/.ssh/authorized_keys2`** (checked only when the audited
  path is the default).

```console
web-1 (deploy@10.0.0.1:22)
  ⚠  alice  SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8  ssh-ed25519  present but OPTIONS DIFFER (server: (none) · manifest: "restrict,command=\"/usr/local/bin/backup\",from=\"10.0.0.5\"")
  → 1 authorized · 1 present · 0 missing · 0 unauthorized

web-2 (deploy@10.0.0.2:22)
  ✓  alice  SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8  ssh-ed25519  present & authorized
  ✓  bob    SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  present & authorized
  ⚠ duplicate entry: alice SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8 appears on 2 lines — sshd tries each line, so the least restricted copy wins
  ⚠ unmanaged authorized_keys2 present: ~/.ssh/authorized_keys2 is non-empty and
    sshd's default AuthorizedKeysFile accepts its keys too — this audit does not
    list them; apply moves the file aside when it writes this server
  → 2 authorized · 2 present · 0 missing · 0 unauthorized

Summary: 0/2 servers compliant · 2 with drift (0 critical) · 0 unreachable  → exit 1
```

Comment drift (`--comments`) stays cosmetic and never affects the exit code.

**Classified errors.** An unreachable server's line names the failure kind:
`host_key_unknown`, `host_key_changed`, `host_key_type_unrecorded`,
`host_key_revoked`, `host_key`, `agent`, `auth`, `dial`, `timeout`, `canceled`,
`handshake` or `remote`. Unclassified errors keep a plain `ERROR:` head. A host key
that **changed** or is marked `@revoked` in `known_hosts` (possible impersonation)
counts as a host-key alert and makes the run exit `2`:

```console
web-1 (deploy@10.0.0.1:22)  ERROR [host_key_changed]: ssh deploy@10.0.0.1:22: presented ssh-ed25519 key SHA256:abc: knownhosts: key mismatch

web-2 (deploy@10.0.0.2:22)  ERROR [auth]: ssh deploy@10.0.0.2:22: ssh: unable to authenticate

Summary: 0/2 servers compliant · 0 with drift (0 critical) · 2 unreachable (1 HOST KEY ALERT)  → exit 2
```

For an unknown host or an unrecorded key type, the hint asks you to verify the
presented fingerprint out of band (on the console,
`ssh-keygen -lf /etc/ssh/ssh_host_<type>_key.pub`, or the cloud console), then
compare it with `ssh-keyscan -t <type> -p <port> '<host>' | ssh-keygen -lf -` before
appending a matching line yourself. SSHepherd never suggests piping `ssh-keyscan`
into `known_hosts`.

**JSON.** `--json` emits one indented JSON document on stdout, pinned by golden
fixtures. Field names are a public contract: additive fields keep `"schema": 1`, and
only a breaking change bumps it — so consumers can hard-fail on an unexpected schema.
The report for the classified-error example above:

```json
{
  "schema": 1,
  "summary": {
    "servers": 2,
    "compliant": 0,
    "drift": 0,
    "critical": 0,
    "unreachable": 2,
    "host_key_alerts": 1,
    "exit_code": 2
  },
  "servers": [
    {
      "name": "web-1",
      "host": "10.0.0.1",
      "port": 22,
      "user": "deploy",
      "status": "unreachable",
      "error": "ssh deploy@10.0.0.1:22: presented ssh-ed25519 key SHA256:abc: knownhosts: key mismatch",
      "error_kind": "host_key_changed",
      "keys": {
        "present": [],
        "missing": [],
        "unauthorized": []
      },
      "parse_errors": [],
      "file_absent": false,
      "no_users_granted": false
    },
    {
      "name": "web-2",
      "host": "10.0.0.2",
      "port": 22,
      "user": "deploy",
      "status": "unreachable",
      "error": "ssh deploy@10.0.0.2:22: ssh: unable to authenticate",
      "error_kind": "auth",
      "keys": {
        "present": [],
        "missing": [],
        "unauthorized": []
      },
      "parse_errors": [],
      "file_absent": false,
      "no_users_granted": false
    }
  ]
}
```

Optional fields, present only when they apply: `servers[].error_kind` (exactly when
`error` is non-null; `"unknown"` for unclassified errors), `summary.host_key_alerts`
(omitted when 0), `keys.present[].options_drift` (`{"actual": [...], "desired": [...]}`),
`keys.present[].comment_drift` (with `--comments`), `servers[].duplicates`
(`[{"owner", "fingerprint", "count"}]`) and `servers[].authorized_keys2_present`.
See `internal/audit/testdata/*.golden.json` for every shape.

### `sshepherd import [ssh-config-path]`

Convert an OpenSSH client config (default `~/.ssh/config`) into a starter manifest.
`users:` and `access:` are derived from each host's `IdentityFile` — or ssh's default
identities — by reading the matching `.pub` files **on this machine**. Private keys
are never read. Run it where you actually `ssh` from.

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `-o, --output` | stdout | Write the manifest to this file |
| `--force` | off | Allow `--output` to overwrite an existing file |
| `--servers-only` | off | Emit servers only; skip identity resolution |
| `--operator` | — | Key file whose owner becomes an operator (repeatable) |
| `--merge FILE` | — | Merge into an existing manifest, preserving its comments |

`--merge` is strictly additive: only genuinely new entries are appended, the
existing manifest wins every conflict (with a loud warning), and re-running with no
new input is a byte-identical no-op.

How the ssh config is read — matching OpenSSH (`ssh -G`):

- A trailing `# comment` after arguments (`Host web1 # prod`) is ignored.
- `Include` keeps the enclosing context: settings after an `Include` belong to the
  block that was current before it, a `Match` at the end of an included file does
  not swallow later lines, and `Host` blocks inside a file included from a `Host`
  block apply only to aliases that block also matches (others are skipped with a
  warning).
- `HostName` expands `%h` (the alias) and `%%`; any other token skips the host with
  a warning.
- `IdentityFile` expands `%d`, `%u`, `%%`, `%n` (alias), `%h` (resolved HostName),
  `%r` (remote user) and `%p` (port, default 22); `--operator` paths support only
  `%d`, `%u` and `%%`. An `IdentityFile` may name the `.pub` itself (agent-held keys
  such as 1Password, Secretive or a YubiKey); the user name drops the `.pub`.

What gets skipped or merged, always with a warning on stderr:

- A host whose alias, HostName or User contains whitespace or control characters
  (e.g. a quoted `Host "web 1"`) — it could never be a valid server entry.
- A `.pub` whose comment has tabs or control/format characters (an error for
  `--operator`).
- **One entry per remote file.** When several aliases resolve to the same host
  (case-insensitive), port, user and `authorized_keys` file — e.g.
  `Host web1 web1.example.com` — the first in config order is kept and the rest are
  skipped; access derived through a skipped alias is granted on the kept one. Under
  `--merge`, an alias whose target is already a manifest server is skipped the same
  way, its access goes to that server, and it counts toward "conflicts skipped".
- Hosts with `ProxyJump`/`ProxyCommand` are still imported, with
  `host "X": ProxyJump <v> set — dialed directly; bastion hosts are not supported yet`.

**Output files** (`-o`, shared with `adopt`): written mode `0600`, fsynced, and
published without ever clobbering an existing file unless `--force` is given.
`--force` refuses a symlinked output path
(`<path> is a symlink; refusing to replace it — pass the link's target path instead`).
On filesystems without hard links (exFAT, some SMB/FUSE mounts) the no-`--force`
write falls back to an exclusive create: it still refuses an existing file, but is
not atomic for readers.

### `sshepherd adopt`

Connect to every server in the manifest (same SSH path as `audit`), read the actual
`authorized_keys`, and emit a complete new manifest in which every installed key is
accounted for: keys of known users found beyond their grants **extend** that user's
access; unknown keys become **new users** with access to exactly the servers where
they were found. The input file is never modified.

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--config` | `sshepherd.yaml` | Path to the manifest |
| `--known-hosts` | `~/.ssh/known_hosts` | `known_hosts` path (strict checking) |
| `--parallel` | `32` | Max concurrent server reads |
| `-o, --output` | stdout | Write the manifest to this file |
| `--force` | off | Allow `--output` to overwrite an existing file |
| `--partial` | off | Proceed even if some servers cannot be read |
| `--merge` | off | Append discoveries to the existing manifest, comments intact |
| `--identity PATH` | none | Private key file to authenticate with, in addition to `ssh-agent` (repeatable); `~/` expands from `$HOME` |
| `--identity-passphrase-file FILE` | none | Default passphrase file for any encrypted `--identity` key |
| `--identity-passphrase KEY=FILE` | none | Passphrase file for one `--identity` key (repeatable); split at the **first** `=` — a key path containing `=` is unsupported |

Any unreadable server aborts the run unless `--partial` is set — adopting a
half-read fleet would silently drop real access.

An on-server key whose comment has tabs or control/format characters is adopted
**without** its comment (options + type + key are kept), with the warning
`key <fp> on <server>: comment contains control or format characters — adopted without its comment`.
Comment-less keys are named `adopted-key-<n>` from the first free `n`, so
`adopt --merge` re-runs continue the numbering (`adopted-key-2`, not
`adopted-key-1-2`). A line whose type token does not match its key material counts
as unparseable.

### `sshepherd apply`

The write path. Makes each targeted server's `authorized_keys` equal the manifest's
rendered desired state.

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--config` | `sshepherd.yaml` | Path to the manifest |
| `--known-hosts` | `~/.ssh/known_hosts` | `known_hosts` path (strict checking) |
| `--parallel` | `32` | Max concurrent server connections |
| `--server` | all | Restrict the run to this server (repeatable; canary rollout) |
| `--dry-run` | off | Plan and report only; never write |
| `--yes` | off | Skip the confirmation prompt (automation) |
| `--identity PATH` | none | Private key file to authenticate with, in addition to `ssh-agent` (repeatable); `~/` expands from `$HOME` |
| `--identity-passphrase-file FILE` | none | Default passphrase file for any encrypted `--identity` key |
| `--identity-passphrase KEY=FILE` | none | Passphrase file for one `--identity` key (repeatable); split at the **first** `=` — a key path containing `=` is unsupported |

`--dry-run` and `--yes` are mutually exclusive. `--yes` skips only the `[y/N]`
confirmation: an encrypted `--identity` key may still prompt for its passphrase on
the terminal (see [Authentication](#authentication)).

Rewrite rows show what changes on a key line, and a rewrite that **drops a
restrictive option** (`from=`, `command=`, `restrict`, `no-*`, `expiry-time=`,
`permitopen=`, `permitlisten=`, `cert-authority`, `principals=`) is painted red and
followed by a warning — highlighted, not refused:

```console
web-1 (deploy@10.0.0.1:22)
  ~  alice (alice@work)  SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  rewrite options: "from=\"10.0.0.5\",command=\"/usr/bin/pg_dump-wrapper\"" → (none)
  ~  (formatting)                                                                         normalize: removing 1 duplicate key lines (some carry options different from the first copy)
  -  (authorized_keys2)                                                                   disable ~/.ssh/authorized_keys2 → ~/.ssh/authorized_keys2.sshepherd.disabled (unmanaged; sshd would keep accepting its keys)
  warning: the rewrite of alice (alice@work)'s key drops restrictive option(s) "from=\"10.0.0.5\"", "command=\"/usr/bin/pg_dump-wrapper\"" — the manifest line grants more than the server does today
  → 3 keys desired · 0 add · 0 remove · 1 rewrite
```

After the writes, a summary reports each server's outcome:

```console
a: applied · verified
b: NOT STARTED: interrupted before the write started
c: FAILED: lockout prevented — restored previous file (post-write login offering only the surviving keys you hold failed: ssh: unable to authenticate)
Summary: 1/3 servers converged (1 applied) · 1 pending · 1 failed  → exit 1
```

**Ctrl-C / SIGTERM** during the writes stops new servers from starting; servers
already being written finish their write, verify and login probe (bounded by a
2-minute session budget). Unstarted servers show `NOT STARTED` and count as pending
(exit 1). A second Ctrl-C kills the process immediately. An interrupt before any
write starts — during `apply`'s planning or at its `[y/N]` prompt — writes nothing
and exits `3`. In `audit` and `adopt`, an interrupt at any point closes in-flight
sessions and exits `3` without rendering a report or writing a manifest (servers cut
short are never passed off as unreachable).

## Authentication

`audit`, `adopt` and `apply` authenticate with the union of two sources, like
`ssh -i`:

1. **`--identity` key files**, offered first, in flag order;
2. **the SSH agent** at `SSH_AUTH_SOCK`, in the agent's own order (certificates
   included).

A key in both is offered once. With at least one `--identity`, a missing, empty or
broken agent is not an error (a set-but-broken `SSH_AUTH_SOCK` logs one warning and
the run continues with the key files). With no `--identity`, the agent is required
and behaves as before — except that `apply` with only agent certificates is now
refused up front (below). Each loaded key is logged once:
`identity loaded path=KEY fp=SHA256:…`.

**Certificates are offered, never counted.** Agent-held certificates still log in,
but they never count as a key you hold for `apply`'s self-lockout guard or its
post-write login probe (a certificate logs in through a `cert-authority` line the
guard cannot prove survives). A `KEY-cert.pub` next to an `--identity` key is not
loaded (`certificate KEY-cert.pub not used; authenticating with the plain key`).
`apply` with only certificates is refused before anything is read.

**Passphrases.** An encrypted key is unlocked by the first source that applies:

1. its `--identity-passphrase KEY=FILE` mapping — a wrong passphrase there is an
   error (exit 3), never a fall-through;
2. `--identity-passphrase-file FILE` — a shared default: if it does not unlock this
   key, resolution continues;
3. a prompt on the controlling terminal (`/dev/tty`, three attempts, like `ssh`);
4. otherwise exit 3: `KEY is encrypted and no passphrase source is available (use --identity-passphrase-file or --identity-passphrase KEY=FILE)`.

There is **no passphrase environment variable and no passphrase flag value** (both
leak through `/proc/<pid>/environ`, `ps`, shell history or core dumps). Files, secret
mounts, `/dev/fd/N` and `<(...)` work. Every passphrase file is read exactly once per
run (a pipe can be read only once), exactly one trailing newline (`\n` or `\r\n`) is
stripped, and a file that is then empty is an error, never an empty passphrase.
Passphrases, passphrase-file contents and key bytes never appear in a log line, an
error or a report. They are wiped from memory when loading finishes — best effort
only: Go cannot guarantee no copies remain, and bcrypt intermediates are not zeroed.

**Prompting and headless runs.** A prompt is shown only when `/dev/tty` opens,
stdin is a terminal, and SSHepherd is the terminal's foreground process. Anything
else — `docker run -t`, a pty-allocating CI executor, `sshepherd … &` — is headless
and fails fast with the no-passphrase-source error instead of hanging. The prompt
and its `waiting for passphrase for KEY on the terminal` line go to the terminal,
never stdout (`audit --json` stays clean), and appear even under `-q`. `--yes` does
not disable prompting. Ctrl-C at the prompt restores the terminal and exits `3`
without connecting anywhere.

**Order of operations.** Flags are validated first, then the manifest; an empty
fleet (or no targeted server) returns before any key file is read; then
`known_hosts` is loaded; only then are key files read (and maybe prompted for). A
manifest typo or a bad `--known-hosts` therefore never costs you a passphrase.

**Key-file rules.**

- **Permissions**, as OpenSSH checks them: a regular file you own must not be
  readable by group or others — `permissions 0644 for FILE are too open (chmod 600 FILE)`.
  A regular file owned by another user (e.g. a root-owned secret mount) is accepted.
  Pipes, sockets and character devices (`/dev/fd/N`, `<(...)`, `/dev/stdin`) are
  exempt: their mode bits do not describe a file at rest. The same rule applies to
  passphrase files.
- **Unreadable** files name the mismatch:
  `cannot read key file FILE as uid N (owner M, mode 0600) — see README 'Container usage'`.
- **Size caps:** key files 64 KiB, passphrase files 4 KiB.
- **Paths are matched lexically:** `~/` expands from `$HOME`, relative paths resolve
  against the working directory, then `filepath.Clean` — no symlink resolution, case
  sensitive. An `--identity-passphrase` KEY must name an `--identity` exactly as
  cleaned (the error lists the cleaned paths); the same KEY twice is an error; a
  path given twice to `--identity` is used once. Two paths holding the same key keep
  the first (an info line names the dropped one).
- **The fingerprint is always the decrypted key's.** A sibling `KEY.pub` (legacy PEM)
  or the embedded public key (OpenSSH format) only labels the prompt; if it
  disagrees with the private key, the key is refused.

**Supported formats.** OpenSSH (`-----BEGIN OPENSSH PRIVATE KEY-----`), unencrypted
or `aes256-ctr`/`aes256-cbc` with bcrypt (at most 2048 rounds), and legacy PEM RSA /
EC (optionally encrypted) and unencrypted PKCS#8. Refused before any prompt, with a
conversion hint:

| Format | Hint |
| ------ | ---- |
| PuTTY `.ppk` | `puttygen KEY -O private-openssh -o NEWFILE` |
| encrypted PKCS#8, other ciphers (e.g. `chacha20-poly1305`, `aes256-gcm`), multi-key files | `ssh-keygen -p -f KEY` |
| bcrypt rounds above 2048 | `ssh-keygen -p -a 100 -f KEY` |
| DSA (`ssh-dss`) | generate a new key (`ssh-dss` is disabled by default in OpenSSH) |
| hardware keys (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-…`) | use them through `ssh-agent` |

**The agent-only-survivor warning.** With `--identity` given, a server whose
surviving keys are all agent keys gets a plan warning — the run passes the guard on
a credential the next agent-less run will not have:

```console
web-2 (deploy@10.0.0.2:22)
  +  alice  SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  add (authorized, missing)
  note: the audited file is absent yet login succeeded — sshd may consult
        another key source; creating the file is purely additive
  warning: only SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4 (agent) keeps access; none of your --identity keys survives — a run without this agent will be locked out
  → 1 keys desired · 1 add · 0 remove · 0 rewrite
```

Guard refusals list every key you hold with its source:

```console
web-1 (deploy@10.0.0.1:22)  REFUSED: none of the 2 keys you hold (identity files + agent) would remain in web-1's authorized_keys — applying would lock this session out (held: SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o (/home/ci/.ssh/ci_old), SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4 (agent)). Add one of your keys to the manifest (or mark its user operator: true); rotating an --identity key? pass the new key with another --identity, so the guard and the post-write login probe can use it
```

**Headless key rotation.** Replace `ci_old` with `ci_new` in the manifest, then run
with both keys: the write logs in with the old key, the guard sees the new key
survive, and the post-write probe (which offers surviving key files first) proves
the new key logs in. A later run needs only the new key.

```console
$ sshepherd apply --yes --identity ~/.ssh/ci_old --identity ~/.ssh/ci_new
```

### CI recipes

The shell recipes unset `SSH_AUTH_SOCK` and the container recipes mount no agent, so
a stray or forwarded agent can never satisfy the guard for a credential CI lacks.

**GitHub Actions** (bash — `<(...)` needs bash or zsh, not POSIX `sh`; `env -u PW`
keeps the secret out of SSHepherd's own environment):

```yaml
- name: apply
  shell: bash
  env:
    PW: ${{ secrets.SSHEPHERD_KEY_PASSPHRASE }}
  run: |
    unset SSH_AUTH_SOCK
    env -u PW sshepherd apply --yes --identity "$HOME/.ssh/ci" \
      --identity-passphrase-file <(printf %s "$PW")
```

**GitLab CI** — a `type: file` variable is a path to a file holding the secret:

```yaml
apply:
  script:
    - unset SSH_AUTH_SOCK
    - sshepherd apply --yes --identity "$SSHEPHERD_KEY" --identity-passphrase-file "$SSHEPHERD_KEY_PASSPHRASE"
```

**Kubernetes CronJob** — key and passphrase from a secret volume:

```yaml
containers:
  - name: sshepherd
    image: ghcr.io/javadh75/sshepherd:latest
    args: ["apply", "--yes", "--identity", "/secrets/ci",
           "--identity-passphrase-file", "/secrets/ci.pass",
           "--config", "/config/sshepherd.yaml", "--known-hosts", "/config/known_hosts"]
    volumeMounts:
      - {name: secrets, mountPath: /secrets, readOnly: true}
securityContext:
  fsGroup: 65532
volumes:
  - name: secrets
    secret: {secretName: sshepherd-ci, defaultMode: 0440}
```

**`docker run`** — bind-mount the files (or use a tmpfs); a host-side `<(...)` file
descriptor is not passed into the container:

```console
$ docker run --rm --user "$(id -u)" \
    -v "$PWD/sshepherd.yaml:/work/sshepherd.yaml:ro" \
    -v "$HOME/.ssh/known_hosts:/work/known_hosts:ro" \
    -v "$HOME/.ssh/ci:/work/ci:ro" -v "$HOME/.ssh/ci.pass:/work/ci.pass:ro" \
    -w /work sshepherd:dev apply --yes --known-hosts /work/known_hosts \
    --identity /work/ci --identity-passphrase-file /work/ci.pass
```

### Container usage

The image runs as uid 65532. A mounted key (or passphrase file) must be either
**owned by the container's uid with mode 0600** — run with `--user` matching the
file's owner, or set Kubernetes `runAsUser` to it — or **owned by root and readable
through group or other bits** — Kubernetes `fsGroup: 65532` with a secret
`defaultMode: 0440`. A file owned by the container uid but group/other-readable is
refused (`permissions … are too open`); a file the uid cannot read at all fails with
`cannot read key file FILE as uid 65532 (owner M, mode …)`.

## Exit codes

Monitoring-style, shared by `audit` and `apply` (code `2` is `audit`-only):

| Code | Meaning |
| ---- | ------- |
| `0` | Compliant / converged — nothing to do |
| `1` | Drift, unreachable servers, or pending changes — compliance not proven |
| `2` | `audit` only: **critical** drift (a server is missing an operator key), or a server whose host key **changed** or is `@revoked` in `known_hosts` (possible impersonation) — `apply` never returns `2` |
| `3` | Tool error — bad flags, unloadable manifest, failed preflight, an `--identity` key that cannot be read, is refused, or has no passphrase source, interrupted `audit`/`adopt`, `apply` interrupted before any write |

## Safety model

`apply` writes to production machines, so it is built to fail closed.

**Full-file rewrite.** Each managed file is rendered from scratch: a managed header
(`# Managed by SSHepherd. Manual edits will be overwritten by 'sshepherd apply'.`),
operator keys first, then the granted keys, with the decided comment policy applied.
Non-key lines — hand-written comments, blank lines — are **deleted** by the rewrite;
the plan shows a `normalize` row with the exact count *before* anything is written.
Output is deterministic, so a repeated `apply` is a byte-for-byte no-op.

**Two-phase, one confirmation.** SSHepherd reads the entire fleet and shows a single
plan, you confirm once (interactive prompt on a TTY, or `--yes`), and only then does
it write — and only to the servers that actually drifted.

**Self-lockout guard.** Any write that would leave a server without a key you hold
(identity files + agent) is refused; the refusal lists every held key with its
source. Certificates never count as held, lines with `cert-authority` or
`principals=` do not count as surviving logins (they accept certificates, not the
bare key), and an empty held set refuses every write. The guard runs again **after**
the confirmation prompt against a fresh listing, so agent keys that expired or were
removed while the prompt waited fail that server instead of locking you out (a
vanished agent simply stops counting; your key files still do).

**Refusals, not guesses.** A server is skipped — loudly, with a `REFUSED:` line, and
nothing changed — when:

- the manifest grants nobody but keys are installed (refusing to wipe);
- the file contains unparseable lines (refusing to rewrite a file it could not fully
  read);
- the rendered file would exceed the 1 MiB the read path accepts
  (`rendered file is N bytes, over the 1048576-byte limit the read path accepts — refusing to write a file that could never be verified or audited`);
- the target is a symlink, its directory is a symlink, or the file or directory is
  not owned by the login user (log in as the owning user — managing another user's
  file as `root` is refused);
- an ancestor directory — walked both as written and with symlinks resolved, up to
  the login user's home (or `/` for a path outside it), like sshd's `StrictModes` —
  is owned by anyone but the login user or root, or is group/other-writable;
- the file **changed since the plan was read**
  (`… changed since the plan was read — refusing to overwrite unreviewed content; re-run apply`);
- another apply holds the file's lock
  (`another apply is in progress on <path> (lock directory <path>.sshepherd.lock; remove it only if no apply is running)`).
  A lock left behind by a killed remote shell must be removed by hand; two applies
  racing for the lock never leave one behind.

**One guarded write per server.** Each write is a single remote script in one
session, which in order: refuses an unsafe path; takes the per-file lock
`<path>.sshepherd.lock`; compares the file with the plan's snapshot (byte length plus
POSIX `cksum`, or absent vs. present) so *what you reviewed is what gets replaced*;
takes the backups; uploads to `<path>.sshepherd.tmp` under `umask 077`; checks the
received byte count; and only then `mv`s it into place. Readers never see a
half-written file, and a dropped connection leaves the original untouched
(`upload incomplete … original left untouched`).

**Backups.** `<path>.sshepherd.bak` holds the previous version and is replaced on
every apply. `<path>.sshepherd.orig` holds the pre-SSHepherd original: it is written
once, the first time an unmanaged file is replaced, and never overwritten — use it to
undo the first apply. A symlink planted at either name is never written through.

**`authorized_keys2`.** When phase 1 found a non-empty `~/.ssh/authorized_keys2`
(default path only), the plan shows
`disable ~/.ssh/authorized_keys2 → ~/.ssh/authorized_keys2.sshepherd.disabled` and the
write moves it aside after the verify and before the login probe — even when
`authorized_keys` itself already matches. A server apply does not write (refused,
or no grants) keeps a hand-removal warning instead. If the move fails, the server is
reported `FAILED` (its `authorized_keys` was still written and verified).

**Verify, then prove you can still log in.** After the rename the file is re-read in
the same session and compared byte-exactly. Then SSHepherd opens a **fresh
connection offering only the surviving keys you hold** (unrestricted ones first,
then key files before agent keys, so a surviving `--identity` key is the one
proven) and runs a probe command over it, so a surviving key whose line forces a `command=` fails
the probe just like a refused login. If the probe fails, the previous file (and a
disabled `authorized_keys2`) is restored over the still-open session and the server
is reported `FAILED: lockout prevented — restored previous file (…)`. The restore
takes the lock again and refuses to replace a file that changed since this apply
wrote it (a concurrent apply); if the restore fails or is refused, the message says
so and names the `.bak` path.

**Connection posture.** Key files and/or agent (see
[Authentication](#authentication)), strict `known_hosts` with no TOFU, per-server and dial timeouts, and bounded fan-out (`--parallel`, default 32,
tuned from the fan-out benchmarks). `known_hosts` is parsed once per run. Host-key
algorithms are negotiated in the order `known_hosts` implies, so a host with an sshd
`HostCertificate` still works when its plain key is pinned; certificate algorithms
are offered only when a matching `@cert-authority` line exists. Keys granted on the
server (operators first) are offered first, to avoid sshd `MaxAuthTries` lockouts
with many held keys. Remote commands always run under `/bin/sh`.

**Output safety.** Terminal escapes from server-supplied text are stripped and
newlines collapsed, so a hostile server cannot forge report rows or a summary line.

## Development

Everything below runs the same commands CI runs.

```console
$ make check        # the full gate: tidy, fmt, vet, lint, deadcode, security, coverage (≥80%)
$ make test         # go test -race with an atomic coverage profile
$ make coverage     # coverage report; fails below 80% line coverage
$ make integration  # dockerized sshd + build-tagged integration tests
$ make fuzz         # short fuzz run of every parser
$ make bench        # fan-out benchmarks
$ make hooks        # install the lefthook pre-commit/pre-push hooks
$ make tools        # install pinned dev tooling (exact versions, no @latest)
```

`make tidy` (part of the gate) uses `go mod tidy -diff`: it fails and prints the
needed change when `go.mod`/`go.sum` are not tidy, and never rewrites them. Re-run
`make tools` after upgrading Go — `make lint` refuses a `golangci-lint` built by a
different Go toolchain.

The gate includes `gofmt`, `go vet`, `golangci-lint`, whole-program `deadcode`,
`gosec`, `govulncheck`, and `gitleaks`. Container work has its own targets:
`make docker` (passes `--build-arg VERSION=$(git describe --tags --always --dirty)`,
overridable with `VERSION=`), `docker-lint` (hadolint + dockle), `docker-scan`
(Trivy), and `smoke` — `scripts/docker-gates.sh`: `--version` and `--help`, an image
size budget under 30 MB (`SIZE_BUDGET_MB`), and a non-root user check. CI also runs
`govulncheck` and every fuzz target daily.

**Releases.** Pushing a `v*` tag runs `.github/workflows/release.yml`, which
publishes a `linux/amd64` + `linux/arm64` image to `ghcr.io/javadh75/sshepherd` with
semver tags, a BuildKit SBOM and provenance, and a keyless cosign signature:

```console
$ cosign verify ghcr.io/javadh75/sshepherd@<digest> \
    --certificate-identity-regexp '^https://github.com/javadh75/SSHepherd/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Test kinds in the repo: unit (table-driven), integration (real `sshd` in Docker,
build-tagged), end-to-end (the CLI binary through adopt → apply → audit), fuzz
(every parser, with a committed seed corpus), benchmarks, race, goroutine-leak
checks (`goleak` in every package), and golden snapshots of rendered output.

### Layout

```
cmd/sshepherd/       CLI: root command, audit, import, adopt, apply, E2E tests
internal/config/     manifest load + strict validation, access resolution
internal/authkeys/   authorized_keys parser and renderer
internal/audit/      fan-out, diffing, text/JSON reports, exit codes
internal/adopt/      pure fleet-discovery plan
internal/apply/      pure plan computation, self-lockout guard, plan report
internal/sshconn/    shared connection glue (dial, credentials: key files + agent, host keys, error kinds)
internal/sshconn/sshtest/  in-process SSH server + agent + key-file helpers for hermetic tests
internal/keyfile/    --identity key files: permission rule, format checks, passphrases, /dev/tty prompt
internal/sshread/    remote read protocol
internal/sshwrite/   remote write protocol (guarded script, CAS, lock, verify, probe)
internal/sshcfg/     OpenSSH client-config parser
internal/identity/   IdentityFile → .pub resolution
internal/manifest/   comment-preserving manifest editing
internal/reconcile/  pure import-merge reconciliation, same-target collapse
internal/naming/     collision-free user-name allocator (import, merge, adopt)
internal/clog/       leveled, colorized logging and output sanitization
scripts/             integration runner, Docker image gates
.github/             CI, release and Dependabot workflows
```

### Design docs

Each slice was specced and planned before it was built; the documents live in
`docs/superpowers/specs/` and `docs/superpowers/plans/` and remain the reference for
*why* things work the way they do — notably the audit slice, operator users and
wildcard access, JSON output and exit codes, the comment-policy memo, the merge
designs, and the apply slice. The review-hardening pass that added the guarded write,
login probe, new drift classes and stricter validation is described in
[`docs/superpowers/specs/2026-10-16-review-hardening-design.md`](docs/superpowers/specs/2026-10-16-review-hardening-design.md). Key-file
authentication (`--identity`, passphrase sources, certificates and the guard) is
specced in
[`docs/superpowers/specs/2026-10-16-identity-keyfile-auth-design.md`](docs/superpowers/specs/2026-10-16-identity-keyfile-auth-design.md).

## License

[Apache License 2.0](LICENSE) — permissive, with an explicit patent grant.

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
- **Revoke / rotate** — `sshepherd revoke alice` or `sshepherd rotate alice --old … --new …`
  edits the manifest (comments kept) and pushes the change to exactly the servers it
  affects, through `apply`'s safety model.
- **Adopt / import** — bootstrap the manifest from a fleet you already run, or from
  your existing `~/.ssh/config`.

It is a **single static binary**, **agentless** (nothing to install on the servers),
and speaks SSH natively via `golang.org/x/crypto/ssh` — no dependency on a host
`ssh` binary.

## Status

Early development, but the core loop works end to end: **adopt → apply → revoke /
rotate → audit**.

| Command  | State | What it does |
| -------- | ----- | ------------ |
| `audit`  | ✅ | Read-only drift report (text + `--json`, monitoring exit codes) |
| `import` | ✅ | Convert an OpenSSH client config into a starter manifest (`--merge` supported) |
| `adopt`  | ✅ | Read the live fleet and generate a manifest that accounts for every installed key (`--merge` supported) |
| `apply`  | ✅ | The write path: plan → confirm → guarded atomic write → verify → login probe (text + `--json`) |
| `revoke` / `rotate` | ✅ | Comment-preserving manifest edit + `apply` over the affected servers: offboard a user, take away one server (`--server`), drop a lost key, swap a key in place or overlap old and new (`--keep-old`) (text + `--json`) |

`audit`, `adopt`, `apply`, `revoke` and `rotate` authenticate with the SSH agent,
`--identity` key files, or both — so they also run headless in CI, cron and containers (see
[Authentication](#authentication)).

## Install

**From source** (Go 1.27.3+):

```console
$ go install github.com/javadh75/SSHepherd/cmd/sshepherd@latest
```

**Build locally** — produces a reproducible static binary at `bin/sshepherd`:

```console
$ make build
```

**Docker** — distroless image (~11 MB): the static binary, TLS roots and nothing else — no
shell, no `ssh`/`ssh-keygen`/`ssh-keyscan` (run those on your host). Non-root (UID 65532,
HOME `/home/nonroot`); sshepherd is PID 1 and handles Ctrl-C/SIGTERM itself (a second
signal exits at once):

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
db-1 (deploy@10.0.0.9:22)  REFUSED: 1 key installed but manifest grants none — refusing to wipe

web-1 (deploy@10.0.0.1:22)
  +  bob                 SHA256:zbv/nU7iZdO0fB0DalMI70dP6/yFD8sctXvvW4+OokY  ssh-ed25519  add (authorized, missing)
  -  (unknown)           SHA256:doxiASlJnKSD9j+JpVoWpfEFHjUrsF9ZYr+cir4FYjo  ssh-ed25519  remove (unauthorized)
  ~  alice (alice@work)  SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  rewrite comment: "alice@old" → "alice@work"
  ~  (formatting)                                                                         normalize: removing 1 non-key line (comments/blank)
  → 2 keys desired · 1 add · 1 remove · 1 rewrite

web-2 (deploy@10.0.0.2:22)  converged (no changes)

web-3 (deploy@10.0.0.3:22)  ERROR: dial tcp 10.0.0.3:22: connection refused

apply 1 of 4 servers? [y/N]
```

Without a TTY and without `--yes`, `apply` refuses rather than assuming consent —
so a CI job that forgot `--yes` fails instead of writing unattended.

### 4. Offboard someone

```console
$ sshepherd revoke alice --dry-run   # preview: the edit header and the plan
$ sshepherd revoke alice             # confirm once: save the manifest, then write
$ git commit -am "offboard alice" && git push
$ sshepherd audit
```

`revoke` removes the user and every `access:` entry naming them, keeps the
manifest's comments, and writes only the servers whose rendered `authorized_keys`
changes. See [`sshepherd revoke`](#sshepherd-revoke) and
[`sshepherd rotate`](#sshepherd-rotate).

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
  `expiry-time` must be `YYYYMMDD[HHMM[SS]]` (optional `Z` for UTC): sshd skips a
  line it cannot read. A bad value fails with e.g.
  `user "alice" key 1: option "expiry-time=\"2027\"" has an invalid value (want YYYYMMDD[HHMM[SS]][Z])`.
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

Reports go to **stdout**; logs, warnings, and the confirmation prompt go to **stderr** —
so `sshepherd apply > plan.txt` captures exactly the report.

### Global flags

These work on every command.

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `-v, --verbose` | off | Debug logging (per-SSH-stage detail); cannot be combined with `--quiet` |
| `-q, --quiet` | off | Log errors only |
| `--color` | `auto` | Colorize output: `auto`, `always`, or `never` |

### Top-level flags

These work only on `sshepherd` itself, before any command name (`sshepherd --version`,
not `sshepherd audit --version`).

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--version` | off | Print the version and exit |

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

On-server comments, options and error text are sanitized — control characters
(C0, DEL, C1) and Unicode format characters (such as U+202E) are removed — so a
hostile `authorized_keys` line cannot smuggle terminal escapes or bidi overrides
through the document; such a comment or option is then not byte-identical to the
server's line. The write-path documents (`apply`/`revoke`/`rotate --json`) do the same.

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
- An `Include` that would re-read a file already being read (directly or through a
  symlink) is skipped with `Include cycle: <file> is already being read, skipping`.
  import reads at most 1024 included files and skips any included file over 1 MiB.
  OpenSSH itself has no cycle check and fails at depth 16.
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

A found key line that sshd would ignore (an unknown option such as `no-ptty`, an
unquoted value such as `from=1.2.3.4`, or a flag that has a value) is not access.
adopt reports it like an unparseable line and does not adopt it. Strict mode aborts
with exit 1, and `--partial` skips the line and keeps the server's other keys:

```console
error: server web-1: key SHA256:z/fSv0Z0RZS+Lccbc6ZoOWwt/fbj1VFJGSBKQbo4icE: sshd ignores this line: option "no-ptty" is not a recognized authorized_keys option
error: 1 server(s) could not be fully read — nothing written; fix the errors above or re-run with --partial
```

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
| `--json` | off | Emit the plan and outcome as machine-readable JSON on stdout (needs `--dry-run` or `--yes`) |
| `--identity PATH` | none | Private key file to authenticate with, in addition to `ssh-agent` (repeatable); `~/` expands from `$HOME` |
| `--identity-passphrase-file FILE` | none | Default passphrase file for any encrypted `--identity` key |
| `--identity-passphrase KEY=FILE` | none | Passphrase file for one `--identity` key (repeatable); split at the **first** `=` — a key path containing `=` is unsupported |

`--dry-run` and `--yes` are mutually exclusive. `--yes` skips only the `[y/N]`
confirmation: an encrypted `--identity` key may still prompt for its passphrase on
the terminal (see [Authentication](#authentication)).

**JSON.** `--json` prints one indented JSON document on stdout at the end of the run
(`"schema": 1`; `command` names the kind — `apply`, `revoke` or `rotate`) and never
the text report; logs stay on stderr. It needs `--dry-run` or `--yes` — a script
cannot answer the prompt — otherwise the run exits `3` before the manifest is read:
`--json needs --dry-run or --yes (a script cannot answer the confirmation prompt)`.
A document is written exactly when the run exits `0` or `1` (including an interrupt
after the plan, where unstarted servers are `pending` with `"error_kind":
"canceled"`); exit-`3` tool errors print no document. Each server carries its
`class` (`converged`, `change`, `refused`, `unreachable`), its `outcome` (`applied`,
`refused`, `failed`, `pending` for a `change` server, `null` otherwise — always
`pending` under `--dry-run`), its `error`, and its `changes` (`add`, `remove`,
`rewrite` with `loosens` naming dropped restrictive options verbatim, `normalize`).
Comments and options are sanitized (control and Unicode format characters
removed), so they may not byte-match the server line. A dry run over a mixed
fleet:

```json
{
  "schema": 1,
  "command": "apply",
  "dry_run": true,
  "edit": null,
  "summary": {
    "servers": 4,
    "skipped": 0,
    "converged": 1,
    "applied": 0,
    "pending": 1,
    "failed": 0,
    "refused": 1,
    "unreachable": 1,
    "exit_code": 1
  },
  "servers": [
    {
      "name": "db-1",
      "host": "10.0.0.9",
      "port": 22,
      "user": "deploy",
      "class": "refused",
      "outcome": null,
      "error": "1 key installed but manifest grants none — refusing to wipe",
      "changes": {
        "add": [],
        "remove": [],
        "rewrite": [],
        "normalize": {
          "reorder": false,
          "non_key_lines": 0,
          "duplicates": 0,
          "duplicate_options_differ": false,
          "whitespace": false
        }
      },
      "file_absent": false,
      "authorized_keys2_present": false,
      "disables_authorized_keys2": false,
      "notes": {}
    },
    {
      "name": "web-1",
      "host": "10.0.0.1",
      "port": 22,
      "user": "deploy",
      "class": "change",
      "outcome": "pending",
      "error": null,
      "changes": {
        "add": [
          {
            "owner": "bob",
            "fingerprint": "SHA256:zbv/nU7iZdO0fB0DalMI70dP6/yFD8sctXvvW4+OokY",
            "type": "ssh-ed25519",
            "comment": "bob"
          }
        ],
        "remove": [
          {
            "owner": null,
            "fingerprint": "SHA256:doxiASlJnKSD9j+JpVoWpfEFHjUrsF9ZYr+cir4FYjo",
            "type": "ssh-ed25519",
            "comment": "stray@laptop"
          }
        ],
        "rewrite": [
          {
            "owner": "alice",
            "fingerprint": "SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4",
            "type": "ssh-ed25519",
            "comment_change": {
              "from": "alice@old",
              "to": "alice@work"
            },
            "loosens": []
          }
        ],
        "normalize": {
          "reorder": false,
          "non_key_lines": 1,
          "duplicates": 0,
          "duplicate_options_differ": false,
          "whitespace": false
        }
      },
      "file_absent": false,
      "authorized_keys2_present": false,
      "disables_authorized_keys2": false,
      "notes": {}
    },
    {
      "name": "web-2",
      "host": "10.0.0.2",
      "port": 22,
      "user": "deploy",
      "class": "converged",
      "outcome": null,
      "error": null,
      "changes": {
        "add": [],
        "remove": [],
        "rewrite": [],
        "normalize": {
          "reorder": false,
          "non_key_lines": 0,
          "duplicates": 0,
          "duplicate_options_differ": false,
          "whitespace": false
        }
      },
      "file_absent": false,
      "authorized_keys2_present": false,
      "disables_authorized_keys2": false,
      "notes": {}
    },
    {
      "name": "web-3",
      "host": "10.0.0.3",
      "port": 22,
      "user": "deploy",
      "class": "unreachable",
      "outcome": null,
      "error": "dial tcp 10.0.0.3:22: connection refused",
      "error_kind": "unknown",
      "changes": {
        "add": [],
        "remove": [],
        "rewrite": [],
        "normalize": {
          "reorder": false,
          "non_key_lines": 0,
          "duplicates": 0,
          "duplicate_options_differ": false,
          "whitespace": false
        }
      },
      "file_absent": false,
      "authorized_keys2_present": false,
      "disables_authorized_keys2": false,
      "notes": {}
    }
  ]
}
```

See `internal/apply/testdata/json_*.golden.json` for every shape.

Rewrite rows show what changes on a key line, and a rewrite that **drops a
restrictive option** (`from=`, `command=`, `restrict`, `no-agent-forwarding`,
`no-port-forwarding`, `no-pty`, `no-user-rc`, `no-X11-forwarding`, `verify-required`,
`expiry-time=`, `permitopen=`, `permitlisten=`, `cert-authority`, `principals=`) or
**adds a relaxing option** (`no-touch-required` always, and `pty`,
`port-forwarding`, `agent-forwarding`, `X11-forwarding`, `user-rc` when both lines
carry `restrict`) is painted red and followed by a warning — highlighted, not
refused. Dropping `no-touch-required` tightens access and is not flagged:

```console
web-1 (deploy@10.0.0.1:22)
  ~  alice (alice@work)  SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  rewrite options: "from=\"10.0.0.5\",command=\"/usr/bin/pg_dump-wrapper\"" → (none)
  ~  (formatting)                                                                         normalize: removing 1 duplicate key line (some carry options different from the first copy)
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

### `sshepherd revoke`

Removes users, keys, or a user's access to named servers from the manifest — comments
preserved — and pushes the edit through `apply`'s pipeline (plan → confirm → guarded
write → verify → login probe), restricted to the servers whose rendered
`authorized_keys` changes.

```console
$ sshepherd revoke alice                       # offboard: alice and every access entry naming her
$ sshepherd revoke bob --server db-1           # bob loses db-1 only; his keys and other grants stay
$ sshepherd revoke --key ~/lost-laptop.pub     # one key: a fingerprint, a key line, or a .pub path
$ sshepherd revoke --key SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4
```

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--key KEY` | none | Key to revoke: a `SHA256:` fingerprint, a public-key line, or a `.pub` file path (repeatable) |
| `--server` | none | Remove the users' access to this server only (repeatable); the users and their keys stay |
| `--operator` | off | Confirm that a target is, or belongs to, an operator user (fleet-wide, protected) |
| `--no-apply` | off | Edit and save the manifest after confirmation; contact no server |
| `--config` | `sshepherd.yaml` | Path to the manifest |
| `--known-hosts` | `~/.ssh/known_hosts` | `known_hosts` path (strict checking) |
| `--parallel` | `32` | Max concurrent server connections |
| `--dry-run` | off | Plan and report only; never write (the manifest is not changed) |
| `--yes` | off | Skip the confirmation prompt (automation) |
| `--json` | off | Emit the plan and outcome as machine-readable JSON on stdout (needs `--dry-run` or `--yes`) |
| `--identity PATH` | none | Private key file to authenticate with, in addition to `ssh-agent` (repeatable); `~/` expands from `$HOME` |
| `--identity-passphrase-file FILE` | none | Default passphrase file for any encrypted `--identity` key |
| `--identity-passphrase KEY=FILE` | none | Passphrase file for one `--identity` key (repeatable); split at the **first** `=` — a key path containing `=` is unsupported |

**Users or keys, not both.** `revoke USER...` deletes each user and every `access:`
entry whose `user:` is that user (unknown users are listed and nothing happens).
`revoke --key KEY...` removes each key line from its owner; a user left with no keys
stays with `keys: []`. A `KEY` is a `SHA256:` fingerprint (pasted `ssh-keygen -lf`
output works), a public-key line (quote it), or a path to a `.pub` file holding
exactly one key. MD5 fingerprints, certificates (`*-cert.pub`) and private keys are
refused with the fix; an error never quotes a file's contents. A key the manifest
does not grant is refused too — `apply` already removes it; `sshepherd audit` shows
where it is installed.

**One server, not the whole user (`--server`).** `revoke USER... --server NAME...`
takes the named servers away from each user and changes nothing else — the user
entry, its keys and its other grants stay. (Unlike `apply --server`, which only
restricts which servers a run touches, `revoke --server` edits the grants.) An
explicit `servers:` list loses every occurrence of the server, and an entry left
empty is deleted (its comment moves on, as for a removed user). A wildcard grant
(`servers: ["*"]`) gets the server appended to `except:` — created right after
`servers:` when absent — so it keeps covering servers added later; a wildcard that
would then cover no current server is deleted, with a warning that later servers are
no longer granted automatically. Refused with exit `3` and nothing edited: `--server`
with `--key` (access is per user), with `--operator`, or on an operator user
(operators have every server by definition), `--server '*'` (use `revoke USER`), an
unknown server, and any user × server pair the user has no access to — every problem
is listed in one message. Only the trimmed servers are contacted, there is no
`scope:` line, and the save reminder ends `re-grants the removed access`.

```console
manifest edit: remove bob's access to web-1, db-1 (2 access entries changed, 1 removed, 1 server excepted) — 2 servers affected
```

```console
manifest edit: remove alice's access to web-1 (1 access entry removed)
manifest edit: remove bob's access to web-1 (1 access entry changed, 1 server excepted)
manifest edit: 2 changes — 1 server affected
warning: alice's wildcard grant is removed — it would cover no current server; servers added later are no longer granted to alice automatically
note: alice has no access left — 'sshepherd revoke alice' removes the user
warning: web-1 would have no granted keys — apply never empties a server, so the keys of alice, bob stay installed there; grant another user (or an operator) on web-1 first, or remove the key by hand
```

**The edit header** heads the plan:

```console
manifest edit: remove user alice (2 keys, 3 access grants) — 3 servers affected
warning: db-1 would have no granted keys — apply never empties a server, so alice's key stays installed there; grant another user (or an operator) on db-1 first, or remove the key by hand
```

```console
manifest edit: remove key SHA256:zbv/nU7iZdO0fB0DalMI70dP6/yFD8sctXvvW4+OokY from bob — 2 servers affected
note: bob has no keys left — 'sshepherd revoke bob' removes the user
```

**Scope.** Only servers whose rendered file changes are contacted, and on those the
full render also converges any other drift (shown in the plan). A revoked key still
installed on a server that never granted it is drift `revoke` does not reach — the
run ends with a `scope:` line pointing at `sshepherd audit` and `sshepherd apply`.

**Confirmation.** `revoke` always asks — even when every affected server already
matches, since the manifest edit is itself a change — or needs `--yes`. The prompt
names what will happen (all forms, from the golden test):

```console
save manifest edit and write 2 of 3 affected servers? [y/N]
save manifest edit (no servers need a write)? [y/N]
save manifest edit (no servers need a write)? [y/N]
save manifest edit? [y/N]
OPERATOR ops-bot: save manifest edit and write 1 of 4 affected servers? [y/N]
OPERATOR ops-bot: OPERATOR ci: save manifest edit? [y/N]
```

Declining exits `1` with `aborted; manifest not changed, nothing written`. When no
affected server can converge (every one refused), nothing is saved and the run
exits `1` without a prompt. `--dry-run` saves nothing and exits exactly as
`apply --dry-run` would. After the save the run prints
`manifest PATH updated — commit and push it: …`; servers left unconverged (failed,
refused for a fixable reason, unreachable, interrupted) are named in a ready-made
`sshepherd apply --server …` command.

**`--no-apply`** shows the header, asks, saves, and contacts nothing; it refuses
`--identity*`, `--known-hosts` and `--parallel` (they would be silently unused).
`--dry-run --no-apply` prints the header only.

**JSON.** Under `--json` (see [`apply`](#sshepherd-apply)) the document adds an
`edit` section — `saved` (the manifest was written: `false` under `--dry-run` and
when nothing could land), `edits` (one per change, fields by `kind`:
`remove-user`, `remove-key`, `rotate` (with `keep_old`), `remove-access`
(`access_servers`, `entries_changed`, `entries_removed`, `servers_excepted`,
`wildcards_removed`, `no_grants_left`)), `affected`, `operators` and `emptied` — and a
removed key the edited manifest no longer owns carries `former_owner`. `--no-apply`
prints the edit section with `servers: []`. `revoke --no-apply --json` still needs
`--yes` (or `--dry-run`). The shape, from the revoke golden fixture (`former_owner`
on removed keys, and `db-1` named in `emptied` because the revoke would leave it
with no granted keys):

```json
{
  "schema": 1,
  "command": "revoke",
  "dry_run": false,
  "edit": {
    "saved": true,
    "edits": [
      {
        "kind": "remove-user",
        "user": "alice",
        "keys": 1,
        "grants": 1
      }
    ],
    "affected": 1,
    "operators": [],
    "emptied": [
      {
        "server": "db-1",
        "users": [
          "carol"
        ],
        "keys": 1
      }
    ]
  },
  "summary": {
    "servers": 1,
    "skipped": 0,
    "converged": 0,
    "applied": 0,
    "pending": 1,
    "failed": 0,
    "refused": 0,
    "unreachable": 0,
    "exit_code": 1
  },
  "servers": [
    {
      "name": "web-1",
      "host": "10.0.0.1",
      "port": 22,
      "user": "deploy",
      "class": "change",
      "outcome": "pending",
      "error": null,
      "changes": {
        "add": [
          {
            "owner": "bob",
            "fingerprint": "SHA256:LA4QoSmstGCy/UHfdU3jKjnPz56pQzud9OmslMh3g8w",
            "type": "ssh-ed25519",
            "comment": "bob"
          }
        ],
        "remove": [
          {
            "owner": null,
            "former_owner": "alice",
            "fingerprint": "SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4",
            "type": "ssh-ed25519",
            "comment": "alice@work"
          },
          {
            "owner": null,
            "former_owner": "bob",
            "fingerprint": "SHA256:zbv/nU7iZdO0fB0DalMI70dP6/yFD8sctXvvW4+OokY",
            "type": "ssh-ed25519",
            "comment": "bob"
          },
          {
            "owner": null,
            "fingerprint": "SHA256:doxiASlJnKSD9j+JpVoWpfEFHjUrsF9ZYr+cir4FYjo",
            "type": "ssh-ed25519",
            "comment": "stray"
          }
        ],
        "rewrite": [],
        "normalize": {
          "reorder": false,
          "non_key_lines": 0,
          "duplicates": 0,
          "duplicate_options_differ": false,
          "whitespace": false
        }
      },
      "file_absent": false,
      "authorized_keys2_present": false,
      "disables_authorized_keys2": false,
      "notes": {}
    }
  ]
}
```

**Operators.** A target that is, or belongs to, an `operator: true` user refuses the
whole command until you pass `--operator` (and `--operator` with no operator target
is refused too); `--yes` never substitutes for it. With it, the header carries an
`OPERATOR:` line, the prompt is prefixed `OPERATOR NAME: `, and revoking an
operator's last key also clears its `operator:` flag. The lockout guard still
applies on top.

**Limitations.**

- **A server is never emptied.** If the revoked user was a server's only grantee,
  the header warns (`would have no granted keys`), that server is refused, and the
  key stays installed — grant another user (or an operator) there first, or remove
  the key by hand.
- **Anchors and aliases.** A manifest using YAML anchors/aliases (or null list
  entries) cannot be edited faithfully:
  `cannot edit PATH: … — edit the manifest by hand and run 'sshepherd apply'`.
- **Fidelity.** Comments are preserved: a removed entry's comment moves to the next
  entry (or the section's end); a removed key line's own comment goes with it. Blank
  lines and quoting may normalize — review the `git diff` before you commit.

**Recipe: offboard someone.**

```console
$ sshepherd revoke alice --dry-run
$ sshepherd revoke alice
$ git commit -am "offboard alice" && git push
$ sshepherd audit
```

**Recipe: a lost laptop.**

```console
$ sshepherd revoke --key ~/keys/alice-laptop.pub
$ git commit -am "revoke alice's laptop key" && git push
$ sshepherd audit
```

**Recipe: take one server away.**

```console
$ sshepherd revoke bob --server db-1 --dry-run
$ sshepherd revoke bob --server db-1
$ git commit -am "bob: no more db-1" && git push
```

### `sshepherd rotate`

Replaces one of a user's keys in place and pushes the swap the same way: the old key
is dead fleet-wide in the same run — unless `--keep-old` (below).

```console
$ sshepherd rotate deploy --old SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o --new ~/.ssh/deploy_2027.pub
```

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--old KEY` | — | Key to rotate out: a `SHA256:` fingerprint, a public-key line, or a `.pub` file path |
| `--new KEY` | — | Key to rotate in: a public-key line or a `.pub` file path |
| `--keep-old` | off | Add the new key alongside the old one instead of replacing it (overlap; the new key keeps the old line's options, `expiry-time` included); finish later with `sshepherd revoke --key OLD` |
| `--operator` | off | Confirm that the user is an operator (fleet-wide, protected); the flag is kept |
| `--no-apply` | off | Edit and save the manifest after confirmation; contact no server |
| `--config` | `sshepherd.yaml` | Path to the manifest |
| `--known-hosts` | `~/.ssh/known_hosts` | `known_hosts` path (strict checking) |
| `--parallel` | `32` | Max concurrent server connections |
| `--dry-run` | off | Plan and report only; never write (the manifest is not changed) |
| `--yes` | off | Skip the confirmation prompt (automation) |
| `--json` | off | Emit the plan and outcome as machine-readable JSON on stdout (needs `--dry-run` or `--yes`) |
| `--identity PATH` | none | Private key file to authenticate with, in addition to `ssh-agent` (repeatable); `~/` expands from `$HOME` |
| `--identity-passphrase-file FILE` | none | Default passphrase file for any encrypted `--identity` key |
| `--identity-passphrase KEY=FILE` | none | Passphrase file for one `--identity` key (repeatable); split at the **first** `=` — a key path containing `=` is unsupported |

- Exactly one `--old` and one `--new`; a repeated flag is refused
  (`rotate takes exactly one --old (got 2)`), never resolved to the last value.
- `--old` must belong to `USER`; `--new` must not already be in the manifest and
  must differ from `--old`.
- The new line replaces the old at the same position. The old line's **options**
  (`from=`, `command=`, `restrict`, …) carry over; options written on `--new` are
  refused (`rotate keeps the old line's options; edit them in the manifest`).
- The **comment** is the new key's, else the old line's inline comment.
- A carried-over `expiry-time=` that has already passed is refused before any edit
  (the new key would be rejected by sshd); a future one is named in the header.
- Confirmation, saving, `--dry-run`, `--no-apply`, operators and the scope line work
  exactly as for `revoke` (no scope line under `--keep-old`: nothing is removed).
- Under `--json` the document carries the same `edit` section as `revoke`'s, with a
  `rotate` entry (`user`, `fingerprint`, `new_fingerprint`, `keeps_expiry` when
  an `expiry-time=` carries over, and `keep_old` (always present on `rotate` entries;
  `false` for a plain rotation)); the rotated-out key's `remove` entry names its
  `former_owner`.

```console
manifest edit: rotate deploy key SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o → SHA256:LA4QoSmstGCy/UHfdU3jKjnPz56pQzud9OmslMh3g8w (keeps expiry-time="20270101") — 5 servers affected
```

**Recipe: rotate a key.**

```console
$ ssh-keygen -t ed25519 -f ~/.ssh/deploy_2027
$ sshepherd rotate deploy --old SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o --new ~/.ssh/deploy_2027.pub --dry-run
$ sshepherd rotate deploy --old SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o --new ~/.ssh/deploy_2027.pub
$ git commit -am "rotate the deploy key" && git push
$ sshepherd audit
```

**Overlap (`--keep-old`).** For a key held by running systems (CI deploy keys,
automation) that cannot all switch at once: the new key is added right after the old
one instead of replacing it. It carries the old line's options, `expiry-time=`
included (a passed one is refused, as for a plain rotation), and the header says
`keeps the old key`. Nothing marks the overlap: the manifest simply lists both keys,
`audit` sees both as granted and `apply` keeps both — so the save reminder warns that
an apply from a copy without the edit removes the new key. The run ends (text mode
only; never under `--json` or `--dry-run`, nor when nothing was saved) with the exact
command that finishes the overlap once every client uses the new key —
`sshepherd revoke --key OLD`, plus `--config` when not the default and `--operator`
for an operator, whose hint gets a second line about `--identity`. It reads
`overlap started — …` when every affected server holds both keys,
`overlap incomplete — N servers do not have the new key yet …` after a partial run,
`overlap recorded, not pushed — …` under `--no-apply`, and
`new key recorded — USER has no grants yet …` when no server is affected.
`--keep-old` again on the same old key adds another key; a plain `--old OLD` during
an overlap replaces the old key.

```console
manifest edit: rotate bob key SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o → SHA256:LA4QoSmstGCy/UHfdU3jKjnPz56pQzud9OmslMh3g8w (keeps the old key; keeps expiry-time="20270101") — 3 servers affected
```

A `--no-apply` overlap, as printed:

```console
manifest edit: rotate deploy key SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o → SHA256:LA4QoSmstGCy/UHfdU3jKjnPz56pQzud9OmslMh3g8w (keeps the old key; keeps expiry-time="20270101") — 2 servers affected
manifest sshepherd.yaml updated — commit and push it: an apply from a copy without this edit removes the new key — clients that already switched would be locked out
no servers contacted — 2 affected servers still carry the old keys; run 'sshepherd apply --server web-1 --server web-2' to push
overlap recorded, not pushed — run the apply hint above, then, once every client uses the new key, finish with: sshepherd revoke --key SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o
```

**Recipe: overlap a deploy key.**

```console
$ ssh-keygen -t ed25519 -f ~/.ssh/deploy_2027
$ sshepherd rotate deploy --old SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o --new ~/.ssh/deploy_2027.pub --keep-old
$ git commit -am "deploy key: start the 2027 overlap" && git push
$ # … switch every client to ~/.ssh/deploy_2027 …
$ sshepherd revoke --key SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o
$ git commit -am "deploy key: end the overlap" && git push
```

**Rotating the key you log in with.** Pass the new private key with `--identity`, so
the lockout guard sees it survive and the post-write login probe proves it — headless
too:

```console
$ sshepherd rotate ci --operator --old ~/.ssh/ci_old.pub --new ~/.ssh/ci_new.pub \
    --yes --identity ~/.ssh/ci_old --identity ~/.ssh/ci_new
$ git commit -am "rotate the ci key" && git push
$ sshepherd audit --identity ~/.ssh/ci_new
```

## Authentication

`audit`, `adopt`, `apply`, `revoke` and `rotate` authenticate with the union of two
sources, like `ssh -i` (`revoke` and `rotate` write through `apply`'s pipeline, so
everything said about `apply` below holds for them too):

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
  → 1 key desired · 1 add · 0 remove · 0 rewrite
```

Guard refusals list every key you hold with its source:

```console
web-1 (deploy@10.0.0.1:22)  REFUSED: none of the 2 keys you hold (identity files + agent) would remain in web-1's authorized_keys — applying would lock this session out (held: SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o (/home/ci/.ssh/ci_old), SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4 (agent)). Add one of your keys to the manifest (or mark its user operator: true); rotating an --identity key? pass the new key with another --identity, so the guard and the post-write login probe can use it
```

**Headless key rotation.** Run `rotate` with both keys: the write logs in with the
old key, the guard sees the new key survive, and the post-write probe (which offers
surviving key files first) proves the new key logs in. Then commit and push the
manifest; a later run needs only the new key.

```console
$ sshepherd rotate ci --operator --old ~/.ssh/ci_old.pub --new ~/.ssh/ci_new.pub \
    --yes --identity ~/.ssh/ci_old --identity ~/.ssh/ci_new
$ git commit -am "rotate the ci key" && git push
$ sshepherd audit --identity ~/.ssh/ci_new
```

If you replaced `ci_old` with `ci_new` in the manifest by hand, the same two
`--identity` flags work with plain `apply`:

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
    # Pin the digest you verified with `cosign verify` (see Releases), never
    # :latest, for an unattended `apply --yes`.
    image: ghcr.io/javadh75/sshepherd:<version>@sha256:<digest>
    args: ["apply", "--yes", "--identity", "/secrets/ci",
           "--identity-passphrase-file", "/secrets/ci.pass",
           "--config", "/config/sshepherd.yaml", "--known-hosts", "/config/known_hosts"]
    securityContext:
      runAsNonRoot: true
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities: {drop: ["ALL"]}
      seccompProfile: {type: RuntimeDefault}
    volumeMounts:
      - {name: secrets, mountPath: /secrets, readOnly: true}
      - {name: config, mountPath: /config, readOnly: true}
securityContext:
  fsGroup: 65532
volumes:
  - name: secrets
    secret: {secretName: sshepherd-ci, defaultMode: 0440}
  - name: config
    configMap: {name: sshepherd-config}   # sshepherd.yaml and known_hosts
```

Get the digest with `docker buildx imagetools inspect ghcr.io/javadh75/sshepherd:<version> --format '{{.Manifest.Digest}}'`,
then verify it as shown under Releases. `apply` writes nothing to the local
filesystem, so `readOnlyRootFilesystem` is safe here; `revoke`/`rotate` edit the
manifest, so mount it from a writable volume for those.

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

Monitoring-style, shared by `audit`, `apply`, `revoke` and `rotate` (code `2` is
`audit`-only):

| Code | Meaning |
| ---- | ------- |
| `0` | Compliant / converged — nothing to do |
| `1` | Drift, unreachable servers, or pending changes — compliance not proven |
| `2` | `audit` only: **critical** drift (a server is missing an operator key), or a server whose host key **changed** or is `@revoked` in `known_hosts` (possible impersonation) — `apply`, `revoke` and `rotate` never return `2` |
| `3` | Tool error — bad flags, unloadable manifest, failed preflight, an `--identity` key that cannot be read, is refused, or has no passphrase source, interrupted `audit`/`adopt`, `apply` interrupted before any write, a manifest that changed since it was read, a `revoke`/`rotate` refused before anything is saved (unknown user or key, an unknown or ungranted `--server`, an operator target without `--operator`, a manifest the edits cannot handle or that is not a regular file, a concurrent save) |

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

**Manifest edits save before they write.** `revoke` and `rotate` save the edited
manifest exactly once — after the confirmation and before the first server is
written — under a lock (`.NAME.sshepherd-lock` next to the manifest, never deleted),
only if the file still holds the bytes the run read (otherwise
`manifest PATH changed since it was read; re-run`), atomically (a temp file with the
original's mode and owner, fsynced, renamed over the file; a symlinked manifest is
saved at its target; a piped manifest — `--config /dev/stdin`, `<(...)` — is refused
before any edit, since there is no file to save). The worst crash leaves the manifest ahead of the fleet —
reported by `audit`, finished by any `apply` — never a revoked key the next `apply`
reinstalls. **Commit and push the manifest afterwards**: an `apply` run from a copy
without the edit grants the removed key again.

**Plain `apply` re-checks the manifest.** Just before its first write, `apply`
re-reads the manifest; if a concurrent `revoke` (or anything else) changed it since
the plan was made, the run stops with nothing written (`exit 3`) instead of
reinstalling a revoked key. A manifest piped in (`--config /dev/stdin`,
`--config <(...)`) cannot be re-read, so the check is skipped for it.

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
different Go toolchain, and `make gosec` fails if gosec cannot type-check the code. The gate supports the Go 1.27 line (what CI runs): when the
`go` on your `PATH` is from another line (e.g. Homebrew's newest), every `make`
target — and the pre-push hook, which goes through `make` — runs under the pinned
`go1.27.3` instead, which the `go` command downloads once. Set `GOTOOLCHAIN`
yourself (`make GOTOOLCHAIN=local …`) to override.

The gate includes `gofmt`, `go vet`, `golangci-lint`, whole-program `deadcode`,
`gosec`, `govulncheck`, and `gitleaks`; `go vet`, `golangci-lint` and `gosec` also
cover the `//go:build integration` test files (gosec through golangci-lint, since
standalone gosec skips test files; name them `*integration_test.go` or
`*e2e_test.go`). Container work has its own targets:
`make docker` (passes `--build-arg VERSION=$(git describe --tags --always --dirty)`,
overridable with `VERSION=`), `docker-lint` (hadolint + dockle), `docker-scan`
(Trivy), and `smoke` — `scripts/docker-gates.sh`: `--version` and `--help`, the
binary's ELF architecture matches the image platform, an image size budget under
30 MB (`SIZE_BUDGET_MB`), a non-root user check, and the PID-1 SIGTERM gate.
`scripts/docker-gates.sh [--platform OS/ARCH] [--pull] [IMAGE]` checks one variant of
any local or registry image. The Dockerfile cross-compiles on the build host's
platform, so a multi-arch `docker buildx` build never runs the compiler under QEMU. CI builds
and gates the image natively on amd64 and arm64. CI also runs `govulncheck` and every fuzz
target daily, and Trivy-scans the published `latest` image for both architectures (job
`published-image-scan`, "Published image CVEs"). Before the first `vX.Y.Z` tag there is
nothing to scan and the job passes. After that, a registry error fails it.

**Releases.** Pushing a `vMAJOR.MINOR.PATCH` tag runs `.github/workflows/release.yml`.
It refuses a tag whose commit is not on `master`, then runs `make check` (including
`govulncheck` on the exact Go the image ships) and `make integration`. It builds the
`linux/amd64` + `linux/arm64` image once (arm64 is cross-compiled) and pushes it by
digest only. It lints the Dockerfile with hadolint and Trivy config before the build.
Then it gates that exact digest on native amd64 and arm64 runners with Trivy (fails on
HIGH/CRITICAL), dockle and `scripts/docker-gates.sh`. Only
when every job passes does it tag the digest with semver tags (`latest` last, and only
for the newest release), sign it keyless with cosign, attach signed build provenance,
and verify that signature with the command below. A manual `workflow_dispatch` run is
a dry run: every job except the publishing one, even one dispatched on a tag. Verify an image before you run it
(requires cosign v3.1.4 or newer, the `COSIGN_VERSION` in release.yml; older cosign v2
may report "no signatures found"):

```console
$ cosign verify ghcr.io/javadh75/sshepherd@<digest> \
    --certificate-identity-regexp '^https://github\.com/javadh75/SSHepherd/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-github-workflow-trigger push \
    --certificate-github-workflow-repository javadh75/SSHepherd
```

This accepts only signatures made by `release.yml` running on a release tag. Use the
same identity in an admission policy. Check the provenance with
`gh attestation verify oci://ghcr.io/javadh75/sshepherd@<digest> --repo javadh75/SSHepherd`.
The latest release is scanned for CVEs daily and gets patch releases; older tags are
not re-scanned.

Release recovery:

1. **A gate or check flakes:** `gh run rerun <run-id> --failed`. Successful jobs keep
   their outputs, so the same digest is gated and published.
2. **release.yml itself is wrong:** fix it on master and tag `vX.Y.Z+1`. Never re-tag:
   the `v*` tag ruleset forbids moving or deleting a tag, and a re-run always uses the
   tagged commit's workflow.
3. **A published release is bad:** move `latest` back to the previous signed digest
   with `docker buildx imagetools create --tag ghcr.io/javadh75/sshepherd:latest ghcr.io/javadh75/sshepherd@<previous signed digest>`,
   then run the `cosign verify` above against it, then cut a fixed `vX.Y.Z+1`.
4. **A release run was cancelled while queued:** GitHub keeps only one pending run in
   the `release` concurrency group, so a third tag pushed while one release runs and
   another waits cancels the waiting one. Nothing was tagged or signed. Re-run it once
   the queue drains: `gh run rerun <run-id>`.

Every release tag must point at a commit at or after `ca50409`, the commit that fixed
the gated release workflow; older commits run an ungated release workflow or one whose
publish step always fails.

Test kinds in the repo: unit (table-driven), integration (real `sshd` in Docker,
build-tagged), end-to-end (the CLI binary through adopt → apply → audit), fuzz
(every parser, with a committed seed corpus), benchmarks, race, goroutine-leak
checks (`goleak` in every package), and golden snapshots of rendered output.

### Layout

```
cmd/sshepherd/       CLI: root command, audit, import, adopt, apply, revoke, rotate, E2E tests
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
internal/manifest/   comment-preserving manifest edits (append, remove, replace, operator flag)
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
[`docs/superpowers/specs/2026-10-16-identity-keyfile-auth-design.md`](docs/superpowers/specs/2026-10-16-identity-keyfile-auth-design.md);
`revoke` and `rotate` in
[`docs/superpowers/specs/2026-10-23-revoke-rotate-design.md`](docs/superpowers/specs/2026-10-23-revoke-rotate-design.md),
and `revoke --server` / `rotate --keep-old` in
[`docs/superpowers/specs/2026-11-07-revoke-server-keep-old-design.md`](docs/superpowers/specs/2026-11-07-revoke-server-keep-old-design.md).
Revocation memory (tombstones, a manifest serial, an opt-in post-revoke sweep, no
adopt wildcard) is a draft awaiting owner decisions, not yet built:
[`docs/superpowers/specs/2026-11-08-revocation-memory-design.md`](docs/superpowers/specs/2026-11-08-revocation-memory-design.md).

## License

[Apache License 2.0](LICENSE) — permissive, with an explicit patent grant.

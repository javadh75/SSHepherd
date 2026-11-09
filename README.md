# SSHepherd

[![CI](https://github.com/javadh75/SSHepherd/actions/workflows/ci.yml/badge.svg)](https://github.com/javadh75/SSHepherd/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Manage SSH `authorized_keys` across a fleet of servers from a single source of truth.**

Declare who should have access to which machines in one YAML manifest. SSHepherd
reads every managed `authorized_keys` file, tells you exactly how each differs from
the manifest, and converges the fleet — adding keys, revoking keys, and rotating
credentials without hand-editing `authorized_keys` or losing track of who can log in
where.

```console
$ sshepherd audit
web-1 (deploy@10.0.0.1:22)
  ✓  alice (alice@sshepherd)  SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8  ssh-ed25519  present & authorized
  ✗  bob                      SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  authorized but MISSING
  ⚠  (unknown) "who@is-this"  SHA256:doxiASlJnKSD9j+JpVoWpfEFHjUrsF9ZYr+cir4FYjo  ssh-ed25519  installed but UNAUTHORIZED
  ⚠ line 3: unparseable entry
  → 2 authorized · 1 present · 1 missing · 1 unauthorized

web-2 (deploy@10.0.0.2:22)  ERROR [dial]: dial tcp 10.0.0.2:22: connect: connection refused
  hint: check the host, port, and firewall; hosts reachable only through a bastion (ProxyJump/ProxyCommand) are dialed directly — jump hosts are not supported yet

Summary: 0/2 servers compliant · 1 with drift (0 critical) · 1 unreachable  → exit 1
```

---

## Why

Managing SSH keys by hand across many servers is error-prone and hard to audit.
You SSH into each box to edit `authorized_keys`, you lose track of who has access
to what, and revoking a departed colleague's access reliably is painful.
SSHepherd centralizes and automates this:

- **Central source of truth** — users, keys, and grants live in one manifest.
- **Audit** — check that every managed `authorized_keys` file holds exactly the
  manifest's keys, in text or JSON. It does not see other accounts on the host or
  sshd's other key sources (see [Per-server `authorized_keys_file`](#per-server-authorized_keys_file)).
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
| `validate` | ✅ | Offline manifest check: schema, policy conflicts, host-key coverage (text + `--json`, `--strict`) |
| `import` | ✅ | Convert an OpenSSH client config into a starter manifest (`--merge` supported, text + `--json`) |
| `adopt`  | ✅ | Read the live fleet and generate a manifest that accounts for every installed key (`--merge` supported, text + `--json`) |
| `apply`  | ✅ | The write path: plan → confirm → guarded atomic write → verify → login probe (text + `--json`) |
| `revoke` / `rotate` | ✅ | Comment-preserving manifest edit + `apply` over the affected servers: offboard a user, take away one server (`--from-server`), drop a lost key, swap a key in place or overlap old and new (`--keep-old`) (text + `--json`) |

`audit`, `adopt`, `apply`, `revoke` and `rotate` authenticate with the SSH agent,
`--identity` key files, or both — so they also run headless in CI, cron and containers (see
[Authentication](#authentication)).

Revocation memory: `revoked:` tombstones and a manifest `serial:`; revoke/rotate record
and bump them, apply refuses a server written by a newer manifest unless the write only
removes keys, audit pages on a revoked key still installed, adopt and `import --merge`
never bring one back, `revoke --sweep` checks the rest of the fleet.

Audit trust and posture: audit checks the managed file and its directories the way StrictModes does, and pages on a world-writable path, an operator key that cannot log in, a host key whose type changed, and a weak key granted on a server. Each server is offered only its granted keys (`--offer-all-keys` restores the old offer).

Tags: `tags:` on a server and `@tag` selectors in `access:` mix with names, `except:` works on any selector, a tombstone blocks a tag-derived grant instead of conflicting, and a `*` reaching a root account warns (kind `wildcard_root`).

## Install

**From source** (Go 1.27.3+):

```console
$ go install github.com/javadh75/SSHepherd/cmd/sshepherd@latest
```

`go install github.com/javadh75/SSHepherd/cmd/sshepherd@vX.Y.Z` reports `vX.Y.Z` in
`sshepherd --version`. `make build` stamps `git describe --tags --always --dirty`
(for example `sshepherd 56713ff-dirty`). A plain `go build` inside a checkout reports
the Go VCS pseudo-version, for example
`sshepherd v0.0.0-20261108032608-56713ff9ffb0+dirty`.

**Release binaries** — each release attaches static binaries named
`sshepherd_vX.Y.Z_{linux,darwin}_{amd64,arm64}`, plus `SHA256SUMS` and its keyless
signature bundle `SHA256SUMS.sigstore.json`. Verify the checksums file, then the binary
(requires cosign v3.1.4 or newer, the `COSIGN_VERSION` in release.yml):

```console
$ cosign verify-blob --bundle SHA256SUMS.sigstore.json \
    --certificate-identity "https://github.com/javadh75/SSHepherd/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
$ sha256sum -c --ignore-missing SHA256SUMS
```

The darwin binaries are not notarized; after verifying the checksum and signature, run
`xattr -d com.apple.quarantine ./sshepherd_*_darwin_*`.

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
- **For every read (`audit`, `adopt`, and the plan of `apply`, `revoke` and `rotate`):**
  `id`, `ls` and `dirname` under `/bin/sh` on each server, for the posture probe. A
  server where the probe fails is reported unreachable (`error_kind: remote`, exit `1`),
  never graded clean.

## Quick start

### 1. Get a manifest

Bootstrap from the fleet you already run, into one manifest. `adopt` reads the
servers from a manifest, so list them first — `import --servers-only` takes them from
your SSH client config — then let `adopt --merge` write a copy of that file with every
key actually installed on them added, review the difference, and keep the copy:

```console
$ sshepherd import --servers-only -o sshepherd.yaml         # servers from ~/.ssh/config
$ sshepherd adopt --merge -o adopted.yaml                   # sshepherd.yaml plus every installed key
$ diff -u sshepherd.yaml adopted.yaml                       # review what adopt added
$ mv adopted.yaml sshepherd.yaml
```

`adopt --merge` keeps the manifest's text (comments intact) and appends the
discovered users and grants under a dated marker; it never modifies its input. Without a manifest, every command
says so and points here:
`no manifest at sshepherd.yaml — create one with 'sshepherd import --servers-only -o sshepherd.yaml', or pass --config PATH`.

Or bootstrap users too from your local SSH client config — `import` resolves each
concrete `Host` to the host/port/user `ssh` would use and derives users from the
`.pub` files next to each `IdentityFile`:

```console
$ sshepherd import ~/.ssh/config -o sshepherd.yaml
```

Both commands only ever *emit* a manifest — review it before you trust it.

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
  +  bob                       SHA256:zbv/nU7iZdO0fB0DalMI70dP6/yFD8sctXvvW4+OokY  ssh-ed25519  add (authorized, missing)
  -  (unknown) "stray@laptop"  SHA256:doxiASlJnKSD9j+JpVoWpfEFHjUrsF9ZYr+cir4FYjo  ssh-ed25519  remove (unauthorized)
  ~  alice (alice@work)        SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  rewrite comment: "alice@old" → "alice@work"
  ~  (formatting)                                                                               normalize: removing 1 non-key line (comments/blank)
  → 2 keys desired · 1 add · 1 remove · 1 rewrite

web-2 (deploy@10.0.0.2:22)  converged (no changes)

web-3 (deploy@10.0.0.3:22)  ERROR [dial]: dial tcp 10.0.0.3:22: connect: connection refused
  hint: check the host, port, and firewall; hosts reachable only through a bastion (ProxyJump/ProxyCommand) are dialed directly — jump hosts are not supported yet

apply 1 of 4 servers? [y/N]
```

Without a TTY and without `--yes`, `apply` refuses rather than assuming consent —
so a CI job that forgot `--yes` fails instead of writing unattended.

### 4. Offboard someone

```console
$ sshepherd revoke alice                              # edit the manifest and push it to every affected server
$ git commit -am "offboard alice" && git push         # publish the edit
$ sshepherd audit                                     # the command the run prints; exits 2 while a revoked key is still installed
```

Running `revoke` with its apply phase (not `--no-apply`) is what stops an older copy
of the manifest from re-granting alice: every affected server learns the new serial.

`revoke` removes the user and every `access:` entry naming them, keeps the
manifest's comments, and writes only the servers whose rendered `authorized_keys`
changes. See [`sshepherd revoke`](#sshepherd-revoke) and
[`sshepherd rotate`](#sshepherd-rotate).

## The manifest

One YAML file — by default `sshepherd.yaml` — with three sections, plus the optional
`serial:` and `revoked:` (see [Revoked keys](#revoked-keys)). Unknown fields
are **rejected**, so a typo like `commment:` fails loudly instead of being silently
ignored. The file must be a **single YAML document**: a `---` separator (even a
trailing empty one) or concatenated files fail with
`manifest contains multiple YAML documents`.

```yaml
serial: 7                               # optional; absent = 0. Integer 0..9007199254740991
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
    tags: [prod, web]                   # optional, see Tags and selectors

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

revoked:                                # optional; revoke/rotate append; deleting an entry = deliberate un-revoke
  - fingerprint: SHA256:abc…            # key entry: this key may never be listed again
    user: carol                         # optional label: the former owner; need not exist
    date: 2026-11-08                    # YYYY-MM-DD, required
    reason: offboarded                  # optional free text
  - user: bob                           # access entry: no fingerprint
    servers: [db-1]                     # bob is never re-granted db-1
    date: 2026-11-08
```

### Operator users

`operator: true` grants a user **every** server implicitly — no `access:` entry
needed — and marks their keys as protected management keys:

- `audit` renders a missing operator key as **CRITICAL** (exit code 2), because that
  is the drift class that threatens your ability to reach the fleet at all.
- `apply` writes operator keys **first** in every rendered file.
- `import --operator-key <key-file>` marks a key's owner as an operator at import time.

A weak operator key freezes every grant on every server: apply refuses each one until `rotate` replaces it. Removals still land.

### Wildcard access

`servers: ["*"]` grants every server currently in the manifest *and* every server
added later, minus anything listed in `except:`. Use it for people (or automation)
whose access should not need updating each time the fleet grows.

A non-operator `servers: ["*"]` entry that reaches a server whose `user` is `root` warns
once per entry, kind `wildcard_root`:
`access for "alice": servers ["*"] includes the root account on web-1 and 3 more; list the servers or use an @tag that excludes root accounts`
(with one root account, `on web-1;`). An `@tag` reaching root does not warn. A warning never
changes an exit code, except that `validate --strict` exits `1`.

### Tags and selectors

```yaml
servers:
  - name: web-1
    host: 10.0.1.5
    user: deploy
    tags: [prod, web]
access:
  - user: carol
    servers: ["@prod", db-1]   # selectors and names mix (union)
    except: [web-3]            # valid with "*" or any "@tag"
```

A tag matches `^[a-z0-9][a-z0-9._-]{0,62}$`, and a tag may not repeat on a server. In an
`access:` entry, `@tag` reaches every server carrying the tag, in manifest order, and
mixes with server names as a union. `except:` removes names from what the selectors reach; it
needs `*` or at least one `@tag`, and each name must be a known server. A name may not be in
both `servers:` and `except:`. An `@tag` matching no server is an error, like an unknown
server name: `access for "carol": unknown tag "@prd"`. Fix the typo, or tag a server. A tag
covers only servers in the manifest now: only `*` covers servers added later, and a new
server joins a tag's grants when you tag it.

### Per-server `authorized_keys_file`

For servers whose sshd reads keys from somewhere other than the default
`~/.ssh/authorized_keys`. The value is the **resolved path** of the file to manage —
sshd's `%u`/`%h`/`%%` tokens are *not* expanded, so `%` is rejected (write
`/etc/ssh/authorized_keys/deploy`, not `/etc/ssh/authorized_keys/%u`). It must be
absolute (`/...`) or home-relative with an explicit `~/` prefix, must name a file
(a trailing `/` is rejected), and may not contain control, format or line-separator
characters. It is POSIX-single-quote escaped before it reaches a remote shell.

When the effective path is the default — or any spelling that resolves on the server
to the login user's `~/.ssh/authorized_keys`, such as `/home/alice/.ssh/authorized_keys`
or a symlink to that existing file — `audit` also checks whether
`~/.ssh/authorized_keys2` — OpenSSH's compiled-in second `AuthorizedKeysFile` —
exists and is non-empty, and reports it as drift. SSHepherd never reads its keys;
`apply` moves it aside to `~/.ssh/authorized_keys2.sshepherd.disabled` whenever it
writes that server (see [Safety model](#safety-model)), so a revoked key cannot keep
logging in from it. Audit reads only the managed file (and, on the default path or an
equivalent spelling, checks `authorized_keys2`). It does not see sshd's other key sources — a custom
`AuthorizedKeysFile` list in `sshd_config`, `AuthorizedKeysCommand`,
`TrustedUserCAKeys`, `AuthorizedPrincipalsFile`/`AuthorizedPrincipalsCommand` — or
other accounts on the same host. Point `authorized_keys_file` at the file sshd
actually reads.

Audit's permission check walks an override path outside `$HOME` up to `/`. A symlinked managed file is drift (exit 1), and a root-owned override audits clean although `apply` refuses to write it.

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
  `command`, `from` and `principals` may appear once per line. sshd rejects a line
  that repeats one, so the loader does too:
  `user "alice" key 1: option "command=\"echo B\"" repeats command=, which sshd allows once per line`.
  `permitopen`, `permitlisten` and `environment` may repeat.
- **Server `name`, `host` and `user`** may not contain whitespace or control, format
  or line-separator characters (U+2028/U+2029 included).
- **Server names starting with `@`** are reserved for tag selectors, like `*` for wildcard
  grants: `servers[N]: name "@x" is reserved for tag selectors`.
- **Tags** must match `^[a-z0-9][a-z0-9._-]{0,62}$`, and a tag may not repeat on a server:
  `server "web-1": tag "Prod" is not valid: want lowercase letters, digits, '.', '_' or '-', starting with a letter or digit, at most 63 characters`,
  `server "web-1": tag "prod" is repeated`.
- **Selectors in `access:`**: `access for "carol": unknown tag "@prd"`;
  `access for "x": "*" must be the only servers entry`; `access for "x": except requires servers ["*"] or an @tag`;
  `access for "x": except takes server names, not the selector "@web"`;
  `access for "x": "web-3" is in both servers and except`;
  `access for "x": selectors grant no servers after except`.
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
- **`serial:`** must be a plain, unquoted decimal integer from 0 to 9007199254740991
  (an empty value, `~` or `null` included):
  `serial: want an integer from 0 to 9007199254740991, got "VALUE"`.
- **`revoked:` entries** (`N` is the zero-based index in `revoked:`):
  - a key entry's fingerprint must be `SHA256:` and 43 unpadded base64 characters:
    `revoked[N]: fingerprint "VALUE" is not a SHA256 fingerprint (want SHA256: followed by 43 base64 characters)`;
  - a key entry may not list servers:
    `revoked[N]: servers is not allowed on a key entry (SHA256:…); record access with a separate entry that has user and servers`;
  - a fingerprint is revoked once: `revoked[N]: SHA256:… is already revoked by revoked[M]`;
  - an entry without a fingerprint needs both `user` and `servers`:
    `revoked[N]: an entry without fingerprint needs user and servers`, and
    `revoked[N]: servers must not be empty`;
  - `*` is not a server: `revoked[N]: servers cannot be "*"; list the servers by name`;
  - a selector is not a server name: `revoked[N]: servers cannot hold a selector; list the servers by name`;
  - `date` is required and must be `YYYY-MM-DD`: `revoked[N]: date is required`,
    `revoked[N]: date "VALUE" is not a YYYY-MM-DD date`;
  - `user` and `reason` follow the names-and-comments rule above
    (`revoked[N]: user contains control or format characters`,
    `revoked[N]: reason has leading or trailing whitespace`) and are capped at 256
    bytes: `revoked[N]: reason is B bytes, over the 256-byte limit` (same for `user`).

A server named in an access entry of `revoked:` that is not in `servers:` is a
warning, not a load error:
`revoked[0]: unknown server "db-9" — this entry is ignored for it; remove db-9 from the entry once the server is gone for good`
(the entry is ignored for that server; re-adding the server re-applies it).

Policy conflicts are not load errors: a revoked key still listed, or a grant over an
access tombstone, loads; `audit` reports it critical (exit 2), `apply` refuses the
servers involved (exit 1), and `adopt`, `import --merge`, `revoke` and `rotate`
refuse to write a manifest that would keep one (exit 3). The two messages:

- `key SHA256:… of user "alice" is revoked (2026-11-08, alice): remove it from users, or delete the revoked: entry to un-revoke it deliberately`
  (without a `user` label the parenthesis is the date alone);
- `user "bob" is granted "db-1" by access[0], but revoked[0] removed that access (2026-11-08): remove the grant, or delete the revoked: entry to restore it deliberately`
  (a wildcard grant conflicts too, unless its `except:` lists the server; an `@tag` grant does not conflict, see [Revoked keys](#revoked-keys)).

A refused save reads, for example:

```console
error: refusing to write the manifest — it would keep 1 policy conflict: key SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8 of user "alice" is revoked (2026-11-08, alice): remove it from users, or delete the revoked: entry to un-revoke it deliberately
```

Weak and expired keys:

- A weak key (DSA, or RSA under 2048 bits) that renders on at least one server is a policy conflict, not a load error: `audit` reports it critical (exit 2) and `apply` refuses those servers. A weak key granted on no server is a load warning. A desired key whose `expiry-time` has passed is a load warning.
- OpenSSH 9.8 and later build sshd without DSA by default, so a DSA key usually cannot log in on a current server anyway; the rule makes that visible instead of silent.
- **On upgrade:** a manifest holding a weak key keeps loading, but every server granting that key goes critical, so a scheduled `audit` that passed before now exits 2 and `apply` skips those servers. `rotate` and `revoke --key` are the way out and always save.

### Comment policy

The comment SSHepherd writes on each key line is resolved in this order:

1. the user's `comment:` field, if set;
2. the key line's own inline comment;
3. the user's `name`.

Setting `comment:` on a user with multiple keys is legal — it deliberately
normalizes every key to the same comment — but the manifest loader warns about it,
so it stays a conscious choice. `audit --comments` reports comment drift on present
keys; it is informational and never affects the exit code.

### Serial

`serial:` counts the manifest's revocations, so an older copy cannot undo them. It
goes up by one on every `revoke` or `rotate` that saves, and on a confirmed `apply`
that removes a key from a server whose header serial is not below the manifest's
(see [`apply`](#sshepherd-apply)). You normally never edit it.

Every managed file's header carries the value:
`# Managed by SSHepherd (serial 7). Manual edits will be overwritten by 'sshepherd apply'.`
A server written by a newer manifest is refused unless the write only removes keys,
and the only override is setting the serial by hand:

```console
s-refused (deploy@10.0.0.5:22)  REFUSED: written by manifest serial 8, this manifest is 7 — a newer manifest revoked or rotated keys here; pull the latest manifest, or if you are sure, set serial: 8 in your manifest (this is the only override)
```

The serial narrows the window for a stale copy and does not close it: only the
servers a bumping run writes learn the new value, and a hand edit bumps it only
through that `apply`. [Safety model](#safety-model) lists the limits.

### Revoked keys

`revoked:` is the manifest's memory of every revoke. A key entry (`fingerprint`,
optional `user` label, `date`, optional `reason`) means that key may never be listed
in `users:` again, and adopt and `import --merge` never bring it back; an access
entry (`user`, `servers`, `date`, optional `reason`) means that user is never
re-granted those servers. `revoke` and `rotate` append entries; deleting one by hand
is a deliberate un-revoke (git history is the audit trail). A server removed from
`servers:` but still named in an access entry is a warning —
`revoked[N]: unknown server "NAME" — this entry is ignored for it; remove NAME from the entry once the server is gone for good`
— never a load error; re-adding the server re-applies the entry.

A grant that reaches a server only through an `@tag` does not conflict with an access entry
for that (user, server): it is **blocked**. The tombstone acts as an `except:` for that user,
the key is not installed, and each blocked pair prints a warning, kind `tombstone_blocks_grant`:
`access[0]: "bob" is not granted "db-1" through @db: revoked[0] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`.
A warning never changes an exit code, except that `validate --strict` exits `1`. A server named
directly (`user: U` with `S` listed, or `*` not excepting it) still conflicts, even in the same
entry as an `@tag`. An operator's implicit grant is not affected, and no warning prints for it.

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

### `sshepherd validate`

Check the manifest offline. It never opens a socket and never reads a key. It parses and validates the manifest, reports policy conflicts, says whether `revoke`, `rotate` and `--merge` can edit it, and, when a known_hosts file loads, warns about each server with no recorded host key.

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--config` | `sshepherd.yaml` | Path to the manifest (`/dev/stdin` and a pipe work) |
| `--known-hosts` | `~/.ssh/known_hosts` | `known_hosts` path. With the default path a missing file is a warning (it fails `--strict`). A file given explicitly that is missing or bad, or a default file that exists but cannot be loaded, exits `3` |
| `--strict` | off | Exit `1` when the manifest is valid but has warnings |
| `--json` | off | Machine-readable result on stdout (schema 1) |

A valid manifest prints one line on stdout, e.g. `manifest OK: 1 user, 1 server, 1 grant (0 warnings)`. A policy conflict prints `manifest has 1 policy conflict: MESSAGE` on stderr and exits `3`. A weak key granted on a server is a policy conflict; an ungranted one is a warning.

`--json` writes one document. It is written on exit `3` too, when the manifest is invalid or has a policy conflict, with `valid: false`, and when the default known_hosts exists but cannot be loaded (`valid: true`, the reason in `errors`). An unreadable manifest, a bad flag or a bad `--known-hosts` file given explicitly writes no document. `import` and `adopt` are the opposite: they write a document on almost no exit `3`, only `adopt --partial` with no server read does. A run that fails only under `--strict` has `valid: true` and exit `1`. `manifest_warnings` adds the kinds `manifest_not_editable`, `known_hosts_missing` and `host_key_not_recorded`; ignore kinds you do not know. `host_keys_checked` is `false` when no known_hosts file loaded.

```json
{
  "schema": 1,
  "valid": true,
  "summary": {
    "users": 1,
    "servers": 1,
    "grants": 1,
    "warnings": 1,
    "exit_code": 0
  },
  "host_keys_checked": true,
  "errors": [],
  "manifest_warnings": [
    {
      "kind": "host_key_not_recorded",
      "server": "web-1",
      "message": "server \"web-1\": no host key recorded for 10.0.1.5:22 in ~/.ssh/known_hosts"
    }
  ]
}
```

An invalid manifest:

```json
{
  "schema": 1,
  "valid": false,
  "summary": {
    "users": 0,
    "servers": 0,
    "grants": 0,
    "warnings": 0,
    "exit_code": 3
  },
  "host_keys_checked": false,
  "errors": [
    "access for \"alice\": unknown server \"web-9\""
  ]
}
```

### `sshepherd audit`

Report drift between the manifest and each server's `authorized_keys`. Read-only.

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--config` | `sshepherd.yaml` | Path to the manifest |
| `--known-hosts` | `~/.ssh/known_hosts` | `known_hosts` path (strict checking) |
| `--parallel` | `32` | Max concurrent server audits |
| `--server` | all | Audit only this server (repeatable). An unknown name exits `3` before anything connects. A policy conflict anywhere in the manifest still exits `2` |
| `--offer-all-keys` | off | Offer every loaded key to every server (default: only the keys the manifest grants there). |
| `--json` | off | Machine-readable report on stdout (schema 1) |
| `--comments` | off | Also report comment drift on present keys (informational) |
| `--identity PATH` | none | Private key file to authenticate with, in addition to `ssh-agent` (repeatable); `~/` expands from `$HOME` |
| `--identity-passphrase-file FILE` | none | Default passphrase file for any encrypted `--identity` key |
| `--identity-passphrase PATH=FILE` | none | Passphrase file for one `--identity` key (repeatable); split at the **first** `=` — a key path containing `=` is unsupported |

When `--server` leaves servers out, the report ends with `(N servers skipped by --server)`
and the JSON summary gains `skipped`; a run that names every server gets neither. The
manifest's policy conflicts are about the manifest, not one server, so they are still
printed and still exit `2`.

**Drift classes.** Besides missing, unauthorized and unparseable entries, these
security-relevant classes make a server non-compliant, always on (exit 1 unless the
entry says otherwise):

- a matched key whose **options differ** from the manifest's (e.g. the server lost a
  `from=` or `command=` restriction);
- a **duplicate entry** — one key on several lines, where sshd tries each line and
  the least restricted copy wins;
- a non-empty, unmanaged **`~/.ssh/authorized_keys2`** (checked when the audited
  path is the default or resolves to it);
- **Unsafe permissions** — audit checks what sshd's StrictModes checks: the managed file and its directories up to `$HOME` (up to `/` for an override path outside it). A group-writable path, a path owned by neither the login user nor root, or a symlinked managed file is drift (exit 1); a world-writable path is critical (exit 2), since anyone on the host can add a key. The report says to fix by hand (`chmod go-w`, `chown`); `apply` refuses to write through these paths (exit 48 in the write script; 45 for a symlinked managed file). A root-owned file audits clean, though `apply` refuses to write it. The probe is evidence about an honest server: a compromised one can print nothing and look clean.
- **Operator key that cannot log in** — a present operator key on a line sshd will not honour (a `cert-authority`/`principals=` line the manifest does not declare, a passed `expiry-time` whether declared or not, or every line ignored) is critical. Audit checks every line of a key, as sshd does: a working second line keeps it non-critical.

Rows are annotated ` · WEAK (dsa)`, ` · WEAK (rsa 1024)` and ` · EXPIRED`; annotations alone do not change the exit code.

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

```console
web-1 (deploy@10.0.0.1:22)
  ✓  op (op@sshepherd)  SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8  ssh-ed25519  present & authorized
  ✓  alice              SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  present & authorized
  ‼ unsafe permissions: /home/deploy/.ssh is world-writable (drwxrwxrwx, uid 1001) — anyone on the host can add a key; sshd's StrictModes would ignore this file
  ⚠ unsafe permissions: /home/deploy/.ssh/authorized_keys is group-writable (-rw-rw-r--, uid 1001) — sshd's StrictModes would ignore this file
  ⚠ unsafe permissions: /srv/keys is owned by uid 1002, not the login user or root — sshd's StrictModes would ignore this file
  ⚠ unsafe permissions: /home/deploy/.ssh/authorized_keys2 is a symlink — apply refuses to write through it
  note: fix by hand (chmod go-w / chown); a login that succeeded here came through another key source or with StrictModes off
  → 2 authorized · 2 present · 0 missing · 0 unauthorized

Summary: 0/1 servers compliant · 1 with drift (1 critical) · 0 unreachable  → exit 2
```

An operator key whose only line is `cert-authority`, which the manifest does not declare:

```console
web-1 (deploy@10.0.0.1:22)
  ‼  op (op@sshepherd)  SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8  ssh-ed25519  present but CANNOT LOG IN (CRITICAL: operator key; server line is cert-only)
  ✓  alice              SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  present & authorized
  → 2 authorized · 2 present · 0 missing · 0 unauthorized

Summary: 0/1 servers compliant · 1 with drift (1 critical) · 0 unreachable  → exit 2
```

A passed `expiry-time` on an operator's line, and weak keys annotated on their rows:

```console
web-1 (deploy@10.0.0.1:22)
  ‼  op (op@sshepherd)  SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8  ssh-ed25519  present but CANNOT LOG IN (CRITICAL: operator key; server line expired 2026-01-01)
  ✓  alice              SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  present & authorized
  ⚠  (unknown)          SHA256:S7W0wWKoAYK3zmBPSPe/2zvxl1kZKp9tk2LXlXIliMU  ssh-dss      installed but UNAUTHORIZED · WEAK (dsa)
  ⚠  (unknown)          SHA256:cqcZ3vi/yOOaDFNtRYf6/1lahzlffXDFaze4HmSibwQ  ssh-rsa      installed but UNAUTHORIZED · WEAK (rsa 1024)
  → 2 authorized · 2 present · 0 missing · 2 unauthorized

Summary: 0/1 servers compliant · 1 with drift (1 critical) · 0 unreachable  → exit 2
```

Comment drift (`--comments`) stays cosmetic and never affects the exit code.

A key the manifest does not own shows as `(unknown)` with its on-server comment
(quoted, sanitized, cut at 40 characters) and, in the status cell, its options
(`installed but UNAUTHORIZED · options: "from=\"10.0.0.0/8\",no-pty"`).

**Revocation memory.** Audit reads the manifest's `revoked:` and `serial:` and the
serial in each server's managed header:

- a **revoked key still installed** is `installed but REVOKED (CRITICAL: revoked key)`,
  labelled with the former owner and date (`(REVOKED DATE)` alone for an unlabelled
  tombstone) — exit `2`;
- a known user's key on a server where their **access was revoked** keeps
  `installed but UNAUTHORIZED`, labelled `bob (access revoked DATE)` — drift, exit `1`;
- a **policy conflict** (a revoked key still listed under `users:`, or a grant over an
  access tombstone) prints as a leading `‼ manifest: … (CRITICAL: policy conflict)` block,
  and each server it names carries a conflict line — exit `2`, even with no server
  read;
- a header **written by a newer manifest** is `⚠ written by newer manifest serial S
  (yours is M): pull the latest manifest` — drift, exit `1`;
- a header serial more than 1000 above the manifest's is `‼ header claims serial S, far
  above this manifest's M — someone edited this file (CRITICAL: forged header)` — exit `2`.

A header serial below the manifest's is not drift (a plain apply leaves it).

```console
‼ manifest: user "alice" is granted "web-1" by access[0], but revoked[2] removed that access (2026-11-08): remove the grant, or delete the revoked: entry to restore it deliberately (CRITICAL: policy conflict)

web-1 (deploy@10.0.0.1:22)
  ✓  op                          SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8  ssh-ed25519  present & authorized
  ✓  alice                       SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  present & authorized
  ✓  bob                         SHA256:zbv/nU7iZdO0fB0DalMI70dP6/yFD8sctXvvW4+OokY  ssh-ed25519  present & authorized
  ‼  carol (REVOKED 2026-11-08)  SHA256:doxiASlJnKSD9j+JpVoWpfEFHjUrsF9ZYr+cir4FYjo  ssh-ed25519  installed but REVOKED (CRITICAL: revoked key)
  ‼ named by a manifest policy conflict above (CRITICAL: policy conflict)
  → 3 authorized · 3 present · 0 missing · 1 unauthorized

web-2 (deploy@10.0.0.2:22)
  ✓  op                               SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8  ssh-ed25519  present & authorized
  ✓  alice                            SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  present & authorized
  ⚠  bob (access revoked 2026-11-08)  SHA256:zbv/nU7iZdO0fB0DalMI70dP6/yFD8sctXvvW4+OokY  ssh-ed25519  installed but UNAUTHORIZED
  ‼  (REVOKED 2026-11-08)             SHA256:RFGPmv0HqTEFgFwzM49kDpWeoM4LSFeh+oNnj0R89WQ  ssh-ed25519  installed but REVOKED (CRITICAL: revoked key)
  ‼ named by a manifest policy conflict above (CRITICAL: policy conflict)
  → 2 authorized · 2 present · 0 missing · 2 unauthorized

Summary: 0/2 servers compliant · 2 with drift (2 critical) · 0 unreachable  → exit 2
```

```console
web-1 (deploy@10.0.0.1:22)
  ✓  op     SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8  ssh-ed25519  present & authorized
  ✓  alice  SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  present & authorized
  ✓  bob    SHA256:zbv/nU7iZdO0fB0DalMI70dP6/yFD8sctXvvW4+OokY  ssh-ed25519  present & authorized
  ⚠ written by newer manifest serial 8 (yours is 7): pull the latest manifest
  → 3 authorized · 3 present · 0 missing · 0 unauthorized

web-2 (deploy@10.0.0.2:22)
  ✓  op     SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8  ssh-ed25519  present & authorized
  ✓  alice  SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  present & authorized
  ‼ header claims serial 9999, far above this manifest's 7 — someone edited this file (CRITICAL: forged header)
  → 2 authorized · 2 present · 0 missing · 0 unauthorized

Summary: 0/2 servers compliant · 2 with drift (1 critical) · 0 unreachable  → exit 2
```

**Classified errors.** An unreachable server's line names the failure kind:
`host_key_unknown`, `host_key_changed`, `host_key_type_changed`, `host_key_type_unrecorded`,
`host_key_revoked`, `host_key`, `agent`, `auth`, `dial`, `timeout`, `canceled`,
`handshake` or `remote`. Unclassified errors keep a plain `ERROR:` head. A host key
that **changed** or is marked `@revoked` in `known_hosts` (possible impersonation)
counts as a host-key alert and makes the run exit `2`.
`host_key_type_changed` (exit 2): `known_hosts` records a key type x/crypto can verify and the server presented a different type, or a certificate from a signer no `@cert-authority` line for this host vouches for. `host_key_type_unrecorded` (exit 1) now remains only when every recorded type is unsupported. A certificate from a vouched CA that fails validation stays `host_key` (exit 1).
A failed or malformed posture probe makes the server unreachable with `error_kind: remote` (exit 1), so a server cannot be graded clean while hiding its posture.
When a failure has a remediation, it prints on its own `hint:` line under the first
server that needs it; a hint shared by many servers prints once:

```console
web-1 (deploy@10.0.0.1:22)  ERROR [host_key_changed]: ssh deploy@10.0.0.1:22: presented ssh-ed25519 key SHA256:abc: knownhosts: key mismatch
  hint: HOST KEY CHANGED for 10.0.0.1:22 — possible impersonation; investigate and verify the new fingerprint out of band before touching ~/.ssh/known_hosts

web-2 (deploy@10.0.0.2:22)  ERROR [auth]: ssh deploy@10.0.0.2:22: ssh: unable to authenticate

Summary: 0/2 servers compliant · 0 with drift (0 critical) · 2 unreachable (1 HOST KEY ALERT)  → exit 2
```

A host key type that changed:

```console
web-1 (deploy@10.0.0.1:22)  ERROR [host_key_type_changed]: ssh deploy@10.0.0.1:22: presented ecdsa-sha2-nistp256 key SHA256:abc: knownhosts: key mismatch
  hint: HOST KEY TYPE CHANGED for 10.0.0.1:22 — the server no longer presents any recorded key type (recorded: ssh-ed25519); possible impersonation

web-2 (deploy@10.0.0.2:22)
  ✓  alice (alice@sshepherd)  SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8  ssh-ed25519  present & authorized
  → 1 authorized · 1 present · 0 missing · 0 unauthorized

Summary: 1/2 servers compliant · 0 with drift (0 critical) · 1 unreachable (1 HOST KEY ALERT)  → exit 2
```

For an unknown host or a changed or unrecorded key type, the hint asks you to verify the
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
      "hint": "HOST KEY CHANGED for 10.0.0.1:22 — possible impersonation; investigate and verify the new fingerprint out of band before touching ~/.ssh/known_hosts",
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

Revocation memory adds optional fields, each omitted when zero or empty (the schema
stays 1): top-level `manifest_serial`, `policy_conflicts` and `manifest_warnings`;
`summary.revoked_keys` and `summary.policy_conflicts`; per-key `revoked` and
`access_revoked`; per-server `header_serial`, `manifest_serial_ahead` and
`forged_header_serial`. Text taken from the manifest passes the same sanitizer as
remote text:

```json
{
  "schema": 1,
  "manifest_serial": 7,
  "policy_conflicts": [
    {
      "kind": "revoked_access",
      "message": "user \"alice\" is granted \"web-1\" by access[0], but revoked[2] removed that access (2026-11-08): remove the grant, or delete the revoked: entry to restore it deliberately",
      "user": "alice",
      "servers": [
        "web-1",
        "web-2"
      ]
    }
  ],
  "manifest_warnings": [
    {
      "kind": "tombstone_unknown_server",
      "revoked_index": 3,
      "user": "alice",
      "server": "db-9",
      "message": "revoked[3]: unknown server \"db-9\" — this entry is ignored for it; remove db-9 from the entry once the server is gone for good"
    },
    {
      "kind": "tombstone_unknown_server",
      "revoked_index": 4,
      "user": "alice",
      "server": "db9",
      "message": "revoked[4]: unknown server \"db\\x1b9\" — this entry is ignored for it; remove \"db\\x1b9\" from the entry once the server is gone for good"
    }
  ],
  "summary": {
    "servers": 2,
    "compliant": 0,
    "drift": 2,
    "critical": 2,
    "unreachable": 0,
    "revoked_keys": 2,
    "policy_conflicts": 1,
    "exit_code": 2
  },
  "servers": [
    {
      "name": "web-1",
      "host": "10.0.0.1",
      "port": 22,
      "user": "deploy",
      "status": "critical",
      "error": null,
      "keys": {
        "present": [
          {
            "owner": "op",
            "fingerprint": "SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8",
            "type": "ssh-ed25519"
          },
          {
            "owner": "alice",
            "fingerprint": "SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4",
            "type": "ssh-ed25519"
          },
          {
            "owner": "bob",
            "fingerprint": "SHA256:zbv/nU7iZdO0fB0DalMI70dP6/yFD8sctXvvW4+OokY",
            "type": "ssh-ed25519"
          }
        ],
        "missing": [],
        "unauthorized": [
          {
            "owner": null,
            "fingerprint": "SHA256:doxiASlJnKSD9j+JpVoWpfEFHjUrsF9ZYr+cir4FYjo",
            "type": "ssh-ed25519",
            "revoked": {
              "user": "carol",
              "date": "2026-11-08",
              "reason": "offboarded"
            }
          }
        ]
      },
      "parse_errors": [],
      "file_absent": false,
      "no_users_granted": false,
      "header_serial": 7
    },
    {
      "name": "web-2",
      "host": "10.0.0.2",
      "port": 22,
      "user": "deploy",
      "status": "critical",
      "error": null,
      "keys": {
        "present": [
          {
            "owner": "op",
            "fingerprint": "SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8",
            "type": "ssh-ed25519"
          },
          {
            "owner": "alice",
            "fingerprint": "SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4",
            "type": "ssh-ed25519"
          }
        ],
        "missing": [],
        "unauthorized": [
          {
            "owner": "bob",
            "fingerprint": "SHA256:zbv/nU7iZdO0fB0DalMI70dP6/yFD8sctXvvW4+OokY",
            "type": "ssh-ed25519",
            "access_revoked": {
              "date": "2026-11-08"
            }
          },
          {
            "owner": null,
            "fingerprint": "SHA256:RFGPmv0HqTEFgFwzM49kDpWeoM4LSFeh+oNnj0R89WQ",
            "type": "ssh-ed25519",
            "revoked": {
              "date": "2026-11-08"
            }
          }
        ]
      },
      "parse_errors": [],
      "file_absent": false,
      "no_users_granted": false,
      "header_serial": 7
    }
  ]
}
```

`manifest_warnings` carries every load warning, in the `audit` document and in the `apply`
document. Each object has `kind` and `message`. `revoked_index`, `user` and `server` appear on `tombstone_unknown_server` and `tombstone_blocks_grant`; `server` also on validate's `host_key_not_recorded`. The kinds are `tombstone_unknown_server`,
`comment_on_multi_key`, `weak_key_ungranted`, `key_expired`, `wildcard_root` and `tombstone_blocks_grant`; ignore kinds you do not know.

Optional fields, present only when they apply: `servers[].error_kind` (exactly when
`error` is non-null; `"unknown"` for unclassified errors), `summary.host_key_alerts`
(omitted when 0), `summary.skipped` (servers `--server` left out; omitted when 0),
`keys.present[].options_drift` (`{"actual": [...], "desired": [...]}`),
`keys.present[].comment_drift` (with `--comments`), `servers[].duplicates`
(`[{"owner", "fingerprint", "count"}]`), `servers[].authorized_keys2_present`,
`servers[].hint` (remediation text, present only when the failure has one; `error`
never contains it) and `keys.unauthorized[].options` (on-server options of a key the
manifest does not own).

The trust posture adds these, also present only when they apply:

- Server: `posture`: `[{"path", "issue", "mode", "uid"}]`; `critical_reasons`: sorted list from `forged_serial`, `operator_cannot_log_in`, `operator_missing`, `policy_conflict`, `revoked_key`, `world_writable`, present exactly when `status` is `critical`. A host-key alert is `status: unreachable` and carries no reason; `error_kind` and `summary.host_key_alerts` say why.
- Key: `cannot_log_in` (`cert_only`, `expired`, `ignored`) on a present operator key that is critical, with `operator: true`; `key_issues` (`dsa`, `rsa_under_2048`, `expired`), never on a key with `revoked`.
- `policy_conflicts` carries the new `kind: "weak_key"`. New `error_kind`: `host_key_type_changed`.

```json
      "posture": [
        {
          "path": "/home/deploy/.ssh",
          "issue": "world_writable",
          "mode": "drwxrwxrwx",
          "uid": "1001"
        },
        {
          "path": "/home/deploy/.ssh/authorized_keys",
          "issue": "group_writable",
          "mode": "-rw-rw-r--",
          "uid": "1001"
        },
        {
          "path": "/srv/keys",
          "issue": "foreign_owner",
          "mode": "drwxr-xr-x",
          "uid": "1002"
        },
        {
          "path": "/home/deploy/.ssh/authorized_keys2",
          "issue": "symlink",
          "mode": "lrwxrwxrwx",
          "uid": "1001"
        }
      ],
      "critical_reasons": [
        "world_writable"
      ]
```

```json
          {
            "owner": "op",
            "fingerprint": "SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8",
            "type": "ssh-ed25519",
            "operator": true,
            "cannot_log_in": "expired",
            "key_issues": [
              "expired"
            ]
          }
```

```json
          {
            "owner": "op",
            "fingerprint": "SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8",
            "type": "ssh-ed25519",
            "operator": true,
            "options_drift": {
              "actual": [
                "cert-authority"
              ],
              "desired": []
            },
            "cannot_log_in": "cert_only"
          }
```

```json
          {
            "owner": null,
            "fingerprint": "SHA256:S7W0wWKoAYK3zmBPSPe/2zvxl1kZKp9tk2LXlXIliMU",
            "type": "ssh-dss",
            "key_issues": [
              "dsa"
            ]
          }
```

```json
      "status": "unreachable",
      "error": "ssh deploy@10.0.0.1:22: presented ecdsa-sha2-nistp256 key SHA256:abc: knownhosts: key mismatch",
      "error_kind": "host_key_type_changed",
      "hint": "HOST KEY TYPE CHANGED for 10.0.0.1:22 — the server no longer presents any recorded key type (recorded: ssh-ed25519); possible impersonation",
```

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
| `--operator-key PATH` | — | Key file whose owner becomes an operator (repeatable) |
| `--merge FILE` | — | Merge into `FILE`: preserve its text and append what is new |
| `--json` | off | Machine-readable report on stdout (schema 1); the manifest goes to `-o`, or into the report's `manifest` field |

`--json` replaces the manifest on stdout with one report (schema 1), and changes nothing else: logs stay on stderr and the manifest bytes match a plain run exactly. With `-o` the manifest goes to the file and the report has `output`; without it the report has `manifest`, so `sshepherd import --json | jq -j .manifest` prints what a plain run prints. A manifest that is not UTF-8 (a `--merge` with nothing to add returns a UTF-16 file's bytes unchanged) cannot go into a JSON string, so without `-o` the run exits `3` and writes no report; with `-o` the file gets the bytes unchanged. Exit `0` writes a report; exit `3` writes none, only a message on stderr. `new_servers`, `new_users` and `extensions` list what the output adds, and `summary` counts what the ssh config yielded. `notes` are steady-state findings and are not counted in `summary.warnings`. `warnings` has the kinds `revoked_pub_skipped`, `revoked_access_skipped`, `ssh_config`, `identity`, `unsafe_host`, `collapsed_target`, `proxy_not_mapped`, `merge_conflict`, `wildcard_grant` and `revocation_memory_dropped`; ignore kinds you do not know.

```json
{
  "schema": 1,
  "command": "import",
  "mode": "merge",
  "output": {
    "path": "fleet.yaml",
    "written": true
  },
  "summary": {
    "hosts": 3,
    "users": 5,
    "grants": 7,
    "conflicts": 3,
    "warnings": 5,
    "exit_code": 0
  },
  "new_servers": [
    {
      "name": "app-1",
      "host": "10.0.0.5",
      "port": 2200,
      "user": "deploy"
    }
  ],
  "new_users": [
    {
      "name": "javad-carol",
      "fingerprint": "SHA256:z/fSv0Z0RZS+Lccbc6ZoOWwt/fbj1VFJGSBKQbo4icE",
      "type": "ssh-ed25519",
      "servers": [
        "app-1"
      ]
    },
    {
      "name": "alice-2",
      "fingerprint": "SHA256:doxiASlJnKSD9j+JpVoWpfEFHjUrsF9ZYr+cir4FYjo",
      "type": "ssh-ed25519",
      "servers": [
        "app-1"
      ]
    }
  ],
  "extensions": [
    {
      "user": "alice",
      "servers": [
        "app-1"
      ]
    }
  ],
  "warnings": [
    {
      "kind": "merge_conflict",
      "server": "db-1",
      "message": "server \"db-1\" in the ssh config differs from the manifest (host/port/user) — manifest kept"
    },
    {
      "kind": "merge_conflict",
      "fingerprint": "SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4",
      "user": "alice",
      "message": "key SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4 from the ssh config belongs to manifest user \"alice\" — extending their access"
    },
    {
      "kind": "merge_conflict",
      "server": "db-1",
      "user": "javad-carol",
      "message": "access for \"javad-carol\" to \"db-1\" dropped: the server conflicts with the manifest"
    },
    {
      "kind": "merge_conflict",
      "user": "javad-doomed",
      "message": "user \"javad-doomed\" not added: its only server \"db-1\" conflicts with the manifest"
    },
    {
      "kind": "merge_conflict",
      "user": "alice-2",
      "message": "user name \"alice\" already taken, using \"alice-2\" for the incoming key"
    }
  ],
  "notes": [
    "server \"web-1\" already in the manifest — identical, skipped",
    "key SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o from the ssh config belongs to manifest user \"bob\" — already covered"
  ]
}
```

`--merge` is strictly additive: only genuinely new entries are appended, the
existing manifest wins every conflict (with a loud warning), and re-running with no
new input is a byte-identical no-op. A `.pub` whose key is revoked is skipped, and a
revoked (user, server) pair is never re-extended:
`key SHA256:doxiASlJnKSD9j+JpVoWpfEFHjUrsF9ZYr+cir4FYjo from ~/.ssh/id_old.pub is REVOKED (2026-11-08, alice) — not imported`.
A `--merge` manifest that would keep a policy conflict is refused (exit 3; see
[Validation rules](#validation-rules)).

A weak `.pub` identity (DSA, RSA under 2048 bits) is skipped with a warning, in plain `import` and under `--merge`. `--operator-key` naming a weak key is an error (exit 3).

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
  `%r` (remote user) and `%p` (port, default 22); `--operator-key` paths support only
  `%d`, `%u` and `%%`. An `IdentityFile` may name the `.pub` itself (agent-held keys
  such as 1Password, Secretive or a YubiKey); the user name drops the `.pub`.

What gets skipped or merged, always with a warning on stderr:

- A host whose alias, HostName or User contains whitespace or control characters (e.g. a quoted `Host "web 1"`), or whose alias starts with `@` (reserved for tag selectors) — it could never be a valid server entry.
- A `.pub` whose comment has tabs or control/format characters (an error for
  `--operator-key`).
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
When `-o` names the manifest the run read (`adopt --config`, `adopt --merge`,
`import --merge FILE`; symlinks followed, however the path is spelled: relative or
absolute, or a case variant on a case-insensitive filesystem), it is an in-place update. Without
`--force` it is refused with
`PATH is the manifest this run read; pass --force to update it in place`. With
`--force` it is saved exactly as `revoke` saves: under the manifest lock, keeping
the file's mode and owner, and refused with
`manifest PATH changed since it was read; re-run` (exit 3) if anything changed the
file meanwhile, so a concurrent revoke is never undone. Identical output writes
nothing. A second hard link to the manifest, under another name, is refused
(`PATH is a hard link to the manifest M; pass the manifest's own path`). A
different existing file overwritten with `--force` is still a new file (mode
`0600`). A fresh `import -o FILE --force` without `--merge` over a manifest holding
revocation memory warns
`FILE holds revocation memory (serial N, M revoked: entries) that this fresh import drops: a revoked key could be re-granted; keep it with --merge FILE`
and proceeds.
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
they were found. The input file is never modified unless `-o` names it (with
`--force`; see Output files).

Unknown keys are granted the servers where they were found, by name — never `["*"]`,
which would also grant servers added later. A key the manifest's `revoked:` list
remembers is skipped with a warning
(`key SHA256:z/fSv0Z0RZS+Lccbc6ZoOWwt/fbj1VFJGSBKQbo4icE on web-2 is REVOKED (2026-11-08, alice) — not adopted; run 'sshepherd apply --server web-2' to remove it`),
and so is a known key on a server whose access was revoked; adopt's exit code is
unchanged. Adopt keeps `serial:` and `revoked:` in both modes (regenerate and
`--merge`), and refuses (exit 3) to write a manifest that would keep a policy
conflict (see [Validation rules](#validation-rules)).

A weak on-server key (DSA, RSA under 2048 bits) is skipped with a warning in both modes and never granted to more servers; audit keeps showing it as `UNAUTHORIZED`.

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--config` | `sshepherd.yaml` | Path to the manifest |
| `--known-hosts` | `~/.ssh/known_hosts` | `known_hosts` path (strict checking) |
| `--parallel` | `32` | Max concurrent server reads |
| `--offer-all-keys` | off | Offer every loaded key to every server (default: only the keys the manifest grants there). |
| `-o, --output` | stdout | Write the manifest to this file |
| `--force` | off | Allow `--output` to overwrite an existing file |
| `--partial` | off | Proceed even if some servers cannot be read |
| `--merge` | off | Merge into `--config`: preserve its text and append what is new |
| `--json` | off | Machine-readable report on stdout (schema 1); the manifest goes to `-o`, or into the report's `manifest` field |
| `--identity PATH` | none | Private key file to authenticate with, in addition to `ssh-agent` (repeatable); `~/` expands from `$HOME` |
| `--identity-passphrase-file FILE` | none | Default passphrase file for any encrypted `--identity` key |
| `--identity-passphrase PATH=FILE` | none | Passphrase file for one `--identity` key (repeatable); split at the **first** `=` — a key path containing `=` is unsupported |

`--json` replaces the manifest on stdout with one report (schema 1), and changes nothing else: logs stay on stderr and the manifest bytes match a plain run exactly. With `-o` the manifest goes to the file and the report has `output` (`written` is `false` when an in-place update changed nothing). Without `-o` the report has `manifest`, so `sshepherd adopt --json | jq -j .manifest` prints what a plain run prints. A manifest that is not UTF-8 (a `--merge` with nothing to adopt returns a UTF-16 file's bytes unchanged) cannot go into a JSON string, so without `-o` the run exits `3` and writes no report; with `-o` the file gets the bytes unchanged. A report with `"emitted": false` has neither.

Exit `0` and `1` always write a report. `emitted` is `true` under `--partial` and `false` when unreadable servers stopped the run. Exit `3` writes none, only a message on stderr, with one exception: `--partial` with no server read writes a report with `"emitted": false`. `unreadable` lists servers that could not be read, each with `error_kind`; `line_issues` lists lines adopt could not use on a server it did read, and `summary.partly_read` counts those servers. `warnings` has the kinds `revoked_key_skipped`, `revoked_access_skipped`, `except_skipped`, `key_differs`, `comment_dropped` and `weak_key_skipped`; ignore kinds you do not know.

```json
{
  "schema": 1,
  "command": "adopt",
  "mode": "merge",
  "emitted": true,
  "output": {
    "path": "fleet.yaml",
    "written": true
  },
  "summary": {
    "servers": 12,
    "read": 11,
    "partly_read": 1,
    "new_users": 1,
    "extensions": 1,
    "warnings": 1,
    "exit_code": 1
  },
  "new_users": [
    {
      "name": "u-laptop",
      "fingerprint": "SHA256:fpLaptop",
      "type": "ssh-ed25519",
      "found_on": [
        "web-1"
      ]
    }
  ],
  "extensions": [
    {
      "user": "bob",
      "servers": [
        "db-1"
      ]
    }
  ],
  "unreadable": [
    {
      "server": "db-3",
      "error_kind": "dial",
      "detail": "dial 10.0.0.3:22: connection refused",
      "hint": "check the host, port, and firewall"
    }
  ],
  "line_issues": [
    {
      "server": "web-9",
      "detail": "line 3: invalid key"
    }
  ],
  "warnings": [
    {
      "kind": "revoked_key_skipped",
      "server": "web-2",
      "fingerprint": "SHA256:fpOld",
      "user": "alice",
      "date": "2026-11-08",
      "message": "key SHA256:fpOld on web-2 is REVOKED (2026-11-08, alice) — not adopted; run 'sshepherd apply --server web-2' to remove it"
    }
  ]
}
```

Any unreadable server aborts the run unless `--partial` is set — adopting a
half-read fleet would silently drop real access. Each unreadable server gets its
own `server <name>: …` line; a connection failure's remediation follows as a
`hint:` line, printed once however many servers share it (`warn:` under
`--partial`, `error:` in strict mode, so it survives `-q`).

Once the fleet has been read, adopt logs `read X of N servers`. When some servers
went unread under `--partial`, it logs this as a warning
(`read 1 of 2 servers — access on the others is NOT in the output`), writes the
partial manifest with a
`# WARNING: server NAME unreadable — its access is NOT represented` line for each
gap, and exits 1 so scripts notice the result is incomplete. A server whose only
problems are lines adopt cannot use (lines sshd ignores, or unparseable lines) counts
as read and is not called unreadable. Its other keys are adopted, and adopt exits 0.
The read count is logged as a warning
(`read 1 of 1 server — 1 server partly read: keys on lines adopt could not use are NOT in the output`),
and the manifest marks the server with
`# WARNING: server NAME partly read — keys on lines adopt could not use are NOT represented`.
When
`--partial` could read no server at all, adopt refuses before rendering, writes
no manifest to stdout or `-o` (under `--json`, stdout gets a report with
`"emitted": false`), and exits 3 with
`read 0 of N servers — nothing could be adopted; fix the errors above`.

An on-server key whose comment has tabs or control/format characters is adopted
**without** its comment (options + type + key are kept), with the warning
`key <fp> on <server>: comment contains control or format characters — adopted without its comment`.
Comment-less keys are named `adopted-key-<n>` from the first free `n`, so
`adopt --merge` re-runs continue the numbering (`adopted-key-2`, not
`adopted-key-1-2`). A line whose type token does not match its key material counts
as unparseable.

A found key line that sshd would ignore (an unknown option such as `no-ptty`, an
unquoted value such as `from=1.2.3.4`, a flag that has a value, a malformed
`expiry-time` such as `expiry-time="2027"`, or a repeated
`command=`/`from=`/`principals=` clause) is not access. sshd skips such a line and
keeps reading, so if a later line of the same key is valid, the key still logs in,
and adopt takes it from that line (in either line order). Only when sshd ignores
every line of a key does adopt report it like an unparseable line and not adopt it
(`sshd ignores this line: …`, or `sshd ignores each of its 2 lines; the first: …`).
Strict mode aborts with exit 1, and `--partial` skips the key and keeps the server's
other keys:

```console
error: server web-1: key SHA256:z/fSv0Z0RZS+Lccbc6ZoOWwt/fbj1VFJGSBKQbo4icE: sshd ignores this line: option "no-ptty" is not a recognized authorized_keys option
error: 1 server could not be fully read — nothing written; fix the errors above or re-run with --partial
```

An unknown key whose line logs in but has control or format characters inside an
option value (sshd accepts these; the manifest does not store them) is reported the
same way, as
`key <fp>: this line logs in, but the manifest cannot hold it: option "…" contains control or format characters — not adopted`.
A known user's key on such a line still extends that user's access, because the
manifest keeps the user's own line.

### `sshepherd apply`

The write path. Makes each targeted server's `authorized_keys` equal the manifest's
rendered desired state.

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--config` | `sshepherd.yaml` | Path to the manifest |
| `--known-hosts` | `~/.ssh/known_hosts` | `known_hosts` path (strict checking) |
| `--parallel` | `32` | Max concurrent server connections |
| `--offer-all-keys` | off | Offer every loaded key to every server (default: only the keys the manifest grants there). |
| `--server` | all | Restrict the run to this server (repeatable; canary rollout) |
| `--dry-run` | off | Plan and report only; never write |
| `--yes` | off | Skip the confirmation prompt (automation) |
| `--json` | off | Emit the plan and outcome as machine-readable JSON on stdout (needs `--dry-run` or `--yes`) |
| `--identity PATH` | none | Private key file to authenticate with, in addition to `ssh-agent` (repeatable); `~/` expands from `$HOME` |
| `--identity-passphrase-file FILE` | none | Default passphrase file for any encrypted `--identity` key |
| `--identity-passphrase PATH=FILE` | none | Passphrase file for one `--identity` key (repeatable); split at the **first** `=` — a key path containing `=` is unsupported |

`--dry-run` and `--yes` are mutually exclusive. `--yes` skips only the `[y/N]`
confirmation: an encrypted `--identity` key may still prompt for its passphrase on
the terminal (see [Authentication](#authentication)).

**JSON.** `--json` prints one indented JSON document on stdout at the end of the run
(`"schema": 1`; `command` names the kind — `apply`, `revoke` or `rotate`) and never
the text report; logs stay on stderr. It needs `--dry-run` or `--yes` — a script
cannot answer the prompt — otherwise the run exits `3` before the manifest is read:
`--json needs --dry-run or --yes (a script cannot answer the confirmation prompt)`.
A document is written exactly when the run exits `0`, `1` or `2` (`2`: a lockout not restored, a rollback that put back a key on the `revoked:` list, a changed or `@revoked` host key or a changed host key type at the login check, or a `--sweep` hit) (including an interrupt
after the plan, where unstarted servers are `pending` with `"error_kind":
"canceled"`); exit-`3` tool errors print no document. A write that fails after the
plan carries `error_kind` when the transport classified the failure (for example
`host_key_changed` when the host key changed between plan and write, `auth`,
`timeout`); refusals and verify failures carry none. Each server carries its
`class` (`converged`, `change`, `refused`, `unreachable`), its `outcome` (`applied`,
`refused`, `failed`, `pending` for a `change` server, `unproven` (written and verified, login not proven; its `error_kind` is the last login failure's, and one of `host_key_changed`, `host_key_revoked`, `host_key_type_changed` means exit 2), `lockout_unrestored`, `null` otherwise — always
`pending` under `--dry-run`), its `error`, and its `changes` (`add`, `remove`,
`rewrite` with `loosens` naming dropped restrictive options verbatim and `widens`
naming the relaxing options it adds (`[]` when none), `normalize`).
Comments and options are sanitized (control and Unicode format characters
removed), so they may not byte-match the server line.
Treat an unknown `outcome` value as not converged. `summary` also counts `unproven` and `lockout_unrestored`. A `failed` server, or a `lockout_unrestored` server whose `authorized_keys` was restored but whose `authorized_keys2` could not be moved back, names each removed key its rollback put back in `error`, and `restored_revoked_keys` lists those on the `revoked:` list (omitted when empty). `warnings` lists per-server warnings (omitted when empty), today the `--identity` headless-proof warning.
A dry run over a mixed fleet:

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
    "unproven": 0,
    "lockout_unrestored": 0,
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
            "loosens": [],
            "widens": []
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
      "error": "dial tcp 10.0.0.3:22: connect: connection refused",
      "error_kind": "dial",
      "hint": "check the host, port, and firewall; hosts reachable only through a bastion (ProxyJump/ProxyCommand) are dialed directly — jump hosts are not supported yet",
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

Each server may carry a `serial` object (`header`, null for no serial; `manifest`; `writes`, null when nothing is written; `case`: `forged`, `newer_converged`, `newer_removal_only`, `newer_refused`, `equal`, `header_only` or `older`) and `notes.serial`; `serial` is omitted when no row applied or when both serials are 0. The document may carry top-level `policy_conflicts`, `manifest_warnings` and `serial_bump` (`from`, `to`, null when the manifest cannot be saved; `saved`; `warning`), each omitted when empty; the schema stays 1. For `revoke` and `rotate`, `edit` adds `revoked` (always present, `[]` when none), `serial` (only when the edit was saved), `already_revoked` and `check_command`, and a new edit kind `record-key` records a key no user holds.

```
      "serial": {
        "header": 6,
        "manifest": 7,
        "writes": 7,
        "case": "header_only"
      }
```

```
      {
        "kind": "record-key",
        "user": "",
        "fingerprint": "SHA256:doxiASlJnKSD9j+JpVoWpfEFHjUrsF9ZYr+cir4FYjo"
      }
```

Optional fields, present only when they apply: `servers[].hint` (the remediation for
an unreachable or failed server; `error` never contains it) and
`changes.remove[].options` (on-server options of a key neither the manifest nor the
pre-edit manifest owns).
See `internal/apply/testdata/json_*.golden.json` for every shape.

Rewrite rows show what changes on a key line, and a rewrite that **drops a
restrictive option** (`from=`, `command=`, `restrict`, `no-agent-forwarding`,
`no-port-forwarding`, `no-pty`, `no-user-rc`, `no-X11-forwarding`, `verify-required`,
`expiry-time=`, the last `permitopen=`/`permitlisten=` (dropping one while others
stay narrows the union and is not flagged), `cert-authority`, `principals=`, or any
on-server option that makes sshd ignore the line today (an unknown option such as
`no-ptty`, a bad value, a repeated `command=`/`from=`/`principals=`): rewriting a
dead line into a live one is the widest change) or
**adds a relaxing option** (`no-touch-required` always, and `pty`,
`port-forwarding`, `agent-forwarding`, `X11-forwarding`, `user-rc` when both lines
carry `restrict`, and a further `permitopen=`/`permitlisten=` next to the server's
(sshd allows the union of all of them)) is painted red and followed by a warning — highlighted, not
refused. Dropping `no-touch-required` tightens access and is not flagged:

```console
web-1 (deploy@10.0.0.1:22)
  ~  alice (alice@work)  SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  rewrite options: "from=\"10.0.0.5\",command=\"/usr/bin/pg_dump-wrapper\"" → (none)
  ~  (formatting)                                                                         normalize: removing 1 duplicate key line (some carry options different from the first copy)
  -  (authorized_keys2)                                                                   disable ~/.ssh/authorized_keys2 → ~/.ssh/authorized_keys2.sshepherd.disabled (unmanaged; sshd would keep accepting its keys)
  warning: the rewrite of alice (alice@work)'s key drops restrictive option(s) "from=\"10.0.0.5\"", "command=\"/usr/bin/pg_dump-wrapper\"" — the manifest line grants more than the server does today
  → 3 keys desired · 0 add · 0 remove · 1 rewrite
```

A rewrite that adds a relaxing option is flagged the same way:

```console
web-1 (deploy@10.0.0.1:22)
  ~  alice (alice@work)  SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  rewrite options: (none) → "no-touch-required"
  warning: the rewrite of alice (alice@work)'s key adds relaxing option(s) "no-touch-required" — the manifest line grants more than the server does today
  → 2 keys desired · 0 add · 0 remove · 1 rewrite
```

After the writes, a summary reports each server's outcome:

```console
a: applied · verified
b: NOT STARTED: interrupted before the write started
c: FAILED: lockout prevented — restored previous file (post-write login offering only the surviving keys you hold failed: ssh: unable to authenticate)
Summary: 1/3 servers converged (1 applied) · 1 pending · 1 failed  → exit 1
```

A write whose login check never got past authentication is kept and reported `UNPROVEN`:

```console
web-1: applied · verified
web-2: UNPROVEN: written and verified, but the login check could not reach the server after 4 attempts (dial tcp 10.0.0.2:22: i/o timeout) — kept the new file; run sshepherd audit to confirm
  hint: check the host, port, and firewall; hosts reachable only through a bastion (ProxyJump/ProxyCommand) are dialed directly — jump hosts are not supported yet
Summary: 1/2 servers converged (1 applied) · 1 unproven  → exit 1
```

A rejected login check whose restore failed needs a human now:

```console
web-1: applied · verified
web-2: UNPROVEN: written and verified, but the login check could not offer the surviving keys you hold after 2 attempts (none of the 1 surviving keys is offered (agent locked, or keys removed since the plan)) — kept the new file; unlock the agent or re-add the key, then run sshepherd audit to confirm
web-3: LOCKOUT — NOT RESTORED: post-write login offering only the surviving keys you hold failed (ssh: unable to authenticate) AND restoring the previous file failed (restore on web-3 failed (exit 1): mv: denied) — the previous version is at ~/.ssh/authorized_keys.sshepherd.bak; repair it over a session that is still open
Summary: 1/3 servers converged (1 applied) · 1 unproven · 1 lockout not restored  → exit 2
```

A rollback names the keys it put back and marks those on the `revoked:` list:

```console
a: applied · verified
b: applied · verified
web-1: FAILED: lockout prevented — restored previous file (post-write login offering only the surviving keys you hold failed: ssh: unable to authenticate); it still grants alice (SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4, on the revoked: list) and bob (SHA256:zbv/nU7iZdO0fB0DalMI70dP6/yFD8sctXvvW4+OokY), which the manifest removed — fix the surviving key and re-run
Summary: 2/3 servers converged (2 applied) · 1 failed  → exit 2
```

**Ctrl-C / SIGTERM** during the writes stops new servers from starting; servers
already being written finish their write, verify and login probe (bounded by a
2-minute session budget), and a notice says so (`interrupt: finishing 2 in-flight writes (write, verify, login check — up to 2m); a second Ctrl-C abandons their login check and rollback`). Unstarted servers show `NOT STARTED` and count as pending
(exit 1). A second Ctrl-C kills the process immediately. An interrupt before any
write starts — during `apply`'s planning or at its `[y/N]` prompt — writes nothing
and exits `3`. In `audit` and `adopt`, an interrupt at any point closes in-flight
sessions and exits `3` without rendering a report or writing a manifest (servers cut
short are never passed off as unreachable).

**Weak keys.** A server that grants a weak key (DSA, RSA under 2048 bits) is refused and the rest of the plan proceeds, exit 1, except a write that grants nothing and removes at least one key: it cannot install or widen the weak key, so it proceeds. A server already holding exactly its keys stays refused until the weak key is gone. A refusal for a weak key never stops `revoke` or `rotate` from saving their edit.

**Serial bump.** A confirmed apply that removes a key from a server whose header serial
is not below the manifest's bumps `serial:` once, saving it under the manifest lock
after the prompt and before the first write:

```console
manifest serial: 0 → 1 (saved; this apply removes keys)
```

`--dry-run` prints `would bump serial: 0 → 1 (this apply removes keys)`. A piped
`--config` (or one the comment-preserving editor cannot save, e.g. with YAML anchors)
cannot be saved and warns `removing keys without a serial bump: an older copy could re-grant them` —
under `--dry-run` too — and the write proceeds. A failed save exits `3` with nothing
written and, under `--json`, no document. A run that sees any server written by a newer
manifest (refused, converged with the `written by newer manifest serial S` note, or a
removal-only write that keeps S) never bumps: that server proves this copy is stale, and
lifting it would let the next apply from it re-grant what the newer manifest revoked.
`--dry-run` prints no would-bump line in that case. A forged header is not evidence.
`--json` reports the bump as `serial_bump`:

```json
  "serial_bump": {
    "from": 7,
    "to": 8,
    "saved": true
  }
```

### `sshepherd revoke`

Removes users, keys, or a user's access to named servers from the manifest — comments
preserved — and pushes the edit through `apply`'s pipeline (plan → confirm → guarded
write → verify → login probe), restricted to the servers whose rendered
`authorized_keys` changes.

```console
$ sshepherd revoke alice                       # offboard: alice and every access entry naming her
$ sshepherd revoke bob --from-server db-1      # bob loses db-1 only; his keys and other grants stay
$ sshepherd revoke --key ~/lost-laptop.pub     # one key: a fingerprint, a key line, or a .pub path
$ sshepherd revoke --key SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4
```

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--key KEY` | none | Key to revoke: a `SHA256:` fingerprint, a public-key line, or a `.pub` file path (repeatable) |
| `--from-server NAME` | none | Remove the users' access to this server only (repeatable); the users and their keys stay |
| `--operator` | off | Confirm that a target is, or belongs to, an operator user (fleet-wide, protected) |
| `--no-apply` | off | Edit and save the manifest after confirmation; contact no server |
| `--reason` | none | Free text recorded with each `revoked:` entry this run adds (printed by every tool; at most 256 bytes) |
| `--sweep` | off | After the writes, read every other server and report any that still has a key this run revoked (read-only; exit `2` when one is found; skipped with `--dry-run` and `--no-apply`) |
| `--config` | `sshepherd.yaml` | Path to the manifest |
| `--known-hosts` | `~/.ssh/known_hosts` | `known_hosts` path (strict checking) |
| `--parallel` | `32` | Max concurrent server connections |
| `--offer-all-keys` | off | Offer every loaded key to every server (default: only the keys the manifest grants there). |
| `--dry-run` | off | Plan and report only; never write (the manifest is not changed) |
| `--yes` | off | Skip the confirmation prompt (automation) |
| `--json` | off | Emit the plan and outcome as machine-readable JSON on stdout (needs `--dry-run` or `--yes`) |
| `--identity PATH` | none | Private key file to authenticate with, in addition to `ssh-agent` (repeatable); `~/` expands from `$HOME` |
| `--identity-passphrase-file FILE` | none | Default passphrase file for any encrypted `--identity` key |
| `--identity-passphrase PATH=FILE` | none | Passphrase file for one `--identity` key (repeatable); split at the **first** `=` — a key path containing `=` is unsupported |

**Users or keys, not both.** `revoke USER...` deletes each user and every `access:`
entry whose `user:` is that user (unknown users are listed and nothing happens).
`revoke NAME` looks NAME up in the manifest first, so users called `tunnel` or
`Alice Smith` are revoked by name. Only an unknown name that looks like a key or
fingerprint gets `NAME looks like a key — did you mean --key?`.
Re-running a revoke for a user already revoked prints a note and exits `0` —
`bob was already revoked (2026-11-08); run 'sshepherd apply' to converge any server that still has the key`
(the hint carries your own non-default flags); with several users, the already-revoked
ones get the note and the rest are revoked as usual. With `--sweep`, a repeat also sweeps
for the recorded keys on every server and exits `2` if one is still installed. A name
that was never revoked
still exits `3` with `not in the manifest (already revoked?)`.
`revoke --key KEY...` removes each key line from its owner; a user left with no keys
stays with `keys: []`. A `KEY` is a `SHA256:` fingerprint (pasted `ssh-keygen -lf`
output works), a public-key line (quote it), or a path to a `.pub` file holding
exactly one key. MD5 fingerprints, certificates (`*-cert.pub`) and private keys are
refused with the fix; an error never quotes a file's contents. `revoke --key` of a key
no user has records it
(`manifest edit: record revoked key SHA256:n6ApDjw082BN1aZBgDkRXVuzv6lUdwKcxFRTkT4l+XU (no user has it; no server is written) — no servers affected`)
instead of failing; repeating it prints
`SHA256:n6ApDjw082BN1aZBgDkRXVuzv6lUdwKcxFRTkT4l+XU was already revoked (2026-11-08)` and exits `0`.

**Revocation memory.** Every revoke that saves records what it removed in `revoked:` —
`revoke USER` one key entry per key, `revoke --key` one per key (labelled with its
owner), `revoke USER --from-server NAME` one access entry naming the servers no `except:` remembers (a selector's new `except:` already remembers its server) — and bumps
`serial:` once. `revoke` refuses to save a manifest that would keep a policy conflict,
exit `3`, nothing saved —
`refusing to write the manifest — it would keep 1 policy conflict: key SHA256:n6ApDjw082BN1aZBgDkRXVuzv6lUdwKcxFRTkT4l+XU of user "dave" is revoked (2026-11-08, dave): remove it from users, or delete the revoked: entry to un-revoke it deliberately`;
`revoke --key` of the conflicting key is the fix.

A save that would **add** a weak key (DSA, or RSA under 2048 bits) is refused, exit `3`, with nothing saved or written. Any other save goes through while the manifest still holds a weak key: an unrelated edit is never blocked, and a weak key's own `rotate` or `revoke --key` always saves. A server that still grants a weak key after the edit is refused in the push (exit `1`), and the edit is saved anyway.

**One server, not the whole user (`--from-server`).** `revoke USER... --from-server NAME...`
takes the named servers away from each user and changes nothing else — the user
entry, its keys and its other grants stay. (Unlike `apply --server`, which only
restricts which servers a run touches, `revoke --from-server` edits the grants.) An
explicit `servers:` list loses every occurrence of the server, and an entry left
empty is deleted (its comment moves on, as for a removed user). A selector entry (`servers: ["*"]`, or one with an `@tag`) gets each server it still reaches appended to `except:` — created right after `servers:` when absent. A server the entry also names loses that item too. A wildcard keeps covering servers added later, so a wildcard that would then cover no current server is deleted, with a warning that later servers are no longer granted automatically. An `@tag` entry left with no name and nothing but excepted members is deleted the same way, without that warning, because a tag promises no future server. When a trim deletes an entry with an `except:`, every server that `except:` remembered also gets an access tombstone, because the deleted `except:` was the only record; the entry carries this run's date. Refused with exit `3` and nothing edited: `--from-server`
with `--key` (access is per user), with `--operator`, or on an operator user
(operators have every server by definition), `--from-server` with `*` or an `@tag` (use `revoke USER`), an
unknown server, and any user × server pair the user has no access to — every problem
is listed in one message. Only the trimmed servers are contacted, and there is no
`check every server:` line (no key is removed). The edit
header says how many other servers each user keeps; `revoke USER` without `--from-server`
removes every grant.

```console
manifest edit: remove alice's access to web-1 (1 access entry changed); alice keeps access to 3 other servers — 1 server affected
```

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
installed on a server that never granted it is drift `revoke` does not reach — every
run that removes a key and does not sweep ends with `check every server: sshepherd audit`
(your own non-default flags included), which exits `2` while a revoked key is still
installed anywhere. An affected server whose keys already match gets a header-only update
carrying the new serial, so an older copy of the manifest is refused there too.

**Confirmation.** `revoke` always asks — even when every affected server already
matches, since the manifest edit is itself a change — or needs `--yes`. The prompt
names what will happen (all forms, from the golden test):

```console
save manifest edit and write 2 of 3 affected servers? [y/N]
save manifest edit (no servers need a write)? [y/N]
save manifest edit (no servers need a write)? [y/N]
save manifest edit? [y/N]
OPERATOR ops-bot: save manifest edit and write 1 of 4 affected servers? [y/N]
OPERATORS ops-bot, ci: save manifest edit? [y/N]
save manifest edit and write 1 of 1 affected server? [y/N]
```

Declining exits `1` with `aborted; manifest not changed, nothing written`. When no
affected server can converge (every one refused), nothing is saved and the run
exits `1` without a prompt. `--dry-run` saves nothing and exits exactly as
`apply --dry-run` would. After the save the run prints
`manifest PATH updated — commit and push it: an apply from a copy without this edit is refused on the servers this run writes (serial 2)`
(under `--no-apply` the note is `servers learn serial 1 only when an apply writes them; until then a copy without this edit can re-grant there`);
servers left unconverged (failed,
refused for a fixable reason, unreachable, interrupted) are named in a ready-made
`sshepherd apply --server …` command. Follow-up hints repeat the run's own
`--config`, `--known-hosts`, `--identity*` (paths only) and `--offer-all-keys` flags, so they can be
pasted as is; `--no-apply` hints leave out servers that would be emptied.

**`--no-apply`** shows the header, asks, saves, and contacts nothing; it refuses
`--identity*`, `--known-hosts`, `--parallel` and `--offer-all-keys` (they would be silently unused).
`--dry-run --no-apply` prints the header (and the `check every server:` line when a
key is removed).

**Post-revoke sweep.** With `--sweep`, after the writes revoke reads every other
server (the run's own known_hosts, keys and `--parallel`; also
`~/.ssh/authorized_keys2` where the managed path is the default) and reports any that
still holds a key this run revoked:

```console
REVOKED KEY STILL INSTALLED: bob SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4 on web-2 — run 'sshepherd apply --server web-2'
swept 1 of 2 servers: 1 still has a revoked key, 0 unreachable
```

A server the manifest leaves empty gets
`REVOKED KEY STILL INSTALLED: bob SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4 on db-9 — remove it by hand or grant another user there first`,
and a copy in `authorized_keys2` is named as
`REVOKED KEY STILL INSTALLED (authorized_keys2): bob SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4 on web-2`.
The sweep only reads. It is skipped under `--dry-run` and `--no-apply`, which print
the audit command instead. It exits `2` when a revoked key is found and `1` when a
server could not be read or could not prove the removal
(`cannot prove removal on web-3 (unreachable)`,
`cannot prove removal on db-7 (authorized_keys2 unreadable)`). A repeated revoke whose
every target was already revoked sweeps too, for the keys already recorded. A server
whose `authorized_keys` has a line the parser refuses cannot prove the removal:
`cannot prove removal on db-2 (authorized_keys has unparseable lines)`, exit `1`. A
Ctrl-C reaching the sweep keeps the report: unread servers show
`cannot prove removal on db-2 (sweep interrupted)`, are not counted in `swept N of M`,
and the run exits `1` (or `2` if a key was found), never `3`. On a run that contacts no
server for its edit (an unowned `--key`), the sweep's known_hosts and credentials check
runs before the save, so a failure exits `3` with nothing saved. Under `--json` the
document gains a `sweep` object (from the golden fixture), and `edit.check_command`
is absent:

```json
  "sweep": {
    "checked": 2,
    "still_installed": [
      {
        "server": "db-2",
        "fingerprint": "SHA256:zbv/nU7iZdO0fB0DalMI70dP6/yFD8sctXvvW4+OokY",
        "user": "bob",
        "file": "authorized_keys2"
      }
    ],
    "unreachable": [
      "db-3"
    ],
    "unprovable": []
  }
```

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
    ],
    "revoked": []
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
    "unproven": 0,
    "lockout_unrestored": 0,
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
`OPERATOR:` line, the prompt is prefixed `OPERATOR NAME: ` (`OPERATORS A, B: ` for
several), and revoking an
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
$ sshepherd revoke bob --from-server db-1 --dry-run
$ sshepherd revoke bob --from-server db-1
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
| `--reason` | none | Free text recorded with the old key's `revoked:` entry (`rotated out` when not given; printed by every tool; at most 256 bytes) |
| `--sweep` | off | After the writes, read every other server and report any that still has a key this run revoked (read-only; exit `2` when one is found; skipped with `--dry-run` and `--no-apply`) |
| `--config` | `sshepherd.yaml` | Path to the manifest |
| `--known-hosts` | `~/.ssh/known_hosts` | `known_hosts` path (strict checking) |
| `--parallel` | `32` | Max concurrent server connections |
| `--offer-all-keys` | off | Offer every loaded key to every server (default: only the keys the manifest grants there). |
| `--dry-run` | off | Plan and report only; never write (the manifest is not changed) |
| `--yes` | off | Skip the confirmation prompt (automation) |
| `--json` | off | Emit the plan and outcome as machine-readable JSON on stdout (needs `--dry-run` or `--yes`) |
| `--identity PATH` | none | Private key file to authenticate with, in addition to `ssh-agent` (repeatable); `~/` expands from `$HOME` |
| `--identity-passphrase-file FILE` | none | Default passphrase file for any encrypted `--identity` key |
| `--identity-passphrase PATH=FILE` | none | Passphrase file for one `--identity` key (repeatable); split at the **first** `=` — a key path containing `=` is unsupported |

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
- Plain `rotate` records the old key in `revoked:` (`reason` is `--reason`, or
  `rotated out` when not given); `--keep-old` records nothing — the finishing
  `revoke --key OLD` does — but bumps `serial:` all the same.
- Confirmation, saving, `--dry-run`, `--no-apply`, operators and the `check every server: sshepherd audit` line work
  exactly as for `revoke` (no check line under `--keep-old`: nothing is removed).
- `--sweep` works as in [`revoke`'s post-revoke sweep](#sshepherd-revoke): it looks for
  the rotated-out key on every other server; `--keep-old` revokes nothing, so it has
  nothing to look for.
- `rotate` refuses, exit `3`, to save a manifest that would keep a policy conflict —
  in particular `--new` of a revoked key
  (`refusing to write the manifest — it would keep 1 policy conflict: key SHA256:n6ApDjw082BN1aZBgDkRXVuzv6lUdwKcxFRTkT4l+XU of user "dave" is revoked (2026-11-08, dave): remove it from users, or delete the revoked: entry to un-revoke it deliberately`).
- A save that would **add** a weak key (DSA, or RSA under 2048 bits) is refused, exit `3`, with nothing saved or written. Any other save goes through while the manifest still holds a weak key: an unrelated edit is never blocked, and a weak key's own `rotate` or `revoke --key` always saves. A server that still grants a weak key after the edit is refused in the push (exit `1`), and the edit is saved anyway.
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
`sshepherd revoke --key OLD`, plus the run's own `--config`, `--known-hosts` and
`--identity*` flags when not the defaults (paths only, so it can be pasted as is) and
`--operator` for an operator, whose hint gets a second line about `--identity`. It reads
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

`audit`, `adopt`, `apply`, `revoke` and `rotate` load keys from two sources, like
`ssh -i` (`revoke` and `rotate` write through `apply`'s pipeline, so everything said
about `apply` below holds for them too):

1. **`--identity` key files**, in flag order;
2. **the SSH agent** at `SSH_AUTH_SOCK`, in the agent's own order (certificates
   included).

A key in both is loaded once. Loading a key does not mean every server is offered it:
see [Key offering](#key-offering). With at least one `--identity`, a missing, empty or
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

1. its `--identity-passphrase PATH=FILE` mapping — a wrong passphrase there is an
   error (exit 3), never a fall-through;
2. `--identity-passphrase-file FILE` — a shared default: if it does not unlock this
   key, resolution continues;
3. a prompt on the controlling terminal (`/dev/tty`, three attempts, like `ssh`);
4. otherwise exit 3: `PATH is encrypted and no passphrase source is available (use --identity-passphrase-file or --identity-passphrase PATH=FILE)`.

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
  sensitive. An `--identity-passphrase` PATH must name an `--identity` exactly as
  cleaned (the error lists the cleaned paths); the same PATH twice is an error; a
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
the surviving keys in the order every later run offers them) proves the new key logs
in. Then commit and push the
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

**GitOps PR check** — no fleet access needed. `--strict` fails on host-key gaps too, so commit a known_hosts file for the job:

```yaml
- name: validate the manifest
  run: sshepherd validate --strict --known-hosts ci/known_hosts --config sshepherd.yaml
```

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

SIGKILL cannot be handled, so give a write time to finish: `docker stop -t 150`, or Kubernetes `terminationGracePeriodSeconds: 150`, more than the 2-minute session budget.

### Key offering

Each server is offered only the keys the manifest grants there (plus operator keys), so a managed server never learns the rest of your keys. A held key that matches through a certificate's key or its CA counts as granted.

`revoke` and `rotate`, including their `--sweep`, offer the keys granted before the edit first, then the keys granted after it: a server that has not been written yet still holds the old keys. A sweep that cannot log in to a server reports it unreachable (exit `1`) and logs each distinct hint once, on stderr.

If you hold none of the keys granted on a server (normal right after `import --servers-only`), every loaded key is offered with one warning. Before any connection, a run warns once when no loaded key is granted on any target server and silences the per-server line. The fallback is about what you **hold**, not what the server has installed: a key granted and held but not yet installed (a new VM with only its cloud-init key, or a key changed by hand in the manifest) fails with `auth`, and the report's hint names `--offer-all-keys`. There is no automatic retry, because that would hand every held key to any server that refuses the granted ones. Bootstrap: `sshepherd apply --server NAME --offer-all-keys`.

## Exit codes

Monitoring-style, one table shared by `audit`, `apply`, `revoke` and `rotate`
(`adopt`, `import` and `validate` use `0`, `1` and `3` as their own footers below say):

| Code | `audit` | `apply` | `revoke` / `rotate` |
| ---- | ------- | ------- | ------------------- |
| `0` | Compliant (a header serial below the manifest's is not drift) | Converged — nothing to do, including a header-only write applied and a newer-serial server with an equal body (with a note) | Converged (with `--sweep`: no revoked key found); a repeated `revoke` whose targets were already revoked (with `--sweep`: no revoked key found); or `--no-apply` saved the edit without pushing it (run the `apply` hint it prints) |
| `1` | Drift or unreachable servers — compliance not proven; a server serial ahead of the manifest; a key installed where its access was revoked; a posture finding short of world-writable (`symlink`, `foreign_owner`, `group_writable`); a failed or malformed posture probe (`error_kind: remote`); `host_key_type_unrecorded`, now only when every recorded type is unsupported; an invalid certificate from a vouched CA (`host_key`) | Pending changes (including a header-only write under `--dry-run`), refused servers (a newer manifest's serial, a policy conflict, a granted weak key, a no-grant server whose `authorized_keys2` holds keys, a header-only write the guard refuses), failed or unreachable servers, a write whose login check could not prove access (`unproven`), other than the host-key alarms in row `2` | Not converged, unproven, as for `apply`; `--sweep` could not read a server or prove the removal |
| `2` | **Critical**: a missing operator key or an operator key present but unable to log in (`cert_only`, `expired`, `ignored`), a host key that **changed**, a host key type that changed, a host key `@revoked` in `known_hosts` (possible impersonation), a world-writable managed path, a revoked key still installed, a policy conflict (including a granted weak key), a forged header serial | **Lockout not restored** (`lockout_unrestored`: after a rejected login check the restore of `authorized_keys` failed or `authorized_keys2` could not be moved back, a restore over a dropped connection could not be retried, or the reconnect after the upload started was refused); a **rollback that put back a key on the manifest's `revoked:` list** (`failed`); the post-write login check **stopped at a changed or `@revoked` host key, or a changed host key type (`host_key_type_changed`)** (`unproven`) | As for `apply`, or `--sweep` found a revoked key still installed |
| `3` | Tool error — bad flags, unloadable manifest, failed preflight, an `--identity` key that cannot be read, is refused, or has no passphrase source, interrupted | Tool error — as for `audit`, interrupted before any write, a manifest that changed since it was read, a failed serial save | Tool error — as for `audit`, a run refused before anything is saved (unknown user (never revoked), an unknown or ungranted `--from-server`, an operator target without `--operator`, a manifest the edits cannot handle or that is not a regular file, a manifest that would keep a policy conflict, a concurrent save). `3` for saving commands additionally covers a save that would **add** a DSA or RSA<2048 key; unrelated saves and a weak key's own `rotate`/`revoke --key` always save |

With `--json`, `audit`, `apply`, `revoke`, `rotate` and `validate` write their report as their own sections say. `adopt` writes one on exit `0` and `1`, with `emitted` saying whether a manifest was produced, and on exit `3` only for `--partial` with no server read. `import` writes one only on exit `0`.

A tag problem (an unknown `@tag`, a malformed tag, a selector in `except:` or in a tombstone's `servers:`) is a manifest load error, so it is exit `3` on every command. A blocked grant and the `wildcard_root` warning change no exit code, except that `validate --strict` exits `1`.

`--help` shows this summary. `audit --help`:

```console
Exit codes:
  0  compliant (a header serial below the manifest's is not drift)
  1  drift or unreachable servers (compliance not proven), including a server
     written by a newer manifest serial and a key installed where its access
     was revoked
  2  critical: a missing operator key or one that cannot log in, a changed or
     @revoked host key or a changed host key type, a world-writable managed
     path, a revoked key still installed, a forged header serial, or a policy
     conflict in the manifest
  3  tool error: bad flags, unloadable manifest, failed preflight, interrupted
```

`apply`, `revoke` and `rotate --help`:

```console
Exit codes:
  0  converged: nothing left to do (a header-only update applied, or a server
     a newer manifest wrote whose keys already match); a revoke whose targets
     were already revoked; or, with revoke/rotate --no-apply, the edit is
     saved but not pushed (run the apply hint it prints)
  1  pending changes, unreachable, refused or failed servers (a newer
     manifest's serial, a policy conflict), a write whose login check could
     not prove access (unproven), or a declined prompt; with --sweep, a server
     the sweep could not read
  2  a human must act now: a lockout not restored (the restore of
     authorized_keys or authorized_keys2 after a rejected login check failed,
     or the reconnect after the upload started was refused), a rollback that
     put back a key on the revoked: list, a changed or @revoked host key or a
     changed host key type at the post-write login check, or revoke/rotate
     --sweep found a revoked key still installed
  3  tool error: bad flags, unloadable manifest, failed preflight, a manifest
     that would keep a policy conflict or add a weak key, a failed serial
     save, or refused before anything was saved or written
```

`adopt --help`:

```console
Exit codes:
  0  manifest emitted
  1  a server could not be fully read and --partial was not given (nothing
     emitted), or --partial could not read some servers (the partial manifest
     is emitted)
  3  tool error: bad flags, unloadable manifest, failed preflight, an existing
     --output without --force, an in-place save refused, a manifest that
     would keep a policy conflict or add a weak key, --partial with no server
     read, interrupted
```

`import --help`:

```console
Exit codes:
  0  manifest emitted
  3  tool error: bad flags, unreadable ssh config or --merge manifest, an
     existing --output without --force, an in-place save refused, a --merge
     manifest that would keep a policy conflict or add a weak key
```

`validate --help`:

```console
Exit codes:
  0  valid (warnings may be present)
  1  valid, with warnings, under --strict
  3  invalid, a policy conflict, or a tool error: bad flags, unreadable
     manifest, a bad --known-hosts file
```

## Safety model

`apply` writes to production machines, so it is built to fail closed.

**Full-file rewrite.** Each managed file is rendered from scratch: a managed header
(`# Managed by SSHepherd. Manual edits will be overwritten by 'sshepherd apply'.`, or
`# Managed by SSHepherd (serial 7). Manual edits will be overwritten by 'sshepherd apply'.` once the manifest has a `serial:`),
operator keys first, then the granted keys, with the decided comment policy applied.
Non-key lines — hand-written comments, blank lines — are **deleted** by the rewrite;
the plan shows a `normalize` row with the exact count *before* anything is written.
Output is deterministic, so a repeated `apply` is a byte-for-byte no-op.

**Manifest authority.** Once the manifest has a `serial:`, the managed header carries it as `(serial N)`, and apply compares each server's header serial S with the manifest's M. A server written by a newer manifest (S > M) is refused unless the write only removes keys. With an equal body it is converged with a note (exit 0). A removal-only write proceeds and keeps S, so a server's serial never goes down. A header more than 1000 above M is treated as forged, as if it had no serial, and is rewritten. `revoke` and `rotate` write a header-only update on affected servers whose keys already match. A confirmed `apply` that removes a key from a server whose header serial is not below M bumps `serial:` once and saves it before the first write.

```
s-forged (deploy@10.0.0.1:22)
  ~  (header)      update header: forged serial 5000 → 7 (keys unchanged)
  warning: header claims serial 5000, far above this manifest's 7 — treated as no serial
  → 2 keys desired · header only

s-headeronly (deploy@10.0.0.2:22)
  ~  (header)      update header: serial 6 → 7 (keys unchanged)
  → 2 keys desired · header only

s-newer (deploy@10.0.0.3:22)  converged (no changes)
  note: written by newer manifest serial 8 (yours is 7): pull the latest manifest

s-older (deploy@10.0.0.4:22)
  +  alice  SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  add (authorized, missing)
  → 2 keys desired · 1 add · 0 remove · 0 rewrite

s-refused (deploy@10.0.0.5:22)  REFUSED: written by manifest serial 8, this manifest is 7 — a newer manifest revoked or rotated keys here; pull the latest manifest, or if you are sure, set serial: 8 in your manifest (this is the only override)

s-removal (deploy@10.0.0.6:22)
  -  (unknown) "stray"  SHA256:doxiASlJnKSD9j+JpVoWpfEFHjUrsF9ZYr+cir4FYjo  ssh-ed25519  remove (unauthorized)
  warning: written by newer manifest serial 8; this write only removes keys, so it proceeds
  → 2 keys desired · 0 add · 1 remove · 0 rewrite
```

**Policy conflicts.** A server a policy conflict names is refused with the conflict message (exit 1); the rest of the fleet is planned normally. A weak-key conflict has one exception: a write that grants nothing and removes at least one key proceeds.

**Known limitations of the serial.**

- The header-only write happens only in the run that bumps. An affected server that run
  does not write (`--no-apply`, unreachable, refused, or a run declined or interrupted)
  and whose keys already match keeps its older header until its next real change, so a
  copy older than the revoke can still re-grant there. Run `revoke` with its apply phase
  rather than `--no-apply` followed by `apply`: a plain `apply` cannot tell those servers
  from unaffected ones.
- A hand edit does not bump the serial by itself. `apply` bumps it only when it writes a
  removal on a server whose header serial is not below the manifest's and no server in
  that run was written by a newer manifest, and only the servers that run writes carry
  the new value, so a copy taken at the same serial can still re-grant on the others. A
  stale copy run with `--server` sees only the selected servers, so it can still bump
  when the newer serial is elsewhere.
- Two branches that each bumped to the same serial cannot be told apart; git discipline
  is the control for that case.
- The `--sweep` read of `authorized_keys2` happens only on the default path.
- Deleting a `revoked:` entry by hand is a deliberate un-revoke, audited only by git
  history.
- An access entry naming a removed server is ignored for it, with a warning; re-adding a
  server under the same name re-applies the entry.

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

**The manifest lock file must be yours.** The lock sidecar
`.NAME.sshepherd-lock` must be a regular file owned by you or by the manifest's
owner. A symlink, FIFO or foreign-owned file is refused and never followed
(`lock manifest: PATH is a symlink; refusing to follow it — remove it and re-run`,
`… is not a regular file — remove it and re-run`,
`… is owned by uid U, not by you (uid V) or the manifest's owner — remove it and re-run`).
A save also keeps the manifest's group when the directory would hand new files
another group (BSD or setgid-directory inheritance). The same lock and rules cover
an in-place `adopt`/`import -o FILE --force` (see Output files).

**Plain `apply` re-checks the manifest.** Just before its first write, `apply`
re-reads the manifest; if a concurrent `revoke` (or anything else) changed it since
the plan was made, the run stops with nothing written (`exit 3`) instead of
reinstalling a revoked key. A manifest piped in (`--config /dev/stdin`,
`--config <(...)`) cannot be re-read, so the check is skipped for it.

**Refusals, not guesses.** A server is skipped — loudly, with a `REFUSED:` line, and
nothing changed (no file, backup or directory is created) — when:

- the manifest grants nobody but keys are installed (refusing to wipe);
- the manifest grants nobody, nothing is installed, but `~/.ssh/authorized_keys2` holds keys
  (`authorized_keys2 holds keys but the manifest grants none — refusing to wipe; remove it by hand`;
  `audit` reports the same server as drift, so both exit 1);
- the file contains unparseable lines (refusing to rewrite a file it could not fully
  read);
- the rendered file would exceed the 1 MiB the read path accepts
  (`rendered file is N bytes, over the 1048576-byte limit the read path accepts — refusing to write a file that could never be verified or audited`);
- a serial bump would push a rendered file over that limit: the whole run is withheld before the prompt, nothing saved or written, exit 1. Its message is `<server>: the serial bump to N would make the rendered file B bytes, over the L-byte limit the read path accepts — nothing saved or written (split the grant across accounts)`, and under `--json` it is `serial_bump.warning`;
- the target is a symlink, its directory is a symlink, or the file or directory is
  not owned by the login user (log in as the owning user — managing another user's
  file as `root` is refused);
- an ancestor directory — walked both as written and with symlinks resolved, up to
  the login user's home (or `/` for a path outside it), like sshd's `StrictModes` —
  is owned by anyone but the login user or root, or is group/other-writable;
- the file **changed since the plan was read**
  (`… changed since the plan was read — refusing to overwrite unreviewed content; re-run apply`);
- another apply holds the file's lock
  (`another apply is in progress on ~/.ssh/authorized_keys (lock held by ci-runner-3 pid 4121 for 3m12s); remove it only if no apply is running on ci-runner-3 (pid 4121): ssh -p 22 deploy@10.0.0.1 'p="${HOME:?}"/'\''.ssh/authorized_keys'\''; rm -f -- "$p.sshepherd.lock/owner"; rmdir -- "$p.sshepherd.lock"' (a killed write can also leave ~/.ssh/authorized_keys.sshepherd.tmp and ~/.ssh/authorized_keys.sshepherd.cas; the next write reclaims both)`).
  The refusal names who holds the lock and for how long (a lock with no record reports `an unknown owner (older sshepherd or killed shell)`) and prints the exact removal command. SSHepherd never removes a lock itself and has no flag to; check that no apply is running there first. A killed write can also leave `<path>.sshepherd.tmp` and `<path>.sshepherd.cas`; the next write reclaims both. Two applies
  racing for the lock never leave one behind.

**One guarded write per server.** Each write is a single remote script in one
session, which in order: refuses an unsafe path — walking the nearest existing
ancestor *before* creating any missing directory and the full path again after,
removing only the directories it created (never one that existed before, even through
a `..`) on any refusal or failure, so a refusal leaves nothing behind; takes
the per-file lock `<path>.sshepherd.lock`; uploads to `<path>.sshepherd.tmp` under
`umask 077`, checks the received byte count and flushes it to disk; then, in one
tight step, copies the current file aside, compares that copy with the plan's
snapshot (byte length plus POSIX `cksum`, or absent vs. present) so *what you
reviewed is what gets replaced* — a key another tool added during the upload refuses
the write (`changed since the plan was read`) instead of vanishing — keeps that same
copy as `.sshepherd.bak` (flushed too), and `mv`s the upload into place. Flushes are
per file (`dd conv=fsync`, never a global `sync`); the directory entry is not
flushed, so after a crash you see either the old or the new complete file. Readers
never see a half-written file. If the connection drops during the upload or the verify, SSHepherd opens one fresh connection, takes the file's lock and re-reads it. The render in place means the rename happened, so the run continues; the planned bytes mean `connection dropped before the rename; original untouched (re-checked under the lock)`; anything else, or a lock that never frees, is `connection dropped; the file is in an unknown state (previous version at <path>.sshepherd.bak) — run sshepherd audit`. If that fresh login is refused with an authentication error after the upload started, the server is reported `LOCKOUT — NOT RESTORED: connection dropped after the upload started and a fresh login offering the keys you hold was refused (…)` and the run exits `2`; the previous version is at `<path>.sshepherd.bak`.

**Backups.** `<path>.sshepherd.bak` holds the previous version and is replaced by
every write that rewrites `authorized_keys`. `.bak` is not rotated by a write that only moves `authorized_keys2` aside: `authorized_keys` is compared and left alone when it already matches. `<path>.sshepherd.orig` holds the pre-SSHepherd original: it is written
once, the first time an unmanaged file is replaced (flushed to disk before the rename,
like `.bak`), and never overwritten. The one-time `.sshepherd.orig` is taken only when the
file's first line is not a managed header — the exact `ParseHeader` grammar, decided on the
bytes the compare-and-swap just proved — use it to undo the first apply. A symlink planted at either name is never written through.

**`authorized_keys2`.** When phase 1 found a non-empty `~/.ssh/authorized_keys2`
(default path or an equivalent spelling), the plan shows
`disable ~/.ssh/authorized_keys2 → ~/.ssh/authorized_keys2.sshepherd.disabled` and the
write moves it aside after the verify and before the login probe — even when
`authorized_keys` itself already matches. A moved-aside copy is never overwritten: if `authorized_keys2.sshepherd.disabled` already exists, the copy is named `authorized_keys2.sshepherd.disabled.<UTC YYYYmmddTHHMMSSZ>` (plus `.<pid>` if that is taken too). The plan row always shows the base name. Copies accumulate; SSHepherd never deletes them. A server apply does not write keeps a hand-removal warning instead; a server the
manifest grants nobody whose `authorized_keys2` holds keys is refused (exit 1), never
written. If the move fails, the server is
reported `FAILED` (its `authorized_keys` was still written and verified). A plan that only moves `authorized_keys2` keeps every path refusal above: a symlinked or foreign-owned `authorized_keys`, or an unsafe ancestor, is `REFUSED:` and `authorized_keys2` is left in place. If its login check is refused, the report reads `lockout prevented — moved authorized_keys2 back (…); authorized_keys was not changed`. If the login check is refused and the copy cannot be moved back, on this kind of plan or after `authorized_keys` was restored, the server is `LOCKOUT — NOT RESTORED:` (`lockout_unrestored`) and the run exits `2`: a key whose `authorized_keys` line refuses this client (for example `from=`) may have been able to log in only through `authorized_keys2`.

**Verify, then prove you can still log in.** After the rename the file is re-read in
the same session and compared byte-exactly. Then SSHepherd opens a **fresh
connection offering only the surviving keys you hold**, in exactly the order every
later connection offers them (see Connection posture), so the probe proves the key
the next run logs in with; it no longer prefers `--identity` key files over agent
keys. It runs a probe command over it, so a surviving key whose line forces a `command=` fails
the probe just like a refused login. The check is sorted by how far it got. A login that never finished authentication proves nothing about the server: a dial or handshake failure is retried (up to 4 attempts, waits 0/2/5/10 s, all inside the 2-minute session budget), a locked or emptied agent once, and a host-key alarm not at all; then the new file is **kept** and the server reports `UNPROVEN: written and verified, but the login check could not reach the server after 4 attempts (…) — kept the new file; run sshepherd audit to confirm`, because undoing could reinstall a key the manifest removed. That is exit `1`, except that a login check stopped by a changed or `@revoked` host key, or a changed host key type, is exit `2`. A login that was refused (every surviving key you hold offered and refused, or `MaxAuthTries`), or anything that goes wrong after it succeeded (a forced `command=`, a session that will not open, a probe command that hangs past 15 s), restores the previous file (and a disabled `authorized_keys2`) over the still-open session: `lockout prevented — restored previous file (…)`. The restore takes the lock again, waits out a busy lock (1, 3 and 6 s, naming the lock's owner and age if it never frees) and refuses to replace a file that changed since this apply wrote it (a concurrent apply); over a dropped connection it is retried once over a fresh login, and a retry that finds the previous file already back counts as restored. If the restore fails or is refused, the message says so and names the `.bak` path. A restore that fails or is refused is reported `LOCKOUT — NOT RESTORED:` and is exit `2`, and so is an `authorized_keys2` that cannot be moved back after `authorized_keys` was restored: `restored previous file (…), but restoring authorized_keys2 failed (…)`. A rollback puts back the keys the plan removed; the `FAILED:` line names each one and marks those on the manifest's `revoked:` list, and a key on that list makes it exit `2`. In a run that mixes agent and `--identity` keys, after a passing login check one more login offers only the unrestricted key files; a failure there never undoes the write and only warns, on stderr as `warn: web-1: your --identity key /k/ci could not log in on its own (…); a headless run with only that key would fail` and in the JSON `warnings` array.

**Connection posture.** Key files and/or agent (see
[Authentication](#authentication)), strict `known_hosts` with no TOFU, per-server and dial timeouts, and bounded fan-out (`--parallel`, default 32,
tuned from the fan-out benchmarks). `known_hosts` is parsed once per run. Host-key
algorithms are negotiated in the order `known_hosts` implies, so a host with an sshd
`HostCertificate` still works when its plain key is pinned; certificate algorithms
are offered only when a matching `@cert-authority` line exists.
A server presenting a different host key type than `known_hosts` records, or a certificate no `@cert-authority` line for this host vouches for, is an impersonation alarm (`host_key_type_changed`, exit `2`). Each server is offered only the keys the manifest grants there (`--offer-all-keys` turns the filter off; see [Key offering](#key-offering)), which
also avoids sshd `MaxAuthTries` lockouts with many held keys,
in one order shared by audit, adopt, apply and the post-write probe: plain lines
first, then lines that may reject the login (`from=`, `expiry-time=`, `restrict`),
then forced `command=` lines, then certificate-only lines (`cert-authority`,
`principals=`); manifest order (operators first, then grant order) within each group.
A session therefore authenticates with an unrestricted key whenever one is held, so
a key that gains a forced `command=` cannot capture later runs. Remote commands always run under `/bin/sh`. Audit's posture check mirrors StrictModes.

**Output safety.** Terminal escapes from server-supplied text are stripped and
newlines collapsed, so a hostile server cannot forge report rows or a summary line.
Server-supplied text in error lines (remote stderr, disconnect or handshake text a
server sends while connecting, and the message of a rejected session channel) is further reduced to printable ASCII plus Latin
letters (anything else shows as `?`), collapsed to one line, and cut at 256
characters (`…(truncated)`).

## Development

Everything below runs the same commands CI runs.

```console
$ make check        # the full gate: tidy, fmt, vet, lint, layering, deadcode, security, licenses, coverage (≥93%, production packages; test helpers excluded)
$ make test         # go test -race with an atomic coverage profile
$ make coverage     # coverage report; fails below 93% line coverage (production packages; test helpers excluded)
$ make integration  # two dockerized alpine sshd containers + build-tagged integration/E2E tests
$ make integration IT_DISTRO=debian  # or alpine | rocky
$ make fuzz         # every Fuzz* target, found automatically (FUZZTIME=15s each); fails if a package's tests do not build
$ make fuzz-list    # every Fuzz* target as 'importpath Target'
$ make layering     # fail when the import graph breaks the package layers (transitive go list -deps check; depguard covers direct imports)
$ make licenses     # dependency licenses of the shipped binary stay Apache-2.0-compatible (part of make check)
$ make actionlint   # lint .github/workflows (shellcheck disabled; not part of make check)
$ make secrets-history BASE=<sha>  # gitleaks over BASE..HEAD (whole history when BASE is empty, all-zero or unknown)
$ make dist GOOS=linux GOARCH=amd64 VERSION=vX.Y.Z  # release binary dist/sshepherd_<VERSION>_<GOOS>_<GOARCH>
$ make bench        # fan-out benchmarks
$ make hooks        # install the lefthook pre-commit/pre-push hooks
$ make tools        # install pinned dev tooling (exact versions, no @latest)
```

`make integration` also runs the revocation-memory end-to-end tests: the E2E loop adds `TestE2ERevokeNoResurrect` (adopt → apply → a revoke with one server unreachable → `adopt --merge` skips the revoked key → audit exit 2 → `apply --server` → audit 0), `TestE2EStaleManifestRefused` (an old copy refused on every affected server, including a header-only one) and `TestE2EStaleManifestAfterHandEdit` (D4b).

`make tidy` (part of the gate) uses `go mod tidy -diff`: it fails and prints the
needed change when `go.mod`/`go.sum` are not tidy, and never rewrites them. Re-run
`make tools` after upgrading Go — `make lint` refuses a `golangci-lint` built by a
different Go toolchain, and `make gosec` fails if gosec cannot type-check the code. The gate supports the Go 1.27 line (what CI runs): when the
`go` on your `PATH` is from another line (e.g. Homebrew's newest), every `make`
target — and the pre-push hook, which goes through `make` — runs under the pinned
`go1.27.3` instead, which the `go` command downloads once. Set `GOTOOLCHAIN`
yourself (`make GOTOOLCHAIN=local …`) to override.

The gate includes `gofmt`, `go vet`, `golangci-lint`, whole-program `deadcode`,
`gosec`, `govulncheck`, `gitleaks` and `go-licenses`; `go vet`, `golangci-lint` and `gosec` also
cover the `//go:build integration` test files (gosec through golangci-lint, since
standalone gosec skips test files; name them `*integration_test.go` or
`*e2e_test.go`). Container work has its own targets:
`make docker` (passes `--build-arg VERSION=$(git describe --tags --always --dirty)`,
overridable with `VERSION=`), `docker-lint` (hadolint + dockle), `docker-scan`
(Trivy), and `smoke` — `scripts/docker-gates.sh`: `--version` and `--help`, the
binary's ELF architecture matches the image platform, an image size budget under
30 MB (`SIZE_BUDGET_MB`), a non-root user check, and the PID-1 SIGTERM gate. The
`--version`, `--help` and PID-1 runs happen on a read-only rootfs with all
capabilities dropped (`--read-only --cap-drop ALL --security-opt no-new-privileges`;
gate line `ok: runs on a read-only rootfs with no capabilities and no-new-privileges`).
The Trivy and dockle scanner images are pinned by digest in `ci/images/trivy.Dockerfile`
and `ci/images/dockle.Dockerfile`, which Dependabot bumps; the workflows read the first
`FROM` line of each, and `trivy config` skips `ci/images`.
`scripts/docker-gates.sh [--platform OS/ARCH] [--pull] [IMAGE]` checks one variant of
any local or registry image. The Dockerfile cross-compiles on the build host's
platform, so a multi-arch `docker buildx` build never runs the compiler under QEMU. CI builds
and gates the image natively on amd64 and arm64. CI runs `govulncheck` and fuzzes every
target for 2 minutes daily, keeping the generated corpus between runs. Every push also
scans its new commits for secrets and reports benchmark deltas. CI also Trivy-scans the published `latest` image for both architectures (job
`published-image-scan`, "Published image CVEs"). Before the first `vX.Y.Z` tag there is
nothing to scan and the job passes. After that, a registry error fails it.

**Releases.** Pushing a `vMAJOR.MINOR.PATCH` tag runs `.github/workflows/release.yml`.
It refuses a tag whose commit is not on `master`, then runs `make check` (including
`govulncheck` on the exact Go the image ships) and `make integration` on alpine,
debian and rocky. It builds the
`linux/amd64` + `linux/arm64` image once (arm64 is cross-compiled) and pushes it by
digest only. It lints the Dockerfile with hadolint and Trivy config before the build.
Then it gates that exact digest on native amd64 and arm64 runners with Trivy (fails on
HIGH/CRITICAL), dockle and `scripts/docker-gates.sh`. Only
when every job passes does it tag the digest with semver tags (`latest` last, and only
for the newest release), sign it keyless with cosign, attach signed build provenance,
and verify that signature with the command below. A manual `workflow_dispatch` run is
a dry run: every job except the two publishing ones (`publish` and `release-binaries`),
even one dispatched on a tag. On a tag push, after the image is published,
`release-binaries` attaches the signed `linux`/`darwin` `amd64`/`arm64` binaries,
`SHA256SUMS` and `SHA256SUMS.sigstore.json` to a GitHub release (see Install). Verify an image before you run it
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
5. **The image published but the GitHub release has no binaries:** `release-binaries`
   runs only after `publish` and every `binaries` leg. Fix the failing leg, then
   `gh run rerun <run-id> --failed`. If the fix needs a release.yml change, cut
   `vX.Y.Z+1` (step 2).

Every release tag must point at a commit at or after `ca50409`, the commit that fixed
the gated release workflow; older commits run an ungated release workflow or one whose
publish step always fails.

Integration and E2E tests run against two throwaway sshd containers built from
`ci/images/sshd-<distro>.Dockerfile` (alpine: busybox; debian: dash, GNU coreutils,
PAM; rocky: bash as /bin/sh, RHEL sshd, PAM). Container A holds every fixture user.
Container B's sshd reads `~/.ssh/fleet_keys`, so the two-host E2E proves real
parallel fan-out, the `authorized_keys_file` override and per-host `known_hosts`.
Host keys are generated when each container starts. Each run uses unique container
names and ports that Docker picks, so parallel runs never collide.
`SSHEPHERD_IT_PORT` pins container A's port, and `SSHEPHERD_IT_NAME` sets the
container name prefix. CI and the release workflow run all three distros as a
matrix, and a release waits for every leg.

Test kinds in the repo: unit (table-driven), integration (real `sshd` in Docker,
build-tagged), end-to-end (the CLI binary through adopt → apply → audit, and apply +
audit across two hosts), fuzz
(every `Fuzz*` target, each with a committed seed corpus under
`<pkg>/testdata/fuzz/<Target>/` that runs as ordinary test cases on every
`go test`), benchmarks, race, goroutine-leak
checks (`goleak` in every package), and golden snapshots of rendered output.

### Layout

```
cmd/sshepherd/       CLI: root command, audit, import, adopt, apply, revoke, rotate, validate, E2E tests
internal/config/     manifest load + strict validation, access resolution, revocation memory (revoked:, serial:, policy conflicts)
internal/authkeys/   authorized_keys parser and renderer, managed header grammar (Header/ParseHeader, serial), option semantics, key offer order (OfferOrder/OfferRank)
internal/audit/      fan-out, diffing, text/JSON reports, exit codes
internal/adopt/      pure fleet-discovery plan
internal/apply/      plan computation (serial rows, D4b bump, sweep report), self-lockout guard, phase-2 fan-out behind the Writer seam, plan/JSON reports — no transport imports
internal/fleet/      shared leaf vocabulary: error kinds, read result, held keys, write request — stdlib only
internal/workflow/   the write workflow for apply/revoke/rotate: plan → confirm → commit manifest → write, behind seams
internal/sshconn/    shared connection glue (dial, credentials: key files + agent, host keys)
internal/sshconn/sshtest/  in-process SSH server + agent + key-file helpers for hermetic tests
internal/keyfile/    --identity key files: permission rule, format checks, passphrases, /dev/tty prompt
internal/sshread/    remote read protocol
internal/sshwrite/   remote write protocol (guarded script, CAS, lock, verify, probe)
internal/sshcfg/     OpenSSH client-config parser
internal/identity/   IdentityFile → .pub resolution
internal/manifest/   comment-preserving manifest edits (append, remove, replace, operator flag, tombstones via AddTombstones, serial bump via BumpSerial)
internal/reconcile/  pure import-merge reconciliation, same-target collapse
internal/naming/     collision-free user-name allocator (import, merge, adopt)
internal/clog/       leveled, colorized logging and output sanitization
scripts/             integration runner, Docker image gates
ci/images/           digest-pinned scanner and sshd test images (Dependabot-visible)
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
and `revoke --from-server` / `rotate --keep-old` in
[`docs/superpowers/specs/2026-11-07-revoke-server-keep-old-design.md`](docs/superpowers/specs/2026-11-07-revoke-server-keep-old-design.md);
revocation memory (tombstones, the manifest serial, the post-revoke sweep) in
[`docs/superpowers/specs/2026-11-08-revocation-memory-design.md`](docs/superpowers/specs/2026-11-08-revocation-memory-design.md).

## License

[Apache License 2.0](LICENSE) — permissive, with an explicit patent grant.

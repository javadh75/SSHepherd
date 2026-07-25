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
| `apply`  | ✅ | The write path: plan → confirm → atomic write → verify |
| `revoke` / `rotate` | — | Not separate commands: both reduce to a manifest edit plus `apply` |

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
and forward your SSH agent:

```console
$ docker run --rm \
    -v "$PWD/sshepherd.yaml:/work/sshepherd.yaml:ro" \
    -v "$HOME/.ssh/known_hosts:/work/known_hosts:ro" \
    -v "$SSH_AUTH_SOCK:/ssh-agent" -e SSH_AUTH_SOCK=/ssh-agent \
    -w /work sshepherd:dev audit --known-hosts /work/known_hosts
```

## Requirements

SSHepherd deliberately has a narrow, strict connection posture:

- **A running SSH agent** holding the key(s) that log into the fleet
  (`SSH_AUTH_SOCK` must be set). Agent-only authentication — SSHepherd never reads,
  asks for, or stores a private key.
- **A populated `known_hosts`** (default `~/.ssh/known_hosts`). Host-key checking is
  **strict, with no TOFU**: an unknown host is an error, not a prompt.

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
ignored.

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

Mirrors sshd's `AuthorizedKeysFile` directive for servers that do not use the
default `~/.ssh/authorized_keys`. Must be absolute (`/...`) or home-relative with an
explicit `~/` prefix. The value is validated strictly and POSIX-single-quote escaped
before it reaches a remote shell.

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

`--json` emits one indented JSON document on stdout, pinned by golden fixtures.
Field names are a public contract: additive fields keep `"schema": 1`, and only a
breaking change bumps it — so consumers can hard-fail on an unexpected schema.
(Fingerprints and the second server are elided below for space.)

```json
{
  "schema": 1,
  "summary": {
    "servers": 2, "compliant": 0, "drift": 1,
    "critical": 0, "unreachable": 1, "exit_code": 1
  },
  "servers": [
    {
      "name": "web-1", "host": "10.0.0.1", "port": 22, "user": "deploy",
      "status": "drift", "error": null,
      "keys": {
        "present": [
          { "owner": "alice", "fingerprint": "SHA256:fe85Jk…", "type": "ssh-ed25519" }
        ],
        "missing": [
          { "owner": "bob", "fingerprint": "SHA256:4A9jyZ…", "type": "ssh-ed25519" }
        ],
        "unauthorized": [
          { "owner": null, "comment": "who@is-this",
            "fingerprint": "SHA256:doxiAS…", "type": "ssh-ed25519" }
        ]
      },
      "parse_errors": [{ "line": 3, "error": "line 3: parse authorized_keys line: …" }],
      "file_absent": false,
      "no_users_granted": false
    }
  ]
}
```

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

Any unreadable server aborts the run unless `--partial` is set — adopting a
half-read fleet would silently drop real access.

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

`--dry-run` and `--yes` are mutually exclusive.

## Exit codes

Monitoring-style, shared by `audit` and `apply`:

| Code | Meaning |
| ---- | ------- |
| `0` | Compliant / converged — nothing to do |
| `1` | Drift, unreachable servers, or pending changes — compliance not proven |
| `2` | **Critical** drift — a server is missing an operator key |
| `3` | Tool error — bad flags, unloadable manifest, failed preflight |

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

**Self-lockout guard.** Any write that would leave a server without a key held by
your agent is refused. If the agent's key listing is unavailable at all, every
removal is refused.

**Refusals, not guesses.** A server is skipped — loudly, with a `REFUSED:` line —
when the manifest grants nobody but keys are installed (refusing to wipe), when the
file contains unparseable lines (refusing to rewrite a file it could not fully
read), or when the target is a symlink.

**Atomic writes with a backup.** The new content goes to a remote temp file under
`umask 077` with noclobber, a `.sshepherd.bak` backup is taken first, and the temp
file is `rename`d into place — readers never see a half-written file. The file is
then **re-read in the same session** to verify the write landed byte-exactly.

**Connection posture.** Agent-only authentication, strict `known_hosts` with no
TOFU, per-server and dial timeouts, and bounded fan-out (`--parallel`, default 32,
tuned from the fan-out benchmarks).

**Output safety.** Terminal escapes from server-supplied text are stripped and
newlines collapsed, so a hostile server cannot forge report rows or a summary line.

## Development

Everything below runs the same commands CI runs.

```console
$ make check        # the full gate: tidy, fmt, vet, lint, deadcode, security, test
$ make test         # go test -race with an atomic coverage profile
$ make coverage     # coverage report; fails below 80% line coverage
$ make integration  # dockerized sshd + build-tagged integration tests
$ make fuzz         # short fuzz run of every parser
$ make bench        # fan-out benchmarks
$ make hooks        # install the lefthook pre-commit/pre-push hooks
$ make tools        # install pinned dev tooling (golangci-lint, gosec, …)
```

The gate includes `gofmt`, `go vet`, `golangci-lint`, whole-program `deadcode`,
`gosec`, `govulncheck`, and `gitleaks`. Container work has its own targets:
`make docker`, `docker-lint` (hadolint + dockle), `docker-scan` (Trivy), `smoke`.

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
internal/sshconn/    shared connection glue (dial, agent auth, host keys)
internal/sshread/    remote read protocol
internal/sshwrite/   remote write protocol (backup, temp+rename, verify)
internal/sshcfg/     OpenSSH client-config parser
internal/identity/   IdentityFile → .pub resolution
internal/manifest/   comment-preserving manifest editing
internal/reconcile/  pure import-merge reconciliation
internal/clog/       leveled, colorized logging and output sanitization
```

### Design docs

Each slice was specced and planned before it was built; the documents live in
`docs/superpowers/specs/` and `docs/superpowers/plans/` and remain the reference for
*why* things work the way they do — notably the audit slice, operator users and
wildcard access, JSON output and exit codes, the comment-policy memo, the merge
designs, and the apply slice.

## License

[Apache License 2.0](LICENSE) — permissive, with an explicit patent grant.

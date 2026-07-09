# Design: `sshepherd audit` — drift/compliance slice

- **Date:** 2026-07-06 (updated 2026-07-09: auth/host-key/concurrency decisions; full review fixes — remote-read semantics, example corrections)
- **Status:** Approved (design), pending spec review
- **Scope:** First real vertical slice of SSHepherd — a read-only drift audit.

## Context & goal

The repo currently has a complete quality/security/container scaffold, a CLI
skeleton that only handles `--version`, and `internal/authkeys` that parses a
single `authorized_keys` line into a structured `Key`. No product capability
exists yet.

This slice delivers the first genuinely useful, end-to-end capability: **audit**.
It answers *"who can log into which server, and does that match our source of
truth?"* It is deliberately **read-only** — no writes to any server — so there is
zero lockout risk, which makes it the safest first slice. It also forces us to
build the two reusable cores that every later slice (`apply`, `revoke`, `rotate`)
depends on: the **YAML source-of-truth model** and the **diff engine**.

## Tier-0 decisions (locked)

| Decision | Choice | Notes |
|---|---|---|
| Source-of-truth format | **YAML** | `gopkg.in/yaml.v3`; human-editable, comments, ubiquitous in infra tooling. |
| SSH transport | **Native `golang.org/x/crypto/ssh`** | No dependency on a host `ssh` binary; unit-testable; enables a future distroless image. Host-key verification via `golang.org/x/crypto/ssh/knownhosts`. |
| CLI framework | **Cobra** (`github.com/spf13/cobra`) | Standard for Go infra CLIs; subcommands/flags/help/completion. Replaces the hand-rolled `flag` in `run.go`. |

## In scope

- `sshepherd audit` subcommand (Cobra), read-only.
- YAML source-of-truth schema: `users`, `servers`, `access`.
- `internal/config`: parse + validate the manifest.
- `internal/authkeys`: extend with whole-file parse + a fingerprint-based diff.
- `internal/sshread`: native SSH client that reads a server's `authorized_keys`.
- `internal/audit`: orchestrator that computes desired vs actual per server and
  formats a report. **Concurrent**: a bounded worker pool (`--parallel N`,
  default 10) fans out across the fleet; results are collected and sorted by
  server name before rendering so output is deterministic.
- Tests: unit, golden, fuzz (extended), and a build-tagged integration test.

## Deliberately deferred (NOT in this slice)

- Groups in the schema (access is flat: user → servers).
- Key **material**/rendering on `Key` (identity is the fingerprint; nothing is
  written, so no rendering needed yet).
- `apply` / `revoke` / `rotate` and all write-path safety (atomic write, mode
  0600, backup/rollback, lockout guard).
- `--json` output.
- `--identity` key-file auth — v1 is SSH-agent-only (`SSH_AUTH_SOCK`); the agent
  natively handles multiple keys by offering each held key in turn. A repeatable
  `--identity` flag for headless/CI use (no agent available) is a **planned**
  follow-up slice, which must also settle passphrase-protected key policy.
- SFTP-based remote reads — v1 reads via a one-shot SSH session `cat`.
- Acting on `comment` / `description` (loaded + validated now; used later).

## Source-of-truth schema (`sshepherd.yaml`)

```yaml
users:
  - name: alice
    description: "Platform team lead"     # optional — documentation only, never sent to a server
    comment: "alice@sshepherd"            # optional — the trailing comment written into authorized_keys (apply slice)
    keys:
      - "ssh-ed25519 AAAA...C alice@laptop"
  - name: bob
    keys:
      - "ssh-rsa AAAA...9 bob@work"

servers:
  - name: web-1
    description: "Primary web frontend"   # optional — documentation only
    host: 10.0.0.1
    port: 22           # optional, default 22
    user: deploy       # remote account we connect as, and whose authorized_keys we audit
  - name: web-2
    host: 10.0.0.2
    user: deploy

access:
  - user: alice
    servers: [web-1, web-2]
  - user: bob
    servers: [web-1]
```

### Field semantics

- **`users[].name`** — unique identifier, referenced by `access`.
- **`users[].description`** *(optional)* — human documentation; lives only in the
  manifest, never transmitted.
- **`users[].comment`** *(optional)* — the comment SSHepherd will attach to that
  user's key line when it writes `authorized_keys` (apply slice). Write-time
  fallback order: `comment` → the key's own inline comment → `name`. Unused by
  audit except as a display label.
- **`users[].keys`** — one or more OpenSSH public keys (full lines).
- **`servers[].description`** *(optional)* — human documentation only.
- **`servers[].host` / `.port` / `.user`** — connection target; `port` defaults
  to 22.
- **`access[]`** — maps a user to the servers they may access.

**Desired key set for a server S** = the union of `keys` of every user whose
`access` entry lists S.

### Validation rules (fail fast, exit 2)

- `users[].name` and `servers[].name` are each unique.
- Every `access[].user` resolves to a defined user; every `access[].servers`
  entry resolves to a defined server.
- Every key in `users[].keys` parses as a valid OpenSSH public key.
- Duplicate public keys across users are a validation error (a fingerprint must
  map to exactly one user, so report labeling is unambiguous). The same key
  listed twice under one user is likewise a validation error.
- Multiple `access` entries for the same user are allowed; their server lists
  are unioned.

## Packages

| Package | Responsibility | Testability |
|---|---|---|
| `internal/config` (new) | Load + validate YAML into typed structs. | Pure unit, table-driven + golden invalid cases. |
| `internal/authkeys` (extend) | Add `ParseFile([]byte) ([]Key, []ParseError)` and `Diff(desired, actual []Key) Result`. `ParseError` carries the 1-based line number and cause so reports can cite `line N`. Identity = SHA256 fingerprint (already on `Key`). | Pure unit + existing fuzz, extended to `ParseFile`. |
| `internal/sshread` (new) | Native `x/crypto/ssh` client: connect (agent auth via `SSH_AUTH_SOCK`, host-key verify via `knownhosts`), read remote `~/.ssh/authorized_keys` via a one-shot session `cat`. Kept deliberately **thin** (connection glue only); anything decision-like — e.g. interpreting the remote exit status to distinguish "file absent" from "read failed" — lives in a unit-testable helper (see *Remote read semantics*). | Real impl covered by a `//go:build integration` test vs a dockerized `sshd`; the exit-status helper is pure unit. |
| `internal/audit` (new) | Orchestrate: bounded worker pool fans out per server → compute desired, fetch actual, `Diff`; collect, sort by server name, format report. Each per-server audit is a self-contained call with no shared mutable state. | Pure unit against a fake `KeyReader`, including concurrency (slow/blocking fakes, pool-cap assertions); exercised under `-race`. |
| `cmd/sshepherd` | Cobra root + `audit` subcommand; keep `--version`; preserve testable `run(args, stdout, stderr) int` via `cmd.SetArgs/SetOut/SetErr`. | `run(...)` test. |

### Diff result

```go
// authkeys.Diff compares desired vs actual key sets by fingerprint.
type Result struct {
    OK           []Key // fingerprint present in both
    Missing      []Key // authorized (desired) but not installed on the server
    Unauthorized []Key // installed on the server but not authorized
}
```

## The testable seam

```go
// KeyReader fetches a server's current authorized_keys bytes.
type KeyReader interface {
    ReadAuthorizedKeys(ctx context.Context, s config.Server) ([]byte, error)
}
```

`internal/audit` depends on this interface, so its logic unit-tests against a
fake with no network. `internal/sshread` provides the real implementation,
exercised only by the build-tagged integration test. This keeps the unit path
hermetic (per CLAUDE.md) and lets coverage stay ≥80% without live SSH.

## Remote read semantics

v1 audits the **default** key source: `~/.ssh/authorized_keys` of the connect
user, read via a one-shot session `cat`. This assumes a POSIX-ish remote (shell
+ `cat`), the default `AuthorizedKeysFile`, and `~` resolving to the connect
user's real HOME. A per-server path override is a natural later field.

Outcomes of the remote read, and what each means:

- **Connection/auth/host-key failure** → the server is *unauditable*: recorded
  as an error result, run continues, exit 1.
- **File read successfully** → parse and diff as normal.
- **File absent (or present but empty)** → reported as "0 keys installed", so
  every desired key shows as missing (drift, exit 1) — **plus a loud
  diagnostic**. Rationale: public-key auth means our own login key had to match
  *some* source sshd consulted; if the file we audit is absent/empty yet login
  succeeded, sshd is consulting a **different source** — a custom
  `AuthorizedKeysFile` path, an `AuthorizedKeysCommand` (LDAP/SSSD/cloud), or
  CA certificates (`TrustedUserCAKeys`). The report says exactly that: this
  server may not be auditable via this file. Distinguishing "absent" from "read
  failed" uses the remote command's exit status via a pure, unit-tested helper.
- **File parses partially** (`ParseError`s) → parsed keys are still diffed;
  each bad line is reported as `⚠ line N: unparseable entry` and the server
  counts **non-compliant** (exit 1) — we cannot certify a file we cannot fully
  read.

## Command surface

```
sshepherd audit [--config sshepherd.yaml] [--known-hosts ~/.ssh/known_hosts] [--parallel 10]
```

- `--config` — path to the manifest (default `sshepherd.yaml`).
- `--known-hosts` — path to the `known_hosts` file (default `~/.ssh/known_hosts`).
- `--parallel` — max concurrent server audits (default 10; <1 is a usage error,
  exit 2). A bounded pool, not unbounded fan-out, so large fleets don't open
  hundreds of sockets.
- Auth: the local SSH agent (`SSH_AUTH_SOCK`) only, in v1. Agent availability is
  checked **once at startup**; if the env var is unset or the socket is dead,
  exit 2 with a clear message *before* dialing any server (otherwise every
  server would fail identically).
- Host-key policy is **strict**: a server whose host key is absent from (or
  conflicts with) `known_hosts` fails its audit; no trust-on-first-use, no
  insecure escape hatch. Gotcha the error message must address: `known_hosts`
  entries are recorded under the host form you `ssh` to — if you normally use a
  hostname but the manifest says `host: 10.0.0.1`, the IP form won't match. The
  remediation hint therefore names the **exact configured host:port**, e.g.
  `ssh-keyscan -p 22 10.0.0.1 >> ~/.ssh/known_hosts`.
- Timeouts: a per-server **overall deadline of 30s** (context-based, covering
  dial + handshake + remote read) with a **10s dial timeout** inside it — so a
  host that accepts TCP and then hangs still frees its worker slot.

### Exit codes

- **0** — every server was reachable and compliant (no drift). An empty
  `servers` list is trivially compliant → exit 0 (with a "0 servers" note).
- **1** — audit could not confirm a clean fleet: drift detected on at least one
  server (missing/unauthorized keys), **and/or** a server could not be audited
  (connection/read failure), **and/or** a server's key file could not be fully
  parsed.
- **2** — config/usage error (bad manifest, unresolved references, unreadable
  config, invalid flags, no usable SSH agent).

Per-server connection/read failures do **not** abort the run; they are recorded,
reported, and yield exit **1** (never masked as success).

### Report (default text output)

Per server: connection line, then one line per key with a status glyph and a
user label resolved by fingerprint:

```
web-1 (deploy@10.0.0.1:22)
  ✓ alice        SHA256:abc…   ssh-ed25519   present & authorized
  ✗ bob          SHA256:def…   ssh-rsa       authorized but MISSING
  ⚠ (unknown)    SHA256:xyz…   ssh-rsa       installed but UNAUTHORIZED
  → 2 authorized · 1 present · 1 missing · 1 unauthorized

web-2 (deploy@10.0.0.2:22)  ERROR: dial tcp 10.0.0.2:22: connection refused

Summary: 0/2 servers compliant · 1 with drift · 1 unreachable  → exit 1
```

Additional report rules:

- The report itself goes to **stdout**; diagnostics/progress go to **stderr** —
  so `sshepherd audit > report.txt` captures exactly the report.
- Matched keys are labeled with the owning user's `name` (and `comment` if
  set); unauthorized keys have no owner.
- Unparseable lines render as `⚠ line N: unparseable entry` under their server
  (see *Remote read semantics*).
- A server with an **empty desired set** (defined in `servers` but granted to
  no user in `access`) is still audited: every installed key flags
  unauthorized, prefixed by an informational `note: no users granted access in
  the manifest`.
- **Not drift in v1** (fingerprint-only identity): comment mismatches,
  `description` anything, and authorized_keys **options** (e.g.
  `no-port-forwarding`) — options on desired keys are likewise ignored by the
  diff.

## Data flow

1. Load + validate `sshepherd.yaml` (fail fast on error → exit 2).
2. Fan out over servers with a bounded worker pool (`--parallel`, default 10).
   Each worker runs one self-contained, shared-state-free call:
   a. Compute the desired key set from `access` + `users`.
   b. `sshread.ReadAuthorizedKeys` → raw bytes; distinguishes connection
      failure (error result) from file-absent (empty bytes + diagnostic flag)
      per *Remote read semantics*.
   c. `authkeys.ParseFile` → actual `[]Key` + any `ParseError`s (recorded in
      the server's result).
   d. `authkeys.Diff(desired, actual)` → `Result`.
3. Collect all per-server results, **sort by server name**, render the report;
   derive the exit code from the aggregate. Sorting after collection keeps the
   output (and golden tests) deterministic despite concurrent completion order.

## Error handling

- Config parse/validate errors → fail fast, exit 2, actionable message.
- Per-server errors are collected, not fatal to the whole run (one unreachable
  box must not blind the operator to the rest of the fleet).
- Errors are wrapped with `%w` at package boundaries (`wrapcheck`/`errorlint`);
  `context.Context` is threaded through the read path (`contextcheck`/`noctx`).

## Dependencies (update `.golangci.yml` depguard allowlist)

- `github.com/spf13/cobra`
- `gopkg.in/yaml.v3`
- `golang.org/x/crypto/ssh` (already present) + `golang.org/x/crypto/ssh/knownhosts`
- **No** SFTP dependency: remote read is a one-shot SSH session `cat
  ~/.ssh/authorized_keys`. The path is fixed (no injection surface) and this is
  not `os/exec` (so gosec G204 does not apply). SFTP is noted as later hardening.

## Testing plan (per CLAUDE.md, for a read-only slice)

- **Unit** — `config` load/validate (table-driven + golden invalid cases);
  `authkeys.ParseFile` and `Diff` (table-driven); `audit` orchestration against a
  fake `KeyReader` — including concurrency behavior: results deterministic
  regardless of completion order, pool never exceeds `--parallel`, one failing/
  hanging server doesn't poison the rest (all run under `-race` per the standard
  suite); `run()` CLI dispatch.
- **Golden** — the rendered audit report and the diff output.
- **Fuzz** — extend the existing `authkeys` fuzz target to `ParseFile`.
- **Benchmarks** — `go test -bench -benchmem` on the fan-out orchestration with
  fake readers (N servers × pool sizes) and on `ParseFile`/`Diff`. This is the
  baseline CLAUDE.md asks for on the named hot path, and later informs
  `--parallel`/timeout tuning.
- **Integration** (`//go:build integration`) — `sshread` against a dockerized
  `sshd`: seed a known `authorized_keys`, assert the bytes read back; also the
  file-absent case (expect empty + diagnostic, not error).
- **Coverage** — stays ≥80% (the CLAUDE.md gate) on the unit path. Risk
  control: `sshread`'s network lines only execute under the integration tag, so
  the package is kept thin and its decision logic (exit-status interpretation)
  is factored into unit-tested helpers.

## Open questions / to settle in later slices

- Interaction between a user's `comment` and a key's inline comment at write time
  (apply slice).
- Whether comment drift should ever be reported (informational, non-failing).
- Whether a guarded trust-on-first-use escape hatch (or a `sshepherd trust`
  command that shows fingerprints for confirmation) is ever warranted; v1 is
  strict-only by decision.
- Tuning the `--parallel` default and timeouts once fleet-scale benchmarks
  exist (`go test -bench` on the fan-out path).
- Per-server `authorized_keys` path override (for custom `AuthorizedKeysFile`
  setups) — the natural fix when the file-absent diagnostic fires; and whether
  `AuthorizedKeysCommand`/CA-cert fleets are ever in scope at all.

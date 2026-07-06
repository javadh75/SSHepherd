# Design: `sshepherd audit` — drift/compliance slice

- **Date:** 2026-07-06
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
  formats a report.
- Tests: unit, golden, fuzz (extended), and a build-tagged integration test.

## Deliberately deferred (NOT in this slice)

- Groups in the schema (access is flat: user → servers).
- Key **material**/rendering on `Key` (identity is the fingerprint; nothing is
  written, so no rendering needed yet).
- `apply` / `revoke` / `rotate` and all write-path safety (atomic write, mode
  0600, backup/rollback, lockout guard).
- Concurrent fleet fan-out — v1 audits servers **sequentially**; concurrency is a
  later benchmark-driven slice.
- `--json` output and `--identity` key-file auth (agent-only for v1).
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
  map to exactly one user, so report labeling is unambiguous).

## Packages

| Package | Responsibility | Testability |
|---|---|---|
| `internal/config` (new) | Load + validate YAML into typed structs. | Pure unit, table-driven + golden invalid cases. |
| `internal/authkeys` (extend) | Add `ParseFile([]byte) ([]Key, []error)` and `Diff(desired, actual []Key) Result`. Identity = SHA256 fingerprint (already on `Key`). | Pure unit + existing fuzz, extended to `ParseFile`. |
| `internal/sshread` (new) | Native `x/crypto/ssh` client: connect (agent auth via `SSH_AUTH_SOCK`, host-key verify via `knownhosts`), read remote `~/.ssh/authorized_keys` via a one-shot session `cat`. | Real impl covered by a `//go:build integration` test vs a dockerized `sshd`. |
| `internal/audit` (new) | Orchestrate: per server → compute desired, fetch actual, `Diff`, collect, format report. | Pure unit against a fake `KeyReader`. |
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

## Command surface

```
sshepherd audit [--config sshepherd.yaml] [--known-hosts ~/.ssh/known_hosts]
```

- `--config` — path to the manifest (default `sshepherd.yaml`).
- `--known-hosts` — path to the `known_hosts` file (default `~/.ssh/known_hosts`).
- Auth: the local SSH agent (`SSH_AUTH_SOCK`) only, in v1.

### Exit codes

- **0** — every server was reachable and compliant (no drift).
- **1** — audit could not confirm a clean fleet: drift detected on at least one
  server (missing/unauthorized keys) **and/or** at least one server could not be
  audited (connection/read failure).
- **2** — config/usage error (bad manifest, unresolved references, unreadable
  config).

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

Summary: 1/2 servers compliant · 1 with drift · 1 unreachable  → exit 1
```

Matched keys are labeled with the owning user's `name` (and `comment` if set);
unauthorized keys have no owner. Comment/description mismatches are **not** drift
in v1.

## Data flow

1. Load + validate `sshepherd.yaml` (fail fast on error → exit 2).
2. For each server (sequential):
   a. Compute the desired key set from `access` + `users`.
   b. `sshread.ReadAuthorizedKeys` → raw bytes (record error, continue on fail).
   c. `authkeys.ParseFile` → actual `[]Key`.
   d. `authkeys.Diff(desired, actual)` → `Result`.
3. Render the report; derive the exit code from the aggregate.

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
  fake `KeyReader`; `run()` CLI dispatch.
- **Golden** — the rendered audit report and the diff output.
- **Fuzz** — extend the existing `authkeys` fuzz target to `ParseFile`.
- **Integration** (`//go:build integration`) — `sshread` against a dockerized
  `sshd`: seed a known `authorized_keys`, assert the bytes read back.
- **Coverage** — stays ≥80% (the CLAUDE.md gate); the live SSH lines are covered
  under the integration tag.

## Open questions / to settle in later slices

- Interaction between a user's `comment` and a key's inline comment at write time
  (apply slice).
- Whether comment drift should ever be reported (informational, non-failing).
- Concurrency model for fleet fan-out (benchmark-driven).
- Host-key trust-on-first-use vs strict-only policy and any escape hatch.

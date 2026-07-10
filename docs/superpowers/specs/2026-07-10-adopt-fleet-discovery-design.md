# Design: `sshepherd adopt` — discover fleet keys into the manifest

- **Date:** 2026-07-10
- **Status:** Approved, not yet implemented
- **Scope:** New subcommand `adopt` (`cmd/sshepherd`), new pure package
  `internal/adopt`, one field added to `internal/authkeys.Key`. Reuses
  `internal/audit`'s fleet read/diff and `import`'s manifest rendering
  unchanged in behavior.

## Context & goal

Adopting SSHepherd on an existing fleet starts from a minimal manifest —
`servers:` (typically from `import --servers-only`) plus the operator's own
user (`import --operator`). Reality, however, already has keys installed
everywhere, and none of them are in the manifest. Hand-transcribing every
`authorized_keys` line into `users:`/`access:` is exactly the error-prone
work SSHepherd exists to remove — and until it is done, a future `apply`
would treat all that real access as unauthorized and revoke it.

`sshepherd adopt` closes the gap: it connects to every server in the
manifest, reads the actual `authorized_keys` (the same battle-tested path
`audit` uses), and emits a complete new manifest in which every key found on
the fleet is accounted for — unknown keys become generated users with access
to exactly the servers where they were found, and keys of already-known users
found beyond their grants get their access extended. The output is a
reviewable draft, never an in-place edit.

## Decisions (locked)

| Decision | Choice | Notes |
|---|---|---|
| Command name | **`adopt`** | The fleet's existing keys are adopted into the manifest (cf. `terraform import` idiom). `scan`/`census` sound read-only-and-report (audit's slot); `gather` is thematic but not self-explanatory. |
| Output destination | **stdout / `-o` file, input untouched** | Same contract as `import`: no-clobber unless `--force`, 0600 perms, `config.Parse` self-check before emit. In-place rewrite was rejected — YAML re-encode loses the user's comments and mutates the source of truth without review. |
| User grouping | **One new user per unique key fingerprint** | The fleet gives no reliable identity signal. Merging by comment silently merges strangers (`root@localhost`); over-splitting one person's laptop/desktop keys is loud in review and trivial to fix by hand. Loud errors beat quiet ones in a reviewed draft. |
| Known keys | **Extend the owning user's access** | A manifest user's key found on an ungranted server appends one *new* access entry for that user (the config layer unions entries), leaving hand-written entries verbatim. Exception: a server in the user's wildcard `except:` list is never re-granted — `except` is a deliberate carve-out; adopt warns and leaves the drift for audit. |
| Partial fleet | **Fail unless `--partial`** | Any unreachable server or unparseable line aborts with a per-server error list and no output. A draft generated from a partial read under-represents reality — the worst failure for a source-of-truth generator. `--partial` proceeds with stderr warnings *and* a comment block in the output naming the skipped servers. |
| Implementation base | **Post-process `audit.Run`** | `Diff.Unauthorized` is exactly the set adopt attributes: `OwnerOf` hit → access extension; miss → new user. No new SSH orchestration; audit and adopt cannot drift apart in connection behavior. |
| Key material | **`authkeys.Key` retains the raw line** | New field `Raw` — the trimmed original `authorized_keys` line — set by `ParseLine`. Adopt must emit real key lines; preserving the original also preserves options (`no-port-forwarding`, …). Manifest-loaded keys get the field for free; the future apply slice needs it anyway. |

## In scope

- `internal/authkeys`: `Key.Raw` field, set by `ParseLine` (trimmed original
  line); tests incl. options round-trip.
- `internal/adopt`: pure attribution — no I/O. Input: `*config.Config` +
  `[]audit.ServerResult`. Output: plan (new users, access extensions,
  warnings) + strict-gate errors (unreachable servers, parse errors) for the
  cmd layer to enforce against `--partial`.
- `cmd/sshepherd`: `adopt.go` (Cobra wiring, preflights, rendering); shared
  render types (`manifestOut` etc.) and `writeFileNoClobber` move from
  `import.go` to a shared file in package `main`. `accessOut` gains
  `except` (omitempty) — import never emits it, but adopt must copy existing
  wildcard entries' `except:` through to the output unchanged.
- Tests: see Testing.

## Deliberately deferred (NOT in this slice)

- In-place manifest merging or comment-preserving YAML round-trip.
- Heuristic identity merging (grouping keys by comment or username part) —
  the reviewer merges users by hand where they know better.
- Reading non-default `authorized_keys` paths or `sshd_config` key sources
  (`audit`'s `FileAbsent` semantics apply unchanged).
- Any write/apply behavior — adopt is read-only toward the fleet.

## CLI surface

```
sshepherd adopt [--config sshepherd.yaml] [--known-hosts ~/.ssh/known_hosts]
                [--parallel 10] [-o FILE] [--force] [--partial]
```

- Preflights identical to `audit`: SSH agent reachable, known_hosts loads;
  failures abort before anything is dialed.
- Header line: `# generated by sshepherd adopt from <config> — review before use`
  (`<config>` as the user typed it, like import's `src`).
- Self-check: the rendered manifest must pass `config.Parse`; a failure is
  reported as a bug, nothing is written.
- Fully readable fleet with nothing to adopt (no unknown keys *and* no
  access extensions): success, manifest emitted (content-identical to input,
  re-rendered), stderr note "nothing to adopt".
- Exit codes: 0 success; 1 on errors, including the strict gate (unreachable
  servers / parse errors without `--partial`).

## Attribution semantics

Processing order: servers by name (as `audit.Run` returns them), keys in file
order within a server. Output is deterministic.

For each server's `Diff.Unauthorized` key:

1. **`cfg.OwnerOf(fingerprint)` hit — known user.** Collect the server under
   that user. After the sweep, each extended user gets **one appended access
   entry** listing the newly found servers, sorted (e.g.
   `{user: alice, servers: [db-2, web-3]}`). Existing access entries are
   copied verbatim; the config layer unions duplicates. If the user's grant
   is `servers: ["*"]` with `except:` and the server is excepted: no
   extension, warning emitted, drift left to audit. Operator keys cannot
   appear here (they are desired everywhere, hence never Unauthorized).
2. **Miss — unknown key.** Grouped by fingerprint across the fleet; each
   unique fingerprint becomes one new user:
   - **Name:** sanitized comment — lowercase, every run of characters outside
     `[a-z0-9]` collapses to a single `-`, trimmed of leading/trailing `-`
     (`Alice@Laptop.local` → `alice-laptop-local`). Empty/unusable result →
     `adopted-key-N`, numbered in discovery order. Collisions with existing
     users or earlier new names get `-2`, `-3`, … suffixes.
   - **Keys:** the `Raw` line exactly as found — options and comment
     preserved. Same fingerprint with different options/comments across
     servers: first occurrence in discovery order wins, warning notes the
     divergence.
   - **Description:** `adopted from <server1>, <server2>` (sorted).
   - **Comment field:** left empty (the raw line already carries the key's
     own comment; `comment:` is apply's rewrite mechanism and adopt must not
     invent one).
   - **Access:** one entry, servers where found, sorted. Found on *every*
     server and fleet ≥ 2 → compacts to `servers: ["*"]` with import's
     "includes servers added later" warning.

Section ordering in the output: existing users, then new users in discovery
order; existing servers verbatim; existing access entries, then extension
entries (manifest user order), then new-user entries (new-user order).

A `FileAbsent` server contributes nothing and is not an error. `ParseErrs`
count as "could not fully read this server" and hit the strict/`--partial`
gate: an unparseable line might be real access that would otherwise be
silently dropped from the draft.

## Error handling

- Manifest load / preflight errors: immediate abort, one clear message.
- Per-server `Err` or `ParseErrs`: collected. Without `--partial`: all
  printed to stderr, exit nonzero, nothing written (stdout or `-o`). With
  `--partial`: stderr warnings plus a comment block in the generated manifest
  (`# WARNING: server X unreadable — its access is NOT represented`).
- `-o`: no-clobber unless `--force`, 0600, pinned on overwrite (shared
  `writeFileNoClobber`).

## Testing

- **Unit (`internal/adopt`)** — table-driven: fingerprint grouping across
  servers; name sanitization and collision suffixes; `adopted-key-N`
  fallback; known-user extension incl. multiple servers; except-carve-out
  non-extension + warning; wildcard compaction at full coverage; option/
  comment divergence first-wins + warning; discovery-order determinism;
  strict-gate classification (Err, ParseErrs, FileAbsent).
- **Unit (`internal/authkeys`)** — `Raw` round-trip incl. options, comments,
  and whitespace trimming.
- **Golden (`cmd/sshepherd`)** — full generated manifests via a fake
  `audit.KeyReader`: fresh adopt; nothing-to-adopt; `--partial` with a dead
  server (comment block present); extension + new-user mix.
- **Fuzz** — the name sanitizer: any comment input yields either a name the
  config validator accepts or the numbered fallback; never panics, never
  emits an empty/duplicate-prone name. Seed corpus in-repo, per project
  policy.
- **cmd tests** — flag validation, no-clobber/`--force`, self-check failure
  path, strict vs `--partial` exit codes.
- **Suite-wide** — goleak `TestMain` in every new test package; `-race` and
  the ≥80% coverage gate as usual. Integration/E2E: the SSH read path is
  unchanged and already covered by audit's integration suite; adopt joins the
  E2E container-fleet flow (import → adopt → audit) when that harness runs.

## Contract with future slices

- **apply** must treat adopt-generated users like any other manifest user;
  nothing in adopt's output is implicitly protected except users the operator
  marks `operator: true` afterward.
- `Key.Raw` is the canonical key material for apply's rendering of
  `authorized_keys`; adopt establishes it, apply consumes it.

# Design: `sshepherd apply` — distribute keys to the fleet

- **Date:** 2026-07-19 (revised same day after adversarial design review —
  guard contract restated over agent-held keys, render-input validation
  hardened, symlink refusal, normalize plan category, `sshconn` extraction
  enumerated)
- **Status:** Implemented 2026-07-19 — see
  `docs/superpowers/plans/2026-07-19-apply-slice.md` (all ten tasks
  executed; two-stage review passed with no blocker/major findings; the
  dockerized integration + E2E suite ran green). Approved earlier the same
  day by the owner with all four open questions resolved as recommended:
  refined lockout guard (intersection over agent-held keys),
  single-generation `.sshepherd.bak` backup, plan-then-prompt confirmation
  (`--yes` for automation), managed header kept. Post-review adjudication:
  the unparseable-file refusal is covered at unit level
  (`internal/apply` plan classification) rather than in the integration
  matrix — it is pure classification of bytes the integration-tested read
  path delivers; and inline key comments are validated with the same
  `RenderTextIssue` predicate as names/comments (defense in depth for the
  `DesiredComment` fallback).
- **Prior art (binding):**
  - `docs/superpowers/specs/2026-07-16-comment-policy-memo.md` — write-time
    comment order `comment` → inline → `name` via `config.DesiredComment`;
    **full-file render, never surgical edits** (the memo's one hard
    dependency on apply's design).
  - `docs/superpowers/specs/2026-07-10-operator-users-wildcard-access-design.md`
    — the apply-slice protection contract: operator keys cannot be stripped
    while flagged, and apply gets a **runtime self-lockout guard**. This
    spec refines the guard's letter (see *The self-lockout guard*): the
    enforced invariant is "after the write, this operator can still log
    in", checked against every agent-held key, not only the one that
    happened to sign the handshake — the literal single-key reading would
    make rotating one's own key impossible.
  - `docs/superpowers/specs/2026-07-06-audit-slice-design.md` — the read
    pipeline, report conventions, strict host-key policy, agent-only auth,
    and (as of 2026-07-19) the tuned `--parallel 32` / 30s / 10s defaults,
    which apply reuses.
  - `cmd/sshepherd/manifest_out.go` `writeFileNoClobber` — the local
    temp-file+rename atomicity pattern, mirrored remotely.
- **Amended by:** [`--identity` key-file auth](2026-10-16-identity-keyfile-auth-design.md) (2026-10-16) — the guard's "held keys" are no longer agent-only.

## Context & goal

Every slice so far is read-only. `apply` is the first write path: it makes
each server's `authorized_keys` equal to the manifest's desired state —
adding missing keys, removing unauthorized ones, and normalizing comments
per the decided policy. It is the slice that unblocks `revoke` and `rotate`
(both become manifest edits followed by `apply`) and the full E2E story.

It is also the first command that can break the fleet, so the design's
center of gravity is the safety story: plan-then-confirm, per-server
refusal gates, a runtime self-lockout guard, and an atomic remote write.

## Decisions (locked by prior specs — not open for relitigation)

| Decision | Choice | Source |
|---|---|---|
| Write model | **Full-file render from the manifest** — the on-server file becomes exactly the rendered desired state; never line-surgical edits. **This deletes non-key lines** (an operator's own `# comments`, blank lines) — stated loudly here and in the plan report. | comment-policy memo |
| Comment per key | `config.DesiredComment(u, k)`: `comment:` → key's inline comment → `name` | comment-policy memo |
| Operator keys | Always in every server's desired set (`DesiredFor`), so a render can never drop one while the flag is set | operator spec |
| Self-lockout guard | Runtime guard before every write; contract refined below | operator spec (refined here) |
| Remote atomicity | Temp file in the destination directory + `mv` (rename), mirroring `writeFileNoClobber` | adopt/manifest slices |
| Transport | Native `x/crypto/ssh`, agent-only auth, strict `knownhosts` — the audit read path, unchanged | audit spec |
| Fan-out | Bounded pool, `defaultParallel` (32), 30s per-server / 10s dial | audit spec + 2026-07-19 tuning resolution |

## New decisions this spec makes (owner approves here)

| Decision | Choice | Alternatives considered |
|---|---|---|
| Execution shape | **Two-phase: read the whole fleet → show one plan → confirm once → write only drifted servers** | Per-server read-confirm-write streams the prompt mid-fan-out and makes canary review impossible; rejected. |
| Confirmation | Required before any write: interactive prompt on a TTY, `--yes` for automation; non-TTY without `--yes` is an error (exit 3). `--dry-run` never writes. | Write-by-default was rejected — this command deletes keys; "additions don't need confirmation" was rejected as two subtly different modes. |
| Convergence test | **Byte-exact**: a server needs a write iff its current file bytes differ from the rendered desired bytes. Byte-only drift (ordering, whitespace, non-key lines) gets its own visible plan category — never a silent rewrite. | Fingerprint-set equality would leave comment/option/ordering drift in place forever, half-enforcing the comment policy the memo decided. |
| Guard invariant | **"After the write, this operator can still log in":** refuse the write unless the rendered desired set intersects the agent's held keys. Removing the very key that authenticated is allowed **when another agent-held key survives** (that is what `rotate` is), with a loud per-server note. | The operator spec's literal "never remove the session key" is nondeterministic (which key signs depends on agent order / server choice) and blocks self-rotation outright; see the guard section for the full argument. Owner signs off on this refinement explicitly (open question 1). |
| Restrictive options on the surviving key | When every guard-satisfying desired line carries an access-limiting option (`from=`, `command=`, `restrict`, `expiry-time=`), the plan carries a loud **warning** (the option may functionally block future SSHepherd logins) but the write proceeds after normal confirmation. | Refusing would break operators who deliberately restrict their own keys; saying nothing leaves a fingerprint-present-but-unusable trap. Warning + confirm is the honest middle. |
| Symlinked target | If the target path is a symlink, **refuse** that server: `mv` would replace the symlink with a regular file, silently diverging what SSHepherd reads (`cat "$p"`) from what sshd may read (the old target), and breaking config-management setups. Checked remotely (`[ -L "$p" ]`) before writing. | Writing through via `readlink -f` is not POSIX; silently replacing is a fidelity lie. Refusal names the target; the operator points `authorized_keys_file` at the real file if that is intended. |
| Managed header | Rendered files begin with one fixed line: `# Managed by SSHepherd. Manual edits will be overwritten by 'sshepherd apply'.` No timestamp — output is byte-stable and golden-testable; the first apply on any server rewrites once, then it is a no-op. | No header (loses on-server discoverability); dated header (breaks idempotency + goldens). |
| Backup | Before each modifying write, `cp -p` the current file to `<path>.sshepherd.bak` (single generation, overwritten per apply). Absent file → no backup. | No backup (an oops has no local undo; the manifest restores desired state but not the pre-apply actual); timestamped generations (unbounded clutter in `~/.ssh`). |
| Empty desired set | A server the manifest grants no keys is **refused only when a write would occur** (installed keys exist). File absent or empty → converged (matches audit's "nothing should be there and nothing is"). Wiping a box to zero keys is never a valid outcome of `apply`. | Refusing unconditionally would page a monitor on an audit-clean fleet; writing a header-only file is a guaranteed lockout. |
| Unparseable current file | Refused (server fails, exit 1): we never overwrite content we could not fully read — a full-file render would destroy lines we cannot account for. Remediation: fix the line remotely or correct `authorized_keys_file`. | `--force`-style override deferred; audit already surfaces these lines. |
| Verify after write | Same session re-reads the file and byte-compares against the render; a server only counts converged after verification. | Trusting the exit status of `mv` leaves silent-corruption blind spots for the cost of one extra `cat`. |
| Connection reuse | The write phase opens **one SSH connection per drifted server** and runs guard pre-check + backup + write + verify over it (sessions on one connection), rather than reconnecting per step. | Reconnecting is simpler but triples handshakes and lets the guard's session identity drift across connections. |
| Shared connect code | Extract connection glue into a new **`internal/sshconn`** used by `sshread` and the new `sshwrite`; exact identifier list below. | Duplicating ~80 lines of security-sensitive glue invites divergence (e.g. a hint fix landing in one copy); rejected. |
| Render-input validation | Prerequisite hardening in `internal/config` (see *Rendering*): `name` and `comment` gain strict character rules so the "a render can never emit an extra line" invariant is actually enforced, not assumed. | Today only `comment:` and key lines reject line breaks; `name` — the `DesiredComment` floor — accepts anything YAML can quote, including newlines. |
| Exit codes | Monitoring-style, mirroring audit: **0** all targeted servers converged (including "already converged" and "applied & verified"); **1** not converged — any server unreachable/refused/failed/verify-failed, plan pending under `--dry-run`, or the operator declined the prompt; **3** usage/config/tool error. **2** stays reserved (audit uses it for critical drift; apply has no equivalent class yet). | A distinct "aborted" code adds public surface for no monitoring value. |

## Command surface

```
sshepherd apply [--config sshepherd.yaml] [--known-hosts ~/.ssh/known_hosts]
                [--parallel 32] [--server NAME]... [--dry-run | --yes]
```

- `--server NAME` — repeatable; restrict the run to named servers (canary
  rollout). An unknown name is a usage error (exit 3). Mechanically: the
  fan-out receives the filtered server slice; all counts and the summary
  are over the **targeted** servers, with a trailing note
  (`(9 servers skipped by --server)`).
- `--dry-run` — phase 1 only (read + plan + report), write nothing. Exit 0
  when the fleet is already converged, 1 when changes are pending or any
  server is unreachable/refused. This is the free preview the comment memo
  promised (`audit --comments` shows comment drift; `apply --dry-run` shows
  the full write plan).
- `--yes` — skip the confirmation prompt (automation). Mutually exclusive
  with `--dry-run` (exit 3).
- Preflights identical to audit: manifest load/validate (+ warnings to
  stderr), agent check, known_hosts preflight — all before dialing. The
  agent preflight additionally records the **agent-held fingerprints** for
  the guard.
- Logging: the standard `-v/-q/--color` contract; phase progress at info
  (`planning 12 servers…`, `applying 3 servers…`), per-stage detail at
  debug; report on stdout, diagnostics on stderr.

## Data flow

**Phase 1 — plan (read-only, exactly audit's pipeline).** Fan out with the
bounded pool; per server: read the file (`sshread`, honoring
`authorized_keys_file`), parse, `Diff` against `DesiredFor`. The audit
orchestrator is reused, extended in two small ways: it accepts the
(possibly `--server`-filtered) server slice, and it retains each server's
raw content bytes (needed for the byte-exact convergence test; today they
are dropped after parsing). Then compute each server's **plan**, pure and
unit-testable:

- render the desired file (see *Rendering*),
- classify: `converged` (bytes equal, or empty-desired with absent/empty
  file) · `change` — with detail rows: add (`Diff.Missing`), remove
  (`Diff.Unauthorized`), rewrite (matched fingerprint whose comment or
  options differ, via `Result.Actual`), and **normalize** (bytes differ
  with no per-key rows: ordering, whitespace, or non-key lines — reported
  with a count of comment/blank lines that will be removed) ·
  `refused` (non-empty file with empty desired set; parse errors;
  guard-predicted lockout) · `unreachable` (read error).
- the guard runs **advisorily** in phase 1 (agent fingerprints are known;
  the phase-1 connection's session key is recorded too): a server whose
  desired set misses every agent key is marked `refused` in the plan, so
  the operator never confirms a plan that phase 2 then refuses.

**Confirmation gate.** Render the full plan report (stdout). If nothing
needs a write: report, exit 0 (or 1 if any server was unreachable/refused —
convergence unproven). Otherwise `--dry-run` stops here; `--yes` proceeds;
a TTY (stdin **and** stderr are terminals) prompts once on **stderr** —
`apply 3 of 12 servers? [y/N]` — reading `cmd.InOrStdin()` (testable), so
`apply > plan.txt` captures exactly the report. Non-TTY without `--yes`
errors (exit 3). Decline → "aborted; no changes made" on stderr, exit 1.

**Phase 2 — write (drifted servers only).** Fan out with the same pool. Per
server, over one connection: re-check the guard (authoritative, against the
same agent fingerprints), then sessions for: symlink pre-check + backup
(`cp -p`), atomic write (temp + `mv`, stdin-fed), verify (re-read +
byte-compare). Any stage failing marks the server failed; other servers
proceed independently (no global abort — partial application is visible in
the report, and re-running apply is always safe because the render is
idempotent).

**TOCTOU note (accepted):** a key edited on the server between plan and
write is overwritten without being shown in the plan. The window is
seconds, the file is supposed to be SSHepherd-managed, and the write is the
rendered desired state either way; the verify step plus a follow-up `audit`
close the loop. Not worth a compare-and-swap protocol in v1.

## Rendering (`internal/authkeys`)

`Render(entries []RenderEntry) []byte`, with
`type RenderEntry struct { Key Key; Comment string }` — pure;
`internal/apply` builds entries from `DesiredFor` + `DesiredComment`
(`authkeys` cannot import `config`, so the comment arrives as a string).
Each entry renders as:

```
options… <keytype> <base64> <comment>
```

- Options: the manifest key line's parsed options, comma-joined verbatim
  (the x/crypto parser preserves quoted values, so join is faithful —
  pinned by the round-trip fuzz target).
- Key material: re-marshaled from the parsed public key (`RenderLine`
  re-parses `Key.Raw` — cheap, keeps `Key` small) via
  `ssh.MarshalAuthorizedKey`, trailing `\n` stripped — one canonical form,
  immune to odd whitespace in manifest lines. Certificate lines
  (`…-cert-v01@…`) round-trip like any other type.
- Comment: `config.DesiredComment` (never empty — `name` is the floor).
- Order: `DesiredFor` order (operators first in `users:` order, then
  grantees in `access:` order) — deterministic, so repeated applies are
  byte-identical.
- File = managed header line + one line per key + trailing newline.

**Prerequisite validation hardening (`internal/config`)** — the render
invariant "one entry, one line, re-parses identically" must be enforced at
manifest load, not assumed:

- `users[].name`: reject control/format characters and leading/trailing
  whitespace (it is an identifier *and* the comment floor; today a YAML
  `name: "x\nEVIL"` would inject a line into every rendered file).
- `users[].comment`: reject all control characters (today only `\r\n`) and
  leading/trailing or all-whitespace values — `ssh.ParseAuthorizedKey`
  trims comments on re-read, so an untrimmed `comment:` would make
  `audit --comments` report permanent, unfixable drift on a byte-converged
  server, breaking the "apply and the drift preview can never disagree"
  promise in `config.go`.

New fuzz target `FuzzRenderRoundTrip` (project rule — this is a writer
whose output our own parser must accept): for any parsed key and any
comment accepted by the hardened validation, `ParseLine(RenderLine(entry))`
succeeds and preserves fingerprint, options, and comment; hostile
names/comments (newlines, control bytes) must be rejected by validation,
never reach the renderer.

## The self-lockout guard

**Invariant enforced: after the write, this operator can still log in to
the server.** Concretely, before writing a server: the rendered desired
set must contain at least one key whose fingerprint the local SSH agent
holds (the fingerprints are listed once at preflight). If the intersection
is empty, refuse:

```
refusing web-1: none of the 2 keys in this agent would remain in
web-1's authorized_keys — applying would lock this session out.
Add one of your keys to the manifest (or mark its user operator: true).
```

Why not the operator spec's literal "never remove the key the session
authenticated with"? Which key signs a handshake is an accident of agent
order and server-side choice. Under the literal rule, the canonical rotate
flow — old key still installed, new key in the manifest, both in the agent
— randomly refuses per server whenever the server picks the old key, which
blocks exactly the workflow apply exists to unblock. The intersection rule
keeps the guarantee that matters (the operator retains access), is
deterministic, and still refuses every true lockout. Two consequences,
both surfaced in the plan:

- Removing the very key that authenticated while another agent key
  survives is **allowed** and noted per server
  (`note: removes the key this session logged in with; sshepherd-new
  remains`).
- If every guard-satisfying line carries a restrictive option
  (`from=`/`command=`/`restrict`/`expiry-time=`), the plan warns that the
  surviving access may be functionally limited (see decision table).

Defensive fallback: if the agent listing is empty or unavailable at guard
time (agent died mid-run), refuse all writes that remove keys. The guard
also structurally enforces the operator contract: an `operator: true` key
is in every desired set and can never be removed by apply; stripping it
requires editing the manifest (flag removal) *and* passing the
confirmation gate — the two explicit steps the operator spec demanded.

## Remote write protocol (`internal/sshwrite`)

Pure command builders (same discipline as `authorizedKeysCmdFor`: the path
enters once via `shQuote`, `~/` becomes `"${HOME:?}"/…`), executed over the
phase-2 connection:

1. **Pre-check + backup:**
   `if [ -L "$p" ]; then exit 45; fi; if [ -e "$p" ]; then cp -p "$p" "$p".sshepherd.bak; fi`
   (exit 45 = symlink sentinel → refusal, sibling of the read path's 44).
2. **Write:**
   `umask 077; d=$(dirname "$p"); mkdir -p "$d"; t="$p".sshepherd.tmp; rm -f "$t"; (set -C; cat > "$t") && mv "$t" "$p" || { rm -f "$t"; exit 1; }`
   — content arrives on stdin (no shell-encoding of key material);
   `umask 077` pins the temp file to 0600 before a byte is written;
   `rm -f` + `set -C` (noclobber) guarantee `cat` creates a fresh file —
   never truncating through a pre-existing file or symlink at the
   predictable temp name; `mv` in the same directory is an atomic rename,
   so sshd never observes a partial file; failure leaves the original
   untouched and removes the temp. A connection dropped mid-`cat` can
   still orphan a temp file; the next apply's `rm -f` reclaims it — which
   is why the name is deliberately **not** PID-suffixed (a `$$` name would
   orphan forever): two concurrent applies to one server are already
   last-writer-wins on `mv`, and `set -C` makes an interleaved `cat` fail
   loudly instead of corrupting, so the fixed name costs nothing.
   `mkdir -p` covers first-contact servers (file-absent case) — for the
   default path that creates `~/.ssh` with 0700; for an override path it
   creates what the operator configured.
3. **Verify:** the existing read command (`authorizedKeysCmdFor`);
   byte-compare against the render.

The remote is assumed POSIX (sh, cat, cp, mv, mkdir, dirname) — the same
assumption the read path already makes. A stderr-producing failure surfaces
through the existing sanitized-error path.

File-absent-but-login-worked (the audit diagnostic: sshd may consult
another key source) does **not** block apply: creating the audited file is
purely additive, and the plan report carries the same diagnostic note so
the operator knows this server's sshd may look elsewhere.

## Report (stdout)

Audit's visual language, plan-tinted. "Converged" counts servers that
needed nothing **and** servers applied-and-verified this run:

```
web-1 (deploy@10.0.0.1:22)
  + alice        SHA256:abc…  ssh-ed25519  add (authorized, missing)
  + carol        SHA256:pqr…  ssh-ed25519  add (authorized, missing)
  - (unknown)    SHA256:xyz…  ssh-rsa      remove (unauthorized)
  ~ bob          SHA256:def…  ssh-rsa      rewrite comment: "bob@old" → "bob@work"
  ~ (formatting) normalize: reordering; removing 3 non-key lines (comments/blank)
  → 12 keys desired · 2 add · 1 remove · 1 rewrite · applied · verified

web-2 (deploy@10.0.0.2:22)  converged (no changes)
db-1  (deploy@10.0.0.9:22)  REFUSED: 3 keys installed but manifest grants none — refusing to wipe

Summary: 11/12 servers converged (1 applied) · 1 refused  → exit 1
```

Colors through the existing report-color infrastructure; glyph/label
rendering shares audit's helpers where they fit. `--json` for apply is
deferred (audit's schema exists; adding a plan schema is its own small
slice once something consumes it).

## Packages

| Package | Responsibility | Testability |
|---|---|---|
| `internal/sshconn` (new, extracted) | Connection glue and shared remote-read/write plumbing. **Moves verbatim from `sshread`:** `shQuote`, the `~/`→`"${HOME:?}"` assignment builder, `authorizedKeysCmdFor`, `interpretExit`, `finishRead`, `sanitizeRemote` + `sanitizedError`, `cappedBuffer`, `hostKeyHint`/`typeRecorded`/`recordedTypes`, the connect sequence (agent dial, knownhosts callback, dial, handshake, deadline plumbing). **New here:** the session-key recorder (wraps agent signers; records the fingerprint whose `Sign` completed the handshake) and the agent-fingerprint listing for the guard. | The moved pure helpers' tests (`TestShQuote`, `TestAuthorizedKeysCmdFor`, `TestSanitizeRemote`, `TestHostKeyHint`, `TestFinishRead`, `FuzzShQuote`) move with them mechanically; glue covered by the existing integration suite. |
| `internal/sshread` (public API unchanged) | Read decision logic on top of `sshconn`. `CheckAgent`/`PreflightKnownHosts`/`Client` keep their signatures and call sites (`cmd` untouched); internals delegate to `sshconn`. | Existing tests unchanged — the refactor is behavior-preserving. |
| `internal/sshwrite` (new) | `FleetWriter`: symlink-check/backup, atomic write, verify over one connection; pure command builders. | Builders + protocol logic pure-unit; network via integration. |
| `internal/apply` (new) | Plan computation incl. guard decisions (pure), orchestration of phase 2 behind a writer seam, report rendering. | Pure unit + fakes; goldens for plan/report. |
| `cmd/sshepherd` | `apply` subcommand: flags, preflights (+ agent fingerprint capture), prompt, exit mapping (`errNonCompliant` reused for "not converged"). | `run()` tests with fake seams. |

## Deliberately deferred (NOT in this slice)

- `revoke` / `rotate` UX (both reduce to manifest edit + `apply`).
- `apply --json` plan output; `prune`; backup retention/rollback command.
- `--identity` key-file auth (agent-only stands; separate roadmap item).
- Overriding refusal gates (`--force` on unparseable files or symlinks).
- Non-POSIX remotes; `AuthorizedKeysCommand`/CA-cert fleets.
- Compare-and-swap writes (TOCTOU accepted above).

## Testing (per project policy — all kinds, coverage ≥ 80%)

- **Unit (table-driven):** plan classification (converged / add / remove /
  rewrite-comment / rewrite-options / normalize-only / empty-desired
  converged-vs-refused / parse-error refusal / unreachable); guard
  decisions (intersection present / absent / session key removed but
  another survives / empty agent listing / operator always passes /
  restrictive-options warning); write-command builders (default path, `~/`
  override, absolute override, quoting, symlink sentinel); confirmation
  gate (TTY yes/no via injected stdin, non-TTY without `--yes`, `--yes`,
  `--dry-run`); exit-code mapping; `--server` filtering incl. unknown
  names and summary note; new config validation rules (hostile names,
  untrimmed comments).
- **Golden:** rendered `authorized_keys` (the CLAUDE.md golden requirement
  lands here: header, operator-first ordering, comment policy, options
  preserved); plan report (drift, converged, refused, normalize, color and
  plain); dry-run output.
- **Fuzz:** `FuzzRenderRoundTrip` (render→parse identity over
  validation-accepted inputs); `FuzzShQuote` continues in its new home;
  the write-command builder gets a quoting round-trip target mirroring the
  read builder's.
- **Integration** (`//go:build integration`, dockerized sshd — **the only
  place any real write happens; no test path ever touches a non-fixture
  host**): drifted seed → apply → file byte-equals render, mode 0600,
  `.sshepherd.bak` holds the pre-apply bytes, no `.tmp.*` residue;
  file-absent → file + `~/.ssh` created with correct modes; symlinked
  target → refused, symlink intact; lockout guard trips (manifest lacking
  every agent key) → file untouched, exit 1; verify-failure path;
  unparseable-file refusal; orphaned-temp reclamation on re-apply.
- **E2E:** drive the built binary against the docker fleet:
  `adopt → apply --yes (first write, normalizes everything) → apply
  (no-op, byte-stable) → remove a grant → apply --dry-run (plan) →
  apply --yes → audit` exits 0 — the first full distribute-then-audit
  loop, satisfying the E2E requirement for the write path.
  (`revoke`/`rotate` legs join when those verbs exist.)
- **Bench:** none new — the fan-out is audit's, already benchmarked.
- Suite-wide: goleak `TestMain` in every new package; `-race`; coverage
  gate.

## Commit plan (trunk-based, each commit green on its own)

1. `docs: apply slice design` (this spec, after owner approval)
2. `feat(config): harden name/comment validation for the render invariant`
3. `refactor(sshconn): extract shared SSH connection glue from sshread`
   (behavior-preserving; helpers and their tests move as units)
4. `feat(authkeys): render authorized_keys lines (+ round-trip fuzz)`
5. `feat(sshconn): session-key recorder + agent fingerprint listing`
6. `feat(audit): retain raw content bytes; accept a server subset`
   (byte-convergence + `--server` inputs; audit behavior unchanged)
7. `feat(sshwrite): atomic remote write with symlink guard, backup, verify`
8. `feat(apply): plan computation, guard, and report` (pure core)
9. `feat(cmd): sshepherd apply — plan, confirm, write, verify`
10. `test(integration): apply against dockerized sshd + E2E loop`
11. `docs: mark apply slice implemented` (CLAUDE.md status, spec status
    line, roadmap memory)

## Open questions — resolved by the owner (2026-07-19)

1. **Guard refinement** — approved: intersection-over-agent-keys, as
   specced in the guard section.
2. **Backup file** — approved: single-generation `<path>.sshepherd.bak`.
3. **Confirmation default** — approved: plan + prompt, `--yes` for
   automation, `--dry-run` available.
4. **Managed header line** — approved: keep, wording as specced.

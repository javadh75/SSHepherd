# Design: `--identity` key-file authentication

- **Date:** 2026-10-16
- **Status:** Approved design (brainstorm 2026-10-16), revised after an
  adversarial three-lens critique (security, feasibility against the code,
  operator UX); not yet implemented.
- **Amends:**
  [audit slice](2026-07-06-audit-slice-design.md) (fulfils the planned
  `--identity` follow-up and settles the passphrase policy it deferred),
  [apply slice](2026-07-19-apply-slice-design.md) (the guard's "held keys"
  are no longer agent-only),
  [review hardening](2026-10-16-review-hardening-design.md) (the post-write
  login probe offers surviving keys from any source).

## Context & goal

Every SSH connection today authenticates through `ssh-agent`
(`SSH_AUTH_SOCK`). That blocks headless use: CI jobs, cron, and containers
without a forwarded agent. This slice adds repeatable `--identity` key files
to `audit`, `adopt` and `apply`, plus a passphrase policy, without weakening
the write path's two safety nets: the self-lockout guard and the post-write
login probe. Both must reason about every key the run can authenticate with,
whatever its source.

## Decisions (locked by prior specs — not open for relitigation)

- Native `golang.org/x/crypto/ssh` transport; no host `ssh`/`ssh-add` binary
  (and `os/exec` is banned in non-test code by depguard).
- Strict `known_hosts`; host-key handling is unchanged by this slice.
- Guard = some key the operator holds must survive in the rendered file,
  excluding `cert-authority`/`principals=` lines; the guard re-runs after the
  confirmation prompt on a fresh "held" listing.
- The login probe offers only surviving held keys (unrestricted first), runs
  a probe command, and restores the previous file on failure.

## New decisions this spec makes (owner-approved 2026-10-16)

1. **Union with the agent, agent optional.** Like `ssh -i`: identity-file
   keys are offered in addition to agent keys. When at least one
   `--identity` is given, a missing, empty or broken agent is not an error
   (a broken-but-set `SSH_AUTH_SOCK` logs one warning). With no
   `--identity`, behavior is exactly today's (agent required, every agent
   entry — certificates included — offered for login).
2. **Passphrase sources: TTY prompt + files; no environment variable.**
   An env var would sit in `/proc/<pid>/environ` (same uid, root) for the
   whole run, be inherited by children and land in core dumps; files,
   secret mounts and `/dev/fd/N` avoid that and still serve CI. A
   passphrase is never accepted as a flag value (argv, `ps`, history).
3. **Repeatable identities, default passphrase plus per-key overrides.**
   Repeatability is required for *headless self-rotation*: the run logs in
   with the old key while the guard and probe need the new key held.
4. **Certificates do not count as held.** `PATH-cert.pub` next to an
   `--identity` is not loaded (info line). Agent-held certificates are still
   *offered for login* (unchanged behavior) but are excluded from the held
   set that feeds the guard and the probe: a certificate logs in via a
   `cert-authority` line, which the guard cannot prove survives without
   modelling CA, principals and validity — a later slice.
5. **Architecture: explicit credential source** (`sshconn.Credentials` +
   new `internal/keyfile`), not an in-process agent keyring (keeps
   agent-specific naming wrong) and not `ssh-add` (mutates the user's agent,
   needs `os/exec`).

## Command surface

New flags on `audit`, `adopt` and `apply` (declared per command, like
`--known-hosts`; not root-persistent). `import` makes no connection and is
unchanged. Usage strings carry backticked varnames so `--help` renders
`--identity PATH`, `--identity-passphrase-file FILE` and
`--identity-passphrase KEY=FILE` (a cmd test compares `--help` with the
README tables).

| Flag | Default | Meaning |
| ---- | ------- | ------- |
| `--identity PATH` | none (repeatable) | Private key file to authenticate with, in addition to `ssh-agent`. `~/` expands from `$HOME`. |
| `--identity-passphrase-file FILE` | none | Default passphrase for any encrypted `--identity` key. |
| `--identity-passphrase KEY=FILE` | none (repeatable) | Passphrase file for one key. Split at the **first** `=`; a key path containing `=` is unsupported (documented). |

**Path matching is lexical**: `~/` expansion, `filepath.Abs` (against the
working directory) and `filepath.Clean`; no symlink resolution; case
sensitive. A mapping attaches to its exact `--identity` path before any
de-duplication.

Flag validation (exit 3, before anything else):

- An `--identity-passphrase` whose `KEY` matches no `--identity` → error
  listing the cleaned `--identity` paths, so the mismatch is visible.
- The same `KEY` twice in `--identity-passphrase` → error.
- Passphrase flags without any `--identity` → error ("passphrase flags need
  --identity").
- The same cleaned path twice in `--identity` → de-duplicated silently.

### Order of operations in each command

1. Flag validation (above).
2. Manifest load and validation; server selection (`apply --server`).
3. Empty-fleet / zero-target early return — **before** any key is read, so
   such a run never prompts and never needs a passphrase (today's exit 0).
4. `known_hosts` preflight.
5. `keyfile.Load` (reads files, may prompt).
6. `CheckCredentials`, then the fan-out.

A manifest typo or bad `--known-hosts` therefore fails before the operator
types a passphrase.

## Loading (`internal/keyfile`, new)

```go
type Spec struct{ Path string }          // cleaned absolute path
type Passphrases struct {
    Default string                       // passphrase file path, "" if none
    PerKey  map[string]string            // key path -> passphrase file path
}
type Prompter interface {                // /dev/tty in production, fake in tests
    Available() bool
    ReadPassphrase(ctx context.Context, prompt string) ([]byte, error)
}
type Identity struct {
    Path        string
    Fingerprint string                   // SHA256 of the DECRYPTED key
    Signer      ssh.Signer
}
func Load(ctx context.Context, specs []Spec, pp Passphrases, p Prompter, fs FS) ([]Identity, error)
```

`FS` is a small interface whose `Open` returns a reader plus the `FileInfo`
of **that open descriptor** (fstat), plus the current uid — every file is
opened once, checked on the descriptor, and read from the same descriptor
(no stat-then-open race). Tests use a fake.

### Reading files (keys and passphrase files alike)

- **Permission rule (OpenSSH `sshkey_perm_ok`), regular files only.** If the
  opened file is a regular file owned by the current uid with
  `mode & 077 != 0` → refuse: "permissions 0644 for FILE are too open
  (chmod 600 FILE)". A regular file owned by another uid (e.g. a root-owned
  secret mount) is accepted, as `ssh` accepts it. FIFOs, sockets and
  character devices (`/dev/fd/N`, `<(...)`, `/dev/stdin`) are **exempt**:
  their mode bits do not describe a file at rest (macOS reports a
  process-substitution pipe as `0440` owned by the caller; Linux as `0600`).
- **Unreadable** (`EACCES`) → targeted error: "cannot read FILE as uid N
  (owner M, mode 0600) — see README 'Container usage'".
- **Bounded reads**: key files are capped at 64 KiB, passphrase files at
  4 KiB; larger → error (protects against `/dev/zero` and mistakes).

### Passphrase files

Every distinct passphrase file path (the default and all `PerKey` values) is
opened and read **exactly once per run, before any key is tried**, and
cached in memory for the duration of `Load` (a pipe can only be read once).
Exactly one trailing `\n` or `\r\n` is stripped. A file that is empty after
stripping → exit 3 naming the file (never tried silently as an empty
passphrase). Cached bytes are `clear()`ed when `Load` returns — best effort
only: Go cannot guarantee no copies, and bcrypt intermediates are not
zeroed. Documented as such.

### Per key, in flag order

1. **Read** the key file (rules above).
2. **Classify the container before any prompt** — x/crypto's API cannot
   tell these apart, so `keyfile` inspects the bytes itself:
   - `PuTTY-User-Key-File-` prefix → refuse (convert with `puttygen`).
   - PEM `ENCRYPTED PRIVATE KEY` (encrypted PKCS#8) → refuse.
   - PEM `DSA PRIVATE KEY` → refuse ("ssh-dss is disabled by default in
     OpenSSH").
   - `openssh-key-v1\0`: decode the header with `ssh.Unmarshal` into a
     local struct (cipher, KDF, KDF options, key count, public key). Refuse
     a cipher other than `none`/`aes256-ctr`/`aes256-cbc`, a KDF other than
     `none`/`bcrypt`, bcrypt rounds above 2048 (x/crypto's cap; hint:
     `ssh-keygen -p -a 100 -f KEY`), more than one key, and a public-key
     type of `ssh-dss` or `sk-*` ("hardware keys must be used via
     ssh-agent").
   - Every other refusal carries the hint `ssh-keygen -p -f KEY` to rewrite
     the key in a supported format.
3. **Parse** with `ssh.ParseRawPrivateKey`. Unencrypted → signer via
   `ssh.NewSignerFromKey`. `*ssh.PassphraseMissingError` → encrypted, step 4.
4. **Passphrase resolution** for an encrypted key, first that applies:
   1. `PerKey[KEY]` → decrypt. Wrong → **exit 3, no fallback** (an explicit
      mapping that does not match is a configuration error).
   2. `Default` → decrypt. Wrong → fall through (the default is a shared
      guess, not a claim about this key).
   3. `Prompter.Available()` → prompt on `/dev/tty`:
      `Enter passphrase for KEY (SHA256:…): `. Up to 3 attempts, like `ssh`;
      exhausted → exit 3.
   4. Otherwise → exit 3: "KEY is encrypted and no passphrase source is
      available (use --identity-passphrase-file or --identity-passphrase
      KEY=FILE)"; if a default file was tried, the message says it did not
      unlock this key.

   **What counts as "wrong passphrase"**: for OpenSSH-format keys, only
   `x509.IncorrectPasswordError` (they carry a reliable check value). For
   legacy encrypted PEM, *any* failure after decryption, because
   `x509.DecryptPEMBlock` cannot always detect a wrong password (about 1 in
   256 wrong passphrases yields valid padding and garbage that then fails to
   parse). Any other error is a hard exit 3, never a retry.
5. **Fingerprint.** `Identity.Fingerprint` is always
   `ssh.FingerprintSHA256(Signer.PublicKey())` of the decrypted key. The
   pre-decryption public key (the OpenSSH header's, or a sibling `KEY.pub`
   for legacy PEM) is only a label for the prompt; if it disagrees with the
   decrypted key → refuse the key ("KEY.pub / embedded public key does not
   match the private key").
6. **De-duplication** runs on decrypted fingerprints: two paths holding the
   same key → first path wins, info line naming the dropped path.
7. **Certificate note.** If `KEY-cert.pub` exists → info line "certificate
   KEY-cert.pub not used; authenticating with the plain key".

`Load` returns every non-interactive error for every key joined
(`errors.Join`), so a CI run reports each misconfigured key at once.

### The `/dev/tty` prompter

- **`Available()`** is true only when `/dev/tty` opens, **stdin** is a
  terminal (matching apply's confirmation contract), and the process is in
  the terminal's foreground process group (`tcgetpgrp == getpgrp`).
  Otherwise the run is headless: `docker run -t`, a pty-allocating CI
  executor, or `cmd &` exit 3 with the "no passphrase source" message
  instead of hanging or being stopped by `SIGTTIN`. An info line
  ("waiting for passphrase for KEY on the terminal") precedes each prompt.
- `--yes` does **not** disable prompting; it only skips the `[y/N]`
  confirmation. Documented.
- **Cancellation.** `ReadPassphrase` saves the terminal state
  (`term.GetState`), reads in a goroutine, and on `ctx.Done()` restores the
  state, prints a newline to the tty, closes the tty to unblock the read,
  and returns `ctx.Err()` → the existing interrupted path (exit 3, nothing
  connected). The first Ctrl-C therefore always works and never leaves the
  shell without echo. Real-tty code is kept out of goleak-checked unit
  tests (exercised via the fake).
- Prompts and the info line go to `/dev/tty`, never stdout (so
  `audit --json` stays clean) and regardless of `-q`; `-q` hides the
  log lines only.

Logging: each loaded key once at info level as `identity loaded path=KEY
fp=SHA256:…`. Passphrases, passphrase-file contents and key bytes never
reach any log, error or report; x/crypto errors are wrapped, never
formatted with key material.

## Credentials and transport (`internal/sshconn`)

```go
type Credentials struct {
    Files     []keyfile.Identity
    AgentSock string   // "" = no agent
    Log       *slog.Logger
}
func (c *Credentials) Signers(ctx context.Context) ([]ssh.Signer, func(), error)
func (c *Credentials) Held(ctx context.Context) ([]HeldKey, error)
type HeldKey struct{ Fingerprint, Source string } // Source: KEY path or "agent"
```

- **`Signers`** — called by `ConnectWith` **before the TCP dial**; it dials
  the agent (applying the ctx deadline to the socket) and the returned
  closer is `defer`red until `ConnectWith` returns. The
  `PublicKeysCallback` only returns the pre-fetched, ordered, wrapped list.
  Order: file signers (flag order), then agent signers (agent order, plain
  keys before certificates). De-duplicated by fingerprint, keeping the file
  signer. Agent failure: with file keys present → continue with file keys
  and warn once per run (`sync.Once` shared with `Held`); with no file
  keys → today's `classify(ErrorKindAgent, …)`, unchanged.
- **`Held`** — fingerprints of the plain keys in the current union, with
  their source; agent certificates excluded. Re-lists the agent on every
  call, so the post-prompt re-check still notices agent keys that expired.
  Agent failure: with file keys present → return the file keys, the
  one-time warning, and a **nil error** (agent keys simply stop counting —
  fail-safe); with no file keys → return the error (today's "no server will
  be written" path).
- **`Dialer`** replaces `AgentSock string` with `Creds *Credentials`.
  `orderSigners` (`Prefer`/`Only`), `wrapSigners` and the session-key
  recorder are unchanged in behavior; within granted-keys-first, ties keep
  `Signers` order (file keys before agent keys).
- **`CheckCredentials(ctx, creds, needHeld bool)`** replaces
  `sshread.CheckAgent`. For `audit`/`adopt` (`needHeld=false`) it counts
  *signers* — a cert-only agent passes, as today. For `apply`
  (`needHeld=true`) it requires a non-empty held set; a cert-only operator
  is refused with a certificate-specific message. With no `--identity`, the
  agent messages are today's verbatim.
- **`AgentFingerprints`** is replaced by `Credentials.Held` at every call
  site.
- **Error kinds:** no new JSON `error_kind`; key-file problems are exit 3
  before any server is contacted; `ErrorKindAgent` and `ErrorKindAuth`
  keep their meaning.
- **`sshtest`** gains a way to authorize a file key with no agent.

Each command builds **one** `Credentials` per run and shares it with the
read client, the writer and the probe.

## Write path (`internal/apply`, `internal/sshwrite`, `cmd/sshepherd/apply.go`)

- **Guard.** "Held" = `Credentials.Held()` at preflight (into
  `apply.Build`) and again after the `[y/N]` prompt (into `ExecOptions`).
  Logic unchanged. `writePhase` uses whatever `Held` returns and never
  substitutes `nil` for a degraded (file-only) set.
- **Survivor order.** Unrestricted first (as today), then file keys before
  agent keys, then fingerprint — deterministic across runs.
- **Probe.** `ConnectOptions{Only: survivors}` over the same `Credentials`.
  Because survivors are file-first, when any `--identity` key survives the
  probe proves that key.
- **Agent-only survivor warning.** When at least one `--identity` is given
  and a server's survivors contain **no** `--identity` key (only agent
  keys), the plan shows a per-server warning: "only SHA256:… (agent) keeps
  access; none of your --identity keys survives — a run without this agent
  will be locked out". This catches a CI runner with a stray or forwarded
  agent satisfying the guard for a credential the next headless run won't
  have. Not a refusal (union semantics are the owner's decision); the
  README's CI recipes also unset `SSH_AUTH_SOCK`.
- **Headless rotation** (the motivating case): manifest replaces `ci_old`
  with `ci_new`; `--identity ci_old --identity ci_new`; the write logs in
  with `ci_old`, the guard sees `ci_new` survive, the probe proves `ci_new`.
  With only `--identity ci_old` (and no agent), the guard refuses with a
  message naming the fix (add `--identity` for the new key).
- **Wording.** Every agent-specific string becomes source-neutral ("keys you
  hold (identity files + agent)"): guard, exec, probe and `LockoutError`
  messages, apply's `Long` help ("no agent-held key"), the
  `CheckCredentials` hints, and the README connection-posture text.
  Refusals list each held key with its source, e.g.
  `SHA256:abc… (~/.ssh/ci_new)` / `SHA256:def… (agent)`. Goldens and
  README samples are regenerated, not hand-edited.

## Packages

| Package | Change |
| ------- | ------ |
| `internal/keyfile` (new) | Load, file reading/permission rule, container classification, passphrase resolution, `/dev/tty` prompter |
| `internal/sshconn` | `Credentials`, `HeldKey`, Dialer uses `Creds`, `Signers` before dial, `sshtest` file-key auth |
| `internal/sshread` | `CheckCredentials`; `Client` carries `Creds` |
| `internal/apply` | held keys with sources, survivor order, agent-only-survivor warning, neutral wording |
| `internal/sshwrite` | probe/`LockoutError` wording; `Creds` plumbing |
| `cmd/sshepherd` | three flags on audit/adopt/apply, order of operations, wiring |
| `.gitleaks.toml` | path-scoped allowlist for `internal/keyfile/testdata` (throwaway keys only) |

## Deliberately deferred (NOT in this slice)

- SSH certificates counting toward the guard (`-cert.pub`, agent certs) —
  needs CA/principals/validity modelling.
- Reading `IdentityFile`/`IdentitiesOnly`/`IdentityAgent` from `ssh_config`
  at connect time.
- `SSH_ASKPASS`, a passphrase environment variable, and
  `--identities-only` (identity-only mode).
- `sk-` keys from a file (x/crypto cannot sign with them; use the agent).
- Lazy decryption (only unlock keys a server actually needs).
- A signature-algorithm restriction (`ssh.NewSignerWithAlgorithms`); the
  session recorder's lack of `MultiAlgorithmSigner` pass-through only
  matters once something restricts algorithms, so it is deferred with it.

## Testing (per project policy — all kinds, coverage ≥ 80%)

- **Fixtures** are generated at test time wherever x/crypto can marshal
  them (`ssh.MarshalPrivateKey`, `MarshalPrivateKeyWithPassphrase`, x509
  marshalers). Formats it cannot produce (`.ppk`, sk, DSA, gcm/chacha
  ciphers, >2048 rounds, mismatched public section) are committed under
  `internal/keyfile/testdata` as throwaway keys behind a path-scoped
  gitleaks allowlist.
- **Unit `keyfile`** (fake `FS`/`Prompter`): every resolution path —
  per-key ok/wrong (no fallback), default ok/wrong (falls through), prompt
  ok / wrong×3 / unavailable / cancelled mid-prompt; a pipe used as the
  default for two encrypted keys (read once); one FILE in two mappings;
  empty passphrase file; permission rule (own regular 0644 refused, own
  0600 ok, other-uid 0644 ok, own FIFO 0440 ok, EACCES message); size caps;
  every container classification and refusal *before* any prompt; legacy
  PEM wrong passphrase producing valid padding treated as wrong; stale
  `.pub` and mismatched OpenSSH public section refused; de-dup by decrypted
  fingerprint; `-cert.pub` note; flag validation errors.
- **Unit `sshconn`** (hermetic `sshtest`): file-only auth with no agent;
  union order and de-dup; agent certificate still offered for login but
  absent from `Held`; broken agent + file key → one warning and success
  (`Signers` and `Held`); broken agent, no file → `ErrorKindAgent`; `Only`
  across sources; session-key recorder sees a file key.
- **Unit `apply`**: headless rotation plan; refusal text with sources;
  agent-only-survivor warning; post-prompt re-check where the agent breaks
  and a file key survives (write proceeds) and where the only survivor was
  an agent key (refused); cert-only operator refused.
- **Unit `cmd`**: flag parsing/validation, first-`=` split, lexical
  matching error listing paths, order of operations (empty fleet + an
  encrypted `--identity` with no TTY → exit 0, no prompt), `--help`
  matches the README tables.
- **Fuzz**: `FuzzClassify` over key-file bytes (container/header
  classification, no KDF — fast) and `FuzzDecrypt` with bcrypt rounds
  clamped low. The leak property uses an injected ≥16-byte high-entropy
  marker passphrase and asserts it never appears in errors or captured
  log output. Both added to `make fuzz` and the scheduled CI job.
- **Integration** (`//go:build integration`, real sshd, `SSH_AUTH_SOCK`
  unset): `audit --identity`; `apply --identity` with an encrypted key and
  `--identity-passphrase-file`; headless rotation end to end (old → new,
  probe passes, a second run with only the new key is a no-op).
- **E2E**: adopt → apply → audit fully headless with `--identity`.
- **goleak** `TestMain` in `internal/keyfile`.

## Docs (same commit as the code)

- README flag tables for audit/adopt/apply (matching `--help`).
- A new **Authentication** section replacing "agent-only": sources and
  union; certificates offered but never counted by the guard; passphrase
  resolution order; the regular-file permission rule and the pipe
  exemption; unsupported formats with their conversion hints; `--yes` still
  allows prompting; headless detection; the memory-hygiene caveat; the
  agent-only-survivor warning.
- **CI recipes**, each unsetting `SSH_AUTH_SOCK`:
  - GitHub Actions (bash): `env -u PW sshepherd apply --identity KEY
    --identity-passphrase-file <(printf %s "$PW") --yes` — `env -u` keeps
    the secret out of sshepherd's own environment; `<(...)` needs bash or
    zsh, not POSIX `sh`.
  - GitLab CI: a `type: file` variable, passed as its path.
  - Kubernetes CronJob: key and passphrase from a secret volume.
  - `docker run`: a bind-mounted file or tmpfs, not process substitution
    (a host-side `<(...)` fd is not passed into the container).
- **Container usage**: the image runs as uid 65532, so a mounted key must be
  either owned by the container uid with mode 0600 (`--user`, or K8s
  `runAsUser` matching the owner) or root-owned and readable through group
  or other bits (K8s `fsGroup: 65532` with `defaultMode: 0440`).
- CLAUDE.md Status paragraph; one-line "amended by" notes in the audit and
  apply specs.

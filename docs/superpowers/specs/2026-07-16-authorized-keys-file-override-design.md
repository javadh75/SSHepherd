# Design: per-server `authorized_keys_file` override

- **Date:** 2026-07-16
- **Status:** Implemented (2026-07-16)
- **Scope:** `internal/config` (new `Server` field + validation),
  `internal/sshread` (command builder + `shQuote`), `internal/audit`
  (path-aware absent/empty notes, JSON field), `cmd/sshepherd`
  (adopt round-trips the field). Adversarially reviewed; verdict "sound"
  with corrections folded in below.

## Context & goal

Audit and adopt read a hardcoded `~/.ssh/authorized_keys` on every server.
Fleets that set sshd's `AuthorizedKeysFile` to a custom location (e.g.
`/etc/ssh/authorized_keys.d/deploy`) audit as file-absent even though keys
are installed and working. This slice adds a per-server manifest override so
the read targets the file sshd actually consults — without breaking the
existing invariant that no manifest text reaches a remote shell unquoted.

## Decisions (locked)

| Decision | Choice | Notes |
|---|---|---|
| YAML key | **`authorized_keys_file`** (Go: `Server.AuthorizedKeysFile`) | Mirrors sshd_config's `AuthorizedKeysFile` directive 1:1 — the situation prompting the override. |
| Path semantics | **Unset ⇒ `~/.ssh/authorized_keys` (exact current behavior); set ⇒ must start with `/` or `~/` with non-empty remainder** | Bare-relative, lone `~`, bare `~/`, and `~user/` are rejected — the explicit prefix removes home-vs-cwd ambiguity. No sshd `%h`/`%u` token expansion. |
| Explicit default is an override | **`authorized_keys_file: ~/.ssh/authorized_keys` set explicitly IS an override** | Intended: path-aware note wording applies and the field is emitted in JSON/YAML. Setting the field means "I am telling you the path"; the reporting reflects that. |
| Quoting contract | **`shQuote` returns the FULLY single-quote-wrapped token** (`abc` → `'abc'`, `a'b` → `'a'\''b'`); templates add NO extra quotes | Absolute: `p=<shQuote(path)>; if [ -e "$p" ]; then cat "$p"; else exit 44; fi`. Home-relative: `p="${HOME:?}"/<shQuote(rest)>; …`. One builder, one splice point, exit-44 sentinel unchanged. |
| `${HOME:?}` over tilde | **Fail loudly if HOME is unset remotely** | Tilde-in-assignment next to quoted text is a dash/ash portability footgun; `"$HOME"/x` with HOME unset silently reads `/x` (false drift). `${HOME:?}` exits ≠ 0/44 and surfaces as a normal remote-read error, never `FileAbsent`. |
| Injection defense | **Two independent layers** | (1) validation rejects any `unicode.IsControl` or `unicode.Cf` rune and caps length at 4096 — newline/CSI smuggling dies before a command is built; (2) `shQuote` renders every remaining metachar (`;`, `$()`, backticks, spaces, quotes) inert. The path enters the command exactly once. Correctness of `shQuote` is load-bearing — hence the `sh -c` round-trip fuzz. |
| Threading | **No interface changes** | `config.Server` already flows through `audit.KeyReader.ReadAuthorizedKeys`; `readAuthorizedKeys` builds the command and passes the string into `readRemote` (one new param). `audit.Run`, `auditOne`, `adopt.Build` untouched. |
| Report wording | **Byte-identical when unset; path-aware when set** | With an override, the absent/empty note names the overridden path and leads with "the authorized_keys_file override may not match sshd's AuthorizedKeysFile" — the most likely cause flips once the operator has declared a path. Renderer: `renderServer` in `internal/audit/report.go`. |
| JSON report | **`servers[].authorized_keys_file`, `omitempty`** | Additive optional field — schema stays **1** (consumers tolerating unknown/absent fields are unaffected). Existing JSON goldens stay byte-identical. |
| Manifest round-trip | **`serverOut` gains the field (`omitempty`); adopt copies it through** | Without the copy, running adopt would silently strip every override (data loss). import derives servers from OpenSSH *client* config, which has no AuthorizedKeysFile concept — it never sets the field. |
| Compatibility | **Older binaries hard-fail on the new field** | `config.Parse` uses `KnownFields(true)`. Acceptable for a solo-dev tool. |

## Validation edge cases (decisions, not omissions)

- `~//x`, `~/./x`, and trailing-slash paths **pass validation**. POSIX
  collapses non-leading `//` and `/./`, so those two resolve to the intended
  file; a trailing slash fails at runtime (cat exit ≠ 0/44 → normal
  remote-read error). Validation checks shape and injection surface, not
  remote filesystem semantics.
- Paths containing spaces or single quotes are **valid** — rendering them
  inert is the quoting layer's job, and rejecting legitimate paths for
  implementer convenience is the wrong trade for a security tool.
- A hostile manifest can at worst point reads at a file the login user can
  already `cat`: no privilege gain, output is capped at 1 MiB and
  control-stripped before display (existing `cappedBuffer`/`sanitizeRemote`).

## Deliberately deferred

- **No per-user paths, no `AuthorizedKeysCommand`, no `%h`/`%u` tokens, no
  multi-path lists** (sshd allows a space-separated `AuthorizedKeysFile`
  list) — one managed account per server is the model; a list-typed
  successor field can supersede this one if ever needed.
  `AuthorizedKeysCommand` output is not a file we could write back to.
- **Integration coverage** (dockerized sshd with a custom
  `AuthorizedKeysFile`, override hit/miss, space-containing path) — noted as
  a follow-up for `scripts/integration.sh`; out of scope for this slice.
- ~~**`make fuzz` wiring** for `FuzzShQuote`~~ — done in the same change
  window (Makefile `fuzz:` target). The fuzz target exercises both
  production splice shapes (absolute and `"${HOME:?}"/`-relative).

## Testing

- **Unit / table** — config validation (accept: unset, absolute, `~/`,
  spaces, single quote, explicit default; reject: bare-relative, lone `~`,
  bare `~/`, `~user/`, newline/ESC/C1/U+202E, >4096); `shQuote` exact
  outputs including the single-quote case; `authorizedKeysCmdFor` exact
  command strings for default/absolute/`~/`-with-spaces/hostile paths,
  pinning that the default (unset) command behaves identically to the old
  const; `interpretExit` case pinning that `${HOME:?}` failure (HOME unset
  remotely) is a normal remote-read error, NOT `FileAbsent`.
- **Fuzz** — `FuzzShQuote` round-trips inputs through local
  `sh -c` (`p=<shQuote(s)>; printf %s "$p"`) comparing bytes; inputs
  containing NUL are skipped (`\x00` cannot survive execve — not a shQuote
  defect; config validation independently rejects all control chars). Seed
  corpus: `'`, `'\''`, backslash, `$()`, backtick, newline, C1 CSI U+009B.
- **Golden** — all existing report/JSON goldens byte-identical (proves the
  no-override path is unchanged); new `report_absent_override.golden` for
  the override + file-absent case.
- **JSON** — unit assertions for `authorized_keys_file` set (emitted) and
  unset (omitted).
- **Round-trip** — adopt regenerates a manifest with the override preserved
  and re-parseable.

# Design: leveled, color-aware logging (quiet / normal / debug)

- **Date:** 2026-07-10
- **Status:** Approved
- **Scope:** New package `internal/clog` (custom `slog.Handler` + color
  detection); persistent `-v/--verbose`, `-q/--quiet`, `--color` flags on the
  root command (`cmd/sshepherd`); `*slog.Logger` injection into
  `internal/sshread` and `internal/audit`; colorized audit report via a new
  `RenderOptions` parameter on `audit.Render`. Manifest output (`import`,
  `adopt`) is never colored.

## Context & goal

SSHepherd today has no logging. Each command writes its product to stdout
(audit report, generated manifest) and a handful of ad-hoc diagnostics to
stderr (`warning: …`, `sshepherd: <err>`). The runtime activity that matters
operationally — SSH dial, host-key check, agent auth, remote read, parallel
fan-out — is silent: a 50-server audit is a blank terminal for up to 30
seconds, and when a run hangs there is no way to see which server or stage is
stuck.

Goal: three verbosity modes — **quiet**, **normal**, **debug** — with useful
content at each, colored output where it helps, and graceful degradation to
plain text whenever color is unsupported (non-TTY, `NO_COLOR`, `TERM=dumb`)
or unwanted (`--color=never`).

## Decisions (with rationale)

1. **Scope: logs on stderr + colorized audit report on stdout.** The
   `✓/✗/‼/⚠` report lines get color under the same degradation rules.
   Manifest YAML is never colored — it is destined for a file.
2. **Quiet is classic quiet** (curl/rsync style): `-q` silences INFO/WARN on
   stderr; ERRORs still print (never swallowed) and the stdout product is
   untouched. Scripts wanting exit-code-only add `> /dev/null` themselves.
3. **Normal shows phase-level progress**, not per-server chatter: a line when
   a phase starts (with counts/parallelism), warnings/failures live as they
   happen, a line when done (with timing). Per-server success detail is
   debug-only — the report already enumerates servers.
4. **Implementation: stdlib `log/slog` + one custom handler** (approach A
   over a bespoke logger or a third-party lib). Internal packages accept a
   standard `*slog.Logger` — no bespoke interface; a future
   `--log-format=json` is a handler swap; no new supply-chain dependency in a
   security-sensitive tool. Only `golang.org/x/term` is added (first-party;
   `x/sys` is already in the tree via `x/crypto`).

## CLI surface & mode semantics

Persistent flags on the root command (inherited by all subcommands):

- `-v, --verbose` — debug mode ("enable debug logging").
- `-q, --quiet` — errors only on stderr; product untouched.
- `--color auto|always|never` — default `auto`. `always` serves
  `audit --color=always | less -R`; `never` serves strict environments.
- `-v` with `-q` is an error (`MarkFlagsMutuallyExclusive`).

Mode → `slog` level cutoff:

| Mode          | stderr shows                                         |
| ------------- | ---------------------------------------------------- |
| quiet (`-q`)  | ERROR only                                           |
| normal        | INFO + WARN + ERROR (phase progress, live failures)  |
| debug (`-v`)  | DEBUG too, plus timestamps and `key=value` attrs     |

**Per-stream color decision.** Color is decided independently for stderr
(logs) and stdout (report): `sshepherd audit > report.txt` writes a plain
report while the terminal still shows colored logs. Under `auto`, a stream
gets color only when all hold: it is a real TTY
(`golang.org/x/term.IsTerminal`), `NO_COLOR` is unset or empty
(no-color.org), and `TERM != "dumb"`. `--color=always/never` overrides
everything. Escape codes are applied at render time by the handler — degraded
output is genuinely plain text, never stripped text.

**Fatal-error line.** `run()`'s final `sshepherd: <err>` prints in all modes,
quiet included, with a red `error:` prefix when stderr color is on.

## Architecture & wiring

**New package `internal/clog`:**

- `Handler` — custom `slog.Handler` rendering human-friendly lines.
  Normal mode: calm lines (`• message`, `warn: message`). Debug mode: dim
  `HH:MM:SS.mmm` timestamp + colored level word + message + `key=value`
  attrs. A mutex serializes writes so concurrent per-server logs interleave
  line-atomically. Only the used slice of the `Handler` contract is
  implemented; `WithGroup` passes through (groups unused).
- `ColorMode` (`auto|always|never`) and `Detect(f *os.File, mode ColorMode)
  bool` — the TTY/`NO_COLOR`/`TERM=dumb`/override decision in one testable
  function.

**Cmd wiring.** `newRootCmd` gains a small `app` state struct. A
`PersistentPreRunE` (after flag parse, before any subcommand) builds
`*slog.Logger` → `clog.Handler` → the injected stderr writer, and computes
the stdout color flag for renderers. `run()` uses the logger for the final
error line when it exists; flag-parse failures that die before
`PersistentPreRunE` fall back to an uncolored handler-rendered `error:` line —
plain is always safe, and an explicit `--color` choice cannot be known before
parsing succeeds. Tests keep passing
buffers exactly as now — color detects false on a buffer; tests can force it
with `--color=always`.

**Logger injection (explicit, matching the codebase's explicit seams):**

- `sshread.Client.Log *slog.Logger` — nil-safe (defaults to discard). DEBUG
  at each SSH stage: dial start/ok with duration, host key verified, agent
  auth ok, remote command exit status, bytes read. Bug fix included:
  `cappedBuffer` truncation at 1 MiB is currently silent — it becomes WARN.
- `audit.Options.Logger *slog.Logger` — per-server done at DEBUG with
  duration; per-server failure at WARN the moment it happens (live).
- Phase-level INFO lives in the cmd layer (workflow narration, not package
  behavior): `loaded manifest: 4 users, 12 servers` → `auditing 12 servers
  (parallelism 10)…` → `done in 2.3s — 11 read, 1 unreachable`. Analogous
  phases for `import` (parsed hosts, derived users) and `adopt` (fleet read,
  N new users / M extensions).

**Migration of existing ad-hoc stderr prints:** adopt's `warning:` lines →
WARN; its strict-mode per-server `error:` lines → ERROR; the
"nothing to adopt" note → INFO (consequence: hidden under `-q`, consistent
with quiet's meaning). Wording unchanged.

## Report coloring

`audit.Render(w, cfg, results, RenderOptions{Color: bool})`. Color off →
byte-identical to today. Color on: green `✓`, red `✗`, bold-red `‼` with bold
`CRITICAL`, yellow `⚠`, red `ERROR` on unreachable-server heads. Glyphs and
key words only — fingerprints, counts, and notes stay plain.

**tabwriter pitfall.** `text/tabwriter` counts runes (ANSI-unaware) for
column widths; ANSI escapes inside a cell inflate its apparent width and
wreck alignment. Fix: every variant appearing in the same column uses SGR
sequences of equal length (pad e.g. `\x1b[0;32m` vs `\x1b[1;31m` — pure
ASCII, so bytes == runes), so invisible characters are identical per column
and alignment holds. Golden tests pin this.

## Security & robustness

- The handler sanitizes every rendered message and attr value — newlines and
  tabs become a single space, all other control characters (C0, DEL, C1) are
  stripped — so a hostile server name or remote error string cannot forge log
  lines or inject terminal escapes. Defense-in-depth behind `sshread.sanitizeRemote`, protecting
  future call sites that forget to sanitize. Invalid UTF-8 bytes are rewritten
  to U+FFFD (never passed through raw — a lone 0x9B is CSI on 8-bit terminals).
  Unicode format characters (Cf: bidi overrides, zero-width) are deliberately
  out of scope: the boundary strips control characters only, and stripping Cf
  would corrupt legitimate international text; revisit if log spoofing via
  bidi becomes a concern.
- The handler sanitizer joins the `make fuzz` set.
- Handler is race-safe (mutex); the audit fan-out exercises it under `-race`.

## Testing

- `internal/clog`: table-driven handler tests (level × color × attrs), golden
  output, sanitizer fuzz, color-detection matrix (`NO_COLOR`, `TERM=dumb`,
  non-TTY pipe, always/never overrides), `goleak` TestMain.
- `internal/audit`: existing report goldens unchanged (color off) + colored
  goldens; ANSI-vs-tabwriter alignment pinned.
- `cmd/sshepherd`: through `run()` — `-q` hides INFO but errors surface; `-v`
  emits DEBUG lines; `-v -q` errors cleanly; `--color=never` yields plain
  bytes.
- E2E flows unchanged — default output stays stable for scripts (color
  auto-disables in pipes).

## Out of scope

- JSON/structured log output (`--log-format`) — enabled later by a handler
  swap if ever needed.
- Progress bars/spinners; log files; syslog.
- Coloring `import`/`adopt` manifest output (explicitly never).

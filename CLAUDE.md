# SSHepherd

## What this project is for

SSHepherd is a tool for **managing SSH access across a fleet of servers**. The
goal is a single source of truth for SSH keys: define who should have access to
which machines in one place, and SSHepherd keeps every server's
`authorized_keys` in sync — adding new keys, revoking old ones, and rotating
credentials without hand-editing files or losing track of who can log in where.

## The problem it solves

Managing SSH keys by hand across many servers is error-prone and hard to audit.
You end up SSH-ing into each box to edit `authorized_keys`, you lose track of who
has access to what, and revoking a departed user's access reliably is painful.
SSHepherd centralizes and automates this.

## Core capabilities (intended)

- **Central source of truth** — declare users, keys, and which servers they may access.
- **Distribute** — push the correct `authorized_keys` to every server in the fleet.
- **Revoke** — remove keys everywhere in one command (e.g. offboarding).
- **Rotate** — replace/rotate keys on a schedule.
- **Audit** — answer "who can log into which server?" at any time.

## Design intent

- Single-binary CLI, agentless where possible (manage the SSH keys that already exist;
  don't require installing a daemon on every box).
- **Language:** Go (decided — `go.mod` targets Go 1.27.3; moved from 1.26 on 2026-11-07 for the crypto/x509 CVE fix and the longer support window).
- **SSH transport:** native `golang.org/x/crypto/ssh` (decided 2026-07) — no dependency on a
  host `ssh` binary; host-key verification via `x/crypto/ssh/knownhosts`, strict (no TOFU).
- **Config format / CLI:** YAML source of truth (`gopkg.in/yaml.v3`); Cobra for subcommands.

## How to work (agents)

**Use workflows and subagents whenever the task fits them** — this is standing
opt-in from the owner; don't ask first. Fits: whole-repo reviews, research
across several packages, multi-package fixes/slices with disjoint file
ownership, and adversarial verification of findings or specs. Shape that has
worked here: scout inline → fan out by package (disjoint files, no commits
from agents) → one integrator runs `make check` + `make integration` and
updates README/spec/Status → an independent verifier → a repair pass. Stay
solo for conversational turns, single-file edits, and owner-decision points
(brainstorm questions, spec approval), which are never delegated.

## README (always keep it current)

`README.md` is the project's user-facing front door. **Always keep it updated** —
treat it like the test suite: a change that makes it stale is an incomplete change.
Update it *in the same commit* as the work, never as a follow-up.

Update the README whenever any of these change:

- **Commands and flags** — a new subcommand, a new/renamed/removed flag, or a changed
  default. The command tables list every flag with its default; they must match
  `--help` exactly.
- **Manifest schema** — new or changed fields in `internal/config` (users, servers,
  access), validation rules, or semantics like `operator:`, `servers: ["*"]`/`except:`,
  `authorized_keys_file`, and the comment policy.
- **Exit codes** and their meanings.
- **Behavior a user must be able to predict before running a write** — the full-file
  rewrite contract, refusal classes, the self-lockout guard, backup/atomicity/verify,
  the confirmation gate, connection posture (agent and/or `--identity` key-file auth, strict `known_hosts`).
- **Status** — the implemented-slice table, when a slice lands.
- **Make targets, install paths, container usage, repo layout.**

Rules for the content:

- **Sample output must be real.** Copy it from the golden fixtures
  (`internal/*/testdata/*.golden`) or actual command output — never hand-write or
  "tidy" a report, plan, or prompt string. When a renderer changes, its goldens
  change; re-copy them.
- Keep the README a *user* document. Design rationale belongs in
  `docs/superpowers/specs/`; link there rather than inlining it.
- Keep it in sync with the Status section below — the two must never disagree.

## Code quality & checks (Go)

Every check below must pass before commit and in CI. They apply once Go code lands
(`go.mod` + packages). Wire them into a single `make check` target so local and CI
run the exact same commands. Target **Go 1.27.3** (go.mod). Listed cheapest-to-run first.

### Formatting
- `gofmt -l ./...` — must print nothing (fail if it lists any file).
- `goimports -l ./...` (`golang.org/x/tools/cmd/goimports`) — formatting + import grouping.

### Vet / correctness (value check)
- `go vet ./...` and `go vet -tags=integration ./...` — catches printf mismatches, unreachable code, bad struct tags, etc., in the plain build and in the `//go:build integration` real-sshd/E2E test files.
- Bundles the `loopclosure` analyzer — flags loop variables captured by goroutines/closures.

### Loop safety
- Go 1.22+ makes loop variables per-iteration, removing the classic capture footgun; still
  lint for the remaining pitfalls.
- `golangci-lint` linters `copyloopvar` and `exportloopref` — range/loop-variable aliasing.
- `go test -race ./...` — race detector; surfaces loop/goroutine data races at test time.

### Static analysis / lint (code quality)
- `golangci-lint run` — aggregated meta-linter. Baseline enabled set:
  `staticcheck`, `govet`, `errcheck`, `ineffassign`, `unused`, `gosimple`, `revive`,
  `misspell`, `bodyclose`, `nilerr`, `gocritic`.
- Error & context correctness: `errorlint` (proper `%w` wrapping), `wrapcheck` (wrap errors
  at package boundaries), `contextcheck` + `noctx` (don't drop `context.Context`).
- Complexity & imports: `gocyclo`/`cyclop` (cap function complexity), `dupl` (copy-paste),
  `depguard` — pin crypto/SSH deps (e.g. force `golang.org/x/crypto/ssh`, ban risky packages).
- Dead code: `deadcode ./cmd/sshepherd` (`golang.org/x/tools/cmd/deadcode`) — whole-program
  reachability from `main`; fails `make check` on unreachable functions. Complements the
  per-package `unused` linter, which can't see cross-package dead exported identifiers.
- Optional but recommended: `gofumpt` (stricter gofmt) and `nilaway` (Uber's nil-panic
  static analysis — experimental, run as a separate step).
- Pin the `golangci-lint` version and commit `.golangci.yml` so results are reproducible.
- `.golangci.yml` sets `run.build-tags: [integration]`, so `golangci-lint run` also type-checks and lints the integration-tagged test files.

### Security (SAST + vulnerabilities)
- `gosec -tags=integration ./...` — SAST for insecure patterns (integration-tagged files included). High-value here: this tool writes
  `authorized_keys`, sets file permissions, and shells out to SSH — gosec flags weak file
  perms (G302/G306), command injection (G204), and weak crypto.
- `govulncheck ./...` — official Go vulnerability scanner. Reachability-aware: only reports
  CVEs in deps/std-lib that your code actually calls, so few false positives. Run in CI.
- `gitleaks detect --no-git` (and as a pre-commit hook) — this repo handles SSH keys; block
  private keys, tokens, or secrets from ever being committed.

### Dependency & supply chain
- `go mod tidy` then fail CI if it dirties the tree: `git diff --exit-code go.mod go.sum`.
- `go mod verify` — module contents match recorded checksums.
- `go-licenses check ./...` — dependency licenses stay compatible with Apache-2.0.
- SBOM per release: `cyclonedx-gomod mod` (or `syft`) — archive the artifact for provenance.
- Automate updates with Dependabot/Renovate, and run `govulncheck` on a daily CI schedule
  (not just on PRs) to catch newly disclosed CVEs in pinned deps.

### Build & tests
- `go build ./...`, plus a reproducible static single binary for releases:
  `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"`.
- Tests and coverage are mandatory and have their own policy — see **Testing** below.
- **Toolchain lockstep** — go.mod's `go` line, the Dockerfile build stage tag and the Makefile's
  `GO_PIN` name the same Go patch release. Go bump procedure: bump go.mod, the Dockerfile and
  `GO_PIN` together in one commit (on the Dependabot `golang` PR's branch, or by hand).

### CI
- One `make check` (or `Taskfile`) target running all of the above; CI invokes the same target.
  Install tool versions via `go install ...@<pinned>` or a `tools.go`.
- Local hooks run the fast subset before code leaves the machine (see `lefthook.yml`, installed
  via `make hooks`): pre-commit runs `gofmt` + `gitleaks --staged`; pre-push runs `go vet`,
  `golangci-lint`, and `go test -race`. The full suite still runs in CI.

## Testing

Every package ships with tests and the suite must stay green. The project maintains
**all kinds of tests** — not just unit tests — and **always produces a coverage report**.
New features and bugfixes land with the tests that cover them; a fix for a bug includes a
test that fails before the fix and passes after.

### Test kinds (all required, kept current)
- **Unit** — table-driven, fast, hermetic; the default for every package. No real network/disk.
- **Integration** — exercise real `authorized_keys` files and a real `sshd` (dockerized or a
  throwaway container); guard behind a build tag (e.g. `//go:build integration`) so the unit
  path stays fast.
- **End-to-end (E2E)** — drive the actual CLI binary through full flows
  (distribute → audit → revoke → rotate) against a small fleet of test containers.
- **Fuzz** — native `go test -fuzz` on all parsers (`authorized_keys`, SSH public keys); keep a
  seed corpus in the repo and run fuzzing in CI on a schedule (prime crash/injection surface).
- **Benchmarks** — `go test -bench=. -benchmem` for hot paths (fan-out to many servers); watch
  for regressions.
- **Race** — run the suite with `-race`.
- **Goroutine leaks** — `go.uber.org/goleak` via a `TestMain` in every test package;
  a package's tests fail if any goroutine outlives the run.
- **Golden** — snapshot the generated `authorized_keys` output so format changes are explicit.

### Coverage report (always produced)
- Generate a profile every run:
  `go test -race -covermode=atomic -coverprofile=coverage.out ./...`.
- Human-readable views: `go tool cover -func=coverage.out` (per-func summary) and
  `go tool cover -html=coverage.out -o coverage.html` (annotated source).
- CI **uploads `coverage.out` / `coverage.html` as an artifact** and **fails below the 80%
  line-coverage minimum** (best-practice gate, enforced by `make coverage` via `COVERAGE_MIN`;
  ratchet upward over time). Never let coverage silently drop.

## Container image

Ship a first-class Docker image: **minimal — the static binary on a distroless base**, nothing
else. Multi-stage build, non-root, no shell. (Decided 2026-11-07: the native
`golang.org/x/crypto/ssh` transport needs no `ssh`/`ssh-keygen`/`ssh-keyscan` in the image, so
the earlier Alpine + openssh-client + tini image was replaced.)

### Build
- **Multi-stage**: a `golang:<ver>-alpine` build stage **on `$BUILDPLATFORM`** (pinned by digest,
  `GOTOOLCHAIN=local`) cross-compiles the static binary with `GOOS=$TARGETOS GOARCH=$TARGETARCH`
  (`CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"`; no QEMU at build time — keep the runtime
  stage free of `RUN`); the runtime stage copies only the binary.
- **Base**: `gcr.io/distroless/static-debian13:nonroot`, pinned by its multi-arch index digest —
  TLS roots, tzdata and a passwd entry for uid 65532 (`nonroot`, HOME `/home/nonroot`); no
  shell, no package manager, no ssh tools (users run `ssh-keygen`/`ssh-keyscan` on the host).
- **No init**: sshepherd is PID 1 and handles SIGINT/SIGTERM itself — the first signal cancels,
  a second exits explicitly with 128+signo (`watchSignals`), because the kernel ignores default
  signal actions for PID 1. `scripts/docker-gates.sh` proves it against the built image.
- **Hardening**: run as a **non-root** user (e.g. UID 65532), compatible with a read-only
  rootfs, no secrets baked into layers, `ENTRYPOINT` = the binary. Pin every base image by digest.
- **Multi-arch**: build `linux/amd64` + `linux/arm64` once with `docker buildx`; gate each variant
  with `scripts/docker-gates.sh --platform OS/ARCH`.

### Docker checks (all in CI)
- **hadolint** — lint the `Dockerfile` for best-practice violations.
- **Trivy** — `trivy image` scans the built image for OS + Go-dependency CVEs (fail on
  HIGH/CRITICAL); `trivy config` lints the `Dockerfile` for misconfiguration.
- **dockle** — image linter / CIS checks (non-root, no setuid surprises, no leaked secrets).
- **Architecture gate** — the binary's ELF machine must match the image platform (`docker-gates.sh`).
- **Smoke test** — `docker run --rm <image> --version` (and `--help`) must succeed.
- **Size & user gates** — assert the final image stays under a budget (e.g. < 30 MB) and does
  not run as root.
- **PID-1 signal gate** — two SIGTERMs to a blocked container must stop it with exit 143.
- **Provenance** — generate an image SBOM (`syft <image>` or `buildx --sbom`), attach build
  provenance/attestations, and sign the image with `cosign`. Keep base images fresh via
  Dependabot/Renovate.

## License

Apache License 2.0 (permissive + explicit patent grant — chosen for broad adoption,
including corporate use, while protecting contributors and users).

## Status

Early development. In place: a user-facing `README.md` covering install, the manifest
schema, every command and flag, exit codes, and the write-path safety model (keep it
current — see the README section above); full quality/security/container scaffold
(Makefile, golangci, CI, lefthook, Dockerfile), a CLI skeleton, and
`internal/authkeys` (single-line
`authorized_keys` parser). Four vertical slices are implemented: read-only drift
**`audit`** (specced in `docs/superpowers/specs/2026-07-06-audit-slice-design.md`) and
**`import`** — an OpenSSH client config → manifest converter built on `internal/sshcfg`
(specced in `docs/superpowers/specs/2026-07-09-import-ssh-config-design.md`), which also
derives `users:`/`access:` from `IdentityFile` `.pub` files via `internal/identity`
(specced in `docs/superpowers/specs/2026-07-09-import-identityfile-users-design.md`).
The manifest supports **operator users** (`operator: true` — fleet-wide,
protected management keys) and **wildcard access** (`servers: ["*"]` with
`except:`); audit renders missing operator keys as CRITICAL, and
`import --operator <key>` marks them at import time (specced in
`docs/superpowers/specs/2026-07-10-operator-users-wildcard-access-design.md`).
The third, **`adopt`**, reads every server's actual `authorized_keys`
through the audit pipeline and generates a complete manifest — unknown keys
become users, known users' keys found beyond their grants extend access
(specced in `docs/superpowers/specs/2026-07-10-adopt-fleet-discovery-design.md`).
CLI-wide leveled logging is in place: `-v/--verbose`, `-q/--quiet`, and
`--color auto|always|never` on the root command, phase-level progress at
normal verbosity, per-SSH-stage detail at debug, and a colorized audit
report — all degrading to plain text on non-TTY/`NO_COLOR`/`TERM=dumb`
(specced in `docs/superpowers/specs/2026-07-10-logging-verbosity-color-design.md`).
Audit is scriptable: `--json` emits a machine-readable report (schema 1)
and exit codes are monitoring-style — 0 compliant, 1 drift/unreachable,
2 critical drift, 3 tool error (specced in
`docs/superpowers/specs/2026-07-16-audit-json-exit-codes-design.md`).
Servers may set `authorized_keys_file` to override the audited path
(absolute or `~/`-relative; injection-safe via validation + POSIX
single-quote escaping; specced in
`docs/superpowers/specs/2026-07-16-authorized-keys-file-override-design.md`),
and fleet-scale fan-out benchmarks (`make bench`) back the
`--parallel`/timeout tuning question with data.
The write-time comment policy is decided (`comment` → inline → `name`;
`config.DesiredComment`), manifests warn on multi-key `comment:`, and
`audit --comments` opt-in reports comment drift, informational only
(decided in `docs/superpowers/specs/2026-07-16-comment-policy-memo.md`).
`adopt --merge` appends discoveries to an existing manifest while
preserving its comments via the new `internal/manifest` package
(specced in `docs/superpowers/specs/2026-07-16-adopt-merge-design.md`).
`import --merge FILE` (merge slice 2) reconciles a fresh ssh-config
conversion against an existing manifest via the new pure
`internal/reconcile` package — strictly additive, manifest-wins conflicts
with loud warnings, fingerprint-first user identity, adopt-style access
extensions for known keys, byte-identical no-op re-runs (specced in
`docs/superpowers/specs/2026-07-19-import-merge-design.md`; exposes
`config.Covers`/`config.ExceptCarveOut` and a servers append on
`internal/manifest`). The `--parallel` default is 32, tuned from the
fan-out benchmarks (Tuning resolution in the audit spec, 2026-07-19).
The fourth slice, **`apply`**, is the first write path: full-file render
of each server's `authorized_keys` from the manifest (comment policy via
`config.DesiredComment`, managed header, operators first), two-phase
plan → confirm (TTY prompt / `--yes` / `--dry-run`) → write, byte-exact
convergence, and a self-lockout guard that refuses any write leaving no
held key (agent or `--identity`) on a server. Writes are atomic (remote temp + rename,
`umask 077`, noclobber), preceded by a `.sshepherd.bak` backup and
followed by an in-session verify re-read; symlinked targets and
unparseable files are refused. Built on the extracted `internal/sshconn`
(shared connection glue + session-key recorder), `internal/sshwrite`
(remote write protocol), and `internal/apply` (pure plan/guard/report),
with a dockerized integration matrix and the first full E2E loop
(adopt → apply → audit) — specced in
`docs/superpowers/specs/2026-07-19-apply-slice-design.md`, planned in
`docs/superpowers/plans/2026-07-19-apply-slice.md`. `revoke`/`rotate`
then landed as their own commands on top of it (below).
A whole-repo **review-hardening pass** (53 findings, specced in
`docs/superpowers/specs/2026-10-16-review-hardening-design.md`) then landed:
apply's write is one guarded remote script per server (symlink/ownership
refusal plus a StrictModes-style ancestor walk, `mkdir` lock, compare-and-swap
against the plan snapshot via length + POSIX `cksum`, `.bak` + one-time `.orig`
backups, length-checked upload before `mv`), followed by verify, moving a
non-empty `~/.ssh/authorized_keys2` aside, and a fresh login probe offering only
the surviving held keys that must run a probe command (catching forced
`command=`) — a failed probe restores the previous file under a fresh lock and
compare-and-swap; the guard ignores `cert-authority`/`principals=` lines and
re-runs after the prompt; option loosening is highlighted; Ctrl-C stops new
writes while started ones finish, and an interrupt before any write (or during
audit/adopt) exits 3 with nothing rendered or written.
Audit gains options-drift, duplicate-entry and unmanaged `authorized_keys2`
drift classes, classified `error_kind`s, and exit 2 for changed/`@revoked`
host keys. Transport: context cancellation, `exec /bin/sh -c` for any login
shell, host-key algorithms ordered from `known_hosts`, granted keys offered
first, `known_hosts` parsed once, and the hermetic `internal/sshconn/sshtest`
server. The manifest is stricter (single document, OpenSSH option allow-list,
type/blob match, no whitespace/control runes in server fields, one entry per
remote target, no empty grants, no `%`/trailing `/` in
`authorized_keys_file`); import matches `ssh -G` more closely (Include context,
trailing `#`, HostName/IdentityFile tokens, `.pub` identities, same-target
collapse, proxy warnings) with shared naming in `internal/naming`. Tooling is
pinned (tools, actions by SHA, images by digest), `make check` ends in the
coverage gate, CI runs daily vuln/fuzz, and tagged releases publish a signed
multi-arch image.
**Key-file authentication** (specced in
`docs/superpowers/specs/2026-10-16-identity-keyfile-auth-design.md`, planned in
`docs/superpowers/plans/2026-10-16-identity-keyfile-auth.md`): `audit`,
`adopt` and `apply` take repeatable `--identity PATH` plus
`--identity-passphrase-file FILE` / `--identity-passphrase KEY=FILE`
(TTY prompt as the last resort; no passphrase env var or flag value), in union
with the agent (agent optional once a key file is given). The new
`internal/keyfile` does the OpenSSH permission rule on the opened descriptor
(pipes exempt), container classification before any prompt, read-once
passphrase files and a foreground-only `/dev/tty` prompter; `sshconn.Credentials`
is the run's one credential source (`Signers` before the dial, `Held` with
sources, certificates offered but never held); `sshread.CheckCredentials`
replaces the agent preflight. apply's guard, survivor order (key files before
agent keys) and probe reason over every held key, refusals list each key with
its source, and an agent-only-survivor warning flags a stray agent satisfying
the guard for a headless run. Headless rotation (old + new `--identity`) is
covered end to end by the integration suite.
**`revoke` and `rotate`** (specced in
`docs/superpowers/specs/2026-10-23-revoke-rotate-design.md`, planned in
`docs/superpowers/plans/2026-10-23-revoke-rotate.md`): `revoke USER...`,
`revoke --key KEY...` and `rotate USER --old KEY --new KEY` edit the manifest
comment-preservingly (`internal/manifest` gains `RemoveUser`/`RemoveKey`/
`ReplaceKey`/`SetOperator`) and push the edit through apply's pipeline over the
affected servers only (`apply.Affected`, a rendered-bytes diff; sole-grantee
servers are warned, never emptied). KEY is a SHA256 fingerprint, a key line or a
`.pub` path (MD5, certificates and private keys refused; errors never quote file
contents). Operator targets need `--operator`. The edit is always confirmed and
saved once — after the prompt, before the first write — under a flock sidecar
with a compare-and-swap and an atomic rename keeping mode and owner; `--dry-run`
saves nothing, `--no-apply` saves without connecting. Apply's run body is now
`runApply(applyRun)`, and plain `apply` re-checks the manifest before writing
(skipped for a piped `--config`, which edits refuse).
Report count strings are pluralized. The E2E loop is adopt → apply → revoke
--key → audit → rotate → audit, plus a headless `rotate`.
`apply`, `revoke` and `rotate` take `--json` (needs `--dry-run` or `--yes`): one
schema-1 document with plan, per-server outcome and the manifest edit, written
exactly when the run exits 0 or 1 (specced in
`docs/superpowers/specs/2026-11-07-apply-json-design.md`); remote text in both JSON
reports passes through the new `internal/sanitize` leaf.
**`revoke --server` and `rotate --keep-old`** (specced in
`docs/superpowers/specs/2026-11-07-revoke-server-keep-old-design.md`, planned in
`docs/superpowers/plans/2026-11-07-revoke-server-keep-old.md`): `revoke USER... --server NAME...`
trims per-server access through the new comment-preserving `manifest.RemoveAccess`
(explicit items removed, wildcards gain `except:`, emptied entries and wildcards left
covering no server deleted with a warning; operators, `--key`, `'*'`, unknown servers
and ungranted pairs refused, all problems listed at once), and `rotate --keep-old`
overlaps the old and new keys via `manifest.AddKeyAfter` (options and `expiry-time=`
carried) and prints the `revoke --key OLD` that finishes the overlap. The save
reminder's tail is per edit kind; JSON gains the `remove-access` edit kind and
`keep_old` on rotate entries (schema stays 1). The E2E suite adds a `revoke --server`
run and a keep-old overlap → finish loop.
The gates also cover the `//go:build integration` files: `make vet` runs `go vet`
plain and with `-tags=integration`, `gosec` runs with `-tags=integration`, and
`.golangci.yml` sets `run.build-tags: [integration]` (review remediation P13-0,
OPS-7; plan in `docs/superpowers/plans/2026-11-07-review-remediation.md`).
The write script's owner checks are pinned by real-sshd ownership fixtures
(root-owned `~/.ssh` and `authorized_keys`, a `nobody`-owned override ancestor, root
writing into another user's file), and the login probe is proven against real sshd
(forced `command=`, unmatched `from=`, and a `restrict` negative control); the
sshwrite integration package runs shuffled and twice with each test reseeding its own
user, and the throwaway sshd sets `PerSourcePenalties no` because those tests fail
logins on purpose (review remediation P03 lane B, TST-1).
`--help` is snapshot-tested (`cmd/sshepherd/testdata/help/*.golden`); bool flags
render without pflag v1.1.0's `[=true|false]` via `cmd/sshepherd/usage.go`, and the
README flag tables (global flags included) are checked against `--help`, defaults
included (review remediation P01).
The image build cross-compiles on `$BUILDPLATFORM` (no QEMU at build time), and
`scripts/docker-gates.sh [--platform OS/ARCH] [--pull] [IMAGE]` gates one variant of
any local or registry image, starting with an ELF-architecture check (review
remediation P02 lane A, OPS-4).

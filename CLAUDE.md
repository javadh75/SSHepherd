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
- **Audit** — check that every managed `authorized_keys` file holds exactly the
  manifest's keys; other accounts and sshd's other key sources are not seen (a
  deeper opt-in check is a later slice).

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
- `gosec -tags=integration ./...` — SAST for insecure patterns in the non-test code (gosec skips `_test.go` files). `make gosec` also runs golangci-lint's gosec (`golangci-lint run --enable-only=gosec`) over the `//go:build integration` test files, which must be named `*integration_test.go` or `*e2e_test.go`. That run is scoped and triaged in `.golangci.yml`. The target fails if gosec cannot type-check the code (rebuild it with `make tools`). High-value here: this tool writes
  `authorized_keys`, sets file permissions, and shells out to SSH — gosec flags weak file
  perms (G302/G306), command injection (G204), and weak crypto.
- `govulncheck ./...` — official Go vulnerability scanner. Reachability-aware: only reports
  CVEs in deps/std-lib that your code actually calls, so few false positives. Run in CI.
- `gitleaks dir --redact .` (working tree, `make secrets`, in `make check`) + `gitleaks git`
  over the pushed range (`make secrets-history BASE=<sha>`: CI's `go` job scans the pushed
  commits, release.yml's `check` job the full history) + `--staged` pre-commit — this
  repo handles SSH keys; block private keys, tokens, or secrets from ever being committed.

### Dependency & supply chain
- `go mod tidy` then fail CI if it dirties the tree: `git diff --exit-code go.mod go.sum`.
- `go mod verify` — module contents match recorded checksums.
- `go-licenses check --disallowed_types=forbidden,restricted,unknown ./cmd/sshepherd`
  (`make licenses`, in `make check`; pinned `GOLICENSES_VERSION` v2.0.1) — dependency
  licenses stay compatible with Apache-2.0.
- SBOM per release: `cyclonedx-gomod mod` (or `syft`) — archive the artifact for provenance.
- Automate updates with Dependabot/Renovate, and run `govulncheck` on a daily CI schedule
  (not just on PRs) to catch newly disclosed CVEs in pinned deps.

### Build & tests
- `go build ./...`, plus a reproducible static single binary for releases:
  `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"`. `make build`/`make dist` stamp
  `-X main.version=$(VERSION)`; `resolveVersion` (cmd/sshepherd/run.go) falls back to
  `debug.ReadBuildInfo().Main.Version`, so `go install …@vX` reports vX.
- Tool pins: the Makefile pins every Go dev tool (`make tools` installs them), including
  `GOLICENSES_VERSION` v2.0.1 and `ACTIONLINT_VERSION` v1.7.12; `BENCHSTAT_VERSION` is used
  with `go run` in CI. `make -s print-<VAR>` reads a pin back. `make actionlint`
  (`-shellcheck=""`) lints the workflows; it is not part of `make check`.
- Tests and coverage are mandatory and have their own policy — see **Testing** below.
- **Toolchain lockstep** — go.mod's `go` line, the Dockerfile build stage tag, the Makefile's
  `GO_PIN` and CI's `setup-go` (`go-version-file: go.mod`) name the same Go patch release; CI
  and release fail otherwise (the "Go toolchain matches the image build stage" step in ci.yml
  `go` and release.yml `check`). Go bump procedure: bump go.mod, the Dockerfile and `GO_PIN`
  together in one commit (on the Dependabot `golang` PR's branch, or by hand).

### CI
- One `make check` (or `Taskfile`) target running all of the above; CI invokes the same target.
  Install tool versions via `go install ...@<pinned>` or a `tools.go`.
- Local hooks run the fast subset before code leaves the machine (see `lefthook.yml`, installed
  via `make hooks`): pre-commit runs `gofmt` + `gitleaks --staged`; pre-push runs `go vet`,
  `golangci-lint`, and `go test -race`. The full suite still runs in CI.
- Required checks, if ever added, name only `ci-ok` (it needs `go`, `docker` and `integration`).
- release.yml publishes only a `vX.Y.Z` tag on master after `check`, `integration`, `image` and
  `gate` pass. Dependabot has a 7-day cooldown (security updates are immediate); its docker
  groups are `golang` (red until go.mod and `GO_PIN` are bumped on the same PR) and
  `runtime-and-ci-images`.

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
  `scripts/integration.sh [alpine|debian|rocky]` (`make integration IT_DISTRO=…`) builds
  `ci/images/sshd-<distro>.Dockerfile` and starts two sshd containers (A: every fixture user;
  B: a custom `AuthorizedKeysFile`) on dynamic ports with unique names. The CI and release
  `integration` jobs are an alpine/debian/rocky matrix.
- **End-to-end (E2E)** — drive the actual CLI binary through full flows
  (distribute → audit → revoke → rotate) against a small fleet of test containers.
  `TestE2EFleetFanOut` drives apply and audit across both containers. It checks the per-host
  `known_hosts` (a swapped host key exits 2 with `host_key_changed`) and B's
  `authorized_keys_file` override.
- **Fuzz** — native `go test -fuzz` on all parsers (`authorized_keys`, SSH public keys); keep a
  seed corpus in the repo and run fuzzing in CI on a schedule (prime crash/injection surface).
  `make fuzz` discovers every `Fuzz*` target (`make fuzz-list`, via `go test -list '^Fuzz'`),
  anchors each `-fuzz=^Target$`, runs all of them even after a failure, and fails if any
  failed; `FUZZTIME` defaults to 15s. The scheduled CI job runs `make fuzz FUZZTIME=2m`
  (90-minute timeout) and restores/saves `$(go env GOCACHE)/fuzz` through actions/cache
  restore/save, keyed per run, so the corpus survives even a crash.
  Every fuzz target has a committed seed corpus under `<pkg>/testdata/fuzz/<Target>/`
  (at most 16 entries of 4 KiB or less per target), and those entries run as ordinary
  test cases on every `go test`. `FuzzWriteCmds` never executes a write script: it
  checks that the target path enters each script only through its leading
  `sshconn.PathAssign` token (the rest is byte-identical to the script built for a
  reference path), and that `PathAssign` evaluated by `/bin/sh` with `HOME=/h` prints
  exactly that path.
- **Benchmarks** — `go test -bench=. -benchmem` for hot paths (fan-out to many servers); watch
  for regressions. An informational `bench` job on push/PR posts benchstat base->head to the
  job summary; it fails only if the head benchmarks fail, and it is not in `ci-ok`.
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
  The smoke enforces it: `--version`/`--help`/PID-1 runs use `--read-only --cap-drop ALL
  --security-opt no-new-privileges`.
- **Pins**: every container image is pinned by digest in a Dockerfile (the release image in
  `Dockerfile`, the scanners and sshd test images in `ci/images/`); Dependabot's docker
  ecosystem covers `directories: ["/", "/ci/images"]` (the sshd test images: alpine 3.24.2,
  debian 13.6-slim, rocky 10.2). Go tools are pinned in the Makefile and bumped by hand.
- **Multi-arch**: build `linux/amd64` + `linux/arm64` once with `docker buildx`; gate each variant
  with `scripts/docker-gates.sh --platform OS/ARCH`.

### Docker checks (CI on both arches, and on every release's pushed digest before it is tagged and signed)
- **hadolint** — lint the `Dockerfile` for best-practice violations.
- **Trivy** — `trivy image` scans the built image for OS + Go-dependency CVEs (fail on
  HIGH/CRITICAL); `trivy config` lints the `Dockerfile` for misconfiguration.
- **dockle** — image linter / CIS checks (non-root, no setuid surprises, no leaked secrets).
- **Architecture gate** — the binary's ELF machine must match the image platform (`docker-gates.sh`).
- **Smoke test** — `docker run --rm <image> --version` (and `--help`) must succeed, hardened
  (read-only rootfs, no capabilities, no-new-privileges).
- **Size & user gates** — assert the final image stays under a budget (e.g. < 30 MB) and does
  not run as root.
- **PID-1 signal gate** — two SIGTERMs to a blocked container must stop it with exit 143.
- **Provenance** — generate an image SBOM (`syft <image>` or `buildx --sbom`), attach build
  provenance/attestations, and sign the image with `cosign`; the verify identity is pinned to
  `release.yml@refs/tags/vX.Y.Z` with trigger `push`. Keep base images fresh via
  Dependabot/Renovate.
- **Release binaries** — the `binaries` matrix (linux/darwin x amd64/arm64, `make dist`,
  `--version` check, `govulncheck -mode=binary` on linux) and `binaries-arm64-run` (native arm64
  execution) feed `release-binaries` (after publish, tag push only; the only job with
  `contents: write`), which writes `SHA256SUMS`, runs cosign `sign-blob` keyless and
  `verify-blob`, then `gh release create`. Exactly two jobs hold `id-token: write`: `publish`
  and `release-binaries`.

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
replaces the agent preflight. apply's guard and probe (production offer order)
reason over every held key, refusals list each key with
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
Count strings in CLI messages are pluralized (three report strings still are not:
audit's `HOST KEY ALERT`, apply's `option(s)` and the guard's `none of the %d keys`);
follow-up hints carry the run's own flags and are paste-ready (double quotes inside
the `'…'`); usage errors print plain `error:` even under `-v`; every command's
`--help` has examples and exit codes; audit, adopt and apply share
one fleet-read setup (`cmd/sshepherd/fleet.go`); a missing manifest points to
`import --servers-only`. The E2E loop is adopt → apply → revoke
--key → audit → rotate → audit, plus a headless `rotate`.
Review remediation W1: authorized_keys option meaning lives in one table
(`internal/authkeys/options.go`) used by manifest validation (a malformed
`expiry-time` now fails the load), apply's loosening highlight (`verify-required`
restricts; added relaxations flagged via `RewriteRow.Widens`), the lockout-guard
warning and rotate's expiry check; it follows sshd's line semantics (a repeated
`command=`/`from=`/`principals=` is rejected; adopt takes each key from its first
line sshd honors and reports a key as a strict/`--partial` issue only when sshd
ignores every one of its lines; a rewrite of a line sshd ignores, or a further
`permitopen=`/`permitlisten=`, is flagged as loosening). sshcfg `Include` skips cycles and caps reads (1024 files,
1 MiB each), and a `ssh -G` differential test checks sshcfg.
Reports name unowned keys by on-server comment/options, connection errors carry
their remediation as a separate `hint` (text: once per distinct hint; JSON:
additive `hint`; adopt's unreadable-server gate likewise prints each distinct
hint once after the per-server lines), a write-phase failure keeps its transport `error_kind`
(a started server cut by the per-server timeout reports `timeout`; `canceled` is
reserved for `pending` servers), apply
JSON's rewrites gain `widens`, and Ctrl-C stops audit's fan-out without dialing
queued servers.
The write-failure semantics spec (P08: login-check failures sorted by stage, exit 2
for an unrestored lockout, self-describing locks (owner, age, hand-removal command;
never removed automatically), interrupts, backup retention; specced in
`docs/superpowers/specs/2026-11-08-write-failure-semantics-design.md`) is drafted
with D9–D10 answered and D10a, D10b and D9c pending, and awaits approval;
implementation is W5+.
The audit trust posture spec (P09: posture probe, operator cannot-log-in critical
tier, `host_key_type_changed`, granted-only key offering with `--offer-all-keys`,
built-in weak/expired key rules via D29; specced in
`docs/superpowers/specs/2026-11-08-audit-trust-posture-design.md`) is drafted with
D14–D19 answered; implementation is W5+ after P14. Audit's claim is narrowed to
the managed `authorized_keys` files (D18).
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
plain and with `-tags=integration`, `.golangci.yml` sets `run.build-tags: [integration]`,
and `make gosec` runs golangci-lint's gosec over those test files (standalone gosec,
pinned at v2.30.0 so it can type-check Go 1.27, skips every `_test.go`; triaged false
positives are `#nosec` lines or source-pinned exclusions) (review remediation P13-0,
OPS-7; plan in `docs/superpowers/plans/2026-11-07-review-remediation.md`).
The write script's owner checks are pinned by real-sshd ownership fixtures
(root-owned `~/.ssh` and `authorized_keys`, a `nobody`-owned override ancestor, root
writing into another user's file), and the login probe is proven against real sshd
(forced `command=`, unmatched `from=`, and a `restrict` negative control); the
sshwrite integration package runs shuffled and twice with each test reseeding its own
user, and the throwaway sshd sets `PerSourcePenalties no` because those tests fail
logins on purpose (review remediation P03 lane B, TST-1). Below that, a unit
matrix pins each of the write script's exit-48 owner checks with one row, run under
sh/dash/bash --posix/busybox through a PATH-stubbed `ls`, plus a committed mutation
self-test (`TestOwnerChecksBite`; a script rewrite updates its `ownerMutants` table,
never deletes the test); `sshtest.ServerConfig.AuthorizedKeysFile` makes the hermetic
server authorize from the written file (re-read per login, honoring `command=` and
`from=`), so the post-write login probe is proven against the bytes a write
installed (review remediation P03 lane A, TST-1/TST-3).
`--help` is snapshot-tested (`cmd/sshepherd/testdata/help/*.golden`); bool flags
render without pflag v1.1.0's `[=true|false]` via `cmd/sshepherd/usage.go`, and the
README flag tables (global flags included) are checked against `--help`, defaults
included (review remediation P01).
The image build cross-compiles on `$BUILDPLATFORM` (no QEMU at build time), and
`scripts/docker-gates.sh [--platform OS/ARCH] [--pull] [IMAGE]` gates one variant of
any local or registry image, starting with an ELF-architecture check (review
remediation P02 lane A, OPS-4).
Releases are gated (tag on master, `make check`, `make integration`, one
cross-compiled multi-arch build gated per arch by digest, then tag/sign/verify, with
signed build provenance), CI checks the shipped Go, gates the image natively on amd64
and arm64 and scans the published image daily, and Dependabot waits 7 days (review
remediation P02 lane B, SEC-6/OPS-1/OPS-2/OPS-3/OPS-4/OPS-6). Every release tag must
point at a commit at or after the release-gating commit `ca50409` (the W0 repair; at
`38c92c0` the publish digest pre-check fails every tag); older commits carry an ungated
or never-publishing release.yml.
Revocation memory (tombstones, manifest serial, opt-in post-revoke sweep, no adopt
wildcard) is specced, awaiting owner decisions, in
`docs/superpowers/specs/2026-11-08-revocation-memory-design.md` (review remediation
P04, PRD-1/PRD-2/SEC-2/SEC-3; implementation in W4).
Review remediation W2. Write-path correctness pass (P11): CAS on a snapshot copy
after the upload with `.bak` = validated bytes, per-file flush of the temp and `.bak`
(never a global `sync`), refusals create nothing (even through `..`), one
`audit.OfferOrder` for every connection and the probe, keys2 on equivalent default
spellings, no-grant + keys2 refused, `sanitize.RemoteSnippet` bounds remote stderr
and handshake/disconnect text. One offer order (`audit.OfferOrder`/`OfferRank`:
plain, then from=/expiry-time=/restrict, then command=, then cert-only; stable in
manifest order) now feeds `GrantedFingerprints` and the post-write probe, so the
probe proves the key the next run logs in with (no `--identity` preference, D31,
WP-5); a no-grant server whose `authorized_keys2` holds keys is refused (exit 1),
agreeing with audit (D30, COR-2).
Manifest store and revoke names (P12): every manifest write goes through
`internal/manifest`'s store (`Store.Save` for revoke/rotate and in-place
`adopt`/`import -o FILE --force`: lock with a no-follow, owner-checked sidecar,
changed-since-read refusal, mode and owner kept; `WriteFile` for new files); fresh
and merged manifests share one encoder from the config types, guarded by a
reflection round-trip test; `revoke NAME` resolves manifest users first;
`adopt --partial` refuses a zero-read fleet (exit 3), exits 1 when some servers
went unread, and reports `read X of N`; a server with only unusable lines is marked
partly read, not unreadable.
CI and gate hygiene (P13, round 1): `make fuzz` discovers every `Fuzz*` target and the
daily CI fuzz keeps its corpus; `make check` adds `go-licenses`, and CI scans each push's
commits with `gitleaks git` (`make secrets-history`); `make build`/`dist` and
`go install …@vX` report a real version; FuzzRemote checks the safety property;
scanner images are pinned in Dependabot-visible `ci/images/*.Dockerfile`; the smoke
runs hardened; an informational `bench` job reports benchstat deltas; and tagged
releases attach signed `linux`/`darwin` `amd64`/`arm64` binaries with `SHA256SUMS`
(D7 = 1).
Fuzz oracles and corpus (P13, round 2): every one of the 19 `Fuzz*` targets has a
committed seed corpus, and `FuzzWriteCmds` proves the target path cannot change its
write script outside the `PathAssign` token.
Distro matrix (P13, round 2): integration and E2E run against two sshd containers on
alpine, debian and rocky (a CI and release matrix).

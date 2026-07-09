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
- **Language:** Go (decided — `go.mod` targets Go 1.26).
- **SSH transport:** native `golang.org/x/crypto/ssh` (decided 2026-07) — no dependency on a
  host `ssh` binary; host-key verification via `x/crypto/ssh/knownhosts`, strict (no TOFU).
- **Config format / CLI:** YAML source of truth (`gopkg.in/yaml.v3`); Cobra for subcommands.

## Code quality & checks (Go)

Every check below must pass before commit and in CI. They apply once Go code lands
(`go.mod` + packages). Wire them into a single `make check` target so local and CI
run the exact same commands. Target **Go 1.22+**. Listed cheapest-to-run first.

### Formatting
- `gofmt -l ./...` — must print nothing (fail if it lists any file).
- `goimports -l ./...` (`golang.org/x/tools/cmd/goimports`) — formatting + import grouping.

### Vet / correctness (value check)
- `go vet ./...` — catches printf mismatches, unreachable code, bad struct tags, etc.
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
- Optional but recommended: `gofumpt` (stricter gofmt) and `nilaway` (Uber's nil-panic
  static analysis — experimental, run as a separate step).
- Pin the `golangci-lint` version and commit `.golangci.yml` so results are reproducible.

### Security (SAST + vulnerabilities)
- `gosec ./...` — SAST for insecure patterns. High-value here: this tool writes
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

Ship a first-class Docker image: **minimal, but carrying the essential runtime tools** — not a
bare `scratch` box. Multi-stage build, non-root, static binary.

### Build
- **Multi-stage**: a `golang:1.26-alpine` build stage (pinned by digest) compiles the static
  binary (`CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"`); the runtime stage starts from a
  minimal base and copies only the binary + certs.
- **Base**: latest stable Alpine, pinned to its minor series (currently `alpine:3.24`; move to a
  digest pin for full reproducibility) — tiny (~7 MB) but ships a shell + `apk`, so the
  essential tools below are present. (The transport decision — native `golang.org/x/crypto/ssh`,
  no `ssh` binary needed — makes the `gcr.io/distroless/static` switch viable for an even
  smaller, shell-less image; do it once `ssh-keygen`/`ssh-keyscan` are also no longer needed
  as in-image conveniences.)
- **Essential tools in the image** — keep this list short, add nothing else:
  `ca-certificates` (TLS to the fleet/registries), `openssh-client` (`ssh`, `ssh-keygen`,
  `ssh-keyscan` for key ops + `known_hosts`), and `tini` as PID 1 for correct signal handling.
- **Hardening**: run as a **non-root** user (e.g. UID 65532), compatible with a read-only
  rootfs, no secrets baked into layers, `ENTRYPOINT` = the binary. Pin every base image by digest.
- **Multi-arch**: build `linux/amd64` + `linux/arm64` with `docker buildx`.

### Docker checks (all in CI)
- **hadolint** — lint the `Dockerfile` for best-practice violations.
- **Trivy** — `trivy image` scans the built image for OS + Go-dependency CVEs (fail on
  HIGH/CRITICAL); `trivy config` lints the `Dockerfile` for misconfiguration.
- **dockle** — image linter / CIS checks (non-root, no setuid surprises, no leaked secrets).
- **Smoke test** — `docker run --rm <image> --version` (and `--help`) must succeed.
- **Size & user gates** — assert the final image stays under a budget (e.g. < 30 MB) and does
  not run as root.
- **Provenance** — generate an image SBOM (`syft <image>` or `buildx --sbom`), attach build
  provenance/attestations, and sign the image with `cosign`. Keep base images fresh via
  Dependabot/Renovate.

## License

Apache License 2.0 (permissive + explicit patent grant — chosen for broad adoption,
including corporate use, while protecting contributors and users).

## Status

Early development. In place: full quality/security/container scaffold (Makefile, golangci,
CI, lefthook, Dockerfile), a CLI skeleton, and `internal/authkeys` (single-line
`authorized_keys` parser). Two vertical slices are implemented: read-only drift
**`audit`** (specced in `docs/superpowers/specs/2026-07-06-audit-slice-design.md`) and
**`import`** — an OpenSSH client config → manifest converter built on `internal/sshcfg`
(specced in `docs/superpowers/specs/2026-07-09-import-ssh-config-design.md`), which also
derives `users:`/`access:` from `IdentityFile` `.pub` files via `internal/identity`
(specced in `docs/superpowers/specs/2026-07-09-import-identityfile-users-design.md`).

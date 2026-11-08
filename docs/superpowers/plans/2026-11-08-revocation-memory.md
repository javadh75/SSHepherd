# Revocation memory and manifest authority (P04-impl, W4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This plan is executed by the wave runner of `docs/superpowers/plans/2026-11-07-review-remediation.md` ("Reusable workflow skeleton"): lane agents work in git worktrees, never commit, and hand back ownership-filtered patches; the integrator commits once per lane. Where a task says "Hand back", that is the lane's last step — not a commit.

**Goal:** Build the approved revocation-memory design (`docs/superpowers/specs/2026-11-08-revocation-memory-design.md`, findings PRD-1, PRD-2, SEC-2, SEC-3): a `revoked:` tombstone list and a `serial:` in the manifest, a header that carries the serial, apply's serial rows (including the PRD-2 header-only write), audit's REVOKED / serial / policy-conflict classes, adopt and `import --merge` honouring tombstones, no adopt wildcard, revoke/rotate writing memory and bumping the serial, apply's D4b bump, the opt-in post-revoke `--sweep`, the JSON additions of spec §9, help, README and E2E.

**Architecture:** The schema lives in `internal/config` (`Serial`, `Tombstone`, validation, D1e warnings, policy conflicts, accessors) and is encoded by `internal/manifest` (`GenerateWith`, `AddTombstones`, `BumpSerial`). The header grammar lives in `internal/authkeys/header.go` (`Header`, `ParseHeader`, `ParseHeaderOf`, `RenderSerial`); the write script's `.orig` decision comes from `fleet.Snapshot.Managed`, set from `ParseHeaderOf` by the planner. `internal/apply` classifies each server by the spec §3 table (`planSerial`), `internal/audit` reorders `statusOf` (critical and drift before compliant), and `cmd/sshepherd` wires revoke/rotate memory, apply's D4b save and the sweep. Nothing adds a delete path, an override flag or a wipe mode.

**Tech Stack:** Go 1.27.3 (`GOTOOLCHAIN=go1.27.3`, the Makefile's `GO_PIN`), `gopkg.in/yaml.v3` node edits, `golang.org/x/crypto/ssh` through the hermetic `internal/sshconn/sshtest` server, goleak, golden files (`-update`), native fuzzing (`FuzzParseHeader`), golangci-lint v2.15.0 (depguard layering, gocyclo 15, dupl), `deadcode ./cmd/sshepherd`, the dockerized sshd matrix (`make integration`).

**Base:** `master` at `7586255` (W3/P14 and its follow-ups `4fa03e6`, `7586255` landed). Every `file:line` below was read at `7586255`; function names are the stable anchors — re-read before editing, because earlier lanes of this wave move lines.

---

## How this plan is cut (read first)

### Why the lanes look the way they do

Three gates shape the rounds, beyond file ownership:

1. **`deadcode ./cmd/sshepherd` is part of `make check`.** Every exported or unexported *function or method* a round adds must be reachable from `main` when that round is committed. So an API is introduced by the lane whose code first calls it from a command path: config accessors land with adopt/reconcile/cmd-adopt (they call every one of them), `manifest.AddTombstones`/`BumpSerial` land with revoke (round 3), `apply.NeedsSerialBump`/`Reserial` with apply's D4b (round 3), `apply.SweepReport` with the sweep (round 4). Constants, types and struct fields are exempt, so shared vocabulary (`authkeys.ForgedMargin`, `fleet.ReadResult.Keys2`, `fleet.Snapshot.Managed`) can land early.
2. **`TestHelpMatchesREADMETables` and `TestHelpExamplesAndExitCodes` read `README.md`.** A lane that changes a flag or an exit-code footer must apply its own `docsDelta` to its worktree's `README.md` before `make check`; the ownership filter drops that README change from the patch, and the integrator re-applies it from `docsDelta`. Every lane below that needs this says so.
3. **`make integration` runs after every round.** E2E tests that must fail first therefore cannot be committed early: lane `e2e` (round 4) proves "fails before W4" by running its new tests against `7586255` (the post-W3 tree the spec names) in a scratch worktree (Task 41), then shows them passing on the round-4 base.

### Rounds

| Round | Lanes (disjoint files) | Builds on |
|---|---|---|
| 1 | `schema` (config, manifest gate + `GenerateWith`, adopt, reconcile, cmd adopt/import) · `header` (authkeys header, fleet, sshwrite `.orig`, sshread keys2, apply snapshot) | `7586255` |
| 2 | `apply` (internal/apply + internal/workflow) · `audit` (internal/audit + cmd audit/run footer) | round 1 |
| 3 | `writecmds` (manifest edits, revoke/rotate memory, apply D4b, cmd write path) | round 2 |
| 4 | `sweep` (post-revoke sweep) · `e2e` (three E2E tests + fixtures) | round 3 |

### Plan decisions (not in the spec; each changes no exit code, refusal or load beyond an answered decision)

1. **`authkeys.Render(entries)` keeps its signature** and renders serial 0 (the legacy bytes); `authkeys.RenderSerial(entries, serial)` is the spec's `Render(entries, serial)`. Every existing caller and golden stays untouched, and `apply.Affected` (via `renderFor`) keeps rendering serial 0 — the spec's "scope ignores the header" holds by construction.
2. **Config field names:** `Config.ManifestSerial` (`yaml:"serial"`) and `Config.Tombstones` (`yaml:"revoked"`), because the spec's accessors `(*Config).Serial()` and `(*Config).Revoked(fp)` take the plain names.
3. **An access tombstone's server name is never a load error beyond the spec §2 table** (D1e: "one stale line never stops a scheduled audit"). A name that fails `ServerFieldIssue` can never be in `servers:`, so it is an unknown server: the D1e warning, printed safely — the first occurrence with `%q` (the spec's quotes), the second (`remove NAME from the entry`) raw when the name passes `ServerFieldIssue` (every real server name, so the spec's text stays verbatim) and `%q`-quoted otherwise. JSON `manifest_warnings` passes `server`/`user`/`message` through `clean`/`sanitize.Remote` (spec §9).
4. **Access-conflict granularity:** one `Conflict` per (access entry, tombstone, tombstoned server) — the message names one server, as the spec's wording does — and `Servers` is, per spec §2, every known server that conflicting `access[N]` entry renders on (its explicit names, or a wildcard's whole fleet minus `except:`), in `servers:` order. apply refuses every server in `Servers` and audit marks each critical, exactly as the spec says; nothing is narrowed.
5. **`fleet.Snapshot.Managed` has one producer, `authkeys.ManagedSnapshot(absent, content)`** (`fleet.SnapshotOf` plus `Managed` from `ParseHeaderOf`): `internal/fleet` is a stdlib-only leaf (depguard `fleet-leaf`) and cannot call authkeys, and the layers forbid apply↔sshwrite imports, so both callers — apply's planner (`planOne`'s `Expect`) and `sshwrite.SnapshotOf` (now a one-line delegate) — call the authkeys helper. `authkeys` importing the `fleet` leaf breaks no `depguard`/`make layering` rule.
6. **`manifest.AddTombstones` returns the entries it added** (`[]config.Tombstone`, not a count): revoke's JSON `edit.revoked` lists exactly those.
7. **D4b counts `Remove` rows only** ("a body that removes keys"): moving `authorized_keys2` aside and collapsing duplicate lines do not bump.
8. **D4b on a manifest `manifest.Load` refuses (`UnsupportedError`: anchors/aliases) is treated like a piped `--config`:** the warning `removing keys without a serial bump: an older copy could re-grant them`, and the write proceeds.
9. **apply JSON `serial` is omitted** when the plan computed no serial row (unreachable, refused before rendering, granted nothing) or when M and S are both 0.
10. **One edit clock:** the existing `rotateNow` seam (`cmd/sshepherd/rotate.go:18`) dates every tombstone (`rotateNow().UTC().Format(time.DateOnly)`).
11. **New edit kind `record-key`** (`apply.EditRecordKey`) for D1b's unowned `--key`: header line `record revoked key SHA256:… (no user has it; no server is written)`, JSON `{"kind": "record-key", "user": "", "fingerprint": …}`.
12. **D1c/D1b texts not fixed by the spec:** `alice's access to db-1 was already revoked (DATE); run 'sshepherd apply …' to converge any server that still has the key`; the save refusal `refusing to write the manifest — it would keep 1 policy conflict: MESSAGE` (exit 3); the sweep's per-server `cannot prove removal on db-3 (unreachable)` lines; audit's per-server `‼ named by a manifest policy conflict above (CRITICAL: policy conflict)`.
13. **`import --merge`'s `IDENTITY`** in `key SHA256:… from IDENTITY is REVOKED (…)` is the `.pub` path the import read, as written: `identity.User.Source` when it already ends in `.pub`, else `Source + ".pub"` — the same rule as `internal/identity`'s `pubPaths` (spec §9: "`identity` is the `.pub` path").
14. **New E2E fixture users** `nra nrb stala stalb handed` (container A), so the three new E2E tests share no state with existing ones: `nra`/`nrb` start with the agent key plus the stale key (what `TestE2ERevokeNoResurrect`'s opening `adopt` discovers), `stala`/`stalb`/`handed` with the agent key alone.
15. **`config.Parse` rejects a `serial:` key whose value is YAML null** (`serial:`, `serial: ~`, `serial: null`) with the spec §2 serial message. yaml.v3 v3.0.1 never calls an `Unmarshaler` for a `!!null` node (`decoder.prepare`, decode.go:406-409), so `Serial.UnmarshalYAML` alone would load it as 0; a second decode into `struct{ Serial yaml.Node }` (a `yaml.Node` field is filled before `prepare`) catches it. `BumpSerial` therefore only ever sees a validated integer.

### Conventions every lane follows

- Go runs under the pin: prefix every `go` command with `GOTOOLCHAIN=go1.27.3`. The rtk hook summarizes test output; use `rtk proxy go test …` when exact failure lines matter.
- A golden is rewritten only with `-update` and then read back line by line before it is accepted.
- **Before hand-back:** apply this lane's `docsDelta` to the worktree's `README.md` (gate only), run `make check` (and `make integration` under the runner's lock when the lane says `needsIntegration`), then `git add -A`, unstage every path outside the lane's globs (README.md and CLAUDE.md always), and write the patch. The README text goes in `docsDelta`, verbatim, with samples copied from the regenerated goldens.
- Coverage: `make coverage` gates production packages at `COVERAGE_MIN := 93`; every new branch below has a test that reaches it.
- **Failing first.** Every test is run and seen failing (build failure or assertion) before the code it tests exists; a test that pins behaviour already present (a regression pin) says so and names a one-line mutation that makes it fail.
- **gocyclo 15 is a production-code gate** (`_test.go` is exempt). Function literals count toward their enclosing function. Where this plan grows a function that is already at 12-14 (`renderChange`, `jsonServerFor`, `runEdit`, `finishEdit`, `newApplyCmd`), the new branches go into the named helpers the tasks give; never `//nolint:gocyclo`.
- **errorlint applies to tests too** (the `_test.go` exclusions are only dupl, errcheck, gocyclo, wrapcheck): compare sentinels with `errors.Is`.
- **README sample output is real.** A docsDelta line that has a golden is copied from the regenerated golden; a line that has none (the revoke/rotate already-revoked notes, the save notes, the `check every server:` line, the `record-key` header, the D4b lines, the sweep's `REVOKED KEY STILL INSTALLED` and `swept N of M` lines, the save refusal) is copied from a captured run (Task 36 Step 5 and Task 40 Step 3 give the commands; both use the default `--config`/`--known-hosts`, so hints carry no temp path) or verbatim from a test `want` literal that contains no path — never paraphrased, and never a literal with its temp paths edited by hand. Lanes `schema` and `audit` capture their non-golden lines (adopt's and import's skip warnings, the D1e warning) the same way: a scratch-directory run of the built binary, or a path-free test literal.

---

## File structure

| File | Round/lane | Responsibility |
|---|---|---|
| `internal/config/revoked.go` (new) | 1 `schema` | `Serial` (+`UnmarshalYAML`), `Tombstone` (+`IsKey`, `Label`), `Conflict`, `TombstoneWarning`, `validateRevoked`, `computeConflicts`, accessors `Serial`/`Revoked`/`AccessRevoked`/`Conflicts` |
| `internal/config/config.go` | 1 `schema` | `Config` gains `ManifestSerial`, `Tombstones`, `TombstoneWarnings`, `conflicts`, `ignored`; `Parse` computes conflicts; `validate` calls `validateRevoked` |
| `internal/config/revoked_test.go` (new), `fuzz_test.go` | 1 `schema` | shape/warning/conflict tables; FuzzLoad property + seeds |
| `internal/manifest/manifest.go`, `manifest_test.go`, `testdata/generate_memory.golden` (new) | 1 `schema` | top-level gate allows `serial`/`revoked`; per-type required keys; `Draft` + `GenerateWith` |
| `internal/adopt/adopt.go`, `adopt_test.go` | 1 `schema` | skip tombstoned keys and access; no wildcard (D5) |
| `internal/reconcile/reconcile.go`, `reconcile_test.go` | 1 `schema` | skip tombstoned `.pub` and access |
| `cmd/sshepherd/conflicts.go` (new), `conflicts_test.go` (new) | 1 `schema` | `conflictRefusal` (D29 save refusal) |
| `cmd/sshepherd/adopt.go`, `adopt_test.go`, `import.go`, `import_merge_test.go`, `schema_roundtrip_test.go`, `testdata/adopt_merge.golden` | 1 `schema` | regenerate keeps `serial`/`revoked`; conflict refusal; no wildcard renderer branch |
| `cmd/sshepherd/run.go` (`exitCodesAdopt`, `exitCodesImport`), `testdata/help/{adopt,import}.golden` | 1 `schema` | footers name the conflict refusal |
| `internal/authkeys/header.go` (new), `header_test.go` (new), `render.go`, `fuzz_test.go`, `testdata/fuzz/FuzzParseHeader/*` (new) | 1 `header` | header grammar, `RenderSerial`, `ForgedMargin`, `ManagedSnapshot` (the one `.orig` decision input), fuzz |
| `internal/fleet/write.go`, `fleet.go` | 1 `header` | `Snapshot.Managed`; `ReadResult.Keys2`/`Keys2Err` |
| `internal/sshwrite/sshwrite.go`, `sshwrite_test.go`, `integration_test.go` | 1 `header` | `.orig` decision from `Snapshot.Managed` (no shell compare) |
| `internal/sshread/sshread.go`, `hermetic_test.go`, `integration_test.go` | 1 `header` | `Client.ReadKeys2` (hermetic and real-sshd tests) |
| `internal/apply/plan.go`, `plan_test.go` | 1 `header`, then 2 `apply` | snapshot via `authkeys.ManagedSnapshot`; `normalize` uses `ParseHeader`; then the serial rows (`Build` removed: `BuildWith` is the only entry) |
| `internal/apply/serial.go` (new), `serial_test.go` (new) | 2 `apply` | `SerialPlan`, `planSerial`, `removalOnly`, `conflictRefusal` |
| `internal/apply/{report,json,edit,affected_test}.go`, goldens | 2 `apply` | header-only rows, serial notes, JSON §9, `EditRecordKey`, edit memory fields |
| `internal/workflow/workflow.go`, `workflow_test.go` | 2 `apply` | `Request.Bumped` → `apply.BuildWith`; commit may re-render headers |
| `internal/audit/{audit,report,json}.go`, tests, goldens | 2 `audit` | header serial on `ServerResult`, `statusOf` order, REVOKED/serial/conflict rows, JSON §9 |
| `cmd/sshepherd/audit.go`, `run.go` (`exitCodesAudit`), `testdata/help/audit.golden` | 2 `audit` | empty-fleet verdict; footer |
| `internal/manifest/edit.go`, `edit_test.go`, `fuzz_edit_test.go`, `testdata/edit_memory.golden`, `testdata/bump_serial_first.golden` (new) | 3 `writecmds` | `AddTombstones`, `BumpSerial` |
| `internal/apply/serialbump.go` (new), `serialbump_test.go` (new) | 3 `writecmds` | `NeedsSerialBump`, `Reserial` |
| `cmd/sshepherd/{revoke,rotate,editrun,edit,apply,run}.go`, tests (incl. `apply_serial_test.go`, `apply_serial_pipe_test.go`), `testdata/help/{apply,revoke,rotate}.golden` | 3 `writecmds` | memory, serial bump, D1b/D1c, save notes, check line, D4b |
| `internal/apply/sweep.go` (new), `json.go`, `sweep_test.go` | 4 `sweep` | `SweepReport`, JSON `sweep`, combined exit |
| `cmd/sshepherd/sweep.go` (new), `sweep_test.go` (new), `editrun.go`, `apply.go`, `run.go`, help goldens | 4 `sweep` | `--sweep` |
| `cmd/sshepherd/e2e_test.go`, `scripts/integration.sh` | 4 `e2e` | three E2E tests, five fixture users |

---
## Round 1 — lane `schema` (Tasks 1–9)

Owns: `internal/config/**`, `internal/manifest/manifest.go`, `internal/manifest/manifest_test.go`, `internal/manifest/testdata/generate_memory.golden`, `internal/adopt/**`, `internal/reconcile/**`, `cmd/sshepherd/conflicts*.go`, `cmd/sshepherd/adopt.go`, `cmd/sshepherd/adopt_test.go`, `cmd/sshepherd/import.go`, `cmd/sshepherd/import_merge_test.go`, `cmd/sshepherd/schema_roundtrip_test.go`, `cmd/sshepherd/run.go`, `cmd/sshepherd/testdata/adopt_*.golden`, `cmd/sshepherd/testdata/help/adopt.golden`, `cmd/sshepherd/testdata/help/import.golden`. Findings: PRD-1, SEC-3.

Every config accessor this lane adds is called by this lane's adopt/reconcile/cmd code (deadcode), so do not move a consumer task to a later round.

### Task 1: `serial:` and `revoked:` load (config types, both top-level gates)

**Files:**
- Create: `internal/config/revoked.go`, `internal/config/revoked_test.go`
- Modify: `internal/config/config.go:55-71` (`Config`), `internal/manifest/manifest.go:117-133` (`checkTopLevelKeys`)
- Test: `internal/manifest/manifest_test.go`

- [ ] **Step 1: Write the failing tests**

`internal/config/revoked_test.go`:

```go
package config

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// memoryManifest: alice (k1) -> web-1, web-2; bob (k2) -> db-1; extra is
// appended verbatim (a revoked: section, usually).
func memoryManifest(t *testing.T, extra string) string {
	t.Helper()
	return `users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
  - {name: db-1, host: 10.0.0.3, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
  - {user: bob, servers: [db-1]}
` + extra
}

// fpOf is a test key's SHA256 fingerprint.
func fpOf(t *testing.T, seed byte) string {
	t.Helper()
	k, err := authkeys.ParseLine(testkeys.Line(t, seed))
	if err != nil || k == nil {
		t.Fatalf("fpOf(%d): %v", seed, err)
	}
	return k.Fingerprint
}

func TestLoadAllowsSerialAndRevoked(t *testing.T) {
	y := "serial: 7\n" + memoryManifest(t, "revoked:\n"+
		"  - {fingerprint: "+fpOf(t, 9)+", user: carol, date: 2026-11-08, reason: offboarded}\n"+
		"  - {user: bob, servers: [web-1], date: 2026-11-08}\n")
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Serial() != 7 {
		t.Errorf("Serial() = %d, want 7", cfg.Serial())
	}
	if len(cfg.Tombstones) != 2 || cfg.Tombstones[0].Reason != "offboarded" ||
		cfg.Tombstones[0].Date != "2026-11-08" || cfg.Tombstones[1].Servers[0] != "web-1" {
		t.Errorf("Tombstones = %+v", cfg.Tombstones)
	}
	if !cfg.Tombstones[0].IsKey() || cfg.Tombstones[1].IsKey() {
		t.Errorf("IsKey wrong: %+v", cfg.Tombstones)
	}
	if len(cfg.Conflicts()) != 0 || len(cfg.Warnings) != 0 {
		t.Errorf("Conflicts = %v, Warnings = %v, want none", cfg.Conflicts(), cfg.Warnings)
	}
	if absent, _ := Parse([]byte(memoryManifest(t, ""))); absent.Serial() != 0 {
		t.Errorf("absent serial = %d, want 0", absent.Serial())
	}
}

func TestSerialNegativeRejected(t *testing.T) {
	const want = `parse manifest: serial: want an integer from 0 to 9007199254740991, got `
	// "", "~" and "null" are YAML null: yaml.v3 skips Unmarshalers for
	// !!null, so Parse checks for them itself (plan decision 15).
	for _, v := range []string{"-1", "'7'", "7.5", "0x10", "1_000", "07", "9007199254740992", "null", "~", "", "[1]"} {
		_, err := Parse([]byte("serial: " + v + "\nusers: []\n"))
		if err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("serial: %s → err %v, want prefix %q", v, err, want)
		}
	}
	for v, n := range map[string]uint64{"0": 0, "1": 1, "9007199254740991": 9007199254740991} {
		cfg, err := Parse([]byte("serial: " + v + "\nusers: []\n"))
		if err != nil || cfg.Serial() != n {
			t.Errorf("serial: %s → %v, %v; want %d", v, cfg, err, n)
		}
	}
}
```

Append to `internal/manifest/manifest_test.go`:

```go
// TestLoadAllowsSerialAndRevoked: both new top-level keys pass the
// comment-preserving editor's gate (revoke must be able to edit a manifest
// that already remembers a revoke).
func TestLoadAllowsSerialAndRevoked(t *testing.T) {
	src := "serial: 3\nusers: []\nservers: []\naccess: []\nrevoked:\n  - {fingerprint: " +
		keyFP(t, 9) + ", date: 2026-11-08}\n"
	mf, err := Load([]byte(src))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	out, err := mf.Encode()
	if err != nil || string(out) == "" {
		t.Fatalf("Encode: %v", err)
	}
	if mf.Config().Serial() != 3 || len(mf.Config().Tombstones) != 1 {
		t.Errorf("config = %+v", mf.Config())
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config/ ./internal/manifest/ -run 'TestLoadAllowsSerialAndRevoked|TestSerialNegativeRejected'`
Expected: build failure (`cfg.Serial undefined`, `cfg.Tombstones undefined`).

- [ ] **Step 3: Implement the types**

Create `internal/config/revoked.go`:

```go
package config

import (
	"fmt"
	"regexp"
	"strconv"

	"gopkg.in/yaml.v3"
)

// MaxSerial is the largest manifest serial, 2^53-1, so every JSON consumer
// reads it exactly. authkeys.MaxHeaderSerial is the same bound for the
// managed header (a test in internal/apply pins the two equal).
const MaxSerial = 1<<53 - 1

// Serial is the manifest's serial: (absent = 0). Only a plain, unquoted
// decimal YAML integer in [0, MaxSerial] decodes: a quoted, signed, hex,
// octal-looking or underscored value is a load error, so the number in the
// file is the number every tool compares.
type Serial uint64

var plainDecimal = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})$`)

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *Serial) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode && n.Tag == "!!int" && n.Style == 0 && plainDecimal.MatchString(n.Value) {
		if v, err := strconv.ParseUint(n.Value, 10, 64); err == nil && v <= MaxSerial {
			*s = Serial(v)
			return nil
		}
	}
	return fmt.Errorf("serial: want an integer from 0 to %d, got %q", MaxSerial, n.Value)
}

// Tombstone is one revoked: entry. A key tombstone has Fingerprint (User is
// an optional label naming the former owner, who need not exist); an access
// tombstone has no Fingerprint and records that User lost Servers. Deleting
// an entry by hand is a deliberate un-revoke.
type Tombstone struct {
	Fingerprint string   `yaml:"fingerprint"`
	User        string   `yaml:"user"`
	Servers     []string `yaml:"servers"`
	Date        string   `yaml:"date"`
	Reason      string   `yaml:"reason"`
}

// IsKey reports a key tombstone (as opposed to an access tombstone).
func (t Tombstone) IsKey() bool { return t.Fingerprint != "" }

// Label is the parenthesis every message prints: "2026-11-08, alice", or
// "2026-11-08" for an unlabelled entry.
func (t Tombstone) Label() string {
	if t.User == "" {
		return t.Date
	}
	return t.Date + ", " + t.User
}

// Serial returns the manifest's serial (0 when absent).
func (c *Config) Serial() uint64 { return uint64(c.ManifestSerial) }

// rejectNullSerial catches serial: with a YAML null value (`serial:`,
// `serial: ~`, `serial: null`). yaml.v3 never calls an Unmarshaler for a
// !!null node (decoder.prepare), so Serial.UnmarshalYAML alone would load
// it as 0 — and BumpSerial would later fail on a value that "passed
// validation". A yaml.Node field is filled before that check, so a second
// decode sees the raw node. Parse calls it only after the strict decode
// succeeded, so this decode cannot fail on syntax.
func rejectNullSerial(data []byte) error {
	var probe struct {
		Serial yaml.Node `yaml:"serial"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil //nolint:nilerr // the strict decode in Parse already reported every syntax error
	}
	n := &probe.Serial
	if n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	if n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null" {
		return fmt.Errorf("serial: want an integer from 0 to %d, got %q", MaxSerial, n.Value)
	}
	return nil
}
```

In `internal/config/config.go`, `Parse` (`:84-102`): after the multiple-documents check and before `c.validate()`, add

```go
	if err := rejectNullSerial(data); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
```

and change the `Config` struct (`:55-71`) to:

```go
// Config is the parsed, validated manifest.
type Config struct {
	// ManifestSerial is serial: (absent = 0). Revoke and rotate bump it; the
	// managed header carries it, so apply can refuse a write from an older
	// copy (spec 2026-11-08 §3). The accessor is Serial().
	ManifestSerial Serial    `yaml:"serial"`
	Users          []User    `yaml:"users"`
	Servers        []Server  `yaml:"servers"`
	Access         []Access  `yaml:"access"`
	// Tombstones is revoked: — the revocation memory every tool honours.
	// The accessors are Revoked and AccessRevoked.
	Tombstones []Tombstone `yaml:"revoked"`

	// Warnings collects non-fatal validation findings (e.g. a comment: set
	// on a multi-key user). The manifest is still valid and safe to act on;
	// callers surface these on stderr. Never part of the YAML itself.
	Warnings []string `yaml:"-"`
	// TombstoneWarnings are the D1e findings of Warnings in structured form
	// (the JSON manifest_warnings objects).
	TombstoneWarnings []TombstoneWarning `yaml:"-"`

	// Built during validation.
	keysByUser map[string][]authkeys.Key // user name -> parsed keys, manifest order
	owners     map[string]User           // fingerprint -> owning user
	grants     map[string][]string       // server name -> user names, access order
	operators  []string                  // operator user names, users order
	ignored    map[int]map[string]bool   // revoked index -> unknown servers it names (D1e)
	conflicts  []Conflict                // policy conflicts (D29), computed after validation
}
```

Add to `revoked.go` the two types the struct names (filled in Tasks 3–4):

```go
// TombstoneWarning is one D1e finding: an access tombstone names a server
// that is not in servers:. That entry is ignored for that server. The json
// tags are the wire shape of audit's and apply's manifest_warnings.
type TombstoneWarning struct {
	Kind         string `json:"kind"` // always "tombstone_unknown_server"
	RevokedIndex int    `json:"revoked_index"`
	User         string `json:"user"`
	Server       string `json:"server"`
	Message      string `json:"message"`
}

// The policy-conflict kinds (D29).
const (
	ConflictRevokedKey    = "revoked_key"
	ConflictRevokedAccess = "revoked_access"
)

// Conflict is a manifest that breaks its own revocation memory: a
// tombstoned key still listed, or a grant over an access tombstone. It is
// not a load error (D29): audit reports it critical, apply refuses Servers,
// and a command that saves the manifest refuses while one remains. The json
// tags are the wire shape of policy_conflicts.
type Conflict struct {
	Kind        string   `json:"kind"`
	Message     string   `json:"message"`
	User        string   `json:"user"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Servers     []string `json:"servers"` // every server the key or grant would render on; never nil
}
```

In `internal/manifest/manifest.go`, `checkTopLevelKeys` (`:117-133`): replace the key test and the doc comment's "plain users/servers/access scalars" with:

```go
// checkTopLevelKeys rejects manifests whose top-level mapping keys are not
// plain serial/users/servers/access/revoked scalars. …(rest of the comment unchanged)
```

```go
		if k.Kind != yaml.ScalarNode || !topLevelKeys[k.Value] {
```

and add above the function:

```go
// topLevelKeys are the manifest's sections (config.Config's yaml keys).
var topLevelKeys = map[string]bool{"serial": true, "users": true, "servers": true, "access": true, "revoked": true}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config/ ./internal/manifest/ -run 'TestLoadAllowsSerialAndRevoked|TestSerialNegativeRejected'`
Expected: `ok` for both packages. (`TestLoadAllowsSerialAndRevoked` in config also checks `IsKey`; `Conflicts()` is added in Task 4 — until then write the conflicts/warnings assertion lines last and keep them commented out; uncomment them in Task 4 Step 1.)

### Task 2: tombstone shape errors (load errors, spec §2 table)

**Files:**
- Modify: `internal/config/revoked.go`, `internal/config/config.go:104-110` (`validate`)
- Test: `internal/config/revoked_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestRevokedFingerprintShape(t *testing.T) {
	fp := fpOf(t, 9)
	long := strings.Repeat("x", 257)
	tests := []struct{ name, entry, want string }{
		{"bad fingerprint", "{fingerprint: SHA256:short, date: 2026-11-08}",
			`revoked[0]: fingerprint "SHA256:short" is not a SHA256 fingerprint (want SHA256: followed by 43 base64 characters)`},
		{"md5 fingerprint", "{fingerprint: 'MD5:aa:bb', date: 2026-11-08}",
			`revoked[0]: fingerprint "MD5:aa:bb" is not a SHA256 fingerprint (want SHA256: followed by 43 base64 characters)`},
		{"padded fingerprint", "{fingerprint: '" + fp + "=', date: 2026-11-08}",
			`revoked[0]: fingerprint "` + fp + `=" is not a SHA256 fingerprint (want SHA256: followed by 43 base64 characters)`},
		{"servers on a key entry", "{fingerprint: " + fp + ", servers: [web-1], date: 2026-11-08}",
			"revoked[0]: servers is not allowed on a key entry (" + fp + "); record access with a separate entry that has user and servers"},
		{"access entry without user", "{servers: [web-1], date: 2026-11-08}",
			"revoked[0]: an entry without fingerprint needs user and servers"},
		{"access entry with empty servers", "{user: bob, servers: [], date: 2026-11-08}",
			"revoked[0]: servers must not be empty"},
		{"wildcard", `{user: bob, servers: ["*"], date: 2026-11-08}`,
			`revoked[0]: servers cannot be "*"; list the servers by name`},
		{"missing date", "{fingerprint: " + fp + "}", "revoked[0]: date is required"},
		{"bad date", "{fingerprint: " + fp + ", date: 2026-13-01}", `revoked[0]: date "2026-13-01" is not a YYYY-MM-DD date`},
		{"unpadded date", "{fingerprint: " + fp + ", date: '2026-1-8'}", `revoked[0]: date "2026-1-8" is not a YYYY-MM-DD date`},
		{"user with control runes", `{fingerprint: ` + fp + `, user: "a\e[31m", date: 2026-11-08}`,
			"revoked[0]: user contains control or format characters"},
		{"reason with edge space", `{fingerprint: ` + fp + `, reason: " x", date: 2026-11-08}`,
			"revoked[0]: reason has leading or trailing whitespace"},
		{"reason too long", "{fingerprint: " + fp + ", reason: " + long + ", date: 2026-11-08}",
			"revoked[0]: reason is 257 bytes, over the 256-byte limit"},
		{"user too long", "{fingerprint: " + fp + ", user: " + long + ", date: 2026-11-08}",
			"revoked[0]: user is 257 bytes, over the 256-byte limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(memoryManifest(t, "revoked:\n  - "+tt.entry+"\n")))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v\nwant it to contain %q", err, tt.want)
			}
		})
	}
}

func TestRevokedDuplicateFingerprint(t *testing.T) {
	fp := fpOf(t, 9)
	y := memoryManifest(t, "revoked:\n  - {fingerprint: "+fp+", date: 2026-11-07}\n  - {fingerprint: "+fp+", date: 2026-11-08}\n")
	_, err := Parse([]byte(y))
	if want := "revoked[1]: " + fp + " is already revoked by revoked[0]"; err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want %q", err, want)
	}
}
```

- [ ] **Step 2: Run to see it fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config/ -run 'TestRevokedFingerprintShape|TestRevokedDuplicateFingerprint'`
Expected: FAIL — every subtest reports `err = <nil>`.

- [ ] **Step 3: Implement the shape checks**

Append to `revoked.go` (add `"slices"`, `"time"` and `"github.com/javadh75/SSHepherd/internal/authkeys"` to its imports):

```go
// fingerprintShape is OpenSSH's SHA256 fingerprint: "SHA256:" and 43
// unpadded base64 characters (32 bytes).
var fingerprintShape = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// maxTombstoneText caps a tombstone's printed user and reason labels.
const maxTombstoneText = 256

// validateRevoked checks each revoked: entry's shape (load errors, spec §2)
// and records the D1e warnings: a server an access tombstone names that is
// not in servers: is ignored for that entry, never an error.
func (c *Config) validateRevoked() []error {
	var errs []error
	c.TombstoneWarnings = nil
	c.ignored = make(map[int]map[string]bool)
	known := make(map[string]bool, len(c.Servers))
	for _, s := range c.Servers {
		known[s.Name] = true
	}
	firstFP := make(map[string]int)
	for i, t := range c.Tombstones {
		p := fmt.Sprintf("revoked[%d]: ", i)
		if t.IsKey() {
			errs = append(errs, keyShape(p, t)...)
			if j, dup := firstFP[t.Fingerprint]; dup {
				errs = append(errs, fmt.Errorf("%s%s is already revoked by revoked[%d]", p, t.Fingerprint, j))
			} else {
				firstFP[t.Fingerprint] = i
			}
		} else {
			errs = append(errs, accessShape(p, t)...)
			c.warnUnknownServers(i, t, known)
		}
		errs = append(errs, dateErrors(p, t.Date)...)
		errs = append(errs, textErrors(p, "user", t.User)...)
		errs = append(errs, textErrors(p, "reason", t.Reason)...)
	}
	return errs
}

func keyShape(p string, t Tombstone) []error {
	var errs []error
	if !fingerprintShape.MatchString(t.Fingerprint) {
		errs = append(errs, fmt.Errorf("%sfingerprint %q is not a SHA256 fingerprint (want SHA256: followed by 43 base64 characters)", p, t.Fingerprint))
	}
	if len(t.Servers) > 0 {
		errs = append(errs, fmt.Errorf("%sservers is not allowed on a key entry (%s); record access with a separate entry that has user and servers", p, t.Fingerprint))
	}
	return errs
}

func accessShape(p string, t Tombstone) []error {
	var errs []error
	switch {
	case t.User == "":
		errs = append(errs, fmt.Errorf("%san entry without fingerprint needs user and servers", p))
	case len(t.Servers) == 0:
		errs = append(errs, fmt.Errorf("%sservers must not be empty", p))
	}
	// Only the spec §2 rules are load errors. Any other name — even one
	// with control runes, which can never be in servers: — is an unknown
	// server: a D1e warning (warnUnknownServers), never a load error.
	if slices.Contains(t.Servers, "*") {
		errs = append(errs, fmt.Errorf(`%sservers cannot be "*"; list the servers by name`, p))
	}
	return errs
}

func dateErrors(p, d string) []error {
	if d == "" {
		return []error{fmt.Errorf("%sdate is required", p)}
	}
	if _, err := time.Parse(time.DateOnly, d); err != nil || len(d) != len(time.DateOnly) {
		return []error{fmt.Errorf("%sdate %q is not a YYYY-MM-DD date", p, d)}
	}
	return nil
}

// textErrors: user and reason are printed by every tool, so they pass the
// render-text predicate and a length cap.
func textErrors(p, field, s string) []error {
	if issue := authkeys.RenderTextIssue(s); issue != "" {
		return []error{fmt.Errorf("%s%s %s", p, field, issue)}
	}
	if len(s) > maxTombstoneText {
		return []error{fmt.Errorf("%s%s is %d bytes, over the %d-byte limit", p, field, len(s), maxTombstoneText)}
	}
	return nil
}

// warnUnknownServers is filled in Task 3.
func (c *Config) warnUnknownServers(int, Tombstone, map[string]bool) {}
```

In `config.go`, `validate` (`:104-110`) becomes:

```go
func (c *Config) validate() error {
	var errs []error
	errs = append(errs, c.validateUsers()...)
	errs = append(errs, c.validateServers()...)
	errs = append(errs, c.validateAccess()...)
	errs = append(errs, c.validateRevoked()...)
	return errors.Join(errs...)
}
```

- [ ] **Step 4: Run to see it pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config/`
Expected: `ok`.

### Task 3: D1e warnings and the `Revoked` / `AccessRevoked` accessors

**Files:**
- Modify: `internal/config/revoked.go`
- Test: `internal/config/revoked_test.go`

- [ ] **Step 1: Write the failing test**

```go
// TestAccessTombstoneUnknownServerWarns (D1e, owner override): a
// decommissioned server named in an access tombstone is a warning, the
// entry is ignored for that server, and re-adding the server re-applies it.
func TestAccessTombstoneUnknownServerWarns(t *testing.T) {
	y := memoryManifest(t, "revoked:\n  - {user: bob, servers: [db-9, db-1], date: 2026-11-08}\n")
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v (an unknown server must not be a load error)", err)
	}
	want := `revoked[0]: unknown server "db-9" — this entry is ignored for it; remove db-9 from the entry once the server is gone for good`
	if len(cfg.Warnings) != 1 || cfg.Warnings[0] != want {
		t.Errorf("Warnings = %q, want [%q]", cfg.Warnings, want)
	}
	if len(cfg.TombstoneWarnings) != 1 || cfg.TombstoneWarnings[0] != (TombstoneWarning{
		Kind: "tombstone_unknown_server", RevokedIndex: 0, User: "bob", Server: "db-9", Message: want,
	}) {
		t.Errorf("TombstoneWarnings = %+v", cfg.TombstoneWarnings)
	}
	if _, ok := cfg.AccessRevoked("bob", "db-9"); ok {
		t.Error("AccessRevoked matched an ignored (unknown) server")
	}
	if got, ok := cfg.AccessRevoked("bob", "db-1"); !ok || got.Date != "2026-11-08" {
		t.Errorf("AccessRevoked(bob, db-1) = %+v, %v; want the entry", got, ok)
	}
	readded := strings.Replace(y, "servers:\n", "servers:\n  - {name: db-9, host: 10.0.0.9, user: deploy}\n", 1)
	again, err := Parse([]byte(readded))
	if err != nil {
		t.Fatalf("Parse re-added: %v", err)
	}
	if len(again.Warnings) != 0 {
		t.Errorf("re-added server still warns: %q", again.Warnings)
	}
	if _, ok := again.AccessRevoked("bob", "db-9"); !ok {
		t.Error("re-adding the server must re-apply the entry")
	}
	// A name no server can have (control runes) is still only a warning
	// (D1e, plan decision 3), printed quoted in both places.
	odd, err := Parse([]byte(memoryManifest(t, "revoked:\n  - {user: bob, servers: [\"db\\e[1A\"], date: 2026-11-08}\n")))
	if err != nil {
		t.Fatalf("Parse: %v (an unknown server must not be a load error)", err)
	}
	wantOdd := `revoked[0]: unknown server "db\x1b[1A" — this entry is ignored for it; remove "db\x1b[1A" from the entry once the server is gone for good`
	if len(odd.Warnings) != 1 || odd.Warnings[0] != wantOdd || strings.ContainsRune(odd.Warnings[0], 0x1b) {
		t.Errorf("Warnings = %q, want [%q]", odd.Warnings, wantOdd)
	}
}

func TestRevokedLookup(t *testing.T) {
	fp := fpOf(t, 9)
	cfg, err := Parse([]byte(memoryManifest(t, "revoked:\n  - {fingerprint: "+fp+", user: carol, date: 2026-11-08}\n")))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := cfg.Revoked(fp); !ok || got.User != "carol" || got.Label() != "2026-11-08, carol" {
		t.Errorf("Revoked = %+v, %v", got, ok)
	}
	if _, ok := cfg.Revoked(fpOf(t, 1)); ok {
		t.Error("an untombstoned key reported revoked")
	}
	if (Tombstone{Date: "2026-11-08"}).Label() != "2026-11-08" {
		t.Error("an unlabelled tombstone's label must be the date alone")
	}
}
```

- [ ] **Step 2: Run to see it fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config/ -run 'TestAccessTombstoneUnknownServerWarns|TestRevokedLookup'`
Expected: build failure (`cfg.AccessRevoked undefined`).

- [ ] **Step 3: Implement**

Replace the `warnUnknownServers` stub and add the accessors in `revoked.go` (`"slices"` and `"strconv"` are already imported, by Tasks 2 and 1):

```go
// warnUnknownServers records, for access tombstone i, every server it names
// that servers: does not hold (D1e): a warning, and the entry is ignored for
// that server (AccessRevoked and the conflict check skip it).
func (c *Config) warnUnknownServers(i int, t Tombstone, known map[string]bool) {
	for _, s := range t.Servers {
		if s == "*" || known[s] {
			continue
		}
		if c.ignored[i] == nil {
			c.ignored[i] = make(map[string]bool)
		}
		c.ignored[i][s] = true
		// The name is printed: quoted first (the spec's quotes); the second
		// time raw for any name a server could have (the spec's text,
		// verbatim) and quoted otherwise, so no control rune reaches a
		// terminal.
		bare := s
		if ServerFieldIssue(s) != "" {
			bare = strconv.Quote(s)
		}
		msg := fmt.Sprintf("revoked[%d]: unknown server %q — this entry is ignored for it; remove %s from the entry once the server is gone for good", i, s, bare)
		c.Warnings = append(c.Warnings, msg)
		c.TombstoneWarnings = append(c.TombstoneWarnings, TombstoneWarning{
			Kind: "tombstone_unknown_server", RevokedIndex: i, User: t.User, Server: s, Message: msg,
		})
	}
}

// Revoked returns the key tombstone for fingerprint fp.
func (c *Config) Revoked(fp string) (Tombstone, bool) {
	for _, t := range c.Tombstones {
		if t.IsKey() && t.Fingerprint == fp {
			return t, true
		}
	}
	return Tombstone{}, false
}

// AccessRevoked returns the latest access tombstone recording that user
// lost server. A server the entry names but servers: does not hold is
// ignored for that entry (D1e), so it never matches.
func (c *Config) AccessRevoked(user, server string) (Tombstone, bool) {
	var found Tombstone
	ok := false
	for i, t := range c.Tombstones {
		if t.IsKey() || t.User != user || !slices.Contains(t.Servers, server) || c.ignored[i][server] {
			continue
		}
		found, ok = t, true
	}
	return found, ok
}
```

- [ ] **Step 4: Run to see it pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config/`
Expected: `ok`.

### Task 4: policy conflicts (D29) — reported, never a load error

**Files:**
- Modify: `internal/config/revoked.go`, `internal/config/config.go:84-102` (`Parse`)
- Test: `internal/config/revoked_test.go` (uncomment the Task 1 conflict assertion)

- [ ] **Step 1: Write the failing tests**

```go
// TestConflictsAreReportedNotFatal (replaces the spec draft's
// TestRevokedRejectsOwnedKey): a listed tombstoned key loads, and
// Conflicts() names it with the verbatim message and the servers it renders on.
func TestConflictsAreReportedNotFatal(t *testing.T) {
	fp := fpOf(t, 1)
	cfg, err := Parse([]byte(memoryManifest(t, "revoked:\n  - {fingerprint: "+fp+", user: alice, date: 2026-11-08}\n")))
	if err != nil {
		t.Fatalf("Parse: %v (a conflict must not be a load error)", err)
	}
	want := Conflict{
		Kind: ConflictRevokedKey, User: "alice", Fingerprint: fp, Servers: []string{"web-1", "web-2"},
		Message: "key " + fp + ` of user "alice" is revoked (2026-11-08, alice): remove it from users, or delete the revoked: entry to un-revoke it deliberately`,
	}
	if got := cfg.Conflicts(); len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Fatalf("Conflicts = %+v\nwant [%+v]", got, want)
	}
	unlabelled, _ := Parse([]byte(memoryManifest(t, "revoked:\n  - {fingerprint: "+fp+", date: 2026-11-08}\n")))
	if m := unlabelled.Conflicts()[0].Message; !strings.Contains(m, "is revoked (2026-11-08): remove") {
		t.Errorf("unlabelled message = %q", m)
	}
}

func TestConflictOperatorAndGrantless(t *testing.T) {
	y := `users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: idle, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
revoked:
  - {fingerprint: ` + fpOf(t, 1) + `, date: 2026-11-08}
  - {fingerprint: ` + fpOf(t, 2) + `, date: 2026-11-08}
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	cs := cfg.Conflicts()
	if len(cs) != 2 || !reflect.DeepEqual(cs[0].Servers, []string{"web-1", "web-2"}) || cs[1].Servers == nil || len(cs[1].Servers) != 0 {
		t.Errorf("Conflicts = %+v; want the operator on every server and a grantless user with servers []", cs)
	}
}

// TestAccessTombstoneConflictsExplicitGrant: one conflict per tombstoned
// server, and Servers is every server the conflicting access entry renders
// on (spec §2) — apply refuses, and audit marks critical, all of them.
func TestAccessTombstoneConflictsExplicitGrant(t *testing.T) {
	const msg = `user "bob" is granted "db-1" by access[0], but revoked[0] removed that access (2026-11-08): remove the grant, or delete the revoked: entry to restore it deliberately`
	tests := []struct {
		name, access string
		want         []string // conflict messages
		servers      []string // each conflict's Servers, in servers: order
	}{
		{"explicit grant", "  - {user: bob, servers: [db-1, web-1]}\n", []string{msg}, []string{"web-1", "db-1"}},
		{"wildcard without except", "  - {user: bob, servers: [\"*\"]}\n", []string{msg}, []string{"web-1", "db-1", "app-1"}},
		{"wildcard excepting another", "  - {user: bob, servers: [\"*\"], except: [app-1]}\n", []string{msg}, []string{"web-1", "db-1"}},
		{"wildcard excepting it", "  - {user: bob, servers: [\"*\"], except: [db-1]}\n", nil, nil},
		{"other server only", "  - {user: bob, servers: [web-1]}\n", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			y := `users:
  - {name: bob, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: db-1, host: 10.0.0.3, user: deploy}
  - {name: app-1, host: 10.0.0.4, user: deploy}
access:
` + tt.access + `revoked:
  - {user: bob, servers: [db-1], date: 2026-11-08}
`
			cfg, err := Parse([]byte(y))
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, c := range cfg.Conflicts() {
				if c.Kind != ConflictRevokedAccess || c.Fingerprint != "" || !reflect.DeepEqual(c.Servers, tt.servers) {
					t.Errorf("conflict shape = %+v", c)
				}
				got = append(got, c.Message)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("messages = %q\nwant %q", got, tt.want)
			}
		})
	}
}

// An access tombstone naming only an unknown server computes no conflict.
func TestConflictIgnoresUnknownTombstoneServer(t *testing.T) {
	y := memoryManifest(t, "revoked:\n  - {user: bob, servers: [db-9], date: 2026-11-08}\n")
	cfg, err := Parse([]byte(y))
	if err != nil || len(cfg.Conflicts()) != 0 {
		t.Fatalf("err %v, conflicts %+v; want none", err, cfg.Conflicts())
	}
}
```

Add `"reflect"` to the test imports, and uncomment Task 1's `cfg.Conflicts()` assertion.

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config/ -run 'Conflict'`
Expected: build failure (`cfg.Conflicts undefined`).

- [ ] **Step 3: Implement**

Append to `revoked.go`:

```go
// Conflicts returns the manifest's policy conflicts (D29), key conflicts
// first, each in revoked: order.
func (c *Config) Conflicts() []Conflict { return slices.Clone(c.conflicts) }

// computeConflicts runs after validation succeeded: owners and grants are
// built, every tombstone is well-formed.
func (c *Config) computeConflicts() []Conflict {
	var out []Conflict
	for _, t := range c.Tombstones {
		u, owned := c.owners[t.Fingerprint]
		if !t.IsKey() || !owned {
			continue
		}
		out = append(out, Conflict{
			Kind: ConflictRevokedKey, User: u.Name, Fingerprint: t.Fingerprint, Servers: c.serversRendering(u),
			Message: fmt.Sprintf("key %s of user %q is revoked (%s): remove it from users, or delete the revoked: entry to un-revoke it deliberately",
				t.Fingerprint, u.Name, t.Label()),
		})
	}
	for m, t := range c.Tombstones {
		if t.IsKey() {
			continue
		}
		out = append(out, c.accessConflicts(m, t)...)
	}
	return out
}

// accessConflicts: an access: entry for t's user that renders on one of
// t's (known) servers — named explicitly, or a wildcard that does not
// except it. One conflict per (entry, tombstoned server); Servers is every
// server that entry renders on (spec §2), so apply refuses, and audit
// marks critical, all of them.
func (c *Config) accessConflicts(m int, t Tombstone) []Conflict {
	var out []Conflict
	for n, a := range c.Access {
		if a.User != t.User {
			continue
		}
		covered := c.entryServers(a)
		for _, s := range t.Servers {
			if c.ignored[m][s] || !slices.Contains(covered, s) {
				continue
			}
			out = append(out, Conflict{
				Kind: ConflictRevokedAccess, User: t.User, Servers: slices.Clone(covered),
				Message: fmt.Sprintf("user %q is granted %q by access[%d], but revoked[%d] removed that access (%s): remove the grant, or delete the revoked: entry to restore it deliberately",
					t.User, s, n, m, t.Date),
			})
		}
	}
	return out
}

// entryServers lists, in servers: order, every server access entry a
// renders its user's keys on: its explicit names, or — for a wildcard —
// every server its except: does not name. Never nil.
func (c *Config) entryServers(a Access) []string {
	wildcard := slices.Contains(a.Servers, "*")
	out := []string{}
	for _, s := range c.Servers {
		if (wildcard && !slices.Contains(a.Except, s.Name)) || (!wildcard && slices.Contains(a.Servers, s.Name)) {
			out = append(out, s.Name)
		}
	}
	return out
}

// serversRendering lists, in servers: order, every server whose rendered
// file holds u's keys: all of them for an operator, else u's grants. Never
// nil (the JSON servers list is always present).
func (c *Config) serversRendering(u User) []string {
	out := []string{}
	for _, s := range c.Servers {
		if u.Operator || slices.Contains(c.grants[s.Name], u.Name) {
			out = append(out, s.Name)
		}
	}
	return out
}
```

In `config.go`, `Parse` (`:98-101`):

```go
	if err := c.validate(); err != nil {
		return nil, err
	}
	c.conflicts = c.computeConflicts()
	return &c, nil
```

- [ ] **Step 4: Run to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test -race ./internal/config/`
Expected: `ok`.

### Task 5: FuzzLoad seeds and properties for the new sections

**Files:**
- Modify: `internal/config/fuzz_test.go:20-70` (`FuzzLoad`)

- [ ] **Step 1: Add seeds and the property**

Append to `FuzzLoad`'s `seeds` slice (after the wildcard/operator seed):

```go
		// revocation memory: serial, key and access tombstones, a conflict, D1e
		"serial: 7\n" + manifest(k1, k2) + "revoked:\n  - {fingerprint: " + fpFor(f, k1) + ", user: alice, date: 2026-11-08, reason: offboarded}\n  - {user: bob, servers: [web-1, db-9], date: 2026-11-08}\n",
		"serial: -1\nusers: []\n",
		"revoked:\n  - {fingerprint: 'SHA256:x', servers: ['*'], date: '2026-1-8', user: \"a\\e\"}\n",
```

with a helper at the bottom of the file:

```go
func fpFor(tb testing.TB, line string) string {
	tb.Helper()
	k, err := authkeys.ParseLine(line)
	if err != nil || k == nil {
		tb.Fatalf("fpFor: %v", err)
	}
	return k.Fingerprint
}
```

Inside `f.Fuzz`, after the servers loop, add:

```go
		if cfg.Serial() > MaxSerial {
			t.Fatalf("accepted serial %d over %d", cfg.Serial(), MaxSerial)
		}
		names := make(map[string]bool, len(cfg.Servers))
		for _, s := range cfg.Servers {
			names[s.Name] = true
		}
		for _, tb := range cfg.Tombstones {
			for _, v := range []string{tb.User, tb.Reason} {
				if authkeys.RenderTextIssue(v) != "" || len(v) > maxTombstoneText {
					t.Fatalf("accepted tombstone text %q", v)
				}
			}
		}
		for _, c := range cfg.Conflicts() {
			for _, s := range c.Servers {
				if !names[s] {
					t.Fatalf("conflict %+v names unknown server %q", c, s)
				}
			}
		}
```

- [ ] **Step 2: Run the seeds and a short fuzz**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config/ -run FuzzLoad && GOTOOLCHAIN=go1.27.3 go test ./internal/config/ -run '^$' -fuzz '^FuzzLoad$' -fuzztime 30s`
Expected: `ok` both times. A crasher written under `testdata/fuzz/FuzzLoad/` is a real bug: fix it, keep the file only if it stays ≤ 4 KiB and the target stays ≤ 16 entries.

### Task 6: `manifest.GenerateWith` — the encoder carries `serial` and `revoked`

**Files:**
- Modify: `internal/manifest/manifest.go:308-388` (`requiredKeys`, `entryNode`, `Generate`)
- Test: `internal/manifest/manifest_test.go`, golden `internal/manifest/testdata/generate_memory.golden`

- [ ] **Step 1: Write the failing test**

```go
// TestGenerateWithMemory: serial is the first key (omitted at 0), revoked
// the last (omitted when empty); key and access tombstones keep only their
// own fields; the output loads back with the same memory.
func TestGenerateWithMemory(t *testing.T) {
	d := Draft{
		Serial:  7,
		Users:   []config.User{{Name: "alice", Keys: []string{testkeys.Line(t, 1)}}},
		Servers: []config.Server{{Name: "web-1", Host: "10.0.0.1", User: "deploy"}},
		Access:  []config.Access{{User: "alice", Servers: []string{"web-1"}}},
		Revoked: []config.Tombstone{
			{Fingerprint: keyFP(t, 9), User: "carol", Date: "2026-11-08", Reason: "offboarded"},
			{User: "alice", Servers: []string{"web-1"}, Date: "2026-11-08"},
		},
	}
	out, err := GenerateWith("# header\n", d)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "generate_memory.golden", out)
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("output does not load: %v\n%s", err, out)
	}
	if cfg.Serial() != 7 || !reflect.DeepEqual(cfg.Tombstones, d.Revoked) {
		t.Errorf("round trip = serial %d, %+v", cfg.Serial(), cfg.Tombstones)
	}
	plain, err := GenerateWith("", Draft{Users: d.Users})
	if err != nil || strings.Contains(string(plain), "serial") || strings.Contains(string(plain), "revoked") {
		t.Errorf("zero memory must emit neither key:\n%s", plain)
	}
}
```

(Add `"reflect"` and `"strings"` to the test imports if missing.)

- [ ] **Step 2: Run to see it fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/manifest/ -run TestGenerateWithMemory`
Expected: build failure (`undefined: Draft`).

- [ ] **Step 3: Implement**

Replace `requiredKeys` (`:308-312`) and the lookup in `entryNode` (`:333`):

```go
// requiredKeys are emitted even at their zero value, per config type (the
// loader requires them); every other field is omitempty. A new config field
// is therefore emitted by adopt, import and Append with no change here —
// and cmd/sshepherd/schema_roundtrip_test.go fails until it round-trips.
var requiredKeys = map[string]map[string]bool{
	"User":      {"name": true, "keys": true},
	"Server":    {"name": true, "host": true, "user": true},
	"Access":    {"user": true, "servers": true},
	"Tombstone": {"date": true},
}
```

```go
		if empty && !requiredKeys[rt.Name()][key] {
			continue
		}
```

Replace `Generate` (`:357-388`) with:

```go
// Draft is everything a generated manifest holds, in output order: serial
// (omitted at 0), users, servers, access, revoked (omitted when empty).
type Draft struct {
	Serial  uint64
	Users   []config.User
	Servers []config.Server
	Access  []config.Access
	Revoked []config.Tombstone
}

// Generate renders a fresh manifest with no revocation memory (import's
// drafts); see GenerateWith.
func Generate(header string, users []config.User, servers []config.Server, access []config.Access) ([]byte, error) {
	return GenerateWith(header, Draft{Users: users, Servers: servers, Access: access})
}

// GenerateWith renders a fresh manifest — header (raw comment lines with
// their own "#" and trailing newline), then d's sections — with the same
// encoder settings as Encode (2-space indent). It is the one renderer for
// adopt's and import's generated drafts; adopt passes the loaded manifest's
// serial and revoked: so a regenerate never erases revocation memory.
func GenerateWith(header string, d Draft) ([]byte, error) {
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	if d.Serial > 0 {
		root.Content = append(root.Content, strScalar("serial"),
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.FormatUint(d.Serial, 10)})
	}
	for _, sec := range []struct {
		key   string
		items func() ([]*yaml.Node, error)
	}{
		{"users", func() ([]*yaml.Node, error) { return entryNodes(d.Users) }},
		{"servers", func() ([]*yaml.Node, error) { return entryNodes(d.Servers) }},
		{"access", func() ([]*yaml.Node, error) { return entryNodes(d.Access) }},
	} {
		items, err := sec.items()
		if err != nil {
			return nil, err
		}
		root.Content = append(root.Content, strScalar(sec.key), &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: items})
	}
	if len(d.Revoked) > 0 {
		items, err := entryNodes(d.Revoked)
		if err != nil {
			return nil, err
		}
		root.Content = append(root.Content, strScalar("revoked"), &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: items})
	}
	var buf bytes.Buffer
	buf.WriteString(header)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}}); err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	return buf.Bytes(), nil
}
```

Add `"strconv"` to `manifest.go`'s imports, and extend the package comment's first paragraph: "Generate/GenerateWith render a fresh manifest (GenerateWith with serial: and revoked:)".

- [ ] **Step 4: Generate the golden, read it back, run**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/manifest/ -run TestGenerateWithMemory -update && cat internal/manifest/testdata/generate_memory.golden && GOTOOLCHAIN=go1.27.3 go test ./internal/manifest/`
Expected: the golden starts `# header`, then `serial: 7`, users/servers/access, and ends with a `revoked:` list whose key entry has `fingerprint`, `user`, `date: "2026-11-08"`, `reason` and whose access entry has `user`, `servers`, `date` only. Then `ok`.

### Task 7: adopt honours tombstones and never writes a wildcard (D2a, D1a, D5)

**Files:**
- Modify: `internal/adopt/adopt.go:19-25` (`NewUser`), `:65-146` (`Build`), `:224-257` (`nameUsers`); `cmd/sshepherd/adopt.go:35-51` (`extensionsAndGrants`)
- Test: `internal/adopt/adopt_test.go` (new tests; rewrite `TestBuildWildcardCompaction` `:203`, `TestBuildNoCompactionSingleServer` `:224`, `TestBuildDivergenceAndCompactionCompose` `:486`, `TestBuildUnreadableServerSuppressesCompaction` `:537`), `cmd/sshepherd/adopt_test.go:128-150` and `:300-312`, goldens `cmd/sshepherd/testdata/adopt_mixed.golden`, `adopt_merge.golden`

- [ ] **Step 1: Write the failing tests**

In `internal/adopt/adopt_test.go`, replace `TestBuildWildcardCompaction` with:

```go
// TestBuildNeverWildcards (D5): a key found on every server of the fleet is
// granted those servers by name — never "*", which would also grant every
// server added later — and adopt says nothing about wildcards.
func TestBuildNeverWildcards(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	everywhere := testkeys.Line(t, 7) + " carol@laptop"
	content := fleet.ReadResult{Content: []byte(op + "\n" + everywhere + "\n")}
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"db-1": content, "web-1": content, "web-2": content,
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 1 || !reflect.DeepEqual(p.NewUsers[0].FoundOn, []string{"db-1", "web-1", "web-2"}) {
		t.Fatalf("NewUsers = %+v, want one user found on all three servers", p.NewUsers)
	}
	for _, w := range p.Warnings {
		if strings.Contains(w, "wildcard") {
			t.Errorf("unexpected wildcard warning %q", w)
		}
	}
}
```

Delete `TestBuildNoCompactionSingleServer` (nothing compacts any more). In `TestBuildDivergenceAndCompactionCompose`, rename it `TestBuildDivergenceKeepsFirstCopy`, change the user check to `if len(p.NewUsers) != 1 || p.NewUsers[0].Line != first {` with message `"want one user keeping the first copy"`, and the tail to:

```go
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "differs") {
		t.Errorf("Warnings = %v, want one divergence note", p.Warnings)
	}
```

In `TestBuildUnreadableServerSuppressesCompaction`, rename it `TestBuildUnreadableServerListed`, and change the first check to `if len(p.NewUsers) != 1 || !reflect.DeepEqual(p.NewUsers[0].FoundOn, []string{"web-1", "web-2"}) {` with message `"want one user found on web-1 and web-2 (db-1 was unreadable)"`.

Add:

```go
// TestBuildSkipsRevokedKey (D2a): a tombstoned key found on a server is
// neither a new user nor an extension, with a loud warning naming the
// server and the apply that removes it; an Issue-free plan keeps adopt's
// exit code untouched.
func TestBuildSkipsRevokedKey(t *testing.T) {
	stale := testkeys.Line(t, 7)
	cfg := parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
revoked:
  - {fingerprint: `+fpOf(t, 7)+`, user: alice, date: 2026-11-08}
`)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n")},
		"web-2": {Content: []byte(testkeys.Line(t, 1) + "\n" + stale + " alice@laptop\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 0 || len(p.Extensions) != 0 || len(p.Issues) != 0 {
		t.Fatalf("plan = %+v, want nothing adopted and no issue", p)
	}
	want := "key " + fpOf(t, 7) + " on web-2 is REVOKED (2026-11-08, alice) — not adopted; run 'sshepherd apply --server web-2' to remove it"
	if len(p.Warnings) != 1 || p.Warnings[0] != want {
		t.Errorf("Warnings = %q\nwant [%q]", p.Warnings, want)
	}
}

// TestBuildHonoursAccessTombstone (D1a): bob's key found on db-1, whose
// access a revoke --server removed, is not re-granted.
func TestBuildHonoursAccessTombstone(t *testing.T) {
	cfg := parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: bob, keys: ["`+testkeys.Line(t, 2)+`"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy}
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: bob, servers: [web-1]}
revoked:
  - {user: bob, servers: [db-1], date: 2026-11-08}
`)
	both := fleet.ReadResult{Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n")}
	r := &fakeReader{byName: map[string]fleet.ReadResult{"db-1": both, "web-1": both}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Extensions) != 0 || len(p.NewUsers) != 0 {
		t.Fatalf("plan = %+v, want db-1 not re-granted", p)
	}
	want := "key " + fpOf(t, 2) + ` of "bob" found on "db-1", whose access was revoked (2026-11-08) — not re-granted; audit flags this drift`
	if len(p.Warnings) != 1 || p.Warnings[0] != want {
		t.Errorf("Warnings = %q\nwant [%q]", p.Warnings, want)
	}
}
```

with the helper (`adopt_test.go` has none; add `"github.com/javadh75/SSHepherd/internal/authkeys"` to its imports — the file imports only `audit`, `config`, `fleet` and `testkeys` today):

```go
func fpOf(t *testing.T, seed byte) string {
	t.Helper()
	k, err := authkeys.ParseLine(testkeys.Line(t, seed))
	if err != nil || k == nil {
		t.Fatalf("fpOf(%d): %v", seed, err)
	}
	return k.Fingerprint
}
```

In `cmd/sshepherd/adopt_test.go`, `TestGenerateAdoptManifestMixedGolden` (`:122-150`): leave `:134` (`op(1) + bob wildcard(1) + …` — bob's grant really is a wildcard) alone; change `:138` `op(1) + carol wildcard(1) + adopted-key-1(1) = 3` → `op(1) + carol(1) + adopted-key-1(1) = 3`; and replace the stale comment at `:143` and the warning check (`:143-146`) with:

```go
	// bob's carve-out warns; carol is listed by name (D5), with no warning.
	if len(plan.Warnings) != 1 {
		t.Errorf("Warnings = %v, want one (except carve-out)", plan.Warnings)
	}
```

and add after it (add `"reflect"` to `cmd/sshepherd/adopt_test.go`'s imports — it has none today):

```go
// TestAdoptMergeNoWildcard (D5): the merged manifest lists carol's three
// servers by name.
func TestAdoptMergeNoWildcard(t *testing.T) {
	src := commentedMergeSrc(t)
	mf, err := manifest.Load(src)
	if err != nil {
		t.Fatal(err)
	}
	got, err := renderMergedManifest(mf, src, adoptPlan(t, mf.Config(), mixedReader(t)), nil, "2026-07-16")
	if err != nil {
		t.Fatal(err)
	}
	out, err := config.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range out.Access {
		if a.User == "carol-laptop" && !reflect.DeepEqual(a.Servers, []string{"db-1", "web-1", "web-2"}) {
			t.Errorf("carol-laptop servers = %v, want the three names", a.Servers)
		}
	}
}
```

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/adopt/ ./cmd/sshepherd/ -run 'TestBuild|TestAdoptMergeNoWildcard|TestGenerateAdoptManifestMixedGolden'`
Expected: FAIL — `TestBuildSkipsRevokedKey` adopts the key, `TestBuildHonoursAccessTombstone` extends bob, wildcard tests still see `["*"]`.

- [ ] **Step 3: Implement**

`internal/adopt/adopt.go`: delete the `Wildcard` field from `NewUser` (`:24`). In `Build`'s unauthorized loop, insert before `k, err := honoredLine(…)` (`:90`):

```go
			// Revocation memory first (D2a): a tombstoned key is never
			// adopted — not even as an Issue that would move adopt's exit
			// code — whatever its lines look like.
			if w, revoked := revokedWarning(cfg, r.Server.Name, first.Fingerprint); revoked {
				p.Warnings = append(p.Warnings, w)
				continue
			}
```

and replace the known-owner block (`:96-108`) with:

```go
			if owner, known := cfg.OwnerOf(k.Fingerprint); known {
				if w, skip := ownerSkip(cfg, owner.Name, r.Server.Name, k.Fingerprint); skip {
					p.Warnings = append(p.Warnings, w)
					continue
				}
				if extByUser[owner.Name] == nil {
					extByUser[owner.Name] = make(map[string]bool)
				}
				extByUser[owner.Name][r.Server.Name] = true
				continue
			}
```

Add the helpers after `Build`:

```go
// revokedWarning reports a key the manifest's revoked: list remembers.
func revokedWarning(cfg *config.Config, server, fp string) (string, bool) {
	t, ok := cfg.Revoked(fp)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("key %s on %s is REVOKED (%s) — not adopted; run 'sshepherd apply --server %s' to remove it",
		fp, server, t.Label(), server), true
}

// ownerSkip reports why a known owner's key found on server is not an
// access extension: their except: list excludes the server, or an access
// tombstone removed it (D1a). Either way audit flags the key as drift.
func ownerSkip(cfg *config.Config, owner, server, fp string) (string, bool) {
	if cfg.ExceptCarveOut(owner, server) {
		return fmt.Sprintf("key %s of %q found on %q, which their except: list deliberately excludes — not re-granted; audit flags this drift",
			fp, owner, server), true
	}
	if t, ok := cfg.AccessRevoked(owner, server); ok {
		return fmt.Sprintf("key %s of %q found on %q, whose access was revoked (%s) — not re-granted; audit flags this drift",
			fp, owner, server, t.Date), true
	}
	return "", false
}
```

Replace `nameUsers` (`:224-257`) and its call (`:142-144`):

```go
	p.Extensions = extensions(cfg, extByUser)
	p.NewUsers = nameUsers(cfg, byFP, order)
	return p
```

```go
// nameUsers turns accumulated unknown keys into named users, resolving
// collisions against manifest names and each other with numeric suffixes
// (the allocator import uses too, see internal/naming). Each user is
// granted exactly the servers its key was found on, by name: never "*",
// which would also grant servers added later (D5).
func nameUsers(cfg *config.Config, byFP map[string]*pending, order []string) []NewUser {
	taken := make(map[string]bool, len(cfg.Users))
	for _, u := range cfg.Users {
		taken[u.Name] = true
	}
	users := make([]NewUser, 0, len(order))
	for _, fp := range order {
		pd := byFP[fp]
		var name string
		if base := sanitizeName(pd.comment); base != "" {
			name, _ = naming.Claim(taken, base)
		} else {
			// Continue numbering past earlier runs' adopted-key-<n>
			// (adopt --merge) instead of restarting at 1 and stacking a
			// suffix onto it.
			name = naming.ClaimNumbered(taken, "adopted-key-")
		}
		sort.Strings(pd.foundOn)
		users = append(users, NewUser{Name: name, Line: pd.line, FoundOn: pd.foundOn})
	}
	return users
}
```

Update the package comment's first sentence ending to "…become new users with access to exactly the servers where they were found (never a wildcard)".

`cmd/sshepherd/adopt.go`, `extensionsAndGrants` (`:35-51`):

```go
// extensionsAndGrants is the plan's access additions: extensions of known
// users first, then each new user's grant — the servers it was found on, by
// name (never "*", D5).
func extensionsAndGrants(plan adopt.Plan) []config.Access {
	access := make([]config.Access, 0, len(plan.Extensions)+len(plan.NewUsers))
	for _, e := range plan.Extensions {
		access = append(access, config.Access{User: e.User, Servers: e.Servers})
	}
	for _, nu := range plan.NewUsers {
		access = append(access, config.Access{User: nu.Name, Servers: nu.FoundOn})
	}
	return access
}
```

In `TestRenderMergedManifestGolden` (`cmd/sshepherd/adopt_test.go:300-312`) change the comment "op + bob(wildcard) + alice(extension, 2 keys) + carol" to "op + bob(wildcard grant) + alice(extension, 2 keys) + carol (listed by name)"; the counts stay 5 and 3.

- [ ] **Step 4: Regenerate the two adopt goldens and run**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestGenerateAdoptManifestMixedGolden|TestRenderMergedManifestGolden' -update && git diff cmd/sshepherd/testdata/ && GOTOOLCHAIN=go1.27.3 go test ./internal/adopt/ ./cmd/sshepherd/`
Expected: the diff of `adopt_mixed.golden` and `adopt_merge.golden` replaces carol-laptop's `- '*'` with `- db-1`, `- web-1`, `- web-2` and nothing else. Then `ok`.

### Task 8: `import --merge` honours tombstones (reconcile)

**Files:**
- Modify: `internal/reconcile/reconcile.go:182-201` (`users`), `:210-250` (`knownKey`)
- Test: `internal/reconcile/reconcile_test.go`

- [ ] **Step 1: Write the failing tests**

```go
// TestReconcileSkipsRevokedPub (D2a for import --merge): a tombstoned
// incoming .pub is neither a new user nor an extension.
func TestReconcileSkipsRevokedPub(t *testing.T) {
	k9 := testkeys.Line(t, 9)
	fp9 := mustFP(t, k9)
	cfg := parseCfg(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
revoked:
  - {fingerprint: `+fp9+`, user: alice, date: 2026-11-08}
`)
	p := mustBuild(t, cfg, nil, []identity.User{{Name: "me-id_old", Source: "~/.ssh/id_old", Key: k9, Servers: []string{"web-1"}}})
	if !p.Empty() {
		t.Fatalf("plan = %+v, want nothing imported", p)
	}
	// IDENTITY is the .pub the import read (plan decision 13, spec §9).
	wantContains(t, "Warnings", p.Warnings, "key "+fp9+" from ~/.ssh/id_old.pub is REVOKED (2026-11-08, alice) — not imported")
	if p.ConflictsSkipped() != 1 {
		t.Errorf("ConflictsSkipped = %d, want 1", p.ConflictsSkipped())
	}
	// An IdentityFile that already names the .pub is printed as is.
	q := mustBuild(t, cfg, nil, []identity.User{{Name: "me-id_old", Source: "~/.ssh/id_old.pub", Key: k9, Servers: []string{"web-1"}}})
	wantContains(t, "Warnings", q.Warnings, "key "+fp9+" from ~/.ssh/id_old.pub is REVOKED (2026-11-08, alice) — not imported")
}

// TestReconcileHonoursAccessTombstone (D1a): a known key used for a server
// whose access was revoked is never extended there.
func TestReconcileHonoursAccessTombstone(t *testing.T) {
	cfg := parseCfg(t, `
users:
  - {name: bob, keys: ["`+testkeys.Line(t, 4)+`"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy}
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: bob, servers: [web-1]}
revoked:
  - {user: bob, servers: [db-1], date: 2026-11-08}
`)
	p := mustBuild(t, cfg, nil, []identity.User{{Name: "bob", Source: "~/.ssh/id_bob", Key: testkeys.Line(t, 4), Servers: []string{"db-1"}}})
	if len(p.Extensions) != 0 {
		t.Fatalf("Extensions = %+v, want none", p.Extensions)
	}
	wantContains(t, "Warnings", p.Warnings,
		"key "+mustFP(t, testkeys.Line(t, 4))+` of "bob" found on "db-1", whose access was revoked (2026-11-08) — not re-granted; audit flags this drift`)
}
```

with, if the file lacks it:

```go
func mustFP(t *testing.T, line string) string {
	t.Helper()
	k, err := authkeys.ParseLine(line)
	if err != nil || k == nil {
		t.Fatalf("mustFP: %v", err)
	}
	return k.Fingerprint
}
```

(import `github.com/javadh75/SSHepherd/internal/authkeys` in the test file.)

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/reconcile/ -run 'Revoked|AccessTombstone'`
Expected: FAIL — the revoked .pub becomes a new user; bob is extended to db-1.

- [ ] **Step 3: Implement**

In `users` (`:183-201`), insert after the nil-key check and before `OwnerOf`:

```go
		if t, revoked := b.cfg.Revoked(k.Fingerprint); revoked {
			b.plan.conflicts++
			b.plan.Warnings = append(b.plan.Warnings, fmt.Sprintf(
				"key %s from %s is REVOKED (%s) — not imported", k.Fingerprint, pubPath(u.Source), t.Label()))
			continue
		}
```

and add:

```go
// pubPath is the .pub an identity was read from, as written: the
// IdentityFile value itself when it already names the .pub, else value +
// ".pub" (internal/identity's pubPaths rule; only .pub files are read).
func pubPath(source string) string {
	if strings.HasSuffix(source, ".pub") {
		return source
	}
	return source + ".pub"
}
```

In `knownKey`'s switch (`:221-235`), replace the `default:` arm with:

```go
		default:
			if t, gone := b.cfg.AccessRevoked(owner.Name, srv); gone {
				b.plan.conflicts++
				b.plan.Warnings = append(b.plan.Warnings, fmt.Sprintf(
					"key %s of %q found on %q, whose access was revoked (%s) — not re-granted; audit flags this drift",
					fp, owner.Name, srv, t.Date))
				continue
			}
			extended = b.extend(owner.Name, srv) || extended
```

and add to `knownKey`'s doc comment: "…except carve-out (never re-granted), an access tombstone (never re-granted, D1a), else an extension pair."

- [ ] **Step 4: Run to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test -race ./internal/reconcile/`
Expected: `ok`.

### Task 9: cmd — regenerate keeps memory, saving commands refuse conflicts, footers

**Files:**
- Create: `cmd/sshepherd/conflicts.go`, `cmd/sshepherd/conflicts_test.go`
- Modify: `cmd/sshepherd/adopt.go:53-69` (`generateAdoptManifest`), `:312-315` (self-check); `cmd/sshepherd/import.go:415-418` (self-check); `cmd/sshepherd/run.go:210-222` (`exitCodesAdopt`, `exitCodesImport`)
- Test: `cmd/sshepherd/schema_roundtrip_test.go`, `cmd/sshepherd/adopt_test.go`, `cmd/sshepherd/import_merge_test.go`; goldens `cmd/sshepherd/testdata/help/adopt.golden`, `import.golden`

- [ ] **Step 1: Write the failing tests**

Append to `cmd/sshepherd/schema_roundtrip_test.go`:

```go
// TestAdoptRegenerateKeepsRevokedAndSerial: a plain adopt rebuilds the
// manifest from structs; it must carry serial: and every revoked: field, or
// one adopt would erase all revocation memory (PRD-1). Every Tombstone
// field needs a sample (fill fails otherwise).
func TestAdoptRegenerateKeepsRevokedAndSerial(t *testing.T) {
	cfg, _, _, _ := roundTripConfig(t)
	key := fill[config.Tombstone](t, map[string]map[string]any{"Tombstone": {
		"Fingerprint": fpOf(t, 9), "User": "carol", "Servers": []string(nil),
		"Date": "2026-11-08", "Reason": "offboarded",
	}})
	access := config.Tombstone{User: "bob", Servers: []string{"web-2"}, Date: "2026-11-08", Reason: "moved teams"}
	cfg.ManifestSerial = 7
	cfg.Tombstones = []config.Tombstone{key, access}
	out, err := generateAdoptManifest(cfg, adopt.Plan{}, "rt.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := config.Parse(out)
	if err != nil {
		t.Fatalf("adopt output does not load: %v\n%s", err, out)
	}
	if got.Serial() != 7 || !reflect.DeepEqual(got.Tombstones, cfg.Tombstones) {
		t.Errorf("adopt lost memory: serial %d, revoked %+v\n%s", got.Serial(), got.Tombstones, out)
	}
}
```

(`fill` sets every exported field from the sample, so `Servers: []string(nil)` is a valid sample for a key tombstone. `fpOf` is `cmd/sshepherd/keyarg_test.go`'s helper.)

Append to `cmd/sshepherd/adopt_test.go` (spec §5 and Threat notes: "adopt never copies a server's header serial into the manifest"):

```go
// TestAdoptNeverCopiesHeaderSerial: servers whose files claim "(serial 99)"
// never move the manifest's serial: regenerate emits the loaded manifest's
// value (7), or no serial: at all when it had none. A regression pin — it
// passes at once (adopt reads no header today) and guards the threat note;
// mutation: emit Serial: 99 in generateAdoptManifest → FAIL.
func TestAdoptNeverCopiesHeaderSerial(t *testing.T) {
	// The literal header line: lane header's authkeys.Header lands in the
	// same round, so this lane cannot call it.
	const claims = "# Managed by SSHepherd (serial 99). Manual edits will be overwritten by 'sshepherd apply'."
	r := mixedReader(t)
	for name, res := range r.byName {
		res.Content = append([]byte(claims+"\n"), res.Content...)
		r.byName[name] = res
	}
	for _, serial := range []uint64{7, 0} {
		cfg := mixedCfg(t)
		cfg.ManifestSerial = config.Serial(serial)
		out, err := generateAdoptManifest(cfg, adoptPlan(t, cfg, r), "sshepherd.yaml", nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := config.Parse(out)
		if err != nil {
			t.Fatalf("adopt output does not load: %v\n%s", err, out)
		}
		if got.Serial() != serial || (serial == 0 && strings.Contains(string(out), "serial:")) {
			t.Errorf("manifest serial %d: adopt emitted serial %d\n%s", serial, got.Serial(), out)
		}
	}
}
```

Create `cmd/sshepherd/conflicts_test.go`:

```go
package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// conflictedManifest lists alice's key and also remembers it as revoked: a
// D29 policy conflict. No servers, so adopt needs no credentials.
func conflictedManifest(t *testing.T) (path, fp string) {
	t.Helper()
	fp = fpOf(t, 1)
	return writeConfig(t, "users:\n  - {name: alice, keys: [\""+testkeys.Line(t, 1)+"\"]}\n"+
		"revoked:\n  - {fingerprint: "+fp+", user: alice, date: 2026-11-08}\n"), fp
}

// TestSaveRefusedWhileConflictRemains (D29): adopt (both modes) and import
// --merge refuse, exit 3, writing nothing, while the manifest they would
// write still has a policy conflict.
func TestSaveRefusedWhileConflictRemains(t *testing.T) {
	path, fp := conflictedManifest(t)
	want := "refusing to write the manifest — it would keep 1 policy conflict: key " + fp + ` of user "alice" is revoked (2026-11-08, alice)`
	for name, args := range map[string][]string{
		"adopt":         {"adopt", "--config", path},
		"adopt --merge": {"adopt", "--merge", "--config", path},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("SSH_AUTH_SOCK", "")
			var out, errBuf bytes.Buffer
			if code := run(args, &out, &errBuf); code != 3 {
				t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
			}
			if out.Len() != 0 || !strings.Contains(errBuf.String(), want) {
				t.Errorf("stdout %q; stderr %q, want %q", out.String(), errBuf.String(), want)
			}
		})
	}
	t.Run("import --merge", func(t *testing.T) {
		hermeticHome(t)
		sshCfg := writeSSHConfig(t, "Host web-1\n  User deploy\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"import", sshCfg, "--merge", path, "--servers-only"}, &out, &errBuf); code != 3 {
			t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
		}
		if out.Len() != 0 || !strings.Contains(errBuf.String(), want) {
			t.Errorf("stdout %q; stderr %q", out.String(), errBuf.String())
		}
	})
}
```

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestAdoptRegenerateKeepsRevokedAndSerial|TestSaveRefusedWhileConflictRemains|TestAdoptNeverCopiesHeaderSerial'`
Expected: FAIL — regenerate drops `serial`/`revoked` (so `TestAdoptNeverCopiesHeaderSerial`'s serial-7 row fails too, until `generateAdoptManifest` passes `cfg.Serial()`); adopt and import exit 0.

- [ ] **Step 3: Implement**

Create `cmd/sshepherd/conflicts.go`:

```go
package main

import (
	"fmt"
	"strings"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/config"
)

// conflictRefusal is the save refusal of every command that writes the
// manifest — revoke, rotate, adopt (both modes), import --merge (D29): nil
// when cfg, the manifest as it would be written, has no policy conflict;
// otherwise one error naming every conflict (exit 3, nothing written). An
// edit that resolves the conflicts passes, so 'sshepherd revoke --key FP'
// of a revoked key still listed is the natural fix.
func conflictRefusal(cfg *config.Config) error {
	cs := cfg.Conflicts()
	if len(cs) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(cs))
	for _, c := range cs {
		msgs = append(msgs, c.Message)
	}
	return fmt.Errorf("refusing to write the manifest — it would keep %s: %s",
		apply.Plural(len(cs), "policy conflict", "policy conflicts"), strings.Join(msgs, "; "))
}
```

`cmd/sshepherd/adopt.go`: `generateAdoptManifest`'s return (`:68`) becomes:

```go
	return manifest.GenerateWith(header.String(), manifest.Draft{ //nolint:wrapcheck // "encode manifest: …"
		Serial: cfg.Serial(), Users: users, Servers: cfg.Servers, Access: access, Revoked: cfg.Tombstones,
	})
```

and its doc comment gains: "serial: and revoked: are copied from the loaded manifest (never from a server's header), so regenerating never erases revocation memory." The self-check (`:312-315`) becomes:

```go
			// Self-check: never emit a manifest our own loader would reject,
			// nor one that keeps a policy conflict (D29).
			saved, err := config.Parse(rendered)
			if err != nil {
				return fmt.Errorf("bug: generated manifest fails validation: %w", err)
			}
			if err := conflictRefusal(saved); err != nil {
				return err
			}
```

`cmd/sshepherd/import.go` (`:415-418`) the same:

```go
			// Self-check: never emit a manifest our own loader would reject,
			// nor (under --merge) one that keeps a policy conflict (D29).
			saved, err := config.Parse(rendered)
			if err != nil {
				return fmt.Errorf("bug: generated manifest fails validation: %w", err)
			}
			if err := conflictRefusal(saved); err != nil {
				return err
			}
```

`cmd/sshepherd/run.go`, the two footers:

```go
const exitCodesAdopt = `Exit codes:
  0  manifest emitted
  1  a server could not be fully read and --partial was not given (nothing
     emitted), or --partial could not read some servers (the partial manifest
     is emitted)
  3  tool error: bad flags, unloadable manifest, failed preflight, an existing
     --output without --force, an in-place save refused, a manifest that
     would keep a policy conflict, --partial with no server read, interrupted`

const exitCodesImport = `Exit codes:
  0  manifest emitted
  3  tool error: bad flags, unreadable ssh config or --merge manifest, an
     existing --output without --force, an in-place save refused, a --merge
     manifest that would keep a policy conflict`
```

- [ ] **Step 4: Regenerate the help goldens, apply the README delta locally, run**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run TestHelpGolden -update && git diff cmd/sshepherd/testdata/help/`
Expected: only the footer lines of `adopt.golden` and `import.golden` change.

Apply this lane's README delta (below) to the worktree's `README.md`, then:
Run: `GOTOOLCHAIN=go1.27.3 go test -race ./cmd/sshepherd/ ./internal/... && make check`
Expected: all `ok`; `make check` green (deadcode finds `Serial`, `Revoked`, `AccessRevoked`, `Conflicts`, `Label`, `GenerateWith` reachable).

- [ ] **Step 5: Hand back** (lane `schema`; the integrator commits `feat(config): revocation memory schema — revoked:, serial:, policy conflicts; adopt/import honour it (P04 W4, PRD-1, SEC-3)`)

**docsDelta (lane `schema`):**
- README `## The manifest`: add `serial: 7` as the first key and a `revoked:` list (one key and one access entry, the spec §1 example) at the end of the annotated example.
- README: new `### Revoked keys` after `### Comment policy`: "`revoked:` is the manifest's memory of every revoke. A key entry (`fingerprint`, optional `user` label, `date`, optional `reason`) means that key may never be listed in `users:` again, and adopt and `import --merge` never bring it back; an access entry (`user`, `servers`, `date`, optional `reason`) means that user is never re-granted those servers. `revoke` and `rotate` append entries; deleting one by hand is a deliberate un-revoke (git history is the audit trail). A server removed from `servers:` but still named in an access entry is a warning — `revoked[N]: unknown server "NAME" — this entry is ignored for it; remove NAME from the entry once the server is gone for good` — never a load error; re-adding the server re-applies the entry."
- README `### Validation rules`: add the spec §2 shape rules (one bullet each, messages verbatim); a bullet for the D1e warning — "a server named in an access entry of `revoked:` that is not in `servers:` is a warning, not a load error: `revoked[N]: unknown server "NAME" — this entry is ignored for it; remove NAME from the entry once the server is gone for good` (the entry is ignored for that server; re-adding the server re-applies it)"; and a paragraph "Policy conflicts are not load errors: a revoked key still listed, or a grant over an access tombstone, loads; `audit` reports it critical (exit 2), `apply` refuses the servers involved (exit 1), and `adopt`, `import --merge`, `revoke` and `rotate` refuse to write a manifest that would keep one (exit 3)", plus the two conflict messages verbatim.
- README `### sshepherd adopt`: "Unknown keys are granted the servers where they were found, by name — never `["*"]`, which would also grant servers added later." and "A key the manifest's `revoked:` list remembers is skipped with a warning (`key SHA256:… on web-2 is REVOKED (2026-11-08, alice) — not adopted; run 'sshepherd apply --server web-2' to remove it`), and so is a known key on a server whose access was revoked; adopt's exit code is unchanged." Re-copy the regenerate and merge samples from `cmd/sshepherd/testdata/adopt_mixed.golden` / `adopt_merge.golden`. Adopt keeps `serial:` and `revoked:` in both modes.
- README `### sshepherd import` `--merge`: "A `.pub` whose key is revoked is skipped, and a revoked (user, server) pair is never re-extended." with the warning line copied from a captured `import --merge` run (shape: `key SHA256:… from ~/.ssh/id_old.pub is REVOKED (2026-11-08, alice) — not imported`).
- README `## Exit codes`: replace the `adopt --help` and `import --help` blocks with the new `exitCodesAdopt` / `exitCodesImport` text verbatim.

---
## Round 1 — lane `header` (Tasks 10–15)

Owns: `internal/authkeys/header*.go`, `internal/authkeys/render.go`, `internal/authkeys/render_test.go`, `internal/authkeys/fuzz_test.go`, `internal/authkeys/testdata/fuzz/FuzzParseHeader/*`, `internal/fleet/**`, `internal/sshwrite/**`, `internal/sshread/**`, `internal/apply/plan.go`, `internal/apply/plan_test.go`. Findings: PRD-2. `needsIntegration: true` (Task 15).

### Task 10: the header grammar (`Header`, `ParseHeader`, `ParseHeaderOf`, `RenderSerial`)

**Files:**
- Create: `internal/authkeys/header.go`, `internal/authkeys/header_test.go`
- Modify: `internal/authkeys/render.go:11-14` (`ManagedHeader`), `:50-67` (`Render`)
- Test: `internal/authkeys/render_test.go`

- [ ] **Step 1: Write the failing tests**

`internal/authkeys/header_test.go`:

```go
package authkeys

import (
	"strconv"
	"testing"
)

const legacy = "# Managed by SSHepherd. Manual edits will be overwritten by 'sshepherd apply'."

func serialLine(digits string) string {
	return "# Managed by SSHepherd (serial " + digits + "). Manual edits will be overwritten by 'sshepherd apply'."
}

// parseHeaderCases is the spec §3 table of first lines. TestParseHeader
// and TestSnapshotManagedMatchesParseHeader (Task 12) both iterate it.
var parseHeaderCases = []struct {
	name    string
	line    string
	serial  uint64
	managed bool
}{
	{"legacy", legacy, 0, true},
	{"serial 7", serialLine("7"), 7, true},
	{"max serial", serialLine("9007199254740991"), MaxHeaderSerial, true},
	{"over max", serialLine("9007199254740992"), 0, false},
	{"17 digits", serialLine("12345678901234567"), 0, false},
	{"leading zero", serialLine("07"), 0, false},
	{"zero", serialLine("0"), 0, false},
	{"negative", serialLine("-1"), 0, false},
	{"trailing space", legacy + " ", 0, false},
	{"trailing CR", legacy + "\r", 0, false},
	{"prefix lookalike", "# Managed by SSHepherd-ish. Manual edits will be overwritten by 'sshepherd apply'.", 0, false},
	{"hand written", "ssh-ed25519 AAAA x", 0, false},
	{"empty", "", 0, false},
}

func TestParseHeader(t *testing.T) {
	for _, tt := range parseHeaderCases {
		t.Run(tt.name, func(t *testing.T) {
			s, m := ParseHeader(tt.line)
			if s != tt.serial || m != tt.managed {
				t.Errorf("ParseHeader(%q) = (%d, %v), want (%d, %v)", tt.line, s, m, tt.serial, tt.managed)
			}
		})
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	if Header(0) != ManagedHeader || ManagedHeader != legacy {
		t.Fatalf("Header(0) = %q, want the legacy bytes", Header(0))
	}
	for _, n := range []uint64{1, 7, 1000, MaxHeaderSerial} {
		if got := Header(n); got != serialLine(strconv.FormatUint(n, 10)) {
			t.Errorf("Header(%d) = %q", n, got)
		}
		if s, m := ParseHeader(Header(n)); s != n || !m {
			t.Errorf("ParseHeader(Header(%d)) = (%d, %v)", n, s, m)
		}
	}
}

func TestParseHeaderOf(t *testing.T) {
	for _, tt := range []struct {
		content string
		serial  uint64
		managed bool
	}{
		{Header(5) + "\nssh-ed25519 AAAA x\n", 5, true},
		{legacy + "\n", 0, true},
		{legacy, 0, true}, // no newline: the whole content is the first line
		{"ssh-ed25519 AAAA x\n" + Header(5) + "\n", 0, false},
		{"", 0, false},
	} {
		if s, m := ParseHeaderOf([]byte(tt.content)); s != tt.serial || m != tt.managed {
			t.Errorf("ParseHeaderOf(%q) = (%d, %v), want (%d, %v)", tt.content, s, m, tt.serial, tt.managed)
		}
	}
}
```

Append to `internal/authkeys/render_test.go`:

```go
// TestRenderSerialZeroIsLegacyBytes: serial 0 renders today's file byte for
// byte, so fleets that never revoke see no churn on upgrade.
func TestRenderSerialZeroIsLegacyBytes(t *testing.T) {
	e := []RenderEntry{{Key: mustKey(t, testkeys.Line(t, 1)), Comment: "a"}}
	old, err := Render(e)
	if err != nil {
		t.Fatal(err)
	}
	zero, err := RenderSerial(e, 0)
	if err != nil || !bytes.Equal(old, zero) || !bytes.HasPrefix(zero, []byte(ManagedHeader+"\n")) {
		t.Fatalf("RenderSerial(…, 0) = %q, %v; want Render's bytes %q", zero, err, old)
	}
}

func TestRenderSerialHeader(t *testing.T) {
	e := []RenderEntry{{Key: mustKey(t, testkeys.Line(t, 1)), Comment: "a"}}
	out, err := RenderSerial(e, 7)
	want := "# Managed by SSHepherd (serial 7). Manual edits will be overwritten by 'sshepherd apply'.\n" + testkeys.Line(t, 1) + " a\n"
	if err != nil || string(out) != want {
		t.Fatalf("RenderSerial = %q, %v\nwant %q", out, err, want)
	}
}
```

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/authkeys/ -run 'Header|RenderSerial'`
Expected: build failure (`undefined: ParseHeader`).

- [ ] **Step 3: Implement**

Create `internal/authkeys/header.go`:

```go
package authkeys

import (
	"bytes"
	"regexp"
	"strconv"
)

// MaxHeaderSerial is the largest serial a managed header may carry: 2^53-1,
// config.MaxSerial (internal/apply pins the two equal).
const MaxHeaderSerial = 1<<53 - 1

// ForgedMargin: a header serial more than this above the manifest's serial
// counts as forged (spec 2026-11-08 §3 row 1). audit reports it critical;
// apply treats it as no serial and rewrites the header.
const ForgedMargin = 1000

// headerTail is the fixed text after the optional serial.
const headerTail = ". Manual edits will be overwritten by 'sshepherd apply'."

// headerRE is the only managed first line: anchored, a serial of 1 to 16
// digits with no leading zero, nothing before or after. The first line is
// remote-controlled input, so it is matched, never evaluated.
var headerRE = regexp.MustCompile(`^# Managed by SSHepherd(?: \(serial ([1-9][0-9]{0,15})\))?\. Manual edits will be overwritten by 'sshepherd apply'\.$`)

// Header is the managed first line for serial: ManagedHeader (the legacy
// bytes) at 0, else "# Managed by SSHepherd (serial N). …".
func Header(serial uint64) string {
	if serial == 0 {
		return ManagedHeader
	}
	return "# Managed by SSHepherd (serial " + strconv.FormatUint(serial, 10) + ")" + headerTail
}

// ParseHeader reads a file's first line: (0, true) for the legacy header,
// (N, true) for a "(serial N)" header, (0, false) for anything else —
// including a serial over MaxHeaderSerial, a leading zero, "(serial 0)",
// or trailing whitespace or a carriage return.
func ParseHeader(firstLine string) (serial uint64, managed bool) {
	m := headerRE.FindStringSubmatch(firstLine)
	if m == nil {
		return 0, false
	}
	if m[1] == "" {
		return 0, true
	}
	v, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil || v > MaxHeaderSerial {
		return 0, false
	}
	return v, true
}

// ParseHeaderOf is ParseHeader on content's first line (the text before the
// first newline; all of content when it has none).
func ParseHeaderOf(content []byte) (serial uint64, managed bool) {
	first, _, _ := bytes.Cut(content, []byte("\n"))
	return ParseHeader(string(first))
}
```

`internal/authkeys/render.go`: the constant (`:11-14`) becomes

```go
// ManagedHeader is the legacy first line of every rendered file — the
// header at serial 0 (see Header). Deliberately undated: output stays
// byte-stable and golden-testable, so a repeated apply is a byte-for-byte
// no-op (2026-07-19 apply spec, owner-approved; amended 2026-11-08).
const ManagedHeader = "# Managed by SSHepherd" + headerTail
```

and `Render` (`:50-67`):

```go
// Render renders the managed file at serial 0 (the legacy header); see
// RenderSerial.
func Render(entries []RenderEntry) ([]byte, error) { return RenderSerial(entries, 0) }

// RenderSerial renders the complete managed authorized_keys file: the
// managed header for serial (Header), one line per entry in order, trailing
// newline. Deterministic — equal input yields byte-identical output; apply's
// convergence test and its idempotency both hang on this.
func RenderSerial(entries []RenderEntry, serial uint64) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(Header(serial))
	b.WriteByte('\n')
	for _, e := range entries {
		line, err := RenderLine(e)
		if err != nil {
			return nil, err
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}
```

- [ ] **Step 4: Run to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test -race ./internal/authkeys/`
Expected: `ok` (the existing render goldens are unchanged).

### Task 11: `FuzzParseHeader`

**Files:**
- Modify: `internal/authkeys/fuzz_test.go`
- Create: `internal/authkeys/testdata/fuzz/FuzzParseHeader/{legacy,serial7,max,leadingzero}`

- [ ] **Step 1: Write the target**

Append to `internal/authkeys/fuzz_test.go`:

```go
// FuzzParseHeader: ParseHeader never panics; the only lines it accepts are
// exactly Header(n) (so the .orig decision and the serial rows can never
// disagree with what Render writes); and any in-range serial rendered by
// RenderSerial parses back.
func FuzzParseHeader(f *testing.F) {
	f.Add(ManagedHeader, uint64(0))
	f.Add(Header(7), uint64(7))
	f.Add("# Managed by SSHepherd (serial 07). Manual edits will be overwritten by 'sshepherd apply'.", uint64(1<<63))
	f.Add(ManagedHeader+"\r", uint64(MaxHeaderSerial))
	f.Fuzz(func(t *testing.T, line string, n uint64) {
		s, managed := ParseHeader(line)
		if !managed && s != 0 {
			t.Fatalf("ParseHeader(%q) = (%d, false): an unmanaged line has no serial", line, s)
		}
		if managed && Header(s) != line {
			t.Fatalf("ParseHeader(%q) accepted a line Header(%d) = %q does not write", line, s, Header(s))
		}
		m := n % (MaxHeaderSerial + 1)
		out, err := RenderSerial(nil, m)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := ParseHeaderOf(out); got != m || !ok {
			t.Fatalf("ParseHeaderOf(RenderSerial(nil, %d)) = (%d, %v)", m, got, ok)
		}
	})
}
```

Create the committed seed corpus (four files, each exactly as shown):

`internal/authkeys/testdata/fuzz/FuzzParseHeader/legacy`:
```
go test fuzz v1
string("# Managed by SSHepherd. Manual edits will be overwritten by 'sshepherd apply'.")
uint64(0)
```
`…/serial7`:
```
go test fuzz v1
string("# Managed by SSHepherd (serial 7). Manual edits will be overwritten by 'sshepherd apply'.")
uint64(7)
```
`…/max`:
```
go test fuzz v1
string("# Managed by SSHepherd (serial 9007199254740992). Manual edits will be overwritten by 'sshepherd apply'.")
uint64(9007199254740991)
```
`…/leadingzero`:
```
go test fuzz v1
string("# Managed by SSHepherd-ish (serial 07). Manual edits will be overwritten by 'sshepherd apply'. ")
uint64(18446744073709551615)
```

- [ ] **Step 2: Run the seeds, then fuzz**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/authkeys/ -run FuzzParseHeader && GOTOOLCHAIN=go1.27.3 go test ./internal/authkeys/ -run '^$' -fuzz '^FuzzParseHeader$' -fuzztime 30s && make fuzz-list | grep -q FuzzParseHeader && echo listed`
Expected: `ok`, `ok`, `listed`.

### Task 12: the `.orig` decision comes from `ParseHeader`, not a shell compare

**Files:**
- Modify: `internal/fleet/write.go:9-18` (`Snapshot`), `internal/authkeys/header.go` (`ManagedSnapshot`), `internal/sshwrite/sshwrite.go:78-80` (`SnapshotOf`), `:227-245` (`casBackupBlock`), the `writeCmdFor` doc step 6 (`:167-179`)
- Test: `internal/authkeys/header_test.go`, `internal/sshwrite/sshwrite_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/authkeys/header_test.go` (add `"os"`, `"path/filepath"`, `"strings"` to its imports). `ManagedSnapshot` is the only producer of `Snapshot.Managed` (plan decision 5), so this one parity test covers both callers — apply's planner and `sshwrite.SnapshotOf`:

```go
// TestSnapshotManagedMatchesParseHeader: ManagedSnapshot(…).Managed equals
// ParseHeader's managed over every TestParseHeader row and every file of
// the FuzzParseHeader seed corpus (Task 11), so the .orig decision can
// never drift from the header grammar.
func TestSnapshotManagedMatchesParseHeader(t *testing.T) {
	lines := map[string]string{}
	for _, tc := range parseHeaderCases {
		lines["table/"+tc.name] = tc.line
	}
	files, err := filepath.Glob(filepath.Join("testdata", "fuzz", "FuzzParseHeader", "*"))
	if err != nil || len(files) == 0 {
		t.Fatalf("corpus: %v (%d files; Task 11 commits four)", err, len(files))
	}
	for _, f := range files {
		raw, err := os.ReadFile(f) // #nosec G304 -- committed corpus under testdata
		if err != nil {
			t.Fatal(err)
		}
		// "go test fuzz v1", then string("…"), then uint64(…).
		for _, l := range strings.Split(string(raw), "\n") {
			if q, ok := strings.CutPrefix(l, "string("); ok {
				v, err := strconv.Unquote(strings.TrimSuffix(q, ")"))
				if err != nil {
					t.Fatalf("%s: %v", f, err)
				}
				lines["corpus/"+filepath.Base(f)] = v
			}
		}
	}
	for name, line := range lines {
		_, want := ParseHeader(line)
		if got := ManagedSnapshot(false, []byte(line+"\nkey-line\n")).Managed; got != want {
			t.Errorf("%s: ManagedSnapshot.Managed = %v, ParseHeader managed = %v (%q)", name, got, want, line)
		}
		if got := ManagedSnapshot(false, []byte(line)).Managed; got != want {
			t.Errorf("%s, no newline: ManagedSnapshot.Managed = %v, want %v", name, got, want)
		}
	}
	if s := ManagedSnapshot(true, nil); s.Managed || !s.Absent {
		t.Errorf("absent file = %+v, want Absent and not Managed", s)
	}
	if s, want := ManagedSnapshot(false, []byte(legacy+"\n")), fleet.SnapshotOf(false, []byte(legacy+"\n")); s.Size != want.Size || s.Cksum != want.Cksum {
		t.Errorf("ManagedSnapshot = %+v, want fleet.SnapshotOf's size and cksum %+v", s, want)
	}
}
```

(also add `"github.com/javadh75/SSHepherd/internal/fleet"` to `header_test.go`'s imports.)

Append to `internal/sshwrite/sshwrite_test.go`:

```go
// headerCases are the first lines the .orig decision must classify exactly
// as authkeys.ParseHeader does (orig: the write keeps a one-time .orig).
var headerCases = []struct {
	name, first string
	orig        bool
}{
	{"legacy header", authkeys.ManagedHeader, false},
	{"serial header", authkeys.Header(9), false},
	{"serial 07", "# Managed by SSHepherd (serial 07). Manual edits will be overwritten by 'sshepherd apply'.", true},
	{"serial 0", "# Managed by SSHepherd (serial 0). Manual edits will be overwritten by 'sshepherd apply'.", true},
	{"legacy plus a trailing space", authkeys.ManagedHeader + " ", true},
	{"prefix lookalike", "# Managed by SSHepherd-ish. Manual edits will be overwritten by 'sshepherd apply'.", true},
	{"hand-written file", "ssh-ed25519 AAAA hand", true},
}

// TestSnapshotOfDelegatesToManagedSnapshot: the write path's snapshot is
// authkeys.ManagedSnapshot's, byte for byte (one implementation), and each
// header case's .orig expectation agrees with it.
func TestSnapshotOfDelegatesToManagedSnapshot(t *testing.T) {
	for _, tc := range headerCases {
		content := []byte(tc.first + "\nkey-line\n")
		got, want := SnapshotOf(false, content), authkeys.ManagedSnapshot(false, content)
		if got != want || got.Managed == tc.orig {
			t.Errorf("%s: SnapshotOf = %+v, ManagedSnapshot = %+v, orig %v", tc.name, got, want, tc.orig)
		}
	}
	if SnapshotOf(true, nil) != authkeys.ManagedSnapshot(true, nil) {
		t.Error("absent: SnapshotOf differs from ManagedSnapshot")
	}
}

// TestOrigDecisionFollowsParseHeader: a legacy or (serial N) file takes no
// .orig; every other first line does — the anchored definition, never a
// shell prefix pattern.
func TestOrigDecisionFollowsParseHeader(t *testing.T) {
	forEachShell(t, func(t *testing.T, sh []string) {
		for _, tc := range headerCases {
			t.Run(tc.name, func(t *testing.T) {
				home := t.TempDir()
				target := filepath.Join(home, "auth")
				old := tc.first + "\nkey-line\n"
				writeFile(t, target, old)
				if code := runSh(t, sh, writeCmdFor(target, SnapshotOf(false, []byte(old)), len(managed)), home, []byte(managed)); code != 0 {
					t.Fatalf("exit = %d, want 0", code)
				}
				if tc.orig {
					if got := readFile(t, target+origSuffix); got != old {
						t.Errorf(".orig = %q, want the pre-SSHepherd bytes", got)
					}
				} else {
					assertAbsent(t, target+origSuffix, "a managed file is not an original")
				}
			})
		}
	})
}

func TestWriteCmdHasNoShellHeaderCompare(t *testing.T) {
	for _, s := range []Snapshot{SnapshotOf(false, []byte("x\n")), SnapshotOf(false, []byte(managed))} {
		if cmd := writeCmdFor("~/.ssh/authorized_keys", s, 10); strings.Contains(cmd, "head -n 1") || strings.Contains(cmd, "Managed by") {
			t.Errorf("write script still compares the header in the shell:\n%s", cmd)
		}
	}
}
```

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/authkeys/ ./internal/sshwrite/ -run 'TestSnapshotManagedMatchesParseHeader|TestSnapshotOfDelegatesToManagedSnapshot|TestOrigDecisionFollowsParseHeader|TestWriteCmdHasNoShellHeaderCompare'`
Expected: build failure (`undefined: ManagedSnapshot`, `Managed undefined`).

- [ ] **Step 3: Implement**

`internal/fleet/write.go`, `Snapshot`:

```go
type Snapshot struct {
	Absent bool
	Size   int
	Cksum  uint32
	// Managed reports that the snapshot's first line is a managed header
	// (authkeys.ParseHeader's verdict, set by the caller — this package is
	// stdlib-only). The write script takes the one-time .orig backup only
	// when it is false, after the compare-and-swap proved the file is still
	// these bytes.
	Managed bool
}
```

`internal/authkeys/header.go` (add `"github.com/javadh75/SSHepherd/internal/fleet"` to its imports — `fleet` is the stdlib-only leaf; no layering rule forbids it):

```go
// ManagedSnapshot is the write's compare-and-swap snapshot of phase-1
// bytes (fleet.SnapshotOf) plus the .orig decision input: Managed is
// ParseHeaderOf's verdict on those very bytes. It is the only producer of
// Snapshot.Managed — apply's planner and sshwrite.SnapshotOf both call it —
// so the write script never re-derives it with a shell pattern.
func ManagedSnapshot(absent bool, content []byte) fleet.Snapshot {
	s := fleet.SnapshotOf(absent, content)
	if !absent {
		_, s.Managed = ParseHeaderOf(content)
	}
	return s
}
```

`internal/sshwrite/sshwrite.go`, `SnapshotOf` (`:78-80`):

```go
// SnapshotOf builds the snapshot of phase-1 bytes read (or of an absent
// file); see authkeys.ManagedSnapshot, the one definition of a managed file.
func SnapshotOf(absent bool, content []byte) Snapshot {
	return authkeys.ManagedSnapshot(absent, content)
}
```

(`sshwrite.go` no longer needs `internal/fleet` for this function; keep the import only if other code uses it.)

`casBackupBlock` (`:227-245`):

```go
// casBackupBlock is the tight step between the completed upload and the mv
// (WP-3): copy the live file to a fresh staging name, compare-and-swap the
// COPY (46 on mismatch), derive .orig from it — only when the snapshot is
// not managed (expect.Managed, decided in Go by authkeys.ParseHeader on the
// very bytes the CAS just proved) — and rename it to .bak, so .bak holds
// exactly the bytes the CAS validated, and a lock-less editor that changed
// the file during the upload refuses the write instead of losing its edit.
// rm -f + set -C keep the staging name from following a planted symlink;
// rm -f "$b" fails (exit 1) on a directory planted at .bak.
func casBackupBlock(expect Snapshot) string {
	if expect.Absent {
		return `if [ -e "$p" ] || [ -L "$p" ]; then exit 46; fi`
	}
	b := `if [ -L "$p" ]; then exit 45; fi; if [ ! -f "$p" ]; then exit 46; fi` +
		`; rm -f "$c" || exit 1; (set -C; cat "$p" > "$c") || exit 1` +
		`; set -- $(cksum < "$c"); if [ "$1" != ` + strconv.FormatUint(uint64(expect.Cksum), 10) +
		` ] || [ "$2" != ` + strconv.Itoa(expect.Size) + ` ]; then rm -f "$c"; exit 46; fi`
	if !expect.Managed {
		b += `; if [ ! -e "$o" ] && [ ! -L "$o" ]; then (set -C; cat "$c" > "$o") || exit 1; dd if=/dev/null of="$o" conv=notrunc,fsync 2>/dev/null || :; fi`
	}
	return b + `; rm -f "$b" || exit 1; mv -f "$c" "$b" || exit 1`
}
```

In `writeCmdFor`'s doc comment, step 6, replace "only while the file is not yet SSHepherd-managed" with "only while the snapshot is not SSHepherd-managed (Snapshot.Managed, authkeys.ParseHeader's anchored verdict)".

- [ ] **Step 4: Run to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test -race ./internal/authkeys/ ./internal/sshwrite/ ./internal/fleet/`
Expected: `ok` — including the existing `TestWriteCmdThroughRealSh/managed file never creates .orig`, `TestWriteCmdFlushesPerFileNeverGlobalSync` (still 3 `dd` calls for a hand file), `TestOwnerChecksBite` and `FuzzWriteCmds`.

### Task 13: apply's snapshot carries `Managed`; `normalize` skips any managed header

**Files:**
- Modify: `internal/apply/plan.go:192-197` (`planOne`), `:318-322` (`normalize`)
- Test: `internal/apply/plan_test.go`

- [ ] **Step 1: Write the failing tests**

```go
func TestPlanSnapshotCarriesManaged(t *testing.T) {
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(authkeys.Header(3) + "\n" + testkeys.Line(t, 9) + "\n")},
	}}
	content := []byte(authkeys.Header(3) + "\n" + testkeys.Line(t, 9) + "\n")
	if p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1"); !p.Expect.Managed || p.Expect != authkeys.ManagedSnapshot(false, content) {
		t.Errorf("Expect = %+v, want authkeys.ManagedSnapshot's (Managed for a (serial 3) file)", p.Expect)
	}
	r.byName["web-1"] = fleet.ReadResult{Content: []byte(testkeys.Line(t, 9) + "\n")}
	if p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1"); p.Expect.Managed {
		t.Error("Expect.Managed = true for a hand-written file")
	}
}

// A serial header is a managed header: never counted as a removed
// hand-written comment line.
func TestNormalizeSkipsSerialHeader(t *testing.T) {
	cfg := planCfg(t)
	body := strings.TrimPrefix(string(renderedFor(t, cfg, "web-1")), authkeys.ManagedHeader+"\n")
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(authkeys.Header(5) + "\n" + testkeys.Line(t, 9) + "\n" + body)},
	}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Normalize.NonKeyLines != 0 {
		t.Errorf("NonKeyLines = %d, want 0 (the serial header is not a hand comment)", p.Normalize.NonKeyLines)
	}
}
```

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply/ -run 'TestPlanSnapshotCarriesManaged|TestNormalizeSkipsSerialHeader'`
Expected: FAIL (`Expect.Managed = false`, `NonKeyLines = 1`).

- [ ] **Step 3: Implement**

In `planOne` (`:196`): `Expect: authkeys.ManagedSnapshot(r.FileAbsent, r.Content),` (Task 12's helper — no second copy in apply; plan decision 5).

In `normalize` (`:320-322`):

```go
		if _, managed := authkeys.ParseHeader(t); managed {
			continue // re-emitted by the render, not removed
		}
```

- [ ] **Step 4: Run to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test -race ./internal/apply/`
Expected: `ok`.

### Task 14: the reader can return `authorized_keys2`'s bytes (for the sweep)

**Files:**
- Modify: `internal/fleet/fleet.go:6-20` (`ReadResult`), `internal/sshread/sshread.go:95-110` (`Client`), `:164-198` (`readAuthorizedKeys`)
- Test: `internal/sshread/hermetic_test.go`, `internal/sshread/integration_test.go` (the new remote `cat` path on a real sshd; it runs in Task 15's `make integration`)

- [ ] **Step 1: Write the failing test**

```go
// TestReadKeys2Content: with ReadKeys2 the reader returns a non-empty
// authorized_keys2's bytes (the post-revoke sweep reads it); without it, or
// when the file is empty or absent, Keys2 stays nil.
func TestReadKeys2Content(t *testing.T) {
	home := t.TempDir()
	writeHomeFile(t, home, ".ssh/authorized_keys", "ssh-ed25519 AAAA main\n")
	writeHomeFile(t, home, ".ssh/authorized_keys2", "ssh-ed25519 AAAA planted\n")
	c, _, srv := hermeticClient(t, home)
	res, err := c.ReadAuthorizedKeys(t.Context(), srv)
	if err != nil || res.Keys2 != nil {
		t.Fatalf("without ReadKeys2: Keys2 = %q, err %v; want nil", res.Keys2, err)
	}
	c.ReadKeys2 = true
	res, err = c.ReadAuthorizedKeys(t.Context(), srv)
	if err != nil || string(res.Keys2) != "ssh-ed25519 AAAA planted\n" || res.Keys2Err != nil || !res.AuthorizedKeys2 {
		t.Fatalf("ReadKeys2: %+v, err %v", res, err)
	}
	writeHomeFile(t, home, ".ssh/authorized_keys2", "")
	res, err = c.ReadAuthorizedKeys(t.Context(), srv)
	if err != nil || res.Keys2 != nil || res.AuthorizedKeys2 {
		t.Fatalf("empty keys2: %+v, err %v", res, err)
	}
}
```

Append to `internal/sshread/integration_test.go` (`//go:build integration`; add `"bytes"` to its imports):

```go
// TestIntegrationReadKeys2Content: on a real sshd and every distro's shell,
// ReadKeys2 returns authorized_keys2's bytes. Container A's user "absent"
// has no default file and the seed key (SSHEPHERD_IT_PUB) in
// authorized_keys2 (scripts/integration.sh).
func TestIntegrationReadKeys2Content(t *testing.T) {
	c, host, port := itClient(t)
	want, err := os.ReadFile(os.Getenv("SSHEPHERD_IT_PUB")) // #nosec G703 -- harness key path (SSHEPHERD_IT_PUB)
	if err != nil {
		t.Fatalf("SSHEPHERD_IT_PUB: %v", err)
	}
	c.ReadKeys2 = true
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.ReadAuthorizedKeys(ctx, config.Server{Name: "it", Host: host, Port: port, User: "absent"})
	if err != nil {
		t.Fatalf("ReadAuthorizedKeys: %v", err)
	}
	if !res.AuthorizedKeys2 || res.Keys2Err != nil || !bytes.Equal(bytes.TrimSpace(res.Keys2), bytes.TrimSpace(want)) {
		t.Errorf("Keys2 = %q (err %v, present %v), want the seed key %q", res.Keys2, res.Keys2Err, res.AuthorizedKeys2, want)
	}
}
```

The `#nosec G703` line is the triage form `.golangci.yml`'s gosec section uses for integration files (`.golangci.yml` is outside this lane's globs, so no source-pinned exclusion is added); `make gosec` must stay green.

- [ ] **Step 2: Run to see it fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshread/ -run TestReadKeys2Content && GOTOOLCHAIN=go1.27.3 go vet -tags=integration ./internal/sshread/`
Expected: build failure (`res.Keys2 undefined`, `c.ReadKeys2 undefined`) in both.

- [ ] **Step 3: Implement**

`internal/fleet/fleet.go`, append to `ReadResult`:

```go
	// Keys2 holds ~/.ssh/authorized_keys2's bytes when the reader was asked
	// for them (sshread.Client.ReadKeys2) and AuthorizedKeys2 is true;
	// Keys2Err is why they could not be read (the main read still stands).
	// Only the post-revoke sweep asks.
	Keys2    []byte
	Keys2Err error
```

`internal/sshread/sshread.go`, add to `Client` after `PreferKeys`:

```go
	// ReadKeys2 also reads a non-empty ~/.ssh/authorized_keys2 (with the
	// managed read's size cap) into ReadResult.Keys2 — the post-revoke
	// sweep's proof that a revoked key is gone from it too.
	ReadKeys2 bool
```

At the end of `readAuthorizedKeys` (`:196-197`):

```go
	res.AuthorizedKeys2 = present
	if present && c.ReadKeys2 {
		res.Keys2, res.Keys2Err = c.readKeys2(ctx, conn, addr)
	}
	return res, nil
}

// readKeys2 cats ~/.ssh/authorized_keys2 on the open connection, with the
// managed read's size cap and error mapping. Errors are control-stripped
// (they can embed remote text) and never fail the main read.
func (c *Client) readKeys2(ctx context.Context, conn *sshconn.Conn, addr string) ([]byte, error) {
	code, stdout, stderr, err := sshconn.Exec(ctx, conn.Client, sshconn.AuthorizedKeysCmdFor(sshconn.SecondaryAuthorizedKeysPath), nil)
	if err != nil {
		return nil, sshconn.SanitizedError{Err: fmt.Errorf("authorized_keys2 read on %s: %w", addr, err)}
	}
	res, err := sshconn.FinishRead(code, stdout, stderr, addr, c.log())
	if err != nil {
		return nil, sshconn.SanitizedError{Err: err}
	}
	if res.FileAbsent {
		return nil, nil
	}
	return res.Content, nil
}
```

- [ ] **Step 4: Run to see it pass**

Run: `GOTOOLCHAIN=go1.27.3 go test -race ./internal/sshread/ ./internal/fleet/`
Expected: `ok`.

### Task 15: integration — a serial-header file takes no `.orig` on a real sshd

**Files:**
- Modify: `internal/sshwrite/integration_test.go` (new test after `TestIntegrationApplyWriteBackupVerify`, `:204-253`)

- [ ] **Step 1: Write the test**

```go
// TestIntegrationOrigFollowsHeaderSerial: on real sshd and every distro's
// shell, a "(serial 9)" file takes no .orig, while a "(serial 07)" lookalike
// — not a managed header by ParseHeader's anchored definition — does.
func TestIntegrationOrigFollowsHeaderSerial(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "writer", Host: host, Port: port, User: "writer"}
	for _, tc := range []struct {
		first string
		orig  bool
	}{
		{authkeys.Header(9), false},
		{"# Managed by SSHepherd (serial 07). Manual edits will be overwritten by 'sshepherd apply'.", true},
	} {
		seed := tc.first + "\n" + itPub(t) + "\n"
		reseed(t, w.Dialer, srv, fixture{keys: strp(seed)})
		if err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, itRendered(t))); err != nil {
			t.Fatalf("Apply over %q: %v", tc.first, err)
		}
		got := remoteOut(t, w.Dialer, srv, `if [ -e "$HOME/.ssh/authorized_keys.sshepherd.orig" ]; then cat "$HOME/.ssh/authorized_keys.sshepherd.orig"; else echo absent; fi`)
		switch {
		case tc.orig && got != seed:
			t.Errorf("first line %q: .orig = %q, want the seeded bytes", tc.first, got)
		case !tc.orig && got != "absent\n":
			t.Errorf("first line %q: .orig = %q, want none", tc.first, got)
		}
	}
}
```

- [ ] **Step 2: Run it under the integration lock**

Run (with the runner's lock held): `make integration IT_DISTRO=alpine`
Expected: PASS, including `TestIntegrationOrigFollowsHeaderSerial` and Task 14's `TestIntegrationReadKeys2Content`. Then `make check`.

- [ ] **Step 3: Hand back** (lane `header`; the integrator commits `feat(authkeys): managed header carries the serial; .orig decided by ParseHeader (P04 W4, PRD-2)`)

**docsDelta (lane `header`):**
- README `## Safety model`, the quoted header: "a managed header (`# Managed by SSHepherd. Manual edits will be overwritten by 'sshepherd apply'.`, or `# Managed by SSHepherd (serial 7). …` once the manifest has a `serial:`)", and in the backups paragraph: "the one-time `.sshepherd.orig` is taken only when the file's first line is not a managed header — the exact `ParseHeader` grammar, decided on the bytes the compare-and-swap just proved".
- No CLAUDE.md change of its own (the W4 Status paragraph is written once, see "Integrator: docs and Status").

---
## Round 2 — lane `apply` (Tasks 16–22)

Owns: `internal/apply/**` (except `serialbump*.go` and `sweep*.go`, which do not exist yet), `internal/workflow/**`. Findings: PRD-2, PRD-1 (D29 apply refusal). `needsIntegration: true` (the planner decides what every write sends).

Keep `audit`'s exported names this lane calls (`audit.UnknownLabel`, `UnknownOptions`, `ErrorTag`, `Hints`, `CleanHint`, `Run`, `ServerResult`) as they are; lane `audit` runs in parallel and keeps them stable too.

### Task 16: `BuildWith`, `BuildOptions`, the plan's serial fields, `workflow.Request.Bumped`

**Files:**
- Create: `internal/apply/serial.go`, `internal/apply/serial_test.go`
- Modify: `internal/apply/plan.go:87-120` (`ServerPlan`), `:133-148` (`Build`, deleted), `:192-264` (`planOne`); `internal/apply/plan_test.go:41`, `:292` (the two `Build(` callers); `internal/workflow/workflow.go:83-102` (`Request`), `:142-158` (`plan`)

`Build` is deleted, not kept as a wrapper: `workflow.plan` (`workflow.go:153`) is its only production caller, so once that calls `BuildWith`, a `Build` wrapper is reachable only from tests and `deadcode ./cmd/sshepherd` fails `make check`.

- [ ] **Step 1: Write the failing tests**

Write the three tests below **and the eight §3 row tests of Task 17 Step 1** into `serial_test.go` now, so every row test's first run is this task's build failure (failing first); Task 17 then proves each one bites with a mutation.

`internal/apply/serial_test.go`:

```go
package apply

import (
	"context"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// serialCfg: serial 7; op (k1, operator) everywhere; alice (k2) -> web-1.
func serialCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`serial: 7
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`))
	if err != nil {
		t.Fatalf("serialCfg: %v", err)
	}
	return cfg
}

// web1Body is web-1's rendered body (everything after the header line).
func web1Body(t *testing.T, cfg *config.Config) string {
	t.Helper()
	return string(bodyOf(renderedFor(t, cfg, "web-1")))
}

// planWeb1 plans web-1 holding content, with op's key held by the agent.
func planWeb1(t *testing.T, cfg *config.Config, content string, keys2, bumped bool) ServerPlan {
	t.Helper()
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(content), AuthorizedKeys2: keys2}}}
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 1})
	plans, err := BuildWith(cfg, results, agentHeld(fp(t, 1)), BuildOptions{Bumped: bumped})
	if err != nil {
		t.Fatalf("BuildWith: %v", err)
	}
	return planFor(t, plans, "web-1")
}

func TestMaxSerialBoundsAgree(t *testing.T) {
	if config.MaxSerial != authkeys.MaxHeaderSerial {
		t.Fatalf("config.MaxSerial %d != authkeys.MaxHeaderSerial %d", uint64(config.MaxSerial), uint64(authkeys.MaxHeaderSerial))
	}
}

func TestPlanEqualSerialConverged(t *testing.T) {
	cfg := serialCfg(t)
	p := planWeb1(t, cfg, authkeys.Header(7)+"\n"+web1Body(t, cfg), false, true)
	if p.Class != ClassConverged || p.Serial != (SerialPlan{Header: 7, Manifest: 7, Writes: 7, Case: SerialEqual}) || p.SerialNote != "" {
		t.Fatalf("plan = %+v", p)
	}
}

// TestBuildWithZeroOptionsIsPlainApply: BuildOptions{} is a plain apply —
// an older equal-body server stays converged (no header-only write).
func TestBuildWithZeroOptionsIsPlainApply(t *testing.T) {
	cfg := serialCfg(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(authkeys.Header(6) + "\n" + web1Body(t, cfg))}}}
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 1})
	plans, err := BuildWith(cfg, results, agentHeld(fp(t, 1)), BuildOptions{})
	if err != nil || plans[0].Class != ClassConverged || !strings.Contains(string(plans[0].Serial.Case), "older") {
		t.Fatalf("BuildWith(…, BuildOptions{}) = %+v, %v; want the plain-apply (not bumped) verdict", plans, err)
	}
}
```

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply/ -run 'TestMaxSerialBoundsAgree|TestPlanEqualSerialConverged|TestBuildWithZeroOptionsIsPlainApply|TestPlan.*Serial|TestPlanForged|TestPlanHeaderOnly|TestPlanRemovalOnly|TestPlanRefusesNewer'`
Expected: build failure (`undefined: BuildWith`, `bodyOf`, `SerialPlan`, `BuildOptions`) — the first run of all eleven tests.

- [ ] **Step 3: Implement**

Create `internal/apply/serial.go`:

```go
package apply

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
)

// SerialCase names the row of the spec 2026-11-08 §3 table that planned a
// server; it is the JSON serial.case value.
type SerialCase string

// The §3 rows (rows 5 and 8 on an equal serial are "equal"; rows 7 and 8
// on an older one are "older").
const (
	SerialForged           SerialCase = "forged"             // row 1
	SerialNewerConverged   SerialCase = "newer_converged"    // row 2 (D4c)
	SerialNewerRemovalOnly SerialCase = "newer_removal_only" // row 3
	SerialNewerRefused     SerialCase = "newer_refused"      // row 4
	SerialEqual            SerialCase = "equal"              // rows 5 and 8
	SerialHeaderOnly       SerialCase = "header_only"        // row 6, the PRD-2 fix
	SerialOlder            SerialCase = "older"              // rows 7 and 8
)

// SerialPlan is one server's header serial against the manifest's.
type SerialPlan struct {
	Header   uint64     // S as the server's header claims it; 0 = no serial (legacy header, hand-written or absent file)
	Manifest uint64     // M, the rendered manifest's serial
	Writes   uint64     // the serial a planned write's header carries (meaningful for ClassChange only)
	Case     SerialCase // "" when no row applied (unreachable, refused before rendering, granted nothing)
}

// BuildOptions tunes Build.
type BuildOptions struct {
	// Bumped: this run saves a higher serial: (revoke, rotate) and every
	// planned server is in its bump scope (the affected set), so a server
	// whose keys already match and whose header is older gets a
	// header-only write carrying the new serial (§3 row 6). A plain apply
	// leaves it false.
	Bumped bool
}

// serialDecision is planSerial's verdict for one server.
type serialDecision struct {
	sp         SerialPlan
	converged  bool   // rows 2, 5, 7: no write
	refusal    string // row 4
	headerOnly bool   // rows 1 and 6 with equal bodies and no authorized_keys2
	equalBody  bool   // the server's body equals the render's: no key rows
	note       string // rows 1-3
}

// bodyOf is a file's body: everything after its first line.
func bodyOf(content []byte) []byte {
	_, body, _ := bytes.Cut(content, []byte("\n"))
	return body
}

// planSerial applies the §3 table. Bodies are equal only when the server's
// first line is a managed header and the rest is byte-identical to the
// render's; a non-empty authorized_keys2 to move aside makes an equal body
// a write (rows 2→3, 5/7→8).
func planSerial(m uint64, r audit.ServerResult, entries []authkeys.RenderEntry, renderedBody []byte, bumped bool) serialDecision {
	var s uint64
	managed := false
	if !r.FileAbsent {
		s, managed = authkeys.ParseHeaderOf(r.Content)
	}
	equal := managed && bytes.Equal(bodyOf(r.Content), renderedBody)
	quiet := equal && !r.AuthorizedKeys2
	d := serialDecision{sp: SerialPlan{Header: s, Manifest: m, Writes: m}, equalBody: equal}
	switch {
	case s > m+authkeys.ForgedMargin:
		d.sp.Case, d.headerOnly = SerialForged, quiet
		d.note = fmt.Sprintf("header claims serial %d, far above this manifest's %d — treated as no serial", s, m)
	case s > m:
		return newerSerial(d, r, entries, quiet)
	case s == m:
		d.sp.Case, d.converged = SerialEqual, quiet
	case quiet && bumped:
		d.sp.Case, d.headerOnly = SerialHeaderOnly, true
	default:
		d.sp.Case, d.converged = SerialOlder, quiet
	}
	return d
}

// newerSerial is rows 2-4: a server a newer manifest wrote. Only a write
// that removes access proceeds, and it keeps the server's serial, so a
// serial on a server never goes down.
func newerSerial(d serialDecision, r audit.ServerResult, entries []authkeys.RenderEntry, quiet bool) serialDecision {
	s, m := d.sp.Header, d.sp.Manifest
	switch {
	case quiet:
		d.sp.Case, d.converged = SerialNewerConverged, true
		d.note = fmt.Sprintf("written by newer manifest serial %d (yours is %d): pull the latest manifest", s, m)
	case removalOnly(r, entries):
		d.sp.Case, d.sp.Writes = SerialNewerRemovalOnly, s
		d.note = fmt.Sprintf("written by newer manifest serial %d; this write only removes keys, so it proceeds", s)
	default:
		d.sp.Case = SerialNewerRefused
		d.refusal = fmt.Sprintf("written by manifest serial %d, this manifest is %d — a newer manifest revoked or rotated keys here; pull the latest manifest, or if you are sure, set serial: %d in your manifest (this is the only override)", s, m, s)
	}
	return d
}

// removalOnly reports a write that grants nothing: every rendered key is
// already installed (its first line, as Diff keeps it) with the same option
// list, and no key is added. Comments, order, non-key lines and duplicate
// lines may differ. Any change to a kept key's options — loosening above
// all (authkeys.Loosening's cases) — is a grant, never removal-only.
func removalOnly(r audit.ServerResult, entries []authkeys.RenderEntry) bool {
	if len(r.Diff.Missing) > 0 {
		return false
	}
	for _, e := range entries {
		actual, ok := r.Diff.Actual[e.Key.Fingerprint]
		if !ok || !slices.Equal(actual.Options, e.Key.Options) {
			return false
		}
	}
	return true
}

// conflictRefusal is the refusal text for a server a policy conflict names
// (D29): each conflict's message, joined; "" when none names it.
func conflictRefusal(cfg *config.Config, server string) string {
	var msgs []string
	for _, c := range cfg.Conflicts() {
		if slices.Contains(c.Servers, server) {
			msgs = append(msgs, c.Message)
		}
	}
	return strings.Join(msgs, "; ")
}
```

`internal/apply/plan.go` — add to `ServerPlan` after `Expect`:

```go
	// HeaderOnly marks a change that rewrites only line 1 — the managed
	// header — to carry the manifest's serial (§3 rows 1 and 6): every byte
	// after it is the server's own, so it cannot widen access.
	HeaderOnly bool
	// Serial is the header-serial verdict; SerialNote the human note of
	// rows 1-3 (forged, newer converged, newer removal-only), "" otherwise.
	Serial     SerialPlan
	SerialNote string
```

Delete `Build` (`:133-148`) and put in its place:

```go
// BuildWith computes the plan for every phase-1 result. held is what the
// run could authenticate with at preflight (the run's held-key listing: key
// files and plain agent keys, with their sources) — the self-lockout
// guard's ground truth. Pure; the only possible error is a render failure,
// impossible for a validated manifest (a tool bug, exit 3).
func BuildWith(cfg *config.Config, results []audit.ServerResult, held []fleet.HeldKey, opts BuildOptions) ([]ServerPlan, error) {
	plans := make([]ServerPlan, 0, len(results))
	for _, r := range results {
		p, err := planOne(cfg, r, held, opts)
		if err != nil {
			return nil, err
		}
		plans = append(plans, p)
	}
	return plans, nil
}
```

Replace `planOne` (`:192-264`) with `planOne` + `planWrite`:

```go
func planOne(cfg *config.Config, r audit.ServerResult, held []fleet.HeldKey, opts BuildOptions) (ServerPlan, error) {
	p := ServerPlan{
		Server: r.Server, Outcome: OutcomePending, FileAbsent: r.FileAbsent,
		AuthorizedKeys2: r.AuthorizedKeys2,
		Expect:          authkeys.ManagedSnapshot(r.FileAbsent, r.Content),
	}
	if r.Err != nil {
		p.Class = ClassUnreachable
		p.Err = r.Err
		return p, nil //nolint:nilerr // an unreachable server is a plan class, not a Build failure
	}
	// A policy conflict names this server (D29): nothing is written here —
	// a revoked key is never installed, a revoked grant never restored.
	if refusal := conflictRefusal(cfg, r.Server.Name); refusal != "" {
		p.Class, p.Refusal = ClassRefused, refusal
		return p, nil
	}

	entries := desiredEntries(cfg, r.Server.Name)
	for _, e := range entries {
		p.Desired = append(p.Desired, e.Key)
	}
	if len(entries) == 0 {
		return planNoGrants(p, r), nil
	}

	// Unparseable lines: a full-file render would destroy content we could
	// not account for. Remediation: fix the line remotely or correct
	// authorized_keys_file.
	if n := len(r.ParseErrs); n > 0 {
		p.Class = ClassRefused
		p.Refusal = fmt.Sprintf(
			"%s — refusing to rewrite a file that could not be fully read (fix %s or correct authorized_keys_file)",
			Plural(n, "unparseable line", "unparseable lines"), theLines(n))
		return p, nil
	}
	return planWrite(cfg, p, r, entries, held, opts)
}

// planWrite renders the server's file and classifies it by the §3 serial
// table: converged, refused (a newer manifest's serial, a render too large
// to verify), a header-only write, or a change with its key rows — then the
// self-lockout guard, which judges every write alike.
func planWrite(cfg *config.Config, p ServerPlan, r audit.ServerResult, entries []authkeys.RenderEntry, held []fleet.HeldKey, opts BuildOptions) (ServerPlan, error) {
	m := cfg.Serial()
	rendered, err := authkeys.RenderSerial(entries, m)
	if err != nil {
		return p, fmt.Errorf("render %s: %w", r.Server.Name, err)
	}
	p.Rendered = rendered
	if len(rendered) > maxRender {
		p.Class = ClassRefused
		p.Refusal = fmt.Sprintf(
			"rendered file is %d bytes, over the %d-byte limit the read path accepts — refusing to write a file that could never be verified or audited (split the grant across accounts)",
			len(rendered), maxRender)
		return p, nil
	}
	d := planSerial(m, r, entries, bodyOf(rendered), opts.Bumped)
	p.Serial, p.SerialNote = d.sp, d.note
	switch {
	case d.refusal != "":
		p.Class, p.Refusal = ClassRefused, d.refusal
		return p, nil
	case d.converged:
		p.Class = ClassConverged
		return p, nil
	}
	if d.sp.Writes != m { // row 3 keeps the server's (higher) serial
		if p.Rendered, err = authkeys.RenderSerial(entries, d.sp.Writes); err != nil {
			return p, fmt.Errorf("render %s: %w", r.Server.Name, err)
		}
	}
	p.HeaderOnly = d.headerOnly
	if !d.equalBody {
		p.Add = r.Diff.Missing
		p.Remove = r.Diff.Unauthorized
		p.Rewrites = rewriteRows(r, entries)
		explained := len(p.Add)+len(p.Remove)+len(p.Rewrites) > 0
		p.Normalize = normalize(r, entries, explained)
	}
	v := guardCheck(cfg, r, entries, held)
	if v.Refusal != "" {
		p.Class = ClassRefused
		p.Refusal = v.Refusal
		return p, nil
	}
	p.Note, p.Warning, p.AgentOnly = v.Note, v.Warning, v.AgentOnly
	p.Class = ClassChange
	return p, nil
}
```

Remove the `"bytes"` import from `plan.go` if nothing else there uses it (it moved to `serial.go`).

`internal/apply/plan_test.go`: the two callers of the deleted `Build` become `BuildWith(cfg, results, held, BuildOptions{})` (`buildPlansHeld`, `:41`) and `BuildWith(cfg, results, agentHeld(fp(t, 2)), BuildOptions{})` (`TestApplyAuditAgreeOnKeys2WithoutGrants`, `:292`); the `t.Fatalf("Build: %v", err)` message becomes `"BuildWith: %v"`. `grep -rn '\bBuild(' internal/apply internal/workflow` then finds nothing.

`internal/workflow/workflow.go`: add to `Request` after `AlwaysConfirm`:

```go
	// Bumped: the run saves a higher serial: and Servers is its bump scope
	// (revoke/rotate's affected set) — servers whose keys already match get
	// a header-only write carrying the new serial (apply.BuildOptions).
	Bumped bool
```

and in `plan` (`:153`):

```go
	plans, err := apply.BuildWith(req.Cfg, results, req.Held, apply.BuildOptions{Bumped: req.Bumped})
```

- [ ] **Step 4: Run to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test -race ./internal/apply/ ./internal/workflow/ && deadcode ./cmd/sshepherd`
Expected: `ok` — the eight row tests of Task 17 included, and every existing plan test still passes (serial 0 manifests and legacy headers take rows 5/8 exactly as the byte compare did); `deadcode` prints nothing.

### Task 17: the §3 rows, one test each — each proven to bite

**Files:**
- Test: `internal/apply/serial_test.go` (the tests below were written in Task 16 Step 1, before the implementation; this task proves each one fails under a one-line mutation of Task 16's code)

- [ ] **Step 1: The tests (already in `serial_test.go` since Task 16 Step 1)**

```go
func TestPlanRefusesNewerServerSerial(t *testing.T) {
	cfg := serialCfg(t)
	// alice's key is not on the server: this manifest's render would add it.
	p := planWeb1(t, cfg, authkeys.Header(8)+"\n"+testkeys.Line(t, 1)+" op\n", false, false)
	want := "written by manifest serial 8, this manifest is 7 — a newer manifest revoked or rotated keys here; pull the latest manifest, or if you are sure, set serial: 8 in your manifest (this is the only override)"
	if p.Class != ClassRefused || p.Refusal != want || p.Serial.Case != SerialNewerRefused {
		t.Fatalf("plan = %+v\nwant refusal %q", p, want)
	}
}

// TestPlanRemovalOnlyProceedsOnNewerSerial: removing a stranger's key from
// a server a newer manifest wrote proceeds, and the header keeps S (8), so
// the write never lowers the server's serial.
func TestPlanRemovalOnlyProceedsOnNewerSerial(t *testing.T) {
	cfg := serialCfg(t)
	p := planWeb1(t, cfg, authkeys.Header(8)+"\n"+web1Body(t, cfg)+testkeys.Line(t, 9)+"\n", false, false)
	if p.Class != ClassChange || p.Serial.Case != SerialNewerRemovalOnly || p.Serial.Writes != 8 || len(p.Remove) != 1 {
		t.Fatalf("plan = %+v", p)
	}
	if want := authkeys.Header(8) + "\n" + web1Body(t, cfg); string(p.Rendered) != want {
		t.Errorf("Rendered = %q\nwant %q (header keeps serial 8)", p.Rendered, want)
	}
	if p.SerialNote != "written by newer manifest serial 8; this write only removes keys, so it proceeds" {
		t.Errorf("SerialNote = %q", p.SerialNote)
	}
	// A comment-only difference is still removal-only.
	c := authkeys.Header(8) + "\n" + testkeys.Line(t, 1) + " op\n" + testkeys.Line(t, 2) + " alice@laptop\n"
	if p := planWeb1(t, cfg, c, false, false); p.Class != ClassChange || p.Serial.Case != SerialNewerRemovalOnly {
		t.Errorf("comment rewrite on a newer server = %+v, want removal-only", p)
	}
}

func TestPlanRemovalOnlyRejectsLoosenedOptions(t *testing.T) {
	cfg := serialCfg(t)
	// The server restricts alice's key; this manifest's line has no from=:
	// writing it would loosen access, which is a grant.
	c := authkeys.Header(8) + "\n" + testkeys.Line(t, 1) + " op\n" + `from="10.0.0.0/8" ` + testkeys.Line(t, 2) + " alice\n"
	if p := planWeb1(t, cfg, c, false, false); p.Class != ClassRefused || p.Serial.Case != SerialNewerRefused {
		t.Fatalf("plan = %+v, want the stale-serial refusal", p)
	}
}

func TestPlanNewerSerialSameBodyConvergedWithNote(t *testing.T) {
	cfg := serialCfg(t)
	p := planWeb1(t, cfg, authkeys.Header(8)+"\n"+web1Body(t, cfg), false, false)
	if p.Class != ClassConverged || p.Serial.Case != SerialNewerConverged ||
		p.SerialNote != "written by newer manifest serial 8 (yours is 7): pull the latest manifest" {
		t.Fatalf("plan = %+v", p)
	}
	// A non-empty authorized_keys2 to move aside turns row 2 into row 3.
	k2 := planWeb1(t, cfg, authkeys.Header(8)+"\n"+web1Body(t, cfg), true, false)
	if k2.Class != ClassChange || !k2.DisableKeys2() || k2.Serial.Case != SerialNewerRemovalOnly || k2.Serial.Writes != 8 {
		t.Fatalf("with authorized_keys2: %+v", k2)
	}
}

// TestPlanForgedSerialTreatedAsNone: S > M+1000 is forged, in any run: a
// header-only write carrying M when the bodies match, an ordinary change
// otherwise. A forged header never blocks a write.
func TestPlanForgedSerialTreatedAsNone(t *testing.T) {
	cfg := serialCfg(t)
	p := planWeb1(t, cfg, authkeys.Header(1008)+"\n"+web1Body(t, cfg), false, false)
	if p.Class != ClassChange || !p.HeaderOnly || p.Serial.Case != SerialForged || p.Serial.Writes != 7 ||
		p.SerialNote != "header claims serial 1008, far above this manifest's 7 — treated as no serial" {
		t.Fatalf("plan = %+v", p)
	}
	q := planWeb1(t, cfg, authkeys.Header(1008)+"\n"+testkeys.Line(t, 1)+" op\n", false, false)
	if q.Class != ClassChange || q.HeaderOnly || len(q.Add) != 1 || !strings.HasPrefix(string(q.Rendered), authkeys.Header(7)+"\n") {
		t.Fatalf("forged with a missing key = %+v", q)
	}
	if b := planWeb1(t, cfg, authkeys.Header(1007)+"\n"+web1Body(t, cfg), false, false); b.Class != ClassConverged || b.Serial.Case != SerialNewerConverged {
		t.Errorf("M+1000 is still a real newer serial: %+v", b)
	}
}

// TestPlanHeaderOnlyWriteOnAffectedOlderSerial (replaces
// TestPlanConvergedOnOlderSerialSameBody — the W0 verifier's PRD-2 hole):
// in a bumped run, an affected server whose keys already match and whose
// header is older (a (serial S) or the legacy header) gets a header-only
// write carrying M.
func TestPlanHeaderOnlyWriteOnAffectedOlderSerial(t *testing.T) {
	cfg := serialCfg(t)
	for _, first := range []string{authkeys.Header(6), authkeys.ManagedHeader} {
		p := planWeb1(t, cfg, first+"\n"+web1Body(t, cfg), false, true)
		if p.Class != ClassChange || !p.HeaderOnly || p.Serial.Case != SerialHeaderOnly || p.Serial.Writes != 7 {
			t.Fatalf("%q: plan = %+v", first, p)
		}
		if len(p.Add)+len(p.Remove)+len(p.Rewrites) != 0 || p.Normalize.Any() {
			t.Errorf("%q: a header-only plan has key rows: %+v", first, p)
		}
		if want := authkeys.Header(7) + "\n" + web1Body(t, cfg); string(p.Rendered) != want {
			t.Errorf("%q: Rendered = %q\nwant the server's bytes with line 1 replaced: %q", first, p.Rendered, want)
		}
	}
}

func TestPlanOlderSerialSameBodyConvergedWithoutBump(t *testing.T) {
	cfg := serialCfg(t)
	p := planWeb1(t, cfg, authkeys.Header(6)+"\n"+web1Body(t, cfg), false, false)
	if p.Class != ClassConverged || p.HeaderOnly || p.Serial.Case != SerialOlder {
		t.Fatalf("plain apply over an older equal-body server = %+v, want converged", p)
	}
}

// TestPlanHeaderOnlyRefusedByGuard: the lockout guard judges a header-only
// write like any write.
func TestPlanHeaderOnlyRefusedByGuard(t *testing.T) {
	cfg := serialCfg(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(authkeys.Header(6) + "\n" + web1Body(t, cfg))}}}
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 1})
	plans, err := BuildWith(cfg, results, agentHeld(fp(t, 9)), BuildOptions{Bumped: true})
	if err != nil {
		t.Fatal(err)
	}
	if p := plans[0]; p.Class != ClassRefused || !strings.Contains(p.Refusal, "lock this session out") {
		t.Fatalf("plan = %+v, want the guard's refusal", p)
	}
}
```

- [ ] **Step 2: Run them**

Run: `GOTOOLCHAIN=go1.27.3 go test -race ./internal/apply/ -run 'TestPlan.*Serial|TestPlanForged|TestPlanHeaderOnly|TestPlanRemovalOnly|TestPlanRefusesNewer'`
Expected: `ok`. If one fails, the defect is in Task 16's `planSerial`/`newerSerial`/`planWrite` — fix it there; do not loosen the test.

- [ ] **Step 3: Mutation check — one per test (inside your worktree only; `git checkout internal/apply/serial.go` after each)**

Apply each mutation alone, run the named test with `GOTOOLCHAIN=go1.27.3 go test ./internal/apply/ -run '^NAME$'`, see FAIL, revert:

| Test | Mutation (in `serial.go`) |
|---|---|
| `TestPlanRefusesNewerServerSerial` | `newerSerial`'s `default:` arm sets `d.converged = true` and no `d.refusal` |
| `TestPlanRemovalOnlyProceedsOnNewerSerial` | the removal-only arm keeps `m`: `d.sp.Case = SerialNewerRemovalOnly` (drop `d.sp.Writes = s`) |
| `TestPlanRemovalOnlyRejectsLoosenedOptions` | `removalOnly` drops the `!slices.Equal(actual.Options, e.Key.Options)` test |
| `TestPlanNewerSerialSameBodyConvergedWithNote` | `planSerial`: `quiet := equal` (ignore `authorized_keys2`) |
| `TestPlanForgedSerialTreatedAsNone` | `planSerial`: delete the `case s > m+authkeys.ForgedMargin:` arm |
| `TestPlanHeaderOnlyWriteOnAffectedOlderSerial` | `planSerial`: `case quiet && bumped:` → `case false:` |
| `TestPlanOlderSerialSameBodyConvergedWithoutBump` | `planSerial`: `case quiet && bumped:` → `case quiet:` |
| `TestPlanHeaderOnlyRefusedByGuard` | `planWrite`: before `v := guardCheck(…)`, insert `if d.headerOnly { p.Class = ClassChange; return p, nil }` |

Record the eight FAIL lines in the hand-back `commands`.

### Task 18: policy conflicts refuse their servers (D29)

**Files:**
- Test: `internal/apply/serial_test.go`

- [ ] **Step 1: Write the test**

```go
// TestPlanRefusesConflictServers: a revoked key still listed refuses every
// server it would render on, with the conflict message; the rest of the
// fleet is planned normally.
func TestPlanRefusesConflictServers(t *testing.T) {
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]}
revoked:
  - {fingerprint: ` + fp(t, 2) + `, user: alice, date: 2026-11-08}
`))
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n")},
		"web-2": {Content: []byte(testkeys.Line(t, 1) + "\n")},
	}}
	plans := buildPlans(t, cfg, r, []string{fp(t, 1)})
	w1, w2 := planFor(t, plans, "web-1"), planFor(t, plans, "web-2")
	if w1.Class != ClassRefused || w1.Refusal != cfg.Conflicts()[0].Message {
		t.Errorf("web-1 = %+v, want the conflict refusal %q", w1, cfg.Conflicts()[0].Message)
	}
	if w2.Class != ClassChange {
		t.Errorf("web-2 = %+v, want an ordinary change", w2)
	}
}
```

- [ ] **Step 2: Run it**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply/ -run TestPlanRefusesConflictServers`
Expected: `ok` (Task 16 added the refusal). Mutation: comment out the `conflictRefusal` branch in `planOne` → FAIL; restore.

### Task 19: `Affected` ignores the serial

**Files:**
- Test: `internal/apply/affected_test.go`

- [ ] **Step 1: Write the test**

```go
// TestAffectedIgnoresSerialBump: a revoke's serial bump alone never widens
// the affected set (renderFor renders serial 0 on both sides).
func TestAffectedIgnoresSerialBump(t *testing.T) {
	base := `users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`
	old, err := config.Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	bumped, err := config.Parse([]byte("serial: 8\n" + base))
	if err != nil {
		t.Fatal(err)
	}
	if got := Affected(old, bumped); len(got.Servers) != 0 {
		t.Fatalf("Affected = %+v, want none", got)
	}
}
```

- [ ] **Step 2: Run it**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply/ -run TestAffectedIgnoresSerialBump`
Expected: `ok` — a regression pin (it holds by construction, plan decision 1). Prove it bites: in `renderFor` (`affected.go:45-51`) render with `authkeys.RenderSerial(entries, cfg.Serial())` instead of `authkeys.Render(entries)`; the test must FAIL (web-1 becomes affected); revert. Add to `renderFor`'s doc comment (`affected.go:42-44`): "Serial 0 on both sides (authkeys.Render): a serial bump alone never makes a server affected."

### Task 20: the plan report — header-only rows and serial notes

**Files:**
- Modify: `internal/apply/report.go:109-142` (`Render`), `:144-197` (`renderChange`)
- Test: `internal/apply/report_test.go`, golden `internal/apply/testdata/plan_serial.golden` (new)

- [ ] **Step 1: Write the failing golden test**

```go
// serialFleet: serial 7, op (k1) operator, alice (k2) on every server; one
// server per row of the §3 table, planned in a bumped (revoke) run.
func serialFleet(t *testing.T) (*config.Config, []ServerPlan) {
	t.Helper()
	cfg, err := config.Parse([]byte(`serial: 7
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: s-forged, host: 10.0.0.1, user: deploy}
  - {name: s-headeronly, host: 10.0.0.2, user: deploy}
  - {name: s-newer, host: 10.0.0.3, user: deploy}
  - {name: s-older, host: 10.0.0.4, user: deploy}
  - {name: s-refused, host: 10.0.0.5, user: deploy}
  - {name: s-removal, host: 10.0.0.6, user: deploy}
access:
  - {user: alice, servers: ["*"]}
`))
	if err != nil {
		t.Fatal(err)
	}
	body := string(bodyOf(renderedFor(t, cfg, "s-forged")))
	opOnly := testkeys.Line(t, 1) + " op\n"
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"s-forged":     {Content: []byte(authkeys.Header(5000) + "\n" + body)},
		"s-headeronly": {Content: []byte(authkeys.Header(6) + "\n" + body)},
		"s-newer":      {Content: []byte(authkeys.Header(8) + "\n" + body)},
		"s-older":      {Content: []byte(authkeys.ManagedHeader + "\n" + opOnly)},
		"s-refused":    {Content: []byte(authkeys.Header(8) + "\n" + opOnly)},
		"s-removal":    {Content: []byte(authkeys.Header(8) + "\n" + body + testkeys.Line(t, 9) + " stray\n")},
	}}
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 2})
	plans, err := BuildWith(cfg, results, agentHeld(fp(t, 1)), BuildOptions{Bumped: true})
	if err != nil {
		t.Fatal(err)
	}
	return cfg, plans
}

func TestRenderPlanSerialGolden(t *testing.T) {
	cfg, plans := serialFleet(t)
	var b bytes.Buffer
	Render(&b, cfg, plans, RenderOptions{})
	checkGolden(t, "plan_serial.golden", b.Bytes())
	for _, want := range []string{
		"(header)", // the label column; tabwriter pads the row, so match its cells separately
		"update header: forged serial 5000 → 7 (keys unchanged)\n",
		"update header: serial 6 → 7 (keys unchanged)\n",
		"  → 2 keys desired · header only",
		"s-newer (deploy@10.0.0.3:22)  converged (no changes)\n  note: written by newer manifest serial 8 (yours is 7): pull the latest manifest\n",
		"  warning: written by newer manifest serial 8; this write only removes keys, so it proceeds",
		"  warning: header claims serial 5000, far above this manifest's 7 — treated as no serial",
		"REFUSED: written by manifest serial 8, this manifest is 7",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, b.String())
		}
	}
}

func TestRenderHeaderOnlyFromNoSerial(t *testing.T) {
	cfg := serialCfg(t)
	p := planWeb1(t, cfg, authkeys.ManagedHeader+"\n"+web1Body(t, cfg), false, true)
	var b bytes.Buffer
	Render(&b, cfg, []ServerPlan{p}, RenderOptions{})
	if !strings.Contains(b.String(), "update header: no serial → 7 (keys unchanged)") {
		t.Errorf("report:\n%s", b.String())
	}
}
```

(`report_test.go` already imports `bytes`, `strings`, `config`, `fleet`, `testkeys`; add `context`, `audit`, `authkeys` if missing.)

- [ ] **Step 2: Run to see it fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply/ -run 'TestRenderPlanSerialGolden|TestRenderHeaderOnlyFromNoSerial'` (no `-update`: a golden written now would pin pre-implementation output)
Expected: FAIL — `read golden (run with -update first)` for `plan_serial.golden`, and `TestRenderHeaderOnlyFromNoSerial` lacks the `update header` row.

- [ ] **Step 3: Implement**

In `Render`, the converged arm:

```go
		case ClassConverged:
			fmt.Fprintf(w, "%s  converged (no changes)\n", head)
			if p.SerialNote != "" {
				fmt.Fprintf(w, "  note: %s\n", p.SerialNote)
			}
			renderKeys2Warning(w, p, pal)
			fmt.Fprintln(w)
```

`renderChange` is at gocyclo 14 today (limit 15), so its three new branches live in helpers and `renderChange` gains only calls. After the `DisableKeys2` row (before `_ = tw.Flush()`): `headerOnlyRow(tw, p, pal)`; after the `FileAbsent` note block: `serialWarning(w, p, pal)`; and replace the final summary `fmt.Fprintf` with `summaryLine(w, p)`. Add after `renderChange`:

```go
// headerOnlyRow is a header-only write's one row in place of key rows (§3
// "Report").
func headerOnlyRow(tw io.Writer, p ServerPlan, pal palette) {
	if p.HeaderOnly {
		fmt.Fprintf(tw, "  %s\t(header)\t\t\tupdate header: %s → %d (keys unchanged)\n",
			pal.paint(codeYellow, "~"), headerFrom(p.Serial), p.Serial.Writes)
	}
}

// serialWarning prints rows 1 and 3's note (forged, removal-only) on a
// change.
func serialWarning(w io.Writer, p ServerPlan, pal palette) {
	if p.SerialNote != "" {
		fmt.Fprintf(w, "  %s %s\n", pal.paint(codeYellow, "warning:"), p.SerialNote)
	}
}

// summaryLine is a change's last line: the key counts, or "header only".
func summaryLine(w io.Writer, p ServerPlan) {
	if p.HeaderOnly {
		fmt.Fprintf(w, "  → %s desired · header only\n", Plural(len(p.Desired), "key", "keys"))
		return
	}
	fmt.Fprintf(w, "  → %s desired · %d add · %d remove · %d rewrite\n",
		Plural(len(p.Desired), "key", "keys"), len(p.Add), len(p.Remove), len(p.Rewrites))
}
```

(Match the existing tabwriter variable's type for `tw` — `*tabwriter.Writer` satisfies `io.Writer`.) Then add:

```go
// headerFrom names the header a header-only write replaces: "no serial"
// (legacy), "serial S", or "forged serial S".
func headerFrom(sp SerialPlan) string {
	switch {
	case sp.Case == SerialForged:
		return fmt.Sprintf("forged serial %d", sp.Header)
	case sp.Header == 0:
		return "no serial"
	default:
		return fmt.Sprintf("serial %d", sp.Header)
	}
}
```

- [ ] **Step 4: Regenerate, read back, run**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply/ -run TestRenderPlanSerialGolden -update && cat internal/apply/testdata/plan_serial.golden && GOTOOLCHAIN=go1.27.3 go test -race ./internal/apply/ && golangci-lint run --enable-only=gocyclo ./internal/apply/`
Expected: six server blocks in name order; `s-older` shows `+ alice … add (authorized, missing)` with `→ 2 keys desired · 1 add · 0 remove · 0 rewrite`; `s-removal` shows `- (unknown) "stray"`; every pre-existing golden unchanged; `ok`.

### Task 21: apply/revoke/rotate JSON (spec §9) and the `record-key` edit

**Files:**
- Modify: `internal/apply/json.go` (`JSONOptions`, `jsonDoc`, `jsonServer`, `jsonNotes`, `jsonEdit`, `jsonEditFor`, `jsonServerFor`, `RenderJSON`), `internal/apply/edit.go` (`EditKind` consts, `EditSummary`, `editText`)
- Test: `internal/apply/json_test.go`, `internal/apply/edit_test.go`; goldens `internal/apply/testdata/json_serial.golden.json` (new), `json_edit_memory.golden.json` (new); regenerate the edit-bearing JSON goldens (`json_revoke`, `json_rotate_edit_only`, `json_rotate_keep_old`, `json_remove_access`, `json_withheld`)

- [ ] **Step 1: Write the failing tests**

Append to `internal/apply/json_test.go`:

```go
func TestRenderJSONSerialGolden(t *testing.T) {
	cfg, plans := serialFleet(t)
	got := renderJSONCfg(t, cfg, plans, JSONOptions{Command: "revoke", DryRun: true})
	checkGolden(t, "json_serial.golden.json", got)
	for _, want := range []string{
		`"case": "header_only"`, `"case": "forged"`, `"case": "newer_converged"`, `"case": "newer_removal_only"`,
		`"case": "newer_refused"`, `"case": "older"`, `"header": null`, `"writes": null`,
		`"serial": "written by newer manifest serial 8 (yours is 7): pull the latest manifest"`,
	} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("document lacks %s", want)
		}
	}
}

// TestRenderJSONSerialOmittedAtZero: a serial-0 fleet's documents are
// byte-identical to before (no serial object).
func TestRenderJSONSerialOmittedAtZero(t *testing.T) {
	cfg, plans := mixedPlans(t)
	if got := renderJSONCfg(t, cfg, plans, JSONOptions{Command: "apply"}); bytes.Contains(got, []byte(`"serial"`)) {
		t.Errorf("serial object on a serial-0 fleet:\n%s", got)
	}
}

func TestRenderJSONManifestMemoryTopLevel(t *testing.T) {
	cfg, err := config.Parse([]byte(`users:
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
revoked:
  - {fingerprint: ` + fp(t, 2) + `, user: alice, date: 2026-11-08}
  - {user: alice, servers: [db-9], date: 2026-11-08}
`))
	if err != nil {
		t.Fatal(err)
	}
	to := uint64(8)
	got := renderJSONCfg(t, cfg, nil, JSONOptions{Command: "apply", DryRun: true, SerialBump: &SerialBump{From: 7, To: &to}})
	var doc struct {
		PolicyConflicts []config.Conflict         `json:"policy_conflicts"`
		ManifestWarns   []config.TombstoneWarning `json:"manifest_warnings"`
		SerialBump      map[string]any            `json:"serial_bump"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.PolicyConflicts) != 1 || doc.PolicyConflicts[0].Kind != "revoked_key" || len(doc.ManifestWarns) != 1 ||
		doc.ManifestWarns[0].Server != "db-9" || doc.SerialBump["to"] != float64(8) || doc.SerialBump["saved"] != false {
		t.Errorf("document = %s", got)
	}
	piped := renderJSONCfg(t, cfg, nil, JSONOptions{Command: "apply", SerialBump: &SerialBump{From: 7,
		Warning: "removing keys without a serial bump: an older copy could re-grant them"}})
	if !bytes.Contains(piped, []byte(`"to": null`)) || !bytes.Contains(piped, []byte(`"warning": "removing keys without a serial bump`)) {
		t.Errorf("piped document = %s", piped)
	}
	saved := renderJSONCfg(t, cfg, nil, JSONOptions{Command: "apply", SerialBump: &SerialBump{From: 7, To: &to, Saved: true}})
	// One golden pins the three serial_bump shapes (spec §9: dry-run, saved,
	// piped) and the policy_conflicts / manifest_warnings objects.
	all := append(append(append([]byte(nil), got...), saved...), piped...)
	checkGolden(t, "json_memory_top.golden.json", all)
}

func TestRenderJSONEditMemoryGolden(t *testing.T) {
	cfg := planCfg(t)
	s := EditSummary{
		Edits: []Edit{
			{Kind: EditRemoveKey, User: "bob", Fingerprint: fp(t, 3)},
			{Kind: EditRecordKey, Fingerprint: fp(t, 9)},
		},
		Serial: 8,
		Revoked: []config.Tombstone{
			{Fingerprint: fp(t, 3), User: "bob", Date: "2026-11-08", Reason: "offboarded"},
			{Fingerprint: fp(t, 9), Date: "2026-11-08"},
		},
		AlreadyRevoked: []AlreadyRevoked{{User: "carol", Date: "2026-11-01"}},
		CheckCommand:   "sshepherd audit --config fleet.yaml",
	}
	got := renderJSONCfg(t, cfg, nil, JSONOptions{Command: "revoke", Edit: &s, Saved: true})
	checkGolden(t, "json_edit_memory.golden.json", got)
	if unsaved := renderJSONCfg(t, cfg, nil, JSONOptions{Command: "revoke", DryRun: true, Edit: &s}); bytes.Contains(unsaved, []byte(`"serial": 8`)) {
		t.Errorf("edit.serial must be omitted when nothing was saved:\n%s", unsaved)
	}
	empty := renderJSONCfg(t, cfg, nil, JSONOptions{Command: "revoke", Edit: &EditSummary{}})
	if !bytes.Contains(empty, []byte(`"revoked": []`)) {
		t.Errorf("edit.revoked must be [] when none:\n%s", empty)
	}
}
```

Append to `internal/apply/edit_test.go`:

```go
func TestEditHeaderRecordKey(t *testing.T) {
	var b bytes.Buffer
	RenderEditHeader(&b, EditSummary{Edits: []Edit{{Kind: EditRecordKey, Fingerprint: "SHA256:x"}}}, RenderOptions{})
	if want := "manifest edit: record revoked key SHA256:x (no user has it; no server is written) — no servers affected\n"; b.String() != want {
		t.Errorf("header = %q, want %q", b.String(), want)
	}
}
```

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply/ -run 'JSON|EditHeaderRecordKey'`
Expected: build failure (`SerialBump`, `EditRecordKey`, `AlreadyRevoked` undefined).

- [ ] **Step 3: Implement**

`internal/apply/edit.go`: add the kind and fields.

```go
// The five edits.
const (
	EditRemoveUser   EditKind = "remove-user"   // revoke USER
	EditRemoveKey    EditKind = "remove-key"    // revoke --key
	EditRotate       EditKind = "rotate"        // rotate USER --old --new
	EditRemoveAccess EditKind = "remove-access" // revoke USER --server
	EditRecordKey    EditKind = "record-key"    // revoke --key of a key no user has (D1b): a tombstone, no server written
)
```

```go
// AlreadyRevoked is a revoke target an earlier revoke already recorded
// (D1c: a user or a user's access; D1b: an unowned fingerprint): a no-op,
// exit 0. The json tags are edit.already_revoked's wire shape.
type AlreadyRevoked struct {
	User        string   `json:"user,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Servers     []string `json:"servers,omitempty"`
	Date        string   `json:"date"`
}
```

Add to `EditSummary` after `Emptied`:

```go
	// Serial is the manifest serial the edit saves (every saving revoke and
	// rotate bumps it once).
	Serial uint64
	// Revoked are the tombstones this edit adds to revoked:.
	Revoked []config.Tombstone
	// AlreadyRevoked are the targets an earlier revoke already recorded.
	AlreadyRevoked []AlreadyRevoked
	// CheckCommand is the printed follow-up audit ("" when no key was
	// removed, or when --sweep ran).
	CheckCommand string
```

(`edit.go` now imports `internal/config`.) In `editText`, add before `default:`:

```go
	case EditRecordKey:
		return fmt.Sprintf("record revoked key %s (no user has it; no server is written)", e.Fingerprint)
```

`internal/apply/json.go`:

```go
// SerialBump is apply's D4b serial bump (spec §6) for the JSON document:
// From → To, saved or not. To is nil and Warning set when the manifest
// cannot be saved (a piped --config).
type SerialBump struct {
	From    uint64  `json:"from"`
	To      *uint64 `json:"to"`
	Saved   bool    `json:"saved"`
	Warning string  `json:"warning,omitempty"`
}
```

Add `SerialBump *SerialBump // apply only (D4b); nil unless the run would bump` to `JSONOptions`. Add to `jsonDoc` after `Servers`:

```go
	// PolicyConflicts, ManifestWarnings and SerialBump are additive-optional
	// (schema stays 1), each omitted when empty.
	PolicyConflicts  []config.Conflict         `json:"policy_conflicts,omitempty"`
	ManifestWarnings []config.TombstoneWarning `json:"manifest_warnings,omitempty"`
	SerialBump       *SerialBump               `json:"serial_bump,omitempty"`
```

Add to `jsonServer` after `Notes`: `Serial *jsonSerial `json:"serial,omitempty"`` with

```go
// jsonSerial is the §3 verdict: header is null for no serial, writes null
// when nothing is written.
type jsonSerial struct {
	Header   *uint64 `json:"header"`
	Manifest uint64  `json:"manifest"`
	Writes   *uint64 `json:"writes"`
	Case     string  `json:"case"`
}

func jsonSerialFor(p ServerPlan) *jsonSerial {
	sp := p.Serial
	if sp.Case == "" || (sp.Header == 0 && sp.Manifest == 0) {
		return nil
	}
	js := &jsonSerial{Manifest: sp.Manifest, Case: string(sp.Case)}
	if sp.Header > 0 {
		h := sp.Header
		js.Header = &h
	}
	if p.Class == ClassChange {
		w := sp.Writes
		js.Writes = &w
	}
	return js
}
```

Add to `jsonNotes`: `Serial string `json:"serial,omitempty"``. Add to `jsonEdit`:

```go
	Serial         *uint64          `json:"serial,omitempty"`
	Revoked        []jsonTombstone  `json:"revoked"`
	AlreadyRevoked []AlreadyRevoked `json:"already_revoked,omitempty"`
	CheckCommand   string           `json:"check_command,omitempty"`
```

```go
// jsonTombstone is a revoked: entry in the manifest's own shape.
type jsonTombstone struct {
	Fingerprint string   `json:"fingerprint,omitempty"`
	User        string   `json:"user,omitempty"`
	Servers     []string `json:"servers,omitempty"`
	Date        string   `json:"date"`
	Reason      string   `json:"reason,omitempty"`
}
```

In `jsonEditFor`, after building `e`:

```go
	e.Revoked = make([]jsonTombstone, 0, len(s.Revoked))
	for _, t := range s.Revoked {
		e.Revoked = append(e.Revoked, jsonTombstone{Fingerprint: t.Fingerprint, User: clean(t.User),
			Servers: t.Servers, Date: t.Date, Reason: clean(t.Reason)})
	}
	if saved && s.Serial > 0 {
		serial := s.Serial
		e.Serial = &serial
	}
	e.AlreadyRevoked, e.CheckCommand = s.AlreadyRevoked, clean(s.CheckCommand)
```

and in its edit loop add `case EditRecordKey: je.Fingerprint = ed.Fingerprint`. In `jsonServerFor`, set `Serial: jsonSerialFor(p)` in the literal and `Serial: clean(p.SerialNote)` in `Notes`. In `RenderJSON`, after the edit block:

```go
	doc.PolicyConflicts, doc.ManifestWarnings = cleanMemory(cfg)
	doc.SerialBump = opts.SerialBump
```

```go
// cleanMemory is the manifest's policy conflicts and D1e warnings with
// every manifest-derived text passed through clean (spec §9: "sanitized
// like today's text fields"). A D1e warning's server can be any string —
// even one with control runes (plan decision 3) — so this is not
// cosmetic. Each list stays nil when empty (omitted).
func cleanMemory(cfg *config.Config) ([]config.Conflict, []config.TombstoneWarning) {
	cs := cfg.Conflicts() // a copy
	for i := range cs {
		cs[i].Message, cs[i].User = clean(cs[i].Message), clean(cs[i].User)
	}
	ws := slices.Clone(cfg.TombstoneWarnings)
	for i := range ws {
		ws[i].User, ws[i].Server, ws[i].Message = clean(ws[i].User), clean(ws[i].Server), clean(ws[i].Message)
	}
	return cs, ws
}
```

(`json.go` imports `"slices"` if it does not already.)

- [ ] **Step 4: Regenerate goldens, read them back, run**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply/ -run 'JSON' -update && git diff --stat internal/apply/testdata && git diff internal/apply/testdata/json_revoke.golden.json && GOTOOLCHAIN=go1.27.3 go test -race ./internal/apply/`
Expected: new `json_serial.golden.json`, `json_edit_memory.golden.json` and `json_memory_top.golden.json` (three documents: dry-run `"saved": false` with `"to": 8`, saved `"saved": true`, piped `"to": null` with the warning; each with one `policy_conflicts` and one `manifest_warnings` entry); the five edit-bearing goldens gain only `"revoked": []` inside `edit`; no other golden changes; `ok`.

### Task 22: the workflow passes `Bumped` and lets the commit re-render headers

**Files:**
- Modify: `internal/workflow/workflow.go:45-52` (`ManifestCommitter` doc)
- Test: `internal/workflow/workflow_test.go`

- [ ] **Step 1: Write the tests**

```go
// captureWriter records each write's content.
type captureWriter struct {
	mu   sync.Mutex
	sent map[string]string
}

func (w *captureWriter) Apply(_ context.Context, s config.Server, req fleet.WriteRequest) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sent[s.Name] = string(req.Content)
	return nil
}

// serialFixture: server "a" already holds exactly the render's body under
// a legacy header; the manifest is at serial 3.
func serialFixture(t *testing.T, r *rec) Request {
	t.Helper()
	req := fixture(t, r)
	line := testkeys.Line(t, 1)
	cfg, err := config.Parse([]byte("serial: 3\nusers:\n  - {name: alice, keys: [\"" + line + "\"]}\n" +
		"servers:\n  - {name: a, host: 10.0.0.1, user: deploy}\n" +
		"access:\n  - {user: alice, servers: [a]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	req.Cfg, req.Servers = cfg, cfg.Servers
	req.Reader = fakeReader{content: map[string]string{"a": authkeys.ManagedHeader + "\n" + line + " alice\n"}}
	return req
}

// TestApplyBumpedPlansHeaderOnly: Bumped reaches apply.BuildWith — the
// equal-body server is a header-only change instead of converged.
func TestApplyBumpedPlansHeaderOnly(t *testing.T) {
	for _, bumped := range []bool{false, true} {
		r := &rec{}
		req := serialFixture(t, r)
		req.DryRun, req.Bumped = true, bumped
		out, err := Apply(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if got := out.Plans[0].HeaderOnly; got != bumped {
			t.Errorf("Bumped=%v: HeaderOnly = %v (plan %+v)", bumped, got, out.Plans[0])
		}
	}
}

// TestCommitMayRewriteHeaders: what Commit leaves in plans[i].Rendered is
// what the writer sends (apply's D4b re-renders headers after its save).
// A regression pin: confirmAndWrite already passes out.Plans to both seams;
// this keeps a future copy of the plans from breaking D4b.
func TestCommitMayRewriteHeaders(t *testing.T) {
	r := &rec{}
	req := fixture(t, r)
	w := &captureWriter{sent: map[string]string{}}
	req.Writer = w
	req.Committer = CommitFunc(func(_ context.Context, plans []apply.ServerPlan, _ []fleet.HeldKey) (bool, error) {
		plans[0].Rendered = []byte("rewritten\n")
		return true, nil
	})
	if _, err := Apply(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if w.sent["a"] != "rewritten\n" {
		t.Fatalf("writer got %q, want the committer's bytes", w.sent["a"])
	}
}
```

- [ ] **Step 2: Run them**

Run: `GOTOOLCHAIN=go1.27.3 go test -race ./internal/workflow/ -run 'TestApplyBumpedPlansHeaderOnly|TestCommitMayRewriteHeaders'`
Expected: `ok` (Task 16 wired `Bumped`; `confirmAndWrite` already passes `out.Plans` to both seams). Both are pins of code that exists, so prove they bite (in your worktree; revert after each):
- drop `Bumped: req.Bumped` from the `apply.BuildWith` call in `workflow.go` (`apply.BuildOptions{}`) → `TestApplyBumpedPlansHeaderOnly` FAILs (`Bumped=true: HeaderOnly = false`);
- in `confirmAndWrite`, hand the committer a copy (`slices.Clone(out.Plans)`) → `TestCommitMayRewriteHeaders` FAILs (the writer gets the original bytes).

- [ ] **Step 3: Document the contract**

`ManifestCommitter.Commit`'s doc comment gains: "Commit may re-render the managed header of plans in place (apply.Reserial, apply's D4b serial bump); it must change nothing else in them. Execute writes what Commit leaves in plans[i].Rendered."

- [ ] **Step 4: Gate and hand back**

Run: `make check` (no README delta in this lane), then `make integration` under the runner's lock.
Expected: green; existing E2E unchanged (every E2E manifest is at serial 0 until round 3).

Hand back (lane `apply`; the integrator commits `feat(apply): serial rows, header-only writes, D29 refusals, JSON §9 (P04 W4, PRD-2)`).

**docsDelta (lane `apply`):**
- README `### sshepherd apply`: a new paragraph **Manifest serial** after the full-file rewrite paragraph: the header carries `(serial N)` once the manifest has one; apply compares each server's header serial S with the manifest's M — a server written by a newer manifest is refused unless the write only removes keys (`written by manifest serial S, this manifest is M — a newer manifest revoked or rotated keys here; pull the latest manifest, or if you are sure, set serial: S in your manifest (this is the only override)`); with an equal body it is converged with the note `written by newer manifest serial S (yours is M): pull the latest manifest` (exit 0); a removal-only write proceeds and keeps S; a header more than 1000 above M is treated as forged (`header claims serial S, far above this manifest's M — treated as no serial`) and rewritten; revoke/rotate write a header-only update (a `~ (header)` row reading `update header: serial 6 → 7 (keys unchanged)`, summary `→ N keys desired · header only`) on affected servers whose keys already match. Copy one block per case from `internal/apply/testdata/plan_serial.golden`.
- README `### sshepherd apply`, policy conflicts: "a server a policy conflict names is refused with the conflict message (exit 1); the rest of the fleet is planned normally."
- README `### sshepherd apply` JSON paragraph: the per-server `serial` object, `notes.serial`, top-level `policy_conflicts`, `manifest_warnings`, `serial_bump`; for revoke/rotate `edit.serial`, `edit.revoked`, `edit.already_revoked`, `edit.check_command`, and the `record-key` edit kind — samples from `json_serial.golden.json` and `json_edit_memory.golden.json`.

---
## Round 2 — lane `audit` (Tasks 23–27)

Owns: `internal/audit/**`, `cmd/sshepherd/audit.go`, `cmd/sshepherd/audit_test.go`, `cmd/sshepherd/audit_hermetic_test.go`, `cmd/sshepherd/run.go`, `cmd/sshepherd/testdata/help/audit.golden`. Findings: PRD-1 (D2, D1d, D29), PRD-2 (D4a, forged). `needsIntegration: false`.

Do not rename or re-sign the exported helpers lane `apply` calls in the same round: `UnknownLabel`, `UnknownOptions`, `ErrorTag`, `Hints`/`Write`, `CleanHint`, `Run`, `Options`, `ServerResult`, `KeyReader`, `GrantedFingerprints`.

### Task 23: `ServerResult` carries the header serial and the `authorized_keys2` bytes

**Files:**
- Modify: `internal/audit/audit.go:26-42` (`ServerResult`), `:139-142` (`auditOne`)
- Test: `internal/audit/audit_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestAuditOneReadsHeaderSerial(t *testing.T) {
	cfg := reportConfig(t)
	reader := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(authkeys.Header(8) + "\n" + testkeys.Line(t, 1) + "\n"), Keys2: []byte("k2\n"), Keys2Err: errors.New("x")},
		"web-2": {FileAbsent: true},
	}}
	res := Run(context.Background(), cfg, reader, Options{Parallel: 1})
	if res[0].HeaderSerial != 8 || !res[0].HeaderManaged || string(res[0].Keys2) != "k2\n" || res[0].Keys2Err == nil {
		t.Errorf("web-1 = %+v", res[0])
	}
	if res[1].HeaderManaged || res[1].HeaderSerial != 0 {
		t.Errorf("an absent file has no header: %+v", res[1])
	}
}
```

- [ ] **Step 2: Run to see it fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/audit/ -run TestAuditOneReadsHeaderSerial`
Expected: build failure (`HeaderSerial undefined`).

- [ ] **Step 3: Implement**

Add to `ServerResult`:

```go
	// HeaderSerial and HeaderManaged are authkeys.ParseHeaderOf's verdict on
	// Content's first line: the serial of the manifest that last wrote the
	// file (0 for the legacy header), and whether it is a managed header at
	// all. Zero for an absent file.
	HeaderSerial  uint64
	HeaderManaged bool
	// Keys2 and Keys2Err carry fleet.ReadResult's authorized_keys2 read;
	// only the post-revoke sweep's reader asks for it.
	Keys2    []byte
	Keys2Err error
```

In `auditOne`, after `res.AuthorizedKeys2 = read.AuthorizedKeys2`:

```go
	res.Keys2, res.Keys2Err = read.Keys2, read.Keys2Err
	if !read.FileAbsent {
		res.HeaderSerial, res.HeaderManaged = authkeys.ParseHeaderOf(read.Content)
	}
```

- [ ] **Step 4: Run to see it pass**

Run: `GOTOOLCHAIN=go1.27.3 go test -race ./internal/audit/`
Expected: `ok`.

### Task 24: classification — critical and drift before compliant

**Files:**
- Modify: `internal/audit/report.go:15-39` (`ExitCode`), `:328-367` (`criticalDrift`, `statusOf`), `:369-395` (`tallyCounts`, `tallyResults`)
- Test: `internal/audit/memory_test.go` (new)

- [ ] **Step 1: Write the failing tests**

Create `internal/audit/memory_test.go`:

```go
package audit

import (
	"context"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// memoryConfig: serial 7; op (k1) operator; alice (k2) -> web-1, web-2;
// bob (k3) -> web-1 (an access tombstone removed his web-2); carol's key
// (k9) is revoked. extra is appended to revoked:.
func memoryConfig(t *testing.T, extra string) *config.Config {
	t.Helper()
	y := `serial: 7
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 3) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
  - {user: bob, servers: [web-1]}
revoked:
  - {fingerprint: ` + fpOf(t, 9) + `, user: carol, date: 2026-11-08, reason: offboarded}
  - {user: bob, servers: [web-2], date: 2026-11-08}
` + extra
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("memoryConfig: %v", err)
	}
	return cfg
}

// (fpOf is internal/audit/audit_test.go's existing helper.)

// memFiles builds each server's content: a first line, then key lines.
func memFiles(t *testing.T, first string, web1, web2 []byte) *fakeReader {
	t.Helper()
	line := func(seeds []byte) string {
		s := first + "\n"
		for _, b := range seeds {
			s += testkeys.Line(t, b) + "\n"
		}
		return s
	}
	return &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(line(web1))},
		"web-2": {Content: []byte(line(web2))},
	}}
}

func memoryRun(t *testing.T, cfg *config.Config, r KeyReader) []ServerResult {
	t.Helper()
	return Run(context.Background(), cfg, r, Options{Parallel: 2})
}

func TestExitCodeRevokedKeyIsCritical(t *testing.T) {
	cfg := memoryConfig(t, "")
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(7), []byte{1, 2, 3, 9}, []byte{1, 2}))
	if s := statusOf(cfg, res[0]); s != statusCritical {
		t.Errorf("web-1 status = %s, want critical", s)
	}
	if code := ExitCode(cfg, res); code != 2 {
		t.Errorf("ExitCode = %d, want 2", code)
	}
}

func TestStatusAccessTombstoneIsDrift(t *testing.T) {
	cfg := memoryConfig(t, "")
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(7), []byte{1, 2, 3}, []byte{1, 2, 3}))
	if s := statusOf(cfg, res[1]); s != statusDrift {
		t.Errorf("web-2 status = %s, want drift (D1d)", s)
	}
	if code := ExitCode(cfg, res); code != 1 {
		t.Errorf("ExitCode = %d, want 1", code)
	}
}

func TestStatusSerialAheadIsDrift(t *testing.T) {
	cfg := memoryConfig(t, "")
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(8), []byte{1, 2, 3}, []byte{1, 2}))
	if s := statusOf(cfg, res[0]); s != statusDrift {
		t.Errorf("key-compliant web-1 at serial 8 = %s, want drift (D4a)", s)
	}
	if code := ExitCode(cfg, res); code != 1 {
		t.Errorf("ExitCode = %d, want 1", code)
	}
}

func TestForgedSerialIsCritical(t *testing.T) {
	cfg := memoryConfig(t, "")
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(7+authkeys.ForgedMargin+1), []byte{1, 2, 3}, []byte{1, 2}))
	if s := statusOf(cfg, res[0]); s != statusCritical {
		t.Errorf("forged header on a key-compliant server = %s, want critical", s)
	}
	if code := ExitCode(cfg, res); code != 2 {
		t.Errorf("ExitCode = %d, want 2", code)
	}
}

func TestOlderHeaderSerialIsCompliant(t *testing.T) {
	cfg := memoryConfig(t, "")
	for _, first := range []string{authkeys.Header(6), authkeys.ManagedHeader} {
		res := memoryRun(t, cfg, memFiles(t, first, []byte{1, 2, 3}, []byte{1, 2}))
		if code := ExitCode(cfg, res); code != 0 {
			t.Errorf("%q: ExitCode = %d, want 0 (an older header is not drift)", first, code)
		}
	}
}

func TestPolicyConflictIsCritical(t *testing.T) {
	cfg := memoryConfig(t, "  - {fingerprint: "+fpOf(t, 3)+", date: 2026-11-08}\n") // bob's key, still listed
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(7), []byte{1, 2, 3}, []byte{1, 2}))
	if s := statusOf(cfg, res[0]); s != statusCritical {
		t.Errorf("web-1 (named by the conflict) = %s, want critical", s)
	}
	if s := statusOf(cfg, res[1]); s != statusCompliant {
		t.Errorf("web-2 = %s, want compliant", s)
	}
	if code := ExitCode(cfg, nil); code != 2 {
		t.Errorf("ExitCode with no servers read = %d, want 2 (a conflict pages on its own)", code)
	}
}
```

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/audit/ -run 'Revoked|AccessTombstone|SerialAhead|Forged|OlderHeader|PolicyConflict'`
Expected: FAIL — revoked key and forged header are "drift"/"compliant", serial-ahead "compliant", conflicts ignored.

- [ ] **Step 3: Implement**

In `report.go`, `ExitCode` gains a first check and an updated doc:

```go
// ExitCode maps audit results to the process exit code (monitoring-style,
// see docs/superpowers/specs/2026-07-16-audit-json-exit-codes-design.md and
// the 2026-11-08 revocation-memory spec §8): 0 every server compliant (an
// empty fleet is trivially compliant; a header serial below the manifest's
// is not drift); 1 drift and/or unreachable servers — including a server
// written by a newer manifest (D4a) and a key installed where its access
// was revoked (D1d); 2 critical — a missing operator key, a revoked key
// still installed (D2), a forged header serial, a policy conflict in the
// manifest (D29, even with no server read), or a host key that changed (or
// is @revoked). Tool errors (exit 3) are the caller's domain.
func ExitCode(cfg *config.Config, results []ServerResult) int {
	if len(cfg.Conflicts()) > 0 {
		return 2
	}
	code := 0
	… (the loop, unchanged)
```

Replace `criticalDrift` and `statusOf`:

```go
// criticalDrift reports drift that threatens the fleet: a missing operator
// key, a revoked key still installed (D2), a forged header serial, or a
// policy conflict naming this server (D29).
func criticalDrift(cfg *config.Config, r ServerResult) bool {
	if r.Err != nil {
		return false // unreachable: nothing knowable about its keys
	}
	for _, k := range r.Diff.Missing {
		if u, ok := cfg.OwnerOf(k.Fingerprint); ok && u.Operator {
			return true
		}
	}
	for _, k := range r.Diff.Unauthorized {
		if _, revoked := cfg.Revoked(k.Fingerprint); revoked {
			return true
		}
	}
	return r.forged(cfg.Serial()) || inConflict(cfg, r.Server.Name)
}

// forged: the header claims a serial more than authkeys.ForgedMargin above
// the manifest's — someone edited the file.
func (r ServerResult) forged(m uint64) bool {
	return r.HeaderManaged && r.HeaderSerial > m+authkeys.ForgedMargin
}

// serialAhead: a newer manifest wrote this server (D4a) — drift, not critical.
func (r ServerResult) serialAhead(m uint64) bool {
	return r.HeaderManaged && r.HeaderSerial > m && !r.forged(m)
}

// inConflict reports whether a policy conflict names server.
func inConflict(cfg *config.Config, server string) bool {
	for _, c := range cfg.Conflicts() {
		if slices.Contains(c.Servers, server) {
			return true
		}
	}
	return false
}
```

```go
// statusOf is the single classifier behind the JSON status field, the
// summary counts, and the exit code. Precedence: unreachable (nothing
// knowable) > critical > drift > compliant — critical and drift are checked
// first, so a key-compliant server with a forged or newer header, or one a
// policy conflict names, is never reported compliant.
func statusOf(cfg *config.Config, r ServerResult) serverStatus {
	switch {
	case r.Err != nil:
		return statusUnreachable
	case criticalDrift(cfg, r):
		return statusCritical
	case !r.Compliant() || r.serialAhead(cfg.Serial()):
		return statusDrift
	default:
		return statusCompliant
	}
}
```

Add `revokedKeys int` to `tallyCounts` and, in `tallyResults`, at the top of the loop:

```go
		for _, k := range r.Diff.Unauthorized {
			if _, revoked := cfg.Revoked(k.Fingerprint); revoked && r.Err == nil {
				c.revokedKeys++
			}
		}
```

(`report.go` imports `"slices"`.)

- [ ] **Step 4: Run to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test -race ./internal/audit/`
Expected: `ok` — every existing test and golden unchanged (serial-0 manifests, legacy headers).

### Task 25: the text report — REVOKED rows, access-revoked label, conflict block, serial lines

**Files:**
- Modify: `internal/audit/report.go:84-96` (`Render`), `:137-202` (`renderServer`)
- Test: `internal/audit/memory_test.go`; goldens `internal/audit/testdata/report_revoked.golden`, `report_serial_ahead.golden` (new)

- [ ] **Step 1: Write the failing tests**

```go
func TestRenderRevokedGolden(t *testing.T) {
	// alice's access to web-1 is tombstoned while her grant (web-1, web-2)
	// still names it: a revoked_access conflict whose Servers is the whole
	// grant (spec §2), so both servers carry the conflict line. Key 8 has an
	// unlabelled tombstone (spec §5: "(REVOKED 2026-11-08)") and sits on web-2.
	cfg := memoryConfig(t, "  - {user: alice, servers: [web-1], date: 2026-11-08}\n  - {fingerprint: "+fpOf(t, 8)+", date: 2026-11-08}\n")
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(7), []byte{1, 2, 3, 9}, []byte{1, 2, 3, 8}))
	var b bytes.Buffer
	Render(&b, cfg, res, RenderOptions{})
	checkGolden(t, "report_revoked.golden", b.Bytes())
	for _, want := range []string{
		`‼ manifest: user "alice" is granted "web-1" by access[0], but revoked[2] removed that access (2026-11-08): remove the grant, or delete the revoked: entry to restore it deliberately (CRITICAL: policy conflict)` + "\n\n",
		"carol (REVOKED 2026-11-08)",
		"installed but REVOKED (CRITICAL: revoked key)\n",
		"bob (access revoked 2026-11-08)",
		"→ exit 2\n",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, b.String())
		}
	}
	if n := strings.Count(b.String(), "  ‼ named by a manifest policy conflict above (CRITICAL: policy conflict)\n"); n != 2 {
		t.Errorf("conflict lines = %d, want 2 (web-1 and web-2: the whole grant)", n)
	}
	// The unlabelled tombstone's row: the label cell is "(REVOKED DATE)" alone.
	if !regexp.MustCompile(`‼ +\(REVOKED 2026-11-08\) +` + regexp.QuoteMeta(fpOf(t, 8))).MatchString(b.String()) {
		t.Errorf("report lacks the unlabelled REVOKED row for key 8:\n%s", b.String())
	}
}

func TestRenderSerialAheadGolden(t *testing.T) {
	cfg := memoryConfig(t, "")
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(8), []byte{1, 2, 3}, []byte{1, 2}))
	res[1].HeaderSerial = 9999 // web-2: forged (the reader cannot vary per server here)
	var b bytes.Buffer
	Render(&b, cfg, res, RenderOptions{})
	checkGolden(t, "report_serial_ahead.golden", b.Bytes())
	for _, want := range []string{
		"  ⚠ written by newer manifest serial 8 (yours is 7): pull the latest manifest\n",
		"  ‼ header claims serial 9999, far above this manifest's 7 — someone edited this file (CRITICAL: forged header)\n",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, b.String())
		}
	}
}

func TestRenderEmptyFleetShowsConflicts(t *testing.T) {
	cfg, err := config.Parse([]byte("users:\n  - {name: a, keys: [\"" + testkeys.Line(t, 1) + "\"]}\nrevoked:\n  - {fingerprint: " + fpOf(t, 1) + ", date: 2026-11-08}\n"))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	Render(&b, cfg, nil, RenderOptions{})
	if !strings.HasPrefix(b.String(), "‼ manifest: key ") || !strings.HasSuffix(b.String(), "Summary: 0 servers configured — nothing to audit\n") {
		t.Errorf("report = %q", b.String())
	}
}
```

(Add `"bytes"`, `"regexp"`, `"strings"` to the test imports. The color variant is covered by the existing `TestRenderColorStrippedEqualsPlain` pattern; add the revoked fixture to it: `for _, fixture := range …` — or, if it is not table-driven, add one more call with `memoryConfig` results.)

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/audit/ -run 'TestRender(Revoked|SerialAhead)Golden|TestRenderEmptyFleetShowsConflicts'` (no `-update`: a golden written now would pin pre-implementation output)
Expected: FAIL — `read golden (run with -update first)` for the two goldens, and `TestRenderEmptyFleetShowsConflicts` lacks the `‼ manifest:` line.

- [ ] **Step 3: Implement**

`Render`:

```go
func Render(w io.Writer, cfg *config.Config, results []ServerResult, opts RenderOptions) {
	pal := palette{on: opts.Color}
	renderConflicts(w, cfg, pal)
	if len(results) == 0 {
		fmt.Fprintln(w, "Summary: 0 servers configured — nothing to audit")
		return
	}
	var hints Hints
	for _, r := range results {
		renderServer(w, cfg, r, pal, opts.Comments, &hints)
		fmt.Fprintln(w)
	}
	renderSummary(w, cfg, results)
}

// renderConflicts prints the manifest's policy conflicts (D29) before any
// server: each one is critical on its own.
func renderConflicts(w io.Writer, cfg *config.Config, pal palette) {
	cs := cfg.Conflicts()
	for _, c := range cs {
		fmt.Fprintf(w, "%s manifest: %s (%s: policy conflict)\n", pal.paint(codeBoldRed, "‼"), c.Message, pal.paint(codeBoldRed, "CRITICAL"))
	}
	if len(cs) > 0 {
		fmt.Fprintln(w)
	}
}
```

In `renderServer`, the unauthorized loop (`:168-179`) becomes:

```go
	for _, k := range r.Diff.Unauthorized {
		if t, revoked := cfg.Revoked(k.Fingerprint); revoked {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tinstalled but %s (%s: revoked key)\n",
				pal.paint(codeBoldRed, "‼"), revokedLabel(t), k.Fingerprint, k.Type,
				pal.paint(codeRed, "REVOKED"), pal.paint(codeBoldRed, "CRITICAL"))
			continue
		}
		// A key the manifest does not own also shows its on-server options:
		// with the comment, the only clue to what it is and what it can do.
		// A known owner's key keeps today's cell.
		suffix := ""
		if _, ok := cfg.OwnerOf(k.Fingerprint); !ok {
			suffix = UnknownOptions(k)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tinstalled but %s%s\n",
			pal.paint(codeYellow, "⚠"), unauthorizedLabel(cfg, r.Server.Name, k), k.Fingerprint, k.Type,
			pal.paint(codeYellow, "UNAUTHORIZED"), suffix)
	}
```

After the `AuthorizedKeys2` block (`:189-193`), call `renderMemoryNotes(w, cfg, r, pal)`:

```go
// renderMemoryNotes prints the server's serial and conflict findings: a
// forged header (critical), a newer manifest's header (drift, D4a), and
// membership in a policy conflict (critical, D29).
func renderMemoryNotes(w io.Writer, cfg *config.Config, r ServerResult, pal palette) {
	m := cfg.Serial()
	switch {
	case r.forged(m):
		fmt.Fprintf(w, "  %s header claims serial %d, far above this manifest's %d — someone edited this file (%s: forged header)\n",
			pal.paint(codeBoldRed, "‼"), r.HeaderSerial, m, pal.paint(codeBoldRed, "CRITICAL"))
	case r.serialAhead(m):
		fmt.Fprintf(w, "  ⚠ written by newer manifest serial %d (yours is %d): pull the latest manifest\n", r.HeaderSerial, m)
	}
	if inConflict(cfg, r.Server.Name) {
		fmt.Fprintf(w, "  %s named by a manifest policy conflict above (%s: policy conflict)\n",
			pal.paint(codeBoldRed, "‼"), pal.paint(codeBoldRed, "CRITICAL"))
	}
}

// revokedLabel labels a tombstoned key: "alice (REVOKED 2026-11-08)", or
// "(REVOKED 2026-11-08)" for an unlabelled tombstone.
func revokedLabel(t config.Tombstone) string {
	if t.User == "" {
		return "(REVOKED " + t.Date + ")"
	}
	return t.User + " (REVOKED " + t.Date + ")"
}

// unauthorizedLabel is label, widened for a known owner whose access to
// server an access tombstone removed (D1d): "bob (access revoked DATE)".
func unauthorizedLabel(cfg *config.Config, server string, k authkeys.Key) string {
	if u, ok := cfg.OwnerOf(k.Fingerprint); ok {
		if t, gone := cfg.AccessRevoked(u.Name, server); gone {
			return u.Name + " (access revoked " + t.Date + ")"
		}
	}
	return label(cfg, k)
}
```

- [ ] **Step 4: Regenerate, read back, run**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/audit/ -run 'TestRender(Revoked|SerialAhead)Golden' -update && cat internal/audit/testdata/report_revoked.golden internal/audit/testdata/report_serial_ahead.golden && GOTOOLCHAIN=go1.27.3 go test -race ./internal/audit/`
Expected: `report_revoked.golden` opens with the conflict line and a blank line; web-1 shows the `‼ carol (REVOKED 2026-11-08)` row and the conflict note; web-2 shows the unlabelled `‼ (REVOKED 2026-11-08)` row for key 8, `⚠ bob (access revoked 2026-11-08) … installed but UNAUTHORIZED` and the conflict note (alice's whole grant is in the conflict); summary ends `→ exit 2`. `report_serial_ahead.golden` ends `→ exit 2` (the forged web-2). Every older golden unchanged; `ok`.

### Task 26: audit JSON (spec §9)

**Files:**
- Modify: `internal/audit/json.go` (`jsonReport`, `jsonSummary`, `jsonServer`, `jsonKey`, `RenderJSON`, `jsonServerFor`)
- Test: `internal/audit/json_test.go`; goldens `report_revoked.golden.json`, `report_serial_ahead.golden.json` (new)

- [ ] **Step 1: Write the failing tests**

```go
func TestRenderJSONRevokedGolden(t *testing.T) {
	// revoked[2]: an access conflict; [3] an unknown server (D1e); [4] an
	// unknown server with a control rune (plan decision 3: a warning, and
	// sanitized here); [5] key 8, unlabelled, installed on web-2.
	cfg := memoryConfig(t, "  - {user: alice, servers: [web-1], date: 2026-11-08}\n  - {user: alice, servers: [db-9], date: 2026-11-08}\n"+
		"  - {user: alice, servers: [\"db\\e9\"], date: 2026-11-08}\n  - {fingerprint: "+fpOf(t, 8)+", date: 2026-11-08}\n")
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(7), []byte{1, 2, 3, 9}, []byte{1, 2, 3, 8}))
	got := renderJSON(t, cfg, res)
	checkGolden(t, "report_revoked.golden.json", got)
	for _, want := range []string{
		`"manifest_serial": 7`, `"policy_conflicts": [`, `"kind": "revoked_access"`, `"manifest_warnings": [`,
		`"kind": "tombstone_unknown_server"`, `"revoked_keys": 2`, `"policy_conflicts": 1`,
		`"revoked": {`, `"user": "carol"`, `"reason": "offboarded"`, `"access_revoked": {`, `"status": "critical"`,
	} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("document lacks %s", want)
		}
	}
	if bytes.ContainsRune(got, 0x1b) || bytes.Contains(got, []byte(`\u001b`)) {
		t.Errorf("a control rune from the manifest reached the document:\n%s", got)
	}
	// spec §9: an unlabelled tombstone's revoked object has no "user".
	var doc struct {
		Servers []struct {
			Keys struct {
				Unauthorized []struct {
					Fingerprint string         `json:"fingerprint"`
					Revoked     map[string]any `json:"revoked"`
				} `json:"unauthorized"`
			} `json:"keys"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range doc.Servers {
		for _, k := range s.Keys.Unauthorized {
			if k.Fingerprint == fpOf(t, 8) {
				_, hasUser := k.Revoked["user"]
				found = k.Revoked["date"] == "2026-11-08" && !hasUser
			}
		}
	}
	if !found {
		t.Errorf("key 8's revoked object must be {date} with no user:\n%s", got)
	}
}

func TestRenderJSONSerialAheadGolden(t *testing.T) {
	cfg := memoryConfig(t, "")
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(8), []byte{1, 2, 3}, []byte{1, 2}))
	res[1].HeaderSerial = 9999
	got := renderJSON(t, cfg, res)
	checkGolden(t, "report_serial_ahead.golden.json", got)
	for _, want := range []string{`"header_serial": 8`, `"manifest_serial_ahead": 8`, `"forged_header_serial": 9999`} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("document lacks %s", want)
		}
	}
}
```

(`json_test.go` already imports `bytes`, `encoding/json`, `config`, `fleet`, `testkeys`; add `internal/authkeys` if it is missing.)

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/audit/ -run 'TestRenderJSON(Revoked|SerialAhead)Golden'` (no `-update` yet)
Expected: FAIL — `read golden (run with -update first)` for both new goldens.

- [ ] **Step 3: Implement**

`jsonReport`:

```go
type jsonReport struct {
	Schema int `json:"schema"`
	// ManifestSerial, PolicyConflicts and ManifestWarnings are
	// additive-optional (schema stays 1), each omitted when zero/empty.
	ManifestSerial   uint64                    `json:"manifest_serial,omitempty"`
	PolicyConflicts  []config.Conflict         `json:"policy_conflicts,omitempty"`
	ManifestWarnings []config.TombstoneWarning `json:"manifest_warnings,omitempty"`
	Summary          jsonSummary               `json:"summary"`
	Servers          []jsonServer              `json:"servers"`
}
```

`jsonSummary` gains, after `HostKeyAlerts`:

```go
	// RevokedKeys and PolicyConflicts are additive-optional (schema stays
	// 1), omitted when zero: installed tombstoned keys across servers, and
	// the manifest's policy conflicts.
	RevokedKeys     int `json:"revoked_keys,omitempty"`
	PolicyConflicts int `json:"policy_conflicts,omitempty"`
```

`jsonServer` gains at the end:

```go
	// HeaderSerial, ManifestSerialAhead (D4a, drift) and ForgedHeaderSerial
	// (critical) are additive-optional (schema stays 1), omitted when 0.
	HeaderSerial        uint64 `json:"header_serial,omitempty"`
	ManifestSerialAhead uint64 `json:"manifest_serial_ahead,omitempty"`
	ForgedHeaderSerial  uint64 `json:"forged_header_serial,omitempty"`
```

`jsonKey` gains:

```go
	// Revoked (a tombstoned unauthorized key, critical) and AccessRevoked
	// (an owner's key where an access tombstone removed it, D1d drift) are
	// additive-optional (schema stays 1).
	Revoked       *jsonRevoked       `json:"revoked,omitempty"`
	AccessRevoked *jsonAccessRevoked `json:"access_revoked,omitempty"`
```

```go
type jsonRevoked struct {
	User   string `json:"user,omitempty"`
	Date   string `json:"date"`
	Reason string `json:"reason,omitempty"`
}

type jsonAccessRevoked struct {
	Date   string `json:"date"`
	Reason string `json:"reason,omitempty"`
}
```

In `RenderJSON`, set `rep.ManifestSerial = cfg.Serial()`, `rep.PolicyConflicts, rep.ManifestWarnings = memoryJSON(cfg)`, and in the summary `RevokedKeys: c.revokedKeys, PolicyConflicts: len(rep.PolicyConflicts)`.

`jsonServerFor` is at gocyclo 13 today (limit 15), so its new branches live in two helpers and it gains two calls: after the error early-return, `serialFields(&s, cfg, r)`; in the unauthorized loop, after the `Options` block and before the `append`, `memoryKey(&jk, cfg, r.Server.Name, k)`. Add:

```go
// serialFields sets the server's header-serial fields (spec §9): the
// header's serial, and the D4a (drift) or forged (critical) verdict.
func serialFields(s *jsonServer, cfg *config.Config, r ServerResult) {
	m := cfg.Serial()
	if r.HeaderManaged {
		s.HeaderSerial = r.HeaderSerial
	}
	switch {
	case r.forged(m):
		s.ForgedHeaderSerial = r.HeaderSerial
	case r.serialAhead(m):
		s.ManifestSerialAhead = r.HeaderSerial
	}
}

// memoryKey marks an unauthorized key the manifest remembers: a key
// tombstone (revoked, critical) or, for a known owner, an access tombstone
// on this server (access_revoked, D1d drift). Tombstone text is printed,
// so it passes sanitize.Remote like every text field (spec §9).
func memoryKey(jk *jsonKey, cfg *config.Config, server string, k authkeys.Key) {
	if t, revoked := cfg.Revoked(k.Fingerprint); revoked {
		jk.Revoked = &jsonRevoked{User: sanitize.Remote(t.User), Date: t.Date, Reason: sanitize.Remote(t.Reason)}
		return
	}
	if u, ok := cfg.OwnerOf(k.Fingerprint); ok {
		if t, gone := cfg.AccessRevoked(u.Name, server); gone {
			jk.AccessRevoked = &jsonAccessRevoked{Date: t.Date, Reason: sanitize.Remote(t.Reason)}
		}
	}
}

// memoryJSON is the manifest's policy conflicts and D1e warnings with
// every manifest-derived text through sanitize.Remote (spec §9). A D1e
// warning's server may hold control runes (plan decision 3). Each list
// stays nil when empty (omitted).
func memoryJSON(cfg *config.Config) ([]config.Conflict, []config.TombstoneWarning) {
	cs := cfg.Conflicts() // a copy
	for i := range cs {
		cs[i].Message, cs[i].User = sanitize.Remote(cs[i].Message), sanitize.Remote(cs[i].User)
	}
	ws := slices.Clone(cfg.TombstoneWarnings)
	for i := range ws {
		ws[i].User, ws[i].Server, ws[i].Message = sanitize.Remote(ws[i].User), sanitize.Remote(ws[i].Server), sanitize.Remote(ws[i].Message)
	}
	return cs, ws
}
```

(`json.go` imports `"slices"` and `internal/authkeys` if it does not already; `sanitize` it does.)

- [ ] **Step 4: Regenerate, read back, run**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/audit/ -run 'TestRenderJSON(Revoked|SerialAhead)Golden' -update && cat internal/audit/testdata/report_revoked.golden.json && GOTOOLCHAIN=go1.27.3 go test -race ./internal/audit/ && golangci-lint run --enable-only=gocyclo ./internal/audit/`
Expected: the new documents carry the fields above; every older `.golden.json` unchanged; `ok`.

### Task 27: `sshepherd audit` — a conflict pages on an empty fleet; the footer

**Files:**
- Modify: `cmd/sshepherd/audit.go:63-65`, `cmd/sshepherd/run.go:197-201` (`exitCodesAudit`)
- Test: `cmd/sshepherd/audit_test.go`; golden `cmd/sshepherd/testdata/help/audit.golden`

- [ ] **Step 1: Write the failing test**

```go
// TestAuditEmptyFleetConflictExits2: a policy conflict is critical on its
// own — a manifest with no servers still exits 2 (D29).
func TestAuditEmptyFleetConflictExits2(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	k, err := authkeys.ParseLine(testkeys.Line(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, "users:\n  - {name: alice, keys: [\""+testkeys.Line(t, 1)+"\"]}\n"+
		"revoked:\n  - {fingerprint: "+k.Fingerprint+", date: 2026-11-08}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", path}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr: %s)\n%s", code, errBuf.String(), out.String())
	}
	if !strings.Contains(out.String(), "(CRITICAL: policy conflict)") {
		t.Errorf("stdout = %q", out.String())
	}
}
```

- [ ] **Step 2: Run to see it fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run TestAuditEmptyFleetConflictExits2`
Expected: FAIL (`exit = 0`).

- [ ] **Step 3: Implement**

`cmd/sshepherd/audit.go` (`:63-65`):

```go
			if len(cfg.Servers) == 0 {
				if err := render(nil); err != nil {
					return err
				}
				return auditVerdict(cfg, nil) // a policy conflict is critical with no server read
			}
```

`cmd/sshepherd/run.go`:

```go
const exitCodesAudit = `Exit codes:
  0  compliant (a header serial below the manifest's is not drift)
  1  drift or unreachable servers (compliance not proven), including a server
     written by a newer manifest serial and a key installed where its access
     was revoked
  2  critical: a missing operator key, a changed or @revoked host key, a
     revoked key still installed, a forged header serial, or a policy
     conflict in the manifest
  3  tool error: bad flags, unloadable manifest, failed preflight, interrupted`
```

- [ ] **Step 4: Golden, README delta, gate**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run TestHelpGolden -update && git diff cmd/sshepherd/testdata/help/`
Expected: only `audit.golden`'s footer changes. Apply this lane's README delta to the worktree, then `make check` → green.

- [ ] **Step 5: Hand back** (lane `audit`; the integrator commits `feat(audit): REVOKED and serial classes, policy conflicts critical (P04 W4, PRD-1, PRD-2)`)

**docsDelta (lane `audit`):**
- README `### sshepherd audit`: new rows, copied from `internal/audit/testdata/report_revoked.golden` and `report_serial_ahead.golden`: the `‼ … (REVOKED DATE) … installed but REVOKED (CRITICAL: revoked key)` row (exit 2, D2); the `bob (access revoked DATE)` label (drift, D1d); the leading `‼ manifest: … (CRITICAL: policy conflict)` block (exit 2, D29) and the per-server conflict line; `⚠ written by newer manifest serial S (yours is M): pull the latest manifest` (drift, D4a); `‼ header claims serial S, far above this manifest's M — someone edited this file (CRITICAL: forged header)`. Note: "a header serial below the manifest's is not drift (a plain apply leaves it)."
- README `### sshepherd audit` JSON: `manifest_serial`, `policy_conflicts`, `manifest_warnings`, `summary.revoked_keys`, `summary.policy_conflicts`, per-key `revoked` / `access_revoked`, per-server `header_serial`, `manifest_serial_ahead`, `forged_header_serial` — sample from `report_revoked.golden.json`.
- README `## Exit codes`: replace the `audit --help` block with the new `exitCodesAudit` verbatim (the table itself is rewritten once, by lane `sweep`'s delta).

---
## Round 3 — lane `writecmds` (Tasks 28–36)

Owns: `internal/manifest/edit.go`, `internal/manifest/edit_test.go`, `internal/manifest/fuzz_edit_test.go`, `internal/manifest/testdata/edit_memory.golden`, `internal/manifest/testdata/bump_serial_first.golden`, `internal/apply/serialbump*.go`, `cmd/sshepherd/revoke*.go`, `cmd/sshepherd/rotate*.go`, `cmd/sshepherd/editrun*.go`, `cmd/sshepherd/edit.go`, `cmd/sshepherd/edit_test.go`, `cmd/sshepherd/apply.go`, `cmd/sshepherd/apply_test.go`, `cmd/sshepherd/apply_serial*_test.go`, `cmd/sshepherd/json_cmd_test.go`, `cmd/sshepherd/memory_test.go`, `cmd/sshepherd/run.go`, `cmd/sshepherd/e2e_test.go`, `cmd/sshepherd/testdata/help/{apply,revoke,rotate}.golden`. Findings: PRD-1, PRD-2, SEC-2. `needsIntegration: true`.

From this round on every saving revoke/rotate bumps `serial:`, and a confirmed plain apply that removes keys bumps it too (D4b). Existing tests that pinned serial-0 output change in Task 36; read each diff.

### Task 28: `manifest.AddTombstones` and `manifest.BumpSerial`

**Files:**
- Modify: `internal/manifest/edit.go` (append), package comment in `internal/manifest/manifest.go:7-19` is lane `schema`'s file — leave it; document the two edits on the functions themselves
- Test: `internal/manifest/edit_test.go`, `internal/manifest/fuzz_edit_test.go`; goldens `internal/manifest/testdata/edit_memory.golden`, `internal/manifest/testdata/bump_serial_first.golden` (new)

- [ ] **Step 1: Write the failing tests**

```go
func TestBumpSerialCreatesFirstKey(t *testing.T) {
	mf, err := Load([]byte(editFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := mf.BumpSerial(); err != nil || n != 1 {
		t.Fatalf("BumpSerial = %d, %v; want 1", n, err)
	}
	out, err := mf.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), "# fleet manifest — hand-maintained\n# owner: platform team\nserial: 1\nusers:\n") {
		t.Errorf("serial must be the first key, under the file header:\n%s", out)
	}
	checkGolden(t, "bump_serial_first.golden", out) // spec Testing: "(golden)" — every other byte of the fixture kept
	again, err := Load([]byte("serial: 41\nusers: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := again.BumpSerial(); err != nil || n != 42 {
		t.Errorf("BumpSerial from 41 = %d, %v", n, err)
	}
	top, err := Load([]byte("serial: 9007199254740991\nusers: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := top.BumpSerial(); err == nil || !strings.Contains(err.Error(), "9007199254740991") {
		t.Errorf("BumpSerial at the bound = %v, want an error", err)
	}
}

func TestAddTombstonesPreservesComments(t *testing.T) {
	mf, err := Load([]byte(editFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mf.RemoveUser("bob"); err != nil {
		t.Fatal(err)
	}
	added, err := mf.AddTombstones([]config.Tombstone{
		{Fingerprint: keyFP(t, 4), User: "bob", Date: "2026-11-08", Reason: "offboarded"},
		{User: "alice", Servers: []string{"db-1"}, Date: "2026-11-08"},
	})
	if err != nil || len(added) != 2 {
		t.Fatalf("AddTombstones = %v, %v", added, err)
	}
	if _, err := mf.BumpSerial(); err != nil {
		t.Fatal(err)
	}
	out, err := mf.Encode()
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "edit_memory.golden", out)
	for _, c := range []string{"# fleet manifest — hand-maintained", "# alice laptop", "# break-glass account", "# reviewed 2026-10-01"} {
		if !strings.Contains(string(out), c) {
			t.Errorf("lost comment %q:\n%s", c, out)
		}
	}
	cfg, err := config.Parse(out)
	if err != nil || len(cfg.Tombstones) != 2 || cfg.Serial() != 1 || len(cfg.Conflicts()) != 0 {
		t.Fatalf("reparse: %+v, %v", cfg, err)
	}
}

func TestAddTombstonesSkipsKnownFingerprint(t *testing.T) {
	mf, err := Load([]byte("users: []\nrevoked:\n  - {fingerprint: " + keyFP(t, 9) + ", date: 2026-11-01}\n"))
	if err != nil {
		t.Fatal(err)
	}
	added, err := mf.AddTombstones([]config.Tombstone{
		{Fingerprint: keyFP(t, 9), Date: "2026-11-08"},
		{Fingerprint: keyFP(t, 8), Date: "2026-11-08"},
		{Fingerprint: keyFP(t, 8), Date: "2026-11-08"},
	})
	if err != nil || len(added) != 1 || added[0].Fingerprint != keyFP(t, 8) {
		t.Fatalf("added = %+v, %v; want only key 8, once", added, err)
	}
	out, err := mf.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if cfg, err := config.Parse(out); err != nil || len(cfg.Tombstones) != 2 || cfg.Tombstones[0].Date != "2026-11-01" {
		t.Fatalf("reparse: %+v, %v (the earliest entry wins)", cfg, err)
	}
}
```

In `FuzzManifestEdit` (`fuzz_edit_test.go`), add a seed with memory:

```go
	f.Add("serial: 3\n"+editFixture(f)+"revoked:\n  - {user: bob, servers: [db-1], date: 2026-11-08}\n", uint8(1))
```

and, after the remove step and before `out, err := mf.Encode()`:

```go
		before := mf.Config().Serial()
		tombs := make([]config.Tombstone, 0, len(gone))
		for _, fp := range gone {
			tombs = append(tombs, config.Tombstone{Fingerprint: fp, Date: "2026-11-08"})
		}
		if _, err := mf.AddTombstones(tombs); err != nil {
			t.Fatalf("AddTombstones: %v", err)
		}
		bumped := before < config.MaxSerial
		if bumped {
			if n, err := mf.BumpSerial(); err != nil || n != before+1 {
				t.Fatalf("BumpSerial from %d = %d, %v", before, n, err)
			}
		}
```

and after the `after` parse:

```go
		for _, fp := range gone {
			if _, ok := after.Revoked(fp); !ok {
				t.Errorf("removed key %s not remembered (input %q)", fp, in)
			}
		}
		for _, c := range after.Conflicts() {
			if c.Kind == config.ConflictRevokedKey && slices.Contains(gone, c.Fingerprint) {
				t.Errorf("removing then tombstoning %s left a conflict: %+v", c.Fingerprint, c)
			}
		}
		if bumped && after.Serial() != before+1 {
			t.Errorf("serial %d → %d, want +1", before, after.Serial())
		}
```

(add `"slices"` to the fuzz test's imports).

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/manifest/ -run 'BumpSerial|AddTombstones|FuzzManifestEdit'`
Expected: build failure (`mf.BumpSerial undefined`).

- [ ] **Step 3: Implement** (append to `internal/manifest/edit.go`; add `"strconv"` and `"github.com/javadh75/SSHepherd/internal/config"` to its imports)

```go
// AddTombstones appends entries to revoked: — created as the last top-level
// key when absent — and returns the entries it added. A key entry whose
// fingerprint is already tombstoned (in the file, or earlier in entries) is
// skipped: the earliest entry wins, so a retried revoke never produces a
// duplicate-fingerprint load error. Entries render through the config
// types' encoder (Generate's). Node tree only.
func (f *File) AddTombstones(entries []config.Tombstone) ([]config.Tombstone, error) {
	m, err := f.rootMapping()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	if seq := valueOf(m, "revoked"); seq != nil && seq.Kind == yaml.SequenceNode {
		for _, it := range seq.Content {
			if fp := scalarField(it, "fingerprint"); fp != "" {
				seen[fp] = true
			}
		}
	}
	var added []config.Tombstone
	for _, t := range entries {
		if t.IsKey() {
			if seen[t.Fingerprint] {
				continue
			}
			seen[t.Fingerprint] = true
		}
		added = append(added, t)
	}
	nodes, err := entryNodes(added)
	if err != nil {
		return nil, err
	}
	return added, f.appendToSection("revoked", nodes)
}

// BumpSerial raises serial: by one — inserting `serial: 1` as the first
// top-level key when absent, under the file's header comment — and returns
// the new value. At config.MaxSerial it fails and changes nothing. Node
// tree only (Load validated the current value).
func (f *File) BumpSerial() (uint64, error) {
	m, err := f.rootMapping()
	if err != nil {
		return 0, err
	}
	if v := valueOf(m, "serial"); v != nil {
		cur, err := strconv.ParseUint(v.Value, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("bug: serial %q passed validation but does not parse: %w", v.Value, err)
		}
		if cur >= config.MaxSerial {
			return 0, fmt.Errorf("serial %d is the largest serial a manifest may carry; it cannot be bumped", cur)
		}
		v.Value = strconv.FormatUint(cur+1, 10)
		return cur + 1, nil
	}
	m.Style = 0
	key := strScalar("serial")
	if len(m.Content) > 0 {
		// The file's header comment rides the first key; keep it on top.
		key.HeadComment, m.Content[0].HeadComment = m.Content[0].HeadComment, ""
	}
	m.Content = append([]*yaml.Node{key, {Kind: yaml.ScalarNode, Tag: "!!int", Value: "1"}}, m.Content...)
	return 1, nil
}
```

- [ ] **Step 4: Golden, read back, run**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/manifest/ -run 'TestAddTombstonesPreservesComments|TestBumpSerialCreatesFirstKey' -update && cat internal/manifest/testdata/edit_memory.golden internal/manifest/testdata/bump_serial_first.golden && GOTOOLCHAIN=go1.27.3 go test -race ./internal/manifest/ && GOTOOLCHAIN=go1.27.3 go test ./internal/manifest/ -run '^$' -fuzz '^FuzzManifestEdit$' -fuzztime 30s`
Expected: `bump_serial_first.golden` is `editFixture` as `Encode` renders it (every comment kept) with `serial: 1` right under the two header comment lines and nothing else new — compare it with an `Encode` of the unedited fixture; the memory golden keeps every fixture comment, has `serial: 1` right under the two header lines, bob gone, and a final `revoked:` list (bob's key entry, alice's access entry); `ok`; fuzz clean.

### Task 29: `--reason`, the edit clock, the conflict refusal, already-revoked notes

**Files:**
- Modify: `cmd/sshepherd/editrun.go:25-62` (`editFlags`, `register`, `validate`), `:112-125` (`editPlan`), `:184-258` (`runEdit`)
- Create: `cmd/sshepherd/memory_test.go`

- [ ] **Step 1: Write the failing test**

```go
package main

// Imports grow with the file: this task uses only these four; Task 30 adds
// internal/authkeys, internal/config and reflect, Task 33 adds io and
// internal/testkeys — the first tasks that use them (an unused import does
// not compile).
import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// fixedEditClock pins the tombstone date (rotateNow is the edit clock).
func fixedEditClock(t *testing.T) {
	t.Helper()
	saved := rotateNow
	rotateNow = func() time.Time { return time.Date(2026, 11, 8, 23, 30, 0, 0, time.FixedZone("x", -5*3600)) } // 2026-11-09 UTC
	t.Cleanup(func() { rotateNow = saved })
}

func TestReasonValidation(t *testing.T) {
	cfg := writeConfig(t, "users: []\n")
	for reason, want := range map[string]string{
		"a\x1bb":                "--reason contains control or format characters",
		" padded":               "--reason has leading or trailing whitespace",
		strings.Repeat("x", 257): "--reason is 257 bytes, over the 256-byte limit",
	} {
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--reason", reason, "--config", cfg}, &out, &errBuf); code != 3 ||
			!strings.Contains(errBuf.String(), want) {
			t.Errorf("--reason %q: exit %d, stderr %q; want 3 and %q", reason, code, errBuf.String(), want)
		}
	}
}

// conflictFleet: alice (k1, the agent's key), bob (k2) and carol (k3) on
// web-1, and bob's key is also in revoked: — a D29 policy conflict that
// revoking carol does not resolve. Returns the manifest body too.
func conflictFleet(t *testing.T) (map[string]editHost, string, string, string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1, 2, 3})
	body := "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n  - {name: bob, keys: [" + qk(t, 2) + "]}\n  - {name: carol, keys: [" + qk(t, 3) + "]}\n" +
		"servers:\n" + hosts["web-1"].line("web-1") +
		"access:\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [web-1]}\n  - {user: carol, servers: [web-1]}\n" +
		"revoked:\n  - {fingerprint: " + fpOf(t, 2) + ", user: bob, date: 2026-11-01}\n"
	return hosts, kh, writeConfig(t, body), body
}

// TestSaveRefusedWhileConflictRemainsOnRevoke: an unrelated policy
// conflict blocks the save (exit 3, nothing saved or written).
func TestSaveRefusedWhileConflictRemainsOnRevoke(t *testing.T) {
	hosts, kh, cfg, body := conflictFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "carol", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 ||
		!strings.Contains(errBuf.String(), "refusing to write the manifest — it would keep 1 policy conflict: key "+fpOf(t, 2)) {
		t.Fatalf("exit %d, stderr %q", code, errBuf.String())
	}
	if string(fileBytes(t, cfg)) != body || len(hosts["web-1"].srv.Attempts()) != 0 {
		t.Fatal("a refused save changed the manifest or contacted a server")
	}
}

// TestRevokeKeyResolvesConflict (spec Testing, D29): revoke --key of the
// conflicting key is the fix — the manifest it would save has no conflict,
// so it saves, and the earliest tombstone wins (no duplicate entry).
func TestRevokeKeyResolvesConflict(t *testing.T) {
	_, kh, cfg, _ := conflictFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "--key", fpOf(t, 2), "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("revoke --key exit %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	saved := readCfg(t, cfg)
	if len(saved.Conflicts()) != 0 || len(saved.Tombstones) != 1 || saved.Tombstones[0].Date != "2026-11-01" || saved.Serial() != 1 {
		t.Errorf("saved = serial %d, %+v (the earliest tombstone wins, no conflict left, one bump)", saved.Serial(), saved.Tombstones)
	}
}
```

- [ ] **Step 2: Run to see it fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestReasonValidation|TestSaveRefusedWhileConflictRemainsOnRevoke|TestRevokeKeyResolvesConflict'`
Expected: FAIL — `unknown flag: --reason`; the conflicted `revoke carol` saves (exit 0); `revoke --key` saves without a serial bump (`serial 0`).

- [ ] **Step 3: Implement**

`editFlags` gains `reason string`; `register` adds:

```go
	cmd.Flags().StringVar(&f.reason, "reason", "",
		"free text recorded with each revoked: entry this run adds (printed by every tool; at most 256 bytes)")
```

`validate` begins:

```go
	if err := checkReason(f.reason); err != nil {
		return identities{}, err
	}
```

```go
// maxReason caps --reason like a tombstone's reason at load.
const maxReason = 256

// checkReason: --reason is printed by every tool that reads the manifest,
// so it passes the same text rules as a revoked: entry's reason (exit 3,
// before the manifest is read).
func checkReason(s string) error {
	if issue := authkeys.RenderTextIssue(s); issue != "" {
		return usageError{fmt.Errorf("--reason %s", issue)}
	}
	if len(s) > maxReason {
		return usageError{fmt.Errorf("--reason is %d bytes, over the %d-byte limit", len(s), maxReason)}
	}
	return nil
}

// editMemo is what a saving revoke/rotate records with each tombstone: the
// run's date (the edit clock rotateNow, in UTC) and --reason.
type editMemo struct {
	date, reason string
}

func (f *editFlags) memo() editMemo {
	return editMemo{date: rotateNow().UTC().Format(time.DateOnly), reason: f.reason}
}
```

`editPlan` gains:

```go
	noop bool // every target was already revoked (D1b/D1c): nothing saved, exit 0
```

and a method:

```go
// remember records the edit's revocation memory: the tombstones (an
// already-tombstoned fingerprint is skipped) and one serial bump. Every
// revoke and rotate that saves calls it exactly once, keep-old included.
func (ep *editPlan) remember(mf *manifest.File, tombs []config.Tombstone) error {
	added, err := mf.AddTombstones(tombs)
	if err != nil {
		return fmt.Errorf("edit manifest: %w", err)
	}
	serial, err := mf.BumpSerial()
	if err != nil {
		return fmt.Errorf("edit manifest: %w", err)
	}
	ep.summary.Revoked, ep.summary.Serial = added, serial
	return nil
}
```

`runEdit` is at gocyclo 13 today (limit 15; rounds 3-4 add more), so the new decisions live in `editPrelude` and `runEdit` begins:

```go
	log := a.logger
	h := f.run.followUp()
	if done, err := editPrelude(stdout, f, ep, h, cmd.Name()); done {
		return err
	}
```

(drop the later `h := f.run.followUp()` line). Add:

```go
// editPrelude settles what runEdit decides before any apply phase: a run
// whose every target was already revoked (D1b/D1c: the notes, exit 0, no
// save), and the D29 save refusal (exit 3); otherwise it prints a mixed
// run's already-revoked notes. done: runEdit returns err as is.
func editPrelude(stdout io.Writer, f *editFlags, ep editPlan, h followUp, command string) (done bool, err error) {
	if ep.noop {
		return true, finishNoop(stdout, f, ep, h, command)
	}
	if err := conflictRefusal(ep.edited); err != nil {
		return true, err
	}
	if !f.run.json {
		printAlready(stdout, ep.summary.AlreadyRevoked, h)
	}
	return false, nil
}
```

```go
// finishNoop ends a run whose every target an earlier revoke already
// recorded (D1b/D1c): nothing saved, no serial bump, exit 0.
func finishNoop(stdout io.Writer, f *editFlags, ep editPlan, h followUp, command string) error {
	if f.run.json {
		return apply.RenderJSON(stdout, ep.former, nil, apply.JSONOptions{ //nolint:wrapcheck // render json: …
			Command: command, DryRun: f.run.dryRun, Former: ep.former, Edit: &ep.summary,
		})
	}
	printAlready(stdout, ep.summary.AlreadyRevoked, h)
	return nil
}

// printAlready prints one note per target an earlier revoke recorded.
func printAlready(w io.Writer, already []apply.AlreadyRevoked, h followUp) {
	converge := h.command("apply", nil)
	for _, a := range already {
		switch {
		case a.Fingerprint != "":
			fmt.Fprintf(w, "%s was already revoked (%s)\n", a.Fingerprint, a.Date)
		case len(a.Servers) > 0:
			fmt.Fprintf(w, "%s's access to %s was already revoked (%s); run '%s' to converge any server that still has the key\n",
				a.User, strings.Join(a.Servers, ", "), a.Date, converge)
		default:
			fmt.Fprintf(w, "%s was already revoked (%s); run '%s' to converge any server that still has the key\n", a.User, a.Date, converge)
		}
	}
}
```

(`editrun.go` imports `time` and `internal/authkeys`.)

- [ ] **Step 4: Run** — Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestReasonValidation|TestSaveRefusedWhileConflictRemainsOnRevoke'` → `ok`. `TestRevokeKeyResolvesConflict` needs Task 31 (`revoke --key` writing the tombstone path through `remember`); it passes there.

### Task 30: `revoke USER` tombstones every key and is idempotent (D1, D1c)

**Files:**
- Modify: `cmd/sshepherd/revoke.go:48-79` (`RunE`), `:154-190` (`planRevokeUsers`)
- Test: `cmd/sshepherd/memory_test.go`

- [ ] **Step 1: Write the failing tests**

```go
func TestRevokeWritesTombstoneAndBumpsSerial(t *testing.T) {
	fixedEditClock(t)
	hosts, kh, cfg := twoUserFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--reason", "offboarded", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	saved := readCfg(t, cfg)
	want := []config.Tombstone{{Fingerprint: fpOf(t, 2), User: "bob", Date: "2026-11-09", Reason: "offboarded"}}
	if saved.Serial() != 1 || !reflect.DeepEqual(saved.Tombstones, want) {
		t.Errorf("saved serial %d, revoked %+v; want 1, %+v", saved.Serial(), saved.Tombstones, want)
	}
	for _, s := range []string{
		"manifest " + cfg + " updated — commit and push it: an apply from a copy without this edit is refused on the servers this run writes (serial 1)\n",
		"check every server: sshepherd audit --config " + cfg + " --known-hosts " + kh + "\n",
	} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("stdout lacks %q:\n%s", s, out.String())
		}
	}
	if strings.Contains(out.String(), "scope:") {
		t.Errorf("the scope line is gone (D3):\n%s", out.String())
	}
	for name, h := range hosts {
		if got := h.keys(t); !strings.HasPrefix(got, authkeys.Header(1)+"\n") {
			t.Errorf("%s = %q, want the (serial 1) header", name, got)
		}
	}
}

func TestRevokeAlreadyRevokedExits0(t *testing.T) {
	fixedEditClock(t)
	_, kh, cfg := twoUserFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("first revoke exit = %d\n%s", code, errBuf.String())
	}
	before := fileBytes(t, cfg)
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("repeat exit = %d, want 0 (D1c)\n%s", code, errBuf.String())
	}
	want := "bob was already revoked (2026-11-09); run 'sshepherd apply --config " + cfg + " --known-hosts " + kh + "' to converge any server that still has the key\n"
	if out.String() != want {
		t.Errorf("stdout = %q\nwant %q", out.String(), want)
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("a repeated revoke saved (or bumped) the manifest")
	}
	errBuf.Reset()
	if code := run([]string{"revoke", "carol", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 ||
		!strings.Contains(errBuf.String(), "unknown user: carol — not in the manifest") {
		t.Errorf("never-revoked name: exit %d, stderr %q; want today's exit 3", code, errBuf.String())
	}
	// D1c with several users: the already-revoked ones get the note, the
	// rest are revoked as usual — one save, exactly one serial bump, exit 0.
	t.Run("already revoked and live in one run", func(t *testing.T) {
		hosts, kh2, _ := editFleet(t, []byte{1}, "web-1")
		hosts["web-1"].install(t, []byte{1, 2, 3})
		cfg2 := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n  - {name: carol, keys: ["+qk(t, 3)+"]}\n"+
			"servers:\n"+hosts["web-1"].line("web-1")+
			"access:\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [web-1]}\n  - {user: carol, servers: [web-1]}\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--yes", "--config", cfg2, "--known-hosts", kh2}, &out, &errBuf); code != 0 {
			t.Fatalf("revoke bob exit = %d\n%s", code, errBuf.String())
		}
		out.Reset()
		if code := run([]string{"revoke", "bob", "carol", "--yes", "--config", cfg2, "--known-hosts", kh2}, &out, &errBuf); code != 0 {
			t.Fatalf("revoke bob carol exit = %d, want 0\n%s\n%s", code, out.String(), errBuf.String())
		}
		note := "bob was already revoked (2026-11-09); run 'sshepherd apply --config " + cfg2 + " --known-hosts " + kh2 + "' to converge any server that still has the key\n"
		if !strings.Contains(out.String(), note) || strings.Contains(out.String(), "carol was already revoked") {
			t.Errorf("stdout lacks bob's note (and only bob's):\n%s", out.String())
		}
		saved := readCfg(t, cfg2)
		want := []config.Tombstone{
			{Fingerprint: fpOf(t, 2), User: "bob", Date: "2026-11-09"},
			{Fingerprint: fpOf(t, 3), User: "carol", Date: "2026-11-09"},
		}
		if saved.Serial() != 2 || !reflect.DeepEqual(saved.Tombstones, want) {
			t.Errorf("saved = serial %d, %+v; want serial 2 (one bump per saving run) and carol's tombstone after bob's", saved.Serial(), saved.Tombstones)
		}
		if _, still := saved.OwnerOf(fpOf(t, 3)); still {
			t.Error("carol's key is still in users:")
		}
		if got := hosts["web-1"].keys(t); !strings.HasPrefix(got, authkeys.Header(2)+"\n") {
			t.Errorf("web-1 = %q, want the (serial 2) header", got)
		}
	})
}
```

(add `"reflect"`, `internal/authkeys` and `internal/config` to `memory_test.go`'s imports — this task is their first use.)

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestRevokeWritesTombstoneAndBumpsSerial|TestRevokeAlreadyRevokedExits0'`
Expected: FAIL (no tombstone, no serial; the repeat exits 3).

- [ ] **Step 3: Implement**

In `RunE`, build the memo once and pass it:

```go
			memo := f.memo()
			switch {
			case len(trim) > 0:
				ep, err = planRevokeAccess(mf, users, trim, h, memo)
			case len(users) > 0:
				ep, err = planRevokeUsers(mf, users, f.operator, h, memo)
			default:
				ep, err = planRevokeKeys(mf, keyArgs, f.operator, memo)
			}
```

Replace `planRevokeUsers`:

```go
// planRevokeUsers resolves and applies 'revoke USER...': each user and its
// access entries go, and each of its keys is tombstoned (D1). A name not in
// users: that a key tombstone labels was already revoked (D1c): a note, no
// edit. A name never seen is refused (exit 3) with what a retried revoke
// needs, carrying the run's flags (h).
func planRevokeUsers(mf *manifest.File, users []string, operator bool, h followUp, memo editMemo) (editPlan, error) {
	cfg := mf.Config()
	live, unknown, already := splitRevokeUsers(cfg, users)
	if len(unknown) > 0 {
		return editPlan{}, fmt.Errorf("unknown %s: %s — not in the manifest (already revoked?); see what is left to push with '%s', verify with '%s'",
			pluralWord(len(unknown), "user", "users"), strings.Join(unknown, ", "),
			h.command("apply", []string{"--dry-run"}), h.command("audit", nil))
	}
	ep := editPlan{former: cfg, summary: apply.EditSummary{AlreadyRevoked: already}}
	if len(live) == 0 {
		ep.noop = true
		return ep, nil
	}
	ops, err := operatorGate(cfg, userNames(live), operator)
	if err != nil {
		return editPlan{}, err
	}
	ep.summary.Operators = ops
	var tombs []config.Tombstone
	for _, u := range live {
		r, err := mf.RemoveUser(u.Name)
		if err != nil {
			return editPlan{}, fmt.Errorf("edit manifest: %w", err)
		}
		ep.summary.Edits = append(ep.summary.Edits, apply.Edit{Kind: apply.EditRemoveUser, User: u.Name, Keys: r.Keys, Grants: r.Grants})
		ep.removesKey = ep.removesKey || r.Keys > 0
		for _, fp := range userFingerprints(u) {
			tombs = append(tombs, config.Tombstone{Fingerprint: fp, User: u.Name, Date: memo.date, Reason: memo.reason})
		}
	}
	ep.stillHas = strings.Join(userNames(live), ", ") + " still " + pluralWord(len(live), "has", "have")
	if err := ep.remember(mf, tombs); err != nil {
		return editPlan{}, err
	}
	if ep.encoded, ep.edited, err = encodeEdit(mf); err != nil {
		return editPlan{}, err
	}
	return ep, nil
}

// splitRevokeUsers sorts revoke's user arguments: in users: (live, manifest
// entries), already revoked (a key tombstone labels the name; D1c), or
// unknown.
func splitRevokeUsers(cfg *config.Config, names []string) (live []config.User, unknown []string, already []apply.AlreadyRevoked) {
	for _, name := range names {
		if i := slices.IndexFunc(cfg.Users, func(u config.User) bool { return u.Name == name }); i >= 0 {
			live = append(live, cfg.Users[i])
			continue
		}
		if t, ok := latestUserTombstone(cfg, name); ok {
			already = append(already, apply.AlreadyRevoked{User: name, Date: t.Date})
			continue
		}
		unknown = append(unknown, name)
	}
	return live, unknown, already
}

// latestUserTombstone is the last key tombstone labelled with name.
func latestUserTombstone(cfg *config.Config, name string) (config.Tombstone, bool) {
	var found config.Tombstone
	ok := false
	for _, t := range cfg.Tombstones {
		if t.IsKey() && t.User == name {
			found, ok = t, true
		}
	}
	return found, ok
}

// userFingerprints lists u's key fingerprints (validated lines).
func userFingerprints(u config.User) []string {
	fps := make([]string, 0, len(u.Keys))
	for _, line := range u.Keys {
		if k, err := authkeys.ParseLine(line); err == nil && k != nil {
			fps = append(fps, k.Fingerprint)
		}
	}
	return fps
}

func userNames(us []config.User) []string {
	out := make([]string, 0, len(us))
	for _, u := range us {
		out = append(out, u.Name)
	}
	return out
}
```

(`revoke.go` imports `internal/authkeys`.)

- [ ] **Step 4: Run** — Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestRevokeWritesTombstoneAndBumpsSerial|TestRevokeAlreadyRevokedExits0'`. Expected: `TestRevokeAlreadyRevokedExits0` passes; `TestRevokeWritesTombstoneAndBumpsSerial` still fails on the save note and check line (Task 34).

### Task 31: `revoke --key` tombstones, records an unowned key (D1b)

**Files:**
- Modify: `cmd/sshepherd/revoke.go:192-248` (`planRevokeKeys`)
- Test: `cmd/sshepherd/memory_test.go`, `cmd/sshepherd/json_cmd_test.go:496`

- [ ] **Step 1: Write the failing test**

```go
func TestRevokeUnownedKeyRecordsTombstone(t *testing.T) {
	fixedEditClock(t)
	hosts, kh, cfg := twoUserFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "--key", fpOf(t, 9), "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (D1b)\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "manifest edit: record revoked key "+fpOf(t, 9)+" (no user has it; no server is written) — no servers affected\n") ||
		!strings.Contains(out.String(), "check every server: sshepherd audit --config "+cfg) {
		t.Errorf("stdout:\n%s", out.String())
	}
	saved := readCfg(t, cfg)
	if saved.Serial() != 1 || len(saved.Tombstones) != 1 || saved.Tombstones[0] != (config.Tombstone{Fingerprint: fpOf(t, 9), Date: "2026-11-09"}) {
		t.Errorf("saved = serial %d, %+v", saved.Serial(), saved.Tombstones)
	}
	for _, h := range hosts {
		if len(h.srv.Attempts()) != 0 {
			t.Error("D1b contacted a server")
		}
	}
	before := fileBytes(t, cfg)
	out.Reset()
	if code := run([]string{"revoke", "--key", fpOf(t, 9), "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 ||
		out.String() != fpOf(t, 9)+" was already revoked (2026-11-09)\n" || !bytes.Equal(fileBytes(t, cfg), before) {
		t.Errorf("repeat: exit %d, stdout %q (want a no-op note, nothing saved)", code, out.String())
	}
}
```

- [ ] **Step 2: Run to see it fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run TestRevokeUnownedKeyRecordsTombstone`
Expected: FAIL (`… is not in the manifest; apply already removes keys …`, exit 3).

- [ ] **Step 3: Implement** — replace `planRevokeKeys`:

```go
// planRevokeKeys resolves and applies 'revoke --key KEY...'. An owned key
// is removed and tombstoned under its owner (an operator losing its last
// key loses the flag first: operator: true with no keys fails validation).
// A key no user has is tombstoned with no label and writes no server (D1b);
// one already tombstoned is a no-op note.
func planRevokeKeys(mf *manifest.File, keys []keyArg, operator bool, memo editMemo) (editPlan, error) {
	cfg := mf.Config()
	ep := editPlan{former: cfg}
	var owned []keyArg
	var unowned, owners []string
	removing := map[string]int{}
	for _, k := range keys {
		u, ok := cfg.OwnerOf(k.Fingerprint)
		switch {
		case ok:
			owned = append(owned, k)
			if !slices.Contains(owners, u.Name) {
				owners = append(owners, u.Name)
			}
			removing[u.Name]++
		default:
			if t, done := cfg.Revoked(k.Fingerprint); done {
				ep.summary.AlreadyRevoked = append(ep.summary.AlreadyRevoked, apply.AlreadyRevoked{Fingerprint: k.Fingerprint, Date: t.Date})
			} else {
				unowned = append(unowned, k.Fingerprint)
			}
		}
	}
	if len(owned)+len(unowned) == 0 {
		ep.noop = true
		return ep, nil
	}
	ops, err := operatorGate(cfg, owners, operator)
	if err != nil {
		return editPlan{}, err
	}
	cleared, err := clearEmptiedOperators(mf, cfg, ops, removing)
	if err != nil {
		return editPlan{}, err
	}
	ep.summary.Operators, ep.removesKey = ops, true
	var tombs []config.Tombstone
	for _, k := range owned {
		owner, last, err := mf.RemoveKey(k.Fingerprint)
		if err != nil {
			return editPlan{}, fmt.Errorf("edit manifest: %w", err)
		}
		ep.summary.Edits = append(ep.summary.Edits, apply.Edit{
			Kind: apply.EditRemoveKey, User: owner, Fingerprint: k.Fingerprint,
			NoKeysLeft: last, ClearsOperator: last && cleared[owner],
		})
		tombs = append(tombs, config.Tombstone{Fingerprint: k.Fingerprint, User: owner, Date: memo.date, Reason: memo.reason})
	}
	for _, fp := range unowned {
		ep.summary.Edits = append(ep.summary.Edits, apply.Edit{Kind: apply.EditRecordKey, Fingerprint: fp})
		tombs = append(tombs, config.Tombstone{Fingerprint: fp, Date: memo.date, Reason: memo.reason})
	}
	ep.stillHas = "the revoked " + pluralWord(len(owned)+len(unowned), "key still has", "keys still have")
	if err := ep.remember(mf, tombs); err != nil {
		return editPlan{}, err
	}
	if ep.encoded, ep.edited, err = encodeEdit(mf); err != nil {
		return editPlan{}, err
	}
	return ep, nil
}

// clearEmptiedOperators clears operator: on each operator target that
// loses every key in this edit, and reports which.
func clearEmptiedOperators(mf *manifest.File, cfg *config.Config, ops []string, removing map[string]int) (map[string]bool, error) {
	cleared := map[string]bool{}
	for _, name := range ops {
		for _, u := range cfg.Users {
			if u.Name == name && removing[name] == len(u.Keys) {
				if err := mf.SetOperator(name, false); err != nil {
					return nil, fmt.Errorf("edit manifest: %w", err)
				}
				cleared[name] = true
			}
		}
	}
	return cleared, nil
}
```

In `json_cmd_test.go:496` (`TestEditJSONToolErrorsLeaveStdoutEmpty`), replace the unowned `--key` row — it is D1b now and exits 0 — with `{"revoke", "--key", "SHA256:nope", "--json", "--dry-run", "--config", cfg, "--known-hosts", kh},` (a malformed key is still exit 3).

- [ ] **Step 4: Run** — `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestRevokeUnownedKeyRecordsTombstone|TestSaveRefusedWhileConflictRemainsOnRevoke|TestRevokeKeyResolvesConflict|TestEditJSONToolErrorsLeaveStdoutEmpty'` → the D1b test still fails only on the check line (Task 34); the other three pass.

### Task 32: `revoke USER --server` records an access tombstone (D1a, D1c)

**Files:**
- Modify: `cmd/sshepherd/revoke.go:250-334` (`planRevokeAccess`, `accessProblems`)
- Test: `cmd/sshepherd/memory_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestRevokeServerRecordsAccessTombstone(t *testing.T) {
	fixedEditClock(t)
	t.Run("explicit grant: a tombstone", func(t *testing.T) {
		_, kh, cfg := twoUserFleet(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--server", "web-2", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
		}
		saved := readCfg(t, cfg)
		want := []config.Tombstone{{User: "bob", Servers: []string{"web-2"}, Date: "2026-11-09"}}
		if saved.Serial() != 1 || !reflect.DeepEqual(saved.Tombstones, want) {
			t.Errorf("saved = serial %d, %+v", saved.Serial(), saved.Tombstones)
		}
		before := fileBytes(t, cfg)
		out.Reset()
		if code := run([]string{"revoke", "bob", "--server", "web-2", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 ||
			!strings.HasPrefix(out.String(), "bob's access to web-2 was already revoked (2026-11-09); run 'sshepherd apply") ||
			!bytes.Equal(fileBytes(t, cfg), before) {
			t.Errorf("repeat: exit %d, stdout %q", code, out.String())
		}
	})
	t.Run("wildcard grant: except: remembers, no tombstone", func(t *testing.T) {
		hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
		for _, h := range hosts {
			h.install(t, []byte{1, 2})
		}
		cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
			"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
			"access:\n  - {user: alice, servers: [\"*\"]}\n  - {user: bob, servers: [\"*\"]}\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--server", "web-2", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if saved := readCfg(t, cfg); saved.Serial() != 1 || len(saved.Tombstones) != 0 {
			t.Errorf("saved = serial %d, %+v; want a bump and no tombstone", saved.Serial(), saved.Tombstones)
		}
	})
}
```

- [ ] **Step 2: Run to see it fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run TestRevokeServerRecordsAccessTombstone`
Expected: FAIL (no tombstone; the repeat exits 3 with `bob has no access to web-2`).

- [ ] **Step 3: Implement** — replace `planRevokeAccess` and `accessProblems`:

```go
// planRevokeAccess resolves and applies 'revoke USER... --server NAME...'.
// There is no operator gate: an operator target is refused outright
// (access to every server by definition). Every problem is listed in one
// refusal before any edit (accessProblems). A pair an access tombstone
// already records is a note (D1c). Servers removed from an explicit list
// are tombstoned (D1a); a server that only gained an except: entry needs
// none — the except: already remembers it.
func planRevokeAccess(mf *manifest.File, users, servers []string, h followUp, memo editMemo) (editPlan, error) {
	cfg := mf.Config()
	problems, trims, already := accessProblems(cfg, users, servers, h)
	if len(problems) > 0 {
		return editPlan{}, errors.New(strings.Join(problems, "; "))
	}
	ep := editPlan{former: cfg, summary: apply.EditSummary{AlreadyRevoked: already}}
	var trimmed []string
	for _, name := range users {
		if len(trims[name]) > 0 {
			trimmed = append(trimmed, name)
		}
	}
	if len(trimmed) == 0 {
		ep.noop = true
		return ep, nil
	}
	ep.stillHas = strings.Join(trimmed, ", ") + " still " + pluralWord(len(trimmed), "has", "have")
	for _, name := range trimmed {
		r, err := mf.RemoveAccess(name, trims[name])
		if err != nil {
			return editPlan{}, fmt.Errorf("edit manifest: %w", err)
		}
		ep.summary.Edits = append(ep.summary.Edits, apply.Edit{
			Kind: apply.EditRemoveAccess, User: name, AccessServers: trims[name],
			EntriesChanged: r.EntriesChanged, EntriesRemoved: r.EntriesRemoved,
			ServersExcepted: r.ServersExcepted, WildcardsRemoved: r.WildcardsRemoved,
		})
	}
	_, mid, err := encodeEdit(mf) // only to see which servers an except: now remembers
	if err != nil {
		return editPlan{}, err
	}
	if err := ep.remember(mf, accessTombstones(mid, trimmed, trims, memo)); err != nil {
		return editPlan{}, err
	}
	if ep.encoded, ep.edited, err = encodeEdit(mf); err != nil {
		return editPlan{}, err
	}
	for i, e := range ep.summary.Edits {
		ep.summary.Edits[i].NoGrantsLeft = !slices.ContainsFunc(ep.edited.Access, func(a config.Access) bool { return a.User == e.User })
		// What is left, said in the header: a "web-1 first" trim must not
		// read as an offboarding.
		for _, srv := range ep.edited.Servers {
			if ep.edited.Covers(e.User, srv.Name) {
				ep.summary.Edits[i].KeepsServers++
			}
		}
	}
	return ep, nil
}

// accessTombstones: one entry per user, naming the trimmed servers no
// wildcard except: remembers in mid (the manifest after the access edit).
func accessTombstones(mid *config.Config, users []string, trims map[string][]string, memo editMemo) []config.Tombstone {
	var tombs []config.Tombstone
	for _, name := range users {
		var lost []string
		for _, s := range trims[name] {
			if !mid.ExceptCarveOut(name, s) {
				lost = append(lost, s)
			}
		}
		if len(lost) > 0 {
			tombs = append(tombs, config.Tombstone{User: name, Servers: lost, Date: memo.date, Reason: memo.reason})
		}
	}
	return tombs
}

// accessProblems lists why 'revoke USER... --server NAME...' cannot run,
// in this order: unknown users (one entry, the existing wording), unknown
// servers, operator targets, then every non-operator user × known server
// pair the user has no access to and no access tombstone records
// (config.Covers: wildcards and except: included). It also returns, per
// user, the servers to trim, and the pairs already revoked (D1c). h
// carries the run's flags into the operator hint.
func accessProblems(cfg *config.Config, users, servers []string, h followUp) (problems []string, trims map[string][]string, already []apply.AlreadyRevoked) {
	var unknown, ops []string
	for _, name := range users {
		i := slices.IndexFunc(cfg.Users, func(u config.User) bool { return u.Name == name })
		switch {
		case i < 0:
			unknown = append(unknown, name)
		case cfg.Users[i].Operator:
			ops = append(ops, name)
		}
	}
	if len(unknown) > 0 {
		problems = append(problems, fmt.Sprintf("unknown %s: %s", pluralWord(len(unknown), "user", "users"), strings.Join(unknown, ", ")))
	}
	var known []string
	for _, s := range servers {
		if slices.ContainsFunc(cfg.Servers, func(c config.Server) bool { return c.Name == s }) {
			known = append(known, s)
		} else {
			problems = append(problems, fmt.Sprintf("no server named %q in the manifest", s))
		}
	}
	for _, name := range ops {
		problems = append(problems, fmt.Sprintf("%s is an operator (access to every server by definition); remove the user with '%s', or clear operator: true by hand",
			name, h.command("revoke", []string{hintArg(name)}, "--operator")))
	}
	trims = map[string][]string{}
	for _, name := range users {
		if slices.Contains(unknown, name) || slices.Contains(ops, name) {
			continue
		}
		trim, gone, date, missing := classifyPairs(cfg, name, known)
		trims[name] = trim
		problems = append(problems, missing...)
		if len(gone) > 0 {
			already = append(already, apply.AlreadyRevoked{User: name, Servers: gone, Date: date})
		}
	}
	return problems, trims, already
}

// classifyPairs sorts one user's --server targets: covered (trim), already
// revoked by an access tombstone (gone, with the latest date), or a problem.
func classifyPairs(cfg *config.Config, name string, servers []string) (trim, gone []string, date string, problems []string) {
	for _, s := range servers {
		if cfg.Covers(name, s) {
			trim = append(trim, s)
			continue
		}
		if t, ok := cfg.AccessRevoked(name, s); ok {
			gone, date = append(gone, s), t.Date
			continue
		}
		problems = append(problems, fmt.Sprintf("%s has no access to %s", name, s))
	}
	return trim, gone, date, problems
}
```

- [ ] **Step 4: Run** — Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestRevokeServer'` → the new test passes; `TestRevokeServerHermetic`/`TestRevokeServerNoApplyDryRun` still fail on the old save note (Task 36 updates them).

### Task 33: `rotate` tombstones the old key; keep-old bumps only

**Files:**
- Modify: `cmd/sshepherd/rotate.go:76-85` (`RunE`), `:96-161` (`rotateOpts`, `planRotate`)
- Test: `cmd/sshepherd/memory_test.go`, `cmd/sshepherd/json_cmd_test.go` (`TestEditJSONToolErrorsLeaveStdoutEmpty`)

- [ ] **Step 1: Write the failing test**

```go
func TestRotateTombstonesOldKey(t *testing.T) {
	fixedEditClock(t)
	for _, tc := range []struct {
		name   string
		args   []string
		reason string
	}{
		{"default reason", nil, "rotated out"},
		{"--reason", []string{"--reason", "laptop stolen"}, "laptop stolen"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, kh, cfg := twoUserFleet(t)
			args := append([]string{"rotate", "bob", "--old", fpOf(t, 2), "--new", writePub(t, "n.pub", testkeys.Line(t, 5)),
				"--yes", "--config", cfg, "--known-hosts", kh}, tc.args...)
			var out, errBuf bytes.Buffer
			if code := run(args, &out, &errBuf); code != 0 {
				t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
			}
			saved := readCfg(t, cfg)
			want := []config.Tombstone{{Fingerprint: fpOf(t, 2), User: "bob", Date: "2026-11-09", Reason: tc.reason}}
			if saved.Serial() != 1 || !reflect.DeepEqual(saved.Tombstones, want) {
				t.Errorf("saved = serial %d, %+v", saved.Serial(), saved.Tombstones)
			}
		})
	}
	t.Run("--keep-old: no tombstone, still a bump", func(t *testing.T) {
		_, kh, cfg := twoUserFleet(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"rotate", "bob", "--old", fpOf(t, 2), "--new", writePub(t, "n.pub", testkeys.Line(t, 5)),
			"--keep-old", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if saved := readCfg(t, cfg); saved.Serial() != 1 || len(saved.Tombstones) != 0 {
			t.Errorf("saved = serial %d, %+v", saved.Serial(), saved.Tombstones)
		}
	})
	t.Run("--new of a revoked key is refused", func(t *testing.T) {
		_, kh, cfg := twoUserFleet(t)
		if code := run([]string{"revoke", "--key", fpOf(t, 5), "--yes", "--config", cfg, "--known-hosts", kh}, io.Discard, io.Discard); code != 0 {
			t.Fatal("recording key 5 failed")
		}
		var errBuf bytes.Buffer
		if code := run([]string{"rotate", "bob", "--old", fpOf(t, 2), "--new", writePub(t, "n.pub", testkeys.Line(t, 5)),
			"--yes", "--config", cfg, "--known-hosts", kh}, io.Discard, &errBuf); code != 3 ||
			!strings.Contains(errBuf.String(), "refusing to write the manifest — it would keep 1 policy conflict: key "+fpOf(t, 5)) {
			t.Errorf("exit %d, stderr %q", code, errBuf.String())
		}
	})
}
```

(add `"io"` and `internal/testkeys` to `memory_test.go`'s imports — this task is their first use.)

Append to `TestEditJSONToolErrorsLeaveStdoutEmpty` (`cmd/sshepherd/json_cmd_test.go`, after the `"interrupted before save"` subtest) the two D29 save refusals, which spec §2 and §9 say write no document under `--json`:

```go
	// D29: a save refused for a policy conflict is exit 3 with no document
	// (spec §2, §9) — for revoke, and for rotate --new of a revoked key.
	t.Run("policy conflict save refusals", func(t *testing.T) {
		_, ckh, ccfg, cbody := conflictFleet(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "carol", "--json", "--yes", "--config", ccfg, "--known-hosts", ckh}, &out, &errBuf); code != 3 || out.Len() != 0 {
			t.Errorf("revoke on a conflicted manifest: exit = %d, stdout = %q\nstderr: %s", code, out.String(), errBuf.String())
		}
		if string(fileBytes(t, ccfg)) != cbody {
			t.Error("the refused revoke saved the manifest")
		}
		_, rkh, rcfg := twoUserFleet(t)
		if code := run([]string{"revoke", "--key", fpOf(t, 5), "--yes", "--config", rcfg, "--known-hosts", rkh}, io.Discard, io.Discard); code != 0 {
			t.Fatal("recording key 5 failed")
		}
		recorded := fileBytes(t, rcfg)
		out.Reset()
		errBuf.Reset()
		if code := run([]string{"rotate", "bob", "--old", fpOf(t, 2), "--new", writePub(t, "n.pub", testkeys.Line(t, 5)),
			"--json", "--yes", "--config", rcfg, "--known-hosts", rkh}, &out, &errBuf); code != 3 || out.Len() != 0 {
			t.Errorf("rotate --new of a revoked key: exit = %d, stdout = %q\nstderr: %s", code, out.String(), errBuf.String())
		}
		if !bytes.Equal(fileBytes(t, rcfg), recorded) {
			t.Error("the refused rotate saved the manifest")
		}
	})
```

(`json_cmd_test.go` already imports `bytes`, `io` and `testkeys`.)

- [ ] **Step 2: Run to see it fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestRotateTombstonesOldKey|TestEditJSONToolErrorsLeaveStdoutEmpty'`
Expected: FAIL (no tombstone, serial 0; `rotate --new` of the recorded key 5 saves, exit 0, and writes a document). The revoke-on-a-conflict row already passes since Task 29 (its first run, in Task 29, was red).

- [ ] **Step 3: Implement**

`rotateOpts` gains `memo editMemo`; `RunE` passes `rotateOpts{operator: f.operator, keepOld: keepOld, now: rotateNow(), memo: f.memo()}`. In `planRotate`, replace the branch at `:145-156` with:

```go
	var tombs []config.Tombstone
	if opts.keepOld {
		err = mf.AddKeyAfter(user, oldArg.Fingerprint, line)
		ep.stillHas = user + "'s new key would get no"
		ep.saveNote = "an apply from a copy without this edit removes the new key — clients that already switched would be locked out"
		ep.overlap = &overlapFinish{user: user, oldFP: oldArg.Fingerprint, operator: u.Operator}
	} else {
		err = mf.ReplaceKey(user, oldArg.Fingerprint, line)
		ep.formerNote, ep.removesKey, ep.stillHas = "rotated out", true, user+"'s old key still has"
		reason := cmp.Or(opts.memo.reason, "rotated out")
		tombs = []config.Tombstone{{Fingerprint: oldArg.Fingerprint, User: user, Date: opts.memo.date, Reason: reason}}
	}
	if err != nil {
		return editPlan{}, fmt.Errorf("edit manifest: %w", err)
	}
	// Keep-old bumps too: a stale copy would otherwise remove the new key
	// on the affected servers (the keep-old save note says so).
	if err := ep.remember(mf, tombs); err != nil {
		return editPlan{}, err
	}
```

(`rotate.go` imports `cmp`.)

- [ ] **Step 4: Run** — `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestRotateTombstonesOldKey|TestEditJSONToolErrorsLeaveStdoutEmpty'` → `ok`.

### Task 34: save notes, the check line, header-only writes in the apply phase

**Files:**
- Modify: `cmd/sshepherd/editrun.go:166-168` (`defaultSaveNote`, removed), `:184-258` (`runEdit`), `:265-332` (`saveOnly`, `noApplyNote`, `saveEdit`), `:349-399` (`finishEdit`, `printScope` → `printCheck`); `cmd/sshepherd/apply.go:141-212` (`applySpec`, `runWorkflow`)
- Test: `cmd/sshepherd/memory_test.go`

- [ ] **Step 1: Write the failing tests**

```go
// TestRevokeHeaderOnlyWriteOnConvergedAffected (the PRD-2 fix, hermetic):
// alice is granted web-1 and web-2 but her key is already missing on
// web-2; revoking her writes web-2's header with the new serial and leaves
// its keys byte-identical.
func TestRevokeHeaderOnlyWriteOnConvergedAffected(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	opLine := testkeys.Line(t, 1) + " op"
	hosts["web-1"].install(t, []byte{1, 2})
	hosts["web-2"].install(t, nil, authkeys.ManagedHeader, opLine)
	cfg := writeConfig(t, "users:\n  - {name: op, operator: true, keys: ["+qk(t, 1)+"]}\n  - {name: alice, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "alice", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if got, want := hosts["web-2"].keys(t), authkeys.Header(1)+"\n"+opLine+"\n"; got != want {
		t.Errorf("web-2 = %q, want %q", got, want)
	}
	for _, s := range []string{"update header: no serial → 1 (keys unchanged)", "web-2: applied · verified"} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("stdout lacks %q:\n%s", s, out.String())
		}
	}
}

// TestRevokeWithoutSweepPrintsAuditCommand (D3): every run that removes a
// key prints the exact follow-up audit with the run's own flags —
// --dry-run and --no-apply included.
func TestRevokeWithoutSweepPrintsAuditCommand(t *testing.T) {
	t.Run("--dry-run", func(t *testing.T) {
		_, kh, cfg := twoUserFleet(t)
		var out, errBuf bytes.Buffer
		run([]string{"revoke", "bob", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
		if want := "check every server: sshepherd audit --config " + cfg + " --known-hosts " + kh + "\n"; !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	})
	t.Run("--no-apply", func(t *testing.T) {
		_, _, cfg := twoUserFleet(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		for _, want := range []string{
			"check every server: sshepherd audit --config " + cfg + "\n",
			"servers learn serial 1 only when an apply writes them; until then a copy without this edit can re-grant there\n",
		} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("stdout lacks %q:\n%s", want, out.String())
			}
		}
	})
}
```

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestRevokeHeaderOnlyWriteOnConvergedAffected|TestRevokeWithoutSweepPrintsAuditCommand|TestRevokeWritesTombstoneAndBumpsSerial|TestRevokeUnownedKeyRecordsTombstone'`
Expected: FAIL — web-2 keeps the legacy header (no `Bumped`), the scope line still prints, old save note.

- [ ] **Step 3: Implement**

`cmd/sshepherd/apply.go`: `applySpec` gains

```go
	// bumped: the run saves a higher serial: and servers is its bump scope
	// (revoke/rotate's affected set): equal-body servers get header-only
	// writes (workflow.Request.Bumped).
	bumped bool
```

and `runWorkflow` sets `Bumped: s.bumped,` in the `workflow.Request` literal. In `runEdit`'s `applySpec` literal add `bumped: true,`.

`editrun.go`:

- Delete `defaultSaveNote`. `saveEdit` becomes:

```go
// saveEdit is step 7's save, then the reminder that the manifest is the
// source of truth only once it is committed (skipped when quiet: --json,
// whose edit.saved carries the fact). pending: --no-apply — the only case
// spec §4 gives the "servers learn serial N …" note; every other save
// (D1b's save-only run included) gets the default note.
func saveEdit(stdout io.Writer, ep editPlan, quiet, pending bool) error {
	if err := ep.target.Save(ep.encoded); err != nil {
		return err
	}
	if quiet {
		return nil
	}
	note := ep.saveNote
	if note == "" {
		note = serialSaveNote(ep.summary.Serial, pending)
	}
	fmt.Fprintf(stdout, "manifest %s updated — commit and push it: %s\n", ep.target.Path, note)
	return nil
}

// serialSaveNote says what the saved serial protects (spec §4).
func serialSaveNote(serial uint64, pending bool) string {
	if pending {
		return fmt.Sprintf("servers learn serial %d only when an apply writes them; until then a copy without this edit can re-grant there", serial)
	}
	return fmt.Sprintf("an apply from a copy without this edit is refused on the servers this run writes (serial %d)", serial)
}
```

  Call sites: in `runEdit`'s commit `saveEdit(stdout, ep, doc != nil, false)`; in `saveOnly` `saveEdit(stdout, ep, doc != nil, f.noApply)`.
- In `planRevokeAccess` (Task 32) there is no `saveNote` any more (already done there).
- Replace `printScope` with:

```go
// printCheck is the follow-up after a key removal when no sweep runs (spec
// §7): the exact audit, with the run's flags, that exits 2 while the
// revoked key is still installed anywhere.
func printCheck(w io.Writer, h followUp) {
	fmt.Fprintf(w, "check every server: %s\n", h.command("audit", nil))
}
```

- In `runEdit`, after `ep.summary.FollowUp = h.suffix()`: `ep.summary.CheckCommand = checkCommand(ep, h)` — a helper, so `runEdit` (gocyclo 13 + `editPrelude`'s one `if`) gains no branch:

```go
// checkCommand is JSON edit.check_command: the printed follow-up audit,
// present whenever the run removes a key ("" otherwise).
func checkCommand(ep editPlan, h followUp) string {
	if !ep.removesKey {
		return ""
	}
	return h.command("audit", nil)
}
```
- `noApplyNote`: drop the `case ep.removesKey:` arm and append after the switch `if ep.removesKey { printCheck(stdout, h) }`.
- `saveOnly`'s dry-run branch: before `if doc != nil {`, add `if doc == nil && ep.removesKey { printCheck(stdout, h) }`.
- `finishEdit` (gocyclo 14 today): delete the `if ep.removesKey { printScope(…) }` block inside `StageConfirmed`, and call `finishTail(stdout, h, ep, out)` before the final `apply.ExitCode` check — the new compound condition lives in the helper, so `finishEdit` ends one branch lower than today:

```go
// finishTail prints the follow-up after the apply phase's summary: the
// check line for a run that removed a key, once it planned or wrote (not
// after a declined prompt). Task 39 adds the sweep report here.
func finishTail(stdout io.Writer, h followUp, ep editPlan, out workflow.Outcome) {
	if ep.removesKey && (out.Stage == workflow.StageConfirmed || out.Stage == workflow.StagePlanned) {
		printCheck(stdout, h)
	}
}
```

- [ ] **Step 4: Run** — Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestRevoke(HeaderOnly|WithoutSweep|WritesTombstone|UnownedKey|AlreadyRevoked|ServerRecords|KeyResolves)|TestRotateTombstones|TestSaveRefused'` → `ok`; `golangci-lint run --enable-only=gocyclo ./cmd/sshepherd/` → clean.

### Task 35: apply bumps the serial after a hand removal (D4b)

**Files:**
- Create: `internal/apply/serialbump.go`, `internal/apply/serialbump_test.go`, `cmd/sshepherd/apply_serial_test.go`, `cmd/sshepherd/apply_serial_pipe_test.go`
- Modify: `cmd/sshepherd/apply.go:68-134` (the `apply` RunE: `commit`, `finish` → `plainApply` methods)

- [ ] **Step 1: Write the failing tests**

`internal/apply/serialbump_test.go`:

```go
package apply

import (
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func TestNeedsSerialBump(t *testing.T) {
	cfg := serialCfg(t) // M = 7
	removal := authkeys.Header(7) + "\n" + web1Body(t, cfg) + testkeys.Line(t, 9) + "\n"
	for _, tc := range []struct {
		name    string
		content string
		want    bool
	}{
		{"equal serial, a removal", removal, true},
		{"newer serial, removal-only", authkeys.Header(9) + "\n" + web1Body(t, cfg) + testkeys.Line(t, 9) + "\n", true},
		{"older serial, a removal (M > S)", authkeys.Header(6) + "\n" + web1Body(t, cfg) + testkeys.Line(t, 9) + "\n", false},
		{"forged counts as no serial", authkeys.Header(5000) + "\n" + web1Body(t, cfg) + testkeys.Line(t, 9) + "\n", false},
		{"no removal", authkeys.Header(7) + "\n" + testkeys.Line(t, 1) + " op\n", false},
	} {
		p := planWeb1(t, cfg, tc.content, false, false)
		if got := NeedsSerialBump([]ServerPlan{p}, cfg.Serial()); got != tc.want {
			t.Errorf("%s: NeedsSerialBump = %v, want %v (plan %+v)", tc.name, got, tc.want, p)
		}
	}
}

func TestReserial(t *testing.T) {
	cfg := serialCfg(t)
	plain := planWeb1(t, cfg, authkeys.Header(7)+"\n"+web1Body(t, cfg)+testkeys.Line(t, 9)+"\n", false, false)
	higher := planWeb1(t, cfg, authkeys.Header(20)+"\n"+web1Body(t, cfg)+testkeys.Line(t, 9)+"\n", false, false)
	plans := []ServerPlan{plain, higher}
	if err := Reserial(plans, 8); err != nil {
		t.Fatal(err)
	}
	if want := authkeys.Header(8) + "\n" + web1Body(t, cfg); string(plans[0].Rendered) != want || plans[0].Serial.Writes != 8 {
		t.Errorf("plain = %q (writes %d)", plans[0].Rendered, plans[0].Serial.Writes)
	}
	if want := authkeys.Header(20) + "\n" + web1Body(t, cfg); string(plans[1].Rendered) != want {
		t.Errorf("a removal-only write keeps its higher S: %q", plans[1].Rendered)
	}
}
```

`cmd/sshepherd/apply_serial_test.go`:

```go
package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/manifest"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestApplyBumpsSerialOnHandRemoval (D4b): a confirmed apply that removes
// a key from a server whose header serial is not above the manifest's
// bumps serial: once, saves it before the first write, and writes the new
// serial; --dry-run only says it would.
func TestApplyBumpsSerialOnHandRemoval(t *testing.T) {
	home := shortHome(t)
	srv, hostKey, cfg := hermeticFleet(t, home)
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
	target := filepath.Join(home, ".ssh", "authorized_keys")
	cur, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, append(cur, []byte(testkeys.Line(t, 9)+" handed\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	before := fileBytes(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 ||
		!strings.Contains(out.String(), "would bump serial: 0 → 1 (this apply removes keys)\n") || !bytes.Equal(fileBytes(t, cfg), before) {
		t.Fatalf("dry-run: exit %d\n%s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "manifest serial: 0 → 1 (saved; this apply removes keys)\n") {
		t.Errorf("stdout:\n%s", out.String())
	}
	if readCfg(t, cfg).Serial() != 1 {
		t.Error("serial not saved")
	}
	if got, _ := os.ReadFile(target); !strings.HasPrefix(string(got), authkeys.Header(1)+"\n") {
		t.Errorf("server file = %q, want the (serial 1) header", got)
	}
}

// TestApplySerialSaveUnavailable: a pipe and an anchored manifest (plan
// decision 8) cannot be saved in place — and the dry run classifies them
// the same way, so it warns instead of promising a bump.
func TestApplySerialSaveUnavailable(t *testing.T) {
	if _, err := saveSerialBump(manifestTarget{manifest.Store{Stream: true}}); !errors.Is(err, errNoSerialSave) {
		t.Errorf("stream: err = %v, want errNoSerialSave", err)
	}
	anchored := writeConfig(t, "users: &u []\nservers: []\naccess: []\n")
	m, err := readManifest(anchored)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := saveSerialBump(m); !errors.Is(err, errNoSerialSave) {
		t.Errorf("anchored manifest: err = %v, want errNoSerialSave", err)
	}
	cfg, err := config.Parse(m.Loaded)
	if err != nil {
		t.Fatal(err)
	}
	removal := []apply.ServerPlan{{Class: apply.ClassChange, Remove: []authkeys.Key{{Fingerprint: "SHA256:x"}}}}
	if b := dryRunBump(m, cfg, removal); b == nil || b.To != nil || b.Warning != noBumpWarning {
		t.Errorf("dry run on an anchored manifest = %+v, want the no-bump warning (as the real run)", b)
	}
}

// TestApplySerialSaveFailsExit3 (spec §6, §8, §9): a D4b save that fails —
// here BumpSerial at the upper bound — is exit 3 with nothing written,
// and under --json no document.
func TestApplySerialSaveFailsExit3(t *testing.T) {
	for _, extra := range [][]string{nil, {"--json"}} {
		hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
		h := hosts["web-1"]
		h.install(t, nil, authkeys.Header(authkeys.MaxHeaderSerial), testkeys.Line(t, 1)+" alice", testkeys.Line(t, 9)+" stray")
		before := h.keys(t)
		cfg := writeConfig(t, "serial: 9007199254740991\nusers:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n"+
			"servers:\n"+h.line("web-1")+"access:\n  - {user: alice, servers: [web-1]}\n")
		manifestBefore := fileBytes(t, cfg)
		var out, errBuf bytes.Buffer
		args := append([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, extra...)
		if code := run(args, &out, &errBuf); code != 3 || !strings.Contains(errBuf.String(), "cannot be bumped") {
			t.Fatalf("%v: exit = %d, want 3 with the bound error\n%s\n%s", extra, code, out.String(), errBuf.String())
		}
		if h.keys(t) != before || !bytes.Equal(fileBytes(t, cfg), manifestBefore) {
			t.Errorf("%v: a failed serial save wrote the server or the manifest", extra)
		}
		if len(extra) > 0 && out.Len() != 0 {
			t.Errorf("--json wrote a document on exit 3:\n%s", out.String())
		}
	}
}
```

`cmd/sshepherd/apply_serial_pipe_test.go` (the `pipeConfig` helper lives in `edit_stream_test.go`, under the same build tag):

```go
//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestApplySerialBumpPipedConfig (spec §6, §9): a piped --config cannot be
// saved, so an apply that removes a key warns and proceeds — the write
// happens, exit 0; --dry-run warns the same way instead of promising a
// bump; --json reports serial_bump {from, to: null, saved: false, warning}.
func TestApplySerialBumpPipedConfig(t *testing.T) {
	stray := strings.Fields(testkeys.Line(t, 9))[1]
	setup := func(t *testing.T) (editHost, string, string) {
		hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
		h := hosts["web-1"]
		h.install(t, []byte{1, 9})
		return h, kh, pipeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n"+
			"servers:\n"+h.line("web-1")+"access:\n  - {user: alice, servers: [web-1]}\n")
	}
	t.Run("text", func(t *testing.T) {
		h, kh, cfg := setup(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d, want 0\n%s\n%s", code, out.String(), errBuf.String())
		}
		if !strings.Contains(errBuf.String(), noBumpWarning) || strings.Contains(out.String(), "manifest serial:") {
			t.Errorf("stderr lacks the no-bump warning (or a bump was claimed):\n%s\n%s", errBuf.String(), out.String())
		}
		if strings.Contains(h.keys(t), stray) {
			t.Error("the write did not proceed: the stray key is still installed")
		}
	})
	t.Run("--dry-run", func(t *testing.T) {
		_, kh, cfg := setup(t)
		var out, errBuf bytes.Buffer
		run([]string{"apply", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
		if !strings.Contains(errBuf.String(), noBumpWarning) || strings.Contains(out.String(), "would bump serial") {
			t.Errorf("dry run must warn, not promise a bump:\n%s\n%s", out.String(), errBuf.String())
		}
	})
	t.Run("--json", func(t *testing.T) {
		_, kh, cfg := setup(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"apply", "--yes", "--json", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		var doc struct {
			SerialBump map[string]any `json:"serial_bump"`
		}
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("stdout is not one document: %v\n%s", err, out.String())
		}
		want := map[string]any{"from": float64(0), "to": nil, "saved": false, "warning": noBumpWarning}
		if !reflect.DeepEqual(doc.SerialBump, want) {
			t.Errorf("serial_bump = %v, want %v", doc.SerialBump, want)
		}
	})
}
```

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply/ ./cmd/sshepherd/ -run 'NeedsSerialBump|Reserial|TestApplyBumpsSerialOnHandRemoval|TestApplySerialSaveUnavailable|TestApplySerialSaveFailsExit3|TestApplySerialBumpPipedConfig'`
Expected: build failure (`undefined: NeedsSerialBump`, `saveSerialBump`, `dryRunBump`, `noBumpWarning`).

- [ ] **Step 3: Implement**

`internal/apply/serialbump.go`:

```go
package apply

import (
	"bytes"
	"fmt"

	"github.com/javadh75/SSHepherd/internal/authkeys"
)

// NeedsSerialBump reports D4b (spec §6): some server this run writes loses
// a key (a remove row) while its header serial S is not below the
// manifest's serial m (m ≤ S; a forged header counts as no serial).
// Moving authorized_keys2 aside and collapsing duplicate lines do not count.
func NeedsSerialBump(plans []ServerPlan, m uint64) bool {
	for _, p := range plans {
		s := p.Serial.Header
		if p.Serial.Case == SerialForged {
			s = 0
		}
		if p.Class == ClassChange && len(p.Remove) > 0 && m <= s {
			return true
		}
	}
	return false
}

// Reserial re-renders the managed header of every change plan after apply
// saved a bumped serial to: each write carries to, or its own higher serial
// (a removal-only write on a newer server keeps S), so a serial on a server
// never goes down. Only line 1 changes.
func Reserial(plans []ServerPlan, to uint64) error {
	for i := range plans {
		p := &plans[i]
		if p.Class != ClassChange {
			continue
		}
		w := max(to, p.Serial.Writes)
		_, body, ok := bytes.Cut(p.Rendered, []byte("\n"))
		if !ok {
			return fmt.Errorf("bug: %s's rendered file has no header line", p.Server.Name)
		}
		p.Rendered = append([]byte(authkeys.Header(w)+"\n"), body...)
		p.Serial.Writes = w
	}
	return nil
}
```

`cmd/sshepherd/apply.go`: `newApplyCmd` is at gocyclo 12 and function literals count toward it, so plain apply's two seams become methods of a small struct and `newApplyCmd` only wires them. In the `RunE`, after `ropts` and the empty-targets branch, build

```go
			pa := &plainApply{m: m, cfg: cfg, log: log, stdout: stdout, rf: &rf, skipped: skipped, ropts: ropts}
```

and in the `applySpec` literal replace the `commit:` and `finish:` closures with `commit: pa.commit,` and `finish: pa.finish,`. Add:

```go
// plainApply is plain apply's commit and finish seams, as methods so the
// command's own function stays small (gocyclo).
type plainApply struct {
	m       manifestTarget
	cfg     *config.Config
	log     *slog.Logger
	stdout  io.Writer
	rf      *runFlags
	skipped int
	ropts   apply.RenderOptions
	bump    *apply.SerialBump // D4b: what this run bumped (or would), for the text and JSON reports
}

// commit runs after the prompt, before the first write. A concurrent
// revoke may have replaced the manifest while this run planned against the
// old one: writing that plan would reinstall the revoked key. Then D4b: a
// removal on a server whose header serial is not above the manifest's
// bumps serial: once, saved here, and every write carries it (Reserial).
func (pa *plainApply) commit(_ context.Context, plans []apply.ServerPlan, _ []fleet.HeldKey) (bool, error) {
	if err := pa.m.Unchanged(); err != nil {
		return false, err
	}
	from := pa.cfg.Serial()
	if !apply.NeedsSerialBump(plans, from) {
		return false, nil
	}
	to, err := saveSerialBump(pa.m)
	if errors.Is(err, errNoSerialSave) {
		pa.log.Warn(noBumpWarning)
		pa.bump = &apply.SerialBump{From: from, Warning: noBumpWarning}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := apply.Reserial(plans, to); err != nil {
		return false, err //nolint:wrapcheck // a bug: … message
	}
	pa.bump = &apply.SerialBump{From: from, To: &to, Saved: true}
	if !pa.rf.json {
		fmt.Fprintf(pa.stdout, "manifest serial: %d → %d (saved; this apply removes keys)\n", from, to)
	}
	return true, nil
}

// finish renders the run's outcome: the JSON document, or the summary and
// the dry-run's would-bump line.
func (pa *plainApply) finish(out workflow.Outcome) error {
	if out.Stage == workflow.StageDeclined {
		pa.log.Error("aborted; no changes made")
	}
	if pa.rf.dryRun {
		pa.bump = dryRunBump(pa.m, pa.cfg, out.Plans)
	}
	if pa.rf.json {
		return finishDoc(func(plans []apply.ServerPlan, _ bool) error {
			return apply.RenderJSON(pa.stdout, pa.cfg, plans, apply.JSONOptions{Command: "apply", DryRun: pa.rf.dryRun, Skipped: pa.skipped, SerialBump: pa.bump})
		}, out)
	}
	apply.RenderSummary(pa.stdout, out.Plans, pa.ropts)
	if pa.skipped > 0 {
		fmt.Fprintf(pa.stdout, "(%s skipped by --server)\n", apply.Plural(pa.skipped, "server", "servers"))
	}
	printDryRunBump(pa.stdout, pa.log, pa.rf.dryRun, pa.bump)
	if out.ExitCode() != 0 {
		return errNonCompliant
	}
	return nil
}
```

Add to `apply.go`:

```go
// noBumpWarning: apply removes keys but cannot save the bumped serial.
const noBumpWarning = "removing keys without a serial bump: an older copy could re-grant them"

// errNoSerialSave: the manifest cannot be saved in place — a pipe, or a
// shape the comment-preserving editor refuses (anchors); apply then warns
// and writes without the bump.
var errNoSerialSave = errors.New("manifest cannot be saved in place")

// serialEditable loads the manifest for the D4b edit — the one
// classification saveSerialBump and dryRunBump share, so a dry run never
// promises a bump the real run would only warn about: a pipe, or a shape
// the comment-preserving editor refuses (anchors, aliases), cannot be
// saved in place (errNoSerialSave: warn and write without the bump).
func serialEditable(m manifestTarget) (*manifest.File, error) {
	if m.Stream {
		return nil, errNoSerialSave
	}
	mf, err := manifest.Load(m.Loaded)
	var ue *manifest.UnsupportedError
	if errors.As(err, &ue) {
		return nil, errNoSerialSave
	}
	if err != nil {
		return nil, fmt.Errorf("serial bump: %w", err)
	}
	return mf, nil
}

// saveSerialBump raises the manifest's serial: by one through the locked
// store (its compare-and-swap included) and returns the new value. A failed
// save is a tool error: nothing is written (spec §6).
func saveSerialBump(m manifestTarget) (uint64, error) {
	mf, err := serialEditable(m)
	if err != nil {
		return 0, err
	}
	to, err := mf.BumpSerial()
	if err != nil {
		return 0, fmt.Errorf("serial bump: %w", err)
	}
	out, err := mf.Encode()
	if err != nil {
		return 0, fmt.Errorf("serial bump: %w", err)
	}
	if err := m.Save(out); err != nil {
		return 0, err //nolint:wrapcheck // "save manifest …" / "changed since it was read" are the user-facing text
	}
	return to, nil
}

// dryRunBump is what a confirmed run of these plans would bump (nil:
// none), classified exactly as saveSerialBump would (serialEditable).
func dryRunBump(m manifestTarget, cfg *config.Config, plans []apply.ServerPlan) *apply.SerialBump {
	from := cfg.Serial()
	if !apply.NeedsSerialBump(plans, from) {
		return nil
	}
	if _, err := serialEditable(m); err != nil {
		return &apply.SerialBump{From: from, Warning: noBumpWarning}
	}
	to := from + 1
	return &apply.SerialBump{From: from, To: &to}
}

// printDryRunBump prints the dry-run's would-bump line (or the warning a
// piped --config gets).
func printDryRunBump(stdout io.Writer, log *slog.Logger, dryRun bool, b *apply.SerialBump) {
	switch {
	case !dryRun || b == nil:
	case b.To == nil:
		log.Warn(b.Warning)
	default:
		fmt.Fprintf(stdout, "would bump serial: %d → %d (this apply removes keys)\n", b.From, *b.To)
	}
}
```

(`apply.go` imports `internal/manifest`, and `log/slog` if it lacks it.)

- [ ] **Step 4: Run** — `GOTOOLCHAIN=go1.27.3 go test -race ./internal/apply/ ./cmd/sshepherd/ -run 'NeedsSerialBump|Reserial|TestApply'` → `ok`; `golangci-lint run --enable-only=gocyclo,errorlint ./cmd/sshepherd/` → clean.

### Task 36: the write footer, help goldens, the E2E loop and the tests this round changes

**Files:**
- Modify: `cmd/sshepherd/run.go:203-208` (`exitCodesWrite`), `cmd/sshepherd/e2e_test.go:82-255` (`TestE2EApplyLoop`)
- Test updates: `cmd/sshepherd/revoke_test.go`, `revoke_server_test.go`, `rotate_test.go`, `json_cmd_test.go`; goldens `cmd/sshepherd/testdata/help/{apply,revoke,rotate}.golden`

- [ ] **Step 1: The footer**

```go
const exitCodesWrite = `Exit codes:
  0  converged: nothing left to do (a header-only update applied, or a server
     a newer manifest wrote whose keys already match); a revoke whose targets
     were already revoked; or, with revoke/rotate --no-apply, the edit is
     saved but not pushed (run the apply hint it prints)
  1  pending changes, unreachable or refused servers (a newer manifest's
     serial, a policy conflict), or a declined prompt
  3  tool error: bad flags, unloadable manifest, failed preflight, a manifest
     that would keep a policy conflict, a failed serial save, or refused
     before anything was saved or written`
```

- [ ] **Step 2: Update the tests whose text this round changes** (each edit below is the whole change; run the file after each)

`revoke_test.go`:
- `:146` → `"manifest " + cfg + " updated — commit and push it: an apply from a copy without this edit is refused on the servers this run writes (serial 1)\n",`
- `:149` → `"check every server: sshepherd audit --config " + cfg + " --known-hosts " + kh + "\n",`
- `:200`, `:552` → `render := authkeys.Header(1) + "\n" + testkeys.Line(t, 1) + " alice\n"` (the servers already carry the serial this revoke saves, so they stay converged — the premise of both tests).
- `:254` → `h.install(t, nil, authkeys.Header(1), testkeys.Line(t, 1)+" alice")`.
- `:775-776` → `"check every server: sshepherd audit --config " + cfg + " --known-hosts " + kh + "\n",`
- `:830-831`: delete the `"key not in the manifest"` row of `TestRevokeUsage` (D1b records it now; `TestRevokeUnownedKeyRecordsTombstone` covers it).

`revoke_server_test.go`:
- `:127` → `"manifest " + cfg + " updated — commit and push it: an apply from a copy without this edit is refused on the servers this run writes (serial 1)\n",`
- `:251` → `"servers learn serial 1 only when an apply writes them; until then a copy without this edit can re-grant there\n",`

`rotate_test.go:48` → `"check every server: sshepherd audit --config " + cfg + " --known-hosts " + kh,` (declare `cfg` in that test from `writeConfig`'s return — it already is).

(`json_cmd_test.go:496`'s unowned `--key` row was already replaced in Task 31 Step 3.)

- [ ] **Step 3: Keep the E2E loop's m0 checks meaningful under a serial**

In `TestE2EApplyLoop` (`e2e_test.go:82`), after the revoke (`"revoke --key --json saves…"`), the server carries `(serial 1)`; a serial-0 manifest is now "written by a newer manifest" there (drift) and a serial-0 ghost manifest would be refused for its serial before the guard runs. Keep m0's YAML in a variable `m0Body` and add, before `"audit is clean after the revoke"`:

```go
	// The revoke saved serial 1 and wrote it to the server: the hand-written
	// m0 must say so too, or audit reports the newer header as drift (D4a).
	m1 := writeE2EManifest(t, dir, "m1.yaml", "serial: 1\n"+m0Body)
```

Use `m1` in place of `m0` in the second audit of `"audit is clean after the revoke"` and in the post-refusal audit of `"lockout guard refuses…"`, and prefix the ghost manifest with `serial: 1\n` so the lockout guard — not the serial rule — refuses it.

- [ ] **Step 4: Goldens, README delta, gates**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run TestHelpGolden -update && git diff cmd/sshepherd/testdata/help/`
Expected: `apply.golden` (footer), `revoke.golden` and `rotate.golden` (footer, the new `--reason` flag row) change; nothing else.

Apply this lane's README delta to the worktree, then:
Run: `GOTOOLCHAIN=go1.27.3 go test -race ./... && make check`, then (with the runner's lock) `make integration`.
Expected: green; the E2E suite passes (TestE2EApplyLoop with `m1`, TestE2EFleetFanOut whose first apply now bumps its manifest to serial 1, TestE2EHeadlessLoop likewise).

- [ ] **Step 5: Capture the README samples (real output, no server needed)**

Every writecmds sample line without a golden is captured from the built binary in a scratch directory, with the default `--config` (`sshepherd.yaml` in the working directory) so the printed hints carry no temp paths. None of these runs contacts a server (`--no-apply`, D1b's save-only path, D1c no-ops, the D29 refusal); the server `host` is a TEST-NET address that is never dialed.

```sh
GOTOOLCHAIN=go1.27.3 go build -o "$PATCH_DIR/sshepherd-w4" ./cmd/sshepherd
D=$(mktemp -d) && cd "$D" && B="$PATCH_DIR/sshepherd-w4"
for k in bob carol stray; do ssh-keygen -q -t ed25519 -N '' -C "$k@laptop" -f "$k"; done
fp() { ssh-keygen -lf "$1.pub" | awk '{print $2}'; }
cat > sshepherd.yaml <<YAML
users:
  - {name: bob, keys: ["$(cat bob.pub)"]}
  - {name: carol, keys: ["$(cat carol.pub)"]}
servers:
  - {name: web-1, host: 192.0.2.10, user: deploy}
access:
  - {user: bob, servers: [web-1]}
  - {user: carol, servers: [web-1]}
YAML
"$B" revoke bob --reason offboarded --no-apply --yes            # header, --no-apply save note, check line
"$B" revoke bob --no-apply --yes                                # D1c note (exit 0)
"$B" revoke --key "$(fp stray)" --yes                           # record-key header, default save note (D1b: no server)
"$B" revoke --key "$(fp stray)" --yes                           # D1b no-op note
cat > conflict.yaml <<YAML
users:
  - {name: carol, keys: ["$(cat carol.pub)"]}
  - {name: dave, keys: ["$(cat stray.pub)"]}
servers:
  - {name: web-1, host: 192.0.2.10, user: deploy}
access:
  - {user: carol, servers: [web-1]}
revoked:
  - {fingerprint: $(fp stray), user: dave, date: 2026-11-08}
YAML
"$B" revoke carol --config conflict.yaml --no-apply --yes; echo "exit $?"   # the D29 save refusal (exit 3; its text carries no path)
```

Paste each printed line verbatim into the docsDelta below in place of its placeholder shape; dates are the capture day's. The D4b lines (`manifest serial: 0 → 1 (saved; this apply removes keys)`, `would bump serial: 0 → 1 (this apply removes keys)`) and the piped warning carry no path: copy them from `TestApplyBumpsSerialOnHandRemoval`'s / `noBumpWarning`'s literals.

- [ ] **Step 6: Hand back** (lane `writecmds`; the integrator commits `feat(revoke): revocation memory, serial bump, header-only writes, D4b (P04 W4, PRD-1, PRD-2, SEC-2)`)

**docsDelta (lane `writecmds`)** — every quoted output line is replaced by its Step 5 capture before hand-back; the shapes below only say which line goes where:
- README `### sshepherd revoke`: the `--reason` flag row (copied from `--help`); "Every revoke that saves records what it removed in `revoked:` — `revoke USER` one key entry per key, `revoke --key` one per key (labelled with its owner), `revoke USER --server NAME` one access entry naming the servers removed from an explicit list (a wildcard's new `except:` already remembers its server) — and bumps `serial:` once." "`revoke --key` of a key no user has records it (captured `manifest edit: record revoked key SHA256:… (no user has it; no server is written) — no servers affected`) instead of failing; repeating it prints the captured `SHA256:… was already revoked (DATE)` and exits 0." **Replace** the sentence at README l.969-971 ("Re-running a revoke whose save landed but whose push did not finish exits `3` with `not in the manifest (already revoked?)` …", false after D1c) with: "Re-running a revoke for a user already revoked prints a note and exits `0` — captured: `bob was already revoked (DATE); run 'sshepherd apply' to converge any server that still has the key` (the hint carries your own non-default flags); with several users, the already-revoked ones get the note and the rest are revoked as usual. A name that was never revoked still exits `3` with `not in the manifest (already revoked?)`." Replace both `scope:` sentences (l.937, l.970-973 at `cfe22dc`; find them by `scope:`) with the captured `check every server: sshepherd audit` line, and the save-note text with the two captured serial notes (spec §4: the default note, and the `--no-apply` one). Add the save refusal: "`revoke` refuses to save a manifest that would keep a policy conflict, exit `3`, nothing saved — captured: `refusing to write the manifest — it would keep 1 policy conflict: …`; `revoke --key` of the conflicting key is the fix." Add: "an affected server whose keys already match gets a header-only update carrying the new serial, so an older copy of the manifest is refused there too."
- README `### sshepherd rotate`: `--reason` (default `rotated out`); plain rotate tombstones the old key; `--keep-old` tombstones nothing (the finishing `revoke --key OLD` does) but bumps the serial. **Replace** l.1250-1251 ("Confirmation, saving, `--dry-run`, `--no-apply`, operators and the scope line work exactly as for `revoke` (no scope line under `--keep-old`: nothing is removed).") with: "Confirmation, saving, `--dry-run`, `--no-apply`, operators and the `check every server: sshepherd audit …` line work exactly as for `revoke` (no check line under `--keep-old`: nothing is removed)." Add the save refusal: "`rotate` refuses, exit `3`, to save a manifest that would keep a policy conflict — in particular `--new` of a revoked key (`refusing to write the manifest — it would keep 1 policy conflict: key SHA256:… of user "bob" is revoked (…)`, the shape of the Step 5 capture)."
- README `### sshepherd apply`: D4b — "a confirmed apply that removes a key from a server whose header serial is not above the manifest's bumps `serial:` once, saving it under the manifest lock after the prompt and before the first write (`manifest serial: 7 → 8 (saved; this apply removes keys)`); `--dry-run` prints `would bump serial: 7 → 8 (this apply removes keys)`; a piped `--config` (or one the editor cannot save, e.g. with YAML anchors) cannot be saved and warns `removing keys without a serial bump: an older copy could re-grant them` — under `--dry-run` too; a failed save exits 3 with nothing written and, under `--json`, no document". The two serial lines are copied from `TestApplyBumpsSerialOnHandRemoval`'s literals (they print `0 → 1` there; use those numbers). JSON `serial_bump` (sample from `internal/apply/testdata/json_memory_top.golden.json`).
- README `## Quick start` `### 4. Offboard someone`: replace the block with `sshepherd revoke alice` (its apply phase writes the serial to every affected server), `git commit -am "offboard alice" && git push`, then the printed `sshepherd audit` command; explain "running revoke with its apply phase (not `--no-apply`) is what stops an older copy of the manifest from re-granting alice: every affected server learns the new serial".
- README `## Exit codes`: replace the `apply, revoke and rotate --help` block with the new `exitCodesWrite`.

---
## Round 4 — lane `sweep` (Tasks 37–40)

Owns: `internal/apply/sweep*.go`, `internal/apply/json.go`, `internal/apply/json_test.go`, `internal/apply/testdata/json_sweep.golden.json`, `cmd/sshepherd/sweep*.go`, `cmd/sshepherd/editrun.go`, `cmd/sshepherd/apply.go`, `cmd/sshepherd/run.go`, `cmd/sshepherd/testdata/help/{apply,revoke,rotate}.golden`. Findings: SEC-2 (D3, D28). `needsIntegration: false` (hermetic `sshtest` coverage; the integrator's `make integration` after the round still runs).

The sweep only reads: it never writes a server, never removes a key, and is not `prune`.

### Task 37: `apply.SweepReport`, JSON `sweep`, the combined exit

**Files:**
- Create: `internal/apply/sweep.go`, `internal/apply/sweep_test.go`
- Modify: `internal/apply/json.go` (`JSONOptions`, `jsonDoc`, `RenderJSON`)
- Golden: `internal/apply/testdata/json_sweep.golden.json` (new)

- [ ] **Step 1: Write the failing tests**

`internal/apply/sweep_test.go`:

```go
package apply

import (
	"bytes"
	"testing"
)

func TestSweepReportExitCode(t *testing.T) {
	var none *SweepReport
	for _, tc := range []struct {
		r    *SweepReport
		want int
	}{
		{none, 0},
		{&SweepReport{Checked: 3}, 0},
		{&SweepReport{Unreachable: []string{"db-3"}}, 1},
		{&SweepReport{Unprovable: []SweepUnprovable{{Server: "db-2", Reason: "authorized_keys2 unreadable"}}}, 1},
		{&SweepReport{Unreachable: []string{"db-3"}, StillInstalled: []SweepHit{{Server: "db-2"}}}, 2},
	} {
		if got := tc.r.ExitCode(); got != tc.want {
			t.Errorf("%+v: ExitCode = %d, want %d", tc.r, got, tc.want)
		}
	}
}

func TestRenderJSONSweepGolden(t *testing.T) {
	cfg := planCfg(t)
	rep := &SweepReport{Checked: 2,
		StillInstalled: []SweepHit{{Server: "db-2", Fingerprint: fp(t, 3), User: "bob", File: "authorized_keys2"}},
		Unreachable:    []string{"db-3"},
	}
	got := renderJSONCfg(t, cfg, nil, JSONOptions{Command: "revoke", Edit: &EditSummary{}, Saved: true, Sweep: rep})
	checkGolden(t, "json_sweep.golden.json", got)
	for _, want := range []string{`"sweep": {`, `"still_installed": [`, `"file": "authorized_keys2"`, `"unprovable": []`, `"exit_code": 2`} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("document lacks %s", want)
		}
	}
	if bytes.Contains(renderJSONCfg(t, cfg, nil, JSONOptions{Command: "revoke", Edit: &EditSummary{}}), []byte(`"sweep"`)) {
		t.Error("a run without a sweep has no sweep object")
	}
}
```

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply/ -run 'Sweep'`
Expected: build failure (`undefined: SweepReport`).

- [ ] **Step 3: Implement**

`internal/apply/sweep.go`:

```go
package apply

// SweepReport is the opt-in post-revoke sweep (spec 2026-11-08 §7):
// read-only, over every manifest server the run did not just write or find
// converged, looking for this run's revoked keys. The json tags are the
// wire shape of the document's sweep object.
type SweepReport struct {
	Checked        int               `json:"checked"`
	StillInstalled []SweepHit        `json:"still_installed"`
	Unreachable    []string          `json:"unreachable"`
	Unprovable     []SweepUnprovable `json:"unprovable"`
}

// SweepHit is a revoked key still installed on Server, in File
// ("authorized_keys" or "authorized_keys2"); User is the tombstone's label.
type SweepHit struct {
	Server      string `json:"server"`
	Fingerprint string `json:"fingerprint"`
	User        string `json:"user,omitempty"`
	File        string `json:"file"`
}

// SweepUnprovable is a server read whose removal the sweep cannot prove.
type SweepUnprovable struct {
	Server string `json:"server"`
	Reason string `json:"reason"`
}

// ExitCode is the sweep's share of the run's exit (spec §8): 2 when a
// revoked key is still installed, 1 when a server could not be read or
// could not prove the removal, else 0 (also for a nil report: no sweep).
func (r *SweepReport) ExitCode() int {
	switch {
	case r == nil:
		return 0
	case len(r.StillInstalled) > 0:
		return 2
	case len(r.Unreachable)+len(r.Unprovable) > 0:
		return 1
	}
	return 0
}

// wire returns r with every list non-nil, so each encodes as [].
func (r *SweepReport) wire() *SweepReport {
	if r == nil {
		return nil
	}
	w := *r
	if w.StillInstalled == nil {
		w.StillInstalled = []SweepHit{}
	}
	if w.Unreachable == nil {
		w.Unreachable = []string{}
	}
	if w.Unprovable == nil {
		w.Unprovable = []SweepUnprovable{}
	}
	return &w
}
```

`internal/apply/json.go`: `JSONOptions` gains `Sweep *SweepReport // revoke/rotate --sweep; nil when no sweep ran`; `jsonDoc` gains, after `SerialBump`:

```go
	// Sweep is additive-optional (schema stays 1): revoke/rotate --sweep
	// only; omitted when no sweep ran (--dry-run, --no-apply, or no flag).
	Sweep *SweepReport `json:"sweep,omitempty"`
```

In `RenderJSON`: `ExitCode: max(ExitCode(plans), opts.Sweep.ExitCode()),` in the summary literal, and `doc.Sweep = opts.Sweep.wire()` after `doc.SerialBump`. Update the `RenderJSON` doc comment: "a document is written for exit 0, 1 or 2 (2: the sweep found a revoked key)".

- [ ] **Step 4: Golden, read back, run**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply/ -run TestRenderJSONSweepGolden -update && cat internal/apply/testdata/json_sweep.golden.json && GOTOOLCHAIN=go1.27.3 go test -race ./internal/apply/`
Expected: the golden ends with the `sweep` object (`checked: 2`, one `still_installed` entry, `unreachable: ["db-3"]`, `unprovable: []`) and `summary.exit_code` 2; every other golden unchanged; `ok`.

### Task 38: the sweep's pure half — targets, classification, text

**Files:**
- Create: `cmd/sshepherd/sweep.go`, `cmd/sshepherd/sweep_test.go`

- [ ] **Step 1: Write the failing tests**

```go
package main

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func mustKey(t *testing.T, seed byte) authkeys.Key {
	t.Helper()
	k, err := authkeys.ParseLine(testkeys.Line(t, seed))
	if err != nil || k == nil {
		t.Fatal(err)
	}
	return *k
}

func TestSweepTargets(t *testing.T) {
	cfg := &config.Config{Servers: []config.Server{{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}}}
	plans := []apply.ServerPlan{
		{Server: config.Server{Name: "a"}, Class: apply.ClassChange, Outcome: apply.OutcomeApplied},
		{Server: config.Server{Name: "b"}, Class: apply.ClassConverged},
		{Server: config.Server{Name: "c"}, Class: apply.ClassUnreachable},
	}
	var names []string
	for _, s := range sweepTargets(cfg, plans) {
		names = append(names, s.Name)
	}
	if !reflect.DeepEqual(names, []string{"c", "d"}) {
		t.Errorf("targets = %v, want [c d] (an unreachable affected server is swept again)", names)
	}
}

func TestClassifySweep(t *testing.T) {
	bob, stray := mustKey(t, 2), mustKey(t, 9)
	tombs := []config.Tombstone{{Fingerprint: bob.Fingerprint, User: "bob", Date: "2026-11-08"}, {User: "x", Servers: []string{"db-1"}, Date: "2026-11-08"}}
	results := []audit.ServerResult{
		{Server: config.Server{Name: "db-1"}, Diff: authkeys.Result{Unauthorized: []authkeys.Key{bob, stray}}},
		{Server: config.Server{Name: "db-2"}, AuthorizedKeys2: true, Keys2: []byte(testkeys.Line(t, 2) + "\n")},
		{Server: config.Server{Name: "db-3"}, Err: errors.New("dial: refused")},
		{Server: config.Server{Name: "db-4"}, AuthorizedKeys2: true, Keys2Err: errors.New("exit 1")},
		{Server: config.Server{Name: "db-5"}, AuthorizedKeys2: true, Keys2: []byte("not a key\n")},
	}
	got := classifySweep(results, tombs)
	want := apply.SweepReport{
		Checked: 5,
		StillInstalled: []apply.SweepHit{
			{Server: "db-1", Fingerprint: bob.Fingerprint, User: "bob", File: "authorized_keys"},
			{Server: "db-2", Fingerprint: bob.Fingerprint, User: "bob", File: "authorized_keys2"},
		},
		Unreachable: []string{"db-3"},
		Unprovable: []apply.SweepUnprovable{
			{Server: "db-4", Reason: "authorized_keys2 unreadable"},
			{Server: "db-5", Reason: "authorized_keys2 unreadable"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("report = %+v\nwant   %+v", got, want)
	}
}

func TestRenderSweep(t *testing.T) {
	cfg, err := config.Parse([]byte("users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n" +
		"servers:\n  - {name: db-2, host: h2, user: u}\n  - {name: db-7, host: h7, user: u}\n  - {name: db-9, host: h9, user: u}\n" +
		"access:\n  - {user: alice, servers: [db-2, db-7]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	fp := mustKey(t, 2).Fingerprint
	rep := apply.SweepReport{Checked: 3,
		StillInstalled: []apply.SweepHit{
			{Server: "db-2", Fingerprint: fp, User: "bob", File: "authorized_keys"},
			{Server: "db-7", Fingerprint: fp, User: "bob", File: "authorized_keys"},
			{Server: "db-9", Fingerprint: fp, User: "bob", File: "authorized_keys"},
		},
		Unprovable: []apply.SweepUnprovable{{Server: "db-7", Reason: "authorized_keys2 unreadable"}},
	}
	var b bytes.Buffer
	renderSweep(&b, rep, cfg, followUp{config: "--config f.yaml"}, 4)
	want := "REVOKED KEY STILL INSTALLED: bob " + fp + " on db-2, db-7 — run 'sshepherd apply --config f.yaml --server db-2 --server db-7'\n" +
		"REVOKED KEY STILL INSTALLED: bob " + fp + " on db-9 — remove it by hand or grant another user there first\n" +
		"cannot prove removal on db-7 (authorized_keys2 unreadable)\n" +
		"swept 3 of 4 servers: 3 still have a revoked key, 0 unreachable\n"
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}
```

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestSweepTargets|TestClassifySweep|TestRenderSweep'`
Expected: build failure (`undefined: sweepTargets`).

- [ ] **Step 3: Implement** — `cmd/sshepherd/sweep.go`:

```go
package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
)

// sweepTargets is every server of cfg except the affected ones this run
// applied-and-verified or found converged (spec §7): those already prove
// the key is gone.
func sweepTargets(cfg *config.Config, plans []apply.ServerPlan) []config.Server {
	done := make(map[string]bool, len(plans))
	for _, p := range plans {
		if p.Class == apply.ClassConverged || (p.Class == apply.ClassChange && p.Outcome == apply.OutcomeApplied) {
			done[p.Server.Name] = true
		}
	}
	var out []config.Server
	for _, s := range cfg.Servers {
		if !done[s.Name] {
			out = append(out, s)
		}
	}
	return out
}

// keyTombstones filters this run's new tombstones to key entries: an access
// tombstone only names servers the run already wrote, so it adds nothing
// to look for.
func keyTombstones(ts []config.Tombstone) []config.Tombstone {
	var out []config.Tombstone
	for _, t := range ts {
		if t.IsKey() {
			out = append(out, t)
		}
	}
	return out
}

// runSweep reads targets with the run's session (known_hosts, credentials,
// --parallel), asking for authorized_keys2 too, and classifies the reads.
func runSweep(ctx context.Context, sess *fleetSession, cfg *config.Config, targets []config.Server, tombs []config.Tombstone) (apply.SweepReport, error) {
	if len(targets) == 0 {
		return classifySweep(nil, tombs), nil // audit.Run would read the whole fleet
	}
	reader := sess.reader(func(s config.Server) []string { return audit.GrantedFingerprints(cfg, s.Name) })
	reader.ReadKeys2 = true
	sess.log.Info(fmt.Sprintf("sweeping %s for revoked keys (parallelism %d)…", apply.Plural(len(targets), "server", "servers"), sess.parallel))
	results := audit.Run(ctx, cfg, reader, audit.Options{Parallel: sess.parallel, PerServerTimeout: perServerTimeout, Servers: targets, Logger: sess.log})
	if err := interrupted(ctx); err != nil {
		return apply.SweepReport{}, err
	}
	return classifySweep(results, tombs), nil
}

// classifySweep keeps only this run's key tombstones found in
// authorized_keys (audit's Unauthorized keys) or in a non-empty
// authorized_keys2; a keys2 that exists but cannot be read or parsed
// cannot prove the removal (exit 1, never 0).
func classifySweep(results []audit.ServerResult, tombs []config.Tombstone) apply.SweepReport {
	label := make(map[string]string, len(tombs))
	for _, t := range tombs {
		if t.IsKey() {
			label[t.Fingerprint] = t.User
		}
	}
	rep := apply.SweepReport{Checked: len(results)}
	for _, r := range results {
		if r.Err != nil {
			rep.Unreachable = append(rep.Unreachable, r.Server.Name)
			continue
		}
		for _, k := range r.Diff.Unauthorized {
			if user, ok := label[k.Fingerprint]; ok {
				rep.StillInstalled = append(rep.StillInstalled, apply.SweepHit{Server: r.Server.Name, Fingerprint: k.Fingerprint, User: user, File: "authorized_keys"})
			}
		}
		rep = keys2Hits(rep, r, label)
	}
	return rep
}

// keys2Hits adds a server's authorized_keys2 findings.
func keys2Hits(rep apply.SweepReport, r audit.ServerResult, label map[string]string) apply.SweepReport {
	if !r.AuthorizedKeys2 {
		return rep
	}
	keys, perrs := authkeys.ParseFile(r.Keys2)
	if r.Keys2Err != nil || r.Keys2 == nil || len(perrs) > 0 {
		rep.Unprovable = append(rep.Unprovable, apply.SweepUnprovable{Server: r.Server.Name, Reason: "authorized_keys2 unreadable"})
		return rep
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if user, ok := label[k.Fingerprint]; ok && !seen[k.Fingerprint] {
			seen[k.Fingerprint] = true
			rep.StillInstalled = append(rep.StillInstalled, apply.SweepHit{Server: r.Server.Name, Fingerprint: k.Fingerprint, User: user, File: "authorized_keys2"})
		}
	}
	return rep
}

// sweepGroup is one revoked key in one file, with the servers holding it:
// fixable by apply, or by hand (the manifest grants nothing there and apply
// never empties a server).
type sweepGroup struct {
	fp, user, file  string
	fixable, byHand []string
}

func groupHits(rep apply.SweepReport, cfg *config.Config) []*sweepGroup {
	var groups []*sweepGroup
	idx := map[string]*sweepGroup{}
	for _, hit := range rep.StillInstalled {
		key := hit.Fingerprint + "\x00" + hit.File
		g := idx[key]
		if g == nil {
			g = &sweepGroup{fp: hit.Fingerprint, user: hit.User, file: hit.File}
			idx[key] = g
			groups = append(groups, g)
		}
		if len(cfg.DesiredFor(hit.Server)) == 0 {
			g.byHand = append(g.byHand, hit.Server)
		} else {
			g.fixable = append(g.fixable, hit.Server)
		}
	}
	return groups
}

// renderSweep prints the sweep: one line per revoked key and file with its
// servers and the fix (the apply hint carries the run's flags), then the
// servers that could not prove the removal, then the tally.
func renderSweep(w io.Writer, rep apply.SweepReport, cfg *config.Config, h followUp, fleetSize int) {
	for _, g := range groupHits(rep, cfg) {
		head := "REVOKED KEY STILL INSTALLED"
		if g.file == "authorized_keys2" {
			head += " (authorized_keys2)"
		}
		who := strings.TrimSpace(g.user + " " + g.fp)
		if len(g.fixable) > 0 {
			fmt.Fprintf(w, "%s: %s on %s — run '%s'\n", head, who, strings.Join(g.fixable, ", "), applyHint(h, g.fixable))
		}
		if len(g.byHand) > 0 {
			fmt.Fprintf(w, "%s: %s on %s — remove it by hand or grant another user there first\n", head, who, strings.Join(g.byHand, ", "))
		}
	}
	for _, s := range rep.Unreachable {
		fmt.Fprintf(w, "cannot prove removal on %s (unreachable)\n", s)
	}
	for _, u := range rep.Unprovable {
		fmt.Fprintf(w, "cannot prove removal on %s (%s)\n", u.Server, u.Reason)
	}
	holding := map[string]bool{}
	for _, hit := range rep.StillInstalled {
		holding[hit.Server] = true
	}
	fmt.Fprintf(w, "swept %d of %s: %d still %s a revoked key, %d unreachable\n",
		rep.Checked, apply.Plural(fleetSize, "server", "servers"), len(holding), pluralWord(len(holding), "has", "have"), len(rep.Unreachable))
}
```

- [ ] **Step 4: Run** — `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestSweepTargets|TestClassifySweep|TestRenderSweep'` → `ok` (`runSweep` is reached from main in Task 39; run `make check` only after it).

### Task 39: `--sweep` on revoke and rotate

**Files:**
- Modify: `cmd/sshepherd/editrun.go` (`editFlags`, `register`, `editDoc`, `runEdit`, `saveOnly`, `noApplyNote`, `finishDoc`, `finishEdit`), `cmd/sshepherd/apply.go` (`applySpec.finish`, `runWorkflow`, apply's own `finish`)
- Test: `cmd/sshepherd/sweep_test.go`

- [ ] **Step 1: Write the failing hermetic tests**

```go
// sweepFleet: alice (k1, the agent's key) on web-1 and web-2; bob (k2)
// granted web-1 only, with a hand copy of his key on web-2.
func sweepFleet(t *testing.T) (map[string]editHost, string, string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	hosts["web-1"].install(t, []byte{1, 2})
	hosts["web-2"].install(t, []byte{1, 2})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: bob, servers: [web-1]}\n")
	return hosts, kh, cfg
}

func TestRevokeSweepFindsStrayExit2(t *testing.T) {
	_, kh, cfg := sweepFleet(t)
	var out, errBuf bytes.Buffer
	code := run([]string{"revoke", "bob", "--sweep", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("exit = %d, want 2\n%s\n%s", code, out.String(), errBuf.String())
	}
	for _, want := range []string{
		"web-1: applied · verified",
		"REVOKED KEY STILL INSTALLED: bob " + fpOf(t, 2) + " on web-2 — run 'sshepherd apply --config " + cfg + " --known-hosts " + kh + " --server web-2'\n",
		"swept 1 of 2 servers: 1 still has a revoked key, 0 unreachable\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "check every server:") {
		t.Error("the check line prints only when no sweep ran")
	}
}

func TestRevokeSweepFindsKeyInKeys2(t *testing.T) {
	hosts, kh, cfg := sweepFleet(t)
	hosts["web-2"].install(t, []byte{1})
	if err := os.WriteFile(filepath.Join(hosts["web-2"].home, ".ssh", "authorized_keys2"), []byte(testkeys.Line(t, 2)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--sweep", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "REVOKED KEY STILL INSTALLED (authorized_keys2): bob "+fpOf(t, 2)+" on web-2") {
		t.Errorf("stdout:\n%s", out.String())
	}
}

func TestSweepSkippedOnDryRunAndNoApply(t *testing.T) {
	for _, mode := range [][]string{{"--dry-run"}, {"--no-apply", "--yes"}} {
		hosts, kh, cfg := sweepFleet(t)
		args := append([]string{"revoke", "bob", "--sweep", "--config", cfg}, mode...)
		if mode[0] == "--dry-run" {
			args = append(args, "--known-hosts", kh)
		}
		var out, errBuf bytes.Buffer
		run(args, &out, &errBuf)
		if len(hosts["web-2"].srv.Attempts()) != 0 || strings.Contains(out.String(), "swept ") {
			t.Errorf("%v: the sweep ran\n%s", mode, out.String())
		}
		if !strings.Contains(out.String(), "check every server: sshepherd audit --config "+cfg) {
			t.Errorf("%v: the skipped sweep must print the audit command\n%s", mode, out.String())
		}
	}
}

func TestRevokeSweepUnreachable(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1, 2})
	closed := closedPort(t) // adopt_test.go's helper: a just-released local port
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+fmt.Sprintf("  - {name: web-3, host: 127.0.0.1, port: %d, user: deploy}\n", closed)+
		"access:\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [web-1]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--sweep", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1 (the sweep could not read web-3)\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "cannot prove removal on web-3 (unreachable)\n") || !strings.Contains(out.String(), "1 unreachable\n") {
		t.Errorf("stdout:\n%s", out.String())
	}
}

// TestRevokeSweepDefaultFlags: with the default --config (sshepherd.yaml
// in the working directory) and --known-hosts (~/.ssh/known_hosts) the
// sweep's hint carries no flags — the form the README shows; Task 40
// Step 3 copies the README sample from this test's log.
func TestRevokeSweepDefaultFlags(t *testing.T) {
	_, kh, cfg := sweepFleet(t)
	home, dir := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), fileBytes(t, kh), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sshepherd.yaml"), fileBytes(t, cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Chdir(dir)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--sweep", "--yes"}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2\n%s\n%s", code, out.String(), errBuf.String())
	}
	for _, want := range []string{
		"REVOKED KEY STILL INSTALLED: bob " + fpOf(t, 2) + " on web-2 — run 'sshepherd apply --server web-2'\n",
		"swept 1 of 2 servers: 1 still has a revoked key, 0 unreachable\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	t.Logf("stdout (the README sample):\n%s", out.String())
}

// TestRevokeUnownedKeySweep: D1b's save-only path sweeps every server.
func TestRevokeUnownedKeySweep(t *testing.T) {
	hosts, kh, cfg := sweepFleet(t)
	hosts["web-2"].install(t, []byte{1, 9})
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "--key", fpOf(t, 9), "--sweep", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "REVOKED KEY STILL INSTALLED: "+fpOf(t, 9)+" on web-2") || !strings.Contains(out.String(), "swept 2 of 2 servers") {
		t.Errorf("stdout:\n%s", out.String())
	}
}

func TestRevokeSweepJSON(t *testing.T) {
	_, kh, cfg := sweepFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--sweep", "--yes", "--json", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2\n%s", code, errBuf.String())
	}
	var doc struct {
		Edit    map[string]any `json:"edit"`
		Summary struct {
			ExitCode int `json:"exit_code"`
		} `json:"summary"`
		Sweep struct {
			StillInstalled []map[string]string `json:"still_installed"`
		} `json:"sweep"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not one document: %v\n%s", err, out.String())
	}
	if doc.Summary.ExitCode != 2 || len(doc.Sweep.StillInstalled) != 1 || doc.Sweep.StillInstalled[0]["server"] != "web-2" {
		t.Errorf("document = %s", out.String())
	}
	if _, ok := doc.Edit["check_command"]; ok {
		t.Error("check_command is present only when --sweep was not given")
	}
}
```

(add `"encoding/json"`, `"fmt"`, `"os"`, `"path/filepath"`, `"strings"` to `sweep_test.go`'s imports.)

- [ ] **Step 2: Run to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'Sweep'`
Expected: FAIL (`unknown flag: --sweep`).

- [ ] **Step 3: Implement**

`editrun.go`:

- `editFlags` gains `sweep bool`; `register` adds

```go
	cmd.Flags().BoolVar(&f.sweep, "sweep", false,
		"after the writes, read every other server and report any that still has a key this run revoked (read-only; exit 2 when one is found; skipped with --dry-run and --no-apply)")
```

- `editDoc` becomes `type editDoc func(plans []apply.ServerPlan, saved bool, sweep *apply.SweepReport) error`; `runEdit`'s doc closure takes the third argument and passes `Sweep: sweep` in its `JSONOptions`.
- In `runEdit`: Task 34's `checkCommand(ep, h)` becomes `checkCommand(ep, h, f.sweep)`, and the helper returns `""` when `sweep` is set (spec §9: `check_command` is present only when `--sweep` was not given) — the branch stays in the helper; `saveOnly(cmd, log, stdout, f, ids, ep, aff, doc, h)` gains `ids`; the `applySpec.finish` becomes `finish: editFinish(cmd, stdout, log, f, ep, aff, h, ropts, doc),` — a named constructor, because a function literal's branches count toward `runEdit`'s gocyclo:

```go
// editFinish is runEdit's finish seam: the opt-in sweep after a confirmed
// apply phase, then finishEdit.
func editFinish(cmd *cobra.Command, stdout io.Writer, log *slog.Logger, f *editFlags, ep editPlan, aff apply.AffectedSet,
	h followUp, ropts apply.RenderOptions, doc editDoc) func(workflow.Outcome, *fleetSession) error {
	return func(out workflow.Outcome, sess *fleetSession) error {
		rep, err := sweepAfter(cmd.Context(), f, ep, out, sess)
		if err != nil {
			return err
		}
		return finishEdit(stdout, log, ep, aff, h, out, ropts, doc, rep)
	}
}
```

  (Match `ropts`'s and `doc`'s actual names and types in `runEdit`.)

- Add:

```go
// sweepAfter runs the opt-in post-revoke sweep after a confirmed apply
// phase; nil when --sweep is off, the run was not confirmed, or it added no
// key tombstone.
func sweepAfter(ctx context.Context, f *editFlags, ep editPlan, out workflow.Outcome, sess *fleetSession) (*apply.SweepReport, error) {
	tombs := keyTombstones(ep.summary.Revoked)
	if !f.sweep || out.Stage != workflow.StageConfirmed || len(tombs) == 0 {
		return nil, nil
	}
	rep, err := runSweep(ctx, sess, ep.edited, sweepTargets(ep.edited, out.Plans), tombs)
	if err != nil {
		return nil, err
	}
	return &rep, nil
}

// sweepSaved is sweepAfter for the save-only path (no server affected,
// e.g. D1b): it opens the run's session itself and sweeps every server.
// --no-apply never sweeps (it contacts no server by contract).
func sweepSaved(ctx context.Context, log *slog.Logger, f *editFlags, ids identities, ep editPlan) (*apply.SweepReport, error) {
	tombs := keyTombstones(ep.summary.Revoked)
	if !f.sweep || f.noApply || len(tombs) == 0 || len(ep.edited.Servers) == 0 {
		return nil, nil
	}
	sess, err := openFleet(ctx, log, &f.run.connFlags, ids, false)
	if err != nil {
		return nil, err
	}
	rep, err := runSweep(ctx, sess, ep.edited, ep.edited.Servers, tombs)
	if err != nil {
		return nil, err
	}
	return &rep, nil
}

// exitFor maps a run's exit code to run()'s sentinels: 2 critical (the
// sweep found a revoked key), 1 not converged, 0 nil.
func exitFor(code int) error {
	switch code {
	case 2:
		return errCriticalDrift
	case 1:
		return errNonCompliant
	}
	return nil
}
```

- `saveOnly`, after `saveEdit`:

```go
	rep, err := sweepSaved(cmd.Context(), log, f, ids, ep)
	if err != nil {
		return err
	}
	if doc != nil {
		if err := doc(nil, true, rep); err != nil {
			return err
		}
		return exitFor(rep.ExitCode())
	}
	noApplyNote(stdout, f, ep, aff, h, rep == nil)
	if rep != nil {
		renderSweep(stdout, *rep, ep.edited, h, len(ep.edited.Servers))
	}
	if ep.overlap != nil {
		fmt.Fprint(stdout, overlapHint(*ep.overlap, h, len(aff.Servers), f.noApply, 0))
	}
	return exitFor(rep.ExitCode())
```

  and its dry-run branch calls `doc(nil, false, nil)`.
- `noApplyNote` gains a `check bool` parameter and prints `printCheck` only `if ep.removesKey && check`.
- `finishDoc(doc editDoc, out workflow.Outcome, rep *apply.SweepReport) error` renders `doc(out.Plans, out.Saved, rep)` and returns `exitFor(max(out.ExitCode(), rep.ExitCode()))`; update its doc comment: "a document is written exactly when the run exits 0, 1 or 2".
- `finishEdit(stdout, log, ep, aff, h, out, ropts, doc, rep)`: `if doc != nil { return finishDoc(doc, out, rep) }`; Task 34's `finishTail(stdout, h, ep, out)` call becomes `finishTail(stdout, h, ep, out, rep)`, and the final check returns `exitFor(max(apply.ExitCode(plans), rep.ExitCode()))`. `finishTail` becomes

```go
// finishTail prints the follow-up after the apply phase's summary: the
// sweep's report when one ran, else the check line for a run that removed
// a key, once it planned or wrote.
func finishTail(stdout io.Writer, h followUp, ep editPlan, out workflow.Outcome, rep *apply.SweepReport) {
	switch {
	case rep != nil:
		renderSweep(stdout, *rep, ep.edited, h, len(ep.edited.Servers))
	case ep.removesKey && (out.Stage == workflow.StageConfirmed || out.Stage == workflow.StagePlanned):
		printCheck(stdout, h)
	}
}
```

`apply.go`: `applySpec.finish` becomes `finish func(out workflow.Outcome, sess *fleetSession) error`; `runWorkflow` ends `return s.finish(out, pre.fleetSession)`; `plainApply.finish` (Task 35) takes `(out workflow.Outcome, _ *fleetSession)` and calls `finishDoc(func(plans []apply.ServerPlan, _ bool, _ *apply.SweepReport) error { … }, out, nil)`.

- [ ] **Step 4: Run** — `GOTOOLCHAIN=go1.27.3 go test -race ./cmd/sshepherd/` → `ok`; `golangci-lint run --enable-only=gocyclo ./cmd/sshepherd/` → clean (`runEdit`, `finishEdit`, `saveOnly`, `newApplyCmd` all ≤ 15; if `saveOnly` crosses it, move its sweep tail into a helper the way `finishTail` does).

### Task 40: the write footer gains exit 2; help goldens; the README exit-code table

**Files:**
- Modify: `cmd/sshepherd/run.go` (`exitCodesWrite`); goldens `cmd/sshepherd/testdata/help/{apply,revoke,rotate}.golden`

- [ ] **Step 1: The footer**

```go
const exitCodesWrite = `Exit codes:
  0  converged: nothing left to do (a header-only update applied, or a server
     a newer manifest wrote whose keys already match); a revoke whose targets
     were already revoked; or, with revoke/rotate --no-apply, the edit is
     saved but not pushed (run the apply hint it prints)
  1  pending changes, unreachable or refused servers (a newer manifest's
     serial, a policy conflict), or a declined prompt; with --sweep, a server
     the sweep could not read
  2  revoke/rotate --sweep found a revoked key still installed
  3  tool error: bad flags, unloadable manifest, failed preflight, a manifest
     that would keep a policy conflict, a failed serial save, or refused
     before anything was saved or written`
```

- [ ] **Step 2: Goldens, README delta, gate**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run TestHelpGolden -update && git diff cmd/sshepherd/testdata/help/`
Expected: the three footers, and the `--sweep` row in `revoke.golden` and `rotate.golden`. Apply this lane's README delta, then `make check` → green.

- [ ] **Step 3: Capture the README samples (real output)**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestRevokeSweepDefaultFlags' -v`
Copy the `REVOKED KEY STILL INSTALLED: …` and `swept … servers: …` lines from the logged stdout verbatim (default flags: the hint is `run 'sshepherd apply --server web-2'`). The lines that carry no path — `cannot prove removal on web-3 (unreachable)`, `cannot prove removal on db-2 (authorized_keys2 unreadable)`, the sole-grantee `… — remove it by hand or grant another user there first` and `REVOKED KEY STILL INSTALLED (authorized_keys2): …` — are copied from the `want` literals of `TestRevokeSweepUnreachable`, Task 38's classification/text tests and `TestRevokeSweepFindsKeyInKeys2`.

- [ ] **Step 4: Hand back** (lane `sweep`; the integrator commits `feat(revoke): opt-in --sweep for revoked keys left on the fleet (P04 W4, SEC-2)`)

**docsDelta (lane `sweep`)** — each quoted output line is the Step 3 capture, not the shape below:
- README `### sshepherd revoke` and `### sshepherd rotate`: the `--sweep` flag row (from `--help`), and a **Post-revoke sweep** paragraph: "With `--sweep`, after the writes revoke reads every other server (the run's own known_hosts, keys and `--parallel`; also `~/.ssh/authorized_keys2` where the managed path is the default) and reports any that still holds a key this run revoked — captured: `REVOKED KEY STILL INSTALLED: bob SHA256:… on web-2 — run 'sshepherd apply --server web-2'`, or `… — remove it by hand or grant another user there first` on a server the manifest leaves empty — ending with the captured `swept N of M servers: K still have a revoked key, U unreachable` line. It only reads; it is skipped under `--dry-run` and `--no-apply`, which print the audit command instead. Exit 2 when a revoked key is found, 1 when a server could not be read or could not prove the removal (`cannot prove removal on db-2 (authorized_keys2 unreadable)`)." JSON `sweep` object (sample from `internal/apply/testdata/json_sweep.golden.json`); the revoke/rotate JSON contract now writes a document on exit 0, 1 or 2.
- README `## Exit codes`: rewrite the table from spec §8 (one shared table: rows 0–3 × audit / apply / revoke-rotate), drop "(code `2` is `audit`-only …)" and "`apply`, `revoke` and `rotate` never return `2`"; in row 3 replace "unknown user or key" with "unknown user (never revoked)" (D1b/D1c); `validate` will join the table with P10. Replace the `apply, revoke and rotate --help` block with this lane's `exitCodesWrite`.

---

## Round 4 — lane `e2e` (Tasks 41–42)

Owns: `cmd/sshepherd/e2e_test.go`, `scripts/integration.sh`. Findings: PRD-1, PRD-2 (end to end). `needsIntegration: true`.

### Task 41: fixture users, the three E2E tests, and the failing-first proof

**Files:**
- Modify: `scripts/integration.sh` (`FIXTURE_A`, the three user loops at `:85`, `:93`, `:114`)
- Modify: `cmd/sshepherd/e2e_test.go` (append)

- [ ] **Step 1: Fixture users**

In `FIXTURE_A`: append ` nra nrb stala stalb handed` to the `mkuser` loop (`:85`) and to the `chown`/`chmod` loop (`:114`); append ` stala stalb handed` to the "agent key alone" `cp /seed/key.pub` loop (`:93`, and to the comment above it: "stala/stalb/handed: the agent key alone (revocation-memory E2E)"); and next to the `writer + e2e + fleet` drifted seeds (`:103-106`) add

```sh
    # nra/nrb: the agent key + the stale key — what TestE2ERevokeNoResurrect's
    # opening adopt discovers (revocation-memory E2E).
    cat /seed/key.pub /seed/stale.pub > /home/nra/.ssh/authorized_keys
    cat /seed/key.pub /seed/stale.pub > /home/nrb/.ssh/authorized_keys
```

- [ ] **Step 2: Write the tests** (append to `cmd/sshepherd/e2e_test.go`; add `"github.com/javadh75/SSHepherd/internal/authkeys"` to its imports. `closedPort` is `adopt_test.go`'s helper — same package, compiled with the `integration` tag too — and gives an "unreachable during revoke" server without stopping a container. Every API these tests call exists at `7586255`, so the file compiles on the pre-W4 tree for Step 3.)

```go
// replaceLast replaces the last occurrence of old in s (the adopted
// manifest lists nr-a before nr-b, and both share the container's port).
func replaceLast(t *testing.T, s, old, repl string) string {
	t.Helper()
	i := strings.LastIndex(s, old)
	if i < 0 {
		t.Fatalf("%q not found in:\n%s", old, s)
	}
	return s[:i] + repl + s[i+len(old):]
}

// TestE2ERevokeNoResurrect (PRD-1), the spec's flow: adopt → apply →
// revoke the adopted user while nr-b is unreachable → adopt --merge finds
// the key on nr-b and does not re-adopt it (the warning names it) → audit
// pages (exit 2) until apply --server removes it → audit is clean.
func TestE2ERevokeNoResurrect(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	stale := itPubLine(t, itKeys(t), "stale")
	staleKey, err := authkeys.ParseLine(stale)
	if err != nil || staleKey == nil {
		t.Fatalf("stale key: %v", err)
	}
	dir := t.TempDir()
	m0 := writeE2EManifest(t, dir, "nr0.yaml", `
users:
  - {name: op, operator: true, keys: ["`+pub+`"]}
servers:
  - {name: nr-a, host: `+host+`, port: `+port+`, user: nra}
  - {name: nr-b, host: `+host+`, port: `+port+`, user: nrb}
`)
	code, out, stderr := runBin(t, bin, "adopt", "--config", m0, "--known-hosts", kh)
	if code != 0 {
		t.Fatalf("adopt exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	adopted := writeE2EManifest(t, dir, "nr.yaml", out)
	cfg, err := config.Parse([]byte(out))
	if err != nil {
		t.Fatalf("adopted manifest does not load: %v\n%s", err, out)
	}
	owner, ok := cfg.OwnerOf(staleKey.Fingerprint)
	if !ok {
		t.Fatalf("adopt did not adopt the stale key:\n%s", out)
	}
	for _, a := range cfg.Access {
		if a.User == owner.Name && strings.Join(a.Servers, ",") != "nr-a,nr-b" {
			t.Errorf("%s granted %v, want [nr-a nr-b] by name (D5)", owner.Name, a.Servers)
		}
	}
	if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", adopted, "--known-hosts", kh); code != 0 {
		t.Fatalf("apply exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	closed := strconv.Itoa(closedPort(t))
	down := writeE2EManifest(t, dir, "nr-down.yaml", replaceLast(t, readFile(t, adopted), "port: "+port+"\n", "port: "+closed+"\n"))
	code, out, stderr = runBin(t, bin, "revoke", owner.Name, "--yes", "--config", down, "--known-hosts", kh)
	if code != 1 || !strings.Contains(out, "nr-a: applied · verified") {
		t.Fatalf("revoke exit = %d, want 1 with nr-a applied and nr-b unreachable (stderr: %s)\n%s", code, stderr, out)
	}
	back := writeE2EManifest(t, dir, "nr-back.yaml", replaceLast(t, readFile(t, down), "port: "+closed+"\n", "port: "+port+"\n"))
	code, out, stderr = runBin(t, bin, "adopt", "--merge", "--config", back, "--known-hosts", kh)
	blob := strings.Fields(stale)[1]
	if code != 0 || strings.Contains(out, blob) {
		t.Fatalf("adopt --merge exit = %d; the revoked key must not come back (stderr: %s)\n%s", code, stderr, out)
	}
	if want := "key " + staleKey.Fingerprint + " on nr-b is REVOKED ("; !strings.Contains(stderr, want) || !strings.Contains(stderr, ", "+owner.Name+") — not adopted") {
		t.Errorf("adopt stderr lacks the revoked-key warning naming the key:\n%s", stderr)
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", back, "--known-hosts", kh); code != 2 || !strings.Contains(out, "installed but REVOKED") {
		t.Fatalf("audit exit = %d, want 2 with the REVOKED row (stderr: %s)\n%s", code, stderr, out)
	}
	if code, out, stderr := runBin(t, bin, "apply", "--server", "nr-b", "--yes", "--config", back, "--known-hosts", kh); code != 0 {
		t.Fatalf("apply --server nr-b exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", back, "--known-hosts", kh); code != 0 {
		t.Fatalf("final audit exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}
}

// TestE2EStaleManifestRefused (PRD-2): a copy of the manifest taken before
// a revoke cannot re-grant on ANY affected server — including stalb, where
// alice's key was already missing and the revoke wrote only the header.
func TestE2EStaleManifestRefused(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	stale := itPubLine(t, itKeys(t), "stale")
	dir := t.TempDir()
	srv := "servers:\n  - {name: stala, host: " + host + ", port: " + port + ", user: stala}\n" +
		"  - {name: stalb, host: " + host + ", port: " + port + ", user: stalb}\n"
	users := "users:\n  - {name: op, operator: true, keys: [\"" + pub + "\"]}\n  - {name: alice, keys: [\"" + stale + "\"]}\n"
	pre := writeE2EManifest(t, dir, "pre.yaml", users+srv+"access:\n  - {user: alice, servers: [stala]}\n")
	if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", pre, "--known-hosts", kh); code != 0 {
		t.Fatalf("seed apply exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	m := writeE2EManifest(t, dir, "m.yaml", users+srv+"access:\n  - {user: alice, servers: [stala, stalb]}\n")
	old := writeE2EManifest(t, dir, "old.yaml", readFile(t, m))
	code, out, stderr := runBin(t, bin, "revoke", "alice", "--yes", "--config", m, "--known-hosts", kh)
	if code != 0 || !strings.Contains(out, "update header: no serial → 1 (keys unchanged)") || !strings.Contains(out, "stalb: applied · verified") {
		t.Fatalf("revoke exit = %d, want 0 with stalb's header-only write (stderr: %s)\n%s", code, stderr, out)
	}
	before := map[string]string{"stala": e2eRemoteCat(t, host, port, kh, "stala"), "stalb": e2eRemoteCat(t, host, port, kh, "stalb")}
	code, out, stderr = runBin(t, bin, "apply", "--yes", "--config", old, "--known-hosts", kh)
	if code != 1 {
		t.Fatalf("stale apply exit = %d, want 1 (stderr: %s)\n%s", code, stderr, out)
	}
	if n := strings.Count(out, "written by manifest serial 1, this manifest is 0"); n != 2 {
		t.Errorf("serial refusals = %d, want 2 (every affected server):\n%s", n, out)
	}
	for user, b := range before {
		if got := e2eRemoteCat(t, host, port, kh, user); got != b {
			t.Errorf("%s changed under a stale apply:\n%s", user, got)
		}
	}
}

// TestE2EStaleManifestAfterHandEdit (D4b): removing alice by hand and
// applying bumps serial: and writes it; the pre-edit copy is then refused.
func TestE2EStaleManifestAfterHandEdit(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	stale := itPubLine(t, itKeys(t), "stale")
	dir := t.TempDir()
	srv := "servers:\n  - {name: handed, host: " + host + ", port: " + port + ", user: handed}\n"
	op := "users:\n  - {name: op, operator: true, keys: [\"" + pub + "\"]}\n"
	m := writeE2EManifest(t, dir, "m.yaml", op+"  - {name: alice, keys: [\""+stale+"\"]}\n"+srv+"access:\n  - {user: alice, servers: [handed]}\n")
	if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("seed apply exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	old := writeE2EManifest(t, dir, "old.yaml", readFile(t, m))
	if err := os.WriteFile(m, []byte(op+srv), 0o600); err != nil { // the hand edit: alice gone
		t.Fatal(err)
	}
	code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", m, "--known-hosts", kh)
	if code != 0 || !strings.Contains(out, "manifest serial: 0 → 1 (saved; this apply removes keys)") {
		t.Fatalf("hand-edit apply exit = %d, want 0 with the serial bump (stderr: %s)\n%s", code, stderr, out)
	}
	if !strings.HasPrefix(readFile(t, m), "serial: 1\n") {
		t.Errorf("manifest not bumped:\n%s", readFile(t, m))
	}
	before := e2eRemoteCat(t, host, port, kh, "handed")
	if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", old, "--known-hosts", kh); code != 1 ||
		!strings.Contains(out, "written by manifest serial 1, this manifest is 0") {
		t.Fatalf("stale apply exit = %d, want 1 with the serial refusal (stderr: %s)\n%s", code, stderr, out)
	}
	if got := e2eRemoteCat(t, host, port, kh, "handed"); got != before {
		t.Errorf("handed changed under a stale apply:\n%s", got)
	}
}
```

- [ ] **Step 3: Prove they fail before W4** (scratch worktree; under the runner's integration lock)

```sh
git worktree add --detach "$PATCH_DIR/w4-e2e-before" 7586255
cp cmd/sshepherd/e2e_test.go "$PATCH_DIR/w4-e2e-before/cmd/sshepherd/e2e_test.go"
cp scripts/integration.sh "$PATCH_DIR/w4-e2e-before/scripts/integration.sh"
(cd "$PATCH_DIR/w4-e2e-before" && make integration IT_DISTRO=alpine) > "$PATCH_DIR/w4-e2e-before.log" 2>&1
grep -E -- '--- (FAIL|PASS): TestE2E(RevokeNoResurrect|StaleManifest)' "$PATCH_DIR/w4-e2e-before.log"
grep -E -- 'adopt --merge exit = .*the revoked key must not come back' "$PATCH_DIR/w4-e2e-before.log"
grep -E -- 'revoke exit = .*with stalb.s header-only write' "$PATCH_DIR/w4-e2e-before.log"
grep -E -- 'hand-edit apply exit = .*with the serial bump' "$PATCH_DIR/w4-e2e-before.log"
git worktree remove --force "$PATCH_DIR/w4-e2e-before"
```

Expected — each test stops at its intended `t.Fatalf`, and each of the three content greps prints exactly one line:
- `--- FAIL: TestE2ERevokeNoResurrect`, at `adopt --merge exit = 0; the revoked key must not come back` — before W4 nothing remembers the revoke, so `adopt --merge` re-adopts the key from nr-b. (On that tree the opening adopt also writes `["*"]`, so the D5 `t.Errorf` fires first; it is not the proof.)
- `--- FAIL: TestE2EStaleManifestRefused`, at `revoke exit = 0, want 0 with stalb's header-only write` — before W4 the revoke writes no header-only update (no serials exist), so the test stops there; it never reaches the stale apply.
- `--- FAIL: TestE2EStaleManifestAfterHandEdit`, at `hand-edit apply exit = 0, want 0 with the serial bump` — before W4 apply never bumps.

A `--- FAIL` without its content line failed for some other reason (fixture, port, a load error) and proves nothing: fix the test, not the base. If the pre-W4 tree does not compile the new file, the tests did not run: fix the test file. Record the three `--- FAIL` lines and the three content lines in the hand-back `commands`.

- [ ] **Step 4: See them pass on the round-4 base**

Run (lock held): `make integration` (all three distros run in CI; locally `IT_DISTRO=alpine` then `IT_DISTRO=debian`).
Expected: `--- PASS` for the three new tests and every existing one.

### Task 42: hand back

- [ ] Run `make check`; hand back (lane `e2e`; the integrator commits `test(e2e): revocation memory end to end — no resurrection, stale copies refused (P04 W4, PRD-1, PRD-2)`).

**docsDelta (lane `e2e`):** README `## Development`, integration paragraph: "the E2E loop adds `TestE2ERevokeNoResurrect` (adopt → apply → a revoke with one server unreachable → `adopt --merge` skips the revoked key → audit exit 2 → `apply --server` → audit 0), `TestE2EStaleManifestRefused` (an old copy refused on every affected server, including a header-only one) and `TestE2EStaleManifestAfterHandEdit` (D4b)". CLAUDE.md Testing bullet "End-to-end (E2E)": the same three names.

---
## Integrator: docs, Status and spec amendments (not a lane)

The integrator applies each lane's `docsDelta` in the lane's commit (samples re-copied from the regenerated goldens, never hand-written), and in the **last** commit of the wave (after lane `e2e`) also:

- **README `## Status`**: add a W4 sentence: "Revocation memory: `revoked:` tombstones and a manifest `serial:`; revoke/rotate record and bump them, apply refuses a server written by a newer manifest unless the write only removes keys, audit pages on a revoked key still installed, adopt and `import --merge` never bring one back, `revoke --sweep` checks the rest of the fleet."
- **README `## Safety model`**: a **Manifest authority** paragraph — serial header, newer-serial refusal (removal-only writes never blocked), forged headers rewritten, header-only writes in a revoke's affected set, D4b, and the **Known limitations** list of spec §"Known limitations" verbatim in substance (header-only writes only in the bumping run; a hand edit bumps only via D4b; two branches at one serial; the sweep reads `authorized_keys2` only on the default path; deleting a `revoked:` entry is a deliberate un-revoke; a removed server's access entry is ignored with a warning).
- **README `## The manifest`**: new `### Serial` after `### Comment policy`: what bumps it (revoke, rotate, D4b apply), that the header carries it, the refusal and its only override (`serial: S` by hand), and the limitations above.
- **README `### Design docs`** (README l.1910-1912): **replace** the sentence "Revocation memory (tombstones, a manifest serial, an opt-in post-revoke sweep, no adopt wildcard) is designed and approved, not yet built: [spec link]" with a plain entry in the list's own style: "revocation memory (tombstones, the manifest serial, the post-revoke sweep) in [`docs/superpowers/specs/2026-11-08-revocation-memory-design.md`](docs/superpowers/specs/2026-11-08-revocation-memory-design.md)." Nothing in the README may still say it is not built.
- **README `### Layout`** (CLAUDE.md: repo layout is a README duty): `internal/authkeys/` → "authorized_keys parser and renderer, managed header grammar (Header/ParseHeader, serial), option semantics, key offer order (OfferOrder/OfferRank)"; `internal/manifest/` → "comment-preserving manifest edits (append, remove, replace, operator flag, tombstones via AddTombstones, serial bump via BumpSerial)"; `internal/apply/` → "plan computation (serial rows, D4b bump, sweep report), self-lockout guard, phase-2 fan-out behind the Writer seam, plan/JSON reports — no transport imports"; `internal/config/` → "manifest load + strict validation, access resolution, revocation memory (revoked:, serial:, policy conflicts)".
- **CLAUDE.md `## Status`**: **replace** the sentence at CLAUDE.md l.502-505 ("Revocation memory (tombstones, manifest serial, opt-in post-revoke sweep, no adopt wildcard) is specced and approved (owner answers recorded 2026-11-08), not yet built, in `docs/superpowers/specs/2026-11-08-revocation-memory-design.md` (review remediation P04, PRD-1/PRD-2/SEC-2/SEC-3; implementation in W4).") — do not append next to it — with this paragraph, in the same place: "**Revocation memory (W4, P04-impl)** (specced in `docs/superpowers/specs/2026-11-08-revocation-memory-design.md`, planned in `docs/superpowers/plans/2026-11-08-revocation-memory.md`): the manifest gains `revoked:` (key and access tombstones; shape errors load-fail, an unknown server in an access entry is a D1e warning, policy conflicts — a revoked key still listed, a grant over an access tombstone — load and are reported: audit exit 2, apply refuses those servers, saving commands exit 3) and `serial:`; the managed header carries `(serial N)` (`authkeys.Header`/`ParseHeader`, `.orig` decided by `Snapshot.Managed`); apply plans by the §3 table (newer serial refused unless removal-only, which keeps S; equal-body newer converged with a note; forged > M+1000 rewritten; header-only writes on a revoke/rotate's affected servers — the PRD-2 fix); revoke/rotate write tombstones, bump the serial, take `--reason` and opt-in `--sweep` (exit 2 on a revoked key still installed), `revoke --key` of an unowned key records it (D1b), a repeated revoke exits 0 (D1c); a confirmed apply that removes keys bumps the serial (D4b); audit adds REVOKED (critical), access-revoked (drift), serial-ahead (drift), forged-header and policy-conflict (critical) classes and JSON fields; adopt never writes `["*"]` and, like `import --merge`, skips tombstoned keys and access. Exit 2 now also means revoke/rotate `--sweep` found a revoked key (one shared table, D28)." Also update the Testing bullet "End-to-end (E2E)" with the three new tests (lane `e2e`'s delta) and the fuzz count (20 `Fuzz*` targets).
- **Spec Status** (`2026-11-08-revocation-memory-design.md` header): `**Status:** Implemented (W4, commits <the seven lane SHAs: schema, header, apply, audit, writecmds, sweep, e2e>)`.
- **Spec amendments** the spec lists under "Amendments to earlier specs": apply them now, one sentence each with a link back — `2026-07-19-apply-slice-design.md` "Managed header" row; `2026-10-23-revoke-rotate-design.md` decision 5 and the save note; `2026-07-10-adopt-fleet-discovery-design.md` "Access" (no wildcard; revoked keys skipped); `2026-07-16-adopt-merge-design.md` (merge honours tombstones; regenerate round-trips `serial`/`revoked`).
- **Master plan** (`2026-11-07-review-remediation.md`): mark the W4 row done and add `internal/apply/serial.go`, `serialbump.go`, `sweep.go`, `cmd/sshepherd/sweep.go`, `conflicts.go` to the hot-files table for P08-impl (which also edits `editrun.go`/`apply.go`).

## Acceptance (whole wave)

- `make check` and `make integration` green after every round (the integrator runs both per round; CI runs the alpine/debian/rocky matrix).
- `make fuzz-list | grep -q FuzzParseHeader` and `make fuzz` (every target, 15 s each) green.
- `GOTOOLCHAIN=go1.27.3 go test -race -tags integration -run 'TestE2ERevokeNoResurrect|TestE2EStaleManifestRefused|TestE2EStaleManifestAfterHandEdit' ./cmd/sshepherd` passes under `scripts/integration.sh`, and lane `e2e`'s log shows all three FAIL at `7586255`, each on its intended `t.Fatalf` line (Task 41 Step 3).
- README `--help` tables and exit-code footers match (`TestHelpMatchesREADMETables`, `TestHelpExamplesAndExitCodes`); README samples are copies of the new goldens or of captured runs (Task 36 Step 5, Task 40 Step 3); `grep -n 'not yet built' README.md CLAUDE.md` finds nothing about revocation memory.
- No on-hold item appears: no `prune`, no `apply --force` or serial override flag, no wipe/empty-server mode, no key generation, `move-key` or `import --prefer`. The sweep only reads; D1b writes no server.

## Self-review (spec coverage → task)

| Spec item | Task(s) |
|---|---|
| §1 schema, placement (serial first, revoked last), accessors | 1, 3, 4, 6, 28 |
| §2 shape errors (verbatim table, nothing added: plan decision 3), D1e warnings, policy conflicts (`Servers` = the whole grant), per-command treatment, no `--json` document on a refused save | 1 (null serial), 2, 3, 4, 9 (adopt/import), 18 (apply), 24–25 (audit), 29, 33 (revoke/rotate, `TestEditJSONToolErrorsLeaveStdoutEmpty` rows); `validate` is P10 |
| §3 `Render`/`ParseHeader`, body, scope, normalize, `.orig` (one `ManagedSnapshot`, parity over the table and the corpus), rows 1–8, removal-only, header-only, bump scope, report, JSON | 10–13, 15, 16–21 |
| §4 revoke/rotate memory, serial bump, `--reason`, clock, D1b, D1c (incl. several users), save notes (the `--no-apply` note only under `--no-apply`), conflicts | 29–34, 36 |
| §5 adopt, regenerate round trip, never the header serial, reconcile (`.pub` path), audit classification/text/JSON (incl. the unlabelled row, sanitized values), D5 | 7–9, 23–26 |
| §6 D4b (save point, text, dry-run, piped — `TestApplySerialBumpPipedConfig` from the command line, JSON, failed save exit 3 and no document — `TestApplySerialSaveFailsExit3`) | 35, 21 (`serial_bump` golden) |
| §7 sweep (targets, keys2 — hermetic and real sshd, output, exit precedence, skipped modes) | 14 (reader), 15 (`make integration`), 37–39 |
| §8 exit codes, one table | 9, 27, 36, 40 + README |
| §9 JSON (audit, apply/revoke/rotate; adopt/import stay stderr until their JSON slice; validate is P10) | 21, 26, 37 |
| Testing list (every named test) | as named in the tasks; `TestRevokeKeyResolvesConflict` is its own top-level test (Task 29); `TestBumpSerialCreatesFirstKey` has its golden (Task 28); JSON goldens for `serial_bump`/`policy_conflicts`/`manifest_warnings` in `json_memory_top.golden.json` (Task 21) |
| E2E (failing first, each on its intended assertion; `TestE2ERevokeNoResurrect` starts with `adopt`) + integration `.orig` and keys2 cases | 41, 15, 14 |

## Open risks

1. **Lane `writecmds` (round 3) is the critical path**: nine tasks, the most cmd edits, and the round that turns serials on — the first `make integration` where servers carry `(serial N)`. Task 36 lists every existing assertion found at `7586255` (grep `scope:`, `re-grants the removed`, `ManagedHeader`, unowned `--key`); a missed one shows up as a red test in that lane, fix it there.
2. **deadcode-driven slicing**: the rounds assume `deadcode` reports any function not reachable from `main` at each commit. If a lane moves a consumer to a later round, its API becomes dead and `make check` fails — keep producers and their first callers together as planned.
3. **gocyclo 15** (production code only; function literals count toward their enclosing function): measured at `7586255`, `renderChange` 14, `finishEdit` 14, `runEdit` 13, `jsonServerFor` 13, `newApplyCmd` 12. The plan routes every new branch of those into named helpers (`headerOnlyRow`/`serialWarning`/`summaryLine`, `serialFields`/`memoryKey`, `editPrelude`/`checkCommand`/`editFinish`, `finishTail`, `plainApply`); `planOne` was split (`planWrite`), `adopt.Build` gained helpers, `accessProblems` delegates to `classifyPairs`. `saveOnly` is the one unmeasured growth (round 4): Task 39 Step 4 runs gocyclo and says what to extract. Never `//nolint:gocyclo`.
4. **Coverage gate (93%)**: `saveSerialBump`'s Encode/BumpSerial-at-max/Save-failure branches and `runSweep`'s interrupted branch are the least covered; add a store-failure seam test (`beforeSave`) if `make coverage` dips.
5. **YAML placement**: a document footer comment rides the last section, so `AddTombstones` puts `revoked:` after it (golden-pinned in Task 28); comments are preserved, not reordered back.
6. **D29 on adopt**: a conflicted manifest now makes plain `adopt` exit 3 too (the spec lists regenerate-mode adopt among saving commands); the error names every conflict and `revoke --key` fixes it.
7. **E2E timing**: `closedPort` binds and closes a local port; another process could grab it in between (then the "unreachable" server answers). Rare; rerun shows it.

## Review log

Three independent reviews of the draft were checked against the code at `7586255`, the spec and the master plan before anything was changed. Every finding was confirmed. Some were applied in an adapted form; none was rejected. Duplicates are merged (R1-2 = R2-1, R1-6 = R2-3, R1-7 = R2-2, R0-12 is a subset of R2-8).

| # | Finding | Verdict | Where / how |
|---|---|---|---|
| R0-1 | Conflict `Servers` narrowed to one server, which contradicts spec §2 | applied | Decision 4 rewritten. `accessConflicts` uses `entryServers` (the whole grant), and the test expects `[web-1 db-1]` / the whole fleet. Task 25's golden expects the conflict line on both servers. |
| R0-2 | Extra load error for odd tombstone server names (against D1e) | applied (adapted) | The load error and its row are dropped (decision 3). The first `NAME` is printed with `%q`. The second is printed raw for any valid server name, so the spec text stays verbatim, and `%q` otherwise. This is safer than quoting both, which would change the spec's wording for every normal name. A test row covers it, and JSON sanitizes it (R0-13). |
| R0-3 | No test for a failed D4b save or a refused save under `--json` | applied | `TestApplySerialSaveFailsExit3` (Task 35); two D29 rows in `TestEditJSONToolErrorsLeaveStdoutEmpty` (Task 33). |
| R0-4 | Piped `--config` not tested from the CLI; `dryRunBump` classified only `Stream` | applied | `TestApplySerialBumpPipedConfig` (new `apply_serial_pipe_test.go`, build tag of `pipeConfig`: text, `--dry-run`, `--json`). `serialEditable` is shared by `saveSerialBump` and `dryRunBump`; the anchored dry-run case is in `TestApplySerialSaveUnavailable`. |
| R0-5 | Parity test checks the wrong function on too few cases | applied (adapted) | One implementation, `authkeys.ManagedSnapshot` (decision 5), is used by apply and `sshwrite.SnapshotOf`. The parity test in authkeys iterates all 13 `parseHeaderCases` and every `FuzzParseHeader` corpus file. sshwrite pins its delegation. |
| R0-6 | No JSON goldens for `serial_bump` / `policy_conflicts` / `manifest_warnings` | applied | `json_memory_top.golden.json` holds the dry-run, saved and piped documents (Task 21). |
| R0-7 | `TestBumpSerialCreatesFirstKey` is not a golden | applied | `bump_serial_first.golden` (Task 28; the lane glob was added). |
| R0-8 | `TestRevokeKeyResolvesConflict` folded into another test | applied | Now a top-level test with a shared `conflictFleet`. It also asserts the one serial bump, so it fails first. |
| R0-9 | D1c with several users untested | applied (adapted) | A subtest of `TestRevokeAlreadyRevokedExits0` uses a three-user fleet and runs `revoke bob carol` after bob is revoked. alice stays live because she holds the agent key and the guard would refuse. It asserts bob's note, carol's tombstone, serial 2 (one bump) and exit 0. |
| R0-10 | E2E starts with `apply`, not `adopt` | applied (adapted) | `nra`/`nrb` are seeded with the agent key plus the stale key, and the test opens with `adopt`. It revokes the adopted user, whose name comes from the stale key's comment and so is not `alice`, found via `OwnerOf`. It also checks D5 (granted by name). |
| R0-11 | README sections missed | applied | (a) README l.969-971 replaced. (b) Rotate l.1250-1251 replaced. (c) D1e bullet added under Validation rules. (d) The save refusal added to revoke and rotate. |
| R0-12 | CLAUDE.md "awaiting/not yet built" sentence kept next to the new paragraph | applied | The integrator replaces CLAUDE.md l.502-505 (see R2-8). |
| R0-13 | JSON values not sanitized | applied | `cleanMemory` (apply) and `memoryJSON` / `memoryKey` (audit) sanitize conflicts, warnings and tombstone `user`/`reason`. A test asserts that no ESC byte reaches the document. |
| R0-14 | `IDENTITY` printed the private-key path | applied (adapted) | `pubPath(Source)`: `Source` when it already ends in `.pub`, else `Source + ".pub"`, matching `pubPaths`. A blind `+ ".pub"` would print `id.pub.pub`. |
| R0-15 | Unlabelled `(REVOKED DATE)` row untested | applied | Key 8 is in the text golden (regexp on the row) and in the JSON golden (`revoked` without `user`). `revoked_keys` becomes 2. |
| R0-16 | `--no-apply` note used for any run with no affected servers | applied (option b) | `saveEdit(…, f.noApply)` follows spec §4 literally; D1b gets the default note. |
| R0-17 | No test that adopt ignores a server's header serial | applied | `TestAdoptNeverCopiesHeaderSerial` (Task 9). It is a regression pin with a named mutation, and uses the literal header because lane `header` runs in the same round. |
| R1-1 | yaml.v3 skips Unmarshalers for null, so `serial: null` loads as 0 | applied | `rejectNullSerial` in `config.Parse` (decision 15); `""` and `~` rows added. Confirmed at decode.go:406-409. |
| R1-2 / R2-1 | `apply.Build` dead after Task 16 | applied | `Build` deleted; the two `plan_test.go` callers and the zero-options test now use `BuildWith`; `deadcode` runs in Task 16 Step 4. |
| R1-3 | gocyclo over 15 in five functions | applied | Values confirmed at `7586255` (14/13/13/14/12). New helpers: `headerOnlyRow`/`serialWarning`/`summaryLine`, `serialFields`/`memoryKey`, `editPrelude`/`checkCommand`/`editFinish`, `finishTail`, and `plainApply` methods. Each task runs `golangci-lint --enable-only=gocyclo`. |
| R1-4 | `err != errNoSerialSave` fails errorlint in tests | applied | `errors.Is`; a convention line was added. |
| R1-5 | Unused or missing test imports | applied | `memory_test.go` imports grow per task (29 → 30 → 33); `authkeys` added to `adopt_test.go` and `reflect` to `cmd/sshepherd/adopt_test.go`. |
| R1-6 / R2-3 | "Task 37" should be "Task 36" | applied | Both places. |
| R1-7 / R2-2 | Base commit stale | applied | `7586255` in the header, rounds table, Task 41 worktree, Acceptance and risks. |
| R1-8 | Wrong `adopt_test.go` comment lines | applied | `:138` and `:143` edited; `:134` (bob's real wildcard) kept. |
| R2-4 | Row tests written after the code | applied | Task 17's eight tests are written in Task 16 Step 1, and Task 17 has a per-test mutation table. Task 19 and Task 22 get mutations; the pins are labelled. |
| R2-5 | `-update` in Step 2 of Tasks 20, 25, 26 | applied | Removed; the missing golden is the expected failure. |
| R2-6 | Wrong expected pre-W4 failures; proof greps only `--- FAIL` | applied | Expectations corrected; each test's intended `t.Fatalf` line is grepped and recorded. |
| R2-7 | "five lane SHAs" | applied | Now seven, with the lanes named. |
| R2-8 | Stale "not yet built" sentences; `### Layout` not scheduled | applied | README Design docs and CLAUDE.md sentences replaced; Layout rows for authkeys, manifest, apply and config. |
| R2-9 | Hand-written sample output | applied | New convention. Task 36 Step 5 captures from the binary with default flags (no server contacted). Task 40 Step 3 captures from the new `TestRevokeSweepDefaultFlags` log. The docsDelta text now names captures, not paraphrases. |
| R2-10 | `authorized_keys2` read never tested on a real sshd | applied | `TestIntegrationReadKeys2Content` (user `absent`, `SSHEPHERD_IT_PUB`) in Task 14, run by lane `header`'s `make integration`. |

## Wave lanes (for the runner)

Rounds run in sequence; lanes inside a round own disjoint files and build only on the previous rounds' commits. Globs are shell `case` patterns (`*` crosses `/`). `README.md` and `CLAUDE.md` belong to no lane: each lane hands its README/CLAUDE.md text over as `docsDelta` (and applies it locally only to pass `make check`). The integrator commits once per lane, in the order the rounds list them.

```json
{
  "rounds": [
    [
      {
        "pkg": "P04",
        "lane": "schema",
        "kind": "fix",
        "ids": ["PRD-1", "SEC-3"],
        "tasks": "Tasks 1-9",
        "files": [
          "internal/config/*",
          "internal/manifest/manifest.go",
          "internal/manifest/manifest_test.go",
          "internal/manifest/testdata/generate_memory.golden",
          "internal/adopt/*",
          "internal/reconcile/*",
          "cmd/sshepherd/conflicts.go",
          "cmd/sshepherd/conflicts_test.go",
          "cmd/sshepherd/adopt.go",
          "cmd/sshepherd/adopt_test.go",
          "cmd/sshepherd/import.go",
          "cmd/sshepherd/import_merge_test.go",
          "cmd/sshepherd/schema_roundtrip_test.go",
          "cmd/sshepherd/run.go",
          "cmd/sshepherd/testdata/adopt_*.golden",
          "cmd/sshepherd/testdata/help/adopt.golden",
          "cmd/sshepherd/testdata/help/import.golden"
        ],
        "needsIntegration": false
      },
      {
        "pkg": "P04",
        "lane": "header",
        "kind": "fix",
        "ids": ["PRD-2"],
        "tasks": "Tasks 10-15",
        "files": [
          "internal/authkeys/header.go",
          "internal/authkeys/header_test.go",
          "internal/authkeys/render.go",
          "internal/authkeys/render_test.go",
          "internal/authkeys/fuzz_test.go",
          "internal/authkeys/testdata/fuzz/FuzzParseHeader/*",
          "internal/fleet/*",
          "internal/sshwrite/*",
          "internal/sshread/*",
          "internal/apply/plan.go",
          "internal/apply/plan_test.go"
        ],
        "needsIntegration": true
      }
    ],
    [
      {
        "pkg": "P04",
        "lane": "apply",
        "kind": "fix",
        "ids": ["PRD-2", "PRD-1"],
        "tasks": "Tasks 16-22",
        "files": [
          "internal/apply/*",
          "internal/workflow/*"
        ],
        "needsIntegration": true
      },
      {
        "pkg": "P04",
        "lane": "audit",
        "kind": "fix",
        "ids": ["PRD-1", "PRD-2"],
        "tasks": "Tasks 23-27",
        "files": [
          "internal/audit/*",
          "cmd/sshepherd/audit.go",
          "cmd/sshepherd/audit_test.go",
          "cmd/sshepherd/audit_hermetic_test.go",
          "cmd/sshepherd/run.go",
          "cmd/sshepherd/testdata/help/audit.golden"
        ],
        "needsIntegration": false
      }
    ],
    [
      {
        "pkg": "P04",
        "lane": "writecmds",
        "kind": "fix",
        "ids": ["PRD-1", "PRD-2", "SEC-2"],
        "tasks": "Tasks 28-36",
        "files": [
          "internal/manifest/edit.go",
          "internal/manifest/edit_test.go",
          "internal/manifest/fuzz_edit_test.go",
          "internal/manifest/testdata/edit_memory.golden",
          "internal/manifest/testdata/bump_serial_first.golden",
          "internal/manifest/testdata/fuzz/FuzzManifestEdit/*",
          "internal/apply/serialbump.go",
          "internal/apply/serialbump_test.go",
          "cmd/sshepherd/revoke*.go",
          "cmd/sshepherd/rotate*.go",
          "cmd/sshepherd/editrun*.go",
          "cmd/sshepherd/edit.go",
          "cmd/sshepherd/edit_test.go",
          "cmd/sshepherd/apply.go",
          "cmd/sshepherd/apply_test.go",
          "cmd/sshepherd/apply_serial*_test.go",
          "cmd/sshepherd/json_cmd_test.go",
          "cmd/sshepherd/memory_test.go",
          "cmd/sshepherd/run.go",
          "cmd/sshepherd/e2e_test.go",
          "cmd/sshepherd/testdata/help/apply.golden",
          "cmd/sshepherd/testdata/help/revoke.golden",
          "cmd/sshepherd/testdata/help/rotate.golden"
        ],
        "needsIntegration": true
      }
    ],
    [
      {
        "pkg": "P04",
        "lane": "sweep",
        "kind": "fix",
        "ids": ["SEC-2"],
        "tasks": "Tasks 37-40",
        "files": [
          "internal/apply/sweep.go",
          "internal/apply/sweep_test.go",
          "internal/apply/json.go",
          "internal/apply/json_test.go",
          "internal/apply/testdata/json_sweep.golden.json",
          "cmd/sshepherd/sweep.go",
          "cmd/sshepherd/sweep_test.go",
          "cmd/sshepherd/editrun.go",
          "cmd/sshepherd/apply.go",
          "cmd/sshepherd/run.go",
          "cmd/sshepherd/testdata/help/apply.golden",
          "cmd/sshepherd/testdata/help/revoke.golden",
          "cmd/sshepherd/testdata/help/rotate.golden"
        ],
        "needsIntegration": false
      },
      {
        "pkg": "P04",
        "lane": "e2e",
        "kind": "fix",
        "ids": ["PRD-1", "PRD-2"],
        "tasks": "Tasks 41-42",
        "files": [
          "cmd/sshepherd/e2e_test.go",
          "scripts/integration.sh"
        ],
        "needsIntegration": true
      }
    ]
  ],
  "mergeOrder": ["P04"]
}
```

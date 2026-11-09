# Flag renames (P10 S2, D26, UX-7) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This plan is executed by the wave runner of `docs/superpowers/plans/2026-11-07-review-remediation.md` ("Reusable workflow skeleton"): lane agents work in git worktrees, never commit, and hand back ownership-filtered patches; the integrator commits once per lane. Where a task says "Hand back", that is the lane's last step, not a commit.

**Commit path of this plan:** `docs/superpowers/plans/2026-11-09-p10-s2-flag-renames.md`

**Goal:** Build slice S2 of the approved design (`docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`, section "S2. Flag renames (D26; UX-7)", finding UX-7): `import --operator` becomes `import --operator-key PATH`, `revoke --server` becomes `revoke --from-server NAME`, the `--identity-passphrase` varname becomes `PATH=FILE`, and the `--merge` help text is clarified on both commands. No release has shipped, so there are no aliases: the old names become unknown flags.

**Architecture:** A pure rename, plus the two help varnames the design's table names (`PATH`, `NAME`). No package gains or loses a symbol, no exit code changes (an unknown flag is exit 3, as every usage error already is, D28 untouched), no JSON field changes (schema stays 1), and `apply --server` and `audit --server` keep their name and meaning. Every message, hint, test, help golden and README mention of an old name moves in the lane that renames it, because no alias covers the gap.

**Tech Stack:** Go 1.27.3 (`GOTOOLCHAIN=go1.27.3`, the Makefile's `GO_PIN`), Cobra/pflag, golden files (`-update`), goleak, golangci-lint v2.15.0, `deadcode ./cmd/sshepherd`, the dockerized sshd matrix (`make integration`: lane `revoke`, the integrator after each round, and the verifier).

**Base:** `master` at `aff7bf0`, or that commit plus S1's commits (see "Overlap with S1"). Every `file:line` below was read at `aff7bf0`; the anchors are the quoted strings, so a shifted line number changes nothing. The landed code wins over the design wherever they differ; the differences found are recorded under "Design check".

---

## How this plan is cut (read first)

### Why the lanes look the way they do

1. **`cmd/sshepherd/testdata/help/adopt.golden` and `revoke.golden` are each changed by two renames.** `adopt.golden` carries the `--merge` help (lane `import`) and the `PATH=FILE` varname (lane `identity`); `revoke.golden` carries `--from-server` (lane `revoke`) and `PATH=FILE`. The design's lane row lists A, B and C as if they were parallel, but lanes in one round must own disjoint files, so `identity` (the design's lane C) runs in **round 2** on top of A and B.
2. **`TestHelpMatchesREADMETables` and `TestHelpShowsIdentityVarnames` read the flag names.** Each lane applies its own `docsDelta` to its worktree's `README.md` before `make check`, because the table test fails otherwise; the ownership filter drops that change from the patch. **The integrator must re-apply the lane's `docsDelta` after `git apply` and before `make check`**, or the integrator's own `make check` fails on the same test. The runner's integrator prompt runs `make check` before a package's docs unless told otherwise, so this is also the `handoffs` entry under "Wave lanes".
3. **`deadcode` is unaffected.** No function is added or removed outside `_test.go`.
4. **Lane `revoke` needs `make integration`.** `cmd/sshepherd/e2e_test.go:329` runs `revoke tmp --server trim-a` under the `integration` build tag; the unit run never executes it.

### Rounds

| Round | Lanes (disjoint files) | Builds on |
|---|---|---|
| 1 | `import` (design lane A) · `revoke` (design lane B) | the wave's base |
| 2 | `identity` (design lane C) | round 1 |

The integrator runs Task 10 lane by lane as it commits, and after round 2 an independent verifier runs Task 11. No lane owns either.

### Overlap with S1

S2 runs in the same wave as S1. S2 stays out of `validate.go`, `run.go`, `fleet.go`, `audit.go`, `apply.go`, `internal/audit/json.go`, `internal/apply/json.go`, `internal/config` and `cmd/sshepherd/usage_test.go`. These files are edited by both slices:

| File | S1 edits | S2 edits (lane) |
|---|---|---|
| `cmd/sshepherd/adopt.go` | the `readFleet` call at line 288 gains the `targets` argument ("adopt passes the whole fleet"; S1's Files list omits this file, see "Design check") | the `--merge` usage string at line 338 (`import`) |
| `cmd/sshepherd/testdata/help/audit.golden` | a new `--server` row | the `--identity-passphrase` row (`identity`) |
| `cmd/sshepherd/help_readme_test.go` | a `validate` row in `TestHelpMatchesREADMETables` | line 168 and the new assertion in `TestHelpShowsIdentityVarnames` (`identity`) |
| `README.md`, `CLAUDE.md` Status, the design's Status line | integrator text | integrator text |

Lanes in one round must own disjoint files, so when S1 and S2 are combined into one set of rounds: **no S1 lane owning `adopt.go` may share a round with lane `import`, and no S1 lane owning `audit.golden` or `help_readme_test.go` may share a round with lane `identity`.** The simple order is S1's rounds first, then S2's. By the design's description of S1, every S2 hunk sits on lines S1 does not touch, so S2 rebases on S1's result without conflict; `audit --server` needs no S2 change. S1's draft plan agrees: its round-1 lane `audit-server` owns `adopt.go` and `audit.golden`, its round-2 lane `validate` owns `help_readme_test.go`, and both slices edit the design's Status line (Task 10 Step 2 handles either order).

### Plan decisions (not in the spec; none changes an exit code, a refusal or a JSON field)

1. **The reconcile error reads `--operator-key SHA256:… belongs to manifest user "alice", …`.** A mechanical rename would give `--operator-key key SHA256:…`, which stutters. The value after the flag name is the fingerprint, so the word `key` goes.
2. **`--operator-key` and `--from-server` show `PATH` and `NAME` in `--help`.** The design's S2 table gives the After column as `import --operator-key PATH` and `revoke --from-server NAME`, lists "its usage text" under Mechanism, and says code-quoted wording is target text. Its Today column also says `--operator PATH`, which `--help` does not print today (`stringArray`), so `PATH` could be read as a placeholder; this plan takes the After column literally. The usage strings become ``key file `PATH` whose owner is an operator: …`` and ``remove the users' access to server `NAME` only …``, matching the sibling `--key KEY` and `--old KEY`, and `helpFlagCell` then requires the README cells `` `--operator-key PATH` `` and `` `--from-server NAME` ``. `apply --server` and S1's `audit --server` keep `stringArray`: D26 does not touch them.
3. **`revoke --help`'s `Long` line is not rewrapped.** The renamed line is 78 columns; rewrapping would churn the five lines below it for no reader benefit.
4. **`internal/identity` and three other comment-only homes move too** (`internal/manifest/edit_test.go`, `internal/adopt/adopt_test.go`, `scripts/integration.sh`). The design's lane row does not list them, but the rule is that every mention of an old name moves in the same lane. They are listed as exact paths, so no other lane is affected.
5. **The old-flag tests live beside each command's tests** (`TestImportOldOperatorFlagRemoved` in `import_test.go`, `TestRevokeOldServerFlagRemoved` in `revoke_server_test.go`), and `TestHelpShowsIdentityVarnames` gains a check that `KEY=FILE` is gone. Existing test function names (`TestRevokeServer*`, `TestImportOperator*`) stay: they are not user-facing, and renaming them would only churn history.
6. **Manifests generated before this slice keep `(--operator)` in their `description:`.** It is free text that nothing parses, and reconcile never rewrites an existing user's description.
7. **README's "`KEY is encrypted …`" becomes "`PATH is encrypted …`".** The placeholder stands for the key's path (`noSourceError` prints `c.path`), and the same line now says `PATH=FILE`.

### Design check (against the code at `aff7bf0`)

None of these changes what the design decides; the owner and the S1 planner should know them.

- **S1's Files list omits `adopt.go`,** but its text requires the edit (`readFleet` is called at `cmd/sshepherd/adopt.go:288`). That makes `adopt.go` shared between S1 and S2 lane A, which the design's lane rows do not show.
- **The `accessProblems` hint names no `--server`.** The design's table lists it among the strings to move, but `revoke.go:481` builds `sshepherd revoke NAME … --operator`, which stays valid. Only `accessProblems`' doc comment (line 450) changes.
- **`editrun.go` needs no edit.** The design's Files list and lane row B name it, but its only `--server` text is `applyHint` (lines 649-655), which the design keeps because it is `apply`'s flag. It is not in lane `revoke`'s globs. Every `followUp.command` call was checked: none builds `revoke … --server`, and `revoke.go:481` and `editrun.go:203` build only `--operator` and `--key`.
- **The design's README list is short by four places:** the Status table (line 64), "Operator users" (line 305), the "Exit codes" row `3` (line 2201, `an unknown or ungranted --server`) and the design-docs paragraph (line 2629). The `docsDelta` blocks cover them, because no alias covers the gap.
- **Lane C cannot run beside A and B** (`adopt.golden`, `revoke.golden`); see above.

### Conventions every lane follows

- Go runs under the pin: prefix every `go` command with `GOTOOLCHAIN=go1.27.3`. The rtk hook summarizes test output; use `rtk proxy go test …` when exact failure lines matter.
- A golden is rewritten only with `-update` and then read back line by line before it is accepted. **`-update` applies only to the tests `-run` selects:** `import_manifest_operators.golden` belongs to `TestGenerateManifestOperatorGolden`, which `-run TestImport` does not reach.
- **Mind `--servers-only`.** A plain `s/--server/…/` also rewrites `--servers-only` (`revoke_memory_import_test.go:63,76` run `import --servers-only`), which is why every pattern below is `--server(?![s-])`.
- **Before hand-back:** apply this lane's `docsDelta` to the worktree's `README.md` (gate only), run `GOTOOLCHAIN=go1.27.3 make check` (and `make integration` under the runner's lock when the lane says `needsIntegration`), then `git add -A`, unstage every path outside the lane's globs (README.md and CLAUDE.md always), and write the patch. `docsDelta` goes in the report as text.
- **Failing first.** Every test is run and seen failing (build failure or assertion) before the code it tests changes. Exception: a golden-only change (Task 3) is seen failing immediately after the code edit and before `-update`; the golden is the test.
- New test variables must not shadow builtins (revive).
- **`docsDelta`** blocks are integrator-only text for `README.md`, `CLAUDE.md` Status and spec Status. README has no sample output that any of these renames touches: `grep -n -e 'operator-key\|from-server\|PATH=FILE' README.md` after a lane's delta shows only command lines, table rows, prose and the one error string under Authentication, which matches `noSourceError` byte for byte after lane `identity`.

---

## File structure

| File | Round/lane | Responsibility |
|---|---|---|
| `cmd/sshepherd/import.go`, `import_test.go`, `import_merge_test.go`, `conflicts_test.go`, `testdata/import_manifest_operators.golden`, `testdata/help/import.golden` | 1 `import` | `--operator-key` flag, Long, example, conflict error, `(--operator-key)` description, `--merge` help |
| `cmd/sshepherd/adopt.go`, `testdata/help/adopt.golden` | 1 `import` | `--merge` help (S1 also edits `adopt.go`) |
| `internal/reconcile/reconcile.go`, `reconcile_test.go` | 1 `import` | the promotion error and `describe` |
| `internal/identity/identity.go`, `identity_test.go` | 1 `import` | comments only |
| `cmd/sshepherd/revoke.go`, `revoke_server_test.go`, `revoke_memory_import_test.go`, `revoke_test.go`, `memory_test.go`, `sweep_test.go`, `e2e_test.go`, `testdata/help/revoke.golden` | 1 `revoke` | `--from-server` flag, `Use`, `Long`, example, `revokeUsage` errors |
| `internal/apply/edit.go`, `edit_test.go`, `internal/manifest/edit_test.go`, `internal/adopt/adopt_test.go`, `scripts/integration.sh` | 1 `revoke` | comments only |
| `cmd/sshepherd/identity.go`, `identity_test.go`, `help_readme_test.go`, `testdata/help/{adopt,apply,audit,revoke,rotate}.golden` | 2 `identity` | the varname (S1 also edits `audit.golden` and `help_readme_test.go`) |
| `internal/keyfile/keyfile.go`, `resolve.go`, `load_test.go`, `resolve_test.go` | 2 `identity` | the two runtime strings |

---

## Round 1 — lane `import` (Tasks 1–4)

Owns: `cmd/sshepherd/import.go`, `import_test.go`, `import_merge_test.go`, `conflicts_test.go`, `adopt.go`, `testdata/import_manifest_operators.golden`, `testdata/help/import.golden`, `testdata/help/adopt.golden`, `internal/reconcile/*`, `internal/identity/*`. Finding: UX-7.

### Task 1: failing tests for `--operator-key`

**Files:** Modify `cmd/sshepherd/import_test.go`, `import_merge_test.go`, `conflicts_test.go`, `internal/reconcile/reconcile_test.go`, `internal/identity/identity_test.go`.

- [ ] **Step 1: Rename the flag in the existing tests.** From the repo root:

```bash
perl -pi -e 's/--operator\b(?!-)/--operator-key/g' \
  cmd/sshepherd/import_test.go cmd/sshepherd/import_merge_test.go \
  cmd/sshepherd/conflicts_test.go internal/reconcile/reconcile_test.go \
  internal/identity/identity_test.go
perl -pi -e 's/unknown --operator-key key is/unknown --operator-key is/' internal/reconcile/reconcile_test.go
```

`--operator` in these five files is always `import`'s flag (`import_test.go:95,119-120,389,406-407,415,427`, `import_merge_test.go:362,374,386,405`, `conflicts_test.go:89,97`, `reconcile_test.go:551,569,581,590`, `identity_test.go:41`). Do not run this over `revoke_*`, `rotate_*`, `e2e_test.go`, `json_cmd_test.go`, `identity_integration_test.go` or `editrun_test.go`: their `--operator` is the `revoke`/`rotate` bool, which stays.

- [ ] **Step 2: Pin the conflict message and the old flag.** In `cmd/sshepherd/import_test.go`, in `TestImportOperatorConflictsServersOnly`, replace the final check and add the new test after the function:

```go
	if want := "--operator-key conflicts with --servers-only (operators are users)"; !strings.Contains(errBuf.String(), want) {
		t.Errorf("stderr = %q, want %q", errBuf.String(), want)
	}
}

// TestImportOldOperatorFlagRemoved: D26 renamed --operator to --operator-key
// with no alias, so the old spelling is an unknown flag (exit 3), and a
// failed flag parse prints nothing on stdout.
func TestImportOldOperatorFlagRemoved(t *testing.T) {
	hermeticHome(t)
	cfg := writeSSHConfig(t, "Host a\n  User u\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", cfg, "--operator", "x"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "unknown flag: --operator") {
		t.Errorf("stderr = %q, want cobra's unknown-flag error", errBuf.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want nothing", out.String())
	}
}
```

(The block replaces the old `if !strings.Contains(errBuf.String(), "--servers-only") { … }` and the function's closing brace. Run Step 1 before this step: Step 1's pattern would rewrite the `"--operator"` this test passes on purpose.)

- [ ] **Step 3: Pin the promotion error.** In `internal/reconcile/reconcile_test.go`, `TestBuildOperatorPromotionError`:

```go
	for _, want := range []string{"--operator-key SHA256:", `"alice"`, "explicit manifest edit"} {
```

- [ ] **Step 4: Run and see them fail.**

Run: `GOTOOLCHAIN=go1.27.3 rtk proxy go test ./cmd/sshepherd ./internal/reconcile -run 'TestImportOperatorConflictsServersOnly|TestImportOldOperatorFlagRemoved|TestBuildOperator|TestGenerateManifestOperatorGolden'`

Expected: FAIL in `TestGenerateManifestOperatorGolden`, `TestImportOperatorConflictsServersOnly`, `TestImportOldOperatorFlagRemoved`, `TestBuildOperatorPromotionError` and `TestBuildOperatorUnknownAppended`.

**docsDelta:** none.

### Task 2: rename `--operator` to `--operator-key`

**Files:** Modify `cmd/sshepherd/import.go`, `internal/reconcile/reconcile.go`, `internal/identity/identity.go`; regenerate `testdata/help/import.golden`, `testdata/import_manifest_operators.golden`.

- [ ] **Step 1: Apply the rename.**

```bash
perl -pi -e 's/marks any --operator keys/marks any key named by --operator-key/; s/--operator-created/--operator-key-created/; s/--operator key %s/--operator-key %s/; s/--operator\b(?!-)/--operator-key/g' \
  cmd/sshepherd/import.go internal/reconcile/reconcile.go internal/identity/identity.go
perl -pi -e 's/"operator", nil,/"operator-key", nil,/; s/"key file whose owner is/"key file `PATH` whose owner is/' cmd/sshepherd/import.go
```

This covers `import.go:103` (comment), `:108` (`desc += " (--operator-key)"`), `:146` (comment), `:374` (`Long`), `:383` (`Example`), `:389` (the conflict error), `:453` (the flag name), `:454` (the `PATH` varname, plan decision 2); `reconcile.go:99,241,409` (comments), `:237` (the promotion error, plan decision 1), `:415` (`describe`); `identity.go:37,127,312` (comments).

Read the result: `git diff cmd/sshepherd/import.go internal/reconcile/reconcile.go internal/identity/identity.go`. `reconcile.go:237` must read `"--operator-key %s belongs to manifest user %q, who is not an operator — promotion must be an explicit manifest edit"`, `import.go:453` `cmd.Flags().StringArrayVar(&operators, "operator-key", nil,`, and `import.go:454` ``"key file `PATH` whose owner is an operator: granted every server and protected from removal (repeatable)")``.

- [ ] **Step 2: Regenerate and read the goldens.**

```bash
GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestHelpGolden|TestGenerateManifestOperatorGolden' -update
git diff cmd/sshepherd/testdata
```

Expected: `import_manifest_operators.golden` changes one line (`(--operator-key)`). `help/import.golden` changes the `Long` line, the example and the whole flag block: `--operator-key PATH` (19 columns) replaces `--operator stringArray` (22) as the longest flag, so cobra narrows every row of `import`'s Flags block by three columns. The `Global Flags` block and everything else stay.

- [ ] **Step 3: Run.**

Run: `GOTOOLCHAIN=go1.27.3 rtk proxy go test ./cmd/sshepherd ./internal/reconcile ./internal/identity`

Expected: PASS, except `TestHelpMatchesREADMETables`, which needs this lane's `docsDelta` (Task 4).

**docsDelta (README "Operator users", "`sshepherd import`"):** applied by Task 4's script (the `--operator` pairs).

### Task 3: clarify the `--merge` help (both commands keep the name)

**Files:** Modify `cmd/sshepherd/import.go:456`, `cmd/sshepherd/adopt.go:338`; regenerate `testdata/help/import.golden`, `testdata/help/adopt.golden`.

- [ ] **Step 1: Change the usage strings.**

In `cmd/sshepherd/import.go`:

```go
	cmd.Flags().StringVar(&mergePath, "merge", "",
		"merge into `FILE`: preserve its text and append what is new")
```

In `cmd/sshepherd/adopt.go`:

```go
	cmd.Flags().BoolVar(&merge, "merge", false, "merge into --config: preserve its text and append what is new")
```

- [ ] **Step 2: See the golden fail, regenerate, read.**

Run: `GOTOOLCHAIN=go1.27.3 rtk proxy go test ./cmd/sshepherd -run TestHelpGolden`
Expected: FAIL on `import` and `adopt`.

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run TestHelpGolden -update && git diff cmd/sshepherd/testdata/help/adopt.golden`
Expected: one changed line in `adopt.golden`, the `--merge` row.

**docsDelta (README "`sshepherd import`", "`sshepherd adopt`"):** applied by Task 4's script (the `--merge` pairs).

### Task 4: gate and hand back

- [ ] **Step 1: Apply this lane's README delta to the worktree (gate only).** This block is also the `docsDelta` text: each old string must match exactly once.

```bash
python3 - <<'PY'
p = 'README.md'
s = open(p, encoding='utf-8').read()
pairs = [
    ('`import --operator <key-file>` marks', '`import --operator-key <key-file>` marks'),
    ('| `--operator` | — | Key file', '| `--operator-key PATH` | — | Key file'),
    ('Merge into an existing manifest, preserving its comments', 'Merge into `FILE`: preserve its text and append what is new'),
    ('`--operator` naming a weak key', '`--operator-key` naming a weak key'),
    ('`--operator` paths support', '`--operator-key` paths support'),
    ('(an error for\n  `--operator`)', '(an error for\n  `--operator-key`)'),
    ('Append discoveries to the existing manifest, comments intact', 'Merge into `--config`: preserve its text and append what is new'),
]
for old, new in pairs:
    assert s.count(old) == 1, old
    s = s.replace(old, new)
open(p, 'w', encoding='utf-8').write(s)
PY
```

- [ ] **Step 2: Check no import mention is left.**

Run: `git grep -nE -e '"--operator"' -- cmd/sshepherd/import.go cmd/sshepherd/import_test.go cmd/sshepherd/import_merge_test.go cmd/sshepherd/conflicts_test.go`
Expected: one line, the argument in `TestImportOldOperatorFlagRemoved`.

Run: `git grep -nE -e '\(--operator\)' -- cmd internal README.md`
Expected: nothing.

- [ ] **Step 3: Run the gate.** `GOTOOLCHAIN=go1.27.3 make check` → PASS.

- [ ] **Step 4: Hand back.** `git add -A`, unstage `README.md` and any other path outside the lane's globs, write the patch, and report the Task 4 block as `docsDelta`.

---

## Round 1 — lane `revoke` (Tasks 5–7)

Owns: `cmd/sshepherd/revoke.go`, `revoke_server_test.go`, `revoke_memory_import_test.go`, `revoke_test.go`, `memory_test.go`, `sweep_test.go`, `e2e_test.go`, `testdata/help/revoke.golden`, `internal/apply/edit.go`, `internal/apply/edit_test.go`, `internal/manifest/edit_test.go`, `internal/adopt/adopt_test.go`, `scripts/integration.sh`. Finding: UX-7. **`make integration` required.**

`apply --server` and `audit --server` keep their name. So do the hints `applyHint` builds (`editrun.go:649-655`), which the existing assertions in `revoke_test.go:422,450,471,637,662`, `revoke_server_test.go:252`, `sweep_test.go:92,123,207`, `editrun_test.go:18-21` and `rotate_keep_old_test.go:149,163` keep pinning. **Do not edit those.**

### Task 5: failing tests for `--from-server`

**Files:** Modify the test files above and `scripts/integration.sh`.

- [ ] **Step 1: Rename the flag in the tests, by content so the `apply` hints survive.**

```bash
perl -pi -e 's/--server(?![s-])/--from-server/g unless /sshepherd apply/' \
  cmd/sshepherd/revoke_server_test.go cmd/sshepherd/revoke_memory_import_test.go
perl -pi -e 's/"--server", "web-2", "--yes"/"--from-server", "web-2", "--yes"/' cmd/sshepherd/memory_test.go
perl -pi -e 's/"--server", "web-1", "--sweep"/"--from-server", "web-1", "--sweep"/; s/revoke USER --server NAME --sweep/revoke USER --from-server NAME --sweep/' cmd/sshepherd/sweep_test.go
perl -pi -e 's/\{"unknown option word with --server", \[\]string\{"revoke", "tunnel", "--server", "web-1"\}/{"unknown option word with --from-server", []string{"revoke", "tunnel", "--from-server", "web-1"}/' cmd/sshepherd/revoke_test.go
perl -pi -e 's/^\/\/ --server trim-a/\/\/ --from-server trim-a/; s/"tmp", "--server", "trim-a"/"tmp", "--from-server", "trim-a"/; s/revoke --server exit/revoke --from-server exit/' cmd/sshepherd/e2e_test.go
perl -pi -e "s/'revoke alice --server web-1'/'revoke alice --from-server web-1'/" internal/apply/edit_test.go
perl -pi -e 's/--server(?![s-])/--from-server/g' internal/manifest/edit_test.go
perl -pi -e 's/a revoke --server removed/a revoke --from-server removed/' internal/adopt/adopt_test.go
perl -pi -e 's/\(revoke --server and rotate --keep-old E2E\)/(revoke --from-server and rotate --keep-old E2E)/' scripts/integration.sh
```

Read the result: `git diff cmd/sshepherd/e2e_test.go cmd/sshepherd/revoke_test.go cmd/sshepherd/memory_test.go cmd/sshepherd/sweep_test.go`. `e2e_test.go:621` (`apply --server nr-b`) and every line with `sshepherd apply` must be unchanged.

- [ ] **Step 2: Pin the old flag.** In `cmd/sshepherd/revoke_server_test.go`, before `// accessRefusalBody:`:

```go
// TestRevokeOldServerFlagRemoved: D26 renamed revoke's --server to
// --from-server with no alias, so the old spelling is an unknown flag
// (exit 3) and nothing is printed on stdout. apply and audit keep --server:
// there it restricts the run, here it edited the grants.
func TestRevokeOldServerFlagRemoved(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--server", "web-1", "--config", "/nonexistent.yaml"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "unknown flag: --server") {
		t.Errorf("stderr = %q, want cobra's unknown-flag error", errBuf.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want nothing", out.String())
	}
}
```

(Run Step 1 before this step, for the same reason as Task 1.)

- [ ] **Step 3: Run and see them fail.**

Run: `GOTOOLCHAIN=go1.27.3 rtk proxy go test ./cmd/sshepherd -run 'TestRevokeServer|TestRevokeOldServerFlagRemoved'`

Expected: FAIL with `unknown flag: --from-server` in every `TestRevokeServer*` that passes the flag, and `TestRevokeOldServerFlagRemoved` fails because stderr lacks the unknown-flag error (the old flag is still accepted, so the run stops at the missing manifest).

**docsDelta:** none.

### Task 6: rename `--server` to `--from-server` on `revoke`

**Files:** Modify `cmd/sshepherd/revoke.go`, `internal/apply/edit.go`; regenerate `testdata/help/revoke.golden`.

- [ ] **Step 1: Apply the rename.**

```bash
perl -pi -e 's/--server(?![s-])/--from-server/g; s/"server", nil,/"from-server", nil,/; s/access to this server only/access to server `NAME` only/' cmd/sshepherd/revoke.go
perl -pi -e 's/revoke USER --server/revoke USER --from-server/' internal/apply/edit.go
```

This covers `revoke.go:25` (`Use`), `:32` (`Long`, 78 columns, plan decision 3), `:45` (`Example`), `:86` (the flag name), `:87` (the `NAME` varname, plan decision 2), `:127` (comment), `:136,138,140` (the three `revokeUsage` errors), `:349,450,498` (comments), and `internal/apply/edit.go:19` (comment). `revoke.go:481` names `--operator` and is untouched.

Read the result: `git diff cmd/sshepherd/revoke.go`. The strings become:

```text
access is granted per user, not per key — use 'sshepherd revoke USER --from-server NAME'
--operator cannot be combined with --from-server: operators have access to every server by definition
--from-server takes server names; to remove all of a user's access use 'sshepherd revoke USER'
```

- [ ] **Step 2: Regenerate and read the golden.**

```bash
GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run TestHelpGolden -update
git diff cmd/sshepherd/testdata/help/revoke.golden
```

Expected: four changes (`Long`, `Usage`, the example, and the flag row, which moves to its alphabetical place between `--dry-run` and `-h, --help` and reads `--from-server NAME`, with the usage `remove the users' access to server NAME only (repeatable); the users and their keys stay`). The column width does not change (`--identity-passphrase-file FILE` stays the longest flag).

- [ ] **Step 3: Run.**

Run: `GOTOOLCHAIN=go1.27.3 rtk proxy go test ./cmd/sshepherd ./internal/apply ./internal/manifest ./internal/adopt && GOTOOLCHAIN=go1.27.3 go vet -tags=integration ./cmd/sshepherd`

Expected: PASS, except `TestHelpMatchesREADMETables`, which needs this lane's `docsDelta` (Task 7).

**docsDelta (README "Status", "`sshepherd revoke`", "Exit codes", the design-docs paragraph):** applied by Task 7's script.

### Task 7: gate and hand back

- [ ] **Step 1: Apply this lane's README delta to the worktree (gate only).** This block is also the `docsDelta` text.

```bash
python3 - <<'PY'
p = 'README.md'
s = open(p, encoding='utf-8').read()
pairs = [
    ('take away one server (`--server`)', 'take away one server (`--from-server`)'),
    ('revoke bob --server db-1           #', 'revoke bob --from-server db-1      #'),
    ('| `--server` | none | Remove', '| `--from-server NAME` | none | Remove'),
    ('`revoke USER --server NAME` one access', '`revoke USER --from-server NAME` one access'),
    ('(`--server`).** `revoke USER... --server NAME...`', '(`--from-server`).** `revoke USER... --from-server NAME...`'),
    ('`revoke --server` edits the grants', '`revoke --from-server` edits the grants'),
    ('nothing edited: `--server`', 'nothing edited: `--from-server`'),
    ("`--server '*'` (use", "`--from-server '*'` (use"),
    ('without `--server`', 'without `--from-server`'),
    ('$ sshepherd revoke bob --server db-1 --dry-run', '$ sshepherd revoke bob --from-server db-1 --dry-run'),
    ('$ sshepherd revoke bob --server db-1\n', '$ sshepherd revoke bob --from-server db-1\n'),
    ('`revoke --server` / `rotate --keep-old`', '`revoke --from-server` / `rotate --keep-old`'),
    ('an unknown or ungranted `--server`', 'an unknown or ungranted `--from-server`'),
]
for old, new in pairs:
    assert s.count(old) == 1, old
    s = s.replace(old, new)
open(p, 'w', encoding='utf-8').write(s)
PY
```

README's remaining `--server` lines are `apply`'s (lines 1080, 1167, 1551, 1628, 1643, 1941, 2189, 2318, 2478 at `aff7bf0`; `audit`'s are added once S1 has landed). Line 1551 is the sentence contrasting `apply --server` with `revoke --from-server`, and stays as it reads.

- [ ] **Step 2: Check no `revoke --server` is left.**

Run: `git grep -nE -e 'revoke[^|]{0,40}--server([^s-]|$)' -- cmd internal scripts`
Expected: two lines, both in `TestRevokeOldServerFlagRemoved`.

Run: `git grep -n 'from-servers' -- cmd internal scripts README.md`
Expected: nothing.

- [ ] **Step 3: Run the gates.** `GOTOOLCHAIN=go1.27.3 make check` → PASS. Then `make integration` under the runner's lock → PASS (`TestE2E…` drives `revoke tmp --from-server trim-a`).

- [ ] **Step 4: Hand back.** `git add -A`, unstage `README.md` and any other path outside the lane's globs, write the patch, and report the Task 7 block as `docsDelta`.

---

## Round 2 — lane `identity` (Tasks 8–9)

Owns: `cmd/sshepherd/identity.go`, `identity_test.go`, `help_readme_test.go`, `testdata/help/adopt.golden`, `apply.golden`, `audit.golden`, `revoke.golden`, `rotate.golden`, `internal/keyfile/*`. Finding: UX-7.

Runs on round 1's commits (`adopt.golden` and `revoke.golden` were just rewritten there).

### Task 8: failing tests for `PATH=FILE`

**Files:** Modify `cmd/sshepherd/identity_test.go`, `help_readme_test.go`, `internal/keyfile/resolve_test.go`, `load_test.go`.

- [ ] **Step 1: Rename the varname in the tests.**

```bash
perl -pi -e 's/KEY=FILE/PATH=FILE/g' cmd/sshepherd/identity_test.go cmd/sshepherd/help_readme_test.go \
  internal/keyfile/resolve_test.go internal/keyfile/load_test.go
perl -pi -e 's/"=", the KEY$/"=", the PATH/' cmd/sshepherd/identity_test.go
```

Subtest names that say `KEY` (`empty KEY`, `same KEY twice`, `unmatched KEY …`) stay, as in plan decision 5: they are not user-facing.

- [ ] **Step 2: Pin that the old varname is gone.** In `cmd/sshepherd/help_readme_test.go`, `TestHelpShowsIdentityVarnames`, after the inner `for … range want` loop, inside the outer loop:

```go
		if strings.Contains(out.String(), "KEY=FILE") {
			t.Errorf("%s --help still shows the old KEY=FILE varname:\n%s", name, out.String())
		}
```

- [ ] **Step 3: Run and see them fail.**

Run: `GOTOOLCHAIN=go1.27.3 rtk proxy go test ./cmd/sshepherd ./internal/keyfile -run 'TestHelpShowsIdentityVarnames|TestIdentityFlagValidation|TestResolve|TestLoadPassphraseResolution'`

Expected: FAIL in `TestHelpShowsIdentityVarnames`, `TestIdentityFlagValidation/*/malformed_mapping`, `TestLoadPassphraseResolution/default_wrong_and_headless_names_the_default` and `TestResolve/{missing_=,empty_FILE,empty_KEY}`.

**docsDelta:** none.

### Task 9: rename the varname, gate and hand back

**Files:** Modify `cmd/sshepherd/identity.go`, `internal/keyfile/keyfile.go`, `resolve.go`; regenerate `testdata/help/{adopt,apply,audit,revoke,rotate}.golden`.

- [ ] **Step 1: Apply the rename.**

```bash
perl -pi -e 's/KEY=FILE/PATH=FILE/g' cmd/sshepherd/identity.go internal/keyfile/resolve.go internal/keyfile/keyfile.go
```

This covers `identity.go:26` (comment), `:33` (usage), `resolve.go:63` (comment), `:67` (`want PATH=FILE`) and `keyfile.go:271` (`noSourceError`). `splitMapping`'s local names (`key`, `file`) and `fleet.go:70` (the flag's value, never the varname) do not change.

- [ ] **Step 2: Regenerate and read the goldens.**

```bash
GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run TestHelpGolden -update
git diff cmd/sshepherd/testdata/help
```

Expected: exactly one changed line in each of `adopt`, `apply`, `audit`, `revoke` and `rotate` (the `--identity-passphrase` row); `import.golden` and `root.golden` are unchanged. `--identity-passphrase PATH=FILE` is now as long as `--identity-passphrase-file FILE`, so no other row moves.

- [ ] **Step 3: Apply this lane's README delta to the worktree (gate only).** This block is also the `docsDelta` text. The first pair matches six times (the five flag tables and the "Authentication" list); the second matches once.

```bash
python3 - <<'PY'
p = 'README.md'
s = open(p, encoding='utf-8').read()
old = '`--identity-passphrase KEY=FILE`'
assert s.count(old) == 6, old
s = s.replace(old, '`--identity-passphrase PATH=FILE`')
old = '`KEY is encrypted and no passphrase source is available (use --identity-passphrase-file or --identity-passphrase KEY=FILE)`'
assert s.count(old) == 1, old
s = s.replace(old, '`PATH is encrypted and no passphrase source is available (use --identity-passphrase-file or --identity-passphrase PATH=FILE)`')
open(p, 'w', encoding='utf-8').write(s)
PY
```

- [ ] **Step 4: Check no old varname is left.**

Run: `git grep -n 'KEY=FILE' -- cmd internal scripts README.md`
Expected: two lines, both the assertion in `TestHelpShowsIdentityVarnames`.

- [ ] **Step 5: Run the gate.** `GOTOOLCHAIN=go1.27.3 make check` → PASS.

- [ ] **Step 6: Hand back.** `git add -A`, unstage `README.md` and any other path outside the lane's globs, write the patch, and report the Step 3 block as `docsDelta`.

---

## Integrator and verification

### Task 10: integrator-only documents

This task is the integrator's. No lane owns it. Task 11 follows it.

**For every lane, in merge order `import`, `revoke`, `identity`:** apply the patch, **then apply the lane's README `docsDelta` script (Task 4 Step 1, Task 7 Step 1, Task 9 Step 3), then run `make check`, then apply the lane's `CLAUDE.md` pairs (Step 2), then commit the lane's patch, README and `CLAUDE.md` together** (`TestHelpMatchesREADMETables` reads README, so `make check` fails without the delta; README and Status must never disagree, so neither lags a commit). Run `make integration` after the last lane of each round: after `revoke` (its E2E) and after `identity`, so the final tree is covered. If S1 lands in the same wave, the scripts match on text, so README line shifts do not matter; if S1 already changed a matched sentence, adapt the old string, keep the new name, and do not touch S1's text. The README "`sshepherd audit`" table's `--server` row (S1) and `apply`'s are unchanged by these scripts.

- [ ] **Step 1: Read the README diff top to bottom** for each lane, and confirm `Long`, `--help` and the tables agree.

- [ ] **Step 2: Apply the remaining edits.**

**docsDelta (CLAUDE.md Status, in place, one block per lane, each in that lane's commit).** Each old string must match exactly once.

With lane `import`:

```bash
python3 - <<'PY'
p = 'CLAUDE.md'
s = open(p, encoding='utf-8').read()
old = '`import --operator <key>` marks them at import time'
assert s.count(old) == 1, old
s = s.replace(old, '`import --operator-key <key>` marks them at import time')
open(p, 'w', encoding='utf-8').write(s)
PY
```

With lane `revoke`:

```bash
python3 - <<'PY'
p = 'CLAUDE.md'
s = open(p, encoding='utf-8').read()
pairs = [
    ('**`revoke --server` and `rotate --keep-old`**', '**`revoke --from-server` and `rotate --keep-old`**'),
    ('`revoke USER... --server NAME...`', '`revoke USER... --from-server NAME...`'),
    ('adds a `revoke --server`\n', 'adds a `revoke --from-server`\n'),
]
for old, new in pairs:
    assert s.count(old) == 1, old
    s = s.replace(old, new)
open(p, 'w', encoding='utf-8').write(s)
PY
```

With lane `identity`:

```bash
python3 - <<'PY'
p = 'CLAUDE.md'
s = open(p, encoding='utf-8').read()
old = '`--identity-passphrase-file FILE` / `--identity-passphrase KEY=FILE`'
assert s.count(old) == 1, old
s = s.replace(old, '`--identity-passphrase-file FILE` / `--identity-passphrase PATH=FILE`')
open(p, 'w', encoding='utf-8').write(s)
PY
```

Everything below in this step goes in the last lane's (`identity`) commit.

**docsDelta (CLAUDE.md Status, a new paragraph at the end of the section; keep the existing text in the same voice):**

```markdown
**Flag renames (P10 S2, D26, UX-7)** (specced in section S2 of
`docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`, planned in
`docs/superpowers/plans/2026-11-09-p10-s2-flag-renames.md`): `import --operator-key PATH`,
`revoke --from-server NAME` and the `--identity-passphrase PATH=FILE` varname replace
`--operator`, `--server` and `KEY=FILE`, with no aliases (no release has shipped, so the
old names are unknown flags, exit 3). `apply`'s `--server` keeps its name because it only
restricts a run, so `revoke`'s apply-phase hint still prints it; `revoke`/`rotate`'s bool
`--operator` keeps its name; `--merge` keeps both names with clearer help. No exit code or
JSON field changed.
```

**docsDelta (spec Status, `docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`, line 4):** the `Not built:` clause must not sit next to a claim that S2 is built, and S1's plan rewrites the same clause. This handles S1 landing first or not at all; if S1's final wording differs, the assertion fails and the integrator adapts the first string, keeping S1's text.

```bash
python3 - <<'PY'
p = 'docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md'
s = open(p, encoding='utf-8').read()
s1 = 'S1 built (plan 2026-11-09-p10-s1-validate-audit-server)'
s2 = 'S2 built (plan 2026-11-09-p10-s2-flag-renames)'
tail = '; the other slices are not built:'
if s.count(s1 + tail) == 1:
    s = s.replace(s1 + tail, s1 + ', ' + s2 + tail)
else:
    assert s.count('Not built:') == 1, 'Not built:'
    s = s.replace('Not built:', s2 + tail)
open(p, 'w', encoding='utf-8').write(s)
PY
```

**docsDelta (same spec, S2 section, a sentence after the "Files." paragraph, recording what the build found):** `` `editrun.go` and the `accessProblems` hint needed no change: `applyHint` builds `apply`'s `--server`, and the hint builds `--operator`. The same section's lanes run in two rounds, because `adopt.golden` and `revoke.golden` carry both a renamed flag and the `PATH=FILE` varname. ``

**docsDelta (same spec, S1 section, the Files paragraph):** add `adopt.go` (the `readFleet` call) if S1's integrator has not already added it.

- [ ] **Step 3: One commit per lane** (patch, README and that lane's `CLAUDE.md` block; the last also carries the new paragraph and the spec edits), each ending with the attribution trailer, e.g. `refactor(cli): rename import --operator to --operator-key (P10 S2, UX-7)`, `refactor(cli): rename revoke --server to --from-server (P10 S2, UX-7)`, `refactor(cli): show PATH=FILE for --identity-passphrase (P10 S2, UX-7)`.

**docsDelta:** none further.

### Task 11: independent verification (Acceptance)

This task is the independent verifier's, after Task 10 is committed. It is read-only: findings go to the repair pass. No lane owns it.

- [ ] **Step 1: Run the gates.** `GOTOOLCHAIN=go1.27.3 make check`, then `make integration` for `IT_DISTRO=alpine`, `debian` and `rocky`. Expected: PASS on all.

- [ ] **Step 2: Drive the built binary.** `GOTOOLCHAIN=go1.27.3 go build -o /tmp/sshepherd-s2 ./cmd/sshepherd`, then in a scratch directory:

| Command | Expected |
|---|---|
| `sshepherd-s2 import --operator x` | exit 3, stderr `unknown flag: --operator` |
| `sshepherd-s2 import --servers-only --operator-key x` | exit 3, `--operator-key conflicts with --servers-only (operators are users)` |
| `sshepherd-s2 revoke bob --server web-1` | exit 3, stderr `unknown flag: --server` |
| `sshepherd-s2 revoke --key SHA256:x --from-server web-1` | exit 3, the `per user, not per key` error naming `--from-server` |
| `sshepherd-s2 revoke --help` | shows `--from-server NAME`, no `--server` flag row |
| `sshepherd-s2 import --help` | shows `--operator-key PATH`, no `--operator` flag row |
| `sshepherd-s2 apply --help` | still shows `--server stringArray` |
| `sshepherd-s2 audit --help` | shows `--identity-passphrase PATH=FILE`; shows `--server` once S1 has landed |
| `sshepherd-s2 audit --identity x --identity-passphrase noequals` | exit 3, `invalid flags: --identity-passphrase "noequals": want PATH=FILE` |
| `sshepherd-s2 import --help`, `adopt --help` | the `--merge` text from the spec's table, verbatim |

- [ ] **Step 3: No old name left.** Run each grep from Tasks 4, 7 and 9 with the pathspec its own task gives, and expect what that task says. Over `README.md`: `git grep -nE -e '--operator([^-a-z]|$)' -- README.md` lists only `revoke`/`rotate`'s bool (eight lines at `aff7bf0`: 1501, 1561, 1797, 1856, 1924, 1961, 2084, 2201), and `git grep -nP -e '--server(?![s-])' -- README.md` lists only `apply`'s lines (Task 7 Step 1's list), plus `audit`'s once S1 has landed. `README.md`'s Status table and `CLAUDE.md`'s Status agree.

- [ ] **Step 4: The hints.** `TestRevokeServer*` and `revoke_test.go:422,637,662` still pin `apply … --server …` on a `--from-server` run (the design's rule that `apply`'s flag keeps its name).

**docsDelta:** none.

---

## Review log

**Draft trial.** The draft's edits were compiled and run against a throwaway export of `aff7bf0`, lane by lane: each lane's tests failed first and passed after the code; `make check` passed on `import` alone, on `revoke` alone and on all three lanes together (coverage 95.7%, 95.7%, 95.6%). That trial found the `--servers-only` trap (hence `--server(?![s-])`), `README.md:2201` and the `-run` scope of `import_manifest_operators.golden`. `make integration` was not run on the draft; `go vet -tags=integration` passed.

**Review round.** Two independent reviews; every point was checked by reading the design and `aff7bf0`. None of the edits below was compiled or run, so the first lane run is their first execution. S1's draft plan was read for the overlap and the Status clause.

| # | Issue | Outcome |
|---|---|---|
| 0.1 | `--help` lacks the design's `PATH`/`NAME` | Applied (fix a): decision 2, Tasks 2, 4, 6, 7, 11. The reviewer's width was off: `--operator stringArray` is 22 columns, so the block narrows by three, not two. |
| 0.2 | CLAUDE.md Status lags README | Applied: Task 10 Step 2 splits the pairs by lane. |
| 0.3 | Integrator's `make integration` misses the final tree | Applied: after the last lane of each round, as the runner's skeleton does. |
| 0.4, 1.4 | README `--server` list omits 2189 | Applied (Task 7). |
| 0.5, 1.8 | Half-renamed comment at `identity_test.go:142` | Applied (Task 8). |
| 0.6 | Spec Status contradicts itself | Applied with different wording: S1's plan rewrites the same `Not built:` clause, so the delta extends S1's clause or replaces the original. |
| 1.1 | Integrator's gate runs before the README delta | Applied: `handoffs` and `plan` bullets in Wave lanes, how-it-is-cut item 2. |
| 1.2 | `from-servers` grep hits this committed plan | Applied (Task 7): pathspec added. |
| 1.3 | Task 11's greps were false over the wider paths | Applied (Task 11 Step 3). |
| 1.5 | Wrong row position for `--from-server` | Applied (Task 6). |
| 1.6 | Task 3 against "Failing first" | Applied: exception in Conventions. |
| 1.7 | `--operator-key key` stutter in a comment | Applied (Task 1). The same check found `import.go:146`, fixed in Task 2. |

---

## Wave lanes (for the runner)

- **`plan`** (the runner's `args.plan`): `docs/superpowers/plans/2026-11-09-p10-s2-flag-renames.md`, committed before round 1.
- **`handoffs`** (the runner's `args.handoffs`), one entry: "P10-S2, per lane in the order import, revoke, identity: git apply that lane's patch, run its docsDelta script on README.md (Task 4 Step 1, Task 7 Step 1, Task 9 Step 3), then make check, then that lane's CLAUDE.md block (Task 10 Step 2), then commit patch, README and CLAUDE.md together, one commit per lane. TestHelpMatchesREADMETables reads README and the patch carries no README change. Lane identity's commit also carries the rest of Task 10 Step 2 (the new Status paragraph and the spec edits)."

Rounds run in sequence; lanes inside a round own disjoint files and build only on the previous rounds' commits. Globs are shell `case` patterns (`*` crosses `/`). `README.md` and `CLAUDE.md` are integrator-only: each lane reports its `docsDelta`, applies it to its own worktree for the gate, and the ownership filter drops it. **The integrator must re-apply a lane's `docsDelta` after its patch and before `make check`** (`TestHelpMatchesREADMETables` and `TestHelpShowsIdentityVarnames` read those names).

```json
{
  "rounds": [
    [
      {
        "pkg": "P10-S2",
        "lane": "import",
        "kind": "fix",
        "ids": ["UX-7"],
        "tasks": "Tasks 1-4",
        "files": [
          "cmd/sshepherd/import.go",
          "cmd/sshepherd/import_test.go",
          "cmd/sshepherd/import_merge_test.go",
          "cmd/sshepherd/conflicts_test.go",
          "cmd/sshepherd/adopt.go",
          "cmd/sshepherd/testdata/import_manifest_operators.golden",
          "cmd/sshepherd/testdata/help/import.golden",
          "cmd/sshepherd/testdata/help/adopt.golden",
          "internal/reconcile/*",
          "internal/identity/*"
        ],
        "needsIntegration": false
      },
      {
        "pkg": "P10-S2",
        "lane": "revoke",
        "kind": "fix",
        "ids": ["UX-7"],
        "tasks": "Tasks 5-7",
        "files": [
          "cmd/sshepherd/revoke.go",
          "cmd/sshepherd/revoke_server_test.go",
          "cmd/sshepherd/revoke_memory_import_test.go",
          "cmd/sshepherd/revoke_test.go",
          "cmd/sshepherd/memory_test.go",
          "cmd/sshepherd/sweep_test.go",
          "cmd/sshepherd/e2e_test.go",
          "cmd/sshepherd/testdata/help/revoke.golden",
          "internal/apply/edit.go",
          "internal/apply/edit_test.go",
          "internal/manifest/edit_test.go",
          "internal/adopt/adopt_test.go",
          "scripts/integration.sh"
        ],
        "needsIntegration": true
      }
    ],
    [
      {
        "pkg": "P10-S2",
        "lane": "identity",
        "kind": "fix",
        "ids": ["UX-7"],
        "tasks": "Tasks 8-9",
        "files": [
          "cmd/sshepherd/identity.go",
          "cmd/sshepherd/identity_test.go",
          "cmd/sshepherd/help_readme_test.go",
          "cmd/sshepherd/testdata/help/adopt.golden",
          "cmd/sshepherd/testdata/help/apply.golden",
          "cmd/sshepherd/testdata/help/audit.golden",
          "cmd/sshepherd/testdata/help/revoke.golden",
          "cmd/sshepherd/testdata/help/rotate.golden",
          "internal/keyfile/*"
        ],
        "needsIntegration": false
      }
    ]
  ],
  "mergeOrder": ["P10-S2"]
}
```

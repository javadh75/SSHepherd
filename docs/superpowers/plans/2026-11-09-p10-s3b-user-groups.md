# User groups (P10 S3b, D20b, PRD-4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This plan is executed by the wave runner of `docs/superpowers/plans/2026-11-07-review-remediation.md` ("Reusable workflow skeleton"): lane agents work in git worktrees, never commit, and hand back ownership-filtered patches; the integrator commits once per lane. Where a task says "Hand back", that is the lane's last step, not a commit.

**Commits at:** `docs/superpowers/plans/2026-11-09-p10-s3b-user-groups.md`

**Goal:** Build slice S3b of the approved access-model design (`docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`, section "S3b. User groups (D20b; PRD-4)", plus its Shared rules, "How selectors meet tombstones" and the "Order and parallel lanes" row): `groups:` in the manifest, `group:` on an access entry as the alternative to `user:`, the `empty_group` warning, a tombstone blocking a group-derived grant for one member only, removal from every group on `revoke USER`, and the refusal of `revoke USER --from-server S` when a group grant reaches the pair.

**Architecture:** A group entry expands to one grant per member inside `validateAccess`, so `c.grants` and `DesiredFor` keep their shape and nothing past `internal/config` learns what a group is, except `manifest.RemoveUser` (membership lists) and `manifest.GenerateWith` (the new section). `entryApplies` becomes a `Config` method that also answers for membership, which is what `Covers` and `ExceptCarveOut` read; `directlyGranted` and `accessConflicts` read `a.User` instead, so a group entry is never "direct" and a tombstone over a group grant is always blocked, never a conflict. `GroupGrantsReaching` lets `revoke` refuse a pair a group reaches, and `OwnExceptCarveOut` keeps a group's `except:` from standing in for a personal trim's tombstone.

**Tech Stack:** Go 1.27.3 (`GOTOOLCHAIN=go1.27.3`, the Makefile's `GO_PIN`), `gopkg.in/yaml.v3` node editing, Cobra, the hermetic `internal/sshconn/sshtest` server through `editFleet`, goleak, golden files (`-update`), native fuzzing (`FuzzLoad`, `FuzzManifestEdit`, `FuzzMergeRoundTrip`, `FuzzRemoveAccess`), golangci-lint (depguard layering, gocyclo 15, revive), `deadcode ./cmd/sshepherd`, the dockerized sshd matrix (`make integration`).

**Base:** `master` at `4f5c468`, after S1, S2, S8 and S3a. Every `file:line` below was read there. `master` has since gained `9319793`, a test-only commit adding two tests to `internal/config/selector_test.go`. This plan does not touch that file, and its `TestBlockedWarningNamesTheGrantingSelector` keeps passing (Task 4's `grantVia` keeps the first-selector rule). `Config.ManifestWarnings`, `audit.ManifestFindings`, `validate`, `audit --server`, the `import --operator-key` and `revoke --from-server` flag names, `internal/config/selector.go` and `blockTombstoned` all exist. P08 and P09 did not touch `expandServers`, `Covers`, `ExceptCarveOut`, `accessConflicts` or `RemoveUser`.

**Compile status.** An independent review applied every Go block, seed and script edit of the previous draft to a scratch export of `9319793` and built them; all compiled after `gofmt` (see the Review log). The blocks this revision added or changed were not compiled: the step that wrote this plan could write only this plan file. They were syntax-checked with `gofmt -e` on stdin and checked by reading every helper they call at `master`. The lane that applies a block compiles it; on a compile error it fixes the block within its stated intent and reports the fix. The goldens and corpus entries named below do not exist yet; the lane generates them (`-update`) and reads each one back before accepting it.

---

## Design gaps and contradictions (for the main session)

Item 1 is a real contradiction with the landed code and needs the main session's eye. No item overrides an answered decision, and no owner answer is needed before the wave runs. Task 15 Step 2 records items 1-6, 8 and 10 in the design. Item 7 needs no text, because the design already says the guard becomes load-bearing in S3b. Item 9 is an implementation detail. Item 11 is a gap for the main session, with no code and no amendment in this plan. The main session can veto any of them.

1. **`HasAccessEntry` is not added: the landed code contradicts the design here.** The design says `NoGrantsLeft` in `planRevokeAccess` "scans `a.User` today" and "moves to `HasAccessEntry`". At `4f5c468` it does not scan anything: S3a's repair made it a count, `ep.summary.Edits[i].NoGrantsLeft = ep.summary.Edits[i].KeepsServers == 0` (`cmd/sshepherd/revoke.go:403-405`), because "an entry a tombstone wholly blocks still names the user and reaches nothing". That count already answers for a group through `Covers`, so the design's goal (a user with group access is not told they have none left) holds without the helper. Adding `HasAccessEntry` with no caller fails `deadcode` in `make check`. Wiring it in place of the count would bring back the bug S3a fixed. `TestRevokeServerKeepsCountIgnoresBlockedGroupPair` (Task 10) pins the design's intent.
2. **`UserRemoval.Groups` gains a reader, which the design's file list does not name.** The design says `RemoveUser` "reports it in `UserRemoval.Groups`". With no reader nothing reports it, and the edit header would read `remove user alice (1 key, 0 access grants)` for a user who just lost every server through a group. Task 11 adds `apply.Edit.Groups`, a `, 1 group` fragment in that header only when non-zero, and an additive `groups` field on `remove-user` JSON entries. No existing golden changes. This adds `internal/apply/{edit,json}.go` to the lane.
3. **Error texts the design leaves open.** These become test expectations:
   - bad name: `group "Web": name is not valid: want lowercase letters, digits, '.', '_' or '-', starting with a letter or digit, at most 63 characters` (the tag text);
   - repeat: `duplicate group "web-team"` (the `duplicate user`/`duplicate server` form);
   - `group "web-team": unknown member "zed"`, `group "web-team": member "alice" is repeated`;
   - neither or both of `user:` and `group:`: `access[2]: set exactly one of user or group`. A missing `user:` read `access: unknown user ""` until now; no test pins that;
   - two groups reaching one pair, which the design's refusal text does not cover: `bob's access to web-1 comes from groups web-team, solo; remove the user from the groups, trim the groups' grants, or add revoked: [{user: bob, servers: [web-1], date: 2026-11-09}] to block only this member`.
4. **`entryDirect` does not change; its two callers read `a.User`.** The design says `entryApplies` becomes group-aware for `Covers` and `ExceptCarveOut`. `accessConflicts` and `directlyGranted` also call it today, and they must not count a group: the table in "How selectors meet tombstones" makes any group entry blocked, even a literal server name. So `accessConflicts` becomes `a.User != t.User` and `directlyGranted` `a.User == user && entryDirect(...)`.
5. **The third way out, with a direct grant beside the group.** The refusal names a hand-written tombstone as a way out. When the user also holds a direct grant of that server, that tombstone is a W4 conflict until the direct grant goes too, because a direct grant is never blocked. The design fixes the text, so the plan keeps it. The README delta says so.
6. **`wildcard_root` on a group entry is read literally.** The design says a group `*` entry reaching root "warns once per entry", with no carve-out. An empty group or an all-operator group therefore warns too, and `TestWildcardRootNamesTheGroup` pins both. `warnWildcardRoot` needs only its label changed: `slices.Contains(c.operators, a.User)` is false for a group entry's empty `a.User`.
7. **S3a's design gap 3 closes here.** `Covers`' `c.blocked` guard is load-bearing from this slice, because a group entry's `*` or literal server matches `Server{Name: n}` in the raw scan. `TestTombstoneBlocksOneGroupMember` fails when the guard is removed (rows `wildcard` and `literal`), and the reconcile test `TestReconcileHonoursBlockedGroupGrant` fails the same way through the import path.
8. **The refused trim has no bytes to snapshot.** The design lists it among "manifest edit goldens". A refused edit writes nothing, so Task 10 pins the exact refusal text and that the file stays byte-identical. The other two goldens are real files.
9. **`Config.members` is built from every named group, valid name or not,** so a group with a bad name is reported once, not again as an unknown group by each entry that uses it. `Parse` still fails the load.
10. **A group's `except:` is not memory for a personal trim (D1a).** Trimming bob's direct `{user: bob, servers: [web-2]}` while a group `*` entry has `except: [web-2]` must still write an access tombstone. D1a exempts only a server that "gained an `except:` entry" from the trim, and nothing gained one here. The group's `except:` stops applying when bob leaves the group, which is a hand edit, and `adopt --merge` would then re-extend him while the key is still installed (the design's Risks section warns about exactly that). So `revoke`'s three reads use a new `Config.OwnExceptCarveOut`, on both the `former` and `mid` sides of `forgottenCarveOut` (reading it on `mid` only would tombstone every group-excepted server). `ExceptCarveOut` stays group-aware for adopt and reconcile, as the design says.
11. **A fresh `import -o FILE --force` drops `groups:` with no warning.** That path generates a new manifest with no groups, and `warnMemoryLost` (`cmd/sshepherd/import.go:26-39`) checks only the serial and tombstones. Dropped groups can leave a warning-free manifest that grants less than it did. The design says only that `adopt` regenerate carries groups and that neither command creates them, so this plan adds no code. The README sentence states the behaviour. The main session should decide whether `warnMemoryLost` should name groups too.

## How this plan is cut (read first)

### Why the lanes look the way they do

1. **Two rounds, not the design's three lanes.** The design's row for S3b is A `internal/config` · B `internal/manifest` · C `revoke.go`, `adopt.go`. The runner needs each lane to compile and pass `make check` on earlier rounds alone. `manifest.Load` refuses a `groups:` key until `topLevelKeys` changes, so every revoke, rotate, adopt-merge and validate test on a group manifest needs lane B's change, and `adopt.go`'s `Draft{Groups: ...}` needs lane B's field. So round 1 is the whole schema (`internal/config` and the tests that read it) and round 2 is one lane, `editor`, holding B and C.
2. **`deadcode ./cmd/sshepherd` is part of `make check`.** Every function round 1 adds is reachable from `Parse`: `validateGroups`, `entryUsers`, `entryLabel`, `entrySubjectError`, `blockEntry`, `grantVia`. `GroupGrantsReaching` and `OwnExceptCarveOut` have their only production callers in `revoke.go`, so they land in round 2 beside those callers, in the new file `internal/config/group_reach.go`. Fields (`Access.Group`, `Draft.Groups`, `UserRemoval.Groups`, `Edit.Groups`) are exempt, and lane `editor` adds their readers anyway.
3. **Between round 1 and round 2 a manifest with `groups:` loads but the editor refuses it** (`manifest contains an unsupported top-level key "groups"`). No test exercises the gap, no fixture has groups until a lane adds them, and `validate`'s tests live in round 2 for this reason.
4. **`TestSchemaRoundTrip*` reflects over `config.Access`,** so the `Group` sample in `cmd/sshepherd/schema_roundtrip_test.go` lands in round 1 with the field, or `make check` fails. The test proving `groups:` regenerates lands in round 2 with `Draft.Groups`.
5. **One help text changes; no flag or exit-code footer does.** Lane `editor` rewords `revoke`'s Long text and regenerates `cmd/sshepherd/testdata/help/revoke.golden`. `TestHelpMatchesREADMETables` and `TestHelpExamplesAndExitCodes` read only flag tables and exit-code footers, so no lane needs its `docsDelta` for the gate. The integrator still applies each lane's delta in that lane's commit, before `make check`, as every plan does.

### Rounds

| Round | Lane (disjoint files) | Builds on |
|---|---|---|
| 1 | `schema`: `internal/config`, the consumer tests in `internal/{apply,adopt,reconcile,audit}`, `schema_roundtrip_test.go` | `9319793` |
| 2 | `editor`: `internal/manifest`, `internal/config/group_reach{,_test}.go`, `internal/apply/{edit,json}.go`, `cmd/sshepherd/{revoke,adopt}.go`, CLI tests, the E2E, `scripts/integration.sh` | round 1 |

After round 2 the integrator runs Task 15 and an independent verifier runs Task 16. No lane owns either.

### Plan decisions (not in the design; none changes an exit code, refusal or load beyond an answered decision)

1. **Fuzz seeds.** `internal/config/testdata/fuzz/FuzzLoad` already holds 16 entries, the CLAUDE.md maximum, so its group seeds go in `f.Add` only. `FuzzManifestEdit`, `FuzzMergeRoundTrip` and `FuzzRemoveAccess` each get one committed group seed with a static key line beside an `f.Add` seed. No new `Fuzz*` target: the count stays 23. `FuzzLoad` gains oracles (an accepted group name has `tagShape`, every accepted member is a user, every accepted access entry has exactly one of `user`/`group`). `FuzzRemoveAccess` changes: it skips a pair a group grant reaches, because `revoke` refuses that pair and `RemoveAccess` is never called on it.
2. **E2E.** The design lists one group grant through adopt → apply → revoke → audit. It needs two fresh sshd accounts, `grpa` and `grpb`, because every E2E has its own (a serial header left by an earlier test would otherwise refuse the write). `scripts/integration.sh` gains them in lane `editor`.

### Conventions every lane follows

- Go runs under the pin: prefix every `go` command with `GOTOOLCHAIN=go1.27.3`. The rtk hook summarizes test output; use `rtk proxy go test …` when exact failure lines matter.
- A golden is rewritten only with `-update` and then read back line by line before it is accepted.
- **Failing first.** Every test is run and seen failing (build failure or assertion) before the code it tests exists; a test that pins behaviour already present says so in its step.
- **gocyclo 15 is a production-code gate;** never `//nolint:gocyclo`.
- **Run `gofmt -w` on every Go file you touch** before `make check`. Struct and comment alignment in these blocks is written by hand and was not machine-checked.
- **New test variables must not shadow builtins** (revive): no `new`, `len`, `max`, `min`, `copy`, `cap`.
- **A mutation run must finish before reporting.** Each lane's last task lists its mutants. Apply one at a time, run the named tests, record killed or survived, and revert. Report the table with the hand-back. Do not hand back while a mutant is still running, and do not report a survivor without saying why it is equivalent or which test you added to kill it.
- **A Fuzz target added or changed needs its seed corpus** under `<pkg>/testdata/fuzz/<Target>/` (at most 16 entries of 4 KiB or less per target).
- **Before hand-back:** run `make check` (and `make integration` under the runner's lock when the lane says `needsIntegration`), then `git add -A`, unstage every path outside the lane's globs (`README.md` and `CLAUDE.md` always), and write the patch.
- **`docsDelta`** blocks are integrator-only text for `README.md`, `CLAUDE.md` Status and spec Status. A lane reports them unchanged and never edits those files in its patch.

---

## File structure

| File | Round/lane | Responsibility |
|---|---|---|
| `internal/config/groups.go` (new) | 1 `schema` | `validateGroups`, `memberErrors`, `entrySubjectError`, `entryUsers`, `entryLabel` |
| `internal/config/config.go` | 1 `schema` | `Group`, `Access.Group`, `Config.Groups`, `Config.members`, `validate` order, `validateAccess`, `expandServers`/`entryShape` labels, `warnWildcardRoot`, `Covers`, `ExceptCarveOut` |
| `internal/config/selector.go` | 1 `schema` | `entryApplies` becomes a method that answers for membership |
| `internal/config/revoked.go` | 1 `schema` | `accessConflicts`, `directlyGranted`, `blockTombstoned`, `blockEntry`, `warnBlocked`, `grantVia` |
| `internal/config/warnings.go` | 1 `schema` | `WarnEmptyGroup` |
| `internal/config/groups_test.go` (new), `fuzz_test.go` | 1 `schema` | every validation row and group message, expansion, `Covers`, tombstones, root warning, fuzz seeds and oracles |
| `internal/apply/groups_equivalence_test.go`, `internal/adopt/groups_test.go`, `internal/reconcile/groups_test.go`, `internal/audit/groups_test.go` (all new) | 1 `schema` | equivalence property, no re-extension, D1d drift |
| `cmd/sshepherd/schema_roundtrip_test.go` | 1 `schema`, then 2 `editor` | `Group` sample (round 1); `TestAdoptRegenerateKeepsGroups` (round 2) |
| `internal/manifest/manifest.go` | 2 `editor` | `topLevelKeys`, `requiredKeys`, `Draft.Groups`, `GenerateWith` |
| `internal/manifest/edit.go` | 2 `editor` | `UserRemoval.Groups`, `RemoveUser` drops memberships |
| `internal/manifest/edit_groups_test.go` (new), `testdata/edit_remove_member.golden`, `testdata/edit_remove_last_member.golden` (new), `fuzz_test.go`, `fuzz_edit_test.go`, `testdata/fuzz/{FuzzRemoveAccess,FuzzManifestEdit,FuzzMergeRoundTrip}/seed-group-*` (new) | 2 `editor` | encoder, edit, goldens, seeds, the `FuzzRemoveAccess` oracle |
| `internal/config/group_reach.go`, `group_reach_test.go` (new) | 2 `editor` | `GroupGrantsReaching` and `OwnExceptCarveOut` beside their first caller |
| `cmd/sshepherd/adopt.go`, `revoke.go` | 2 `editor` | `Draft{Groups}`; the refusal in `classifyPairs`; `OwnExceptCarveOut` in `accessTombstones` and `forgottenCarveOut`; `Groups` on the remove-user edit; help text |
| `internal/apply/edit.go`, `json.go`, `edit_groups_test.go` (new) | 2 `editor` | `Edit.Groups`, the header fragment, additive JSON |
| `cmd/sshepherd/revoke_groups_test.go`, `groups_consumers_test.go`, `validate_groups_test.go`, `groups_e2e_test.go` (all new), `testdata/help/revoke.golden` | 2 `editor` | hermetic revoke, rotate, adopt/import merge, validate, E2E |
| `scripts/integration.sh` | 2 `editor` | fixture accounts `grpa`, `grpb` |

---

## Round 1 — lane `schema` (Tasks 1–7)

Owns: `internal/config/*`, `internal/apply/groups_equivalence_test.go`, `internal/adopt/groups_test.go`, `internal/reconcile/groups_test.go`, `internal/audit/groups_test.go`, `cmd/sshepherd/schema_roundtrip_test.go`. Finding: PRD-4. Builds on `9319793`.

### Task 1: the `groups:` section and its validation

**Files:**
- Create: `internal/config/groups.go`, `internal/config/groups_test.go`
- Modify: `internal/config/config.go:50-58` (`Access`), `:61-90` (`Config`), `:128-136` (`validate`); `internal/config/warnings.go:5-12`; `cmd/sshepherd/schema_roundtrip_test.go:23`

- [ ] **Step 1: Write the failing tests.** Create `internal/config/groups_test.go`:

```go
package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// webTeam is a groups: entry; alice and bob are its members.
const webTeam = "  - {name: web-team, members: [alice, bob]}\n"

// groupFleet: alice (k1), bob (k2), carol (k3), op (k4, operator); web-1 and
// web-2 tagged web, web-3 tagged web on root, db-1 tagged db. groups, access
// and extra are spliced in verbatim.
func groupFleet(t *testing.T, groups, access, extra string) string {
	t.Helper()
	return `users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: carol, keys: ["` + testkeys.Line(t, 3) + `"]}
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 4) + `"]}
groups:
` + groups + `servers:
  - {name: web-1, host: 10.0.1.1, user: deploy, tags: [web]}
  - {name: web-2, host: 10.0.1.2, user: deploy, tags: [web]}
  - {name: web-3, host: 10.0.1.3, user: root, tags: [web]}
  - {name: db-1, host: 10.0.2.1, user: deploy, tags: [db]}
access:
` + access + extra
}

func TestGroupValidation(t *testing.T) {
	long := strings.Repeat("a", 64)
	for _, tc := range []struct{ name, groups, want string }{
		{"uppercase", "  - {name: Web, members: [alice]}\n",
			`group "Web": name is not valid: want lowercase letters, digits, '.', '_' or '-', starting with a letter or digit, at most 63 characters`},
		{"empty name", `  - {name: "", members: [alice]}` + "\n", `group "": name is not valid`},
		{"64 characters", "  - {name: " + long + ", members: [alice]}\n", `group "` + long + `": name is not valid`},
		{"leading dash", "  - {name: -x, members: [alice]}\n", `group "-x": name is not valid`},
		{"repeated name", webTeam + webTeam, `duplicate group "web-team"`},
		{"unknown member", "  - {name: g, members: [zed]}\n", `group "g": unknown member "zed"`},
		{"repeated member", "  - {name: g, members: [alice, alice]}\n", `group "g": member "alice" is repeated`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(groupFleet(t, tc.groups, "", "")))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
	valid := mustParse(t, groupFleet(t, "  - {name: a.b_c-d, description: docs only, members: [alice]}\n  - {name: 9lives, members: [bob, alice]}\n", "", ""))
	if len(valid.Groups) != 2 || valid.Groups[0].Description != "docs only" || !reflect.DeepEqual(valid.Groups[1].Members, []string{"bob", "alice"}) {
		t.Errorf("Groups = %+v", valid.Groups)
	}
	if len(valid.Warnings) != 0 {
		t.Errorf("Warnings = %q, want none", valid.Warnings)
	}
}

// TestEmptyGroupWarns: an empty group loads, so revoking the last member
// never breaks the manifest; a missing members: key is the same as [].
func TestEmptyGroupWarns(t *testing.T) {
	const want = `group "web-team" has no members; its grants add nothing`
	for _, groups := range []string{"  - {name: web-team, members: []}\n", "  - {name: web-team}\n"} {
		cfg := mustParse(t, groupFleet(t, groups, "", ""))
		if !reflect.DeepEqual(cfg.Warnings, []string{want}) {
			t.Errorf("Warnings = %q, want [%q]", cfg.Warnings, want)
		}
		if len(cfg.ManifestWarnings) != 1 || cfg.ManifestWarnings[0].Kind != WarnEmptyGroup || cfg.ManifestWarnings[0].Message != want {
			t.Errorf("ManifestWarnings = %+v", cfg.ManifestWarnings)
		}
	}
}
```

- [ ] **Step 2: Run it to see it fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run 'TestGroupValidation|TestEmptyGroupWarns'`
Expected: FAIL, with `unknown field` on `groups`/`WarnEmptyGroup undefined`.

- [ ] **Step 3: Add the types.** In `internal/config/config.go`, replace the `Access` type (`:50-58`) with:

```go
// Group names a set of users for access: entries (spec 2026-11-08 S3b). An
// access entry with group: grants every member. Membership is checked at
// load: each member is a known user, listed once.
type Group struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"` // docs only, never sent to a server
	Members     []string `yaml:"members"`
}

// Access grants one user, or every member of one group, access to a list of
// servers. Exactly one of User and Group is set. An item is a server name or
// a selector: "*" (every server, including ones added later; it must be the
// only item) or "@tag" (every server carrying the tag now). Names and tags
// mix as a union; except: removes names from what the selectors reach.
type Access struct {
	User    string   `yaml:"user"`
	Group   string   `yaml:"group"`
	Servers []string `yaml:"servers"`
	Except  []string `yaml:"except"` // only valid with a selector in Servers
}
```

In `Config` add, after `Users []User` (`:66`):

```go
	Groups         []Group  `yaml:"groups"`
```

and, after the `blocked` line (`:87`), the private field:

```go
	members    map[string][]string       // group name -> members, as listed
```

In `validate` (`:128-136`) add one line after `c.validateServers()`:

```go
	errs = append(errs, c.validateGroups()...)
```

In `internal/config/warnings.go`, add to the const block (`:5-12`):

```go
	WarnEmptyGroup             = "empty_group"
```

Create `internal/config/groups.go`:

```go
package config

import "fmt"

// validateGroups checks groups: each name has tagShape and is unique, and
// every member is a known user, listed once. An empty group is valid with a
// warning, so revoking its last member never breaks the manifest. It records
// c.members for access: entries, every named group included so one bad name
// is reported once.
func (c *Config) validateGroups() []error {
	var errs []error
	users := make(map[string]bool, len(c.Users))
	for _, u := range c.Users {
		users[u.Name] = true
	}
	c.members = make(map[string][]string, len(c.Groups))
	for _, g := range c.Groups {
		if !tagShape.MatchString(g.Name) {
			errs = append(errs, fmt.Errorf("group %q: name is not valid: want lowercase letters, digits, '.', '_' or '-', starting with a letter or digit, at most 63 characters", g.Name))
		}
		if _, dup := c.members[g.Name]; dup {
			errs = append(errs, fmt.Errorf("duplicate group %q", g.Name))
			continue
		}
		c.members[g.Name] = g.Members
		errs = append(errs, memberErrors(g, users)...)
		if len(g.Members) == 0 {
			c.warn(ManifestWarning{Kind: WarnEmptyGroup, Message: fmt.Sprintf("group %q has no members; its grants add nothing", g.Name)})
		}
	}
	return errs
}

// memberErrors checks one group's members: each is a known user, listed once.
func memberErrors(g Group, users map[string]bool) []error {
	var errs []error
	seen := make(map[string]bool, len(g.Members))
	for _, m := range g.Members {
		switch {
		case !users[m]:
			errs = append(errs, fmt.Errorf("group %q: unknown member %q", g.Name, m))
		case seen[m]:
			errs = append(errs, fmt.Errorf("group %q: member %q is repeated", g.Name, m))
		}
		seen[m] = true
	}
	return errs
}
```

- [ ] **Step 4: Give `Access.Group` a sample.** `fill` sets every field, and a user plus a group would fail the exactly-one-of rule, so the sample is empty. In `cmd/sshepherd/schema_roundtrip_test.go:23` replace the `"Access"` line with:

```go
		// Group is "": fill sets every field, and a user plus a group would
		// fail exactly-one-of. TestAdoptRegenerateKeepsGroups proves a group
		// entry round-trips; Append has no groups parameter.
		"Access": {"User": "bob", "Group": "", "Servers": []string{"*"}, "Except": []string{"web-1"}},
```

- [ ] **Step 5: Run.**

Run: `GOTOOLCHAIN=go1.27.3 gofmt -w internal/config/config.go internal/config/groups.go && GOTOOLCHAIN=go1.27.3 go test ./internal/config ./cmd/sshepherd -run 'TestGroupValidation|TestEmptyGroupWarns|TestSchemaRoundTrip'`
Expected: PASS.

**docsDelta (README, lane `schema`):**

a. `README.md:249`, change `` `serial:` and `revoked:` (see [Revoked keys](#revoked-keys)). Unknown fields `` to `` `serial:`, `groups:` and `revoked:` (see [Groups](#groups) and [Revoked keys](#revoked-keys)). Unknown fields ``.

b. In the manifest sample, before `servers:` (`README.md:269`), add:

```yaml
groups:                                 # optional, see Groups
  - name: web-team
    description: docs only
    members: [alice]

```

and at the end of the sample's `access:` list (after `except: [ci]`, `README.md:289`), add:

```yaml

  - group: web-team                     # exactly one of user: / group:
    servers: ["@web"]
```

c. Add a new subsection after **Tags and selectors**, before **Per-server `authorized_keys_file`** (`README.md:348`):

````markdown
### Groups

```yaml
groups:
  - name: web-team
    description: docs only
    members: [alice, bob]
access:
  - group: web-team      # exactly one of user: / group:
    servers: ["@web"]
```

A group names a set of users. An `access:` entry with `group:` grants every member, exactly as one entry per member would; `servers:` and `except:` work as they do for a user entry. A group name follows the tag rules, `^[a-z0-9][a-z0-9._-]{0,62}$`. Every member must be a user in the manifest, listed once. A group with no members is valid and warns, kind `empty_group`: `group "web-team" has no members; its grants add nothing`, so revoking the last member never breaks the manifest. A warning never changes an exit code, except that `validate --strict` exits `1`. `adopt` and `import` never create a group. `adopt` keeps them; `adopt --merge` and `import --merge` leave them as they are; a fresh `import -o FILE --force` replaces the file without them.
````

d. In **Validation rules**, after the **Selectors in `access:`** bullet (`README.md:403-407`), add:

```markdown
- **Groups**: `group "Web": name is not valid: want lowercase letters, digits, '.', '_' or '-', starting with a letter or digit, at most 63 characters`;
  `duplicate group "web-team"`; `group "web-team": unknown member "zed"`; `group "web-team": member "alice" is repeated`.
- **An `access:` entry** has exactly one of `user:` and `group:`: `access[2]: set exactly one of user or group`.
  An unknown group is an error, like an unknown user: `access: unknown group "x"`. Messages about a group entry
  name the group: `access for group "web-team": unknown server "web-9"`.
```

e. At `README.md:1000-1001`, change `` `key_expired`, `wildcard_root` and `tombstone_blocks_grant`; ignore kinds you do not know. `` to `` `key_expired`, `wildcard_root`, `tombstone_blocks_grant` and `empty_group`; ignore kinds you do not know. ``.

---

### Task 2: an access entry names a user or a group

**Files:**
- Modify: `internal/config/groups.go`, `internal/config/config.go:374-475`
- Test: `internal/config/groups_test.go`

- [ ] **Step 1: Write the failing tests.** Append to `internal/config/groups_test.go`:

```go
func TestAccessEntrySubject(t *testing.T) {
	for _, tc := range []struct{ name, access, want string }{
		{"neither", "  - {servers: [web-1]}\n", "access[0]: set exactly one of user or group"},
		{"both", "  - {user: alice, group: web-team, servers: [web-1]}\n", "access[0]: set exactly one of user or group"},
		{"second entry index", "  - {user: alice, servers: [web-1]}\n  - {servers: [web-1]}\n", "access[1]: set exactly one of user or group"},
		{"unknown group", "  - {group: nope, servers: [web-1]}\n", `access: unknown group "nope"`},
		{"unknown user unchanged", "  - {user: zed, servers: [web-1]}\n", `access: unknown user "zed"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(groupFleet(t, webTeam, tc.access, "")))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestGroupEntryErrorsNameTheGroup: every access-entry message prints the
// group, never `access for ""` (spec S3b, "Error text").
func TestGroupEntryErrorsNameTheGroup(t *testing.T) {
	for _, tc := range []struct{ name, entry, want string }{
		{"unknown server", `servers: [web-9]`, `access for group "web-team": unknown server "web-9"`},
		{"unknown tag", `servers: ["@nope"]`, `access for group "web-team": unknown tag "@nope"`},
		{"wildcard not alone", `servers: ["*", web-1]`, `access for group "web-team": "*" must be the only servers entry`},
		{"except needs a selector", `servers: [web-1], except: [web-2]`, `access for group "web-team": except requires servers ["*"] or an @tag`},
		{"empty servers", `servers: []`, `access for group "web-team": servers is empty (grants no servers)`},
		{"selector in except", `servers: ["@web"], except: ["@db"]`, `access for group "web-team": except takes server names, not the selector "@db"`},
		{"unknown except", `servers: ["@web"], except: [web-9]`, `access for group "web-team": unknown except server "web-9"`},
		{"in both lists", `servers: ["@web", web-1], except: [web-1]`, `access for group "web-team": "web-1" is in both servers and except`},
		{"wildcard grants nothing", `servers: ["*"], except: [web-1, web-2, web-3, db-1]`, `access for group "web-team": wildcard grants no servers`},
		{"selectors grant nothing", `servers: ["@db"], except: [db-1]`, `access for group "web-team": selectors grant no servers after except`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(groupFleet(t, webTeam, "  - {group: web-team, "+tc.entry+"}\n", "")))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func desiredFPs(cfg *Config, server string) []string {
	var out []string
	for _, k := range cfg.DesiredFor(server) {
		out = append(out, k.Fingerprint)
	}
	return out
}

func TestGroupEntryGrantsEveryMember(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: [\"@web\"], except: [web-2]}\n", ""))
	for seed, want := range map[byte][]string{1: {"web-1", "web-3"}, 2: {"web-1", "web-3"}, 3: nil} {
		if got := grantedOn(t, cfg, seed); !reflect.DeepEqual(got, want) {
			t.Errorf("key %d granted on %v, want %v", seed, got, want)
		}
	}
}

// TestGroupGrantRenderOrder: access order, then member order inside an
// entry; a user reached twice is emitted once, at the first reach.
func TestGroupGrantRenderOrder(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, "  - {name: rev, members: [bob, alice]}\n",
		"  - {user: carol, servers: [web-1]}\n  - {group: rev, servers: [web-1]}\n  - {user: alice, servers: [web-1]}\n", ""))
	want := []string{fpOf(t, 4), fpOf(t, 3), fpOf(t, 2), fpOf(t, 1)}
	if got := desiredFPs(cfg, "web-1"); !reflect.DeepEqual(got, want) {
		t.Errorf("DesiredFor = %v\nwant %v", got, want)
	}
}

// TestGroupOperatorMemberRenderedOnce: the existing redundant-grant skip
// applies to an operator member.
func TestGroupOperatorMemberRenderedOnce(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, "  - {name: ops, members: [op, alice]}\n", "  - {group: ops, servers: [web-1]}\n", ""))
	if got, want := desiredFPs(cfg, "web-1"), []string{fpOf(t, 4), fpOf(t, 1)}; !reflect.DeepEqual(got, want) {
		t.Errorf("DesiredFor = %v\nwant %v", got, want)
	}
	if got := cfg.GrantCount(); got != 5 { // op on 4 servers, alice on 1
		t.Errorf("GrantCount = %d, want 5", got)
	}
}

func TestEmptyGroupEntryGrantsNothing(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, "  - {name: none, members: []}\n", "  - {group: none, servers: [web-1]}\n", ""))
	if got, want := desiredFPs(cfg, "web-1"), []string{fpOf(t, 4)}; !reflect.DeepEqual(got, want) {
		t.Errorf("DesiredFor = %v\nwant %v (the operator only)", got, want)
	}
}
```

- [ ] **Step 2: Run it to see it fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run 'TestAccessEntrySubject|TestGroupEntry|TestGroupGrantRenderOrder|TestGroupOperatorMember|TestEmptyGroupEntry'`
Expected: FAIL (`access: unknown user ""`; `access for ""`).

- [ ] **Step 3: Add the helpers.** Append to `internal/config/groups.go`:

```go
// entrySubjectError checks who access entry i grants to: exactly one of
// user: and group:, naming something that exists.
func (c *Config) entrySubjectError(i int, a Access, users map[string]bool) error {
	switch {
	case (a.User == "") == (a.Group == ""):
		return fmt.Errorf("access[%d]: set exactly one of user or group", i)
	case a.Group != "":
		if _, ok := c.members[a.Group]; !ok {
			return fmt.Errorf("access: unknown group %q", a.Group)
		}
	case !users[a.User]:
		return fmt.Errorf("access: unknown user %q", a.User)
	}
	return nil
}

// entryUsers lists whom access entry a grants to: its user, or its group's
// members in member order.
func (c *Config) entryUsers(a Access) []string {
	if a.Group != "" {
		return c.members[a.Group]
	}
	return []string{a.User}
}

// entryLabel names an access entry in messages: `"x"` for a user entry and
// `group "x"` for a group entry.
func entryLabel(a Access) string {
	if a.Group != "" {
		return fmt.Sprintf("group %q", a.Group)
	}
	return fmt.Sprintf("%q", a.User)
}
```

- [ ] **Step 4: Expand group entries.** In `internal/config/config.go`, replace the loop body of `validateAccess` (`:386-411`) with:

```go
	for i, a := range c.Access {
		if err := c.entrySubjectError(i, a, users); err != nil {
			errs = append(errs, err)
			continue
		}
		targets, tErrs := c.expandServers(a, servers)
		if len(tErrs) > 0 {
			errs = append(errs, tErrs...)
			continue
		}
		c.warnWildcardRoot(a, targets)
		who := c.entryUsers(a)
		for _, srv := range targets {
			if !servers[srv] {
				errs = append(errs, fmt.Errorf("access for %s: unknown server %q", entryLabel(a), srv))
				continue
			}
			if granted[srv] == nil {
				granted[srv] = make(map[string]bool)
			}
			for _, user := range who {
				if granted[srv][user] { // multiple entries union silently
					continue
				}
				granted[srv][user] = true
				c.grants[srv] = append(c.grants[srv], user)
			}
		}
	}
```

Replace the two error returns at the end of `expandServers` (`:440,442`) with:

```go
		return nil, []error{fmt.Errorf("access for %s: wildcard grants no servers", entryLabel(a))}
	}
	return nil, []error{fmt.Errorf("access for %s: selectors grant no servers after except", entryLabel(a))}
```

Replace `entryShape` (`:448-475`) with:

```go
func (c *Config) entryShape(a Access, servers map[string]bool) []error {
	if slices.Contains(a.Servers, "*") && len(a.Servers) != 1 {
		return []error{fmt.Errorf("access for %s: %q must be the only servers entry", entryLabel(a), "*")}
	}
	if len(a.Except) > 0 && !slices.ContainsFunc(a.Servers, IsSelector) {
		return []error{fmt.Errorf(`access for %s: except requires servers ["*"] or an @tag`, entryLabel(a))}
	}
	if len(a.Servers) == 0 {
		return []error{fmt.Errorf("access for %s: servers is empty (grants no servers)", entryLabel(a))}
	}
	var errs []error
	for _, item := range a.Servers {
		if isTagSelector(item) && !c.tagInUse(item) {
			errs = append(errs, fmt.Errorf("access for %s: unknown tag %q", entryLabel(a), item))
		}
	}
	for _, e := range a.Except { // duplicates are tolerated, like grants unioning
		switch {
		case isTagSelector(e):
			errs = append(errs, fmt.Errorf("access for %s: except takes server names, not the selector %q", entryLabel(a), e))
		case !servers[e]:
			errs = append(errs, fmt.Errorf("access for %s: unknown except server %q", entryLabel(a), e))
		case slices.Contains(a.Servers, e):
			errs = append(errs, fmt.Errorf("access for %s: %q is in both servers and except", entryLabel(a), e))
		}
	}
	return errs
}
```

- [ ] **Step 5: Run.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config`
Expected: PASS (every S3a `access for "x"` expectation still holds: `entryLabel` prints `%q` for a user).

No docsDelta beyond Task 1's.

---

### Task 3: `Covers` and `ExceptCarveOut` answer for members

**Files:**
- Modify: `internal/config/selector.go:71-72`, `internal/config/config.go:569-573, 586-590, 551-561, 577-584`, `internal/config/revoked.go:279-305, 373-376`
- Test: `internal/config/groups_test.go`

- [ ] **Step 1: Write the failing test.** Append to `internal/config/groups_test.go`:

```go
func TestGroupCoversAndCarveOut(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: [\"*\"], except: [web-2]}\n", ""))
	for _, tc := range []struct {
		user, server string
		want         bool
	}{
		{"alice", "web-1", true},
		{"bob", "db-1", true},
		{"alice", "web-2", false},
		{"alice", "future", true}, // a member gets every wildcard, future servers included
		{"carol", "web-1", false},
	} {
		if got := cfg.Covers(tc.user, tc.server); got != tc.want {
			t.Errorf("Covers(%s, %s) = %v, want %v", tc.user, tc.server, got, tc.want)
		}
	}
	if !cfg.ExceptCarveOut("alice", "web-2") || !cfg.ExceptCarveOut("bob", "web-2") {
		t.Error("a group entry's except: must carve out for every member")
	}
	if cfg.ExceptCarveOut("carol", "web-2") {
		t.Error("carol is no member; the group's except: is not hers")
	}
	tagged := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: [\"@web\"]}\n", ""))
	if tagged.Covers("alice", "future") {
		t.Error("an @tag never covers a server not in the manifest yet")
	}
}
```

- [ ] **Step 2: Run it to see it fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run TestGroupCoversAndCarveOut`
Expected: FAIL at `future` and at the carve-out (the raw scans compare `a.User`).

- [ ] **Step 3: Make `entryApplies` group-aware.** In `internal/config/selector.go`, replace `:71-72` with:

```go
// entryApplies reports whether access entry a grants to user: it names the
// user, or its group has the user as a member.
func (c *Config) entryApplies(a Access, user string) bool {
	if a.Group != "" {
		return slices.Contains(c.members[a.Group], user)
	}
	return a.User == user
}
```

In `internal/config/config.go`, `Covers` (`:570`) and `ExceptCarveOut` (`:587`) become `c.entryApplies(a, user)`. Add to `Covers`' comment (`:551-561`), before the operators paragraph:

```go
// The c.blocked check comes first because a group entry's "*" or literal
// name matches the raw scan below for a member a tombstone blocked.
//
```

and to `ExceptCarveOut`'s comment (`:577-584`), before its last paragraph:

```go
// A group entry's except: carves out for every member.
//
```

In `internal/config/revoked.go`, a group entry is never a direct grant, so the two callers that decide "direct" read `a.User`. Replace `accessConflicts`' guard (`:289-291`) with:

```go
		if a.User != t.User { // a group entry is blocked, never a conflict
			continue
		}
```

and `directlyGranted` (`:373-376`) with:

```go
// directlyGranted reports a user: entry of user reaching server by name or
// "*". A group entry never counts: it is always blocked (the table in the
// spec's "How selectors meet tombstones").
func (c *Config) directlyGranted(user, server string) bool {
	return slices.ContainsFunc(c.Access, func(a Access) bool { return a.User == user && entryDirect(a, server) })
}
```

Update `entryDirect`'s comment in `selector.go` (`:84`) to add `It is only ever asked about a user: entry.`

- [ ] **Step 4: Run.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config`
Expected: PASS.

---

### Task 4: a tombstone blocks a group-derived grant for one member only

**Files:**
- Modify: `internal/config/revoked.go:320-348, 378-389`
- Test: `internal/config/groups_test.go`

This task closes S3a's design gap 3: `Covers`' `c.blocked` guard is load-bearing from here on, and the `wildcard` and `literal` rows fail when it is removed.

- [ ] **Step 1: Write the failing tests.** Add `"slices"` to the imports of `internal/config/groups_test.go` and append:

```go
const aliceOffWeb1 = "revoked:\n  - {user: alice, servers: [web-1], date: 2026-11-08}\n"

const blockedAlice = `access[0]: "alice" is not granted "web-1" through group web-team: revoked[0] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`

func TestTombstoneBlocksOneGroupMember(t *testing.T) {
	for _, tc := range []struct{ name, servers string }{
		{"tag", `["@web"]`},
		{"wildcard", `["*"]`},         // kills Covers without its c.blocked check
		{"literal", `[web-1, web-2]`}, // same, and proves a group name is not direct
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: "+tc.servers+"}\n", aliceOffWeb1))
			if hasKey(t, cfg, 1, "web-1") {
				t.Error("alice's key is still rendered on web-1")
			}
			if !hasKey(t, cfg, 2, "web-1") || !hasKey(t, cfg, 1, "web-2") {
				t.Errorf("other members and servers lost the grant: web-1 %v, alice %v", desiredFPs(cfg, "web-1"), grantedOn(t, cfg, 1))
			}
			if cfg.Covers("alice", "web-1") {
				t.Error("Covers(alice, web-1) = true: c.blocked must win over the raw scan")
			}
			if !cfg.Covers("bob", "web-1") {
				t.Error("Covers(bob, web-1) = false: only alice is blocked")
			}
			if _, ok := cfg.AccessRevoked("alice", "web-1"); !ok {
				t.Error("AccessRevoked must still answer for a blocked pair")
			}
			if len(cfg.Conflicts()) != 0 {
				t.Errorf("Conflicts = %+v, want none: a blocked grant is not a conflict", cfg.Conflicts())
			}
			if !slices.Contains(cfg.Warnings, blockedAlice) {
				t.Errorf("Warnings = %q\nwant %q", cfg.Warnings, blockedAlice)
			}
			i := slices.IndexFunc(cfg.ManifestWarnings, func(w ManifestWarning) bool { return w.Message == blockedAlice })
			if i < 0 {
				t.Fatalf("ManifestWarnings = %+v", cfg.ManifestWarnings)
			}
			w := cfg.ManifestWarnings[i]
			if w.Kind != WarnTombstoneBlocksGrant || w.RevokedIndex == nil || *w.RevokedIndex != 0 || w.User != "alice" || w.Server != "web-1" {
				t.Errorf("warning = %+v", w)
			}
		})
	}
}

// TestGroupDirectGrantStaysConflict: a user: entry naming the server is a W4
// conflict even beside a group entry, the pair is not blocked, and only the
// user: entry is named.
func TestGroupDirectGrantStaysConflict(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: [web-1]}\n  - {user: alice, servers: [web-1]}\n", aliceOffWeb1))
	if !hasKey(t, cfg, 1, "web-1") {
		t.Error("a direct grant over a tombstone is a conflict, not a block")
	}
	cs := cfg.Conflicts()
	if len(cs) != 1 || cs[0].Kind != ConflictRevokedAccess || !strings.Contains(cs[0].Message, `is granted "web-1" by access[1]`) {
		t.Errorf("Conflicts = %+v, want one naming access[1]", cs)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("Warnings = %q, want none", cfg.Warnings)
	}
}

// TestGroupAndTagEntriesEachWarn: one warning per (entry, user, server).
func TestGroupAndTagEntriesEachWarn(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: [\"@web\"]}\n  - {user: alice, servers: [\"@web\"]}\n", aliceOffWeb1))
	want := []string{blockedAlice, `access[1]: "alice" is not granted "web-1" through @web: revoked[0] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`}
	if !reflect.DeepEqual(cfg.Warnings, want) {
		t.Errorf("Warnings = %q\nwant %q", cfg.Warnings, want)
	}
	if hasKey(t, cfg, 1, "web-1") || len(cfg.Conflicts()) != 0 {
		t.Errorf("web-1 = %v, conflicts = %+v", desiredFPs(cfg, "web-1"), cfg.Conflicts())
	}
}

func TestOperatorGroupMemberBlockedNoWarning(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, "  - {name: ops, members: [op]}\n", "  - {group: ops, servers: [web-1]}\n",
		"revoked:\n  - {user: op, servers: [web-1], date: 2026-11-08}\n"))
	if !hasKey(t, cfg, 4, "web-1") {
		t.Error("the implicit operator grant must still install the key")
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("Warnings = %q, want none: 'is not granted' would be false", cfg.Warnings)
	}
}

// TestKeyTombstoneCoversGroupGrant: serversRendering reads c.grants, so a key
// tombstone's conflict names the servers a group grant renders the key on.
func TestKeyTombstoneCoversGroupGrant(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: [\"@web\"]}\n",
		"revoked:\n  - {fingerprint: "+fpOf(t, 1)+", user: alice, date: 2026-11-08}\n"))
	cs := cfg.Conflicts()
	if len(cs) != 1 || cs[0].Kind != ConflictRevokedKey || !reflect.DeepEqual(cs[0].Servers, []string{"web-1", "web-2", "web-3"}) {
		t.Errorf("Conflicts = %+v", cs)
	}
}

func TestBlockedGroupPairLeavesConflictsOfOthersAlone(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: [\"@web\"]}\n  - {user: bob, servers: [web-1]}\n",
		"revoked:\n  - {user: bob, servers: [web-1], date: 2026-11-08}\n  - {user: alice, servers: [web-2], date: 2026-11-08}\n"))
	if !hasKey(t, cfg, 2, "web-1") || hasKey(t, cfg, 1, "web-2") {
		t.Errorf("bob on web-1 is a conflict (kept), alice on web-2 is blocked: web-1 %v, web-2 %v", desiredFPs(cfg, "web-1"), desiredFPs(cfg, "web-2"))
	}
	if cs := cfg.Conflicts(); len(cs) != 1 || cs[0].User != "bob" {
		t.Errorf("Conflicts = %+v", cs)
	}
}
```

`TestGroupDirectGrantStaysConflict` and `TestOperatorGroupMemberBlockedNoWarning` pass already at the Task 3 state: Task 3 made `accessConflicts` read `a.User`, the group entry is not yet blocked, and the operator's key still renders with no warning. They pin behaviour Step 3 must not lose, so Step 2 names them apart from the others. Task 7's mutant 6 is what proves the operator test can fail.

- [ ] **Step 2: Run it to see it fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run 'TestTombstoneBlocksOneGroupMember|TestGroupDirectGrantStaysConflict|TestGroupAndTagEntriesEachWarn|TestOperatorGroupMember|TestKeyTombstoneCoversGroupGrant|TestBlockedGroupPair'`
Expected: FAIL, except `TestGroupDirectGrantStaysConflict`, `TestKeyTombstoneCoversGroupGrant` and `TestOperatorGroupMemberBlockedNoWarning` (already correct at the Task 3 state): `blockTombstoned` loops `a.User`, which is empty for a group entry, so alice keeps web-1.

- [ ] **Step 3: Block per member.** In `internal/config/revoked.go`, replace `blockTombstoned` (`:320-348`) with:

```go
// blockTombstoned drops every (user, server) grant an access tombstone
// covers and no user: entry reaches directly, so the tombstone acts as an
// implicit except: for that user alone: other members of a group keep the
// grant (spec "How selectors meet tombstones"). The grant leaves c.grants, so
// DesiredFor, apply.Affected and every report see no access; c.blocked keeps
// it out of Covers and entryServers. AccessRevoked still answers, which keeps
// adopt, reconcile, revoke's D1c note and audit's D1d label working. Each
// (entry, user, server) warns, unless the implicit operator grant still
// installs the key.
func (c *Config) blockTombstoned() {
	c.blocked = make(map[grantPair]bool)
	revoked := c.latestAccessTombstones()
	for n, a := range c.Access {
		for _, user := range c.entryUsers(a) {
			if len(revoked[user]) > 0 {
				c.blockEntry(n, a, user, revoked[user])
			}
		}
	}
}

// blockEntry applies blockTombstoned to entry n for one of its users. gone
// maps each server the user lost to its latest tombstone's index.
func (c *Config) blockEntry(n int, a Access, user string, gone map[string]int) {
	for _, s := range c.Servers {
		m, lost := gone[s.Name]
		if !lost || !entryCovers(a, s) || c.directlyGranted(user, s.Name) {
			continue
		}
		c.blocked[grantPair{user, s.Name}] = true
		c.grants[s.Name] = slices.DeleteFunc(c.grants[s.Name], func(u string) bool { return u == user })
		if !slices.Contains(c.operators, user) {
			c.warnBlocked(n, m, a, user, s)
		}
	}
}
```

Replace `warnBlocked` (`:378-389`) with:

```go
func (c *Config) warnBlocked(n, m int, a Access, user string, s Server) {
	msg := fmt.Sprintf(`access[%d]: %q is not granted %q through %s: revoked[%d] removed that access (%s); delete the revoked: entry to restore it deliberately`,
		n, user, s.Name, grantVia(a, s), m, c.Tombstones[m].Date)
	c.warn(ManifestWarning{Kind: WarnTombstoneBlocksGrant, RevokedIndex: &m, User: user, Server: s.Name, Message: msg})
}

// grantVia names how entry a reaches s in a blocked-grant warning: its group,
// or the first selector that reaches s.
func grantVia(a Access, s Server) string {
	if a.Group != "" {
		return "group " + a.Group
	}
	for _, item := range a.Servers {
		if SelectorMatches(item, s) {
			return item
		}
	}
	return ""
}
```

- [ ] **Step 4: Run.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config`
Expected: PASS, including every S3a tombstone test in `selector_test.go`.

**docsDelta (README, lane `schema`).** Append to **Revoked keys** (`README.md:520`, after the paragraph ending `no warning prints for it.`):

```markdown
A grant through a group is blocked for that member only; the other members keep it. Every kind of group entry is blocked, even one naming the server, because a group is not a personal grant:
`access[0]: "alice" is not granted "web-1" through group web-team: revoked[0] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`.
A `user:` entry for the same user and server still conflicts, even beside a group entry. A key entry in `revoked:` covers every server a group grant renders that key on.
```

---

### Task 5: `wildcard_root` names a group entry

**Files:**
- Modify: `internal/config/config.go:482-505`
- Test: `internal/config/groups_test.go`

- [ ] **Step 1: Write the failing test.** Append to `internal/config/groups_test.go`:

```go
// TestWildcardRootNamesTheGroup: a group "*" entry reaching a root account
// warns once per entry (spec S3b), an @tag does not.
func TestWildcardRootNamesTheGroup(t *testing.T) {
	const want = `access for group "web-team": servers ["*"] includes the root account on web-3; list the servers or use an @tag that excludes root accounts`
	cfg := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: [\"*\"]}\n", ""))
	if !reflect.DeepEqual(cfg.Warnings, []string{want}) {
		t.Errorf("Warnings = %q\nwant %q", cfg.Warnings, want)
	}
	if cfg.ManifestWarnings[0].Kind != WarnWildcardRoot || cfg.ManifestWarnings[0].User != "" {
		t.Errorf("warning = %+v", cfg.ManifestWarnings[0])
	}
	if tagged := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: [\"@web\"]}\n", "")); len(tagged.Warnings) != 0 {
		t.Errorf("an @tag warned: %q", tagged.Warnings)
	}
	// Four root accounts: the design's literal text, which the README sample
	// copies.
	rootFleet := `users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
groups:
  - {name: web-team, members: [alice]}
servers:
  - {name: web-1, host: 10.0.1.1, user: root}
  - {name: web-2, host: 10.0.1.2, user: root}
  - {name: web-3, host: 10.0.1.3, user: root}
  - {name: web-4, host: 10.0.1.4, user: root}
access:
  - {group: web-team, servers: ["*"]}
`
	const wantMore = `access for group "web-team": servers ["*"] includes the root account on web-1 and 3 more; list the servers or use an @tag that excludes root accounts`
	if got := mustParse(t, rootFleet).Warnings; !reflect.DeepEqual(got, []string{wantMore}) {
		t.Errorf("Warnings = %q\nwant %q", got, wantMore)
	}
	// An empty or all-operator group warns too: the grant stands for whoever
	// joins later (design gap 6). The empty group's own warning is another
	// kind, so only wildcard_root is compared.
	for _, tc := range []struct{ name, groups, group string }{
		{"empty group", "  - {name: none, members: []}\n", "none"},
		{"all-operator group", "  - {name: ops, members: [op]}\n", "ops"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grouped := mustParse(t, groupFleet(t, tc.groups, "  - {group: "+tc.group+", servers: [\"*\"]}\n", ""))
			var gotRoot []string
			for _, w := range grouped.ManifestWarnings {
				if w.Kind == WarnWildcardRoot {
					gotRoot = append(gotRoot, w.Message)
				}
			}
			wantRoot := `access for group "` + tc.group + `": servers ["*"] includes the root account on web-3; list the servers or use an @tag that excludes root accounts`
			if !reflect.DeepEqual(gotRoot, []string{wantRoot}) {
				t.Errorf("wildcard_root warnings = %q\nwant one %q", gotRoot, wantRoot)
			}
		})
	}
}
```

- [ ] **Step 2: Run it to see it fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run TestWildcardRootNamesTheGroup`
Expected: FAIL (the warning reads `access for ""`).

- [ ] **Step 3: Use the label.** In `internal/config/config.go`, in `warnWildcardRoot` replace the `c.warn` call (`:502-504`) with:

```go
	c.warn(ManifestWarning{Kind: WarnWildcardRoot, Message: fmt.Sprintf(
		`access for %s: servers ["*"] includes the root account on %s; list the servers or use an @tag that excludes root accounts`,
		entryLabel(a), where)})
```

and extend its comment (`:482-484`) with:

```go
// A group entry always warns: its members are not operators by default and
// its grant stands for whoever joins later.
```

- [ ] **Step 4: Run.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config`
Expected: PASS.

**docsDelta (README, lane `schema`).** Append to **Wildcard access**, after `changes an exit code, except that `validate --strict` exits `1`.` (`README.md:323`):

```markdown
A group entry with `servers: ["*"]` warns the same way, naming the group, whoever its members are:
`access for group "web-team": servers ["*"] includes the root account on web-1 and 3 more; list the servers or use an @tag that excludes root accounts`.
```

The sample line is the `wantMore` expectation of `TestWildcardRootNamesTheGroup`, copied byte for byte (CLAUDE.md: sample output must be real). If the test's text changes, re-copy it.

---

### Task 6: the consumers see groups only through `DesiredFor`, `Covers` and `AccessRevoked`

**Files:**
- Create: `internal/apply/groups_equivalence_test.go`, `internal/adopt/groups_test.go`, `internal/reconcile/groups_test.go`, `internal/audit/groups_test.go`

These tests pin behaviour already present after Tasks 1-5, so each passes when first run. Prove each can fail: apply its mutant for one run, see the test fail, revert, and report the result with Task 7's table.

| Test | Mutant |
|---|---|
| `TestGroupManifestMatchesFlatTwin` | `validateAccess` iterates `who[:min(1, len(who))]` (killed in review) |
| `TestBuildGroupGrantIsNotDrift` | the same mutant, through the second member `dee` (not run yet; `Build` reads audit's `Unauthorized`, so `dee`'s key becomes an extension) |
| `TestReconcileGroupGrantCoversMember` | the same mutant, through the second member `dee` on an `@db` entry (not run yet; a `*` entry would be answered by `Covers`' raw scan and hide it) |
| `TestBuildExceptOnGroupEntryNotExtended`, `TestReconcileExceptOnGroupEntryNotExtended` | `ExceptCarveOut` reads `a.User == user` in place of `c.entryApplies(a, user)` (killed in review) |
| `TestBuildHonoursBlockedGroupGrant`, `TestBlockedGroupGrantIsDrift` | `blockTombstoned` iterates `[]string{a.User}` (Task 7's mutant 5) |
| `TestReconcileHonoursBlockedGroupGrant` | delete `Covers`' `c.blocked` check (Task 7's mutant 1) |
| `TestReconcileGroupWildcardAbsorbsNewServer` | `entryApplies` drops the group branch (Task 7's mutant 2; `db-9` is in no grant, so only the raw scan can answer) |

- [ ] **Step 1: The equivalence test.** Create `internal/apply/groups_equivalence_test.go`:

```go
package apply

import (
	"reflect"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func groupEquivFleet(t *testing.T, groups, access, extra string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 3) + `"]}
groups:
` + groups + `servers:
  - {name: web-1, host: 10.0.1.1, user: deploy, tags: [prod, web]}
  - {name: web-2, host: 10.0.1.2, user: deploy, tags: [prod, web]}
  - {name: db-1, host: 10.0.2.1, user: deploy, tags: [prod, db]}
  - {name: ci, host: 10.0.3.1, user: git}
access:
` + access + extra))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cfg
}

// TestGroupManifestMatchesFlatTwin: a group entry expands to one grant per
// member inside validateAccess, so a grouped manifest and its hand-flattened
// twin must give every consumer the same answer: DesiredFor per server and
// Affected from a common starting point (spec S3b, equivalence property).
func TestGroupManifestMatchesFlatTwin(t *testing.T) {
	const team = "  - {name: team, members: [alice, bob]}\n"
	const blocked = "revoked:\n  - {user: alice, servers: [web-1], date: 2026-11-08}\n"
	for _, tc := range []struct {
		name, groups, grouped, flat, extra string
	}{
		{"one group", team, "  - {group: team, servers: [web-1, ci]}\n",
			"  - {user: alice, servers: [web-1, ci]}\n  - {user: bob, servers: [web-1, ci]}\n", ""},
		{"tag and except", team, "  - {group: team, servers: [\"@prod\"], except: [web-2]}\n",
			"  - {user: alice, servers: [web-1, db-1]}\n  - {user: bob, servers: [web-1, db-1]}\n", ""},
		{"wildcard", team, "  - {group: team, servers: [\"*\"], except: [ci]}\n",
			"  - {user: alice, servers: [web-1, web-2, db-1]}\n  - {user: bob, servers: [web-1, web-2, db-1]}\n", ""},
		{"member order", "  - {name: team, members: [bob, alice]}\n", "  - {group: team, servers: [web-1]}\n",
			"  - {user: bob, servers: [web-1]}\n  - {user: alice, servers: [web-1]}\n", ""},
		{"beside a direct grant", team, "  - {user: alice, servers: [ci]}\n  - {group: team, servers: [web-1]}\n",
			"  - {user: alice, servers: [ci]}\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [web-1]}\n", ""},
		{"blocked for one member", team, "  - {group: team, servers: [\"@web\"]}\n",
			"  - {user: alice, servers: [web-2]}\n  - {user: bob, servers: [web-1, web-2]}\n", blocked},
		{"operator member", "  - {name: team, members: [op, alice]}\n", "  - {group: team, servers: [web-1]}\n",
			"  - {user: op, servers: [web-1]}\n  - {user: alice, servers: [web-1]}\n", ""},
		{"empty group", "  - {name: none, members: []}\n", "  - {group: none, servers: [web-1]}\n", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grouped, flat := groupEquivFleet(t, tc.groups, tc.grouped, tc.extra), groupEquivFleet(t, "", tc.flat, tc.extra)
			before := groupEquivFleet(t, "", "", tc.extra)
			for _, s := range grouped.Servers {
				if got, want := fingerprints(grouped.DesiredFor(s.Name)), fingerprints(flat.DesiredFor(s.Name)); !reflect.DeepEqual(got, want) {
					t.Errorf("DesiredFor(%s) = %v\nflat twin      = %v", s.Name, got, want)
				}
			}
			if got, want := Affected(before, grouped), Affected(before, flat); !reflect.DeepEqual(got, want) {
				t.Errorf("Affected = %+v\nflat twin = %+v", got, want)
			}
			if got := Affected(flat, grouped); len(got.Servers) != 0 {
				t.Errorf("Affected(flat, grouped) = %+v, want none", got)
			}
		})
	}
}
```

`fingerprints` is `internal/apply/tags_equivalence_test.go:33`.

- [ ] **Step 2: adopt never re-extends a member.** Create `internal/adopt/groups_test.go`:

```go
package adopt

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func groupAdoptCfg(t *testing.T, access, extra string) *config.Config {
	t.Helper()
	return parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: bob, keys: ["`+testkeys.Line(t, 2)+`"]}
  - {name: dee, keys: ["`+testkeys.Line(t, 3)+`"]}
groups:
  - {name: dba, members: [bob, dee]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy, tags: [db]}
  - {name: db-2, host: 10.0.0.4, user: deploy, tags: [db]}
access:
  - `+access+"\n"+extra)
}

// TestBuildHonoursBlockedGroupGrant: a tombstone blocks bob's group grant on
// db-1 and his key is still installed there. Adopt must not re-extend him
// (AccessRevoked still answers for a blocked pair).
func TestBuildHonoursBlockedGroupGrant(t *testing.T) {
	cfg := groupAdoptCfg(t, `{group: dba, servers: ["*"]}`, "revoked:\n  - {user: bob, servers: [db-1], date: 2026-11-08}\n")
	both := fleet.ReadResult{Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n")}
	r := &fakeReader{byName: map[string]fleet.ReadResult{"db-1": both, "db-2": both}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Extensions) != 0 || len(p.NewUsers) != 0 {
		t.Fatalf("plan = %+v, want db-1 not re-granted", p)
	}
	want := "key " + fpOf(t, 2) + ` of "bob" found on "db-1", whose access was revoked (2026-11-08) — not re-granted; audit flags this drift`
	if len(p.Warnings) != 1 || p.Warnings[0].Message != want || p.Warnings[0].Kind != WarnRevokedAccessSkipped {
		t.Errorf("Warnings = %+v\nwant [%q]", p.Warnings, want)
	}
}

// TestBuildExceptOnGroupEntryNotExtended: a group entry's except: excludes
// every member.
func TestBuildExceptOnGroupEntryNotExtended(t *testing.T) {
	cfg := groupAdoptCfg(t, `{group: dba, servers: ["@db"], except: [db-1]}`, "")
	both := fleet.ReadResult{Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n")}
	r := &fakeReader{byName: map[string]fleet.ReadResult{"db-1": both, "db-2": both}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Extensions) != 0 {
		t.Fatalf("Extensions = %+v, want none", p.Extensions)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0].Message, "their except: list deliberately excludes") {
		t.Errorf("Warnings = %+v", p.Warnings)
	}
}

// TestBuildGroupGrantIsNotDrift: every member's key on a server the group
// reaches is granted, so nothing is extended and nothing warns. dee is the
// second member, so a grant that expanded only the first would extend her.
func TestBuildGroupGrantIsNotDrift(t *testing.T) {
	cfg := groupAdoptCfg(t, `{group: dba, servers: [db-1, db-2]}`, "")
	every := fleet.ReadResult{Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n" + testkeys.Line(t, 3) + "\n")}
	r := &fakeReader{byName: map[string]fleet.ReadResult{"db-1": every, "db-2": every}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Extensions) != 0 || len(p.NewUsers) != 0 || len(p.Warnings) != 0 {
		t.Errorf("plan = %+v, want nothing", p)
	}
}
```

- [ ] **Step 3: reconcile.** Create `internal/reconcile/groups_test.go`:

```go
package reconcile

import (
	"testing"

	"github.com/javadh75/SSHepherd/internal/identity"
	"github.com/javadh75/SSHepherd/internal/sshcfg"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// groupCfg: bob (k4) is in dba, which holds "*" minus db-2, and a tombstone
// blocks bob on db-1.
func groupCfg(t *testing.T) string {
	t.Helper()
	return `
users:
  - {name: bob, keys: ["` + testkeys.Line(t, 4) + `"]}
groups:
  - {name: dba, members: [bob]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy, tags: [db]}
  - {name: db-2, host: 10.0.0.4, user: deploy, tags: [db]}
  - {name: db-3, host: 10.0.0.5, user: deploy, tags: [db]}
access:
  - {group: dba, servers: ["*"], except: [db-2]}
revoked:
  - {user: bob, servers: [db-1], date: 2026-11-08}
`
}

func bobOn(t *testing.T, servers ...string) []identity.User {
	t.Helper()
	return []identity.User{{Name: "bob", Source: "~/.ssh/id_bob", Key: testkeys.Line(t, 4), Servers: servers}}
}

// TestReconcileHonoursBlockedGroupGrant also kills Covers without its
// c.blocked check: the raw "*" scan would answer true and skip the
// tombstone's warning.
func TestReconcileHonoursBlockedGroupGrant(t *testing.T) {
	p := mustBuild(t, parseCfg(t, groupCfg(t)), nil, bobOn(t, "db-1"))
	if len(p.Extensions) != 0 {
		t.Fatalf("Extensions = %+v, want none", p.Extensions)
	}
	wantContains(t, "Warnings", messages(p.Warnings),
		"key "+mustFP(t, testkeys.Line(t, 4))+` of "bob" found on "db-1", whose access was revoked (2026-11-08) — not re-granted; audit flags this drift`)
}

func TestReconcileExceptOnGroupEntryNotExtended(t *testing.T) {
	p := mustBuild(t, parseCfg(t, groupCfg(t)), nil, bobOn(t, "db-2"))
	if len(p.Extensions) != 0 {
		t.Fatalf("Extensions = %+v, want none", p.Extensions)
	}
	wantContains(t, "Warnings", messages(p.Warnings), "which their except: list deliberately excludes")
}

func TestReconcileGroupGrantCoversMember(t *testing.T) {
	p := mustBuild(t, parseCfg(t, groupCfg(t)), nil, bobOn(t, "db-3"))
	if len(p.Extensions) != 0 || len(p.Warnings) != 0 {
		t.Errorf("plan = %+v, want the group grant to cover bob", p)
	}
	// dee is the second member, on an @tag: Covers' raw scan cannot answer for
	// a tagless server, so this needs the expansion to reach every member.
	tagged := `
users:
  - {name: bob, keys: ["` + testkeys.Line(t, 4) + `"]}
  - {name: dee, keys: ["` + testkeys.Line(t, 5) + `"]}
groups:
  - {name: dba, members: [bob, dee]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy, tags: [db]}
access:
  - {group: dba, servers: ["@db"]}
`
	dee := []identity.User{{Name: "dee", Source: "~/.ssh/id_dee", Key: testkeys.Line(t, 5), Servers: []string{"db-1"}}}
	p = mustBuild(t, parseCfg(t, tagged), nil, dee)
	if len(p.Extensions) != 0 || len(p.Warnings) != 0 {
		t.Errorf("plan = %+v, want the group grant to cover dee", p)
	}
}

// TestReconcileGroupWildcardAbsorbsNewServer: "*" covers a server the
// manifest does not have yet, for a member too; an @tag does not.
func TestReconcileGroupWildcardAbsorbsNewServer(t *testing.T) {
	hosts := []sshcfg.Host{{Alias: "db-9", HostName: "10.0.0.9", User: "deploy"}}
	p := mustBuild(t, parseCfg(t, groupCfg(t)), hosts, bobOn(t, "db-9"))
	if len(p.Extensions) != 0 {
		t.Errorf("Extensions = %+v, want the wildcard to absorb db-9", p.Extensions)
	}
	tagged := `
users:
  - {name: bob, keys: ["` + testkeys.Line(t, 4) + `"]}
groups:
  - {name: dba, members: [bob]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy, tags: [db]}
access:
  - {group: dba, servers: ["@db"]}
`
	p = mustBuild(t, parseCfg(t, tagged), hosts, bobOn(t, "db-9"))
	if len(p.Extensions) != 1 || p.Extensions[0].User != "bob" || p.Extensions[0].Servers[0] != "db-9" {
		t.Errorf("Extensions = %+v, want bob extended to db-9 by name", p.Extensions)
	}
}
```

- [ ] **Step 4: audit's D1d label.** Create `internal/audit/groups_test.go`:

```go
package audit

import (
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestBlockedGroupGrantIsDrift (D1d): bob's group grant over web-2 is blocked
// by a tombstone. His key still on web-2 is the "access revoked" drift, with
// the same label and exit 1 as a removed literal grant.
func TestBlockedGroupGrantIsDrift(t *testing.T) {
	cfg, err := config.Parse([]byte(`serial: 7
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 3) + `"]}
groups:
  - {name: ops, members: [bob]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}
  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}
access:
  - {user: alice, servers: [web-1, web-2]}
  - {group: ops, servers: ["@web"]}
revoked:
  - {user: bob, servers: [web-2], date: 2026-11-08}
`))
	if err != nil {
		t.Fatal(err)
	}
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(7), []byte{1, 2, 3}, []byte{1, 2, 3}))
	if s := statusOf(cfg, res[1]); s != statusDrift {
		t.Errorf("web-2 status = %s, want drift", s)
	}
	if code := ExitCode(cfg, res); code != 1 {
		t.Errorf("ExitCode = %d, want 1", code)
	}
	if label := unauthorizedLabel(cfg, "web-2", res[1].Diff.Unauthorized[0]); label != "bob (access revoked 2026-11-08)" {
		t.Errorf("label = %q", label)
	}
}
```

- [ ] **Step 5: Run.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply ./internal/adopt ./internal/reconcile ./internal/audit`
Expected: PASS.

---

### Task 7: fuzz seeds and oracles; mutation run; hand back

**Files:**
- Modify: `internal/config/fuzz_test.go:22-76, 109-113`

- [ ] **Step 1: Seeds.** `FuzzLoad`'s committed corpus already holds the 16-entry maximum, so these go in `f.Add` only. In `internal/config/fuzz_test.go`, add to the `seeds` slice, before its closing `}` (`:76`):

```go
		// groups: a member blocked by a tombstone, an empty group, bad shapes
		`
users:
  - {name: alice, keys: ["` + k1 + `"]}
  - {name: bob, keys: ["` + k2 + `"]}
groups:
  - {name: team, description: d, members: [alice, bob]}
  - {name: empty, members: []}
servers:
  - {name: s1, host: h1, user: root, tags: [prod]}
  - {name: s2, host: h2, user: u, tags: [prod]}
access:
  - {group: team, servers: ["*"], except: [s2]}
  - {group: empty, servers: [s1]}
  - {user: bob, servers: ["@prod"]}
revoked:
  - {user: alice, servers: [s1], date: 2026-11-08}
`,
		"groups:\n  - {name: Bad, members: [x, x]}\n  - {name: Bad}\naccess:\n  - {user: a, group: b, servers: []}\n  - {servers: [s]}\n  - {group: nope, servers: [s]}\n",
```

- [ ] **Step 2: Oracles.** After the `for pair := range cfg.blocked` loop (`:109-113`), add:

```go
		for _, g := range cfg.Groups {
			if !tagShape.MatchString(g.Name) {
				t.Fatalf("accepted group name %q", g.Name)
			}
			for _, m := range g.Members {
				if !slices.ContainsFunc(cfg.Users, func(u User) bool { return u.Name == m }) {
					t.Fatalf("accepted unknown member %q in group %q", m, g.Name)
				}
			}
		}
		for _, a := range cfg.Access {
			if (a.User == "") == (a.Group == "") {
				t.Fatalf("accepted access entry %+v with neither or both of user and group", a)
			}
		}
```

- [ ] **Step 3: Run everything in the lane, plus a short fuzz.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config ./internal/apply ./internal/adopt ./internal/reconcile ./internal/audit ./cmd/sshepherd && GOTOOLCHAIN=go1.27.3 go test ./internal/config -run '^$' -fuzz '^FuzzLoad$' -fuzztime 20s`
Expected: PASS; the fuzz run ends with no new failure.

- [ ] **Step 4: Mutation run; it must finish before you report.** Apply each mutant alone, run the named test, record killed or survived, revert. Report the table.

| # | Mutant (file) | Killed by |
|---|---|---|
| 1 | delete the `c.blocked` check in `Covers` (`config.go`) | `TestTombstoneBlocksOneGroupMember` rows `wildcard`, `literal`; `TestReconcileHonoursBlockedGroupGrant` |
| 2 | `entryApplies`: drop the group branch (`selector.go`) | `TestGroupCoversAndCarveOut`, `future` row |
| 3 | `directlyGranted`: `c.entryApplies(a, user) && entryDirect(a, server)` (`revoked.go`) | `TestTombstoneBlocksOneGroupMember` row `literal` |
| 4 | `accessConflicts`: `!c.entryApplies(a, t.User)` as the guard | `TestGroupDirectGrantStaysConflict` (a second conflict, naming `access[0]`) |
| 5 | `blockTombstoned`: iterate `[]string{a.User}` | `TestTombstoneBlocksOneGroupMember` |
| 6 | `blockEntry`: drop the `slices.Contains(c.operators, user)` guard | `TestOperatorGroupMemberBlockedNoWarning` |
| 7 | `grantVia`: drop the group branch | `TestTombstoneBlocksOneGroupMember` |
| 8 | `validateGroups`: drop the `tagShape` check | `TestGroupValidation` |
| 9 | `validateGroups`: drop the empty warning | `TestEmptyGroupWarns` |
| 10 | `memberErrors`: drop the `seen` case | `TestGroupValidation`, `repeated member` |
| 11 | `entrySubjectError`: `a.User == "" && a.Group == ""` only | `TestAccessEntrySubject`, `both` |
| 12 | `entryLabel`: always `%q` of `a.User` | `TestGroupEntryErrorsNameTheGroup` |
| 13 | `validateAccess`: iterate `who[:min(1, len(who))]` | `TestGroupEntryGrantsEveryMember` |
| 14 | `warnWildcardRoot`: format `%q` with `a.User` instead of `entryLabel(a)` | `TestWildcardRootNamesTheGroup` |
| 15 | `warnWildcardRoot`: return early when no member is a non-operator (`a.Group != "" && !slices.ContainsFunc(c.members[a.Group], func(m string) bool { return !slices.Contains(c.operators, m) })`) | `TestWildcardRootNamesTheGroup`, rows `empty group` and `all-operator group` |

- [ ] **Step 5: Hand back.** `make check`. No lane test reads a README line this slice changes, so no gate-only README edit is needed. Report the docsDelta of Tasks 1, 4 and 5 and the `schema` CLAUDE.md paragraph below. Unstage everything outside the lane's globs and write the patch.

**docsDelta (CLAUDE.md, lane `schema`).** Append after the paragraph that ends `` `config.ServerNameIssue`), so a generated manifest always loads. ``:

```markdown
**User groups** (P10 S3b, D20b, PRD-4; section S3b of
`docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`, planned in
`docs/superpowers/plans/2026-11-09-p10-s3b-user-groups.md`): `groups:` (name in tag shape, members
known users, listed once; an empty group warns, kind `empty_group`) and `access: - group: X`
(exactly one of `user:`/`group:`) expand to one grant per member inside `validateAccess`, so
`c.grants`, `DesiredFor` and `apply.Affected` keep their shape (`TestGroupManifestMatchesFlatTwin`
is the equivalence test). `entryApplies` answers for membership; `Covers` and `ExceptCarveOut` read
it, so a group's `except:` carves out for every member. A group entry is never direct:
`directlyGranted` and `accessConflicts` read `a.User`, so a tombstone over any group grant is
blocked for that member only (`blockEntry`, `tombstone_blocks_grant`), and `Covers`' `c.blocked`
check is load-bearing (a group `*` or literal matches its raw scan).
```

---

## Round 2 — lane `editor` (Tasks 8–14)

Owns: `internal/manifest/*`, `internal/config/group_reach.go`, `internal/config/group_reach_test.go`, `internal/apply/edit.go`, `internal/apply/json.go`, `internal/apply/edit_groups_test.go`, `cmd/sshepherd/revoke.go`, `cmd/sshepherd/adopt.go`, `cmd/sshepherd/schema_roundtrip_test.go`, `cmd/sshepherd/revoke_groups_test.go`, `cmd/sshepherd/groups_consumers_test.go`, `cmd/sshepherd/validate_groups_test.go`, `cmd/sshepherd/groups_e2e_test.go`, `cmd/sshepherd/testdata/help/revoke.golden`, `scripts/integration.sh`. Finding: PRD-4. Builds on round 1.

### Task 8: `groups:` in the editor and the generator

**Files:**
- Modify: `internal/manifest/manifest.go:8-19, 114-121, 312-321, 366-374, 387-413`; `cmd/sshepherd/adopt.go:67-69`; `cmd/sshepherd/schema_roundtrip_test.go`
- Test: `internal/manifest/edit_groups_test.go` (new)

- [ ] **Step 1: Write the failing tests.** Create `internal/manifest/edit_groups_test.go`:

```go
package manifest

import (
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// groupEditFixture: alice is in web-team, bob in web-team and solo, each
// group holding one entry; comments ride the group and its members.
func groupEditFixture(tb testing.TB) string {
	tb.Helper()
	return `# fleet manifest
users:
  - {name: alice, keys: ["` + testkeys.Line(tb, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(tb, 4) + `"]}
# who works on what
groups:
  - name: web-team
    description: docs only # kept
    members:
      # lead
      - alice
      - bob
  - name: solo
    members: [bob]
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}
  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}
access:
  # the team
  - group: web-team
    servers: ["@web"]
  - group: solo
    servers: [web-1]
# end of manifest
`
}

// TestLoadKeepsGroups: the editor accepts groups: and a no-op re-encode keeps
// the section and its comments.
func TestLoadKeepsGroups(t *testing.T) {
	f := loadFixture(t, groupEditFixture(t))
	out, cfg := encodeParsed(t, f)
	if len(cfg.Groups) != 2 || cfg.Groups[1].Name != "solo" {
		t.Errorf("Groups = %+v", cfg.Groups)
	}
	for _, want := range []string{"# who works on what", "# lead", "description: docs only # kept", "- group: web-team"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestGenerateWithGroups(t *testing.T) {
	out, err := GenerateWith("", Draft{
		Users:   []config.User{{Name: "alice", Keys: []string{testkeys.Line(t, 2)}}},
		Groups:  []config.Group{{Name: "web-team", Description: "d", Members: []string{"alice"}}, {Name: "none"}},
		Servers: []config.Server{{Name: "web-1", Host: "10.0.0.1", User: "deploy"}},
		Access:  []config.Access{{Group: "web-team", Servers: []string{"web-1"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	u, g, s := strings.Index(got, "users:"), strings.Index(got, "groups:"), strings.Index(got, "servers:")
	if u < 0 || g < u || s < g {
		t.Errorf("want users:, groups:, servers: in order:\n%s", got)
	}
	if strings.Contains(got, `user: ""`) {
		t.Errorf("a group entry was written with a junk user key:\n%s", got)
	}
	if !strings.Contains(got, "members: []") {
		t.Errorf("an empty group must write members: []:\n%s", got)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("generated manifest does not load: %v\n%s", err, got)
	}
	if !reflect.DeepEqual(cfg.Access[0], config.Access{Group: "web-team", Servers: []string{"web-1"}}) {
		t.Errorf("access[0] = %+v", cfg.Access[0])
	}
}

// TestGenerateOmitsEmptyGroups: no groups, no key, so every existing golden
// stays byte-identical.
func TestGenerateOmitsEmptyGroups(t *testing.T) {
	out, err := GenerateWith("", Draft{Users: []config.User{{Name: "alice", Keys: []string{testkeys.Line(t, 2)}}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "groups") {
		t.Errorf("empty Groups wrote a section:\n%s", out)
	}
}
```

Append to `cmd/sshepherd/schema_roundtrip_test.go`, and add `"strings"` to its imports:

```go
// TestAdoptRegenerateKeepsGroups: a plain adopt rebuilds the manifest from
// structs; it must carry groups: and a group entry, or one adopt would erase
// every group. Every Group field needs a sample (fill fails otherwise).
// Append cannot carry a group: it has no groups parameter, and adopt and
// import never create one.
func TestAdoptRegenerateKeepsGroups(t *testing.T) {
	cfg, _, _, _ := roundTripConfig(t)
	group := fill[config.Group](t, map[string]map[string]any{"Group": {
		"Name": "web-team", "Description": "d", "Members": []string{"op", "bob"},
	}})
	entry := config.Access{Group: "web-team", Servers: []string{"web-2"}}
	cfg.Groups = []config.Group{group}
	cfg.Access = append(cfg.Access, entry)
	out, err := generateAdoptManifest(cfg, adopt.Plan{}, "rt.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := config.Parse(out)
	if err != nil {
		t.Fatalf("adopt output does not load: %v\n%s", err, out)
	}
	if !reflect.DeepEqual(got.Groups, cfg.Groups) || !reflect.DeepEqual(got.Access[len(got.Access)-1], entry) {
		t.Errorf("adopt lost the group: groups %+v, access %+v\n%s", got.Groups, got.Access, out)
	}
	if strings.Contains(string(out), `user: ""`) {
		t.Errorf("a group entry was written with a junk user key:\n%s", out)
	}
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/manifest -run 'TestLoadKeepsGroups|TestGenerate' ; GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run TestAdoptRegenerateKeepsGroups`
Expected: FAIL. The manifest tests do not compile (`unknown field Groups in struct literal`). The CLI test compiles and fails: `generateAdoptManifest` drops `groups:`, so the output does not load (`access: unknown group "web-team"`).

- [ ] **Step 3: Implement.** In `internal/manifest/manifest.go`:

Line 12 (package comment): `//   - RemoveUser deletes a users: entry, every access: entry naming it and its groups: memberships;`.

Replace `topLevelKeys` (`:114-115`) with:

```go
// topLevelKeys are the manifest's sections (config.Config's yaml keys).
var topLevelKeys = map[string]bool{"serial": true, "users": true, "groups": true, "servers": true, "access": true, "revoked": true}
```

and change `:118` to `// plain serial/users/groups/servers/access/revoked scalars. config.Parse tolerates a few exotic`.

Replace `requiredKeys` (`:316-321`) with:

```go
var requiredKeys = map[string]map[string]bool{
	"User":      {"name": true, "keys": true},
	"Group":     {"name": true, "members": true},
	"Server":    {"name": true, "host": true, "user": true},
	"Access":    {"servers": true}, // user: is set or group: is; the loader enforces exactly one
	"Tombstone": {"date": true},
}
```

Replace `Draft` (`:366-374`) with:

```go
// Draft is everything a generated manifest holds, in output order: serial
// (omitted at 0), users, groups (omitted when empty), servers, access,
// revoked (omitted when empty).
type Draft struct {
	Serial  uint64
	Users   []config.User
	Groups  []config.Group
	Servers []config.Server
	Access  []config.Access
	Revoked []config.Tombstone
}
```

Replace the section loop and the `revoked` block of `GenerateWith` (`:393-413`) with:

```go
	for _, sec := range []struct {
		key       string
		items     func() ([]*yaml.Node, error)
		omitEmpty bool
	}{
		{"users", func() ([]*yaml.Node, error) { return entryNodes(d.Users) }, false},
		{"groups", func() ([]*yaml.Node, error) { return entryNodes(d.Groups) }, true},
		{"servers", func() ([]*yaml.Node, error) { return entryNodes(d.Servers) }, false},
		{"access", func() ([]*yaml.Node, error) { return entryNodes(d.Access) }, false},
		{"revoked", func() ([]*yaml.Node, error) { return entryNodes(d.Revoked) }, true},
	} {
		items, err := sec.items()
		if err != nil {
			return nil, err
		}
		if sec.omitEmpty && len(items) == 0 {
			continue
		}
		root.Content = append(root.Content, strScalar(sec.key), &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: items})
	}
```

In `cmd/sshepherd/adopt.go`, replace the `manifest.GenerateWith` call (`:67-69`) with:

```go
	return manifest.GenerateWith(header.String(), manifest.Draft{ //nolint:wrapcheck // "encode manifest: …"
		Serial: cfg.Serial(), Users: users, Groups: cfg.Groups, Servers: cfg.Servers, Access: access, Revoked: cfg.Tombstones,
	})
```

- [ ] **Step 4: Run.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/manifest ./cmd/sshepherd -run 'TestLoadKeepsGroups|TestGenerate|TestSchemaRoundTrip|TestAdoptRegenerate'`
Expected: PASS. Every existing `*.golden` is byte-identical (`make check` confirms).

**docsDelta:** none beyond Task 1's (`groups:` is already in the README from lane `schema`; carrying them through adopt is the sentence in **Groups**).

---

### Task 9: `RemoveUser` drops the user from every group

**Files:**
- Modify: `internal/manifest/edit.go:14-46`
- Test: `internal/manifest/edit_groups_test.go`
- Create: `internal/manifest/testdata/edit_remove_member.golden`, `internal/manifest/testdata/edit_remove_last_member.golden`

- [ ] **Step 1: Write the failing tests.** Append to `internal/manifest/edit_groups_test.go`:

```go
// TestRemoveUserDropsMembership: alice is gone from web-team and bob stays;
// the group and every comment stay.
func TestRemoveUserDropsMembership(t *testing.T) {
	f := loadFixture(t, groupEditFixture(t))
	r, err := f.RemoveUser("alice")
	if err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if r.Keys != 1 || r.Grants != 0 || !reflect.DeepEqual(r.Groups, []string{"web-team"}) {
		t.Errorf("UserRemoval = %+v", r)
	}
	out, cfg := encodeParsed(t, f)
	if !reflect.DeepEqual(cfg.Groups[0].Members, []string{"bob"}) {
		t.Errorf("web-team members = %v", cfg.Groups[0].Members)
	}
	checkGolden(t, "edit_remove_member.golden", []byte(out))
}

// TestRemoveUserLeavesLastGroupEmpty: bob is solo's last member. The group
// keeps its entry and its access: entry, with the empty_group warning, so
// revoking the last member never breaks the manifest (spec S3b).
func TestRemoveUserLeavesLastGroupEmpty(t *testing.T) {
	f := loadFixture(t, groupEditFixture(t))
	r, err := f.RemoveUser("bob")
	if err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if !reflect.DeepEqual(r.Groups, []string{"web-team", "solo"}) {
		t.Errorf("Groups = %v", r.Groups)
	}
	out, cfg := encodeParsed(t, f)
	if len(cfg.Groups) != 2 || len(cfg.Groups[1].Members) != 0 || len(cfg.Access) != 2 {
		t.Errorf("Groups = %+v, access = %+v", cfg.Groups, cfg.Access)
	}
	if !strings.Contains(out, "members: []") {
		t.Errorf("solo must write members: []:\n%s", out)
	}
	if len(cfg.ManifestWarnings) != 1 || cfg.ManifestWarnings[0].Kind != config.WarnEmptyGroup {
		t.Errorf("ManifestWarnings = %+v", cfg.ManifestWarnings)
	}
	checkGolden(t, "edit_remove_last_member.golden", []byte(out))
}

func TestRemoveUserNotInAnyGroupReportsNone(t *testing.T) {
	f := loadFixture(t, editFixture(t))
	r, err := f.RemoveUser("alice")
	if err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if r.Groups != nil {
		t.Errorf("Groups = %v, want nil", r.Groups)
	}
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/manifest -run 'TestRemoveUser(DropsMembership|LeavesLastGroupEmpty|NotInAnyGroup)'`
Expected: FAIL (`r.Groups undefined`).

- [ ] **Step 3: Implement.** In `internal/manifest/edit.go`, replace `:14-46` with:

```go
// UserRemoval reports what RemoveUser deleted.
type UserRemoval struct {
	Keys   int      // key lines the users: entry held
	Grants int      // access: entries whose user: named the user
	Groups []string // groups: the user was dropped from, manifest order
}

// RemoveUser deletes the users: entry named name, every access: entry
// whose user: is name, and the name from every groups: members list. A
// group left empty keeps its entry (it warns at the next load, and its
// access: entries stay). A removed entry's head comment moves to the next
// entry of its section, or to the section's footer when none follows; its
// line and foot comments go with it; a removed member's comments go with it.
// Node tree only: nothing validates until Encode.
func (f *File) RemoveUser(name string) (UserRemoval, error) {
	m, err := f.rootMapping()
	if err != nil {
		return UserRemoval{}, err
	}
	usersKey, users := sectionOf(m, "users")
	item := userItem(users, name)
	if item == nil {
		return UserRemoval{}, fmt.Errorf("user %q is not in the manifest", name)
	}
	var r UserRemoval
	if keys := valueOf(item, "keys"); keys != nil && keys.Kind == yaml.SequenceNode {
		r.Keys = len(keys.Content)
	}
	removeItems(usersKey, users, func(n *yaml.Node) bool { return n == item }, true)
	if accessKey, access := sectionOf(m, "access"); access != nil {
		r.Grants = removeItems(accessKey, access, func(n *yaml.Node) bool {
			return scalarField(n, "user") == name
		}, true)
	}
	if _, groups := sectionOf(m, "groups"); groups != nil {
		r.Groups = dropMember(groups, name)
	}
	return r, nil
}

// dropMember removes name from every group's members list and returns the
// groups it was in, manifest order (nil for none).
func dropMember(groups *yaml.Node, name string) []string {
	var out []string
	for _, g := range groups.Content {
		members := valueOf(g, "members")
		if g.Kind != yaml.MappingNode || members == nil || members.Kind != yaml.SequenceNode {
			continue
		}
		if removeItems(nil, members, func(n *yaml.Node) bool {
			return n.Kind == yaml.ScalarNode && n.Value == name
		}, false) > 0 {
			out = append(out, scalarField(g, "name"))
		}
	}
	return out
}
```

- [ ] **Step 4: Generate and read the goldens.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/manifest -run 'TestRemoveUser(DropsMembership|LeavesLastGroupEmpty)' -update`

Read both new files. Check: `edit_remove_member.golden` has no `alice` in `users:` or `members:`, has `# who works on what` and `- bob`, and `# lead` (a removed member's head comment goes with it, so `# lead` is gone from this file). `edit_remove_last_member.golden` keeps `# lead` and `- alice`, has `name: solo` with `members: []`, and both access entries.

- [ ] **Step 5: Run.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/manifest`
Expected: PASS.

---

### Task 10: `revoke --from-server` refuses a pair a group reaches

**Files:**
- Create: `internal/config/group_reach.go`, `internal/config/group_reach_test.go`, `cmd/sshepherd/revoke_groups_test.go`
- Modify: `cmd/sshepherd/revoke.go:24-39, 348-358, 414-423, 438-449, 452-459, 490, 500-515`; `cmd/sshepherd/testdata/help/revoke.golden`

- [ ] **Step 1: Write the failing tests.** Create `internal/config/group_reach_test.go`:

```go
package config

import (
	"reflect"
	"testing"
)

func TestGroupGrantsReaching(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, webTeam+"  - {name: dba, members: [alice]}\n",
		"  - {group: web-team, servers: [\"@web\"], except: [web-3]}\n  - {group: dba, servers: [web-1, db-1]}\n  - {group: dba, servers: [web-1]}\n  - {user: bob, servers: [db-1]}\n",
		"revoked:\n  - {user: alice, servers: [web-2], date: 2026-11-08}\n"))
	for _, tc := range []struct {
		user, server string
		want         []string
	}{
		{"alice", "web-1", []string{"web-team", "dba"}}, // access order, a group once
		{"bob", "web-1", []string{"web-team"}},
		{"alice", "db-1", []string{"dba"}},
		{"alice", "web-2", nil}, // blocked: the member gets the D1c note instead
		{"bob", "web-3", nil},   // excepted
		{"bob", "db-1", nil},    // a direct grant is not a group grant
		{"carol", "web-1", nil}, // not a member
		{"alice", "no-such", nil},
	} {
		if got := cfg.GroupGrantsReaching(tc.user, tc.server); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("GroupGrantsReaching(%s, %s) = %v, want %v", tc.user, tc.server, got, tc.want)
		}
	}
}

// TestOwnExceptCarveOut: only the user's own access: entries count. A group's
// except: does not, and ExceptCarveOut still answers for it.
func TestOwnExceptCarveOut(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, webTeam,
		"  - {group: web-team, servers: [\"*\"], except: [web-2]}\n  - {user: carol, servers: [\"*\"], except: [web-3]}\n", ""))
	for _, tc := range []struct {
		user, server string
		want         bool
	}{
		{"carol", "web-3", true},
		{"carol", "web-2", false},
		{"alice", "web-2", false},
		{"bob", "web-3", false},
	} {
		if got := cfg.OwnExceptCarveOut(tc.user, tc.server); got != tc.want {
			t.Errorf("OwnExceptCarveOut(%s, %s) = %v, want %v", tc.user, tc.server, got, tc.want)
		}
	}
	if !cfg.ExceptCarveOut("alice", "web-2") {
		t.Error("ExceptCarveOut must stay group-aware for adopt and reconcile")
	}
}
```

Create `cmd/sshepherd/revoke_groups_test.go`:

```go
package main

import (
	"bytes"
	"strings"
	"testing"
)

// groupFleetManifest: alice (k1, held) holds web-1 and web-2 by name; bob (k2)
// and carol (k3) are in web-team, which holds @web; all three keys are
// installed on both servers. groups, access and extra are spliced in.
func groupFleetManifest(t *testing.T, groups, access, extra string) (map[string]editHost, string, string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	for _, h := range hosts {
		h.install(t, []byte{1, 2, 3})
	}
	tagged := func(name string) string {
		return strings.TrimSuffix(hosts[name].line(name), "}\n") + ", tags: [web]}\n"
	}
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n  - {name: carol, keys: ["+qk(t, 3)+"]}\n"+
		"groups:\n  - {name: web-team, members: [bob, carol]}\n"+groups+
		"servers:\n"+tagged("web-1")+tagged("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {group: web-team, servers: [\"@web\"]}\n"+access+extra)
	return hosts, kh, cfg
}

// TestRevokeServerRefusedThroughGroup: any group grant reaching the pair
// refuses the trim, with a direct grant or without (trimming the direct one
// would leave the access). Exit 3, nothing saved, and the date is the run's.
// Under --json stdout stays empty: the document is written exactly on exit
// 0, 1 or 2.
func TestRevokeServerRefusedThroughGroup(t *testing.T) {
	fixedEditClock(t)
	const want = "bob's access to web-1 comes from group web-team; remove the user from the group, trim the group's grant, or add revoked: [{user: bob, servers: [web-1], date: 2026-11-09}] to block only this member"
	for _, tc := range []struct {
		name, access string
		flags        []string
	}{
		{"group only", "", nil},
		{"a direct grant too", "  - {user: bob, servers: [web-1]}\n", nil},
		{"--json writes no document", "", []string{"--json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, kh, cfg := groupFleetManifest(t, "", tc.access, "")
			before := fileBytes(t, cfg)
			var out, errBuf bytes.Buffer
			args := append([]string{"revoke", "bob", "--from-server", "web-1", "--yes", "--config", cfg, "--known-hosts", kh}, tc.flags...)
			code := run(args, &out, &errBuf)
			if code != 3 || out.Len() != 0 || !strings.Contains(errBuf.String(), want) {
				t.Errorf("exit = %d, stdout = %q, stderr = %q\nwant stderr to contain %q", code, out.String(), errBuf.String(), want)
			}
			if !bytes.Equal(fileBytes(t, cfg), before) {
				t.Errorf("the manifest changed:\n%s", fileBytes(t, cfg))
			}
		})
	}
}

// TestRevokeServerRefusalNamesEveryGroup: two groups reaching the pair are
// named together.
func TestRevokeServerRefusalNamesEveryGroup(t *testing.T) {
	fixedEditClock(t)
	const want = "bob's access to web-1 comes from groups web-team, solo; remove the user from the groups, trim the groups' grants, or add revoked: [{user: bob, servers: [web-1], date: 2026-11-09}] to block only this member"
	_, kh, cfg := groupFleetManifest(t, "  - {name: solo, members: [bob]}\n", "  - {group: solo, servers: [web-1]}\n", "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--from-server", "web-1", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 || !strings.Contains(errBuf.String(), want) {
		t.Errorf("exit = %d, stderr = %q\nwant %q", code, errBuf.String(), want)
	}
}

// TestRevokeServerBlockedGroupMemberIsAlreadyRevoked (D1c): GroupGrantsReaching
// ignores a blocked pair, so a member the tombstone blocks gets the note, not
// the refusal: exit 0, nothing saved.
func TestRevokeServerBlockedGroupMemberIsAlreadyRevoked(t *testing.T) {
	_, kh, cfg := groupFleetManifest(t, "", "", "revoked:\n  - {user: bob, servers: [web-2], date: 2026-11-08}\n")
	before := fileBytes(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--from-server", "web-2", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
	if !strings.HasPrefix(out.String(), "bob's access to web-2 was already revoked (2026-11-08); run 'sshepherd apply") {
		t.Errorf("stdout = %q", out.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Errorf("the manifest changed:\n%s", fileBytes(t, cfg))
	}
	if !strings.Contains(errBuf.String(), `is not granted "web-2" through group web-team`) {
		t.Errorf("stderr lacks the load warning:\n%s", errBuf.String())
	}
}

// TestRevokeServerKeepsCountIgnoresBlockedGroupPair: bob is in a group whose
// "*" entry excepts web-2, with a direct grant of web-2 and a tombstone
// blocking db-1. The trim of web-2 is not refused, because the group does not
// reach it, and it records a tombstone: the group's except: stops applying
// when bob leaves the group, so it is no memory for this trim (D1a). db-1 does
// not count as kept: without Covers' c.blocked check it would read 2 other
// servers. The header never says no access is left: he keeps web-1 through
// the group (the design's HasAccessEntry goal, met by the S3a count).
func TestRevokeServerKeepsCountIgnoresBlockedGroupPair(t *testing.T) {
	hosts, _, _ := editFleet(t, []byte{1}, "web-1", "web-2", "db-1")
	body := "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n  - {name: bob, keys: [" + qk(t, 2) + "]}\n" +
		"groups:\n  - {name: team, members: [bob]}\n" +
		"servers:\n" + hosts["web-1"].line("web-1") + hosts["web-2"].line("web-2") + hosts["db-1"].line("db-1") +
		"access:\n  - {user: alice, servers: [web-1, web-2, db-1]}\n  - {group: team, servers: [\"*\"], except: [web-2]}\n  - {user: bob, servers: [web-2]}\n" +
		"revoked:\n  - {user: bob, servers: [db-1], date: 2026-11-08}\n"
	t.Run("trim keeps the honest count", func(t *testing.T) {
		cfg := writeConfig(t, body)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--from-server", "web-2", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
		}
		if !strings.Contains(out.String(), "manifest edit: remove bob's access to web-2 (1 access entry removed); bob keeps access to 1 other server") {
			t.Errorf("stdout:\n%s", out.String())
		}
		if strings.Contains(out.String(), "no access left") {
			t.Errorf("bob keeps web-1 through the group:\n%s", out.String())
		}
		saved := readCfg(t, cfg)
		if len(saved.Access) != 2 || !saved.ExceptCarveOut("bob", "web-2") {
			t.Errorf("access = %+v", saved.Access)
		}
		if _, ok := saved.AccessRevoked("bob", "web-2"); !ok {
			t.Errorf("no tombstone for the trimmed direct grant:\n%s", fileBytes(t, cfg))
		}
		if len(saved.Conflicts()) != 0 {
			t.Errorf("Conflicts = %+v, want none: the group excepts web-2", saved.Conflicts())
		}
		if len(saved.Warnings) != 1 || !strings.Contains(saved.Warnings[0], `"db-1"`) {
			t.Errorf("Warnings = %q, want only the fixture's blocked db-1", saved.Warnings)
		}
	})
	t.Run("the blocked pair is a note", func(t *testing.T) {
		cfg := writeConfig(t, body)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--from-server", "db-1", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if !strings.Contains(out.String(), "bob's access to db-1 was already revoked (2026-11-08)") {
			t.Errorf("stdout = %q", out.String())
		}
	})
}

// TestRevokeServerLeavesGroupExceptsAlone: trimming db-1 records db-1 and
// nothing else. The group's except: of web-2 was never bob's own and did not
// change, so it must not turn into a tombstone (forgottenCarveOut reads the
// user's own except: on both sides).
func TestRevokeServerLeavesGroupExceptsAlone(t *testing.T) {
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"groups:\n  - {name: team, members: [bob]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.1.1, user: deploy, tags: [web]}\n  - {name: web-2, host: 10.0.1.2, user: deploy, tags: [web]}\n  - {name: db-1, host: 10.0.2.1, user: deploy}\n"+
		"access:\n  - {user: alice, servers: [web-1]}\n  - {group: team, servers: [\"@web\"], except: [web-2]}\n  - {user: bob, servers: [db-1]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--from-server", "db-1", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	saved := readCfg(t, cfg)
	if _, ok := saved.AccessRevoked("bob", "db-1"); !ok {
		t.Errorf("no tombstone for db-1:\n%s", fileBytes(t, cfg))
	}
	if _, ok := saved.AccessRevoked("bob", "web-2"); ok {
		t.Errorf("the group's except: became a tombstone:\n%s", fileBytes(t, cfg))
	}
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run 'TestGroupGrantsReaching|TestOwnExceptCarveOut' ; GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestRevokeServer(RefusedThroughGroup|RefusalNamesEveryGroup|BlockedGroupMember|KeepsCountIgnoresBlockedGroupPair|LeavesGroupExcepts)'`
Expected:
- `internal/config` does not compile (`GroupGrantsReaching undefined`, `OwnExceptCarveOut undefined`).
- The CLI refusal tests fail: the trim gets exit 0.
- `TestRevokeServerKeepsCountIgnoresBlockedGroupPair`: subtest `trim keeps the honest count` fails on the `AccessRevoked` assertion; subtest `the blocked pair is a note` already passes. The proof for the count is deleting `Covers`' `c.blocked` check.
- `TestRevokeServerBlockedGroupMemberIsAlreadyRevoked` already passes. Task 14's mutant 1 is what proves it can fail.
- `TestRevokeServerLeavesGroupExceptsAlone` already passes. Task 14's mutant 18 is what proves it can fail.

- [ ] **Step 3: Implement `GroupGrantsReaching`.** Create `internal/config/group_reach.go`:

```go
package config

import "slices"

// GroupGrantsReaching names, in access order and once each, every group whose
// access: entry reaches server for user. A pair an access tombstone blocked
// reaches nothing (its member gets revoke's D1c note), and a server not in the
// manifest is reached by no group here: it has nothing to refuse.
func (c *Config) GroupGrantsReaching(user, server string) []string {
	if c.blocked[grantPair{user, server}] {
		return nil
	}
	i := slices.IndexFunc(c.Servers, func(s Server) bool { return s.Name == server })
	if i < 0 {
		return nil
	}
	var out []string
	for _, a := range c.Access {
		if a.Group == "" || !c.entryApplies(a, user) || !entryCovers(a, c.Servers[i]) || slices.Contains(out, a.Group) {
			continue
		}
		out = append(out, a.Group)
	}
	return out
}

// OwnExceptCarveOut is ExceptCarveOut limited to the user's own access:
// entries. A group's except: stops applying when the member leaves the group,
// so it is no memory for a personal trim (D1a). revoke asks this one before
// it skips a tombstone. adopt and reconcile keep ExceptCarveOut, because a
// member's key on a server the group excepts is drift today.
func (c *Config) OwnExceptCarveOut(user, server string) bool {
	return slices.ContainsFunc(c.Access, func(a Access) bool {
		return a.User == user && slices.Contains(a.Except, server)
	})
}
```

- [ ] **Step 4: Refuse in `classifyPairs`.** In `cmd/sshepherd/revoke.go`:

Change the call in `planRevokeAccess` (`:358`) to `problems, trims, already := accessProblems(cfg, users, servers, h, memo.date)`.

Change `accessProblems`' signature (`:459`) to:

```go
func accessProblems(cfg *config.Config, users, servers []string, h followUp, runDate string) (problems []string, trims map[string][]string, already []apply.AlreadyRevoked) {
```

and the call inside it (`:490`) to `trim, gone, date, missing := classifyPairs(cfg, name, known, runDate)`. Extend the comment above (`:455-456`): after `(config.Covers: selectors and except: included)` add `, and every pair a group grant reaches (refused whether or not a direct grant exists, because trimming that one would leave the access)`.

Replace `classifyPairs` (`:500-515`) with:

```go
// classifyPairs sorts one user's --from-server targets: reached by a group
// grant (a problem: trimming a direct grant would leave the access), covered
// (trim), already revoked by an access tombstone (gone, with the latest date),
// or a problem. runDate goes in the refusal's paste-ready tombstone.
func classifyPairs(cfg *config.Config, name string, servers []string, runDate string) (trim, gone []string, date string, problems []string) {
	for _, s := range servers {
		if groups := cfg.GroupGrantsReaching(name, s); len(groups) > 0 {
			problems = append(problems, groupRefusal(name, s, groups, runDate))
			continue
		}
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

// groupRefusal is revoke's message for a (user, server) pair a group grant
// reaches: the three ways out, the third a paste-ready tombstone carrying the
// run's date.
func groupRefusal(user, server string, groups []string, date string) string {
	return fmt.Sprintf("%s's access to %s comes from %s %s; remove the user from the %s, trim the %s, or add revoked: [{user: %s, servers: [%s], date: %s}] to block only this member",
		user, server, pluralWord(len(groups), "group", "groups"), strings.Join(groups, ", "),
		pluralWord(len(groups), "group", "groups"), pluralWord(len(groups), "group's grant", "groups' grants"),
		user, server, date)
}
```

Replace the tail of the `Long` text (`:34-39`) with:

```go
			"except: entry); the users and their keys stay. A pair a group grant reaches is\n" +
			"refused; 'revoke USER...' also drops each user from every group. Operator users\n" +
			"(and their keys) need --operator. The plan is shown and confirmed once; the\n" +
			"manifest is saved after confirmation and before the first write, so commit and\n" +
			"push it afterwards. --dry-run changes nothing; --no-apply saves the edit\n" +
			"without contacting any server. A server whose only grantee is revoked is\n" +
			"never emptied: the key stays installed there (a warning says so).\n\n" + exitCodesWrite,
```

Do not change `NoGrantsLeft`: it is already `KeepsServers == 0` (design gap 1).

- [ ] **Step 4b: Read only the user's own `except:` when deciding on a tombstone (design gap 10).** Still in `cmd/sshepherd/revoke.go`:

In `planRevokeAccess`'s comment (`:351-353`), after `the except: already remembers it.`, add `A group's except: does not count: it stops applying when the member leaves the group.`

In `accessTombstones`' comment (`:415-421`), after the first sentence, add `A group's except: is not memory here (it stops applying when the member leaves the group), so the check reads OwnExceptCarveOut.`

Change `:422` to `if !mid.OwnExceptCarveOut(name, s) {`.

Replace `forgottenCarveOut` (`:438-449`) with:

```go
// forgottenCarveOut reports a server only a deleted selector entry's except:
// remembered: excluded in former, neither excluded nor covered in mid, and
// not already recorded by an access tombstone. Both sides read the user's own
// except:, so a group's except: is neither forgotten nor memory.
func forgottenCarveOut(former, mid *config.Config, user, server string) bool {
	if former.Covers(user, server) || !former.OwnExceptCarveOut(user, server) {
		return false
	}
	if mid.OwnExceptCarveOut(user, server) || mid.Covers(user, server) {
		return false
	}
	_, recorded := former.AccessRevoked(user, server)
	return !recorded
}
```

A manifest with no groups behaves exactly as before: without a group entry, `OwnExceptCarveOut` and `ExceptCarveOut` give the same answer.

- [ ] **Step 5: Regenerate the help golden.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run TestHelpGolden/revoke -update`

Read the diff: only the reflowed tail of the `Long` text changes.

- [ ] **Step 6: Run.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config ./cmd/sshepherd`
Expected: PASS.

**docsDelta (README, lane `editor`).**

a. In **`sshepherd revoke`**, change the opening of the **Users or keys, not both.** paragraph from `` `revoke USER...` deletes each user and every `access:` entry whose `user:` is that user `` to `` `revoke USER...` deletes each user, every `access:` entry whose `user:` is that user, and the user from every group's `members:` (a group left empty stays and warns) ``.

b. In the refusal list (`README.md:1835`), after `` `--from-server` with `*` or an `@tag` (use `revoke USER`), `` add `` any user × server pair a group grant reaches, whether or not a direct grant exists too (a direct trim would leave the access): `bob's access to web-1 comes from group web-team; remove the user from the group, trim the group's grant, or add revoked: [{user: bob, servers: [web-1], date: 2026-11-08}] to block only this member`; ``. Then, after the paragraph, add: `` The third way out blocks that one member and leaves the group alone. If the user also holds a direct grant of the server, that tombstone is a policy conflict until you remove the direct grant too. A pair a tombstone already blocks reads as already revoked, exit `0`. ``

c. At `README.md:1820`, change `` the servers no `except:` remembers (a selector's new `except:` already remembers its server) `` to `` the servers none of that user's own `except:` lists remembers (a selector's new `except:` already remembers its server; a group's `except:` does not count, because it stops applying when the member leaves the group) ``.

---

### Task 11: the edit header and JSON report the groups

**Files:**
- Modify: `internal/apply/edit.go:30-32, 148-150`, `internal/apply/json.go:109-113, 341-343`, `cmd/sshepherd/revoke.go:188`
- Test: `internal/apply/edit_groups_test.go` (new), `cmd/sshepherd/revoke_groups_test.go`

- [ ] **Step 1: Write the failing tests.** Create `internal/apply/edit_groups_test.go`:

```go
package apply

import (
	"strings"
	"testing"
)

// TestEditHeaderCountsGroups: a member of two groups reads "2 groups"; with
// none the line is the one every existing golden pins.
func TestEditHeaderCountsGroups(t *testing.T) {
	for _, tc := range []struct {
		name   string
		groups []string
		want   string
	}{
		{"none", nil, "manifest edit: remove user alice (1 key, 0 access grants) — 1 server affected\n"},
		{"one", []string{"web-team"}, "manifest edit: remove user alice (1 key, 0 access grants, 1 group) — 1 server affected\n"},
		{"two", []string{"web-team", "dba"}, "manifest edit: remove user alice (1 key, 0 access grants, 2 groups) — 1 server affected\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			RenderEditHeader(&b, EditSummary{Edits: []Edit{{Kind: EditRemoveUser, User: "alice", Keys: 1, Groups: tc.groups}}, Affected: 1}, RenderOptions{})
			if b.String() != tc.want {
				t.Errorf("got %q\nwant %q", b.String(), tc.want)
			}
		})
	}
}
```

Append to `cmd/sshepherd/revoke_groups_test.go`, and add `"context"`, `"reflect"` and `"github.com/javadh75/SSHepherd/internal/testkeys"` to its imports:

```go
// TestRevokeUserDropsGroupMembership: bob leaves web-team, his key leaves
// both servers, carol's stays, and the header says a group was changed.
func TestRevokeUserDropsGroupMembership(t *testing.T) {
	hosts, kh, cfg := groupFleetManifest(t, "", "", "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "manifest edit: remove user bob (1 key, 0 access grants, 1 group) — 2 servers affected\n") {
		t.Errorf("stdout:\n%s", out.String())
	}
	saved := readCfg(t, cfg)
	if !reflect.DeepEqual(saved.Groups[0].Members, []string{"carol"}) {
		t.Errorf("members = %v", saved.Groups[0].Members)
	}
	gone, kept := strings.Fields(testkeys.Line(t, 2))[1], strings.Fields(testkeys.Line(t, 3))[1]
	for _, name := range []string{"web-1", "web-2"} {
		if file := hosts[name].keys(t); strings.Contains(file, gone) || !strings.Contains(file, kept) {
			t.Errorf("%s:\n%s", name, file)
		}
	}
}

// TestRevokeLastGroupMemberLeavesGroupWarning: the group keeps its entry and
// its access: entry, and the manifest still loads. The run that empties the
// group prints the warning itself, and the next load carries it.
func TestRevokeLastGroupMemberLeavesGroupWarning(t *testing.T) {
	const want = `group "web-team" has no members; its grants add nothing`
	_, _, cfg := groupFleetManifest(t, "", "", "")
	for _, user := range []string{"bob", "carol"} {
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", user, "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("%s: exit = %d\n%s\n%s", user, code, out.String(), errBuf.String())
		}
		if user == "carol" && !strings.Contains(errBuf.String(), want) {
			t.Errorf("the run that empties the group did not warn:\n%s", errBuf.String())
		}
	}
	saved := readCfg(t, cfg)
	if len(saved.Groups) != 1 || len(saved.Groups[0].Members) != 0 || len(saved.Access) != 2 {
		t.Errorf("groups = %+v, access = %+v", saved.Groups, saved.Access)
	}
	if len(saved.ManifestWarnings) != 1 || saved.ManifestWarnings[0].Message != want {
		t.Errorf("ManifestWarnings = %+v", saved.ManifestWarnings)
	}
}

// TestRevokeLastGroupMemberJSONWarns: the run that empties the group carries
// the warning in its own document, not only on a later load.
func TestRevokeLastGroupMemberJSONWarns(t *testing.T) {
	_, _, cfg := groupFleetManifest(t, "", "", "")
	doc := runJSONDoc(context.Background(), t, 0, "revoke", "bob", "carol", "--json", "--no-apply", "--yes", "--config", cfg)
	ws, _ := doc["manifest_warnings"].([]any)
	want := map[string]any{"kind": "empty_group", "message": `group "web-team" has no members; its grants add nothing`}
	if len(ws) != 1 || !reflect.DeepEqual(ws[0], want) {
		t.Errorf("manifest_warnings = %v\nwant one %v", ws, want)
	}
}

func TestRevokeUserGroupsJSON(t *testing.T) {
	_, kh, cfg := groupFleetManifest(t, "", "", "")
	doc := runJSONDoc(context.Background(), t, 0, "revoke", "bob", "--json", "--yes", "--config", cfg, "--known-hosts", kh)
	e := doc["edit"].(map[string]any)["edits"].([]any)[0].(map[string]any)
	if e["kind"] != "remove-user" || e["grants"] != float64(0) || !reflect.DeepEqual(e["groups"], []any{"web-team"}) {
		t.Errorf("edit entry = %v", e)
	}
}
```

- [ ] **Step 2: Run them to see them fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply -run TestEditHeaderCountsGroups ; GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestRevoke(UserDropsGroupMembership|LastGroupMember|UserGroupsJSON)'`
Expected:
- `internal/apply` does not compile (`unknown field Groups`).
- The CLI package compiles. `TestRevokeUserDropsGroupMembership` fails on the `1 group` header and `TestRevokeUserGroupsJSON` on the missing `groups` field.
- `TestRevokeLastGroupMemberLeavesGroupWarning` and `TestRevokeLastGroupMemberJSONWarns` already pass, because Task 9 provides the behaviour. Prove each can fail by removing the `dropMember` call from `RemoveUser` for one run (the group would keep a user that no longer exists, so the save is refused; not run yet for these two tests).

- [ ] **Step 3: Implement.** In `internal/apply/edit.go`, after `Keys, Grants int` (`:32`) add:

```go
	// Groups (EditRemoveUser) names the groups the user was dropped from.
	Groups []string
```

Replace the `EditRemoveUser` case of `editText` (`:148-150`) with:

```go
	case EditRemoveUser:
		counts := Plural(e.Keys, "key", "keys") + ", " + Plural(e.Grants, "access grant", "access grants")
		if len(e.Groups) > 0 {
			counts += ", " + Plural(len(e.Groups), "group", "groups")
		}
		return fmt.Sprintf("remove user %s (%s)", e.User, counts)
```

In `internal/apply/json.go`, add to `jsonEditEntry` after `Grants` (`:112`):

```go
	Groups         []string `json:"groups,omitempty"`
```

and in the `EditRemoveUser` case (`:341-343`), after the `je.Keys, je.Grants` line:

```go
			je.Groups = ed.Groups
```

In `cmd/sshepherd/revoke.go:188`, change the `apply.Edit` to carry them:

```go
		ep.summary.Edits = append(ep.summary.Edits, apply.Edit{Kind: apply.EditRemoveUser, User: u.Name, Keys: r.Keys, Grants: r.Grants, Groups: r.Groups})
```

- [ ] **Step 4: Run.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply ./cmd/sshepherd`
Expected: PASS; no existing golden changes (a user in no group adds nothing).

**docsDelta (README, lane `editor`).** In the **JSON.** paragraph of **`sshepherd revoke`**, in the `edits` list, change `` `remove-user`, `remove-key`, `` to `` `remove-user` (with `groups` when the user was in a group), `remove-key`, ``. In **`sshepherd revoke`**, after the sentence added in Task 10a, add: `` The edit header counts the groups: `manifest edit: remove user bob (1 key, 0 access grants, 1 group) — 2 servers affected`. ``

---

### Task 12: validate, rotate and the merge commands on a group manifest

**Files:**
- Create: `cmd/sshepherd/validate_groups_test.go`, `cmd/sshepherd/groups_consumers_test.go`

These tests pin behaviour the rounds so far produce; none needs new production code, so each passes when first run. Step 3 lists the mutant that proves each can fail.

- [ ] **Step 1: Validate.** Create `cmd/sshepherd/validate_groups_test.go`:

```go
package main

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// validateGroupManifest: alice and bob; web-1 on root, web-2 on deploy, both
// tagged web. groups, access and extra are spliced in.
func validateGroupManifest(t *testing.T, groups, access, extra string) string {
	t.Helper()
	return "users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n  - {name: bob, keys: [\"" + testkeys.Line(t, 2) + "\"]}\n" +
		"groups:\n" + groups +
		"servers:\n  - {name: web-1, host: 10.0.1.5, user: root, tags: [web]}\n  - {name: web-2, host: 10.0.1.6, user: deploy, tags: [web]}\n" +
		"access:\n" + access + extra
}

// TestValidateUnderstandsGroups also proves the editor accepts groups:
// notEditable would otherwise add a manifest_not_editable warning.
func TestValidateUnderstandsGroups(t *testing.T) {
	path := writeConfig(t, validateGroupManifest(t, "  - {name: team, members: [alice, bob]}\n", "  - {group: team, servers: [\"@web\"]}\n", ""))
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", recordedKnownHosts(t, "10.0.1.5", "10.0.1.6"))
	if code != 0 || out != "manifest OK: 2 users, 2 servers, 4 grants (0 warnings)\n" {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
}

func TestValidateUnknownGroupExit3(t *testing.T) {
	const want = `access: unknown group "nope"`
	path := writeConfig(t, validateGroupManifest(t, "", "  - {group: nope, servers: [web-1]}\n", ""))
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", recordedKnownHosts(t))
	if code != 3 || out != "" || !strings.Contains(stderr, want) {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
	code, out, _ = validateCLI(t, "--json", "--config", path, "--known-hosts", recordedKnownHosts(t))
	doc := oneJSONDoc(t, out)
	errs, _ := doc["errors"].([]any)
	if code != 3 || doc["valid"] != false || len(errs) != 1 || errs[0] != want {
		t.Fatalf("--json: exit = %d, doc = %v", code, doc)
	}
}

// TestUnknownGroupExit3EveryCommand: an unknown group is a manifest load
// error, so every command that reads the manifest exits 3 before it dials.
func TestUnknownGroupExit3EveryCommand(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, validateGroupManifest(t, "", "  - {group: nope, servers: [web-1]}\n", ""))
	for _, args := range [][]string{
		{"audit", "--config", path},
		{"apply", "--dry-run", "--config", path},
		{"revoke", "alice", "--dry-run", "--config", path},
		{"adopt", "--config", path},
		{"rotate", "alice", "--old", fpOf(t, 1), "--new", writePub(t, "id_new.pub", testkeys.Line(t, 6)), "--dry-run", "--config", path},
		{"import", writeSSHConfig(t, "Host a\n  HostName 10.0.0.9\n  User deploy\n"), "--merge", path},
	} {
		t.Run(args[0], func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := run(args, &out, &errBuf)
			if code != 3 || out.Len() != 0 || !strings.Contains(errBuf.String(), `access: unknown group "nope"`) {
				t.Errorf("exit = %d, stdout = %q, stderr = %q", code, out.String(), errBuf.String())
			}
		})
	}
}

// TestValidateGroupWarnings: empty_group, the group wildcard_root and the
// group tombstone_blocks_grant are warnings: exit 0, exit 1 only under
// --strict, one JSON object each with exactly these fields.
func TestValidateGroupWarnings(t *testing.T) {
	const team = "  - {name: team, members: [alice]}\n"
	for _, tc := range []struct {
		name, groups, access, extra, kind, text string
		fields                                  map[string]any
	}{
		{"empty group", "  - {name: none, members: []}\n", "  - {user: alice, servers: [web-2]}\n", "", "empty_group",
			`group "none" has no members; its grants add nothing`, nil},
		{"root wildcard", team, "  - {group: team, servers: [\"*\"]}\n", "", "wildcard_root",
			`access for group "team": servers ["*"] includes the root account on web-1; list the servers or use an @tag that excludes root accounts`, nil},
		{"blocked member", team, "  - {group: team, servers: [\"@web\"]}\n", "revoked:\n  - {user: alice, servers: [web-2], date: 2026-11-08}\n", "tombstone_blocks_grant",
			`access[0]: "alice" is not granted "web-2" through group team: revoked[0] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`,
			map[string]any{"revoked_index": float64(0), "user": "alice", "server": "web-2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, validateGroupManifest(t, tc.groups, tc.access, tc.extra))
			kh := recordedKnownHosts(t, "10.0.1.5", "10.0.1.6")
			code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", kh)
			if code != 0 || !strings.Contains(out, "(1 warning)") || !strings.Contains(stderr, tc.text) {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
			}
			code, out, _ = validateCLI(t, "--strict", "--json", "--config", path, "--known-hosts", kh)
			if code != 1 {
				t.Fatalf("--strict: exit = %d, want 1", code)
			}
			ws, _ := oneJSONDoc(t, out)["manifest_warnings"].([]any)
			if len(ws) != 1 {
				t.Fatalf("manifest_warnings = %v", ws)
			}
			want := map[string]any{"kind": tc.kind, "message": tc.text}
			for k, v := range tc.fields {
				want[k] = v
			}
			if !reflect.DeepEqual(ws[0], want) {
				t.Errorf("warning = %v\nwant %v", ws[0], want)
			}
		})
	}
}
```

Append to `cmd/sshepherd/validate_groups_test.go`:

```go
// TestGroupWarningsInAuditAndApplyJSON (spec Shared rules): the group warnings
// reach audit's and apply's JSON as well as validate's, and change no exit
// code. apply goes through its own cleanMemory copy of the warnings. The plan
// is converged first, because apply --dry-run exits 1 on a pending change.
func TestGroupWarningsInAuditAndApplyJSON(t *testing.T) {
	for _, tc := range []struct {
		name, groups, extra string
		want                map[string]any
	}{
		{"empty group", "  - {name: none, members: []}\n", "", map[string]any{
			"kind": "empty_group", "message": `group "none" has no members; its grants add nothing`,
		}},
		{"blocked member", "", "revoked:\n  - {user: bob, servers: [web-2], date: 2026-11-08}\n", map[string]any{
			"kind": "tombstone_blocks_grant", "revoked_index": float64(0), "user": "bob", "server": "web-2",
			"message": `access[1]: "bob" is not granted "web-2" through group web-team: revoked[0] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hosts, kh, cfg := groupFleetManifest(t, tc.groups, "", tc.extra)
			if tc.extra != "" {
				hosts["web-2"].install(t, []byte{1, 3}) // the blocked member's key is gone
			}
			check := func(command string, doc map[string]any) {
				t.Helper()
				ws, _ := doc["manifest_warnings"].([]any)
				if len(ws) != 1 || !reflect.DeepEqual(ws[0], tc.want) {
					t.Errorf("%s: manifest_warnings = %v\nwant one %v", command, ws, tc.want)
				}
			}
			check("audit", runJSONDoc(context.Background(), t, 0, "audit", "--json", "--config", cfg, "--known-hosts", kh))
			var out, errBuf bytes.Buffer
			if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
				t.Fatalf("apply: exit = %d\n%s\n%s", code, out.String(), errBuf.String())
			}
			check("apply", runJSONDoc(context.Background(), t, 0, "apply", "--dry-run", "--json", "--config", cfg, "--known-hosts", kh))
		})
	}
}
```

- [ ] **Step 2: Rotate and the merge commands.** Create `cmd/sshepherd/groups_consumers_test.go`:

```go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestRotateGroupMemberReachesGroupServers: a member's rotation pushes to the
// servers the group reaches, and the group is untouched. carol is the second
// member, so a grant that expanded only the first would affect no server.
func TestRotateGroupMemberReachesGroupServers(t *testing.T) {
	hosts, kh, cfg := groupFleetManifest(t, "", "", "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"rotate", "carol", "--old", fpOf(t, 3), "--new", writePub(t, "id_new.pub", testkeys.Line(t, 6)), "--yes",
		"--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), " — 2 servers affected\n") {
		t.Errorf("stdout:\n%s", out.String())
	}
	gone, added := strings.Fields(testkeys.Line(t, 3))[1], strings.Fields(testkeys.Line(t, 6))[1]
	for _, name := range []string{"web-1", "web-2"} {
		if file := hosts[name].keys(t); strings.Contains(file, gone) || !strings.Contains(file, added) {
			t.Errorf("%s:\n%s", name, file)
		}
	}
	saved := readCfg(t, cfg)
	if !reflect.DeepEqual(saved.Groups[0].Members, []string{"bob", "carol"}) {
		t.Errorf("members = %v", saved.Groups[0].Members)
	}
	if _, revoked := saved.Revoked(fpOf(t, 3)); !revoked {
		t.Error("the old key was not tombstoned")
	}
}

// TestAdoptMergeHonoursBlockedGroupMember: bob's key is still on web-2, a
// tombstone blocks his group grant there, and adopt --merge must not extend
// him: the plan is empty, so the file is untouched byte for byte.
func TestAdoptMergeHonoursBlockedGroupMember(t *testing.T) {
	_, kh, cfg := groupFleetManifest(t, "", "", "revoked:\n  - {user: bob, servers: [web-2], date: 2026-11-08}\n")
	before := fileBytes(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--merge", "--config", cfg, "-o", cfg, "--force", "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Errorf("the manifest changed:\n%s", fileBytes(t, cfg))
	}
	if readCfg(t, cfg).Covers("bob", "web-2") {
		t.Errorf("adopt --merge re-granted web-2:\n%s", fileBytes(t, cfg))
	}
	if !strings.Contains(errBuf.String(), "whose access was revoked") {
		t.Errorf("stderr lacks the not-re-granted warning:\n%s", errBuf.String())
	}
}

// TestAdoptMergeAppendKeepsGroups: an unknown key makes the plan non-empty, so
// the merge goes through Append and Encode. A new user is appended, and the
// groups: section, its comment included, is byte for byte what it was: adopt
// never creates or rewrites a group.
func TestAdoptMergeAppendKeepsGroups(t *testing.T) {
	const kept = "groups:\n  - {name: web-team, members: [bob, carol]}\n  # kept group comment\n  - name: solo\n    members: [bob]\nservers:\n"
	hosts, kh, cfg := groupFleetManifest(t, "  # kept group comment\n  - name: solo\n    members: [bob]\n", "", "")
	hosts["web-1"].install(t, []byte{1, 2, 3, 5})
	want := readCfg(t, cfg).Groups
	if !strings.Contains(string(fileBytes(t, cfg)), kept) {
		t.Fatalf("the fixture lacks the groups block:\n%s", fileBytes(t, cfg))
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--merge", "--config", cfg, "-o", cfg, "--force", "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(string(fileBytes(t, cfg)), kept) {
		t.Errorf("groups: changed:\n%s", fileBytes(t, cfg))
	}
	saved := readCfg(t, cfg)
	if !reflect.DeepEqual(saved.Groups, want) {
		t.Errorf("Groups = %+v\nwant %+v", saved.Groups, want)
	}
	if owner, ok := saved.OwnerOf(fpOf(t, 5)); !ok || !saved.Covers(owner.Name, "web-1") {
		t.Errorf("the unknown key was not adopted on web-1:\n%s", fileBytes(t, cfg))
	}
}

// TestImportMergeHonoursBlockedGroupMember: the same for import --merge, on a
// group "*" entry. A conflict-only plan returns the file unchanged.
func TestImportMergeHonoursBlockedGroupMember(t *testing.T) {
	home := hermeticHome(t)
	bobKey := filepath.Join(home, "bob")
	if err := os.WriteFile(bobKey+".pub", []byte(testkeys.Line(t, 4)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := writeConfig(t, "users:\n  - {name: bob, keys: ["+qk(t, 4)+"]}\n"+
		"groups:\n  - {name: team, members: [bob]}\n"+
		"servers:\n  - {name: db-1, host: 10.0.0.3, user: deploy}\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n"+
		"access:\n  - {group: team, servers: [\"*\"]}\n"+
		"revoked:\n  - {user: bob, servers: [db-1], date: 2026-11-08}\n")
	before := fileBytes(t, m)
	path := writeSSHConfig(t, "Host db-1\n  HostName 10.0.0.3\n  User deploy\n  IdentityFile "+bobKey+"\n"+
		"Host web-1\n  HostName 10.0.0.1\n  User deploy\n  IdentityFile "+bobKey+"\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path, "--merge", m, "-o", m, "--force"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, m), before) {
		t.Errorf("the manifest changed:\n%s", fileBytes(t, m))
	}
	saved := readCfg(t, m)
	if saved.Covers("bob", "db-1") || !saved.Covers("bob", "web-1") {
		t.Errorf("covers db-1 %v, web-1 %v", saved.Covers("bob", "db-1"), saved.Covers("bob", "web-1"))
	}
	if !strings.Contains(errBuf.String(), "whose access was revoked") {
		t.Errorf("stderr lacks the not-re-granted warning:\n%s", errBuf.String())
	}
}
```

- [ ] **Step 3: Run.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestValidate(UnderstandsGroups|UnknownGroup|GroupWarnings)|TestGroupWarningsInAuditAndApplyJSON|TestUnknownGroupExit3|TestRotateGroupMember|TestAdoptMerge(Honours|AppendKeepsGroups)|TestImportMergeHonours'`
Expected: PASS.

Prove each can fail: apply its mutant for one run, see the test fail, revert, and report the result with Task 14's table. The mutants in `internal/config` are local to this proof and never land in the patch.

| Test | Mutant |
|---|---|
| `TestValidateUnderstandsGroups` | remove `"groups": true` from `topLevelKeys` (it reports 1 warning) |
| `TestValidateUnknownGroupExit3`, `TestUnknownGroupExit3EveryCommand` | delete the `a.Group != ""` case in `entrySubjectError` |
| `TestValidateGroupWarnings` | drop `validateGroups`' empty-group warning (row `empty group`); use `a.User` in `warnWildcardRoot` (row `root wildcard`); drop `grantVia`'s group branch (row `blocked member`, not run yet) |
| `TestGroupWarningsInAuditAndApplyJSON` | drop `validateGroups`' empty-group warning (row `empty group`); drop `grantVia`'s group branch (row `blocked member`) |
| `TestRotateGroupMemberReachesGroupServers` | `validateAccess` iterates `who[:min(1, len(who))]`: `carol`, the second member, loses every server (`bob` would survive this mutant) |
| `TestAdoptMergeHonoursBlockedGroupMember` | `blockTombstoned` iterates `[]string{a.User}` (deleting `Covers`' guard does not fail it: its entry is `@web`, and the raw scan passes a tagless server) |
| `TestImportMergeHonoursBlockedGroupMember` | delete `Covers`' `c.blocked` check |
| `TestAdoptMergeAppendKeepsGroups` | remove `"groups": true` from `topLevelKeys` (exit 3 before the merge) |

**docsDelta (README, lane `editor`).** In **Exit codes**, at the paragraph that begins `A tag problem` (`README.md:2485`), change it to: `` A tag or group problem (an unknown `@tag` or group, a malformed tag or group name, a selector in `except:` or in a tombstone's `servers:`, an entry with both or neither of `user:` and `group:`) is a manifest load error, so it is exit `3` on every command. A blocked grant, the `wildcard_root` warning and the `empty_group` warning change no exit code, except that `validate --strict` exits `1`. ``

---

### Task 13: fuzz seeds and the `FuzzRemoveAccess` oracle

**Files:**
- Modify: `internal/manifest/fuzz_edit_test.go:27-28, 123-146`, `internal/manifest/fuzz_test.go:26`
- Create: `internal/manifest/testdata/fuzz/FuzzRemoveAccess/seed-group-carve-out`, `internal/manifest/testdata/fuzz/FuzzManifestEdit/seed-group-member`, `internal/manifest/testdata/fuzz/FuzzMergeRoundTrip/seed-group-entry`

- [ ] **Step 1: Seeds.** In `FuzzManifestEdit`, after the `tagEditFixture` seeds (`internal/manifest/fuzz_edit_test.go:27-28`), add:

```go
	f.Add(groupEditFixture(f), uint8(1))
	f.Add(groupEditFixture(f), uint8(3))
```

In `FuzzRemoveAccess`, after `f.Add(editFixture(f), uint8(1))`, add:

```go
	f.Add(groupEditFixture(f), uint8(0))
```

In `FuzzMergeRoundTrip`, add `groupEditFixture(f),` to `seeds` (`internal/manifest/fuzz_test.go:26`, before the closing `}`).

- [ ] **Step 2: The oracle.** A group grant reaching the pair is refused by `revoke`, so `RemoveAccess` is never called on it, and the "no longer covers" check would be false for it. In `FuzzRemoveAccess`, after the `server :=` line, add:

```go
		if len(cfg.GroupGrantsReaching(user, server)) > 0 {
			t.Skip() // revoke refuses this pair; RemoveAccess is never called on it
		}
```

Extend `FuzzRemoveAccess`'s comment: after `taking one server from a non-operator user`, add `(a pair no group grant reaches: revoke refuses those)`.

- [ ] **Step 3: Committed corpus.** Write these three files, each with its exact bytes (`gofmt` does not touch them):

`internal/manifest/testdata/fuzz/FuzzRemoveAccess/seed-group-carve-out`:

```text
go test fuzz v1
string("users:\n  - name: bob\n    keys: [\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58\"]\ngroups:\n  - {name: team, members: [bob]}\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: web-2, host: 10.0.0.2, user: deploy}\naccess:\n  - {group: team, servers: [\"*\"], except: [web-2]}\n  - {user: bob, servers: [web-2]}\n")
uint8(16)
```

`internal/manifest/testdata/fuzz/FuzzManifestEdit/seed-group-member`:

```text
go test fuzz v1
string("users:\n  - name: bob\n    keys: [\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58\"]\ngroups:\n  - {name: team, members: [bob]}\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\naccess:\n  - {group: team, servers: [web-1]}\n")
uint8(1)
```

`internal/manifest/testdata/fuzz/FuzzMergeRoundTrip/seed-group-entry`:

```text
go test fuzz v1
string("users:\n  - name: bob\n    keys: [\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58\"]\ngroups:\n  - {name: team, description: d, members: [bob]}\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\naccess:\n  - {group: team, servers: [web-1]}\n")
```

`seed-group-carve-out`'s `uint8(16)` picks bob (the only non-operator) and server index 1, `web-2`: the group's `except:` keeps the pair out of `GroupGrantsReaching`, so the seed runs the trim and is not skipped.

- [ ] **Step 4: Run.**

Run: `GOTOOLCHAIN=go1.27.3 rtk proxy go test ./internal/manifest -v -run '^Fuzz(RemoveAccess|ManifestEdit|MergeRoundTrip)$' && GOTOOLCHAIN=go1.27.3 go test ./internal/manifest -run '^$' -fuzz '^FuzzRemoveAccess$' -fuzztime 20s && GOTOOLCHAIN=go1.27.3 go test ./internal/manifest -run '^$' -fuzz '^FuzzManifestEdit$' -fuzztime 20s`
Expected: PASS. In the verbose run, the three `seed-group-*` entries report `--- PASS`, not `--- SKIP`; a skip means `Load` refused the seed, or `GroupGrantsReaching` reached the carve-out seed, so fix the seed.

**docsDelta:** none. The `Fuzz*` count stays 23.

---

### Task 14: the E2E, mutation run and hand back

**Files:**
- Create: `cmd/sshepherd/groups_e2e_test.go`
- Modify: `scripts/integration.sh:85, 90-94, 121`

- [ ] **Step 1: Fixture accounts.** In `scripts/integration.sh`, append ` grpa grpb` to the user lists at `:85` and `:121` (before `; do`), and to the agent-key-alone list at `:94` (before `; do`). Extend the comment at `:90-92` so it reads `...trima/trimb/overlap: the agent key alone (revoke --from-server and rotate --keep-old E2E); grpa/grpb: the agent key alone (group-grant E2E); ...`.

- [ ] **Step 2: The test.** Create `cmd/sshepherd/groups_e2e_test.go`:

```go
//go:build integration

package main

import (
	"strings"
	"testing"
)

// TestE2EGroupGrant drives one group grant through the design's loop: adopt
// carries the group through, apply installs the member's key on both
// servers, audit is clean, a per-server revoke of the member is refused, a
// full revoke removes the member and the key, and audit is clean again with
// the empty group's warning.
func TestE2EGroupGrant(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	member := itPubLine(t, itKeys(t), "stale")
	dir := t.TempDir()
	m := writeE2EManifest(t, dir, "group.yaml", `
users:
  - {name: op, operator: true, keys: ["`+pub+`"]}
  - {name: tmp, keys: ["`+member+`"]}
groups:
  - {name: team, members: [tmp]}
servers:
  - {name: grp-a, host: `+host+`, port: `+port+`, user: grpa, tags: [grp]}
  - {name: grp-b, host: `+host+`, port: `+port+`, user: grpb, tags: [grp]}
access:
  - {group: team, servers: ["@grp"]}
`)
	code, out, stderr := runBin(t, bin, "adopt", "--config", m, "--known-hosts", kh)
	if code != 0 {
		t.Fatalf("adopt exit = %d (stderr: %s)", code, stderr)
	}
	for _, want := range []string{"groups:", "group: team"} {
		if !strings.Contains(out, want) {
			t.Errorf("adopt output lacks %q:\n%s", want, out)
		}
	}
	adopted := writeE2EManifest(t, dir, "adopted.yaml", out)
	if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", adopted, "--known-hosts", kh); code != 0 {
		t.Fatalf("apply exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	blob := strings.Fields(member)[1]
	for _, user := range []string{"grpa", "grpb"} {
		if got := e2eRemoteCat(t, host, port, kh, user); !strings.Contains(got, blob) {
			t.Errorf("%s lacks the member's key:\n%s", user, got)
		}
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", adopted, "--known-hosts", kh); code != 0 {
		t.Fatalf("audit exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}
	before := readFile(t, adopted)
	code, out, stderr = runBin(t, bin, "revoke", "tmp", "--from-server", "grp-a", "--yes", "--config", adopted, "--known-hosts", kh)
	if code != 3 || !strings.Contains(stderr, "tmp's access to grp-a comes from group team") {
		t.Fatalf("revoke --from-server exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	if readFile(t, adopted) != before {
		t.Error("the refused trim changed the manifest")
	}
	code, out, stderr = runBin(t, bin, "revoke", "tmp", "--yes", "--config", adopted, "--known-hosts", kh)
	if code != 0 || !strings.Contains(out, "manifest edit: remove user tmp (1 key, 0 access grants, 1 group)") {
		t.Fatalf("revoke exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	for _, user := range []string{"grpa", "grpb"} {
		if got := e2eRemoteCat(t, host, port, kh, user); strings.Contains(got, blob) {
			t.Errorf("%s still holds the member's key:\n%s", user, got)
		}
	}
	code, out, stderr = runBin(t, bin, "audit", "--config", adopted, "--known-hosts", kh)
	if code != 0 || !strings.Contains(stderr, `group "team" has no members`) {
		t.Fatalf("final audit exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
}
```

- [ ] **Step 3: Run the lane.**

Run: `make check && make integration`
Expected: PASS. `make check` also runs `make layering`, `deadcode`, and the fuzz seeds as ordinary tests.

- [ ] **Step 4: Mutation run; it must finish before you report.** Apply each mutant alone, run the named test, record killed or survived, revert. Report the table.

| # | Mutant (file) | Killed by |
|---|---|---|
| 1 | `GroupGrantsReaching`: drop the `c.blocked` check | `TestGroupGrantsReaching` (`alice`,`web-2`) and `TestRevokeServerBlockedGroupMember…` |
| 2 | `GroupGrantsReaching`: drop `a.Group == ""` | `TestGroupGrantsReaching` (`bob`,`db-1`) |
| 3 | `GroupGrantsReaching`: drop `entryCovers` | `TestGroupGrantsReaching` (`bob`,`web-3`) |
| 4 | `GroupGrantsReaching`: drop the repeat check | `TestGroupGrantsReaching` (`alice`,`web-1`) |
| 5 | `classifyPairs`: move the group check after `Covers` | `TestRevokeServerRefusedThroughGroup`, `a direct grant too` |
| 6 | `classifyPairs`: delete the group check | `TestRevokeServerRefusedThroughGroup` |
| 7 | `groupRefusal`: print the literal `"1999-01-01"` instead of `date` (a `time.Now()` mutant is not a valid check: on some days the wall clock matches the pinned clock's UTC date) | `TestRevokeServerRefusedThroughGroup` |
| 8 | `RemoveUser`: delete the `dropMember` call | `TestRemoveUserDropsMembership`; `FuzzManifestEdit` seeds (Encode refuses) |
| 9 | `requiredKeys`: put `user` back | `TestGenerateWithGroups` |
| 10 | `requiredKeys`: drop `members` | `TestGenerateWithGroups` (`members: []`) |
| 11 | `GenerateWith`: `groups` not `omitEmpty` | `TestGenerateOmitsEmptyGroups` |
| 12 | `topLevelKeys`: drop `groups` | `TestLoadKeepsGroups`, `TestValidateUnderstandsGroups` |
| 13 | `generateAdoptManifest`: drop `Groups:` | `TestAdoptRegenerateKeepsGroups` |
| 14 | `editText`: drop the group fragment | `TestEditHeaderCountsGroups` |
| 15 | `json.go`: drop `je.Groups` | `TestRevokeUserGroupsJSON` |
| 16 | `revoke.go`: drop `Groups: r.Groups` | `TestRevokeUserDropsGroupMembership` |
| 17 | `accessTombstones`: read `mid.ExceptCarveOut` in the trim loop | `TestRevokeServerKeepsCountIgnoresBlockedGroupPair`, `trim keeps the honest count` |
| 18 | `forgottenCarveOut`: `former.ExceptCarveOut` beside `mid.OwnExceptCarveOut` (the mid-only half fix) | `TestRevokeServerLeavesGroupExceptsAlone` |
| 19 | `OwnExceptCarveOut`: `c.entryApplies(a, user)` in place of `a.User == user` | `TestOwnExceptCarveOut`, `alice`,`web-2` |

- [ ] **Step 5: Hand back.** Report the docsDelta of Tasks 10, 11 and 12, the `editor` CLAUDE.md paragraph below, and the mutation table. Unstage everything outside the lane's globs and write the patch.

**docsDelta (CLAUDE.md, lane `editor`).** Append after lane `schema`'s paragraph:

```markdown
`groups:` flows through `manifest.Draft`/`GenerateWith` (omitted when empty, after `users:`), and
`requiredKeys["Access"]` no longer lists `user`, so a group entry regenerates without a junk key.
`RemoveUser` drops the name from every `groups[].members` (a group left empty stays and warns) and
reports `UserRemoval.Groups`, shown in the edit header and on `remove-user` JSON as `groups`.
`revoke USER --from-server S` is refused when `Config.GroupGrantsReaching` is non-empty, with or
without a direct grant (exit 3, nothing saved); a blocked member gets the D1c note. `NoGrantsLeft`
stays the S3a count, which already answers for groups through `Covers`, so `HasAccessEntry` was not
added. `accessTombstones` and `forgottenCarveOut` read `Config.OwnExceptCarveOut`, so a group's
`except:` is not memory for a personal trim (D1a); `ExceptCarveOut` stays group-aware for adopt and
reconcile. `TestE2EGroupGrant` is the E2E (fixture accounts `grpa`, `grpb`). `FuzzRemoveAccess` skips a
pair a group grant reaches, because `revoke` refuses it.
```

---

## Task 15: integrator (no lane owns this)

- [ ] **Step 1: Per lane, in merge order `schema`, `editor`:** `git apply` the patch, apply that lane's docsDelta (README and CLAUDE.md, listed under Tasks 1, 4, 5, 7 for `schema` and Tasks 10, 11, 12, 14 for `editor`) **before** `make check`, then `make check` (plus `make integration` for lane `editor`). Commit the patch and its docsDelta together, one commit per lane. Lane `editor`'s commit also carries Step 2.

`TestHelpMatchesREADMETables` and `TestHelpExamplesAndExitCodes` pass with the README before or after the delta (no flag or exit footer moved). Apply the delta before `make check` regardless, so the gate runs on the tree being committed.

- [ ] **Step 2: Design amendments** (commit with lane `editor`) in `docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`:

  1. Header `Status`: add `S3b built (plan 2026-11-09-p10-s3b-user-groups)` beside S1, S2, S8 and S3a.
  2. In S3b's **Validation** list, after the empty-group rule, add: `` A bad name reads `group "X": name is not valid: want lowercase letters, digits, '.', '_' or '-', starting with a letter or digit, at most 63 characters`, a repeated name `duplicate group "X"`, an unknown member `group "X": unknown member "y"`, a repeated member `group "X": member "y" is repeated`, and neither or both of `user:` and `group:` `access[N]: set exactly one of user or group`. ``
  3. In **Group access is not a personal grant**, change `` so `Config` exports `HasAccessEntry(user)` and `GroupGrantsReaching(user, server) []string`. `` to `` so `Config` exports `GroupGrantsReaching(user, server) []string`. `directlyGranted` and `accessConflicts` read `a.User`, so a group entry is never direct. ``
  4. In **Editor**, replace the `NoGrantsLeft` bullet with: `` `NoGrantsLeft` stays `KeepsServers == 0` (S3a), which already answers for group access through `Covers`, so a user with group access is not told they have none left. The `HasAccessEntry` this design first named would have had no caller. ``
  5. In the `RemoveUser` bullet, after `reports it in `UserRemoval.Groups``, add `` , shown in the edit header (`1 group`) and additively on `remove-user` JSON as `groups` ``.
  6. In the refusal bullet, after `(exit 3, nothing saved). The date printed is the run's date.`, add `` Two groups reaching the pair are named together: `bob's access to web-1 comes from groups web-team, solo; remove the user from the groups, trim the groups' grants, or add revoked: [{user: bob, servers: [web-1], date: 2026-11-09}] to block only this member`. When a direct grant also exists, the third way out is a W4 conflict until that direct grant is removed too. ``
  7. In **Tests**, change `Manifest edit goldens: remove a member; the refused trim; removing the last member.` to `` Manifest edit goldens: remove a member; removing the last member. The refused trim writes nothing, so a test pins its text and that the file is byte-identical. ``
  8. In **Files**, add `internal/apply/{edit,json}.go`, `scripts/integration.sh`.
  9. In "Order and parallel lanes", change S3b's row to `` A: `internal/config` and the consumer tests · B (after A): `internal/manifest`, `group_reach.go`, `internal/apply/{edit,json}.go`, `revoke.go`, `adopt.go` (a group manifest needs both editor and schema, so one lane) ``.
  10. In S3b's **Semantics**, after the `wildcard_root` sample line, add: `` The entry warns whoever its members are, an empty or all-operator group included (its grant stands for whoever joins later). ``
  11. In **Group access is not a personal grant**, after `A group entry carries an `except:` for every member.`, add: `` `revoke`'s D1a check reads `OwnExceptCarveOut`, which ignores group entries: a group's `except:` stops applying when the member leaves the group, so it is no memory for a personal trim. Adopt and reconcile keep `ExceptCarveOut`. ``

- [ ] **Step 3: Status line in the README.** Append to **Status**, after the Tags line (`README.md:78`), in lane `editor`'s commit:

```markdown
Groups: `groups:` and `access: - group: X` grant every member, a tombstone blocks a group grant for one member only, and `revoke USER --from-server` is refused where a group grant reaches the pair.
```

- [ ] **Step 4:** Confirm `git diff --stat 9319793 -- cmd/sshepherd/testdata/help` lists only `revoke.golden`.

## Task 16: independent verifier (no lane owns this)

Check against `master` after Task 15 and report findings; change nothing.

- [ ] Every validation row of the design's S3b list loads or fails as the design says, with this plan's text where the design gives none (design gap 3).
- [ ] `TestGroupManifestMatchesFlatTwin` passes, and no production code past `internal/config` reads `Access.Group`, except `manifest.GenerateWith` through reflection. This prints nothing: `rtk proxy grep -rnE '\.Group\b' cmd internal --include='*.go' --exclude='*_test.go' | grep -v '^internal/config/' | grep -v 'config\.Group\b'` (the last filter drops the type name in `manifest.Draft`).
- [ ] Tombstones: a member is blocked with the `through group …` warning and other members keep the grant; a literal server inside a group entry is blocked, not a conflict; a `user:` entry beside it is a W4 conflict naming only that entry; `Covers` false and `AccessRevoked` true; no warning for a blocked operator; a key tombstone's `Servers` includes group-rendered servers.
- [ ] Removing `Covers`' `c.blocked` check fails `TestTombstoneBlocksOneGroupMember` and `TestRevokeServerKeepsCountIgnoresBlockedGroupPair`.
- [ ] `validate`: unknown group exit 3 with the `errors` list; `empty_group`, `wildcard_root` and `tombstone_blocks_grant` exit 0, exit 1 under `--strict`, one JSON object each, with `user` only on the last. A group manifest raises no `manifest_not_editable`.
- [ ] `RemoveUser`: both goldens; `revoke USER` reports `1 group` and `groups` in JSON; a group left empty keeps its entry and its access: entry; a user in no group changes no existing golden.
- [ ] `revoke USER --from-server S`: refused (exit 3, byte-identical file) when a group grant reaches the pair, with or without a direct grant, and under `--json` stdout stays empty; a blocked member gets the D1c note; `KeepsServers` is not inflated; `NoGrantsLeft` is still the count and `HasAccessEntry` does not exist.
- [ ] D1a: trimming a direct grant beside a group's `except:` writes an access tombstone with no conflict; a group's `except:` of another server does not become a tombstone; `revoke.go` reads `OwnExceptCarveOut` at all three places and `ExceptCarveOut` not at all, and adopt and reconcile still read `ExceptCarveOut`.
- [ ] The run that empties a group warns on stderr and in its own `--json` document; `audit --json` and `apply --dry-run --json` carry `empty_group` and the group `tombstone_blocks_grant` at exit 0.
- [ ] `rotate`, `adopt --merge` and `import --merge` on a group manifest behave as Task 12 pins; `adopt` regenerates `groups:` and a group entry with no `user:` key.
- [ ] `git diff 9319793 -- cmd/sshepherd/testdata internal/*/testdata` adds only `internal/manifest/testdata/edit_remove_member.golden`, `edit_remove_last_member.golden` and the three `seed-group-*` corpus files, and changes only the reworded tail of `cmd/sshepherd/testdata/help/revoke.golden`.
- [ ] No new exit-2 case exists (D28): a group problem is exit 3, a blocked grant, `empty_group` and the group `wildcard_root` change no exit code outside `validate --strict`. JSON stays schema 1 with no golden changed; `go list -deps ./internal/config ./internal/manifest` names no cobra or transport package (`make layering`).
- [ ] The design amendments of Task 15 Step 2 match the code. No other design text changed.
- [ ] Each lane's mutation table is complete, including the per-test proofs of Tasks 6 and 12, and every survivor is explained.

---

## Review log

Two independent reviews of the draft. Each issue was checked against the code at `9319793` and the design before it was applied. All 16 were applied; none was rejected. "Adjusted" means the fix differs from the one the review proposed.

| Issue | Outcome | Change |
|---|---|---|
| R0-1 | applied, extended | Design gap 10, `OwnExceptCarveOut` (Tasks 10, 14). Added `TestOwnExceptCarveOut`, `TestRevokeServerLeavesGroupExceptsAlone` and mutants 17-19. Adjusted: "no warning" is scoped to `web-2`, because the fixture's blocked `db-1` warns by design. |
| R0-2 | applied | The `carol` iteration asserts stderr; `TestRevokeLastGroupMemberJSONWarns` added (Task 11). |
| R0-3 | applied, adjusted | `TestGroupWarningsInAuditAndApplyJSON` (Task 12). `apply --dry-run` exits 1 on a pending change (`apply.ExitCode`, `plan.go:653-665`), so the test converges with `apply --yes` first, as S3a's `TestBlockedGrantNeverChangesTheExit` does. |
| R0-4 | applied | `rotate` and `import --merge` rows (Task 12). |
| R0-5 | applied | Task 1 docsDelta c; the missing warning is design gap 11, with no code. |
| R0-6 | applied | Four-root row, two rows for empty and all-operator groups (Task 5), mutant 15 (Task 7). |
| R0-7 | applied | Gap 3, amendments 6 and 10, and the header of the design gaps. |
| R0-8 | applied | `TestAdoptMergeAppendKeepsGroups` (Task 12). |
| R0-9 | applied | A `--json` row in `TestRevokeServerRefusedThroughGroup` (Task 10). |
| R1-1 | applied | Mutant 7 prints the literal `"1999-01-01"` (Task 14). |
| R1-2 | applied | Per-test proofs (Task 12); `TestRotateGroupMemberReachesGroupServers` rotates `carol`. |
| R1-3 | applied, adjusted | Per-test proofs (Task 6). The review named two tests for the second-member case. `TestReconcileGroupGrantCoversMember` also needs an `@db` entry, because `Covers`' raw scan answers a `*` entry. `TestReconcileGroupWildcardAbsorbsNewServer` is proved by mutant 2. |
| R1-4 | applied | Task 4. |
| R1-5 | applied | Tasks 10 and 11 Step 2. After R0-1, `TestRevokeServerKeepsCountIgnoresBlockedGroupPair`'s trim subtest now fails first, on `AccessRevoked`. |
| R1-6 | applied | Task 7 cites `:109-113`. |
| R1-7 | applied, adjusted | Task 16 drops `"group"`. It also filters tests and `config.Group`, or `Draft`'s field type in `manifest.go` would be a false hit. |

**Not verified by review or by this revision:**

- `make tidy`, the full `make integration` matrix (`TestE2EGroupGrant` ran on the alpine container only) and a confirmed `make licenses` result. The lane and integrator gates run them.
- The blocks this revision added or changed were not compiled: `OwnExceptCarveOut`, the revised `forgottenCarveOut`, and the tests named above. They were syntax-checked with `gofmt -e` only.
- The review did not run mutants 8-12 of Task 7 or mutants 2-4 of Task 14. Mutants 15 and 17-19 and the proofs marked "not run yet" are new.

## Wave lanes (for the runner)

- **`plan`** (the runner's `args.plan`): `docs/superpowers/plans/2026-11-09-p10-s3b-user-groups.md`, committed before round 1.
- **`handoffs`** (the runner's `args.handoffs`), one entry: "P10-S3b, per lane in the order schema, editor: git apply that lane's patch, apply its docsDelta (README and CLAUDE.md; Tasks 1, 4, 5, 7 for schema; Tasks 10, 11, 12, 14 for editor) before make check, then make check (make integration for lane editor), then commit patch and docsDelta together, one commit per lane. No lane's gate needs a README edit (no flag or exit footer changed; revoke's reworded Long text is only in its help golden), but apply the delta before make check regardless. Lane editor's commit also carries Task 15 Steps 2 and 3."

Rounds run in sequence; lanes inside a round own disjoint files and build only on the previous rounds' commits. Globs are shell `case` patterns (`*` crosses `/`). `README.md` and `CLAUDE.md` are integrator-only: each lane reports its `docsDelta`, and the integrator applies it after the patch and before `make check`.

```json
{
  "rounds": [
    [
      {
        "pkg": "P10-S3b",
        "lane": "schema",
        "kind": "fix",
        "ids": ["PRD-4"],
        "tasks": "Tasks 1-7",
        "files": [
          "internal/config/*",
          "internal/apply/groups_equivalence_test.go",
          "internal/adopt/groups_test.go",
          "internal/reconcile/groups_test.go",
          "internal/audit/groups_test.go",
          "cmd/sshepherd/schema_roundtrip_test.go"
        ],
        "needsIntegration": false
      }
    ],
    [
      {
        "pkg": "P10-S3b",
        "lane": "editor",
        "kind": "fix",
        "ids": ["PRD-4"],
        "tasks": "Tasks 8-14",
        "files": [
          "internal/manifest/*",
          "internal/config/group_reach.go",
          "internal/config/group_reach_test.go",
          "internal/apply/edit.go",
          "internal/apply/json.go",
          "internal/apply/edit_groups_test.go",
          "cmd/sshepherd/revoke.go",
          "cmd/sshepherd/adopt.go",
          "cmd/sshepherd/schema_roundtrip_test.go",
          "cmd/sshepherd/revoke_groups_test.go",
          "cmd/sshepherd/groups_consumers_test.go",
          "cmd/sshepherd/validate_groups_test.go",
          "cmd/sshepherd/groups_e2e_test.go",
          "cmd/sshepherd/testdata/help/revoke.golden",
          "scripts/integration.sh"
        ],
        "needsIntegration": true
      }
    ]
  ],
  "mergeOrder": ["P10-S3b"]
}
```

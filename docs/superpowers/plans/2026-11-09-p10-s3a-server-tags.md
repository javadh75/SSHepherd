# Server tags and `@tag` selectors (P10 S3a, D20, D20a, PRD-5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This plan is executed by the wave runner of `docs/superpowers/plans/2026-11-07-review-remediation.md` ("Reusable workflow skeleton"): lane agents work in git worktrees, never commit, and hand back ownership-filtered patches; the integrator commits once per lane. Where a task says "Hand back", that is the lane's last step, not a commit.

**Commits at:** `docs/superpowers/plans/2026-11-09-p10-s3a-server-tags.md`

**Goal:** Build slice S3a of the approved access-model design (`docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`, section "S3a. Server tags and `@tag` selectors (D20, D20a; PRD-5)", plus its Shared rules and "How selectors meet tombstones"): `tags:` on a server, `@tag` selectors in `access:` that mix with names, `except:` on any selector, the root-wildcard warning, the blocked rule for a tombstone over a tag-derived grant, and `revoke --from-server` trimming a selector entry.

**Architecture:** Expansion stays inside `expandServers`, so `c.grants` and `DesiredFor` do not change shape and nothing past `internal/config` learns what a tag is, except `manifest.RemoveAccess`, which resolves selectors through two exported helpers (`config.IsSelector`, `config.SelectorMatches`). `Covers`, `ExceptCarveOut`, `accessConflicts` and `entryServers` move to shared `entryApplies`/`entryCovers`/`entryDirect` helpers in the new `internal/config/selector.go`. A new `blockTombstoned` step in `Config.validate`, after `validateRevoked`, drops tag-only grants a tombstone covers.

**Tech Stack:** Go 1.27.3 (`GOTOOLCHAIN=go1.27.3`, the Makefile's `GO_PIN`), `gopkg.in/yaml.v3` node editing, Cobra, the hermetic `internal/sshconn/sshtest` server through `editFleet`, goleak, golden files (`-update`), native fuzzing (`FuzzLoad`, `FuzzManifestEdit`, `FuzzMergeRoundTrip`, the new `FuzzRemoveAccess`), golangci-lint (depguard layering, gocyclo 15, revive), `deadcode ./cmd/sshepherd`.

**Base:** `master` at `766aa82`, after S1, S2 and S8. Every `file:line` below was read there. The flags are `import --operator-key` and `revoke --from-server`; `Config.ManifestWarnings` and `audit.ManifestFindings` exist. `master` has since gained `1c64975`, test additions in `cmd/sshepherd/import_json_test.go` and `internal/reconcile/reconcile_test.go`. This plan touches neither file, so every citation still holds.

**Compiled and run (draft blocks only).** Unlike the S8 plan, every Go block of the draft was applied to a clean export of `766aa82` and built there: `go build ./...`, `go vet -tags=integration ./...`, `gofmt`, `goimports`, `golangci-lint run` (0 issues), `deadcode ./cmd/sshepherd` (empty), `gosec -tags=integration ./...` (empty) and `go test -race ./...` all pass, with statement coverage 94.4% across the module (helpers included; the production total is higher). `make integration` was not run on the draft; this slice changes no real-sshd behavior and adds no integration test, and lane `editor` runs the matrix. A mutation pass over the draft killed 17 of 18 mutants; the survivor is the equivalent mutant named in design gap 3. **The review revision was not compiled.** The revision step could write only this plan file, so the blocks it added or changed (marked in the Review log) were checked by reading every helper they call at `master` and by `gofmt -e`. The lane that applies one of them compiles it; on a compile error it fixes the block within its stated intent and reports the fix. The goldens and the corpus entries in Tasks 8 and 10 have not been generated or run.

---

## Design gaps filled here (for the main session)

None of these overrides an answered decision, and no owner answer is needed before the wave runs. Task 12 Step 2 records each in the design. The main session can veto any of them. There is **no real contradiction** between the design and the landed code: P08 and P09 did not touch `expandServers`, `Covers`, `ExceptCarveOut`, `accessConflicts` or `RemoveAccess`, and the design's "until P09-impl lands" notes concern S4/S5, not S3a. P09's `weakConflicts` reads `c.grants` through `serversRendering` after `blockTombstoned` runs, so a blocked pair no longer renders a weak key, which is what the design's "every report then see no access" requires.

1. **Error texts the design leaves open.** The design words `unknown tag`, the reserved-name and `except` errors and the selector-in-tombstone error. It gives no text for five more rows; these become test expectations:
   - bad tag: `server "web-1": tag "Prod" is not valid: want lowercase letters, digits, '.', '_' or '-', starting with a letter or digit, at most 63 characters`;
   - repeated tag: `server "web-1": tag "prod" is repeated`;
   - `@tag` in `except:`: `access for "carol": except takes server names, not the selector "@web"`;
   - a name in `servers:` and `except:`: `access for "carol": "ci" is in both servers and except`;
   - an `@tag` entry that grants nothing after `except:`: `access for "carol": selectors grant no servers after except` (the `*` form keeps today's `wildcard grants no servers`).
2. **`blockTombstoned` derives each pair's sources from `c.Access`** instead of `validateAccess` recording them. The design's order of work (`validateAccess`, `validateRevoked`, `blockTombstoned`) and result are unchanged, and there is no second copy of "how this entry reaches that server" to keep in step with `expandServers`. It uses `latestAccessTombstones` so the load is not quadratic in a long `revoked:` list.
3. **`Covers`' `c.blocked` guard is written as the design says, and cannot fail in S3a.** A blocked pair is reached only through `@tag`, and `Covers`' raw-entry scan passes a tagless `Server{Name: n}`, so the scan already answers false. The guard becomes load-bearing in S3b, where a group entry with `servers: ["*"]` can be blocked. A mutant that deletes it survives this slice's tests: that is the equivalent mutant, and it needs no test here.
4. **`entryCovers(a Access, s Server)` takes the server, not a name**, so a server carrying tags and a future server use one code path: `Covers` passes `Server{Name: server}`, which carries no tags, which is exactly the design's "a `@tag` never covers a server that is not in the manifest yet". `entryServers` and `blockTombstoned` pass the real entry. This also keeps `entryServers` linear in the fleet.
5. **`revoke --from-server '@tag'` reuses the existing `*` refusal**, `--from-server takes server names; to remove all of a user's access use 'sshepherd revoke USER'`, which the design's shorter quote is a prefix of.
6. **`tombstone_blocks_grant` carries `revoked_index`, `user` and `server`; `wildcard_root` carries only `kind` and `message`.** The design's Shared rule gives a manifest warning "`Kind`, `Message` and the existing tombstone fields, which stay omitted for other kinds". `tombstone_blocks_grant` is a tombstone kind and `wildcard_root` is not, so the user stays in the message. The draft added `user` to `wildcard_root`; that contradicted the rule and is withdrawn. With exactly one root account the root warning reads `on web-3;` with no `and 0 more`.
7. **`AccessRemoval.WildcardsRemoved` stays `*`-only.** A deleted `@tag` entry counts in `EntriesRemoved` and prints no "wildcard grant is removed" warning, because a tag does not promise future servers; JSON's `wildcards_removed` stays 0.
8. **The tombstone `*` error keeps its text** (`servers cannot be "*"; list the servers by name`, pinned in the README) and a separate `@`-prefixed check adds `servers cannot hold a selector; list the servers by name`.

## How this plan is cut (read first)

### Why the lanes look the way they do

1. **Two rounds, not three parallel lanes.** The design's row for S3a is A `internal/config` · B `internal/manifest` · C `revoke.go`, `import.go`. The runner needs each lane to compile and pass `make check` on earlier rounds alone. `RemoveAccess` needs `Server.Tags` and `config.IsSelector`, and revoke's trim tests need the new `RemoveAccess`. So round 1 is the whole schema (`internal/config` and the tests that read it), and round 2 is `editor` (`internal/manifest` and `revoke.go`, which depend on each other) beside `import` (`import.go` alone).
2. **`deadcode ./cmd/sshepherd` is part of `make check`.** Every new function is reachable from `Parse` on commit: `ServerNameIssue` from `validateServers`, `IsSelector` and `SelectorMatches` from `expandServers`. `import.go`'s and `edit.go`'s calls in round 2 are additional callers, so no producer lands without a caller.
3. **Between round 1 and round 2 a manifest with `@tag` loads, but `revoke --from-server` cannot trim it.** No test exercises that gap and no fixture has tags until a lane adds them.
4. **`TestSchemaRoundTrip*` reflects over `config.Server`**, so the `Tags` sample in `cmd/sshepherd/schema_roundtrip_test.go` lands in round 1 with the field, or `make check` fails.
5. **One help text changes; no flag or exit-code footer does.** Lane `editor` rewords one clause of `revoke`'s Long text (`a selector grant ('*' or @tag) gains an except: entry`) and regenerates `cmd/sshepherd/testdata/help/revoke.golden`, the only help golden that moves. The README holds no copy of that clause, and `TestHelpMatchesREADMETables` and `TestHelpExamplesAndExitCodes` read only flag tables and exit-code footers, so no lane needs its `docsDelta` for the gate. The integrator still applies each lane's delta in that lane's commit, before `make check`, as every plan does.

### Rounds

| Round | Lane (disjoint files) | Builds on |
|---|---|---|
| 1 | `schema`: `internal/config`, the consumer tests in `internal/{apply,adopt,reconcile,audit}`, `validate_tags_test.go`, `schema_roundtrip_test.go` | `766aa82` |
| 2 | `editor`: `internal/manifest`, `revoke.go`, `internal/apply/edit.go` (one comment), `revoke_tags_test.go`, two `cmd/sshepherd` goldens · `import`: `import.go`, `import_tags_test.go` | round 1 |

After round 2 the integrator runs Task 12 and an independent verifier runs Task 13. No lane owns either.

### Plan decisions (not in the design; none changes an exit code, refusal or load beyond an answered decision)

1. **Fuzz seeds.** `internal/config/testdata/fuzz/FuzzLoad` already holds 16 entries, the CLAUDE.md maximum, so its tag seeds go in `f.Add` only. `FuzzManifestEdit` and `FuzzMergeRoundTrip` hold 3 committed entries each, so each gets one committed tag seed with static key lines beside its `f.Add` seed. Neither target calls `RemoveAccess`, so Task 10 adds `FuzzRemoveAccess` with its own committed corpus; the count of `Fuzz*` targets goes from 22 to 23. `FuzzLoad` also gains two oracles: an accepted server name passes `ServerNameIssue` and an accepted tag matches `tagShape`, and a blocked pair is never in `c.grants` or `Covers`.
2. **No new E2E.** The design's test list has none, expansion ends at `c.grants`, and `TestTaggedManifestMatchesFlatTwin` proves the write path sees identical inputs. The hermetic revoke tests drive a real `revoke` through `sshtest`.

### Conventions every lane follows

- Go runs under the pin: prefix every `go` command with `GOTOOLCHAIN=go1.27.3`. The rtk hook summarizes test output; use `rtk proxy go test …` when exact failure lines matter.
- A golden is rewritten only with `-update` and then read back line by line before it is accepted.
- **Failing first.** Every test is run and seen failing (build failure or assertion) before the code it tests exists; a test that pins behaviour already present says so.
- **gocyclo 15 is a production-code gate;** never `//nolint:gocyclo`.
- **New test variables must not shadow builtins** (revive): no `new`, `len`, `max`, `min`, `copy`, `cap`.
- **Before hand-back:** run `make check` (and `make integration` under the runner's lock when the lane says `needsIntegration`), then `git add -A`, unstage every path outside the lane's globs (`README.md` and `CLAUDE.md` always), and write the patch. No lane in this plan needs a gate-only README change.
- **`docsDelta`** blocks are integrator-only text for `README.md`, `CLAUDE.md` Status and spec Status. A lane reports them unchanged.

---

## File structure

| File | Round/lane | Responsibility |
|---|---|---|
| `internal/config/selector.go` (new) | 1 `schema` | `IsSelector`, `SelectorMatches`, `ServerNameIssue`, `tagShape`, `validateTags`, `grantPair`, `entryApplies`, `entryCovers`, `entryDirect` |
| `internal/config/config.go` | 1 `schema` | `Server.Tags`, `Config.blocked`, `expandServers`/`entryShape`/`tagInUse`, `warnWildcardRoot`, `Covers`, `ExceptCarveOut`, `validate` order |
| `internal/config/revoked.go` | 1 `schema` | `accessShape`, `accessConflicts`, `entryServers`, `blockTombstoned`, `latestAccessTombstones`, `directlyGranted`, `warnBlocked` |
| `internal/config/warnings.go` | 1 `schema` | `WarnWildcardRoot`, `WarnTombstoneBlocksGrant`, the `ManifestWarning` comment |
| `internal/config/selector_test.go` (new), `fuzz_test.go` | 1 `schema` | every validation row, expansion, `Covers`, root warning, tombstones, fuzz seeds and oracles |
| `internal/apply/tags_equivalence_test.go`, `internal/adopt/tags_test.go`, `internal/reconcile/tags_test.go`, `internal/audit/tags_test.go` (all new) | 1 `schema` | equivalence property, no re-extension, D1d drift |
| `cmd/sshepherd/schema_roundtrip_test.go`, `validate_tags_test.go` (new) | 1 `schema` | `Tags` sample, adopt keeps selectors, validate on the new schema, blocked-grant JSON and exits, exit 3 on an unknown tag |
| `internal/manifest/edit.go`, `manifest.go` (package comment) | 2 `editor` | `RemoveAccess` on selector entries, `selectorReach`, `exceptServers` over a reach |
| `internal/manifest/edit_tags_test.go` (new), `testdata/edit_remove_access_tags.golden` and `testdata/edit_remove_access_tags_deleted.golden` (new), `fuzz_test.go`, `fuzz_edit_test.go`, `testdata/fuzz/{FuzzRemoveAccess,FuzzManifestEdit,FuzzMergeRoundTrip}/seed-tag-*` (new) | 2 `editor` | edit shapes, goldens, `FuzzRemoveAccess`, seeds |
| `cmd/sshepherd/revoke.go`, `internal/apply/edit.go` (comment), `revoke_tags_test.go` (new), `testdata/revoke_tag_two_trims.golden` (new), `testdata/help/revoke.golden` | 2 `editor` | `--from-server` refuses selectors; `NoGrantsLeft` counts reach; help text; hermetic trim, two-trim tombstones and golden, D1c note, `--json` trims |
| `cmd/sshepherd/import.go`, `import_tags_test.go` (new) | 2 `import` | an `@` alias skipped with a warning |

---

## Round 1 — lane `schema` (Tasks 1–7)

Owns: `internal/config/*`, `internal/apply/tags_equivalence_test.go`, `internal/adopt/tags_test.go`, `internal/reconcile/tags_test.go`, `internal/audit/tags_test.go`, `cmd/sshepherd/schema_roundtrip_test.go`, `cmd/sshepherd/validate_tags_test.go`. Finding: PRD-5.

### Task 1: tags on a server, and the reserved names

**Files:** Create `internal/config/selector.go`, `internal/config/selector_test.go`. Modify `internal/config/config.go:44`, `:253-261`, `:306`, `cmd/sshepherd/schema_roundtrip_test.go:22`.

- [ ] **Step 1: Write the failing tests.** `internal/config/selector_test.go` (the helpers are shared by later tasks):

```go
package config

import (
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// tagFleet: alice (k1), bob (k2), carol (k3), op (k4, operator); web-1 and
// web-2 are prod+web, web-3 prod+web on root, db-1 prod+db, db-2 db, and ci
// carries no tag. access and extra are appended verbatim.
func tagFleet(t *testing.T, access, extra string) string {
	t.Helper()
	return `users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: carol, keys: ["` + testkeys.Line(t, 3) + `"]}
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 4) + `"]}
servers:
  - {name: web-1, host: 10.0.1.1, user: deploy, tags: [prod, web]}
  - {name: web-2, host: 10.0.1.2, user: deploy, tags: [prod, web]}
  - {name: web-3, host: 10.0.1.3, user: root, tags: [prod, web]}
  - {name: db-1, host: 10.0.2.1, user: deploy, tags: [prod, db]}
  - {name: db-2, host: 10.0.2.2, user: deploy, tags: [db]}
  - {name: ci, host: 10.0.3.1, user: git}
access:
` + access + extra
}

func mustParse(t *testing.T, y string) *Config {
	t.Helper()
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, y)
	}
	return cfg
}

// hasKey reports whether user's key is rendered on server.
func hasKey(t *testing.T, cfg *Config, seed byte, server string) bool {
	t.Helper()
	fp := fpOf(t, seed)
	return slices.ContainsFunc(cfg.DesiredFor(server), func(k authkeys.Key) bool { return k.Fingerprint == fp })
}

func grantedOn(t *testing.T, cfg *Config, seed byte) []string {
	t.Helper()
	var out []string
	for _, s := range cfg.Servers {
		if hasKey(t, cfg, seed, s.Name) {
			out = append(out, s.Name)
		}
	}
	return out
}

func TestTagValidation(t *testing.T) {
	long := strings.Repeat("a", 63)
	const web1 = "  - {name: web-1, host: 10.0.1.1, user: deploy, "
	for _, tc := range []struct{ name, servers, want string }{
		{"uppercase tag", web1 + "tags: [Prod]}\n", `server "web-1": tag "Prod" is not valid`},
		{"leading dash", web1 + "tags: [-prod]}\n", `server "web-1": tag "-prod" is not valid`},
		{"empty tag", web1 + `tags: [""]}` + "\n", `server "web-1": tag "" is not valid`},
		{"tag of 64 characters", web1 + "tags: [" + long + "a]}\n", `tag "` + long + `a" is not valid`},
		{"repeated tag", web1 + "tags: [prod, prod]}\n", `server "web-1": tag "prod" is repeated`},
		{"at-name reserved", "  - {name: web-1, host: 10.0.1.1, user: deploy}\n  - {name: \"@x\", host: 10.0.1.2, user: deploy}\n",
			`servers[1]: name "@x" is reserved for tag selectors`},
		{"wildcard name reserved", "  - {name: \"*\", host: 10.0.1.1, user: deploy}\n",
			`servers[0]: name "*" is reserved for wildcard grants`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte("users: []\nservers:\n" + tc.servers))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
	valid := mustParse(t, "users: []\nservers:\n"+web1+"tags: [a.b_c-d, 9lives, "+long+"]}\n")
	if got := valid.Servers[0].Tags; len(got) != 3 {
		t.Errorf("Tags = %v", got)
	}
}

func TestServerNameIssue(t *testing.T) {
	for name, want := range map[string]string{
		"web-1": "",
		"*":     "is reserved for wildcard grants",
		"@prod": "is reserved for tag selectors",
		"a b":   "contains whitespace",
		"a@b":   "",
	} {
		if got := ServerNameIssue(name); got != want {
			t.Errorf("ServerNameIssue(%q) = %q, want %q", name, got, want)
		}
	}
}
```

- [ ] **Step 2: Run to see it fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run 'TestTagValidation|TestServerNameIssue'`
Expected: build failure, `undefined: ServerNameIssue`.

- [ ] **Step 3: Add the field.** In `internal/config/config.go`, after `AuthorizedKeysFile` (line 44):

```go
	AuthorizedKeysFile string `yaml:"authorized_keys_file"`
	// Tags name this server in @tag selectors of access: entries (spec
	// 2026-11-08 S3a). Each matches tagShape; a tag repeats on no server.
	Tags []string `yaml:"tags"`
}
```

`Tags` is last, so `entryNode` emits it after `authorized_keys_file` and no existing golden moves (an empty slice is omitted).

- [ ] **Step 4: Write `internal/config/selector.go`.** All of it now; later tasks call these helpers.

```go
package config

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// tagSelectorPrefix starts an @tag selector in an access: servers list.
const tagSelectorPrefix = "@"

// tagShape is a valid tag: lowercase, digits, '.', '_' and '-', starting with
// a letter or digit, at most 63 characters.
var tagShape = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// IsSelector reports whether an access: servers item selects servers ("*" or
// "@tag") instead of naming one.
func IsSelector(item string) bool { return item == "*" || isTagSelector(item) }

func isTagSelector(item string) bool { return strings.HasPrefix(item, tagSelectorPrefix) }

// SelectorMatches reports whether selector item reaches server s: "*" reaches
// every server, "@tag" those carrying the tag. A server name is not a
// selector and matches nothing here.
func SelectorMatches(item string, s Server) bool {
	if item == "*" {
		return true
	}
	tag, ok := strings.CutPrefix(item, tagSelectorPrefix)
	return ok && slices.Contains(s.Tags, tag)
}

// ServerNameIssue reports why name cannot be a server name; empty means it
// can. It is ServerFieldIssue plus the names selector syntax reserves.
// Exported so import skips such an alias with a warning instead of generating
// a manifest that fails to load.
func ServerNameIssue(name string) string {
	if issue := ServerFieldIssue(name); issue != "" {
		return issue
	}
	switch {
	case name == "*":
		return "is reserved for wildcard grants"
	case isTagSelector(name):
		return "is reserved for tag selectors"
	}
	return ""
}

// validateTags checks one server's tags: each has tagShape, none repeats.
func validateTags(s *Server) []error {
	var errs []error
	seen := make(map[string]bool, len(s.Tags))
	for _, tag := range s.Tags {
		if !tagShape.MatchString(tag) {
			errs = append(errs, fmt.Errorf("server %q: tag %q is not valid: want lowercase letters, digits, '.', '_' or '-', starting with a letter or digit, at most 63 characters", s.Name, tag))
			continue
		}
		if seen[tag] {
			errs = append(errs, fmt.Errorf("server %q: tag %q is repeated", s.Name, tag))
		}
		seen[tag] = true
	}
	return errs
}

// grantPair is one (user, server) grant.
type grantPair struct{ user, server string }

// entryApplies reports whether access entry a grants to user.
func entryApplies(a Access, user string) bool { return a.User == user }

// entryCovers reports whether entry a reaches server s: named, or selected
// and not excepted. A server not in the manifest is passed as Server{Name: n}:
// it carries no tags, so only "*" can reach it.
func entryCovers(a Access, s Server) bool {
	if slices.Contains(a.Except, s.Name) {
		return false
	}
	return slices.ContainsFunc(a.Servers, func(item string) bool { return item == s.Name || SelectorMatches(item, s) })
}

// entryDirect reports whether entry a reaches server by name or through "*",
// the two forms a tombstone contradicts outright (a D29 policy conflict).
func entryDirect(a Access, server string) bool {
	if slices.Contains(a.Except, server) {
		return false
	}
	return slices.Contains(a.Servers, server) || slices.Contains(a.Servers, "*")
}
```

- [ ] **Step 5: Use it in `validateServers` and `validateServerFields`.** Replace `internal/config/config.go:253-261`:

```go
		if issue := ServerNameIssue(s.Name); issue != "" {
			// %q escapes the hostile runes so the error itself is inert.
			errs = append(errs, fmt.Errorf("servers[%d]: name %q %s", i, s.Name, issue))
			continue
		}
```

and replace `return append(errs, validateAuthorizedKeysFile(s.Name, s.AuthorizedKeysFile)...)` (line 306):

```go
	errs = append(errs, validateTags(s)...)
	return append(errs, validateAuthorizedKeysFile(s.Name, s.AuthorizedKeysFile)...)
```

- [ ] **Step 6: Add the round-trip sample.** `cmd/sshepherd/schema_roundtrip_test.go:22`, on the `"Server"` line, after the `AuthorizedKeysFile` entry add `"Tags": []string{"prod", "web"}`, so the line ends:

```go
"AuthorizedKeysFile": "/etc/ssh/keys/deploy", "Tags": []string{"prod", "web"}},
```

- [ ] **Step 7: Run.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run 'TestTagValidation|TestServerNameIssue' && GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestSchemaRoundTrip|TestAdoptRegenerateKeepsRevokedAndSerial'`
Expected: PASS. The two round-trip tests read the `Tags` sample. They fail with `config.Server.Tags has no sample` without Step 6.

### Task 2: selectors expand inside `expandServers`

**Files:** Modify `internal/config/config.go:410-449`, `internal/config/selector_test.go`.

- [ ] **Step 1: Append the failing tests** to `internal/config/selector_test.go`, and add `"reflect"` to its imports:

```go
func TestTagSelectorExpansion(t *testing.T) {
	for _, tc := range []struct {
		name, access string
		want         []string
	}{
		{"one tag, manifest order", `  - {user: carol, servers: ["@web"]}`, []string{"web-1", "web-2", "web-3"}},
		{"two tags union", `  - {user: carol, servers: ["@web", "@db"]}`, []string{"web-1", "web-2", "web-3", "db-1", "db-2"}},
		{"selector and name mix", `  - {user: carol, servers: ["@db", ci]}`, []string{"db-1", "db-2", "ci"}},
		{"name repeated by a tag", `  - {user: carol, servers: ["@db", db-1]}`, []string{"db-1", "db-2"}},
		{"except removes selector-derived", `  - {user: carol, servers: ["@web", ci], except: [web-2]}`, []string{"web-1", "web-3", "ci"}},
		{"except naming a server outside the tag", `  - {user: carol, servers: ["@db"], except: [ci]}`, []string{"db-1", "db-2"}},
		{"entries union", "  - {user: carol, servers: [\"@db\"]}\n  - {user: carol, servers: [web-1]}", []string{"web-1", "db-1", "db-2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustParse(t, tagFleet(t, tc.access+"\n", ""))
			if got := grantedOn(t, cfg, 3); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("granted on %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSelectorEntryValidation(t *testing.T) {
	for _, tc := range []struct{ name, access, want string }{
		{"unknown tag", `  - {user: carol, servers: ["@prd"]}`, `access for "carol": unknown tag "@prd"`},
		{"empty tag selector", `  - {user: carol, servers: ["@"]}`, `access for "carol": unknown tag "@"`},
		{"malformed tag selector", `  - {user: carol, servers: ["@Prod"]}`, `access for "carol": unknown tag "@Prod"`},
		{"wildcard not alone", `  - {user: carol, servers: ["*", "@prod"]}`, `access for "carol": "*" must be the only servers entry`},
		{"except with names only", `  - {user: carol, servers: [web-1], except: [web-2]}`, `access for "carol": except requires servers ["*"] or an @tag`},
		{"except names an unknown server", `  - {user: carol, servers: ["@prod"], except: [nope]}`, `access for "carol": unknown except server "nope"`},
		{"tag in except", `  - {user: carol, servers: ["@prod"], except: ["@web"]}`, `access for "carol": except takes server names, not the selector "@web"`},
		{"tag in a wildcard's except", `  - {user: carol, servers: ["*"], except: ["@web"]}`, `access for "carol": except takes server names, not the selector "@web"`},
		{"name in servers and except", `  - {user: carol, servers: ["@db", ci], except: [ci]}`, `access for "carol": "ci" is in both servers and except`},
		{"selector grants nothing", `  - {user: carol, servers: ["@db"], except: [db-1, db-2]}`, `access for "carol": selectors grant no servers after except`},
		{"wildcard grants nothing", `  - {user: carol, servers: ["*"], except: [web-1, web-2, web-3, db-1, db-2, ci]}`, `access for "carol": wildcard grants no servers`},
		{"unknown literal beside a tag", `  - {user: carol, servers: ["@db", nope]}`, `access for "carol": unknown server "nope"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tagFleet(t, tc.access+"\n", "")))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run to see it fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run 'TestTagSelectorExpansion|TestSelectorEntryValidation'`
Expected: FAIL; `@web` reaches `validateAccess` as an unknown server.

- [ ] **Step 3: Replace `expandServers`** (`internal/config/config.go:410-449`) with these three functions. `targets` may repeat a server: `validateAccess` already unions.

```go
// expandServers resolves an access entry's server list: each name as
// written, each selector ("*", "@tag") as the servers it reaches in manifest
// order minus the except names. A server reached twice is left for
// validateAccess's union. Errors cover misused selector and except syntax; an
// entry that grants nothing is certainly a mistake.
func (c *Config) expandServers(a Access, servers map[string]bool) ([]string, []error) {
	if errs := c.entryShape(a, servers); len(errs) > 0 {
		return nil, errs
	}
	var targets []string
	for _, item := range a.Servers {
		if !IsSelector(item) {
			targets = append(targets, item)
			continue
		}
		for i := range c.Servers {
			if s := c.Servers[i]; SelectorMatches(item, s) && !slices.Contains(a.Except, s.Name) {
				targets = append(targets, s.Name)
			}
		}
	}
	switch {
	case len(targets) > 0:
		return targets, nil
	case slices.Contains(a.Servers, "*"):
		return nil, []error{fmt.Errorf("access for %q: wildcard grants no servers", a.User)}
	}
	return nil, []error{fmt.Errorf("access for %q: selectors grant no servers after except", a.User)}
}

// entryShape is the access-entry rules that hold before any expansion: "*"
// stands alone, except: needs a selector and lists known server names none of
// which the entry also names, and every @tag is carried by some server.
func (c *Config) entryShape(a Access, servers map[string]bool) []error {
	if slices.Contains(a.Servers, "*") && len(a.Servers) != 1 {
		return []error{fmt.Errorf("access for %q: %q must be the only servers entry", a.User, "*")}
	}
	if len(a.Except) > 0 && !slices.ContainsFunc(a.Servers, IsSelector) {
		return []error{fmt.Errorf(`access for %q: except requires servers ["*"] or an @tag`, a.User)}
	}
	if len(a.Servers) == 0 {
		return []error{fmt.Errorf("access for %q: servers is empty (grants no servers)", a.User)}
	}
	var errs []error
	for _, item := range a.Servers {
		if isTagSelector(item) && !c.tagInUse(item) {
			errs = append(errs, fmt.Errorf("access for %q: unknown tag %q", a.User, item))
		}
	}
	for _, e := range a.Except { // duplicates are tolerated, like grants unioning
		switch {
		case isTagSelector(e):
			errs = append(errs, fmt.Errorf("access for %q: except takes server names, not the selector %q", a.User, e))
		case !servers[e]:
			errs = append(errs, fmt.Errorf("access for %q: unknown except server %q", a.User, e))
		case slices.Contains(a.Servers, e):
			errs = append(errs, fmt.Errorf("access for %q: %q is in both servers and except", a.User, e))
		}
	}
	return errs
}

// tagInUse reports whether any server carries selector's tag.
func (c *Config) tagInUse(selector string) bool {
	return slices.ContainsFunc(c.Servers, func(s Server) bool { return SelectorMatches(selector, s) })
}
```

Update the `Access` comment (`config.go:47-53`):

```go
// Access grants one user access to a list of servers. An item is a server
// name or a selector: "*" (every server, including ones added later; it must
// be the only item) or "@tag" (every server carrying the tag now). Names and
// tags mix as a union; except: removes names from what the selectors reach.
type Access struct {
	User    string   `yaml:"user"`
	Servers []string `yaml:"servers"`
	Except  []string `yaml:"except"` // only valid with a selector in Servers
}
```

- [ ] **Step 4: Run.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config`
Expected: PASS, including the existing `except without wildcard` row, whose `except requires servers` still matches the longer message.

### Task 3: one helper for raw access entries

**Files:** Modify `internal/config/config.go:81`, `:495-540`, `internal/config/selector_test.go`.

- [ ] **Step 1: Append the failing test:**

```go
func TestCoversSelectors(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, `  - {user: alice, servers: ["*"], except: [ci]}
  - {user: carol, servers: ["@db", web-1], except: [db-2]}
`, ""))
	for _, tc := range []struct {
		name, user, server string
		want               bool
	}{
		{"tag member", "carol", "db-1", true},
		{"literal beside a tag", "carol", "web-1", true},
		{"excepted tag member", "carol", "db-2", false},
		{"not in the tag", "carol", "web-2", false},
		{"future server, @tag", "carol", "db-9", false},
		{"future server, wildcard", "alice", "db-9", true},
		{"wildcard's except", "alice", "ci", false},
	} {
		if got := cfg.Covers(tc.user, tc.server); got != tc.want {
			t.Errorf("%s: Covers(%s, %s) = %v, want %v", tc.name, tc.user, tc.server, got, tc.want)
		}
	}
	if !cfg.ExceptCarveOut("carol", "db-2") {
		t.Error("ExceptCarveOut must answer for an @tag entry")
	}
	if cfg.ExceptCarveOut("carol", "web-2") {
		t.Error("a server the except: does not name is no carve-out")
	}
}
```

- [ ] **Step 2: Run to see it fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run TestCoversSelectors`
Expected: FAIL, `ExceptCarveOut must answer for an @tag entry`.

- [ ] **Step 3: Add the field** after `ignored` (`config.go:81`):

```go
	blocked    map[grantPair]bool        // @tag grants an access tombstone dropped (spec "How selectors meet tombstones")
```

- [ ] **Step 4: Replace `Covers` and `ExceptCarveOut`** (`config.go:495-540`, through the end of the file):

```go
// Covers reports whether user's access — explicit grants, a selector minus
// its except: list, not a grant an access tombstone blocked — covers server.
// server need not exist in the manifest yet: a wildcard grant covers future
// servers by design, so beyond the expanded grants (which only know the
// current fleet) the user's raw access entries are scanned, with server as a
// tagless entry: a future server carries no tag, so an @tag never covers it.
//
// Operators' implicit fleet-wide grant is deliberately excluded — check
// Operator first. Reading Covers(op, srv) == false as "no access" would
// contradict DesiredFor, which grants operators every server
// unconditionally.
func (c *Config) Covers(user, server string) bool {
	if c.blocked[grantPair{user, server}] {
		return false
	}
	if slices.Contains(c.grants[server], user) {
		return true
	}
	for _, a := range c.Access {
		if entryApplies(a, user) && entryCovers(a, Server{Name: server}) {
			return true
		}
	}
	return false
}

// ExceptCarveOut reports whether user's access deliberately excludes
// server via an except: list, on a "*" or an @tag entry. Such a server is
// never re-granted by merge tooling — the carve-out is a statement of intent;
// an installed key there is drift.
//
// Callers must only ask about (user, server) pairs the grant union does
// not cover (i.e. after Covers returned false) — outside that context a
// user with an explicit grant of an excepted server would be misclassified.
func (c *Config) ExceptCarveOut(user, server string) bool {
	for _, a := range c.Access {
		if entryApplies(a, user) && slices.Contains(a.Except, server) { // except: requires a selector
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Run.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config`
Expected: PASS.

### Task 4: warn when `*` reaches a root account (D20a)

**Files:** Modify `internal/config/config.go:391`, `internal/config/warnings.go:9`, `internal/config/selector_test.go`.

- [ ] **Step 1: Append the failing test:**

```go
func TestWildcardRootWarning(t *testing.T) {
	roots := "  - {name: r-1, host: 10.0.9.1, user: root}\n  - {name: r-2, host: 10.0.9.2, user: root}\n  - {name: r-3, host: 10.0.9.3, user: root}\n"
	withRoots := func(t *testing.T, access string) string {
		return strings.Replace(tagFleet(t, access, ""), "access:\n", roots+"access:\n", 1)
	}
	const tail = `; list the servers or use an @tag that excludes root accounts`
	for _, tc := range []struct {
		name, y string
		want    []string
	}{
		{"three more", withRoots(t, "  - {user: alice, servers: [\"*\"]}\n"),
			[]string{`access for "alice": servers ["*"] includes the root account on web-3 and 3 more` + tail}},
		{"one root left, no count", tagFleet(t, "  - {user: alice, servers: [\"*\"]}\n", ""),
			[]string{`access for "alice": servers ["*"] includes the root account on web-3` + tail}},
		{"once per entry", tagFleet(t, "  - {user: alice, servers: [\"*\"]}\n  - {user: bob, servers: [\"*\"], except: [ci]}\n", ""),
			[]string{
				`access for "alice": servers ["*"] includes the root account on web-3` + tail,
				`access for "bob": servers ["*"] includes the root account on web-3` + tail,
			}},
		{"except removes the root account", tagFleet(t, "  - {user: alice, servers: [\"*\"], except: [web-3]}\n", ""), nil},
		{"an operator does not warn", tagFleet(t, "  - {user: op, servers: [\"*\"]}\n", ""), nil},
		{"an @tag reaching root does not warn", tagFleet(t, "  - {user: alice, servers: [\"@web\"]}\n", ""), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustParse(t, tc.y)
			if !reflect.DeepEqual(cfg.Warnings, tc.want) {
				t.Errorf("Warnings = %q\nwant %q", cfg.Warnings, tc.want)
			}
			for _, w := range cfg.ManifestWarnings {
				if w.Kind != WarnWildcardRoot || w.User != "" || w.RevokedIndex != nil || w.Server != "" {
					t.Errorf("warning = %+v", w)
				}
			}
		})
	}
}
```

- [ ] **Step 2: Run to see it fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run TestWildcardRootWarning`
Expected: build failure, `undefined: WarnWildcardRoot`.

- [ ] **Step 3: Add the kinds** after `WarnKeyExpired` (`internal/config/warnings.go:9`; Task 5 uses the second):

```go
	WarnWildcardRoot           = "wildcard_root"
	WarnTombstoneBlocksGrant   = "tombstone_blocks_grant"
```

- [ ] **Step 4: Add `warnWildcardRoot` to `config.go`** directly after `tagInUse`:

```go
// warnWildcardRoot records D20a: a non-operator servers: ["*"] entry that
// reaches a root account, once per entry. An operator is fleet-wide by
// definition and an @tag is a deliberate list, so neither warns.
func (c *Config) warnWildcardRoot(a Access, targets []string) {
	if !slices.Contains(a.Servers, "*") || slices.Contains(c.operators, a.User) {
		return
	}
	var roots []string
	for _, s := range c.Servers {
		if s.User == "root" && slices.Contains(targets, s.Name) {
			roots = append(roots, s.Name)
		}
	}
	if len(roots) == 0 {
		return
	}
	where := roots[0]
	if more := len(roots) - 1; more > 0 {
		where = fmt.Sprintf("%s and %d more", where, more)
	}
	c.warn(ManifestWarning{Kind: WarnWildcardRoot, Message: fmt.Sprintf(
		`access for %q: servers ["*"] includes the root account on %s; list the servers or use an @tag that excludes root accounts`,
		a.User, where)})
}
```

and call it in `validateAccess`, right after the `tErrs` check and before the `for _, srv := range targets` loop (`config.go:391-392`):

```go
		c.warnWildcardRoot(a, targets)
```

- [ ] **Step 5: Run.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config`
Expected: PASS.

### Task 5: a tombstone blocks a tag-derived grant

**Files:** Modify `internal/config/config.go:127`, `internal/config/revoked.go:172`, `:276-314`, `internal/config/warnings.go:12-15`, `internal/config/selector_test.go`.

- [ ] **Step 1: Append the failing tests:**

```go
// memoryOnDB is a tombstone removing bob from db-1.
const memoryOnDB = "revoked:\n  - {user: bob, servers: [db-1], date: 2026-11-08}\n"

const blockedDB1 = `access[0]: "bob" is not granted "db-1" through @db: revoked[0] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`

func TestTombstoneBlocksTagGrant(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, "  - {user: bob, servers: [\"@db\"]}\n", memoryOnDB))
	if c := cfg.Conflicts(); len(c) != 0 {
		t.Errorf("Conflicts = %+v, want none: a blocked grant is not a conflict", c)
	}
	if !reflect.DeepEqual(cfg.Warnings, []string{blockedDB1}) {
		t.Errorf("Warnings = %q\nwant %q", cfg.Warnings, blockedDB1)
	}
	w := cfg.ManifestWarnings[0]
	if w.Kind != WarnTombstoneBlocksGrant || w.RevokedIndex == nil || *w.RevokedIndex != 0 || w.User != "bob" || w.Server != "db-1" {
		t.Errorf("warning = %+v", w)
	}
	if got := grantedOn(t, cfg, 2); !reflect.DeepEqual(got, []string{"db-2"}) {
		t.Errorf("granted on %v, want [db-2]", got)
	}
	if cfg.Covers("bob", "db-1") {
		t.Error("Covers must be false for a blocked pair")
	}
	if _, ok := cfg.AccessRevoked("bob", "db-1"); !ok {
		t.Error("AccessRevoked must still answer")
	}
	if cfg.GrantCount() != 1+6 { // bob on db-2, op everywhere
		t.Errorf("GrantCount = %d", cfg.GrantCount())
	}
}

func TestBlockedPairsPerEntryAndLatestTombstone(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, "  - {user: bob, servers: [\"@db\"]}\n  - {user: bob, servers: [\"@prod\"]}\n",
		"revoked:\n  - {user: bob, servers: [db-1], date: 2026-01-01}\n  - {user: bob, servers: [db-1], date: 2026-11-08}\n"))
	want := []string{
		`access[0]: "bob" is not granted "db-1" through @db: revoked[1] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`,
		`access[1]: "bob" is not granted "db-1" through @prod: revoked[1] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`,
	}
	if !reflect.DeepEqual(cfg.Warnings, want) {
		t.Errorf("Warnings = %q\nwant %q", cfg.Warnings, want)
	}
	if got, _ := cfg.AccessRevoked("bob", "db-1"); got.Date != "2026-11-08" {
		t.Errorf("AccessRevoked = %+v; the warning must name the same tombstone", got)
	}
}

func TestLiteralInSameEntryStaysConflict(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, "  - {user: bob, servers: [\"@db\", db-1]}\n", memoryOnDB))
	if len(cfg.Warnings) != 0 {
		t.Errorf("Warnings = %q, want none: a literal is direct", cfg.Warnings)
	}
	want := Conflict{Kind: ConflictRevokedAccess, User: "bob", Servers: []string{"db-1", "db-2"},
		Message: `user "bob" is granted "db-1" by access[0], but revoked[0] removed that access (2026-11-08): remove the grant, or delete the revoked: entry to restore it deliberately`}
	if got := cfg.Conflicts(); len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Errorf("Conflicts = %+v\nwant [%+v]", got, want)
	}
	if !cfg.Covers("bob", "db-1") {
		t.Error("a conflicted pair stays granted")
	}
}

func TestLiteralAndTagInTwoEntriesNamesOnlyLiteralEntry(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, "  - {user: bob, servers: [db-1]}\n  - {user: bob, servers: [\"@db\"]}\n", memoryOnDB))
	got := cfg.Conflicts()
	if len(got) != 1 || !strings.Contains(got[0].Message, "by access[0],") || !reflect.DeepEqual(got[0].Servers, []string{"db-1"}) {
		t.Errorf("Conflicts = %+v, want only access[0], servers [db-1]", got)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("Warnings = %q: the pair is not blocked", cfg.Warnings)
	}
}

func TestBlockedPairLeavesConflictServersAlone(t *testing.T) {
	// web-1 is blocked (through @web), db-1 is a W4 conflict (literal): the
	// conflict's Servers is what the entry renders on, without web-1.
	cfg := mustParse(t, tagFleet(t, "  - {user: bob, servers: [\"@web\", db-1]}\n",
		"revoked:\n  - {user: bob, servers: [db-1, web-1], date: 2026-11-08}\n"))
	got := cfg.Conflicts()
	if len(got) != 1 || !reflect.DeepEqual(got[0].Servers, []string{"web-2", "web-3", "db-1"}) {
		t.Errorf("Conflicts = %+v, want Servers [web-2 web-3 db-1]", got)
	}
}

func TestWildcardOverTombstoneStaysConflict(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, "  - {user: bob, servers: [\"*\"]}\n", memoryOnDB))
	if len(cfg.Conflicts()) != 1 {
		t.Errorf("Conflicts = %+v, want the W4 conflict", cfg.Conflicts())
	}
}

// TestWildcardExceptIsNotDirect: a server a wildcard excepts is not reached
// directly, so an @tag entry reaching it is blocked, not a conflict.
func TestWildcardExceptIsNotDirect(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, "  - {user: bob, servers: [\"*\"], except: [db-1, web-3]}\n  - {user: bob, servers: [\"@db\"]}\n", memoryOnDB))
	if len(cfg.Conflicts()) != 0 || cfg.Covers("bob", "db-1") {
		t.Errorf("Conflicts = %+v, Covers = %v; want blocked", cfg.Conflicts(), cfg.Covers("bob", "db-1"))
	}
	if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], `access[1]: "bob" is not granted "db-1" through @db`) {
		t.Errorf("Warnings = %q", cfg.Warnings)
	}
}

func TestOperatorBlockedPairNoWarning(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, "  - {user: op, servers: [\"@db\"]}\n", "revoked:\n  - {user: op, servers: [db-1], date: 2026-11-08}\n"))
	if len(cfg.Warnings) != 0 || len(cfg.Conflicts()) != 0 {
		t.Errorf("Warnings = %q, Conflicts = %+v, want neither", cfg.Warnings, cfg.Conflicts())
	}
	if !hasKey(t, cfg, 4, "db-1") {
		t.Error("the implicit operator grant must still install the key")
	}
}

func TestTombstoneIgnoredServerDoesNotBlock(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, "  - {user: bob, servers: [\"@db\"]}\n", "revoked:\n  - {user: bob, servers: [db-9], date: 2026-11-08}\n"))
	if got := grantedOn(t, cfg, 2); !reflect.DeepEqual(got, []string{"db-1", "db-2"}) {
		t.Errorf("granted on %v", got)
	}
	if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "unknown server") {
		t.Errorf("Warnings = %q, want only the D1e warning", cfg.Warnings)
	}
}

func TestTombstoneSelectorIsLoadError(t *testing.T) {
	_, err := Parse([]byte(tagFleet(t, "  - {user: bob, servers: [db-1]}\n", "revoked:\n  - {user: bob, servers: [\"@db\"], date: 2026-11-08}\n")))
	if err == nil || !strings.Contains(err.Error(), "revoked[0]: servers cannot hold a selector; list the servers by name") {
		t.Errorf("err = %v", err)
	}
}
```

- [ ] **Step 2: Run to see it fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run 'Tombstone|Blocked|Literal|WildcardExcept'`
Expected: FAIL; a tag grant over a tombstone is still granted. Four tests in the group pin behavior already present at the Task 4 state and pass here: `TestWildcardOverTombstoneStaysConflict`, `TestTombstoneIgnoredServerDoesNotBlock`, `TestOperatorBlockedPairNoWarning` and `TestLiteralAndTagInTwoEntriesNamesOnlyLiteralEntry` (the old `entryServers` does not read `@db`, so only the literal entry is named). They guard Steps 3-6 against regressions. Every other test in the group fails.

- [ ] **Step 3: Refuse a selector in a tombstone.** In `accessShape` (`internal/config/revoked.go:172`), after the `*` check:

```go
	if slices.ContainsFunc(t.Servers, isTagSelector) {
		errs = append(errs, fmt.Errorf("%sservers cannot hold a selector; list the servers by name", p))
	}
```

- [ ] **Step 4: Narrow `accessConflicts` and `entryServers`.** Replace `accessConflicts` (`revoked.go:276-300`) and `entryServers` (`:302-314`):

```go
// accessConflicts: an access: entry for t's user that renders on one of
// t's (known) servers and reaches it directly — named explicitly, or a
// wildcard that does not except it. An @tag reaching it is blocked instead,
// and blockTombstoned leaves such a pair only when another entry is direct, so
// an @tag entry is never the one named here. One conflict per (entry,
// tombstoned server); Servers is every server that entry renders on (spec
// §2), so apply refuses, and audit marks critical, all of them.
func (c *Config) accessConflicts(m int, t Tombstone) []Conflict {
	var out []Conflict
	for n, a := range c.Access {
		if !entryApplies(a, t.User) {
			continue
		}
		covered := c.entryServers(a)
		for _, s := range t.Servers {
			if c.ignored[m][s] || !slices.Contains(covered, s) || !entryDirect(a, s) {
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
// renders its user's keys on: what it names or selects, minus its except:
// list and any pair an access tombstone blocked. Never nil.
func (c *Config) entryServers(a Access) []string {
	out := []string{}
	for _, s := range c.Servers {
		if entryCovers(a, s) && !c.blocked[grantPair{a.User, s.Name}] {
			out = append(out, s.Name)
		}
	}
	return out
}
```

- [ ] **Step 5: Add `blockTombstoned`** and its helpers to `revoked.go`, directly after `entryServers`:

```go
// blockTombstoned drops every (user, server) grant an access tombstone
// covers and no entry reaches directly, so the tombstone acts as an implicit
// except: for that user (spec "How selectors meet tombstones"). The grant
// leaves c.grants, so DesiredFor, apply.Affected and every report see no
// access; c.blocked keeps it out of Covers and entryServers. AccessRevoked
// still answers, which keeps adopt, reconcile, revoke's D1c note and audit's
// D1d label working. Each (entry, user, server) warns, unless the implicit
// operator grant still installs the key.
func (c *Config) blockTombstoned() {
	c.blocked = make(map[grantPair]bool)
	revoked := c.latestAccessTombstones()
	for n, a := range c.Access {
		if len(revoked[a.User]) == 0 {
			continue
		}
		for _, s := range c.Servers {
			m, gone := revoked[a.User][s.Name]
			if !gone || !entryCovers(a, s) || c.directlyGranted(a.User, s.Name) {
				continue
			}
			pair := grantPair{a.User, s.Name}
			c.blocked[pair] = true
			c.grants[s.Name] = slices.DeleteFunc(c.grants[s.Name], func(u string) bool { return u == a.User })
			if !slices.Contains(c.operators, a.User) {
				c.warnBlocked(n, m, a, s)
			}
		}
	}
}

// latestAccessTombstones is AccessRevoked for every pair at once, for
// blockTombstoned: user -> server -> index of the latest access tombstone
// naming it, ignored (D1e) servers skipped. The one-pair walk would make the
// load quadratic in a long revoked: list.
func (c *Config) latestAccessTombstones() map[string]map[string]int {
	out := make(map[string]map[string]int)
	for i, t := range c.Tombstones {
		if t.IsKey() {
			continue
		}
		for _, s := range t.Servers {
			if c.ignored[i][s] {
				continue
			}
			if out[t.User] == nil {
				out[t.User] = make(map[string]int)
			}
			out[t.User][s] = i
		}
	}
	return out
}

// directlyGranted reports an entry of user reaching server by name or "*".
func (c *Config) directlyGranted(user, server string) bool {
	return slices.ContainsFunc(c.Access, func(a Access) bool { return entryApplies(a, user) && entryDirect(a, server) })
}

func (c *Config) warnBlocked(n, m int, a Access, s Server) {
	through := ""
	for _, item := range a.Servers {
		if SelectorMatches(item, s) {
			through = item
			break
		}
	}
	msg := fmt.Sprintf(`access[%d]: %q is not granted %q through %s: revoked[%d] removed that access (%s); delete the revoked: entry to restore it deliberately`,
		n, a.User, s.Name, through, m, c.Tombstones[m].Date)
	c.warn(ManifestWarning{Kind: WarnTombstoneBlocksGrant, RevokedIndex: &m, User: a.User, Server: s.Name, Message: msg})
}
```

- [ ] **Step 6: Run it from `validate`.** `internal/config/config.go:127`:

```go
	errs = append(errs, c.validateRevoked()...)
	c.blockTombstoned() // needs both validateAccess's grants and validateRevoked's ignored set
	return errors.Join(errs...)
```

- [ ] **Step 7: Update the `ManifestWarning` comment** (`internal/config/warnings.go:12-15`):

```go
// ManifestWarning is one load warning in structured form: an object of
// manifest_warnings in the audit, apply and validate JSON. RevokedIndex, User
// and Server belong to tombstone_unknown_server and tombstone_blocks_grant;
// Server also to validate's host_key_not_recorded. RevokedIndex is a pointer
// so revoked[0] still prints.
```

- [ ] **Step 8: Run.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config`
Expected: PASS. `TestAccessTombstoneConflictsExplicitGrant` and the other W4 rows stay green: a literal or `*` is direct, so nothing is blocked and the conflict text is unchanged.

### Task 6: the consumers see tags only through `DesiredFor`, `Covers` and `AccessRevoked`

**Files:** Create `internal/apply/tags_equivalence_test.go`, `internal/adopt/tags_test.go`, `internal/reconcile/tags_test.go`, `internal/audit/tags_test.go`.

These tests pin behavior Tasks 1–5 already deliver. They need no production code; a failure here means a consumer read the raw entries.

- [ ] **Step 1: The equivalence property.** `internal/apply/tags_equivalence_test.go`:

```go
package apply

import (
	"reflect"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// tagEquivFleet parses a tagged fleet. access is the access: block and extra
// is appended verbatim.
func tagEquivFleet(t *testing.T, access, extra string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 3) + `"]}
servers:
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

func fingerprints(keys []authkeys.Key) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Fingerprint)
	}
	return out
}

// TestTaggedManifestMatchesFlatTwin: expansion stays inside expandServers, so
// a tagged manifest and its hand-flattened twin must give every consumer the
// same answer: DesiredFor per server, and Affected from a common starting
// point (spec S3a, equivalence property).
func TestTaggedManifestMatchesFlatTwin(t *testing.T) {
	const blocked = "revoked:\n  - {user: bob, servers: [db-1], date: 2026-11-08}\n"
	for _, tc := range []struct {
		name, tagged, flat, extra string
	}{
		{"one tag", "  - {user: alice, servers: [\"@web\"]}\n", "  - {user: alice, servers: [web-1, web-2]}\n", ""},
		{"tag and name", "  - {user: alice, servers: [\"@db\", ci]}\n", "  - {user: alice, servers: [db-1, ci]}\n", ""},
		{"two tags", "  - {user: alice, servers: [\"@web\", \"@db\"]}\n", "  - {user: alice, servers: [web-1, web-2, db-1]}\n", ""},
		{"except", "  - {user: alice, servers: [\"@prod\"], except: [web-2]}\n", "  - {user: alice, servers: [web-1, db-1]}\n", ""},
		{"wildcard beside a tag entry", "  - {user: alice, servers: [\"*\"], except: [ci]}\n  - {user: bob, servers: [\"@db\"]}\n",
			"  - {user: alice, servers: [web-1, web-2, db-1]}\n  - {user: bob, servers: [db-1]}\n", ""},
		{"blocked tag grant", "  - {user: bob, servers: [\"@prod\"]}\n", "  - {user: bob, servers: [web-1, web-2]}\n", blocked},
		{"access order kept", "  - {user: bob, servers: [\"@web\"]}\n  - {user: alice, servers: [\"@web\"]}\n",
			"  - {user: bob, servers: [web-1, web-2]}\n  - {user: alice, servers: [web-1, web-2]}\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tagged, flat := tagEquivFleet(t, tc.tagged, tc.extra), tagEquivFleet(t, tc.flat, tc.extra)
			before := tagEquivFleet(t, "", tc.extra)
			for _, s := range tagged.Servers {
				if got, want := fingerprints(tagged.DesiredFor(s.Name)), fingerprints(flat.DesiredFor(s.Name)); !reflect.DeepEqual(got, want) {
					t.Errorf("DesiredFor(%s) = %v\nflat twin      = %v", s.Name, got, want)
				}
			}
			if got, want := Affected(before, tagged), Affected(before, flat); !reflect.DeepEqual(got, want) {
				t.Errorf("Affected = %+v\nflat twin = %+v", got, want)
			}
			if got := Affected(flat, tagged); len(got.Servers) != 0 {
				t.Errorf("Affected(flat, tagged) = %+v, want none", got)
			}
		})
	}
}
```

- [ ] **Step 2: Adopt does not re-extend.** `internal/adopt/tags_test.go`:

```go
package adopt

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestBuildHonoursBlockedTagGrant: a tombstone blocks bob's @db grant on
// db-1, and bob's key is still installed there. Adopt must not re-extend him
// (AccessRevoked still answers for a blocked pair).
func TestBuildHonoursBlockedTagGrant(t *testing.T) {
	cfg := parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: bob, keys: ["`+testkeys.Line(t, 2)+`"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy, tags: [db]}
  - {name: db-2, host: 10.0.0.4, user: deploy, tags: [db]}
access:
  - {user: bob, servers: ["@db"]}
revoked:
  - {user: bob, servers: [db-1], date: 2026-11-08}
`)
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

// TestBuildExceptOnTagEntryNotExtended: a key found on a server an @tag
// entry's except: excludes is the carve-out warning, not an extension.
func TestBuildExceptOnTagEntryNotExtended(t *testing.T) {
	cfg := parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: bob, keys: ["`+testkeys.Line(t, 2)+`"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy, tags: [db]}
  - {name: db-2, host: 10.0.0.4, user: deploy, tags: [db]}
access:
  - {user: bob, servers: ["@db"], except: [db-1]}
`)
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
```

- [ ] **Step 3: Reconcile does not re-extend; a tag never covers a new server.** `internal/reconcile/tags_test.go`:

```go
package reconcile

import (
	"testing"

	"github.com/javadh75/SSHepherd/internal/identity"
	"github.com/javadh75/SSHepherd/internal/sshcfg"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// tagCfg: bob (k4) holds @db minus db-2, and a tombstone blocks db-1.
func tagCfg(t *testing.T) string {
	t.Helper()
	return `
users:
  - {name: bob, keys: ["` + testkeys.Line(t, 4) + `"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy, tags: [db]}
  - {name: db-2, host: 10.0.0.4, user: deploy, tags: [db]}
  - {name: db-3, host: 10.0.0.5, user: deploy, tags: [db]}
access:
  - {user: bob, servers: ["@db"], except: [db-2]}
revoked:
  - {user: bob, servers: [db-1], date: 2026-11-08}
`
}

func TestReconcileHonoursBlockedTagGrant(t *testing.T) {
	p := mustBuild(t, parseCfg(t, tagCfg(t)), nil, []identity.User{{Name: "bob", Source: "~/.ssh/id_bob", Key: testkeys.Line(t, 4), Servers: []string{"db-1"}}})
	if len(p.Extensions) != 0 {
		t.Fatalf("Extensions = %+v, want none", p.Extensions)
	}
	wantContains(t, "Warnings", messages(p.Warnings),
		"key "+mustFP(t, testkeys.Line(t, 4))+` of "bob" found on "db-1", whose access was revoked (2026-11-08) — not re-granted; audit flags this drift`)
}

func TestReconcileExceptOnTagEntryNotExtended(t *testing.T) {
	p := mustBuild(t, parseCfg(t, tagCfg(t)), nil, []identity.User{{Name: "bob", Source: "~/.ssh/id_bob", Key: testkeys.Line(t, 4), Servers: []string{"db-2"}}})
	if len(p.Extensions) != 0 {
		t.Fatalf("Extensions = %+v, want none", p.Extensions)
	}
	wantContains(t, "Warnings", messages(p.Warnings), "which their except: list deliberately excludes")
}

// TestReconcileTagNeverCoversNewServer: only "*" covers a server the manifest
// does not have yet; an @tag grant is extended by name like any other.
func TestReconcileTagNeverCoversNewServer(t *testing.T) {
	p := mustBuild(t, parseCfg(t, tagCfg(t)),
		[]sshcfg.Host{{Alias: "db-9", HostName: "10.0.0.9", User: "deploy"}},
		[]identity.User{{Name: "bob", Source: "~/.ssh/id_bob", Key: testkeys.Line(t, 4), Servers: []string{"db-9"}}})
	if len(p.Extensions) != 1 || p.Extensions[0].User != "bob" || p.Extensions[0].Servers[0] != "db-9" {
		t.Errorf("Extensions = %+v, want bob extended to db-9 by name", p.Extensions)
	}
}

// TestReconcileTaggedServerIdentical: tags are manifest-only, so a tagged
// server matching the ssh config is an identical re-run, not a conflict.
func TestReconcileTaggedServerIdentical(t *testing.T) {
	p := mustBuild(t, parseCfg(t, tagCfg(t)),
		[]sshcfg.Host{{Alias: "db-1", HostName: "10.0.0.3", User: "deploy"}}, nil)
	if len(p.Warnings) != 0 || len(p.NewServers) != 0 {
		t.Errorf("plan = %+v, want a silent identical skip", p)
	}
}
```

- [ ] **Step 4: Audit's D1d drift.** `internal/audit/tags_test.go`:

```go
package audit

import (
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestBlockedTagGrantIsDrift (D1d): bob's @web grant over web-2 is blocked
// by a tombstone. His key still on web-2 is the "access revoked" drift, with
// the same label and exit 1 as a removed literal grant. With the key absent,
// the warning alone exits 0 (cmd's TestBlockedGrantNeverChangesTheExit).
func TestBlockedTagGrantIsDrift(t *testing.T) {
	cfg, err := config.Parse([]byte(`serial: 7
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 3) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}
  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}
access:
  - {user: alice, servers: [web-1, web-2]}
  - {user: bob, servers: ["@web"]}
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

### Task 7: `validate`, generation and fuzz; hand back

**Files:** Create `cmd/sshepherd/validate_tags_test.go`. Modify `cmd/sshepherd/schema_roundtrip_test.go` (new test before line 104), `internal/config/fuzz_test.go:50`, `:68-74`.

These tests pin behavior Tasks 1–5 already deliver, so they pass as soon as they are written. They need no production code; a failure here means a command reads the raw entries.

- [ ] **Step 1: `validate`, the JSON warning objects and the exit codes.** `cmd/sshepherd/validate_tags_test.go`:

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

// validateTagManifest: alice granted "@web", web-1 root, web-2 deploy.
func validateTagManifest(t *testing.T, access, extra string) string {
	t.Helper()
	return "users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n" +
		"servers:\n  - {name: web-1, host: 10.0.1.5, user: root, tags: [web]}\n  - {name: web-2, host: 10.0.1.6, user: deploy, tags: [web]}\n" +
		"access:\n" + access + extra
}

func TestValidateUnderstandsTags(t *testing.T) {
	path := writeConfig(t, validateTagManifest(t, "  - {user: alice, servers: [\"@web\"]}\n", ""))
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", recordedKnownHosts(t, "10.0.1.5", "10.0.1.6"))
	if code != 0 || out != "manifest OK: 1 user, 2 servers, 2 grants (0 warnings)\n" {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
}

func TestValidateUnknownTagExit3(t *testing.T) {
	path := writeConfig(t, validateTagManifest(t, "  - {user: alice, servers: [\"@wbe\"]}\n", ""))
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", recordedKnownHosts(t))
	if code != 3 || out != "" || !strings.Contains(stderr, `access for "alice": unknown tag "@wbe"`) {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
	code, out, _ = validateCLI(t, "--json", "--config", path, "--known-hosts", recordedKnownHosts(t))
	doc := oneJSONDoc(t, out)
	if code != 3 || doc["valid"] != false {
		t.Fatalf("--json: exit = %d, doc = %v", code, doc)
	}
	errs, _ := doc["errors"].([]any)
	if len(errs) != 1 || errs[0] != `access for "alice": unknown tag "@wbe"` {
		t.Errorf("errors = %v", doc["errors"])
	}
}

// TestValidateTagWarnings: wildcard_root and tombstone_blocks_grant are
// warnings: exit 0, exit 1 only under --strict, one JSON object each. The
// exact object pins which fields each kind carries (spec "Manifest warnings
// in JSON": the tombstone fields stay omitted for other kinds).
func TestValidateTagWarnings(t *testing.T) {
	for _, tc := range []struct {
		name, access, extra, kind, stderr string
		fields                            map[string]any
	}{
		{"root wildcard", "  - {user: alice, servers: [\"*\"]}\n", "", "wildcard_root",
			`access for "alice": servers ["*"] includes the root account on web-1; list the servers or use an @tag that excludes root accounts`, nil},
		{"blocked grant", "  - {user: alice, servers: [\"@web\"]}\n", "revoked:\n  - {user: alice, servers: [web-2], date: 2026-11-08}\n", "tombstone_blocks_grant",
			`access[0]: "alice" is not granted "web-2" through @web: revoked[0] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`,
			map[string]any{"revoked_index": float64(0), "user": "alice", "server": "web-2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, validateTagManifest(t, tc.access, tc.extra))
			kh := recordedKnownHosts(t, "10.0.1.5", "10.0.1.6")
			code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", kh)
			if code != 0 || !strings.Contains(out, "(1 warning)") || !strings.Contains(stderr, tc.stderr) {
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
			want := map[string]any{"kind": tc.kind, "message": tc.stderr}
			for k, v := range tc.fields {
				want[k] = v
			}
			if !reflect.DeepEqual(ws[0], want) {
				t.Errorf("warning = %v\nwant %v", ws[0], want)
			}
		})
	}
}

// blockedTagFleet: alice (k1, held) holds web-1 and web-2 by name, bob (k2)
// holds @web, a tombstone blocks him on web-2, and each server holds exactly
// the keys the manifest grants there (bob's key is absent from web-2).
func blockedTagFleet(t *testing.T) (string, string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	hosts["web-1"].install(t, []byte{1, 2})
	hosts["web-2"].install(t, []byte{1})
	tagged := func(name string) string {
		return strings.TrimSuffix(hosts[name].line(name), "}\n") + ", tags: [web]}\n"
	}
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+tagged("web-1")+tagged("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: bob, servers: [\"@web\"]}\n"+
		"revoked:\n  - {user: bob, servers: [web-2], date: 2026-11-08}\n")
	return cfg, kh
}

// wantBlockedWarning checks the one tombstone_blocks_grant object of a run
// against blockedTagFleet; revoked_index 0 is why that field is a pointer.
func wantBlockedWarning(t *testing.T, doc map[string]any) {
	t.Helper()
	ws, _ := doc["manifest_warnings"].([]any)
	if len(ws) != 1 {
		t.Fatalf("manifest_warnings = %v", doc["manifest_warnings"])
	}
	w := ws[0].(map[string]any)
	if w["kind"] != "tombstone_blocks_grant" || w["revoked_index"] != float64(0) || w["user"] != "bob" || w["server"] != "web-2" {
		t.Errorf("warning = %v", w)
	}
}

// TestBlockedGrantNeverChangesTheExit (spec Shared rules): with the key absent
// a blocked grant is a warning and exit 0, on audit and on apply. apply goes
// through its own cleanMemory copy of the warnings.
func TestBlockedGrantNeverChangesTheExit(t *testing.T) {
	cfg, kh := blockedTagFleet(t)
	wantBlockedWarning(t, runJSONDoc(context.Background(), t, 0, "audit", "--json", "--config", cfg, "--known-hosts", kh))
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("apply: exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	wantBlockedWarning(t, runJSONDoc(context.Background(), t, 0, "apply", "--dry-run", "--json", "--config", cfg, "--known-hosts", kh))
}

// TestUnknownTagExit3EveryCommand: an unknown @tag is a manifest load error,
// so every command that reads the manifest exits 3 before it dials.
func TestUnknownTagExit3EveryCommand(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, validateTagManifest(t, "  - {user: alice, servers: [\"@wbe\"]}\n", ""))
	for _, args := range [][]string{
		{"audit", "--config", path},
		{"apply", "--dry-run", "--config", path},
		{"revoke", "alice", "--dry-run", "--config", path},
		{"adopt", "--config", path},
	} {
		t.Run(args[0], func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := run(args, &out, &errBuf)
			if code != 3 || out.Len() != 0 || !strings.Contains(errBuf.String(), `access for "alice": unknown tag "@wbe"`) {
				t.Errorf("exit = %d, stdout = %q, stderr = %q", code, out.String(), errBuf.String())
			}
		})
	}
}
```

- [ ] **Step 2: adopt keeps a selector entry.** In `cmd/sshepherd/schema_roundtrip_test.go`, before `TestAdoptRegenerateKeepsRevokedAndSerial`:

```go
// TestAdoptRegenerateKeepsTagSelectors: adopt carries access: entries from
// the loaded config, so an @tag selector and its except: come back unchanged.
func TestAdoptRegenerateKeepsTagSelectors(t *testing.T) {
	cfg, _, _, _ := roundTripConfig(t)
	cfg.Access = []config.Access{{User: "bob", Servers: []string{"@web", "web-2"}, Except: []string{"web-1"}}}
	out, err := generateAdoptManifest(cfg, adopt.Plan{}, "rt.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := config.Parse(out)
	if err == nil && reflect.DeepEqual(got.Access, cfg.Access) {
		return
	}
	t.Errorf("adopt changed the selector entry (err %v):\n%s", err, out)
}
```

- [ ] **Step 3: Fuzz seeds and oracles.** In `FuzzLoad` (`internal/config/fuzz_test.go`), add to `seeds`, after the `serial: -1`/`revoked:` entries (line 50):

```go
		// tags, @tag selectors, a blocked grant, reserved names
		`
users:
  - {name: bob, keys: ["` + k2 + `"]}
servers:
  - {name: s1, host: h1, user: root, tags: [prod, a.b_c-d]}
  - {name: s2, host: h2, user: u, tags: [prod, prod]}
  - {name: "@x", host: h3, user: u, tags: [Bad]}
access:
  - {user: bob, servers: ["@prod", s2], except: [s1]}
  - {user: bob, servers: ["@nope"]}
revoked:
  - {user: bob, servers: [s2, "@prod"], date: 2026-11-08}
`,
		`
users:
  - {name: bob, keys: ["` + k2 + `"]}
servers:
  - {name: s1, host: h1, user: root, tags: [prod]}
  - {name: s2, host: h2, user: u, tags: [prod]}
access:
  - {user: bob, servers: ["@prod"]}
revoked:
  - {user: bob, servers: [s2], date: 2026-11-08}
`,
```

and extend the server loop's checks, before `checkRenderRoundTrip`, then add the blocked-pair check after the loop:

```go
			if issue := ServerNameIssue(s.Name); issue != "" {
				t.Fatalf("accepted server name %q %s", s.Name, issue)
			}
			for _, tag := range s.Tags {
				if !tagShape.MatchString(tag) {
					t.Fatalf("accepted tag %q on %q", tag, s.Name)
				}
			}
			checkRenderRoundTrip(t, cfg, s.Name)
		}
		for pair := range cfg.blocked {
			if cfg.Covers(pair.user, pair.server) || slices.Contains(cfg.grants[pair.server], pair.user) {
				t.Fatalf("blocked pair %+v is still granted", pair)
			}
		}
```

- [ ] **Step 4: Run everything in the lane, plus a short fuzz.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config ./internal/apply ./internal/adopt ./internal/reconcile ./internal/audit ./cmd/sshepherd && GOTOOLCHAIN=go1.27.3 go test ./internal/config -run '^$' -fuzz '^FuzzLoad$' -fuzztime 20s`
Expected: PASS; the fuzz run ends with no new failure.

- [ ] **Step 5: Hand back.** `make check`. No lane test reads a README line this slice changes, so no gate-only README edit is needed. Report the `docsDelta` of Task 12 Step 3, block `schema`. Unstage everything outside the lane's globs and write the patch.

---

## Round 2 — lane `editor` (Tasks 8–10)

Owns: `internal/manifest/*`, `internal/apply/edit.go`, `cmd/sshepherd/revoke.go`, `cmd/sshepherd/revoke_tags_test.go`, `cmd/sshepherd/testdata/revoke_tag_two_trims.golden`, `cmd/sshepherd/testdata/help/revoke.golden`. Finding: PRD-5. Builds on round 1.

### Task 8: `RemoveAccess` on a selector entry

**Files:** Create `internal/manifest/edit_tags_test.go`, `internal/manifest/testdata/edit_remove_access_tags.golden`, `internal/manifest/testdata/edit_remove_access_tags_deleted.golden`, `cmd/sshepherd/revoke_tags_test.go`, `cmd/sshepherd/testdata/revoke_tag_two_trims.golden`. Modify `internal/manifest/edit.go:245`, `:250-259`, `:297-315`, `:318-341`, `:343-378`, `internal/manifest/manifest.go:16-18`.

- [ ] **Step 1: Write the failing tests.** `internal/manifest/edit_tags_test.go`:

```go
package manifest

import (
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// tagEditFixture: bob holds @web and db-1 mixed, alice a block-style @db,
// carol a wildcard. web-1 and web-2 are tagged web; db-1 and db-2 db.
func tagEditFixture(tb testing.TB) string {
	tb.Helper()
	return `# fleet manifest
users:
  - {name: alice, keys: ["` + testkeys.Line(tb, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(tb, 4) + `"]}
  - {name: carol, keys: ["` + testkeys.Line(tb, 5) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]} # front
  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}
  - {name: db-1, host: 10.0.0.9, user: deploy, tags: [db]}
  - {name: db-2, host: 10.0.0.8, user: deploy, tags: [db]}
access:
  # bob: the web tier and a db
  - user: bob
    servers: ["@web", db-1] # reviewed 2026-10
  # alice: every db
  - user: alice
    servers:
      - "@db"
  # carol: everywhere
  - user: carol
    servers: ["*"]
# end of manifest
`
}

func TestRemoveAccessSelectors(t *testing.T) {
	for _, tc := range []struct {
		name, user string
		servers    []string
		want       AccessRemoval
		yaml       string
		grants     []string
	}{
		{"tag member: except created after servers, flow", "bob", []string{"web-2"},
			AccessRemoval{EntriesChanged: 1, ServersExcepted: 1},
			"    servers: [\"@web\", db-1] # reviewed 2026-10\n    except: [web-2]\n", []string{"web-1", "db-1"}},
		{"literal item only", "bob", []string{"db-1"}, AccessRemoval{EntriesChanged: 1},
			"    servers: [\"@web\"] # reviewed 2026-10\n", []string{"web-1", "web-2"}},
		{"tag member and literal together", "bob", []string{"web-1", "db-1"},
			AccessRemoval{EntriesChanged: 1, ServersExcepted: 1},
			"    servers: [\"@web\"] # reviewed 2026-10\n    except: [web-1]\n", []string{"web-2"}},
		{"block style: except stays block", "alice", []string{"db-1"},
			AccessRemoval{EntriesChanged: 1, ServersExcepted: 1},
			"    servers:\n      - \"@db\"\n    except:\n      - db-1\n", []string{"db-2"}},
		{"wildcard behaves as before", "carol", []string{"db-1"},
			AccessRemoval{EntriesChanged: 1, ServersExcepted: 1},
			"    servers: [\"*\"]\n    except: [db-1]\n", []string{"web-1", "web-2", "db-2"}},
		{"name kept: tag fully excepted, entry stays", "bob", []string{"web-1", "web-2"},
			AccessRemoval{EntriesChanged: 1, ServersExcepted: 2},
			"    servers: [\"@web\", db-1] # reviewed 2026-10\n    except: [web-1, web-2]\n", []string{"db-1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := loadFixture(t, tagEditFixture(t))
			r, err := f.RemoveAccess(tc.user, tc.servers)
			if err != nil {
				t.Fatalf("RemoveAccess: %v", err)
			}
			if r != tc.want {
				t.Errorf("AccessRemoval = %+v, want %+v", r, tc.want)
			}
			out, cfg := encodeParsed(t, f)
			inOrder(t, out, tc.yaml)
			if got := grantsOf(cfg, tc.user); !slices.Equal(got, tc.grants) {
				t.Errorf("grants = %v, want %v", got, tc.grants)
			}
			inOrder(t, out, "tags: [web]} # front\n", "# bob: the web tier", "# alice: every db", "# carol: everywhere", "# end of manifest")
		})
	}
}

// TestRemoveAccessTagMemberAlsoNamed: a server both named and reached by a
// tag loses the name and gains except:, or the entry would still reach it.
func TestRemoveAccessTagMemberAlsoNamed(t *testing.T) {
	f := loadFixture(t, "users:\n  - {name: bob, keys: [\""+testkeys.Line(t, 4)+"\"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}\n  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}\n"+
		"access:\n  - {user: bob, servers: [\"@web\", web-1]}\n")
	r, err := f.RemoveAccess("bob", []string{"web-1"})
	if err != nil || r != (AccessRemoval{EntriesChanged: 1, ServersExcepted: 1}) {
		t.Fatalf("RemoveAccess = (%+v, %v)", r, err)
	}
	out, cfg := encodeParsed(t, f)
	inOrder(t, out, "{user: bob, servers: [\"@web\"], except: [web-1]}")
	if got := grantsOf(cfg, "bob"); !slices.Equal(got, []string{"web-2"}) {
		t.Errorf("grants = %v, want [web-2]", got)
	}
}

// TestRemoveAccessTagEntryDeleted: nothing named and every tag member
// excepted: the entry goes, its head comment rescued, no wildcard counted.
func TestRemoveAccessTagEntryDeleted(t *testing.T) {
	f := loadFixture(t, tagEditFixture(t))
	r, err := f.RemoveAccess("alice", []string{"db-1", "db-2"})
	if err != nil || r != (AccessRemoval{EntriesRemoved: 1}) {
		t.Fatalf("RemoveAccess = (%+v, %v), want one entry removed, no wildcard", r, err)
	}
	out, cfg := encodeParsed(t, f)
	if strings.Contains(out, "- user: alice") || len(grantsOf(cfg, "alice")) != 0 {
		t.Errorf("alice's entry survived:\n%s", out)
	}
	inOrder(t, out, "# alice: every db\n  # carol: everywhere\n  - user: carol\n")
	checkGolden(t, "edit_remove_access_tags_deleted.golden", []byte(out))
}

// TestRemoveAccessMixedFullyTrimmed: the name goes and every tag member is
// excepted, so nothing is left: the entry is deleted.
func TestRemoveAccessMixedFullyTrimmed(t *testing.T) {
	f := loadFixture(t, tagEditFixture(t))
	r, err := f.RemoveAccess("bob", []string{"web-1", "web-2", "db-1"})
	if err != nil || r != (AccessRemoval{EntriesRemoved: 1}) {
		t.Fatalf("RemoveAccess = (%+v, %v)", r, err)
	}
	out, _ := encodeParsed(t, f)
	if strings.Contains(out, "- user: bob") || strings.Contains(out, "reviewed 2026-10") {
		t.Errorf("bob's entry survived:\n%s", out)
	}
}

// TestRemoveAccessTagNotCovered: a server the entry neither names nor
// selects is left alone, byte for byte.
func TestRemoveAccessTagNotCovered(t *testing.T) {
	want, err := loadFixture(t, tagEditFixture(t)).Encode()
	if err != nil {
		t.Fatal(err)
	}
	f := loadFixture(t, tagEditFixture(t))
	r, err := f.RemoveAccess("alice", []string{"web-1"})
	if err != nil || r != (AccessRemoval{}) {
		t.Fatalf("RemoveAccess = (%+v, %v), want nothing changed", r, err)
	}
	if out, _ := encodeParsed(t, f); out != string(want) {
		t.Errorf("an uncovered entry was edited:\n%s", out)
	}
}

// TestRemoveAccessSecondTrimDeletesEntry: except: from the first trim stays
// until the last one removes the entry; each run re-parses, as revoke does.
func TestRemoveAccessSecondTrimDeletesEntry(t *testing.T) {
	f := loadFixture(t, tagEditFixture(t))
	if _, err := f.RemoveAccess("alice", []string{"db-1"}); err != nil {
		t.Fatal(err)
	}
	out, _ := encodeParsed(t, f)
	second := loadFixture(t, out)
	r, err := second.RemoveAccess("alice", []string{"db-2"})
	if err != nil || r != (AccessRemoval{EntriesRemoved: 1}) {
		t.Fatalf("second trim = (%+v, %v)", r, err)
	}
	if last, _ := encodeParsed(t, second); strings.Contains(last, "- user: alice") {
		t.Errorf("the entry survived:\n%s", last)
	}
}

// TestRemoveAccessTagGolden: one File, the three shapes trimmed, one Encode.
func TestRemoveAccessTagGolden(t *testing.T) {
	f := loadFixture(t, tagEditFixture(t))
	for _, c := range []struct {
		user    string
		servers []string
	}{{"bob", []string{"web-2", "db-1"}}, {"alice", []string{"db-2"}}, {"carol", []string{"web-1"}}} {
		if _, err := f.RemoveAccess(c.user, c.servers); err != nil {
			t.Fatalf("RemoveAccess(%s): %v", c.user, err)
		}
	}
	out, _ := encodeParsed(t, f)
	checkGolden(t, "edit_remove_access_tags.golden", []byte(out))
}
```

Then `cmd/sshepherd/revoke_tags_test.go`, the two tests that need this task's trim; Task 9 appends the rest:

```go
package main

import (
	"bytes"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// tagFleetManifest: alice (k1, held) holds web-1 and web-2 by name, bob (k2)
// holds @web, and both keys are installed on both servers.
func tagFleetManifest(t *testing.T) (map[string]editHost, string, string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	for _, h := range hosts {
		h.install(t, []byte{1, 2})
	}
	tagged := func(name string) string {
		return strings.TrimSuffix(hosts[name].line(name), "}\n") + ", tags: [web]}\n"
	}
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+tagged("web-1")+tagged("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: bob, servers: [\"@web\"]}\n")
	return hosts, kh, cfg
}

// normalizedManifest is the saved manifest with what varies per run replaced:
// the date of this run's tombstone and each server's port.
func normalizedManifest(t *testing.T, path string) []byte {
	t.Helper()
	out := regexp.MustCompile(`date: \d{4}-\d{2}-\d{2}`).ReplaceAll(fileBytes(t, path), []byte("date: DATE"))
	return regexp.MustCompile(`port: \d+`).ReplaceAll(out, []byte("port: PORT"))
}

// TestRevokeServerTrimsTagGrant: the tag entry gains except: (no tombstone,
// the except: remembers), bob's key leaves web-1 only and web-2 is untouched.
func TestRevokeServerTrimsTagGrant(t *testing.T) {
	hosts, kh, cfg := tagFleetManifest(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--from-server", "web-1", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "manifest edit: remove bob's access to web-1 (1 access entry changed, 1 server excepted); bob keeps access to 1 other server — 1 server affected\n") {
		t.Errorf("stdout:\n%s", out.String())
	}
	saved := readCfg(t, cfg)
	if !reflect.DeepEqual(saved.Access[1], config.Access{User: "bob", Servers: []string{"@web"}, Except: []string{"web-1"}}) {
		t.Errorf("access[1] = %+v", saved.Access[1])
	}
	if len(saved.Tombstones) != 0 || saved.Serial() != 1 {
		t.Errorf("tombstones = %+v, serial = %d", saved.Tombstones, saved.Serial())
	}
	k2 := strings.Fields(testkeys.Line(t, 2))[1]
	if strings.Contains(hosts["web-1"].keys(t), k2) {
		t.Errorf("bob's key survives on web-1:\n%s", hosts["web-1"].keys(t))
	}
	if !strings.Contains(hosts["web-2"].keys(t), k2) {
		t.Errorf("web-2 must keep bob's key:\n%s", hosts["web-2"].keys(t))
	}
}

// TestRevokeServerTwoTrimsTombstoneBothServers (D1a through an @tag entry):
// the second trim deletes the entry and its except:, so both servers get
// tombstones; the saved manifest is a golden, and adopt --merge does not
// re-grant either.
func TestRevokeServerTwoTrimsTombstoneBothServers(t *testing.T) {
	_, kh, cfg := tagFleetManifest(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--from-server", "web-1", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("first trim: exit %d\n%s", code, errBuf.String())
	}
	if len(readCfg(t, cfg).Tombstones) != 0 || !readCfg(t, cfg).ExceptCarveOut("bob", "web-1") {
		t.Fatal("the first trim should record web-1 in except: only")
	}
	if code := run([]string{"revoke", "bob", "--from-server", "web-2", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("second trim: exit %d\n%s", code, errBuf.String())
	}
	saved := readCfg(t, cfg)
	if len(saved.Access) != 1 {
		t.Errorf("bob's entry survived: %+v", saved.Access)
	}
	for _, s := range []string{"web-1", "web-2"} {
		if _, ok := saved.AccessRevoked("bob", s); !ok {
			t.Errorf("no access tombstone for %s: %+v", s, saved.Tombstones)
		}
	}
	checkGolden(t, "revoke_tag_two_trims.golden", normalizedManifest(t, cfg))
	errBuf.Reset()
	if code := run([]string{"adopt", "--merge", "--config", cfg, "-o", cfg, "--force", "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("adopt --merge: exit %d\n%s", code, errBuf.String())
	}
	if readCfg(t, cfg).Covers("bob", "web-1") {
		t.Errorf("adopt --merge re-granted web-1:\n%s", fileBytes(t, cfg))
	}
}
```

- [ ] **Step 2: Run to see it fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/manifest -run 'RemoveAccess'; GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestRevokeServerTrimsTagGrant|TestRevokeServerTwoTrimsTombstoneBothServers'`
Expected: FAIL in both packages. In `internal/manifest`, a tag member gains no `except:` (`TestRemoveAccessGolden` and the other `RemoveAccess` tests stay green, and the golden tests are missing their files). In `cmd/sshepherd`, `TestRevokeServerTrimsTagGrant` does not print `1 access entry changed`, and `TestRevokeServerTwoTrimsTombstoneBothServers` stops at `the first trim should record web-1 in except: only`, because today's first trim writes a tombstone instead.

- [ ] **Step 3: Update the comments.** `internal/manifest/edit.go:245`:

```go
	EntriesRemoved   int // entries deleted: list emptied, or selectors left covering nothing with no name left
```

Replace the comment above `RemoveAccess` (`edit.go:250-259`):

```go
// RemoveAccess takes servers away from user's access: entries, leaving the
// user, its keys and every other grant alone. An item naming one of servers
// is removed. Each of servers a selector ("*", "@tag") of the entry still
// reaches is appended to except: — created right after servers:, in that
// list's flow/block style, when absent. An entry left with no servers, or
// with no name left and nothing its selectors reach but excepted servers, is
// deleted (its head comment rescued as RemoveUser does). A server already
// excepted is not covered, so it is never appended twice. Every name in
// servers must be a server of the loaded config; selectors are resolved
// against f.Config().Servers.
```

and the package-comment bullet in `internal/manifest/manifest.go:16-18`:

```go
//   - RemoveAccess takes servers away from a user's access: entries
//     (named items removed, selectors gain except:, emptied entries
//     deleted);
```

- [ ] **Step 4: Replace `accessTargets`, `entryTrim`'s `gone` comment, `trimEntry` and `exceptServers`.** `accessTargets` (`edit.go:297-315`) now hands back the fleet:

```go
// accessTargets checks RemoveAccess's arguments against the loaded
// manifest (user has a users: entry, every server is a servers: entry) and
// returns the fleet, manifest order.
func (f *File) accessTargets(m *yaml.Node, user string, servers []string) ([]config.Server, error) {
	_, users := sectionOf(m, "users")
	if userItem(users, user) == nil {
		return nil, fmt.Errorf("user %q is not in the manifest", user)
	}
	for _, s := range servers {
		if !slices.ContainsFunc(f.cfg.Servers, func(c config.Server) bool { return c.Name == s }) {
			return nil, fmt.Errorf("server %q is not in the manifest", s)
		}
	}
	return f.cfg.Servers, nil
}
```

In `entryTrim` (`edit.go:318-323`) the `gone` comment:

```go
	gone     bool // the entry must be deleted (list emptied, or selectors left covering nothing and no name left)
```

Replace `trimEntry` (`edit.go:325-341`) and add its helpers:

```go
// trimEntry removes servers from one access: entry: every item naming one
// (the removed item's comments go with it), and except: appends for each one
// a selector of the entry still reaches.
func trimEntry(entry *yaml.Node, servers []string, fleet []config.Server) entryTrim {
	list := valueOf(entry, "servers")
	if list == nil || list.Kind != yaml.SequenceNode {
		return entryTrim{}
	}
	wildcard := seqHas(list, "*")
	reach := selectorReach(list, fleet)
	removed := removeItems(nil, list, func(it *yaml.Node) bool {
		return it.Kind == yaml.ScalarNode && slices.Contains(servers, it.Value)
	}, false)
	if !slices.ContainsFunc(list.Content, isSelectorItem) {
		return entryTrim{changed: removed > 0, gone: removed > 0 && len(list.Content) == 0}
	}
	covered := slices.DeleteFunc(slices.Clone(servers), func(s string) bool { return !slices.Contains(reach, s) })
	n, none := exceptServers(entry, list, covered, reach)
	gone := none && !slices.ContainsFunc(list.Content, func(it *yaml.Node) bool { return !isSelectorItem(it) })
	return entryTrim{changed: n > 0 || removed > 0, gone: gone, wildcard: wildcard, excepted: n}
}

func isSelectorItem(it *yaml.Node) bool {
	return it.Kind == yaml.ScalarNode && config.IsSelector(it.Value)
}

// selectorReach lists, in manifest order, every server of fleet a selector
// item of list reaches (nil when list has no selector).
func selectorReach(list *yaml.Node, fleet []config.Server) []string {
	var out []string
	for _, s := range fleet {
		if slices.ContainsFunc(list.Content, func(it *yaml.Node) bool {
			return it.Kind == yaml.ScalarNode && config.SelectorMatches(it.Value, s)
		}) {
			out = append(out, s.Name)
		}
	}
	return out
}
```

Replace `exceptServers`' comment, its `fleet` parameter and the final loop (`edit.go:343-378`, the body otherwise unchanged):

```go
// exceptServers appends to a selector entry's except: every server of
// servers the entry still covers, creating except: right after servers:
// (same sequence style) when absent or null. gone reports that the
// selectors would then reach no server of reach, every server they select
// being excepted: the caller deletes the entry unless a name is left
// (decision 1b) and the appends do not matter.
func exceptServers(entry, list *yaml.Node, servers, reach []string) (appended int, gone bool) {
	except := valueOf(entry, "except")
	if except != nil && except.Kind == yaml.ScalarNode && except.Tag == "!!null" {
		*except = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: list.Style & yaml.FlowStyle,
			HeadComment: except.HeadComment, LineComment: except.LineComment, FootComment: except.FootComment}
	}
	for _, s := range servers {
		if except != nil && seqHas(except, s) {
			continue // already carved out: not covered
		}
		if except == nil {
			except = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: list.Style & yaml.FlowStyle}
			at := len(entry.Content)
			for i := 0; i+1 < len(entry.Content); i += 2 {
				if entry.Content[i].Value == "servers" {
					at = i + 2
					break
				}
			}
			entry.Content = append(entry.Content[:at], append([]*yaml.Node{strScalar("except"), except}, entry.Content[at:]...)...)
		}
		except.Content = append(except.Content, strScalar(s))
		appended++
	}
	for _, s := range reach {
		if except == nil || !seqHas(except, s) {
			return appended, false
		}
	}
	return appended, true
}
```

`RemoveAccess` itself is unchanged: `fleet` now holds `[]config.Server` and goes to `trimEntry` the same way.

- [ ] **Step 5: Run, write the goldens, and read them back.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/manifest -run 'RemoveAccessTagGolden|RemoveAccessTagEntryDeleted' -update && GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestRevokeServerTwoTrimsTombstoneBothServers' -update && GOTOOLCHAIN=go1.27.3 go test ./internal/manifest && GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestRevokeServerTrimsTagGrant|TestRevokeServerTwoTrimsTombstoneBothServers'`
Expected: PASS. Read each golden line by line:

- `internal/manifest/testdata/edit_remove_access_tags.golden`: bob keeps `servers: ["@web"] # reviewed 2026-10` and `except: [web-2]`, alice's `@db` block gains `except:` with `db-2`, carol's `*` gains `except: [web-1]`, every comment including `# front` and the document footer survives.
- `internal/manifest/testdata/edit_remove_access_tags_deleted.golden`: no `- user: alice`; `# alice: every db` sits directly above `# carol: everywhere`; bob's and carol's entries are untouched.
- `cmd/sshepherd/testdata/revoke_tag_two_trims.golden`: every server reads `port: PORT`, `access:` holds only alice's entry (no `bob`), `serial` is 2, and one `revoked:` entry for bob names `web-2` and then `web-1` with `date: DATE`.

### Task 9: `revoke --from-server` on selectors

**Files:** Modify `cmd/sshepherd/revoke_tags_test.go` (Task 8), `cmd/sshepherd/revoke.go:33-34`, `:125-141`, `:352-355`, `:395-404`, `:408-414`, `:436-438`, `:454`, `internal/apply/edit.go:52-53`, `cmd/sshepherd/testdata/help/revoke.golden`.

- [ ] **Step 1: Append the tests** to `cmd/sshepherd/revoke_tags_test.go`, and add `"context"` to its imports. `TestRevokeServerBlockedPairIsAlreadyRevoked` (round 1's `AccessRevoked`), `TestRevokeServerTagJSON` (Task 8) and `TestRevokeServerLiteralBesideTagIsTombstoned` (today's `accessTombstones`) pin behavior already present and pass as soon as they are written:

```go
func TestRevokeFromServerRefusesSelectors(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	for _, sel := range []string{"@prod", "*"} {
		var out, errBuf bytes.Buffer
		code := run([]string{"revoke", "bob", "--from-server", sel, "--config", "/nonexistent"}, &out, &errBuf)
		if code != 3 || out.Len() != 0 || !strings.Contains(errBuf.String(), "--from-server takes server names") {
			t.Errorf("%s: exit = %d, stdout = %q, stderr = %q", sel, code, out.String(), errBuf.String())
		}
	}
}

// TestRevokeServerBlockedPairIsAlreadyRevoked (D1c): the pair a tombstone
// blocks is already revoked: a note, exit 0, nothing saved.
func TestRevokeServerBlockedPairIsAlreadyRevoked(t *testing.T) {
	_, kh, cfg := tagFleetManifest(t)
	raw := string(fileBytes(t, cfg)) + "revoked:\n  - {user: bob, servers: [web-2], date: 2026-11-08}\n"
	cfg = writeConfig(t, raw)
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
	if !strings.Contains(errBuf.String(), `is not granted "web-2" through @web`) {
		t.Errorf("stderr lacks the load warning:\n%s", errBuf.String())
	}
}

// TestRevokeServerLastUnblockedServerNoGrantsLeft: a tombstone blocks bob on
// web-2 and the trim takes web-1, the last server he reaches. The entry stays
// (its except: names only web-1) but reaches nothing he can use, so every
// report says no access is left (spec "every report then see no access").
func TestRevokeServerLastUnblockedServerNoGrantsLeft(t *testing.T) {
	blocked := func(t *testing.T) string {
		t.Helper()
		_, _, cfg := tagFleetManifest(t)
		return writeConfig(t, string(fileBytes(t, cfg))+"revoked:\n  - {user: bob, servers: [web-2], date: 2026-11-08}\n")
	}
	t.Run("text", func(t *testing.T) {
		cfg := blocked(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--from-server", "web-1", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if !strings.Contains(out.String(), "note: bob has no access left — 'sshepherd revoke bob") {
			t.Errorf("stdout:\n%s", out.String())
		}
		if got := readCfg(t, cfg).Access[1]; !reflect.DeepEqual(got, config.Access{User: "bob", Servers: []string{"@web"}, Except: []string{"web-1"}}) {
			t.Errorf("access[1] = %+v, want the entry kept", got)
		}
	})
	t.Run("json", func(t *testing.T) {
		cfg := blocked(t)
		doc := runJSONDoc(context.Background(), t, 0, "revoke", "bob", "--from-server", "web-1", "--json", "--no-apply", "--yes", "--config", cfg)
		e := doc["edit"].(map[string]any)["edits"].([]any)[0].(map[string]any)
		if e["no_grants_left"] != true {
			t.Errorf("edit entry = %v", e)
		}
	})
}

// TestRevokeServerTagJSON: the counts of a selector trim, and of a deleted
// @tag entry, which is not a wildcard removal.
func TestRevokeServerTagJSON(t *testing.T) {
	entry := func(doc map[string]any) map[string]any {
		return doc["edit"].(map[string]any)["edits"].([]any)[0].(map[string]any)
	}
	t.Run("selector trim", func(t *testing.T) {
		_, kh, cfg := tagFleetManifest(t)
		e := entry(runJSONDoc(context.Background(), t, 0, "revoke", "bob", "--from-server", "web-1", "--json", "--yes", "--config", cfg, "--known-hosts", kh))
		if e["kind"] != "remove-access" || e["entries_changed"] != float64(1) || e["servers_excepted"] != float64(1) ||
			e["entries_removed"] != float64(0) || e["wildcards_removed"] != float64(0) || e["no_grants_left"] != false {
			t.Errorf("edit entry = %v", e)
		}
	})
	t.Run("deleted @tag entry", func(t *testing.T) {
		_, kh, cfg := tagFleetManifest(t)
		e := entry(runJSONDoc(context.Background(), t, 0, "revoke", "bob", "--from-server", "web-1", "--from-server", "web-2", "--json", "--yes", "--config", cfg, "--known-hosts", kh))
		if e["entries_removed"] != float64(1) || e["wildcards_removed"] != float64(0) || e["no_grants_left"] != true {
			t.Errorf("edit entry = %v", e)
		}
	})
	t.Run("deleted @tag entry warns of no wildcard", func(t *testing.T) {
		_, _, cfg := tagFleetManifest(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--from-server", "web-1", "--from-server", "web-2", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if strings.Contains(out.String(), "wildcard grant is removed") || !strings.Contains(out.String(), "note: bob has no access left") {
			t.Errorf("stdout:\n%s", out.String())
		}
	})
}

// TestRevokeServerLiteralBesideTagIsTombstoned: a name removed from a mixed
// list gains no except: (the tag does not reach it), so a tombstone is what
// remembers it (accessTombstones, D1a).
func TestRevokeServerLiteralBesideTagIsTombstoned(t *testing.T) {
	hosts, _, _ := editFleet(t, []byte{1}, "web-1", "db-1")
	tagged := strings.TrimSuffix(hosts["web-1"].line("web-1"), "}\n") + ", tags: [web]}\n"
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+tagged+hosts["db-1"].line("db-1")+
		"access:\n  - {user: alice, servers: [web-1, db-1]}\n  - {user: bob, servers: [\"@web\", db-1]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--from-server", "db-1", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
	saved := readCfg(t, cfg)
	if !reflect.DeepEqual(saved.Access[1], config.Access{User: "bob", Servers: []string{"@web"}}) {
		t.Errorf("access[1] = %+v", saved.Access[1])
	}
	if _, ok := saved.AccessRevoked("bob", "db-1"); !ok {
		t.Errorf("no access tombstone for db-1: %+v", saved.Tombstones)
	}
}
```

- [ ] **Step 2: Run to see it fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestRevokeFromServerRefusesSelectors|TestRevokeServerLastUnblockedServerNoGrantsLeft'`
Expected: FAIL. For `@prod` the run reaches the manifest and says something else (exit 3, wrong text). `TestRevokeServerLastUnblockedServerNoGrantsLeft` lacks the note and reads `no_grants_left: false`, because the entry still names bob.

- [ ] **Step 3: Refuse a selector.** In `revokeUsage` (`cmd/sshepherd/revoke.go:139`) replace the `slices.Contains(servers, "*")` case:

```go
	case slices.ContainsFunc(servers, config.IsSelector):
		return errors.New("--from-server takes server names; to remove all of a user's access use 'sshepherd revoke USER'")
```

and update its comment line (`revoke.go:127-128`) to end `never with --key or --operator, and never a selector ('*', @tag).`.

- [ ] **Step 4: Count what the user reaches.** In `planRevokeAccess` (`revoke.go:395-404`), replace the loop. An entry a tombstone wholly blocks still names the user, and a load rejects any other entry that grants nothing, so nothing else changes:

```go
	for i, e := range ep.summary.Edits {
		// What is left, said in the header: a "web-1 first" trim must not
		// read as an offboarding.
		for _, srv := range ep.edited.Servers {
			if ep.edited.Covers(e.User, srv.Name) {
				ep.summary.Edits[i].KeepsServers++
			}
		}
		// Counted, not read off access: an entry a tombstone wholly blocks
		// still names the user and reaches nothing.
		ep.summary.Edits[i].NoGrantsLeft = ep.summary.Edits[i].KeepsServers == 0
	}
```

and the field comment (`internal/apply/edit.go:52-53`):

```go
	// NoGrantsLeft (EditRemoveAccess) reports that the user covers no server
	// after the whole edit (KeepsServers is 0).
```

- [ ] **Step 5: Reword what still says wildcard only.** The logic is unchanged. `revoke.go:352-355`, the end of `planRevokeAccess`'s comment:

```go
// refusal before any edit (accessProblems). A pair an access tombstone
// already records is a note (D1c). A server no except: remembers after the
// edit is tombstoned (D1a); one that gained an except: entry needs none —
// the except: already remembers it.
```

`revoke.go:408-414`, the comment on `accessTombstones`:

```go
// accessTombstones: one entry per user, naming the trimmed servers no
// selector except: remembers in mid (the manifest after the access edit).
// A selector entry this trim deleted took its except: list with it, so a
// server only that list remembered is tombstoned too, or a later adopt
// --merge would re-grant it (D1a); the original date is unknown, so this
// run's is recorded. Only the former manifest's servers are named (a
// tombstone for a server it does not have would only warn).
```

`revoke.go:436-438`, the comment on `forgottenCarveOut`:

```go
// forgottenCarveOut reports a server only a deleted selector entry's except:
// remembered: excluded in former, neither excluded nor covered in mid, and
// not already recorded by an access tombstone.
```

`revoke.go:454`, in `accessProblems`' comment: `(config.Covers: selectors and except: included)`.

- [ ] **Step 6: The help text.** `cmd/sshepherd/revoke.go:33-34`, keeping the lines after them as they are:

```go
			"the users' access to those servers (a selector grant ('*' or @tag) gains an\n" +
			"except: entry); the users and their keys stay. Operator users (and their keys)\n" +
```

Then regenerate its golden and read the diff.

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run TestHelpGolden -update && git diff --stat -- cmd/sshepherd/testdata/help`
Expected: only `revoke.golden` changes, and only its two lines above.

- [ ] **Step 7: Run.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'Revoke|Rotate|TestHelp'`
Expected: PASS, including `TestRevokeServerUsage`'s `*` row, the new D1c and two-trim tests, and `TestRevokeServerWildcard` (a wildcard left covering nothing still reports `no_grants_left`).

### Task 10: `FuzzRemoveAccess`, seeds and hand back

**Files:** Modify `internal/manifest/fuzz_edit_test.go` (`FuzzManifestEdit` seeds, new `FuzzRemoveAccess`), `internal/manifest/fuzz_test.go` (`FuzzMergeRoundTrip` seeds). Create `internal/manifest/testdata/fuzz/FuzzRemoveAccess/seed-tag-{gains-except,literal-removed,entry-deleted}`, `internal/manifest/testdata/fuzz/FuzzManifestEdit/seed-tag-selector-entry`, `internal/manifest/testdata/fuzz/FuzzMergeRoundTrip/seed-tag-selector-entry`.

`FuzzManifestEdit` and `FuzzMergeRoundTrip` call only `RemoveKey`, `RemoveUser`, `Encode` and `Append`, so their tag seeds cover `Load`, `RemoveUser` and `Encode`. `FuzzRemoveAccess` is what fuzzes `trimEntry`, `selectorReach` and `exceptServers`. These pin Task 8, which is already in place; a fuzz crash here is a defect in Task 8, not a seed to drop.

- [ ] **Step 1: Add the `f.Add` seeds.** In `FuzzManifestEdit`, after the `serial: 3` seed:

```go
	f.Add(tagEditFixture(f), uint8(1))
	f.Add(tagEditFixture(f)+"revoked:\n  - {user: bob, servers: [web-1], date: 2026-11-08}\n", uint8(3))
```

In `FuzzMergeRoundTrip`'s `seeds`, after the `&0000:` entry:

```go
		tagEditFixture(f),
```

- [ ] **Step 2: Add `FuzzRemoveAccess`** at the end of `internal/manifest/fuzz_edit_test.go`:

```go
// FuzzRemoveAccess asserts RemoveAccess's safety property on selector and
// plain entries alike: on any manifest Load accepts, taking one server from a
// non-operator user leaves a manifest Encode writes and config.Parse accepts
// (the deletion rule must never leave an entry granting nothing), and the
// user no longer covers that server. pick selects the user and the server.
func FuzzRemoveAccess(f *testing.F) {
	f.Add(tagEditFixture(f), uint8(0))
	f.Add(tagEditFixture(f), uint8(7))
	f.Add(editFixture(f), uint8(1))
	f.Fuzz(func(t *testing.T, in string, pick uint8) {
		mf, err := Load([]byte(in))
		if err != nil {
			t.Skip()
		}
		cfg := mf.Config()
		var users []string
		for _, u := range cfg.Users {
			if !u.Operator {
				users = append(users, u.Name)
			}
		}
		if len(users) == 0 || len(cfg.Servers) == 0 {
			t.Skip()
		}
		user := users[int(pick)%len(users)]
		server := cfg.Servers[int(pick/16)%len(cfg.Servers)].Name
		if _, err := mf.RemoveAccess(user, []string{server}); err != nil {
			t.Fatalf("RemoveAccess(%q, %q) on input %q: %v", user, server, in, err)
		}
		out, err := mf.Encode()
		if err != nil {
			t.Fatalf("Encode after RemoveAccess on input %q: %v", in, err)
		}
		after, err := config.Parse(out)
		if err != nil {
			t.Fatalf("edited manifest rejected for input %q:\n%s\nerr: %v", in, out, err)
		}
		if after.Covers(user, server) {
			t.Errorf("%q still covers %q after RemoveAccess (input %q):\n%s", user, server, in, out)
		}
	})
}
```

- [ ] **Step 3: Commit the corpus.** Five files, each under 4 KiB, with a static key line (the one `FuzzManifestEdit/seed-remove-wildcard-user` already holds). `carol` has no keys, so `pick` 0 and 32 both select bob: `FuzzRemoveAccess` takes `servers[(pick/16)%3]`, web-1 for 0 and db-1 for 32.

`internal/manifest/testdata/fuzz/FuzzRemoveAccess/seed-tag-gains-except` (web-1 joins `except:`):

```text
go test fuzz v1
string("users:\n  - name: bob\n    keys: [\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58\"]\n  - name: carol\n    keys: []\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}\n  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}\n  - {name: db-1, host: 10.0.0.9, user: deploy, tags: [db]}\naccess:\n  # bob: the web tier and a db\n  - user: bob\n    servers: [\"@web\", db-1]\n    except: [web-2]\n")
uint8(0)
```

`internal/manifest/testdata/fuzz/FuzzRemoveAccess/seed-tag-literal-removed` (the name db-1 goes):

```text
go test fuzz v1
string("users:\n  - name: bob\n    keys: [\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58\"]\n  - name: carol\n    keys: []\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}\n  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}\n  - {name: db-1, host: 10.0.0.9, user: deploy, tags: [db]}\naccess:\n  # bob: the web tier and a db\n  - user: bob\n    servers: [\"@web\", db-1]\n    except: [web-2]\n")
uint8(32)
```

`internal/manifest/testdata/fuzz/FuzzRemoveAccess/seed-tag-entry-deleted` (the last tag member goes, so the entry is deleted):

```text
go test fuzz v1
string("users:\n  - name: bob\n    keys: [\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58\"]\n  - name: carol\n    keys: []\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}\n  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}\naccess:\n  # bob: the web tier\n  - user: bob\n    servers: [\"@web\"]\n    except: [web-2]\n")
uint8(0)
```

`internal/manifest/testdata/fuzz/FuzzManifestEdit/seed-tag-selector-entry`:

```text
go test fuzz v1
string("users:\n  - name: bob\n    keys: [\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58\"]\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}\n  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}\naccess:\n  # bob: the web tier\n  - user: bob\n    servers: [\"@web\"]\n    except: [web-2]\n")
uint8(1)
```

`internal/manifest/testdata/fuzz/FuzzMergeRoundTrip/seed-tag-selector-entry`:

```text
go test fuzz v1
string("users:\n  - name: bob\n    keys: [\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58\"]\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}\n  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}\naccess:\n  # bob: the web tier\n  - user: bob\n    servers: [\"@web\"]\n    except: [web-2]\n")
```

- [ ] **Step 4: Run.**

Run: `GOTOOLCHAIN=go1.27.3 rtk proxy go test ./internal/manifest -v -run '^Fuzz(RemoveAccess|ManifestEdit|MergeRoundTrip)$' && GOTOOLCHAIN=go1.27.3 go test ./internal/manifest -run '^$' -fuzz '^FuzzRemoveAccess$' -fuzztime 20s && GOTOOLCHAIN=go1.27.3 go test ./internal/manifest -run '^$' -fuzz '^FuzzManifestEdit$' -fuzztime 20s`
Expected: PASS. In the verbose run, all five `seed-tag-*` corpus entries report `--- PASS`, none `--- SKIP`; a skip means `Load` refused the seed, so fix the seed. The fuzz runs end with no new failure.

- [ ] **Step 5: Hand back.** `make check` and `make integration` (under the runner's lock). Report the `docsDelta` of Task 12 Step 3, block `editor`, and the `editor` entry of Step 4. Unstage everything outside the lane's globs and write the patch.

---

## Round 2 — lane `import` (Task 11)

Owns: `cmd/sshepherd/import.go`, `cmd/sshepherd/import_tags_test.go`. Finding: PRD-5. Builds on round 1.

### Task 11: an `@` alias is skipped with a warning

**Files:** Create `cmd/sshepherd/import_tags_test.go`. Modify `cmd/sshepherd/import.go:47-71`.

- [ ] **Step 1: Write the failing tests.** `cmd/sshepherd/import_tags_test.go`:

```go
package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestImportSkipsTagSelectorAlias: an alias starting with @ cannot be a
// server name, so it is skipped with a warning; the sibling alias of the same
// Host line is kept and import exits 0.
func TestImportSkipsTagSelectorAlias(t *testing.T) {
	hermeticHome(t)
	path := writeSSHConfig(t, "Host @web web1\n  HostName 10.0.0.1\n  User deploy\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path, "--servers-only"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
	}
	if want := `host "@web": alias "@web" is reserved for tag selectors, skipped (not valid in a manifest)`; !strings.Contains(errBuf.String(), want) {
		t.Errorf("stderr = %q, want %q", errBuf.String(), want)
	}
	if !strings.Contains(out.String(), "name: web1") || strings.Contains(out.String(), "@web") {
		t.Errorf("manifest = %q, want web1 kept and @web left out", out.String())
	}
}

func TestImportJSONTagSelectorAliasKind(t *testing.T) {
	hermeticHome(t)
	path := writeSSHConfig(t, "Host @web\n  HostName 10.0.0.1\n  User deploy\nHost web1\n  HostName 10.0.0.2\n  User deploy\n")
	code, doc, stderr := importJSONCLI(t, path, "--servers-only")
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	if len(doc.Warnings) != 1 || doc.Warnings[0].Kind != importWarnUnsafeHost || !strings.Contains(doc.Warnings[0].Message, "reserved for tag selectors") {
		t.Errorf("warnings = %+v", doc.Warnings)
	}
}
```

- [ ] **Step 2: Run to see it fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestImportSkipsTagSelectorAlias|TestImportJSONTagSelectorAliasKind'`
Expected: FAIL; the self-check reports `bug: generated manifest fails validation: servers[0]: name "@web" is reserved for tag selectors` and exits 3.

- [ ] **Step 3: Skip the alias.** Replace `dropUnsafeHosts` (`cmd/sshepherd/import.go:47-71`):

```go
// dropUnsafeHosts removes hosts whose alias, HostName or User could never
// form a valid server entry (config.ServerFieldIssue: whitespace, control or
// format runes — e.g. a quoted `Host "web 1"`; config.ServerNameIssue also
// reserves an alias like `@web` for tag selectors), warning for each. Filtering
// before identity resolution and target collapse keeps such a host from
// deriving grants or winning a same-target collapse.
func dropUnsafeHosts(w *importWarnings, hosts []sshcfg.Host) []sshcfg.Host {
	kept := hosts[:0:0]
	for _, h := range hosts {
		bad := ""
		for _, f := range []struct {
			field, value string
			issue        func(string) string
		}{
			{"alias", h.Alias, config.ServerNameIssue},
			{"HostName", h.HostName, config.ServerFieldIssue},
			{"User", h.User, config.ServerFieldIssue},
		} {
			if issue := f.issue(f.value); issue != "" {
				bad = fmt.Sprintf("%s %q %s", f.field, f.value, issue)
				break
			}
		}
		if bad != "" {
			w.addAll(importWarnUnsafeHost, fmt.Sprintf("host %q: %s, skipped (not valid in a manifest)", h.Alias, bad))
			continue
		}
		kept = append(kept, h)
	}
	return kept
}
```

- [ ] **Step 4: Hand back.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd`
Expected: PASS. Then `make check`. Report the `docsDelta` of Task 12 Step 3, block `import`. Unstage everything outside the lane's globs and write the patch.

---

## Task 12: integrator (no lane owns this)

- [ ] **Step 1: Per lane, in merge order `schema`, `editor`, `import`:** `git apply` the patch, apply that lane's README delta from Step 3, then `make check` (plus `make integration` for lane `editor`). Commit the patch, the README delta and that lane's CLAUDE.md paragraph (Step 4) together. Lane `import`'s commit also carries Step 2.

No lane's gate needed a README change: no flag or exit footer moved, and `revoke`'s reworded Long text is only in its help golden. `TestHelpMatchesREADMETables` and `TestHelpExamplesAndExitCodes` pass with the README before or after the delta. Apply the delta before `make check` regardless, so the gate runs on the tree being committed.

- [ ] **Step 2: Design amendments** (commit with lane `import`) in `docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`:

  1. Header `Status`: add `S3a built (plan 2026-11-09-p10-s3a-server-tags)` beside S1, S2 and S8.
  2. In S3a's **Validation** list, after the `except:` rule, add: `` A tag's error reads `server "X": tag "Y" is not valid: want lowercase letters, digits, '.', '_' or '-', starting with a letter or digit, at most 63 characters`, a repeat reads `server "X": tag "Y" is repeated`, `@tag` in `except:` reads `access for "X": except takes server names, not the selector "@y"`, a name in both lists reads `access for "X": "s" is in both servers and except`, and an `@tag` entry granting nothing after `except:` reads `access for "X": selectors grant no servers after except`. ``
  3. In "How selectors meet tombstones", **Order of work**: the sentence spans two lines, so replace lines 227-228 as a range. They read `` `validateRevoked`, and blocking needs both. `validateAccess` records each grant's `` and `` sources; `validateRevoked` stays where it is; a new `blockTombstoned` step then drops ``. The replacement lines are `` `validateRevoked`, and blocking needs both. `validateRevoked` stays where it is; a new `` and `` `blockTombstoned` step then derives each grant's sources from `c.Access` and drops ``.
  4. In S3a's **Raw-entry scanners**, after `entryCovers(a, server)` add `` (it takes the server entry; `Covers` passes `Server{Name: n}` for a server not in the manifest, which carries no tags) ``. After the `ExceptCarveOut` bullet add: `` In S3a `Covers`' `c.blocked` check cannot fail, because a blocked pair is reached only through `@tag` and the scan passes a tagless server; it becomes load-bearing with S3b's group entries. ``
  5. In S3a's **Manifest editor**, after `--from-server takes server names` add `` (the existing `*` refusal's full text, reused) ``, and note `` a deleted `@tag` entry is not a wildcard removal: `wildcards_removed` stays 0 and no warning prints. ``
  6. In S3a's **Root warning**, after the message add: `` One root account reads `on web-1;`, with no count. `` In **How selectors meet tombstones**, after `` Save refusals do not apply: a blocked grant is not a conflict. ``, add: `` `tombstone_blocks_grant` carries `revoked_index`, `user` and `server`. ``
  7. In "Order and parallel lanes", change S3a's row to `` A: `internal/config` and the consumer tests · B: `internal/manifest`, `revoke.go` · C: `import.go` (B and C after A: the runner compiles each lane on earlier rounds) ``.

- [ ] **Step 3: README deltas.** Apply each block in its lane's commit. Message texts in these blocks are pinned by the tests named beside them, and none is sample command output.

**`schema` block.**

a. In the manifest sample (`README.md:273`), after the `authorized_keys_file` line of `web-1`, add:

```yaml
    tags: [prod, web]                   # optional, see Tags and selectors
```

b. Append to **Wildcard access** (`README.md:310-314`):

```markdown
A non-operator `servers: ["*"]` entry that reaches a server whose `user` is `root` warns
once per entry, kind `wildcard_root`:
`access for "alice": servers ["*"] includes the root account on web-1 and 3 more; list the servers or use an @tag that excludes root accounts`
(with one root account, `on web-1;`). An `@tag` reaching root does not warn. A warning never
changes an exit code, except that `validate --strict` exits `1`.
```

c. Add a new subsection after **Wildcard access**, before **Per-server `authorized_keys_file`**:

````markdown
### Tags and selectors

```yaml
servers:
  - name: web-1
    host: 10.0.1.5
    user: deploy
    tags: [prod, web]
access:
  - user: carol
    servers: ["@prod", db-1]   # selectors and names mix (union)
    except: [web-3]            # valid with "*" or any "@tag"
```

A tag matches `^[a-z0-9][a-z0-9._-]{0,62}$`, and a tag may not repeat on a server. In an
`access:` entry, `@tag` reaches every server carrying the tag, in manifest order, and
mixes with server names as a union. `except:` removes names from what the selectors reach; it
needs `*` or at least one `@tag`, and each name must be a known server. A name may not be in
both `servers:` and `except:`. An `@tag` matching no server is an error, like an unknown
server name: `access for "carol": unknown tag "@prd"`. Fix the typo, or tag a server. A tag
covers only servers in the manifest now: only `*` covers servers added later, and a new
server joins a tag's grants when you tag it.
````

d. In **Validation rules**, after the **Server `name`, `host` and `user`** bullet (`README.md:364-365`), add:

```markdown
- **Server names starting with `@`** are reserved for tag selectors, like `*` for wildcard
  grants: `servers[N]: name "@x" is reserved for tag selectors`.
- **Tags** must match `^[a-z0-9][a-z0-9._-]{0,62}$`, and a tag may not repeat on a server:
  `server "web-1": tag "Prod" is not valid: want lowercase letters, digits, '.', '_' or '-', starting with a letter or digit, at most 63 characters`,
  `server "web-1": tag "prod" is repeated`.
- **Selectors in `access:`**: `access for "carol": unknown tag "@prd"`;
  `access for "x": "*" must be the only servers entry`; `access for "x": except requires servers ["*"] or an @tag`;
  `access for "x": except takes server names, not the selector "@web"`;
  `access for "x": "web-3" is in both servers and except`;
  `access for "x": selectors grant no servers after except`.
```

In the same section's `revoked:` list, after the `*` is not a server bullet (`README.md:391`), add `` a selector is not a server name: `revoked[N]: servers cannot hold a selector; list the servers by name`; ``. At the end of the "Policy conflicts are not load errors" paragraph's parenthesis on the wildcard, change `(a wildcard grant conflicts too, unless its `except:` lists the server)` to `(a wildcard grant conflicts too, unless its `except:` lists the server; an `@tag` grant does not conflict, see [Revoked keys](#revoked-keys))`.

e. Append to **Revoked keys** (`README.md:459-470`):

```markdown
A grant that reaches a server only through an `@tag` does not conflict with an access entry
for that (user, server): it is **blocked**. The tombstone acts as an `except:` for that user,
the key is not installed, and each blocked pair prints a warning, kind `tombstone_blocks_grant`:
`access[0]: "bob" is not granted "db-1" through @db: revoked[0] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`.
A warning never changes an exit code, except that `validate --strict` exits `1`. A server named
directly (`user: U` with `S` listed, or `*` not excepting it) still conflicts, even in the same
entry as an `@tag`. An operator's implicit grant is not affected, and no warning prints for it.
```

f. At `README.md:949-950`, change the two sentences to:

```markdown
document. Each object has `kind` and `message`. `revoked_index`, `user` and `server` appear on `tombstone_unknown_server` and `tombstone_blocks_grant`; `server` also on validate's `host_key_not_recorded`. The kinds are `tombstone_unknown_server`,
`comment_on_multi_key`, `weak_key_ungranted`, `key_expired`, `wildcard_root` and `tombstone_blocks_grant`; ignore kinds you do not know.
```

g. In **Exit codes**, after the `With --json` paragraph that follows the table (`README.md:2440`), add:

```markdown
A tag problem (an unknown `@tag`, a malformed tag, a selector in `except:` or in a tombstone's `servers:`) is a manifest load error, so it is exit `3` on every command. A blocked grant and the `wildcard_root` warning change no exit code, except that `validate --strict` exits `1`.
```

h. Append to **Status**, after the "Audit trust and posture" paragraph (`README.md:76`):

```markdown
Tags: `tags:` on a server and `@tag` selectors in `access:` mix with names, `except:` works on any selector, a tombstone blocks a tag-derived grant instead of conflicting, and a `*` reaching a root account warns (kind `wildcard_root`).
```

**`editor` block.** In **Revocation memory** under **`sshepherd revoke`**, change lines 1770-1771 (they read `` owner), `revoke USER --from-server NAME` one access entry naming the servers removed from `` and `` an explicit list (a wildcard's new `except:` already remembers its server) — and bumps ``) to `` owner), `revoke USER --from-server NAME` one access entry naming the servers no `except:` remembers (a selector's new `except:` already remembers its server) — and bumps ``.

In **`sshepherd revoke`**, replace the sentences from `A wildcard grant` through `this run's date.` (`README.md:1784-1790`) with:

```markdown
A selector entry (`servers: ["*"]`, or one with an `@tag`) gets each server it still reaches appended to `except:` — created right after `servers:` when absent. A server the entry also names loses that item too. A wildcard keeps covering servers added later, so a wildcard that would then cover no current server is deleted, with a warning that later servers are no longer granted automatically. An `@tag` entry left with no name and nothing but excepted members is deleted the same way, without that warning, because a tag promises no future server. When a trim deletes an entry with an `except:`, every server that `except:` remembered also gets an access tombstone, because the deleted `except:` was the only record; the entry carries this run's date.
```

and change `` `--from-server '*'` (use `revoke USER`), `` in the refusal list (`README.md:1792`) to `` `--from-server` with `*` or an `@tag` (use `revoke USER`), ``.

**`import` block.** In the "What gets skipped or merged" list (`README.md:1191-1192`), change the first bullet to:

```markdown
- A host whose alias, HostName or User contains whitespace or control characters (e.g. a quoted `Host "web 1"`), or whose alias starts with `@` (reserved for tag selectors) — it could never be a valid server entry.
```

- [ ] **Step 4: CLAUDE.md Status** (append after the `import --json` paragraph, one paragraph per lane commit, in this order).

Lane `schema`:

```markdown
**Server tags and `@tag` selectors** (P10 S3a, D20, D20a, PRD-5; section S3a of
`docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`, planned in
`docs/superpowers/plans/2026-11-09-p10-s3a-server-tags.md`): `tags:` on a server and `@tag` in
`access: servers:` (mixed with names, in manifest order, with `except:` on any selector) expand
inside `expandServers`, so `c.grants`, `DesiredFor` and `apply.Affected` keep their shape
(`TestTaggedManifestMatchesFlatTwin` is the equivalence test). `config.ServerNameIssue` reserves
`@…` server names, an unknown tag is a load error, and an `@tag` never covers a server not in
the manifest yet. `internal/config/selector.go` holds `entryApplies`, `entryCovers` and
`entryDirect`. A tombstone over a tag-only grant **blocks** it (`blockTombstoned`, `c.blocked`,
kind `tombstone_blocks_grant`) instead of conflicting, while a name or `*` in any of the user's
entries stays a D29 conflict. A non-operator `*` reaching a root account warns once per entry
(kind `wildcard_root`). `Covers`' `c.blocked` check is load-bearing only from S3b.
```

Lane `editor`:

```markdown
`manifest.RemoveAccess` handles selector entries: named items are removed, servers a selector
still reaches go to `except:`, and an entry left with no name and only excepted members is
deleted. `revoke --from-server` refuses `*` and `@tag`; `accessTombstones`' logic is unchanged,
because `ExceptCarveOut` now answers for any selector entry, and `no_grants_left` is now
`KeepsServers == 0`, so an entry a tombstone wholly blocks reports no access left.
`FuzzRemoveAccess` is the 23rd `Fuzz*` target.
```

Also in `CLAUDE.md`, in the **Fuzz oracles and corpus** paragraph, change `every one of the 22 `Fuzz*` targets` to `every one of the 23 `Fuzz*` targets`; lane `editor`'s commit carries it.

Lane `import`:

```markdown
`import` skips an alias that starts with `@` with an `unsafe_host` warning (`dropUnsafeHosts` uses
`config.ServerNameIssue`), so a generated manifest always loads.
```

- [ ] **Step 5:** Confirm `TestHelpMatchesREADMETables` and `TestHelpExamplesAndExitCodes` pass with the README as committed, and that `git diff --stat 766aa82 -- cmd/sshepherd/testdata/help` lists only `revoke.golden`.

## Task 13: independent verifier (no lane owns this)

Check against `master` after Task 12 and report findings; change nothing.

- [ ] Every validation row of the design's S3a list loads or fails as the design says, with the design's text where it gives one and this plan's otherwise (design gaps 1 and 8).
- [ ] `TestTaggedManifestMatchesFlatTwin` passes, and no code past `internal/config` interprets `Access.Servers` except the two listed sites (adopt only copies entries through verbatim): `manifest.RemoveAccess`/`selectorReach` and `cmd/sshepherd/import_json.go`'s fresh-import listing (which only ever sees generated `import` output, no `@tag`).
- [ ] Tombstones: a tag grant is blocked with the warning; a name in the same entry is a W4 conflict; a name in another entry names only that entry; `Covers` false and `AccessRevoked` true; `revoke --from-server` on a blocked pair is the D1c note; adopt and reconcile do not re-extend; audit reports D1d drift when the key is installed; no warning for an operator's blocked pair; `@tag` in a tombstone's `servers:` is a load error.
- [ ] `validate`: unknown tag exit 3 with the `errors` list; `wildcard_root` and `tombstone_blocks_grant` exit 0, exit 1 under `--strict`, one JSON object each, with `user` only on the second. `audit --json` and `apply --dry-run --json` on a blocked pair with the key absent exit 0 and carry `tombstone_blocks_grant` with `revoked_index` 0. `audit`, `apply --dry-run`, `revoke` and `adopt` exit 3 on an unknown `@tag`. JSON stays schema 1, with no golden changed except new ones.
- [ ] `RemoveAccess`: each row of `TestRemoveAccessSelectors`, the deleted-entry rows and the two-trim path; every comment survives (`edit_remove_access_tags.golden`, `edit_remove_access_tags_deleted.golden`); `revoke_tag_two_trims.golden` shows tombstones for both servers and no bob entry. A blocked last server reports `no_grants_left: true` and the note. `revoke --json` on a tag trim counts `servers_excepted: 1`; a deleted `@tag` entry counts `entries_removed: 1` and `wildcards_removed: 0`. A name removed from `["@web", db-1]` gets a tombstone. `FuzzRemoveAccess` exists with its committed corpus.
- [ ] `revoke --from-server '@prod'` and `'*'` both refuse before reading the manifest.
- [ ] `import` skips `Host @web` with kind `unsafe_host` and still exits 0.
- [ ] `git diff 766aa82 -- cmd/sshepherd/testdata internal/*/testdata` adds only `internal/manifest/testdata/edit_remove_access_tags.golden`, `internal/manifest/testdata/edit_remove_access_tags_deleted.golden`, `cmd/sshepherd/testdata/revoke_tag_two_trims.golden` and the five `seed-tag-*` corpus files, and changes only the reworded clause of `cmd/sshepherd/testdata/help/revoke.golden`.
- [ ] `go list -deps ./internal/config ./internal/manifest` names no cobra or transport package (`make layering`).
- [ ] The design amendments of Task 12 Step 2 match the code. No other design text changed.

---

## Review log

Two independent reviews of the draft, each issue checked against `master` and the design. All 16 were applied and none rejected; the two reviews' first items are the same bug.

| Issue | Where it landed |
|---|---|
| R0-1, R1-1 `no_grants_left` false for a user with only blocked access | Task 9 Step 4, `TestRevokeServerLastUnblockedServerNoGrantsLeft`; the `internal/apply/edit.go` field comment moves with it, so lane `editor` owns that file |
| R0-2 two edit goldens missing | `edit_remove_access_tags_deleted.golden` (Task 8), `revoke_tag_two_trims.golden` with date and port normalized (`editFleet` ports vary), Task 13 |
| R0-3 JSON and exit rules tested on `validate` only | Task 7: `TestBlockedGrantNeverChangesTheExit` (`audit --json`, `apply --dry-run --json`), `TestUnknownTagExit3EveryCommand`, exact objects in `TestValidateTagWarnings`; Task 6's comment corrected. The `wildcard_root` `user` assertion became an assertion that the field is absent (R0-7) |
| R0-4 no `revoke --json` on a selector trim | `TestRevokeServerTagJSON` (Task 9) |
| R0-5 stale README sentence, no test for a name beside a tag | Task 12 Step 3 `editor` block; `TestRevokeServerLiteralBesideTagIsTombstoned` |
| R0-6 help text | Task 9 Step 6, `revoke.golden` in lane `editor`, plan item 5, Task 12 Step 5, Task 13 |
| R0-7 `wildcard_root` carrying `user` contradicts Shared rules | Took the second option: `User` dropped from `warnWildcardRoot`, its test, README delta f and gap 6. The approved shared rule stands, so no owner veto is needed |
| R0-8 amendment misstates the JSON | Task 12 Step 2 item 5 |
| R0-9 fuzz seed reason covers one target | Plan decision 1, Task 10 Step 3 |
| R1-2 three tests never seen failing | The two trim tests moved to Task 8 Steps 1-2; Task 9 Step 1 names its pins |
| R1-3 Tasks 5 and 7 convention | Task 7 sentence; Task 5 Step 2 names the pins, plus a fourth the review did not list (`TestLiteralAndTagInTwoEntriesNamesOnlyLiteralEntry`, also green at the Task 4 state) |
| R1-4 seeds do not reach `RemoveAccess` | `FuzzRemoveAccess` and corpus (Task 10), `Fuzz*` count 22 to 23 |
| R1-5 two-line anchor | Task 12 Step 2 item 3 is a line-range edit of 227-228 |
| R1-6 Files range | Task 8 Files reads `:250-259` |
| R1-7 stale `revoke.go` comments | Task 9 Step 5, also `:352-355` (R0-6) and `:454` (same wording, found while checking) |

**Not compiled.** Everything this table adds or changes in a Go block, plus the corpus files and the three new goldens. See the header. Blocks unchanged from the draft keep the draft's compile result, except that `TestRevokeServerTwoTrimsTombstoneBothServers` gained one golden line and moved to Task 8.

## Wave lanes (for the runner)

- **`plan`** (the runner's `args.plan`): `docs/superpowers/plans/2026-11-09-p10-s3a-server-tags.md`, committed before round 1.
- **`handoffs`** (the runner's `args.handoffs`), one entry: "P10-S3a, per lane in the order schema, editor, import: git apply that lane's patch, apply its README delta from Task 12 Step 3, then make check (make integration for lane editor), then commit patch, README and that lane's CLAUDE.md paragraph (Task 12 Step 4) together, one commit per lane. No lane's gate needs a README edit (no flag or exit footer changed; revoke's reworded Long text is only in its help golden). Lane import's commit also carries Task 12 Step 2 (the design amendments)."

Rounds run in sequence; lanes inside a round own disjoint files and build only on the previous rounds' commits. Globs are shell `case` patterns (`*` crosses `/`). `README.md` and `CLAUDE.md` are integrator-only: each lane reports its `docsDelta`, and the integrator applies it after the patch and before `make check`.

```json
{
  "rounds": [
    [
      {
        "pkg": "P10-S3a",
        "lane": "schema",
        "kind": "fix",
        "ids": ["PRD-5"],
        "tasks": "Tasks 1-7",
        "files": [
          "internal/config/*",
          "internal/apply/tags_equivalence_test.go",
          "internal/adopt/tags_test.go",
          "internal/reconcile/tags_test.go",
          "internal/audit/tags_test.go",
          "cmd/sshepherd/schema_roundtrip_test.go",
          "cmd/sshepherd/validate_tags_test.go"
        ],
        "needsIntegration": false
      }
    ],
    [
      {
        "pkg": "P10-S3a",
        "lane": "editor",
        "kind": "fix",
        "ids": ["PRD-5"],
        "tasks": "Tasks 8-10",
        "files": [
          "internal/manifest/*",
          "internal/apply/edit.go",
          "cmd/sshepherd/revoke.go",
          "cmd/sshepherd/revoke_tags_test.go",
          "cmd/sshepherd/testdata/revoke_tag_two_trims.golden",
          "cmd/sshepherd/testdata/help/revoke.golden"
        ],
        "needsIntegration": true
      },
      {
        "pkg": "P10-S3a",
        "lane": "import",
        "kind": "fix",
        "ids": ["PRD-5"],
        "tasks": "Task 11",
        "files": [
          "cmd/sshepherd/import.go",
          "cmd/sshepherd/import_tags_test.go"
        ],
        "needsIntegration": false
      }
    ]
  ],
  "mergeOrder": ["P10-S3a"]
}
```

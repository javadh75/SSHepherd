# `revoke USER --server` and `rotate --keep-old` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `revoke USER... --server NAME...` takes named servers away from users (explicit lists shortened, wildcards gain `except:`, emptied entries deleted) without touching the users or their keys, and `rotate USER --old K1 --new K2 --keep-old` adds the new key beside the old one (an overlap) and prints the `revoke --key K1` that finishes it.

**Architecture:** Two new comment-preserving node-tree edits in `internal/manifest` — `RemoveAccess` and `AddKeyAfter` — feed the existing revoke/rotate pipeline (`editPlan` → `runEdit` → `runApply`/`saveOnly` → `finishEdit`). `internal/apply` gains the `remove-access` edit kind, its header text and notes, a `KeepOld` flag on rotate edits, and the matching additive JSON fields. `cmd/sshepherd` gains the `--server` / `--keep-old` flags, the usage and post-load refusals, a per-edit save-reminder tail (`editPlan.saveNote`) and the keep-old finish hint (`overlapHint`).

**Tech Stack:** Go 1.26, `gopkg.in/yaml.v3` node trees, Cobra, the hermetic `sshtest` server, golden files (`-update`), goleak, the dockerized integration harness (`scripts/integration.sh`).

**Spec:** `docs/superpowers/specs/2026-11-07-revoke-server-keep-old-design.md` — read it first; it is the contract. This plan never overrides it; where the spec left a choice open, the resolution is stated inline and listed under "Spec resolutions" at the end.

---

## Execution model (read before starting)

This plan is executed by a **sequential** Workflow in the **main tree** (no worktrees): each stage starts only after the previous one has handed back, because the stages share files (`internal/apply/edit.go`, `json.go`, `cmd/sshepherd/editrun.go`, `README.md`). Ownership per stage:

| Stage | Owner | Tasks | Files (owned during the stage) |
|---|---|---|---|
| 1 | **Manifest agent** | M1–M5 | `internal/manifest/edit.go`, `internal/manifest/edit_test.go`, `internal/manifest/manifest.go` (package doc comment only), `internal/manifest/testdata/edit_remove_access.golden` (new) |
| 2 | **Revoke agent** | R1–R6 | `internal/apply/edit.go`, `internal/apply/edit_test.go`, `internal/apply/json.go`, `internal/apply/json_test.go`, `internal/apply/testdata/edit_header_access*.golden` + `json_remove_access.golden.json` (new), `cmd/sshepherd/revoke.go`, `cmd/sshepherd/editrun.go` (`saveNote` only), `cmd/sshepherd/revoke_server_test.go` (new), `README.md` (**the `--server` row of the revoke flag table only**) |
| 3 | **Rotate agent** | K1–K6 | `internal/apply/edit.go`, `internal/apply/edit_test.go`, `internal/apply/json.go`, `internal/apply/json_test.go`, `internal/apply/testdata/edit_header_keep_old*.golden` + `json_rotate_keep_old.golden.json` (new) + `json_rotate_edit_only.golden.json` (regenerated), `cmd/sshepherd/rotate.go`, `cmd/sshepherd/editrun.go` (overlap hint only), `cmd/sshepherd/editrun_test.go` (append one test), `cmd/sshepherd/rotate_keep_old_test.go` (new), `README.md` (**the `--keep-old` row of the rotate flag table only**) |
| 4 | **Integrator** | I1–I4 | `cmd/sshepherd/e2e_test.go`, `scripts/integration.sh` (three container accounts), rest of `README.md`, `CLAUDE.md`, the spec's Status line, plus fixes for anything the gates find |
| 5 | **Verifier** | V | read-only |
| 6 | **Repair** | — | only files named by confirmed verifier findings |

Rules for every agent:
- **No commits.** Leave changes in the working tree; the integrator commits once (I4).
- Do not edit files another stage owns; if a gate failure points into one, report it in the hand-back instead.
- Toolchain trap: run Go with `GOTOOLCHAIN=go1.26.9` (Homebrew go1.27 breaks the pinned golangci-lint). Example: `GOTOOLCHAIN=go1.26.9 go test ./internal/manifest/`.
- The rtk hook summarizes test output; use `rtk proxy go test …` whenever exact failure lines matter (every "expect FAIL" step below).
- Golden files are written with `-update` and then **read back and compared** with the expected content printed in the task before being accepted. Never hand-edit a golden.
- Every code block in this plan was compiled and run against a scratch copy of commit `25a62ae` (unit, `-race`, `golangci-lint run ./...`, `deadcode`, and `make integration` all green, coverage 90.6%). If a step's result disagrees with the plan, stop and report the difference in the hand-back rather than bending the test.
- Hand-back (every agent): files changed, goldens created/regenerated (with a one-line description of what you checked in each), gate results, any deviation and why.

---

## Stage 1 — Manifest agent

### Task M1: `RemoveAccess` on explicit lists

**Files:**
- Modify: `internal/manifest/edit.go` (add `"slices"` to the imports; append the new code at the end of the file)
- Test: `internal/manifest/edit_test.go` (add `"slices"` to the imports; append)

- [ ] **Step 1: Write the failing tests** — append to `internal/manifest/edit_test.go` (and add `"slices"` to its standard-library imports, just before `"strings"`):

```go
// accessFixture exercises every access: shape RemoveAccess handles: a
// flow explicit list with a line comment, a flow wildcard with except:, a
// block wildcard without except:, and a second explicit entry for the same
// user — with head comments on entries (first, middle, last) and a
// document footer.
func accessFixture(tb testing.TB) string {
	tb.Helper()
	return `# fleet manifest
users:
  - {name: alice, keys: ["` + testkeys.Line(tb, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(tb, 4) + `"]}
  - {name: carol, keys: ["` + testkeys.Line(tb, 5) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
  - {name: db-1, host: 10.0.0.9, user: deploy}
access:
  # alice: the web tier
  - user: alice
    servers: [web-1, web-2, db-1] # reviewed 2026-10
  # bob: everywhere but the database
  - user: bob
    servers: ["*"]
    except: [db-1]
  # carol: everywhere
  - user: carol
    servers:
      - "*"
  # alice db access (temporary)
  - user: alice
    servers: [db-1]
# end of manifest
`
}

// grantsOf returns user's effective servers in the re-parsed config.
func grantsOf(cfg *config.Config, user string) []string {
	var out []string
	for _, s := range cfg.Servers {
		if cfg.Covers(user, s.Name) {
			out = append(out, s.Name)
		}
	}
	return out
}

// TestRemoveAccessExplicitPositions: the first, middle and last item of an
// explicit list; removing db-1 also empties alice's second entry, which is
// deleted with its head comment rescued to the section footer (before the
// document footer). The surviving item keeps the entry's line comment.
func TestRemoveAccessExplicitPositions(t *testing.T) {
	for _, tt := range []struct {
		server string
		list   string
		want   AccessRemoval
		grants []string
	}{
		{"web-1", "servers: [web-2, db-1] # reviewed 2026-10", AccessRemoval{EntriesChanged: 1}, []string{"web-2", "db-1"}},
		{"web-2", "servers: [web-1, db-1] # reviewed 2026-10", AccessRemoval{EntriesChanged: 1}, []string{"web-1", "db-1"}},
		{"db-1", "servers: [web-1, web-2] # reviewed 2026-10", AccessRemoval{EntriesChanged: 1, EntriesRemoved: 1}, []string{"web-1", "web-2"}},
	} {
		t.Run(tt.server, func(t *testing.T) {
			f := loadFixture(t, accessFixture(t))
			r, err := f.RemoveAccess("alice", []string{tt.server})
			if err != nil {
				t.Fatalf("RemoveAccess: %v", err)
			}
			if r != tt.want {
				t.Errorf("AccessRemoval = %+v, want %+v", r, tt.want)
			}
			out, cfg := encodeParsed(t, f)
			if got := grantsOf(cfg, "alice"); !slices.Equal(got, tt.grants) {
				t.Errorf("alice's grants = %v, want %v", got, tt.grants)
			}
			inOrder(t, out, "  # alice: the web tier\n  - user: alice\n    "+tt.list+"\n", "  # bob: everywhere but the database\n")
			if tt.server == "db-1" {
				inOrder(t, out, "      - \"*\"\n# alice db access (temporary)\n# end of manifest\n")
				if strings.Count(out, "- user: alice") != 1 {
					t.Errorf("the emptied entry survived:\n%s", out)
				}
			}
		})
	}
}

// TestRemoveAccessDuplicateItems: every item equal to the server goes.
func TestRemoveAccessDuplicateItems(t *testing.T) {
	f := loadFixture(t, "users:\n  - {name: bob, keys: [\""+testkeys.Line(t, 4)+"\"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: db-1, host: 10.0.0.9, user: deploy}\n"+
		"access:\n  - {user: bob, servers: [web-1, db-1, web-1]}\n")
	r, err := f.RemoveAccess("bob", []string{"web-1"})
	if err != nil || r != (AccessRemoval{EntriesChanged: 1}) {
		t.Fatalf("RemoveAccess = (%+v, %v)", r, err)
	}
	out, _ := encodeParsed(t, f)
	if !strings.Contains(out, "{user: bob, servers: [db-1]}") {
		t.Errorf("want only db-1 left:\n%s", out)
	}
}

// TestRemoveAccessBlockListComments: in a block list, a removed item's
// line comment goes with it; a surviving item keeps its own.
func TestRemoveAccessBlockListComments(t *testing.T) {
	f := loadFixture(t, "users:\n  - {name: bob, keys: [\""+testkeys.Line(t, 4)+"\"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: db-1, host: 10.0.0.9, user: deploy}\n"+
		"access:\n  - user: bob\n    servers:\n      - web-1 # primary\n      - db-1 # replica\n")
	if _, err := f.RemoveAccess("bob", []string{"db-1"}); err != nil {
		t.Fatalf("RemoveAccess: %v", err)
	}
	out, _ := encodeParsed(t, f)
	inOrder(t, out, "    servers:\n      - web-1 # primary\n")
	if strings.Contains(out, "replica") {
		t.Errorf("the removed item's line comment survived:\n%s", out)
	}
}

// TestRemoveAccessEmptiedRescuesToNextEntry: a deleted entry that is not
// the last passes its head comment to the next entry.
func TestRemoveAccessEmptiedRescuesToNextEntry(t *testing.T) {
	f := loadFixture(t, accessFixture(t))
	r, err := f.RemoveAccess("alice", []string{"web-1", "web-2", "db-1"})
	if err != nil || r != (AccessRemoval{EntriesRemoved: 2}) {
		t.Fatalf("RemoveAccess = (%+v, %v), want 2 entries removed", r, err)
	}
	out, cfg := encodeParsed(t, f)
	if len(grantsOf(cfg, "alice")) != 0 || len(cfg.Users) != 3 {
		t.Errorf("alice must keep her user entry and lose every grant:\n%s", out)
	}
	inOrder(t, out, "access:\n  # alice: the web tier\n  # bob: everywhere but the database\n  - user: bob\n",
		"# alice db access (temporary)\n# end of manifest\n")
	if strings.Contains(out, "reviewed 2026-10") {
		t.Errorf("a deleted entry's line comment survived:\n%s", out)
	}
}

func TestRemoveAccessErrors(t *testing.T) {
	f := loadFixture(t, accessFixture(t))
	if _, err := f.RemoveAccess("dave", []string{"web-1"}); err == nil || !strings.Contains(err.Error(), `user "dave" is not in the manifest`) {
		t.Errorf("unknown user err = %v", err)
	}
	if _, err := f.RemoveAccess("alice", []string{"db-9"}); err == nil || !strings.Contains(err.Error(), `server "db-9" is not in the manifest`) {
		t.Errorf("unknown server err = %v", err)
	}
}
```

- [ ] **Step 2: Run — expect FAIL** (`undefined: AccessRemoval`, `f.RemoveAccess undefined`):
`GOTOOLCHAIN=go1.26.9 rtk proxy go test ./internal/manifest/ -run 'TestRemoveAccess' -count=1`

- [ ] **Step 3: Implement** — add `"slices"` to `edit.go`'s imports and append:

```go
// AccessRemoval reports what RemoveAccess changed.
type AccessRemoval struct {
	EntriesChanged   int // entries edited in place (list shortened or except: extended)
	EntriesRemoved   int // entries deleted: list emptied, or wildcard left covering nothing
	ServersExcepted  int // servers appended to except: lists
	WildcardsRemoved int // of EntriesRemoved: wildcard entries deleted (decision 1b)
}

// RemoveAccess takes servers away from user's access: entries, leaving the
// user, its keys and every other grant alone. An explicit servers: list
// loses every item naming one of servers; an entry left with no servers is
// deleted (its head comment rescued as RemoveUser does). A wildcard
// (servers: ["*"]) gets each covered server appended to except: — created
// right after servers:, in that list's flow/block style, when absent — and
// is deleted instead when it would then cover no server of the loaded
// config. A server already excepted is not covered, so it is never
// appended twice. Every name in servers must be a server of the loaded
// config; the wildcard is resolved against f.Config().Servers.
func (f *File) RemoveAccess(user string, servers []string) (AccessRemoval, error) {
	m, err := f.rootMapping()
	if err != nil {
		return AccessRemoval{}, err
	}
	fleet, err := f.accessTargets(m, user, servers)
	if err != nil {
		return AccessRemoval{}, err
	}
	var r AccessRemoval
	accessKey, access := sectionOf(m, "access")
	if access == nil {
		return r, nil
	}
	drop := map[*yaml.Node]bool{}
	for _, entry := range access.Content {
		if entry.Kind != yaml.MappingNode || scalarField(entry, "user") != user {
			continue
		}
		switch t := trimEntry(entry, servers, fleet); {
		case t.gone:
			drop[entry] = true
			r.EntriesRemoved++
			if t.wildcard {
				r.WildcardsRemoved++
			}
		case t.changed:
			r.EntriesChanged++
			r.ServersExcepted += t.excepted
		}
	}
	if len(drop) > 0 {
		removeItems(accessKey, access, func(n *yaml.Node) bool { return drop[n] }, true)
	}
	return r, nil
}

// accessTargets checks RemoveAccess's arguments against the loaded
// manifest (user has a users: entry, every server is a servers: entry) and
// returns the fleet's server names, manifest order.
func (f *File) accessTargets(m *yaml.Node, user string, servers []string) ([]string, error) {
	_, users := sectionOf(m, "users")
	if userItem(users, user) == nil {
		return nil, fmt.Errorf("user %q is not in the manifest", user)
	}
	fleet := make([]string, 0, len(f.cfg.Servers))
	for _, s := range f.cfg.Servers {
		fleet = append(fleet, s.Name)
	}
	for _, s := range servers {
		if !slices.Contains(fleet, s) {
			return nil, fmt.Errorf("server %q is not in the manifest", s)
		}
	}
	return fleet, nil
}

// entryTrim is what trimEntry did to one access: entry.
type entryTrim struct {
	changed  bool // servers: shortened or except: extended
	gone     bool // the entry must be deleted (list emptied, or wildcard left covering nothing)
	wildcard bool // the entry is a servers: ["*"] grant
	excepted int  // servers appended to except:
}

// trimEntry removes servers from one access: entry of the user: items of
// an explicit list (every occurrence; the removed item's comments go with
// it), or except: appends on a wildcard.
func trimEntry(entry *yaml.Node, servers, fleet []string) entryTrim {
	list := valueOf(entry, "servers")
	if list == nil || list.Kind != yaml.SequenceNode {
		return entryTrim{}
	}
	if seqHas(list, "*") {
		return entryTrim{} // wildcards: Task M2 replaces this branch
	}
	n := removeItems(nil, list, func(it *yaml.Node) bool {
		return it.Kind == yaml.ScalarNode && slices.Contains(servers, it.Value)
	}, false)
	return entryTrim{changed: n > 0, gone: n > 0 && len(list.Content) == 0}
}

// seqHas reports whether a sequence holds a scalar item equal to v.
func seqHas(seq *yaml.Node, v string) bool {
	return slices.ContainsFunc(seq.Content, func(it *yaml.Node) bool { return it.Kind == yaml.ScalarNode && it.Value == v })
}
```

Notes: list items use `removeItems(nil, …, false)` — a removed item's head and line comments go with it, as `RemoveKey` does (spec: "a removed list item's line comment goes with it"); emptied **entries** use `rescue=true`, as `RemoveUser` does. `fleet` is unused by the explicit branch until M2 (it is a parameter, so it compiles).

- [ ] **Step 4: Run — expect PASS:** `GOTOOLCHAIN=go1.26.9 rtk proxy go test ./internal/manifest/ -run 'TestRemoveAccess' -count=1`

### Task M2: `RemoveAccess` on wildcards (`except:` and decision 1b)

**Files:** `internal/manifest/edit.go`, `internal/manifest/edit_test.go`

- [ ] **Step 1: Write the failing tests** — append:

```go
// TestRemoveAccessWildcard: except: extended (flow), created (block and
// flow styles, right after servers:), and a wildcard left covering no
// current server deleted (decision 1b).
func TestRemoveAccessWildcard(t *testing.T) {
	t.Run("except appended", func(t *testing.T) {
		f := loadFixture(t, accessFixture(t))
		r, err := f.RemoveAccess("bob", []string{"web-2"})
		if err != nil || r != (AccessRemoval{EntriesChanged: 1, ServersExcepted: 1}) {
			t.Fatalf("RemoveAccess = (%+v, %v)", r, err)
		}
		out, cfg := encodeParsed(t, f)
		inOrder(t, out, "  - user: bob\n    servers: [\"*\"]\n    except: [db-1, web-2]\n")
		if got := grantsOf(cfg, "bob"); !slices.Equal(got, []string{"web-1"}) {
			t.Errorf("bob's grants = %v, want [web-1]", got)
		}
		if !cfg.Covers("bob", "web-9") {
			t.Error("the wildcard must keep covering future servers")
		}
	})
	t.Run("except created, block style", func(t *testing.T) {
		f := loadFixture(t, accessFixture(t))
		r, err := f.RemoveAccess("carol", []string{"db-1", "web-1"})
		if err != nil || r != (AccessRemoval{EntriesChanged: 1, ServersExcepted: 2}) {
			t.Fatalf("RemoveAccess = (%+v, %v)", r, err)
		}
		out, cfg := encodeParsed(t, f)
		inOrder(t, out, "  # carol: everywhere\n  - user: carol\n    servers:\n      - \"*\"\n    except:\n      - db-1\n      - web-1\n  # alice db access")
		if got := grantsOf(cfg, "carol"); !slices.Equal(got, []string{"web-2"}) {
			t.Errorf("carol's grants = %v, want [web-2]", got)
		}
	})
	t.Run("except created, flow style", func(t *testing.T) {
		f := loadFixture(t, "users:\n  - {name: bob, keys: [\""+testkeys.Line(t, 4)+"\"]}\n"+
			"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: db-1, host: 10.0.0.9, user: deploy}\n"+
			"access:\n  - user: bob\n    servers: [\"*\"] # all of them\n")
		if _, err := f.RemoveAccess("bob", []string{"web-1"}); err != nil {
			t.Fatalf("RemoveAccess: %v", err)
		}
		out, _ := encodeParsed(t, f)
		inOrder(t, out, "    servers: [\"*\"] # all of them\n    except: [web-1]\n")
	})
	t.Run("null except is rebuilt in place", func(t *testing.T) {
		f := loadFixture(t, "users:\n  - {name: bob, keys: [\""+testkeys.Line(t, 4)+"\"]}\n"+
			"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: db-1, host: 10.0.0.9, user: deploy}\n"+
			"access:\n  - user: bob\n    servers: [\"*\"]\n    except:\n")
		if _, err := f.RemoveAccess("bob", []string{"db-1"}); err != nil {
			t.Fatalf("RemoveAccess: %v", err)
		}
		out, _ := encodeParsed(t, f)
		inOrder(t, out, "    servers: [\"*\"]\n    except: [db-1]\n")
	})
	t.Run("wildcard left covering nothing is deleted", func(t *testing.T) {
		f := loadFixture(t, accessFixture(t))
		r, err := f.RemoveAccess("bob", []string{"web-1", "web-2"})
		if err != nil || r != (AccessRemoval{EntriesRemoved: 1, WildcardsRemoved: 1}) {
			t.Fatalf("RemoveAccess = (%+v, %v), want 1 wildcard entry removed", r, err)
		}
		out, cfg := encodeParsed(t, f)
		if len(grantsOf(cfg, "bob")) != 0 || strings.Contains(out, "- user: bob") {
			t.Errorf("bob's wildcard survived:\n%s", out)
		}
		inOrder(t, out, "  # bob: everywhere but the database\n  # carol: everywhere\n  - user: carol\n")
	})
}

// TestRemoveAccessUntouched: an entry covering none of the servers (the
// server is already excepted) is not edited, and other users' entries
// never are: the encode is byte-identical to the unedited one.
func TestRemoveAccessUntouched(t *testing.T) {
	want, err := loadFixture(t, accessFixture(t)).Encode()
	if err != nil {
		t.Fatal(err)
	}
	f := loadFixture(t, accessFixture(t))
	r, err := f.RemoveAccess("bob", []string{"db-1"})
	if err != nil || r != (AccessRemoval{}) {
		t.Fatalf("RemoveAccess = (%+v, %v), want nothing changed", r, err)
	}
	if out, _ := encodeParsed(t, f); out != string(want) {
		t.Errorf("an uncovered entry was edited:\n%s", out)
	}
}
```

- [ ] **Step 2: Run — expect FAIL** (wildcard subtests report `AccessRemoval = ({…0…}, <nil>)`; `TestRemoveAccessUntouched` passes already):
`GOTOOLCHAIN=go1.26.9 rtk proxy go test ./internal/manifest/ -run 'TestRemoveAccessWildcard|TestRemoveAccessUntouched' -count=1`

- [ ] **Step 3: Implement** — in `trimEntry`, replace the M1 wildcard branch:

```go
	if seqHas(list, "*") {
		n, gone := exceptServers(entry, list, servers, fleet)
		return entryTrim{changed: n > 0, gone: gone, wildcard: true, excepted: n}
	}
```

and add, after `trimEntry`:

```go
// exceptServers appends to a wildcard entry's except: every server of
// servers the entry still covers, creating except: right after servers:
// (same sequence style) when absent or null. gone reports that the
// wildcard would then cover no server of fleet: the caller deletes the
// entry (decision 1b) and the appends do not matter.
func exceptServers(entry, list *yaml.Node, servers, fleet []string) (appended int, gone bool) {
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
	for _, s := range fleet {
		if except == nil || !seqHas(except, s) {
			return appended, false
		}
	}
	return appended, true
}
```

Counting rule (resolution, see the end): a wildcard deleted under decision 1b counts only in `EntriesRemoved` and `WildcardsRemoved` — never in `EntriesChanged` or `ServersExcepted` (its appends are discarded with it).

- [ ] **Step 4: Run — expect PASS:** `GOTOOLCHAIN=go1.26.9 rtk proxy go test ./internal/manifest/ -run 'TestRemoveAccess' -count=1`

### Task M3: `RemoveAccess` golden

**Files:** `internal/manifest/edit_test.go`, create `internal/manifest/testdata/edit_remove_access.golden`

- [ ] **Step 1: Write the test** — append:

```go
// TestRemoveAccessGolden: one File, three users trimmed, one Encode — the
// shape revoke USER... --server uses.
func TestRemoveAccessGolden(t *testing.T) {
	f := loadFixture(t, accessFixture(t))
	for _, c := range []struct {
		user    string
		servers []string
	}{{"alice", []string{"db-1"}}, {"bob", []string{"web-2"}}, {"carol", []string{"db-1"}}} {
		if _, err := f.RemoveAccess(c.user, c.servers); err != nil {
			t.Fatalf("RemoveAccess(%s): %v", c.user, err)
		}
	}
	out, _ := encodeParsed(t, f)
	for _, want := range []string{"# fleet manifest", "# alice: the web tier", "# reviewed 2026-10",
		"# bob: everywhere but the database", "# carol: everywhere", "# alice db access (temporary)", "# end of manifest"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	checkGolden(t, "edit_remove_access.golden", []byte(out))
}
```

- [ ] **Step 2: Run — expect FAIL** (`read golden (run with -update first)`):
`GOTOOLCHAIN=go1.26.9 rtk proxy go test ./internal/manifest/ -run TestRemoveAccessGolden -count=1`

- [ ] **Step 3: Generate and inspect:** `GOTOOLCHAIN=go1.26.9 go test ./internal/manifest/ -run TestRemoveAccessGolden -update`, then read the file. It must be exactly (key blobs are testkeys seeds 2, 4, 5):

```yaml
# fleet manifest
users:
  - {name: alice, keys: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOU"]}
  - {name: bob, keys: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58"]}
  - {name: carol, keys: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG56HN0psLeP0Tr0xVmP7/TvKpcWbjym8uT7/M2AUFvx"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
  - {name: db-1, host: 10.0.0.9, user: deploy}
access:
  # alice: the web tier
  - user: alice
    servers: [web-1, web-2] # reviewed 2026-10
  # bob: everywhere but the database
  - user: bob
    servers: ["*"]
    except: [db-1, web-2]
  # carol: everywhere
  - user: carol
    servers:
      - "*"
    except:
      - db-1
# alice db access (temporary)
# end of manifest
```

- [ ] **Step 4: Run without `-update` — expect PASS.**

### Task M4: `AddKeyAfter`

**Files:** `internal/manifest/edit.go`, `internal/manifest/edit_test.go`

- [ ] **Step 1: Write the failing test** — append:

```go
// TestAddKeyAfter: the new line lands right after the old key (first,
// middle, last); every existing line, comment and operator: flag stays.
func TestAddKeyAfter(t *testing.T) {
	three := `users:
  - name: ops
    # break-glass account
    operator: true # vault-held
    keys:
      # ops laptop
      - ` + testkeys.Line(t, 1) + ` ops@laptop
      # ops desktop
      - ` + testkeys.Line(t, 2) + ` ops@desk
      - ` + testkeys.Line(t, 3) + ` ops@ci # ci runner
`
	newLine := `from="10.0.0.0/8" ` + testkeys.Line(t, 5) + " ops@new"
	for _, tt := range []struct {
		name string
		old  byte
		want []byte // seeds in order; 5 is the new key
	}{
		{"first", 1, []byte{1, 5, 2, 3}},
		{"middle", 2, []byte{1, 2, 5, 3}},
		{"last", 3, []byte{1, 2, 3, 5}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := loadFixture(t, three)
			if err := f.AddKeyAfter("ops", keyFP(t, tt.old), newLine); err != nil {
				t.Fatalf("AddKeyAfter: %v", err)
			}
			out, cfg := encodeParsed(t, f)
			u := cfg.Users[0]
			if !u.Operator || len(u.Keys) != 4 {
				t.Fatalf("ops = %+v, want an operator with 4 keys", u)
			}
			for i, seed := range tt.want {
				if k, err := authkeys.ParseLine(u.Keys[i]); err != nil || k.Fingerprint != keyFP(t, seed) {
					t.Errorf("keys[%d] = %q, want seed %d", i, u.Keys[i], seed)
				}
			}
			if !slices.Contains(u.Keys, newLine) {
				t.Errorf("new line not stored verbatim: %q", u.Keys)
			}
			for _, c := range []string{"# break-glass account", "operator: true # vault-held", "# ops laptop", "# ops desktop", "# ci runner"} {
				if !strings.Contains(out, c) {
					t.Errorf("output lacks %q:\n%s", c, out)
				}
			}
		})
	}
	t.Run("flow list", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		if err := f.AddKeyAfter("bob", keyFP(t, 4), newLine); err != nil {
			t.Fatalf("AddKeyAfter: %v", err)
		}
		_, cfg := encodeParsed(t, f)
		if got := cfg.Users[1].Keys; len(got) != 2 || got[1] != newLine {
			t.Errorf("bob keys = %q", got)
		}
	})
	t.Run("errors", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		if err := f.AddKeyAfter("alice", keyFP(t, 9), newLine); err == nil || !strings.Contains(err.Error(), "is not in the manifest") {
			t.Errorf("unknown key err = %v", err)
		}
		if err := f.AddKeyAfter("bob", keyFP(t, 2), newLine); err == nil || !strings.Contains(err.Error(), `belongs to "alice", not "bob"`) {
			t.Errorf("wrong owner err = %v", err)
		}
	})
}
```

- [ ] **Step 2: Run — expect FAIL** (`f.AddKeyAfter undefined`):
`GOTOOLCHAIN=go1.26.9 rtk proxy go test ./internal/manifest/ -run TestAddKeyAfter -count=1`

- [ ] **Step 3: Implement** — append to `edit.go`:

```go
// AddKeyAfter inserts newLine as a new keys: item of user immediately after
// the item whose fingerprint is oldFP (rotate --keep-old). It only inserts:
// the old item, its comments and the user's operator: flag are untouched;
// the caller composes newLine (rotatedLine), and nothing is validated until
// Encode.
func (f *File) AddKeyAfter(user, oldFP, newLine string) error {
	owner, keys, idx, err := f.findKey(oldFP)
	if err != nil {
		return err
	}
	if name := scalarField(owner, "name"); name != user {
		return fmt.Errorf("key %s belongs to %q, not %q", oldFP, name, user)
	}
	item := strScalar(newLine)
	keys.Content = append(keys.Content[:idx+1], append([]*yaml.Node{item}, keys.Content[idx+1:]...)...)
	return nil
}
```

- [ ] **Step 4: Run — expect PASS:** `GOTOOLCHAIN=go1.26.9 rtk proxy go test ./internal/manifest/ -count=1`

### Task M5: Package doc and gates

**Files:** `internal/manifest/manifest.go` (package comment only)

- [ ] **Step 1:** In the package comment's edit list (`manifest.go` lines 6–11), add two bullets after the `SetOperator` bullet and adjust the fidelity sentence:

```go
//   - SetOperator sets or removes a user's operator: flag;
//   - RemoveAccess takes servers away from a user's access: entries
//     (explicit items removed, wildcards gain except:, emptied entries
//     deleted);
//   - AddKeyAfter inserts one keys: line right after another.
```

and in the fidelity paragraph: "a removed users:/access: entry's head comment moves to the next entry or the section's footer; a removed key line's or servers: item's head comment goes with it".

- [ ] **Step 2: Gates:**
  - `GOTOOLCHAIN=go1.26.9 rtk proxy go test -race -count=1 ./internal/manifest/` — PASS.
  - `GOTOOLCHAIN=go1.26.9 golangci-lint run ./internal/manifest/...` — `0 issues` (the `trimEntry`/`exceptServers` split exists to keep `RemoveAccess` under `gocyclo`; do not inline them).
  - `GOTOOLCHAIN=go1.26.9 go test -cover ./internal/manifest/` — not below 90%.
  - `GOTOOLCHAIN=go1.26.9 go test ./internal/manifest/ -run FuzzManifestEdit -count=1` — the existing fuzz seeds still pass.
- [ ] **Step 3: Hand back** (no commit).

---

## Stage 2 — Revoke agent

### Task R1: `remove-access` edit kind, header text and notes

**Files:** `internal/apply/edit.go`, `internal/apply/edit_test.go`, create `internal/apply/testdata/edit_header_access.golden`, `edit_header_access_multi.golden`, `edit_header_access_color.golden`

- [ ] **Step 1: Write the failing tests** — append to `internal/apply/edit_test.go`:

```go
// TestRenderEditHeaderRemoveAccess: one line per user; count fragments
// pluralized and omitted when zero (the first present one names "access
// entry"); the wildcard-removed warning and the no-access-left note follow
// the edit lines; the affected tail obeys the lone-edit rule.
func TestRenderEditHeaderRemoveAccess(t *testing.T) {
	tests := []struct {
		golden string
		s      EditSummary
		color  bool
	}{
		{"edit_header_access.golden", EditSummary{
			Edits: []Edit{{Kind: EditRemoveAccess, User: "bob", AccessServers: []string{"web-1", "db-1"},
				EntriesChanged: 2, EntriesRemoved: 1, ServersExcepted: 1}},
			Affected: 2,
		}, false},
		{"edit_header_access_multi.golden", EditSummary{
			Edits: []Edit{
				{Kind: EditRemoveAccess, User: "alice", AccessServers: []string{"web-1"}, EntriesRemoved: 1, WildcardsRemoved: 1, NoGrantsLeft: true},
				{Kind: EditRemoveAccess, User: "bob", AccessServers: []string{"web-1"}, EntriesChanged: 1, ServersExcepted: 1},
			},
			Affected: 1,
			Emptied:  []EmptiedServer{{Server: "web-1", Users: []string{"alice", "bob"}, Keys: 2}},
		}, false},
		{"edit_header_access_color.golden", EditSummary{
			Edits:    []Edit{{Kind: EditRemoveAccess, User: "carol", AccessServers: []string{"db-1"}, EntriesRemoved: 1, WildcardsRemoved: 1, NoGrantsLeft: true}},
			Affected: 1,
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.golden, func(t *testing.T) {
			var buf bytes.Buffer
			RenderEditHeader(&buf, tt.s, RenderOptions{Color: tt.color})
			checkGolden(t, tt.golden, buf.Bytes())
		})
	}
}

// TestEditTextRemoveAccessCounts pins every fragment combination.
func TestEditTextRemoveAccessCounts(t *testing.T) {
	e := func(changed, removed, excepted int) Edit {
		return Edit{Kind: EditRemoveAccess, User: "bob", AccessServers: []string{"web-1"},
			EntriesChanged: changed, EntriesRemoved: removed, ServersExcepted: excepted}
	}
	for _, tt := range []struct {
		e    Edit
		want string
	}{
		{e(1, 0, 0), "remove bob's access to web-1 (1 access entry changed)"},
		{e(2, 1, 2), "remove bob's access to web-1 (2 access entries changed, 1 removed, 2 servers excepted)"},
		{e(0, 2, 0), "remove bob's access to web-1 (2 access entries removed)"},
		{e(1, 0, 1), "remove bob's access to web-1 (1 access entry changed, 1 server excepted)"},
		{e(0, 0, 0), "remove bob's access to web-1"},
	} {
		if got := editText(tt.e); got != tt.want {
			t.Errorf("editText(%+v) = %q, want %q", tt.e, got, tt.want)
		}
	}
}
```

- [ ] **Step 2: Run — expect FAIL** (`undefined: EditRemoveAccess`, unknown fields `AccessServers` …):
`GOTOOLCHAIN=go1.26.9 rtk proxy go test ./internal/apply/ -run 'RemoveAccess' -count=1`

- [ ] **Step 3: Implement** in `internal/apply/edit.go`.

Kind constants (replace the block and its comment):

```go
// The four edits.
const (
	EditRemoveUser   EditKind = "remove-user"   // revoke USER
	EditRemoveKey    EditKind = "remove-key"    // revoke --key
	EditRotate       EditKind = "rotate"        // rotate USER --old --new
	EditRemoveAccess EditKind = "remove-access" // revoke USER --server
)
```

`Edit`: extend the `User` comment to "…, the rotated user (EditRotate), or the user losing access (EditRemoveAccess)." and append after `NoKeysLeft, ClearsOperator bool`:

```go
	// AccessServers (EditRemoveAccess) are the servers the user loses, as
	// named on the command line (de-duplicated, order kept).
	AccessServers []string
	// EntriesChanged, EntriesRemoved, ServersExcepted and WildcardsRemoved
	// (EditRemoveAccess) are manifest.AccessRemoval's counts.
	EntriesChanged, EntriesRemoved, ServersExcepted, WildcardsRemoved int
	// NoGrantsLeft (EditRemoveAccess) reports that the user has no access:
	// entry left after the whole edit.
	NoGrantsLeft bool
```

`RenderEditHeader`: replace the notes loop (`for _, e := range s.Edits { switch { case e.ClearsOperator: …` ) with:

```go
	for _, e := range s.Edits {
		if e.WildcardsRemoved > 0 {
			fmt.Fprintf(w, "%s %s's wildcard grant is removed — it would cover no current server; servers added later are no longer granted to %s automatically\n",
				pal.paint(codeYellow, "warning:"), e.User, e.User)
		}
		switch {
		case e.NoGrantsLeft:
			fmt.Fprintf(w, "note: %s has no access left — 'sshepherd revoke %s' removes the user\n", e.User, e.User)
		case e.ClearsOperator:
			fmt.Fprintf(w, "note: %s has no keys left, so its operator flag is cleared — 'sshepherd revoke %s' removes the user\n", e.User, e.User)
		case e.NoKeysLeft:
			fmt.Fprintf(w, "note: %s has no keys left — 'sshepherd revoke %s' removes the user\n", e.User, e.User)
		}
	}
```

Also extend `RenderEditHeader`'s doc comment: "…a note per user left without keys or without access, a warning per user whose wildcard grant is removed, an OPERATOR line…". (One wildcard warning per user's edit — see resolutions.)

`editText`: add before `default:`:

```go
	case EditRemoveAccess:
		t := fmt.Sprintf("remove %s's access to %s", e.User, strings.Join(e.AccessServers, ", "))
		if c := accessCounts(e); c != "" {
			t += " (" + c + ")"
		}
		return t
```

and add after `editText`:

```go
// accessCounts is a remove-access edit's count fragments, each omitted
// when zero; "access entry/entries" names the first one present.
func accessCounts(e Edit) string {
	var parts []string
	noun := func(n int) string {
		if len(parts) == 0 {
			return Plural(n, "access entry", "access entries")
		}
		return fmt.Sprint(n)
	}
	if e.EntriesChanged > 0 {
		parts = append(parts, noun(e.EntriesChanged)+" changed")
	}
	if e.EntriesRemoved > 0 {
		parts = append(parts, noun(e.EntriesRemoved)+" removed")
	}
	if e.ServersExcepted > 0 {
		parts = append(parts, Plural(e.ServersExcepted, "server", "servers")+" excepted")
	}
	return strings.Join(parts, ", ")
}
```

Run `gofmt -w internal/apply/edit.go`.

- [ ] **Step 4: Generate the goldens and inspect:** `GOTOOLCHAIN=go1.26.9 go test ./internal/apply/ -run TestRenderEditHeaderRemoveAccess -update`. Expected bytes:

`edit_header_access.golden`:
```
manifest edit: remove bob's access to web-1, db-1 (2 access entries changed, 1 removed, 1 server excepted) — 2 servers affected
```

`edit_header_access_multi.golden`:
```
manifest edit: remove alice's access to web-1 (1 access entry removed)
manifest edit: remove bob's access to web-1 (1 access entry changed, 1 server excepted)
manifest edit: 2 changes — 1 server affected
warning: alice's wildcard grant is removed — it would cover no current server; servers added later are no longer granted to alice automatically
note: alice has no access left — 'sshepherd revoke alice' removes the user
warning: web-1 would have no granted keys — apply never empties a server, so the keys of alice, bob stay installed there; grant another user (or an operator) on web-1 first, or remove the key by hand
```

`edit_header_access_color.golden` (shown with `cat -v`; only `warning:` is painted, yellow `\x1b[0;33m` … `\x1b[0m`):
```
manifest edit: remove carol's access to db-1 (1 access entry removed) — 1 server affected
^[[0;33mwarning:^[[0m carol's wildcard grant is removed — it would cover no current server; servers added later are no longer granted to carol automatically
note: carol has no access left — 'sshepherd revoke carol' removes the user
```

- [ ] **Step 5: Run the package — expect PASS** (every pre-existing header golden unchanged): `GOTOOLCHAIN=go1.26.9 rtk proxy go test ./internal/apply/ -count=1`

### Task R2: `remove-access` JSON fields

**Files:** `internal/apply/json.go`, `internal/apply/json_test.go`, create `internal/apply/testdata/json_remove_access.golden.json`

- [ ] **Step 1: Write the failing test** — append to `json_test.go`:

```go
// TestRenderJSONRemoveAccess: a remove-access entry carries exactly its
// fields — access_servers ([] never null), the four counts and
// no_grants_left, zero/false included — and no other kind's.
func TestRenderJSONRemoveAccess(t *testing.T) {
	sum := EditSummary{
		Edits: []Edit{
			{Kind: EditRemoveAccess, User: "bob", AccessServers: []string{"web-1", "db-1"}, EntriesChanged: 1, EntriesRemoved: 1, ServersExcepted: 1},
			{Kind: EditRemoveAccess, User: "carol", EntriesRemoved: 1, WildcardsRemoved: 1, NoGrantsLeft: true},
		},
		Affected: 2,
	}
	out := renderJSONCfg(t, planCfg(t), nil, JSONOptions{Command: "revoke", Edit: &sum, Saved: true})
	checkGolden(t, "json_remove_access.golden.json", out)
	var doc struct {
		Edit struct {
			Edits []map[string]any `json:"edits"`
		} `json:"edit"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	bob, carol := doc.Edit.Edits[0], doc.Edit.Edits[1]
	for _, k := range []string{"access_servers", "entries_changed", "entries_removed", "servers_excepted", "wildcards_removed", "no_grants_left"} {
		if _, ok := bob[k]; !ok {
			t.Errorf("remove-access entry lacks %q: %v", k, bob)
		}
	}
	for _, k := range []string{"keys", "grants", "fingerprint", "no_keys_left", "clears_operator", "keep_old"} {
		if _, ok := bob[k]; ok {
			t.Errorf("remove-access entry carries another kind's %q: %v", k, bob)
		}
	}
	if bob["wildcards_removed"] != float64(0) || bob["no_grants_left"] != false {
		t.Errorf("zero values must be present: %v", bob)
	}
	if s, ok := carol["access_servers"].([]any); !ok || len(s) != 0 {
		t.Errorf("empty access_servers = %v, want []", carol["access_servers"])
	}
	if carol["no_grants_left"] != true || carol["wildcards_removed"] != float64(1) {
		t.Errorf("carol = %v", carol)
	}
}
```

- [ ] **Step 2: Run — expect FAIL** (golden missing; once generated, the field asserts fail): `GOTOOLCHAIN=go1.26.9 rtk proxy go test ./internal/apply/ -run TestRenderJSONRemoveAccess -count=1`

- [ ] **Step 3: Implement** in `json.go`. Append to `jsonEditEntry` after `ClearsOperator`:

```go
	// remove-access: AccessServers is a pointer so an empty list still
	// encodes as [] (never null) while staying absent for other kinds.
	AccessServers    *[]string `json:"access_servers,omitempty"`
	EntriesChanged   *int      `json:"entries_changed,omitempty"`
	EntriesRemoved   *int      `json:"entries_removed,omitempty"`
	ServersExcepted  *int      `json:"servers_excepted,omitempty"`
	WildcardsRemoved *int      `json:"wildcards_removed,omitempty"`
	NoGrantsLeft     *bool     `json:"no_grants_left,omitempty"`
```

In `jsonEditFor`'s switch, add:

```go
		case EditRemoveAccess:
			jsonRemoveAccess(&je, ed)
```

and above `jsonEditFor`:

```go
// jsonRemoveAccess fills a remove-access entry: every field present, the
// server list [] rather than null.
func jsonRemoveAccess(je *jsonEditEntry, ed Edit) {
	servers := append([]string{}, ed.AccessServers...)
	changed, removed, excepted, wildcards, noGrants := ed.EntriesChanged, ed.EntriesRemoved, ed.ServersExcepted, ed.WildcardsRemoved, ed.NoGrantsLeft
	je.AccessServers = &servers
	je.EntriesChanged, je.EntriesRemoved, je.ServersExcepted, je.WildcardsRemoved = &changed, &removed, &excepted, &wildcards
	je.NoGrantsLeft = &noGrants
}
```

(The helper keeps `jsonEditFor` under `gocyclo`.)

- [ ] **Step 4: Generate and inspect:** `… -run TestRenderJSONRemoveAccess -update`. The `edit` section must read:

```json
  "edit": {
    "saved": true,
    "edits": [
      {
        "kind": "remove-access",
        "user": "bob",
        "access_servers": [
          "web-1",
          "db-1"
        ],
        "entries_changed": 1,
        "entries_removed": 1,
        "servers_excepted": 1,
        "wildcards_removed": 0,
        "no_grants_left": false
      },
      {
        "kind": "remove-access",
        "user": "carol",
        "access_servers": [],
        "entries_changed": 0,
        "entries_removed": 1,
        "servers_excepted": 0,
        "wildcards_removed": 1,
        "no_grants_left": true
      }
    ],
    "affected": 2,
    "operators": [],
    "emptied": []
  },
```

followed by an all-zero `summary` (exit_code 0) and `"servers": []`.

- [ ] **Step 5: Run the package — expect PASS**, all pre-existing JSON goldens unchanged.

### Task R3: `--server` flag, usage refusals, `Use`/`Long`, README row

**Files:** `cmd/sshepherd/revoke.go`, create `cmd/sshepherd/revoke_server_test.go`, `README.md` (one row)

- [ ] **Step 1: Write the failing test** — create `cmd/sshepherd/revoke_server_test.go` (R4 adds the `testkeys` import and R5 the `context` import, each with the first test that uses it):

```go
package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestRevokeServerUsage: the usage refusals, first match wins, all before
// the manifest is read (the missing manifest would otherwise be the
// error) and with nothing on stdout.
func TestRevokeServerUsage(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	const (
		both     = "revoke takes users or --key, not both"
		perUser  = "access is granted per user, not per key — use 'sshepherd revoke USER --server NAME'"
		operator = "--operator cannot be combined with --server: operators have access to every server by definition"
		star     = "--server takes server names; to remove all of a user's access use 'sshepherd revoke USER'"
	)
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"users, --key and --server", []string{"bob", "--key", fpOf(t, 2), "--server", "web-1"}, both},
		{"--server with --key", []string{"--key", fpOf(t, 2), "--server", "web-1"}, perUser},
		{"--server with --key, --operator and '*'", []string{"--key", fpOf(t, 2), "--server", "*", "--operator"}, perUser},
		{"--server with --operator", []string{"bob", "--server", "web-1", "--operator"}, operator},
		{"--server '*' with --operator", []string{"bob", "--server", "*", "--operator"}, operator},
		{"--server '*'", []string{"bob", "--server", "web-1", "--server", "*"}, star},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			args := append(append([]string{"revoke"}, tt.args...), "--config", "/nonexistent.yaml")
			if code := run(args, &out, &errBuf); code != 3 {
				t.Fatalf("exit = %d, want 3\n%s", code, errBuf.String())
			}
			if !strings.Contains(errBuf.String(), tt.want) || out.Len() != 0 {
				t.Errorf("stderr = %q, stdout = %q; want %q", errBuf.String(), out.String(), tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run — expect FAIL** (`unknown flag: --server` in stderr):
`GOTOOLCHAIN=go1.26.9 rtk proxy go test ./cmd/sshepherd/ -run TestRevokeServerUsage -count=1`

- [ ] **Step 3: Implement** in `revoke.go`.

Variables and `Use`/`Long`:

```go
	var (
		f       editFlags
		keys    []string
		servers []string
	)
	cmd := &cobra.Command{
		Use:   "revoke {USER... [--server NAME...] | --key KEY...}",
		Short: "Remove users or keys from the manifest and push the change to the servers it affects",
		Long: "Edits the manifest — comments preserved — and pushes the edit through\n" +
			"apply's pipeline, restricted to the servers whose rendered\n" +
			"authorized_keys changes. 'revoke USER...' removes each user and every\n" +
			"access entry naming them (offboarding); 'revoke --key KEY...' removes\n" +
			"single keys (a lost laptop): KEY is a SHA256: fingerprint, a public-key\n" +
			"line, or a .pub file path. 'revoke USER... --server NAME...' removes only\n" +
			"the users' access to those servers (a wildcard grant gains an except:\n" +
			"entry); the users and their keys stay. Operator users (and their keys)\n" +
			"need --operator. The plan is shown and confirmed once; the manifest is\n" +
			"saved after confirmation and before the first write, so commit and push\n" +
			"it afterwards. --dry-run changes nothing; --no-apply saves the edit\n" +
			"without contacting any server. A server whose only grantee is revoked is\n" +
			"never emptied: the key stays installed there (a warning says so).",
```

In `RunE`, for this task only (R4 replaces the `_`):

```go
			users, keyArgs, _, err := revokeTargets(args, keys, servers, f.operator)
```

Flag registration, after `--key`:

```go
	cmd.Flags().StringArrayVar(&servers, "server", nil,
		"remove the users' access to this server only (repeatable); the users and their keys stay")
```

Replace `revokeTargets` (and its comment) with:

```go
// revokeTargets applies revoke's usage rules (revokeUsage) and classifies
// --key arguments (step 1): a user argument that looks like a key is a
// mistake, and duplicate users, keys and servers are dropped silently.
func revokeTargets(args, keys, servers []string, operator bool) (users []string, keyArgs []keyArg, trim []string, err error) {
	if err := revokeUsage(args, keys, servers, operator); err != nil {
		return nil, nil, nil, err
	}
	for _, u := range args {
		if looksLikeKey(u) {
			return nil, nil, nil, fmt.Errorf("%s looks like a key — did you mean --key?", u)
		}
	}
	for _, k := range keys {
		ka, err := parseKeyArg(roleKey, k)
		if err != nil {
			return nil, nil, nil, err
		}
		if !slices.ContainsFunc(keyArgs, func(o keyArg) bool { return o.Fingerprint == ka.Fingerprint }) {
			keyArgs = append(keyArgs, ka)
		}
	}
	return unique(args), keyArgs, unique(servers), nil
}

// revokeUsage is revoke's flag/argument combination rules, before the
// manifest is read; the first that matches wins. Users and keys are
// exclusive and one is required; --server goes with users only — never
// with --key or --operator, and never '*'.
func revokeUsage(args, keys, servers []string, operator bool) error {
	switch {
	case len(args) > 0 && len(keys) > 0:
		return errors.New("revoke takes users or --key, not both")
	case len(args) == 0 && len(keys) == 0:
		return errors.New("nothing to revoke: name the users, or pass --key KEY")
	case len(servers) > 0 && len(keys) > 0:
		return errors.New("access is granted per user, not per key — use 'sshepherd revoke USER --server NAME'")
	case len(servers) > 0 && operator:
		return errors.New("--operator cannot be combined with --server: operators have access to every server by definition")
	case slices.Contains(servers, "*"):
		return errors.New("--server takes server names; to remove all of a user's access use 'sshepherd revoke USER'")
	}
	return nil
}

// unique returns in without repeats, first occurrence kept (nil for none).
func unique(in []string) []string {
	var out []string
	for _, s := range in {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}
```

(The split into `revokeUsage` keeps `revokeTargets` under `gocyclo`.)

`README.md` — in the `### sshepherd revoke` flag table, directly under the `--key KEY` row, add exactly:

```
| `--server` | none | Remove the users' access to this server only (repeatable); the users and their keys stay |
```

(The first cell is `` `--server` `` with no varname: the usage string has no backticks, exactly like `apply --server`; `TestHelpMatchesREADMETables` compares this cell.)

- [ ] **Step 4: Run — expect PASS:** `GOTOOLCHAIN=go1.26.9 rtk proxy go test ./cmd/sshepherd/ -run 'TestRevokeServerUsage|TestRevokeUsage|TestHelpMatchesREADMETables|TestRevokeDeduplicates' -count=1`

### Task R4: post-load refusals, the edit, the save reminder

**Files:** `cmd/sshepherd/revoke.go`, `cmd/sshepherd/editrun.go` (`saveNote`), `cmd/sshepherd/revoke_server_test.go`

- [ ] **Step 1: Write the failing tests** — append to `revoke_server_test.go` (add `"github.com/javadh75/SSHepherd/internal/testkeys"` to its imports):

```go
// accessRefusalBody: alice explicit on web-1/web-2, bob wildcard minus
// db-1, ops-bot an operator with no access: entry.
func accessRefusalBody(t *testing.T) string {
	return "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n  - {name: bob, keys: [" + qk(t, 2) + "]}\n" +
		"  - {name: ops-bot, operator: true, keys: [" + qk(t, 3) + "]}\n" +
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: web-2, host: 10.0.0.2, user: deploy}\n" +
		"  - {name: db-1, host: 10.0.0.9, user: deploy}\n" +
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: bob, servers: [\"*\"], except: [db-1]}\n"
}

// TestRevokeServerRefusals: after the manifest is read, every problem is
// listed in one exit-3 message, in order (unknown users, unknown servers,
// operators, ungranted pairs); operators are refused without the
// --operator gate; nothing is edited and nothing is printed on stdout.
func TestRevokeServerRefusals(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	const opMsg = "ops-bot is an operator (access to every server by definition); remove the user with 'sshepherd revoke ops-bot --operator', or clear operator: true by hand"
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"unknown server", []string{"bob", "--server", "db-9"}, `no server named "db-9" in the manifest`},
		{"operator target, no gate", []string{"ops-bot", "--server", "web-1"}, opMsg},
		{"every ungranted pair listed", []string{"alice", "bob", "--server", "web-1", "--server", "db-1"},
			"alice has no access to db-1; bob has no access to db-1"},
		{"all problems, in order", []string{"carol", "ops-bot", "alice", "--server", "db-9", "--server", "db-1"},
			`unknown user: carol; no server named "db-9" in the manifest; ` + opMsg + "; alice has no access to db-1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := writeConfig(t, accessRefusalBody(t))
			before := fileBytes(t, cfg)
			var out, errBuf bytes.Buffer
			args := append(append([]string{"revoke"}, tt.args...), "--yes", "--config", cfg)
			if code := run(args, &out, &errBuf); code != 3 {
				t.Fatalf("exit = %d, want 3\n%s", code, errBuf.String())
			}
			if !strings.Contains(errBuf.String(), tt.want) {
				t.Errorf("stderr = %q, want %q", errBuf.String(), tt.want)
			}
			if strings.Contains(errBuf.String(), "pass --operator to confirm") {
				t.Errorf("the --server path must not run the operator gate: %q", errBuf.String())
			}
			if out.Len() != 0 || !bytes.Equal(fileBytes(t, cfg), before) {
				t.Error("a refused trim printed or edited something")
			}
		})
	}
}

// TestRevokeServerHermetic: bob loses web-1 only — his entry keeps web-2,
// his user entry and key stay, only web-1 is contacted, the reminder names
// the removed access, and there is no scope line (servers not named are
// genuinely unaffected).
func TestRevokeServerHermetic(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--server", "web-1", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	for _, want := range []string{
		"manifest edit: remove bob's access to web-1 (1 access entry changed) — 1 server affected\n",
		"manifest " + cfg + " updated — commit and push it: an apply from a copy without this edit re-grants the removed access\n",
		"web-1: applied · verified",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "scope:") || strings.Contains(out.String(), "web-2:") {
		t.Errorf("a trim prints no scope line and never touches web-2:\n%s", out.String())
	}
	raw := string(fileBytes(t, cfg))
	for _, want := range []string{"  # bob leaves on Friday\n", "  - {user: bob, servers: [web-2]}\n", "  - {user: alice, servers: [web-1, web-2]}\n"} {
		if !strings.Contains(raw, want) {
			t.Errorf("manifest lacks %q:\n%s", want, raw)
		}
	}
	if len(readCfg(t, cfg).Users) != 2 {
		t.Error("the trim removed a user")
	}
	if got := hosts["web-1"].keys(t); strings.Contains(got, testkeys.Line(t, 2)) || !strings.Contains(got, testkeys.Line(t, 1)) {
		t.Errorf("web-1 authorized_keys = %q, want alice only", got)
	}
	if len(hosts["web-2"].srv.Attempts()) != 0 || !strings.Contains(hosts["web-2"].keys(t), testkeys.Line(t, 2)) {
		t.Error("web-2 was contacted or changed")
	}
}
```

- [ ] **Step 2: Run — expect FAIL** (with the `_` from R3 the trim is ignored: the refusal cases exit 3 for lack of credentials with the wrong message, and the hermetic case removes bob entirely, so the header assert fails):
`GOTOOLCHAIN=go1.26.9 rtk proxy go test ./cmd/sshepherd/ -run 'TestRevokeServerRefusals|TestRevokeServerHermetic' -count=1`

- [ ] **Step 3: Implement.**

`revoke.go` `RunE` — take `trim` and dispatch:

```go
			users, keyArgs, trim, err := revokeTargets(args, keys, servers, f.operator)
			if err != nil {
				return err
			}
			m, mf, err := loadForEdit(a.logger, f.run.cfgPath)
			if err != nil {
				return err
			}
			var ep editPlan
			switch {
			case len(trim) > 0:
				ep, err = planRevokeAccess(mf, users, trim)
			case len(users) > 0:
				ep, err = planRevokeUsers(mf, users, f.operator)
			default:
				ep, err = planRevokeKeys(mf, keyArgs, f.operator)
			}
```

`revoke.go` — add above `pluralWord`:

```go
// planRevokeAccess resolves and applies 'revoke USER... --server NAME...'.
// There is no operator gate: an operator target is refused outright
// (access to every server by definition). Every problem is listed in one
// refusal before any edit (accessProblems).
func planRevokeAccess(mf *manifest.File, users, servers []string) (editPlan, error) {
	cfg := mf.Config()
	if problems := accessProblems(cfg, users, servers); len(problems) > 0 {
		return editPlan{}, errors.New(strings.Join(problems, "; "))
	}
	ep := editPlan{
		former:   cfg,
		stillHas: strings.Join(users, ", ") + " still " + pluralWord(len(users), "has", "have"),
		saveNote: "an apply from a copy without this edit re-grants the removed access",
	}
	for _, name := range users {
		r, err := mf.RemoveAccess(name, servers)
		if err != nil {
			return editPlan{}, fmt.Errorf("edit manifest: %w", err)
		}
		ep.summary.Edits = append(ep.summary.Edits, apply.Edit{
			Kind: apply.EditRemoveAccess, User: name, AccessServers: servers,
			EntriesChanged: r.EntriesChanged, EntriesRemoved: r.EntriesRemoved,
			ServersExcepted: r.ServersExcepted, WildcardsRemoved: r.WildcardsRemoved,
		})
	}
	var err error
	if ep.encoded, ep.edited, err = encodeEdit(mf); err != nil {
		return editPlan{}, err
	}
	for i, e := range ep.summary.Edits {
		ep.summary.Edits[i].NoGrantsLeft = !slices.ContainsFunc(ep.edited.Access, func(a config.Access) bool { return a.User == e.User })
	}
	return ep, nil
}

// accessProblems lists why 'revoke USER... --server NAME...' cannot run,
// in this order: unknown users (one entry, the existing wording), unknown
// servers, operator targets, then every non-operator user × known server
// pair the user has no access to (config.Covers: wildcards and except:
// included).
func accessProblems(cfg *config.Config, users, servers []string) []string {
	var problems, unknown, ops []string
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
		problems = append(problems, fmt.Sprintf("%s is an operator (access to every server by definition); remove the user with 'sshepherd revoke %s --operator', or clear operator: true by hand", name, name))
	}
	for _, name := range users {
		if slices.Contains(unknown, name) || slices.Contains(ops, name) {
			continue
		}
		for _, s := range known {
			if !cfg.Covers(name, s) {
				problems = append(problems, fmt.Sprintf("%s has no access to %s", name, s))
			}
		}
	}
	return problems
}
```

`editPlan` fields for the trim, per spec: `removesKey` false (zero value — no scope line), `formerNote` unused (every removed key is still the user's, so plan labels show the owner), `stillHas` gives `bob still has access on 2 servers`, `saveNote` as above.

`editrun.go` — add the field to `editPlan` (after `stillHas`):

```go
	saveNote   string // the save reminder's tail; "" = defaultSaveNote
```

add after the struct:

```go
// defaultSaveNote is the save reminder's tail for edits that remove a key
// (revoke USER, revoke --key, plain rotate).
const defaultSaveNote = "an apply from a copy without this edit re-grants the removed key"
```

and in `saveEdit`, replace the `Fprintf` line:

```go
	note := ep.saveNote
	if note == "" {
		note = defaultSaveNote
	}
	fmt.Fprintf(stdout, "manifest %s updated — commit and push it: %s\n", ep.target.Path, note)
	return nil
```

Run `gofmt -w cmd/sshepherd/`.

- [ ] **Step 4: Run — expect PASS:** `GOTOOLCHAIN=go1.26.9 rtk proxy go test ./cmd/sshepherd/ -run 'TestRevokeServer|TestRevoke' -count=1` (every pre-existing revoke test still passes: their reminder uses the default tail).

### Task R5: behavior pins — wildcard, sole grantee, `--no-apply`, `--dry-run`, nothing-can-land, `--json`

**Files:** `cmd/sshepherd/revoke_server_test.go` (add `"context"` to the imports)

- [ ] **Step 1: Write the tests** — append:

```go
// TestRevokeServerWildcard: a wildcard grant gains except: (created in the
// entry's flow style); a wildcard left covering no current server is
// deleted with the warning and the no-access-left note.
func TestRevokeServerWildcard(t *testing.T) {
	setup := func(t *testing.T, bobAccess string) (map[string]editHost, string, string) {
		hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
		for _, h := range hosts {
			h.install(t, []byte{1, 2})
		}
		cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
			"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
			"access:\n  - {user: alice, servers: [web-1, web-2]}\n"+bobAccess)
		return hosts, kh, cfg
	}
	t.Run("except created", func(t *testing.T) {
		hosts, kh, cfg := setup(t, "  - user: bob\n    servers: [\"*\"]\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--server", "web-1", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
		}
		if want := "manifest edit: remove bob's access to web-1 (1 access entry changed, 1 server excepted) — 1 server affected\n"; !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
		if raw := string(fileBytes(t, cfg)); !strings.Contains(raw, "  - user: bob\n    servers: [\"*\"]\n    except: [web-1]\n") {
			t.Errorf("manifest:\n%s", raw)
		}
		if strings.Contains(hosts["web-1"].keys(t), testkeys.Line(t, 2)) || !strings.Contains(hosts["web-2"].keys(t), testkeys.Line(t, 2)) {
			t.Error("want bob's key gone from web-1 only")
		}
	})
	t.Run("wildcard left covering nothing", func(t *testing.T) {
		_, kh, cfg := setup(t, "  - {user: bob, servers: [\"*\"], except: [web-2]}\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--server", "web-1", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
		}
		for _, want := range []string{
			"manifest edit: remove bob's access to web-1 (1 access entry removed) — 1 server affected\n",
			"warning: bob's wildcard grant is removed — it would cover no current server; servers added later are no longer granted to bob automatically\n",
			"note: bob has no access left — 'sshepherd revoke bob' removes the user\n",
		} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("stdout lacks %q:\n%s", want, out.String())
			}
		}
		saved := readCfg(t, cfg)
		if len(saved.Users) != 2 || len(saved.Access) != 1 || saved.Access[0].User != "alice" {
			t.Errorf("saved = %+v, want bob kept with no access entry", saved)
		}
	})
}

// TestRevokeServerSoleGrantee: db-1's only grantee loses it — the emptied
// warning heads the report, db-1 is refused and keeps the key, web-1
// converges, and the emptied entry is gone with the no-access-left note.
func TestRevokeServerSoleGrantee(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "db-1")
	hosts["web-1"].install(t, []byte{1, 2})
	hosts["db-1"].install(t, []byte{2})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["db-1"].line("db-1")+
		"access:\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [web-1, db-1]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--server", "web-1", "--server", "db-1", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s\n%s", code, out.String(), errBuf.String())
	}
	s := out.String()
	for _, want := range []string{
		"manifest edit: remove bob's access to web-1, db-1 (1 access entry removed) — 2 servers affected\n",
		"note: bob has no access left — 'sshepherd revoke bob' removes the user\n",
		"warning: db-1 would have no granted keys — apply never empties a server, so bob's key stays installed there",
		"web-1: applied · verified",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("stdout lacks %q:\n%s", want, s)
		}
	}
	if !strings.Contains(hosts["db-1"].keys(t), testkeys.Line(t, 2)) {
		t.Error("db-1 was emptied")
	}
	if saved := readCfg(t, cfg); len(saved.Users) != 2 || len(saved.Access) != 1 {
		t.Errorf("saved = %+v", saved)
	}
}

// TestRevokeServerNoApplyDryRun: --no-apply saves and names the apply that
// pushes it (no scope line); --dry-run saves and writes nothing; a
// repeated --server is one server; --dry-run --no-apply prints the header
// only.
func TestRevokeServerNoApplyDryRun(t *testing.T) {
	t.Run("--no-apply", func(t *testing.T) {
		hosts, _, cfg := twoUserFleet(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--server", "web-1", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		for _, want := range []string{
			"re-grants the removed access\n",
			"no servers contacted — 1 affected server still carries the old keys; run 'sshepherd apply --config " + cfg + " --server web-1' to push\n",
		} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("stdout lacks %q:\n%s", want, out.String())
			}
		}
		if strings.Contains(out.String(), "scope:") {
			t.Errorf("no scope line on a trim:\n%s", out.String())
		}
		for name, h := range hosts {
			if len(h.srv.Attempts()) != 0 {
				t.Errorf("--no-apply connected to %s", name)
			}
		}
	})
	t.Run("--dry-run", func(t *testing.T) {
		hosts, kh, cfg := twoUserFleet(t)
		before := fileBytes(t, cfg)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--server", "web-1", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("exit = %d, want 1 (pending)\n%s", code, errBuf.String())
		}
		if !bytes.Equal(fileBytes(t, cfg), before) || !strings.Contains(hosts["web-1"].keys(t), testkeys.Line(t, 2)) {
			t.Error("--dry-run changed something")
		}
	})
	t.Run("duplicate --server, --dry-run --no-apply", func(t *testing.T) {
		_, _, cfg := twoUserFleet(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--server", "web-1", "--server", "web-1", "--no-apply", "--dry-run", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if out.String() != "manifest edit: remove bob's access to web-1 (1 access entry changed) — 1 server affected\n" {
			t.Errorf("stdout = %q", out.String())
		}
	})
}

// TestRevokeServerNothingCanLand: every affected server refused — the
// refusal reads "bob still has access on N servers", nothing saved.
func TestRevokeServerNothingCanLand(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	for _, h := range hosts {
		h.install(t, []byte{1, 2}, "this line is not a key")
	}
	before := fileBytes(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--server", "web-1", "--server", "web-2", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "nothing saved — bob still has access on 2 servers;") {
		t.Errorf("stderr = %q", errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("manifest saved although nothing could land")
	}
}

// TestRevokeServerJSON: the remove-access entry and its fields; the
// removed key is still bob's, so it carries owner, not former_owner.
func TestRevokeServerJSON(t *testing.T) {
	_, kh, cfg := twoUserFleet(t)
	doc := runJSONDoc(context.Background(), t, 0, "revoke", "bob", "--server", "web-1", "--json", "--yes", "--config", cfg, "--known-hosts", kh)
	edit := doc["edit"].(map[string]any)
	if edit["saved"] != true || edit["affected"] != float64(1) {
		t.Errorf("edit = %v", edit)
	}
	e := edit["edits"].([]any)[0].(map[string]any)
	if e["kind"] != "remove-access" || e["user"] != "bob" || e["entries_changed"] != float64(1) ||
		e["entries_removed"] != float64(0) || e["no_grants_left"] != false || e["keys"] != nil {
		t.Errorf("edit entry = %v", e)
	}
	if s := e["access_servers"].([]any); len(s) != 1 || s[0] != "web-1" {
		t.Errorf("access_servers = %v", s)
	}
	servers := docServers(doc)
	if len(servers) != 1 || servers[0]["name"] != "web-1" || servers[0]["outcome"] != "applied" {
		t.Fatalf("servers = %v", servers)
	}
	removed := servers[0]["changes"].(map[string]any)["remove"].([]any)
	if len(removed) != 1 || removed[0].(map[string]any)["owner"] != "bob" {
		t.Errorf("remove = %v", removed)
	}
}
```

(`runJSONDoc` and `docServers` live in `json_cmd_test.go`; `twoUserFleet`, `editFleet`, `qk`, `readCfg`, `fileBytes` in `revoke_test.go`; `writeConfig` in `audit_test.go`.)

- [ ] **Step 2: Run — expect PASS** (the behavior falls out of R1–R4): `GOTOOLCHAIN=go1.26.9 rtk proxy go test ./cmd/sshepherd/ -run TestRevokeServer -count=1 -v`. If one fails, the assertion names the gap — fix it in `revoke.go`/`editrun.go`/`internal/apply`, never by loosening the test, and report it.

### Task R6: Stage gates

- [ ] `GOTOOLCHAIN=go1.26.9 rtk proxy go test -race -count=1 ./internal/apply/ ./internal/manifest/ ./cmd/sshepherd/` — PASS.
- [ ] `gofmt -l cmd internal` and `goimports -l cmd internal` — print nothing.
- [ ] `GOTOOLCHAIN=go1.26.9 golangci-lint run ./...` — no issues (if the cache reports paths under `.claude/worktrees/…`, run `golangci-lint cache clean` and re-run).
- [ ] `GOTOOLCHAIN=go1.26.9 deadcode ./cmd/sshepherd` — prints nothing.
- [ ] Hand back (no commit).

---

## Stage 3 — Rotate agent

### Task K1: `KeepOld` on rotate edits — header

**Files:** `internal/apply/edit.go`, `internal/apply/edit_test.go`, create `internal/apply/testdata/edit_header_keep_old.golden`, `edit_header_keep_old_expiry.golden`

- [ ] **Step 1: Write the failing test** — append to `edit_test.go`:

```go
// TestRenderEditHeaderKeepOld: rotate --keep-old adds "keeps the old key",
// joined to the expiry fragment with "; " when one carries over.
func TestRenderEditHeaderKeepOld(t *testing.T) {
	for _, tt := range []struct {
		golden string
		expiry string
	}{
		{"edit_header_keep_old.golden", ""},
		{"edit_header_keep_old_expiry.golden", `expiry-time="20270101"`},
	} {
		t.Run(tt.golden, func(t *testing.T) {
			var buf bytes.Buffer
			RenderEditHeader(&buf, EditSummary{
				Edits: []Edit{{Kind: EditRotate, User: "bob", Fingerprint: fp(t, 4), NewFingerprint: fp(t, 5),
					KeepsExpiry: tt.expiry, KeepOld: true}},
				Affected: 3,
			}, RenderOptions{})
			checkGolden(t, tt.golden, buf.Bytes())
		})
	}
	var buf bytes.Buffer
	RenderEditHeader(&buf, EditSummary{Edits: []Edit{{Kind: EditRotate, User: "bob", Fingerprint: "SHA256:old", NewFingerprint: "SHA256:new",
		KeepsExpiry: `expiry-time="20270101"`, KeepOld: true}}, Affected: 3}, RenderOptions{})
	if want := "manifest edit: rotate bob key SHA256:old → SHA256:new (keeps the old key; keeps expiry-time=\"20270101\") — 3 servers affected\n"; buf.String() != want {
		t.Errorf("header = %q, want %q", buf.String(), want)
	}
}
```

- [ ] **Step 2: Run — expect FAIL** (`unknown field KeepOld in struct literal`): `GOTOOLCHAIN=go1.26.9 rtk proxy go test ./internal/apply/ -run TestRenderEditHeaderKeepOld -count=1`

- [ ] **Step 3: Implement.** In `Edit`, after `KeepsExpiry string`:

```go
	// KeepOld (EditRotate) is rotate --keep-old: the new key is added
	// after the old one, which stays (an overlap).
	KeepOld bool
```

In `editText`, replace the `default:` body:

```go
	default:
		t := fmt.Sprintf("rotate %s key %s → %s", e.User, e.Fingerprint, e.NewFingerprint)
		var keeps []string
		if e.KeepOld {
			keeps = append(keeps, "keeps the old key")
		}
		if e.KeepsExpiry != "" {
			keeps = append(keeps, "keeps "+e.KeepsExpiry)
		}
		if len(keeps) > 0 {
			t += " (" + strings.Join(keeps, "; ") + ")"
		}
		return t
```

- [ ] **Step 4: Generate and inspect** (`… -run TestRenderEditHeaderKeepOld -update`):

`edit_header_keep_old.golden`:
```
manifest edit: rotate bob key SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o → SHA256:LA4QoSmstGCy/UHfdU3jKjnPz56pQzud9OmslMh3g8w (keeps the old key) — 3 servers affected
```

`edit_header_keep_old_expiry.golden`:
```
manifest edit: rotate bob key SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o → SHA256:LA4QoSmstGCy/UHfdU3jKjnPz56pQzud9OmslMh3g8w (keeps the old key; keeps expiry-time="20270101") — 3 servers affected
```

- [ ] **Step 5: Run the package — expect PASS**; `edit_header_rotate.golden` (plain rotate) must be unchanged.

### Task K2: `keep_old` in JSON

**Files:** `internal/apply/json.go`, `internal/apply/json_test.go`, create `internal/apply/testdata/json_rotate_keep_old.golden.json`, regenerate `json_rotate_edit_only.golden.json`

- [ ] **Step 1: Write the failing test** — append to `json_test.go`:

```go
// TestRenderJSONKeepOld: keep_old is present on every rotate entry — true
// for --keep-old, false for a plain rotate — and on no other kind.
func TestRenderJSONKeepOld(t *testing.T) {
	sum := EditSummary{
		Edits:    []Edit{{Kind: EditRotate, User: "bob", Fingerprint: fp(t, 4), NewFingerprint: fp(t, 5), KeepOld: true}},
		Affected: 3,
	}
	out := renderJSONCfg(t, planCfg(t), nil, JSONOptions{Command: "rotate", Edit: &sum, Saved: true})
	checkGolden(t, "json_rotate_keep_old.golden.json", out)
	if !strings.Contains(string(out), `"keep_old": true`) {
		t.Errorf("keep_old missing:\n%s", out)
	}
	plain := EditSummary{Edits: []Edit{
		{Kind: EditRotate, User: "bob", Fingerprint: fp(t, 4), NewFingerprint: fp(t, 5)},
		{Kind: EditRemoveKey, User: "bob", Fingerprint: fp(t, 3)},
	}}
	out = renderJSONCfg(t, planCfg(t), nil, JSONOptions{Command: "rotate", Edit: &plain})
	if strings.Count(string(out), `"keep_old"`) != 1 || !strings.Contains(string(out), `"keep_old": false`) {
		t.Errorf("want keep_old: false on the rotate entry only:\n%s", out)
	}
}
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement.** In `jsonEditEntry`, directly after `KeepsExpiry`:

```go
	KeepOld        *bool  `json:"keep_old,omitempty"` // always present on rotate entries
```

In `jsonEditFor`, replace the `EditRotate` case:

```go
		case EditRotate:
			keepOld := ed.KeepOld
			je.Fingerprint, je.NewFingerprint, je.KeepsExpiry, je.KeepOld = ed.Fingerprint, ed.NewFingerprint, ed.KeepsExpiry, &keepOld
```

- [ ] **Step 4: Regenerate both goldens:** `GOTOOLCHAIN=go1.26.9 go test ./internal/apply/ -run 'TestRenderJSONKeepOld|TestRenderJSONEditOnly' -update`, then `git diff internal/apply/testdata/json_rotate_edit_only.golden.json` must show exactly:

```diff
-        "keeps_expiry": "expiry-time=\"20270101\""
+        "keeps_expiry": "expiry-time=\"20270101\"",
+        "keep_old": false
```

and the new golden's rotate entry is `kind, user, fingerprint, new_fingerprint, "keep_old": true` (no `keeps_expiry`), `affected: 3`, `operators: []`, `emptied: []`, all-zero summary, `servers: []`.

- [ ] **Step 5: Run the package — expect PASS.** `rtk proxy grep -rn keep_old README.md` must print nothing yet (no README JSON sample carries a rotate entry; the integrator documents the field).

### Task K3: The finish hint (`overlapHint`)

**Files:** `cmd/sshepherd/editrun.go`, `cmd/sshepherd/editrun_test.go`

- [ ] **Step 1: Write the failing test** — append to `editrun_test.go`:

```go
// TestOverlapHint pins every finish-hint row, the --config/--operator
// parts of CMD (quoted like applyHint), and the operator's second line.
func TestOverlapHint(t *testing.T) {
	bob := overlapFinish{user: "bob", oldFP: "SHA256:old+/="}
	ops := overlapFinish{user: "ops", oldFP: "SHA256:old", operator: true}
	const opLine = "if the old key is how this machine logs in, run the finish with --identity pointing at the new key's private key, or the lockout guard will refuse it\n"
	for _, tt := range []struct {
		name                   string
		o                      overlapFinish
		cfg                    string
		affected, notConverged int
		noApply                bool
		want                   string
	}{
		{"started", bob, "sshepherd.yaml", 3, 0, false,
			"overlap started — every affected server accepts both keys; once every client uses the new key, finish with: sshepherd revoke --key SHA256:old+/=\n"},
		{"incomplete, one", bob, "sshepherd.yaml", 3, 1, false,
			"overlap incomplete — 1 server does not have the new key yet; push it first (see the apply hint above), then finish with: sshepherd revoke --key SHA256:old+/=\n"},
		{"incomplete, many", bob, "/etc/fleet.yaml", 3, 2, false,
			"overlap incomplete — 2 servers do not have the new key yet; push it first (see the apply hint above), then finish with: sshepherd revoke --key SHA256:old+/= --config /etc/fleet.yaml\n"},
		{"not pushed", bob, "my fleet.yaml", 3, 0, true,
			"overlap recorded, not pushed — run the apply hint above, then, once every client uses the new key, finish with: sshepherd revoke --key SHA256:old+/= --config 'my fleet.yaml'\n"},
		{"no grants", bob, "sshepherd.yaml", 0, 0, true,
			"new key recorded — bob has no grants yet, so no server was contacted; finish the overlap with: sshepherd revoke --key SHA256:old+/=\n"},
		{"operator", ops, "sshepherd.yaml", 2, 0, false,
			"overlap started — every affected server accepts both keys; once every client uses the new key, finish with: sshepherd revoke --key SHA256:old --operator\n" + opLine},
	} {
		if got := overlapHint(tt.o, tt.cfg, tt.affected, tt.noApply, tt.notConverged); got != tt.want {
			t.Errorf("%s:\n got %q\nwant %q", tt.name, got, tt.want)
		}
	}
}
```

- [ ] **Step 2: Run — expect FAIL** (`undefined: overlapFinish`): `GOTOOLCHAIN=go1.26.9 rtk proxy go test ./cmd/sshepherd/ -run TestOverlapHint -count=1`

- [ ] **Step 3: Implement** in `editrun.go`. Add the `editPlan` field after `saveNote`:

```go
	overlap    *overlapFinish // rotate --keep-old: the finish hint to print; nil otherwise
```

and after the struct:

```go
// overlapFinish is rotate --keep-old's pending finish: the revoke --key
// that ends the overlap once every client uses the new key.
type overlapFinish struct {
	user     string // the rotated user
	oldFP    string // the old key, which the finish revokes
	operator bool   // the user is an operator: the finish needs --operator
}

// overlapHint is rotate --keep-old's finish hint for one text-mode path
// (never under --json or --dry-run, whose callers return first): affected
// is the affected-server count, noApply is --no-apply, and notConverged
// counts a confirmed run's affected servers that do not hold the new key
// yet. CMD quotes like applyHint; an operator's hint gets a second line.
func overlapHint(o overlapFinish, cfgPath string, affected int, noApply bool, notConverged int) string {
	cmd := "sshepherd revoke --key " + hintArg(o.oldFP)
	if cfgPath != "sshepherd.yaml" {
		cmd += " --config " + hintArg(cfgPath)
	}
	if o.operator {
		cmd += " --operator"
	}
	var lead string
	switch {
	case affected == 0:
		lead = "new key recorded — " + o.user + " has no grants yet, so no server was contacted; finish the overlap with: "
	case noApply:
		lead = "overlap recorded, not pushed — run the apply hint above, then, once every client uses the new key, finish with: "
	case notConverged == 0:
		lead = "overlap started — every affected server accepts both keys; once every client uses the new key, finish with: "
	default:
		lead = fmt.Sprintf("overlap incomplete — %s %s not have the new key yet; push it first (see the apply hint above), then finish with: ",
			apply.Plural(notConverged, "server", "servers"), pluralWord(notConverged, "does", "do"))
	}
	out := lead + cmd + "\n"
	if o.operator {
		out += "if the old key is how this machine logs in, run the finish with --identity pointing at the new key's private key, or the lockout guard will refuse it\n"
	}
	return out
}
```

Row precedence (resolution): zero affected wins over `--no-apply` (there is no apply hint "above" to point at when nothing is affected).

- [ ] **Step 4: Run — expect PASS.**

### Task K4: `--keep-old` flag, `planRotate`, hint wiring, README row

**Files:** `cmd/sshepherd/rotate.go`, `cmd/sshepherd/editrun.go` (`saveOnly`, `finishEdit`), create `cmd/sshepherd/rotate_keep_old_test.go`, `README.md` (one row)

- [ ] **Step 1: Write the failing tests** — create `cmd/sshepherd/rotate_keep_old_test.go`:

```go
package main

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// keepOldFleet: alice holds k1 (the agent's key) on web-1 and web-2; the
// servers also accept k5, whose private key file is returned.
func keepOldFleet(t *testing.T) (map[string]editHost, string, string, string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1, 5}, "web-1", "web-2")
	for _, h := range hosts {
		h.install(t, []byte{1})
	}
	cfg := writeConfig(t, "users:\n  - name: alice\n    keys:\n      # alice's laptop\n      - "+qk(t, 1)+"\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n")
	return hosts, kh, cfg, sshtest.WriteKeyFile(t, t.TempDir(), "id_new", sshtest.Key(5), nil)
}

// inOrderCmd asserts each want occurs in s, in the given order.
func inOrderCmd(t *testing.T, s string, wants ...string) {
	t.Helper()
	at := 0
	for _, w := range wants {
		i := strings.Index(s[at:], w)
		if i < 0 {
			t.Fatalf("output lacks %q after offset %d:\n%s", w, at, s)
		}
		at += i + len(w)
	}
}

// TestRotateKeepOldLifecycle: --keep-old installs both keys (no scope
// line, the keep-old save reminder, the "overlap started" finish hint);
// the printed finish — revoke --key OLD, here with the new key's
// --identity — leaves only the new key, and audit is clean.
func TestRotateKeepOldLifecycle(t *testing.T) {
	hosts, kh, cfg, newKey := keepOldFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"rotate", "alice", "--old", fpOf(t, 1), "--new", newKey + ".pub", "--keep-old", "--yes",
		"--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	finish := "sshepherd revoke --key " + fpOf(t, 1) + " --config " + cfg
	for _, want := range []string{
		"manifest edit: rotate alice key " + fpOf(t, 1) + " → " + fpOf(t, 5) + " (keeps the old key) — 2 servers affected\n",
		"manifest " + cfg + " updated — commit and push it: an apply from a copy without this edit removes the new key — clients that already switched would be locked out\n",
		"web-1: applied · verified",
		"web-2: applied · verified",
		"overlap started — every affected server accepts both keys; once every client uses the new key, finish with: " + finish + "\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "scope:") || strings.Contains(out.String(), "rotated out") || strings.Contains(out.String(), "if the old key") {
		t.Errorf("keep-old prints no scope line, no rotated-out label and no operator line:\n%s", out.String())
	}
	if got := readCfg(t, cfg).Users[0].Keys; !slices.Equal(got, []string{testkeys.Line(t, 1), testkeys.Line(t, 5)}) {
		t.Errorf("manifest keys = %q, want old then new", got)
	}
	if !strings.Contains(string(fileBytes(t, cfg)), "# alice's laptop") {
		t.Error("the old key's head comment was lost")
	}
	for name, h := range hosts {
		if got := h.keys(t); !strings.Contains(got, testkeys.Line(t, 1)) || !strings.Contains(got, testkeys.Line(t, 5)) {
			t.Errorf("%s authorized_keys = %q, want both keys", name, got)
		}
	}

	out.Reset()
	errBuf.Reset()
	if code := run(append(strings.Fields(finish)[1:], "--yes", "--known-hosts", kh, "--identity", newKey), &out, &errBuf); code != 0 {
		t.Fatalf("finish exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if strings.Contains(out.String(), "has no keys left") {
		t.Errorf("the finish must not leave alice keyless:\n%s", out.String())
	}
	if got := readCfg(t, cfg).Users[0].Keys; !slices.Equal(got, []string{testkeys.Line(t, 5)}) {
		t.Errorf("manifest keys after the finish = %q, want the new key only", got)
	}
	for name, h := range hosts {
		if got := h.keys(t); strings.Contains(got, testkeys.Line(t, 1)) || !strings.Contains(got, testkeys.Line(t, 5)) {
			t.Errorf("%s authorized_keys = %q, want the new key only", name, got)
		}
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh, "--identity", newKey}, &out, &errBuf); code != 0 {
		t.Fatalf("audit exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
}

// TestRotateKeepOldExpiryNoGrants: the new key carries the old line's
// options, expiry-time included (named in the header); a user with no
// grants gets the "new key recorded" hint (--no-apply included); the
// multi-key comment: warning surfaces as for any edit.
func TestRotateKeepOldExpiryNoGrants(t *testing.T) {
	saved := rotateNow
	rotateNow = func() time.Time { return time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { rotateNow = saved })
	cfg := writeConfig(t, "users:\n  - {name: deploy, comment: deploy@ci, keys: ['expiry-time=\"20990101\" "+testkeys.Line(t, 1)+"']}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"rotate", "deploy", "--old", fpOf(t, 1), "--new", writePub(t, "n.pub", testkeys.Line(t, 5)),
		"--keep-old", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
	for _, want := range []string{
		`(keeps the old key; keeps expiry-time="20990101") — no servers affected` + "\n",
		"no servers contacted — no server's desired keys changed\n",
		"new key recorded — deploy has no grants yet, so no server was contacted; finish the overlap with: sshepherd revoke --key " + fpOf(t, 1) + " --config " + cfg + "\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	if !strings.Contains(errBuf.String(), `user "deploy": comment is set on a user with 2 keys; apply will write the same comment on every key`) {
		t.Errorf("stderr lacks the multi-key comment warning: %q", errBuf.String())
	}
	want := []string{`expiry-time="20990101" ` + testkeys.Line(t, 1), `expiry-time="20990101" ` + testkeys.Line(t, 5)}
	if got := readCfg(t, cfg).Users[0].Keys; !slices.Equal(got, want) {
		t.Errorf("keys = %q, want %q", got, want)
	}
}

// TestRotateKeepOldHintRows: the --no-apply row (after the apply hint),
// the "overlap incomplete" row (after the finish line), the operator's
// --identity line, and no hint under --dry-run, on nothing-can-land, or
// on a declined prompt.
func TestRotateKeepOldHintRows(t *testing.T) {
	newPub := func(t *testing.T) string { return writePub(t, "n.pub", testkeys.Line(t, 5)) }
	t.Run("--no-apply", func(t *testing.T) {
		_, _, cfg, _ := keepOldFleet(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"rotate", "alice", "--old", fpOf(t, 1), "--new", newPub(t), "--keep-old", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		inOrderCmd(t, out.String(),
			"no servers contacted — 2 affected servers still carry the old keys; run 'sshepherd apply --config "+cfg+" --server web-1 --server web-2' to push\n",
			"overlap recorded, not pushed — run the apply hint above, then, once every client uses the new key, finish with: sshepherd revoke --key "+fpOf(t, 1)+" --config "+cfg+"\n")
	})
	t.Run("overlap incomplete", func(t *testing.T) {
		hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
		hosts["web-1"].install(t, []byte{1})
		cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
			fmt.Sprintf("  - {name: web-2, host: 127.0.0.1, port: %d, user: deploy}\n", closedPort(t))+
			"access:\n  - {user: alice, servers: [web-1, web-2]}\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"rotate", "alice", "--old", fpOf(t, 1), "--new", newPub(t), "--keep-old", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("exit = %d, want 1\n%s\n%s", code, out.String(), errBuf.String())
		}
		inOrderCmd(t, out.String(),
			"manifest updated; 1 server not converged — finish with: sshepherd apply --config "+cfg+" --server web-2\n",
			"overlap incomplete — 1 server does not have the new key yet; push it first (see the apply hint above), then finish with: sshepherd revoke --key "+fpOf(t, 1)+" --config "+cfg+"\n")
	})
	t.Run("operator", func(t *testing.T) {
		cfg := writeConfig(t, "users:\n  - {name: ops, operator: true, keys: ["+qk(t, 1)+"]}\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"rotate", "ops", "--old", fpOf(t, 1), "--new", newPub(t), "--keep-old", "--operator", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		inOrderCmd(t, out.String(),
			"finish with: sshepherd revoke --key "+fpOf(t, 1)+" --config "+cfg+" --operator\n"+
				"if the old key is how this machine logs in, run the finish with --identity pointing at the new key's private key, or the lockout guard will refuse it\n")
		if u := readCfg(t, cfg).Users[0]; !u.Operator || len(u.Keys) != 2 {
			t.Errorf("ops = %+v, want an operator with both keys", u)
		}
	})
	t.Run("no hint: --dry-run, nothing-can-land, declined", func(t *testing.T) {
		hosts, kh, cfg, _ := keepOldFleet(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"rotate", "alice", "--old", fpOf(t, 1), "--new", newPub(t), "--keep-old", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("--dry-run exit = %d, want 1\n%s", code, errBuf.String())
		}
		if strings.Contains(out.String(), "overlap") || strings.Contains(out.String(), "new key recorded") {
			t.Errorf("--dry-run printed a finish hint:\n%s", out.String())
		}
		var prompt bytes.Buffer
		usePromptStreams(t, strings.NewReader("n\n"), &prompt)
		out.Reset()
		if code := run([]string{"rotate", "alice", "--old", fpOf(t, 1), "--new", newPub(t), "--keep-old", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("declined exit = %d, want 1", code)
		}
		if strings.Contains(out.String(), "overlap") {
			t.Errorf("a declined run printed a finish hint:\n%s", out.String())
		}
		for _, h := range hosts {
			h.install(t, []byte{1}, "this line is not a key")
		}
		out.Reset()
		errBuf.Reset()
		if code := run([]string{"rotate", "alice", "--old", fpOf(t, 1), "--new", newPub(t), "--keep-old", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("nothing-can-land exit = %d, want 1", code)
		}
		if !strings.Contains(errBuf.String(), "nothing saved — alice's new key would get no access on 2 servers;") || strings.Contains(out.String(), "overlap") {
			t.Errorf("stdout = %s\nstderr = %q", out.String(), errBuf.String())
		}
	})
}
```

(Helpers from other test files: `editFleet`, `editHost`, `qk`, `readCfg`, `fileBytes` — `revoke_test.go`; `writePub` — `rotate_test.go`; `fpOf` — `keyarg_test.go`; `writeConfig` — `audit_test.go`; `closedPort` — `adopt_test.go`; `usePromptStreams` — `apply_test.go`. `context` is used in K5.)

- [ ] **Step 2: Run — expect FAIL** (`unknown flag: --keep-old`): `GOTOOLCHAIN=go1.26.9 rtk proxy go test ./cmd/sshepherd/ -run 'TestRotateKeepOld' -count=1`

- [ ] **Step 3: Implement.**

`rotate.go` — add `keepOld bool` to the `var (…)` block; change the `Long` text's middle (the sentence gains "(unless --keep-old)"; the rest reflows):

```go
		Long: "Replaces USER's --old key with --new in the manifest, in place — the old\n" +
			"line's options (from=, command=, restrict, …) carry over; the comment is\n" +
			"the new key's, else the old line's — and pushes the swap through\n" +
			"apply's pipeline on the servers that grant USER. The old key is dead\n" +
			"fleet-wide in the same run (unless --keep-old). --old is a SHA256:\n" +
			"fingerprint, a public-key line, or a .pub path; --new is a public-key\n" +
			"line or a .pub path. Rotating the key you log in with? Pass the new\n" +
			"private key with --identity, so the lockout guard and the post-write\n" +
			"login probe can use it. Operators need --operator (the flag is kept).\n" +
			"Saves and confirms like revoke.",
```

the `planRotate` call:

```go
			ep, err := planRotate(mf, args[0], oldArg, newArg, rotateOpts{operator: f.operator, keepOld: keepOld, now: rotateNow()})
```

the flag, after `--new`:

```go
	cmd.Flags().BoolVar(&keepOld, "keep-old", false,
		"add the new key alongside the old one instead of replacing it (overlap; the new key keeps the old line's options, expiry-time included); finish later with 'sshepherd revoke --key OLD'")
```

and replace `planRotate`'s comment, signature and tail (from `line, expiry, err := rotatedLine(...)` to the `encodeEdit` call):

```go
// rotateOpts are planRotate's flags and clock.
type rotateOpts struct {
	operator bool      // --operator
	keepOld  bool      // --keep-old: add the new key after the old one
	now      time.Time // the expiry-time= check's clock
}

// planRotate resolves and applies 'rotate USER --old --new' against the
// as-loaded config: ownership, novelty, operator and expiry checks, then
// the one edit — an in-place replacement, or with --keep-old an insert
// right after the old key (an overlap; the old key stays).
func planRotate(mf *manifest.File, user string, oldArg, newArg keyArg, opts rotateOpts) (editPlan, error) {
```

(the body up to `operatorGate` is unchanged except `operatorGate(cfg, []string{user}, opts.operator)`), then:

```go
	line, expiry, err := rotatedLine(*u, oldArg, newArg, opts.now)
	if err != nil {
		return editPlan{}, err
	}
	ep := editPlan{
		former: cfg,
		summary: apply.EditSummary{Operators: ops, Edits: []apply.Edit{{
			Kind: apply.EditRotate, User: user, Fingerprint: oldArg.Fingerprint,
			NewFingerprint: newArg.Fingerprint, KeepsExpiry: expiry, KeepOld: opts.keepOld,
		}}},
	}
	if opts.keepOld {
		err = mf.AddKeyAfter(user, oldArg.Fingerprint, line)
		ep.stillHas = user + "'s new key would get no"
		ep.saveNote = "an apply from a copy without this edit removes the new key — clients that already switched would be locked out"
		ep.overlap = &overlapFinish{user: user, oldFP: oldArg.Fingerprint, operator: u.Operator}
	} else {
		err = mf.ReplaceKey(user, oldArg.Fingerprint, line)
		ep.formerNote, ep.removesKey, ep.stillHas = "rotated out", true, user+"'s old key still has"
	}
	if err != nil {
		return editPlan{}, fmt.Errorf("edit manifest: %w", err)
	}
	if ep.encoded, ep.edited, err = encodeEdit(mf); err != nil {
		return editPlan{}, err
	}
	return ep, nil
}
```

`rotatedLine` is reused unchanged: the new key keeps the old line's options **including `expiry-time=`** (decision 7) and the comment rule; a passed expiry is still refused before any edit.

`editrun.go` — `saveOnly`, after the closing brace of the `switch` and before `return nil`:

```go
	if ep.overlap != nil {
		fmt.Fprint(stdout, overlapHint(*ep.overlap, f.run.cfgPath, len(affected), f.noApply, 0))
	}
```

`finishEdit`, inside `if stage == stageConfirmed {`, after the `if ep.removesKey { printScope(…) }` block:

```go
		if ep.overlap != nil {
			fmt.Fprint(stdout, overlapHint(*ep.overlap, cfgPath, len(aff.Servers), false, len(pending)))
		}
```

Why these sites cover the spec's table exactly: `saveOnly` returns before them under `--dry-run` and on a declined prompt, and returns `doc(…)` before them under `--json`; `finishEdit` returns via `finishDoc` under `--json` and before the `stageConfirmed` block on `stageDeclined`/`stageWithheld` (nothing-can-land, save withheld) and `stagePlanned` (`--dry-run`). `pending` already counts failed/refused/unreachable/not-started servers and excludes emptied ones (none under keep-old).

`README.md` — in the `### sshepherd rotate` flag table, directly under the `--new KEY` row, add exactly:

```
| `--keep-old` | off | Add the new key alongside the old one instead of replacing it (overlap; the new key keeps the old line's options, `expiry-time` included); finish later with `sshepherd revoke --key OLD` |
```

Run `gofmt -w cmd/sshepherd/`.

- [ ] **Step 4: Run — expect PASS:** `GOTOOLCHAIN=go1.26.9 rtk proxy go test ./cmd/sshepherd/ -run 'TestRotate|TestOverlapHint|TestHelpMatchesREADMETables' -count=1` (every pre-existing rotate test unchanged: plain rotate keeps `rotated out`, the scope line and the default reminder).

### Task K5: Pins — repeat overlap, refusals, `--json`

**Files:** `cmd/sshepherd/rotate_keep_old_test.go`

- [ ] **Step 1: Write the tests** — append:

```go
// TestRotateKeepOldRepeat: during an overlap, --keep-old on the same old
// key inserts the third key right after it; a plain rotate of the old key
// replaces it in place.
func TestRotateKeepOldRepeat(t *testing.T) {
	cfg := writeConfig(t, "users:\n  - {name: bob, keys: ["+qk(t, 1)+"]}\n")
	for _, step := range []struct {
		args []string
		want []byte
	}{
		{[]string{"--new", testkeys.Line(t, 5), "--keep-old"}, []byte{1, 5}},
		{[]string{"--new", testkeys.Line(t, 6), "--keep-old"}, []byte{1, 6, 5}},
		{[]string{"--new", testkeys.Line(t, 7)}, []byte{7, 6, 5}},
	} {
		var out, errBuf bytes.Buffer
		args := append([]string{"rotate", "bob", "--old", fpOf(t, 1)}, step.args...)
		if code := run(append(args, "--no-apply", "--yes", "--config", cfg), &out, &errBuf); code != 0 {
			t.Fatalf("%v: exit = %d\n%s", step.args, code, errBuf.String())
		}
		var want []string
		for _, s := range step.want {
			want = append(want, testkeys.Line(t, s))
		}
		if got := readCfg(t, cfg).Users[0].Keys; !slices.Equal(got, want) {
			t.Errorf("%v: keys = %q, want seeds %v", step.args, got, step.want)
		}
	}
}

// TestRotateKeepOldRefusals: --keep-old changes only the edit — plain
// rotate's refusals (operator gate, novelty, passed expiry) all apply.
func TestRotateKeepOldRefusals(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	saved := rotateNow
	rotateNow = func() time.Time { return time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { rotateNow = saved })
	body := "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n  - {name: bob, keys: [" + qk(t, 2) + "]}\n" +
		"  - {name: ops, operator: true, keys: [" + qk(t, 3) + "]}\n" +
		"  - {name: old, keys: ['expiry-time=\"20200101\" " + testkeys.Line(t, 4) + "']}\n"
	newPub := writePub(t, "n.pub", testkeys.Line(t, 5))
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"operator without --operator", []string{"ops", "--old", fpOf(t, 3), "--new", newPub}, "ops is an operator (fleet-wide, protected); pass --operator to confirm"},
		{"--new already owned", []string{"alice", "--old", fpOf(t, 1), "--new", testkeys.Line(t, 2)}, "is already in the manifest (owned by bob)"},
		{"passed expiry", []string{"old", "--old", fpOf(t, 4), "--new", newPub}, `the old line's expiry-time="20200101" has passed`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := writeConfig(t, body)
			var out, errBuf bytes.Buffer
			args := append(append([]string{"rotate"}, tt.args...), "--keep-old", "--no-apply", "--yes", "--config", cfg)
			if code := run(args, &out, &errBuf); code != 3 || !strings.Contains(errBuf.String(), tt.want) {
				t.Errorf("exit = %d, stderr = %q; want 3 and %q", code, errBuf.String(), tt.want)
			}
			if !bytes.Equal(fileBytes(t, cfg), []byte(body)) {
				t.Error("a refused rotation edited the manifest")
			}
		})
	}
}

// TestRotateKeepOldJSON: keep_old true on the edit entry; the server adds
// the new key and removes nothing; the text hint never reaches stdout.
func TestRotateKeepOldJSON(t *testing.T) {
	_, kh, cfg, newKey := keepOldFleet(t)
	doc := runJSONDoc(context.Background(), t, 0, "rotate", "alice", "--old", fpOf(t, 1), "--new", newKey+".pub", "--keep-old",
		"--json", "--yes", "--config", cfg, "--known-hosts", kh)
	e := doc["edit"].(map[string]any)["edits"].([]any)[0].(map[string]any)
	if e["kind"] != "rotate" || e["keep_old"] != true {
		t.Errorf("edit entry = %v", e)
	}
	for _, s := range docServers(doc) {
		ch := s["changes"].(map[string]any)
		if len(ch["add"].([]any)) != 1 || len(ch["remove"].([]any)) != 0 || s["outcome"] != "applied" {
			t.Errorf("%v: changes = %v", s["name"], ch)
		}
	}
}
```

(`runJSONDoc` → `oneJSONDoc` already fails the test if anything but one JSON value reaches stdout, which pins "no hint under `--json`".)

- [ ] **Step 2: Run — expect PASS:** `GOTOOLCHAIN=go1.26.9 rtk proxy go test ./cmd/sshepherd/ -run 'TestRotateKeepOld' -count=1 -v`. A failure names a real gap: fix the code, not the test, and report it.

### Task K6: Stage gates

- [ ] `GOTOOLCHAIN=go1.26.9 rtk proxy go test -race -count=1 ./...` — PASS.
- [ ] `gofmt -l cmd internal` / `goimports -l cmd internal` — nothing.
- [ ] `GOTOOLCHAIN=go1.26.9 golangci-lint run ./...` — no issues.
- [ ] `GOTOOLCHAIN=go1.26.9 deadcode ./cmd/sshepherd` — nothing.
- [ ] Hand back (no commit).

---

## Integrator

### Task I1: Full gates

- [ ] `GOTOOLCHAIN=go1.26.9 make check` — PASS (tidy, fmt, vet, lint, deadcode, gosec, govulncheck, gitleaks, coverage ≥ 80%).
- [ ] `git status` lists only files named in this plan (plus this plan file itself).

### Task I2: Integration + E2E

**Files:** `scripts/integration.sh`, `cmd/sshepherd/e2e_test.go`

The E2E additions need three fresh container accounts (seeded with the agent key alone) so they cannot disturb the existing loops.

- [ ] **Step 1: `scripts/integration.sh`** — append ` trima trimb overlap` to **both** `for u in writer virgin sym e2e … rotatecmd; do` lists (the `adduser` loop and the `chown`/`chmod` loop), and seed them with the agent key by extending the existing loop and its comment:

```sh
    # cas/locked/verifyfail/drop/lockout: the agent key alone (write-path
    # refusal and failure cases); trima/trimb/overlap: the agent key alone
    # (revoke --server and rotate --keep-old E2E); unparse: plus a line
    # apply cannot parse.
    for u in cas locked verifyfail drop lockout trima trimb overlap; do
      cp /seed/key.pub "/home/$u/.ssh/authorized_keys"
    done
```

- [ ] **Step 2: append to `cmd/sshepherd/e2e_test.go`** (imports already present: `filepath`, `strings`, `testing`):

```go
// TestE2ERevokeServer: tmp is granted trim-a and trim-b; revoke tmp
// --server trim-a removes the key from trim-a only (trim-b is never
// contacted), the manifest keeps tmp with trim-b, and audit is clean.
func TestE2ERevokeServer(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	stale := itPubLine(t, itKeys(t), "stale")
	m := writeE2EManifest(t, t.TempDir(), "trim.yaml", `
users:
  - {name: op, operator: true, keys: ["`+pub+`"]}
  - {name: tmp, keys: ["`+stale+`"]}
servers:
  - {name: trim-a, host: `+host+`, port: `+port+`, user: trima}
  - {name: trim-b, host: `+host+`, port: `+port+`, user: trimb}
access:
  - {user: tmp, servers: [trim-a, trim-b]}
`)
	if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("apply exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	code, out, stderr := runBin(t, bin, "revoke", "tmp", "--server", "trim-a", "--yes", "--config", m, "--known-hosts", kh)
	if code != 0 {
		t.Fatalf("revoke --server exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	for _, want := range []string{"manifest edit: remove tmp's access to trim-a (1 access entry changed) — 1 server affected", "trim-a: applied · verified"} {
		if !strings.Contains(out, want) {
			t.Errorf("revoke output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "trim-b:") {
		t.Errorf("trim-b was contacted:\n%s", out)
	}
	blob := strings.Fields(stale)[1]
	if got := e2eRemoteCat(t, host, port, kh, "trima"); strings.Contains(got, blob) {
		t.Errorf("trim-a still holds tmp's key:\n%s", got)
	}
	if got := e2eRemoteCat(t, host, port, kh, "trimb"); !strings.Contains(got, blob) {
		t.Errorf("trim-b lost tmp's key:\n%s", got)
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("audit exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}
}

// TestE2ERotateKeepOld: rotate --keep-old installs the new key beside the
// old one (audit clean with both), and the printed finish — revoke --key
// OLD — leaves only the new key (audit clean again).
func TestE2ERotateKeepOld(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	keys := itKeys(t)
	stale, ciOld := itPubLine(t, keys, "stale"), itPubLine(t, keys, "ci_old")
	m := writeE2EManifest(t, t.TempDir(), "overlap.yaml", `
users:
  - {name: op, operator: true, keys: ["`+pub+`"]}
  - {name: deploy, keys: ["`+stale+`"]}
servers:
  - {name: ov, host: `+host+`, port: `+port+`, user: overlap}
access:
  - {user: deploy, servers: [ov]}
`)
	if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("apply exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	code, out, stderr := runBin(t, bin, "rotate", "deploy", "--old", filepath.Join(keys, "stale.pub"), "--new", filepath.Join(keys, "ci_old.pub"),
		"--keep-old", "--yes", "--config", m, "--known-hosts", kh)
	if code != 0 {
		t.Fatalf("rotate --keep-old exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	const lead = "overlap started — every affected server accepts both keys; once every client uses the new key, finish with: "
	_, finish, ok := strings.Cut(out, lead)
	if !ok || !strings.Contains(out, "(keeps the old key)") {
		t.Fatalf("rotate output lacks the keep-old header or the finish hint:\n%s", out)
	}
	finish, _, _ = strings.Cut(finish, "\n")
	got := e2eRemoteCat(t, host, port, kh, "overlap")
	if !strings.Contains(got, strings.Fields(stale)[1]) || !strings.Contains(got, strings.Fields(ciOld)[1]) {
		t.Errorf("overlap must hold both keys:\n%s", got)
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("audit during the overlap exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}
	args := strings.Fields(finish)
	if len(args) < 4 || args[0] != "sshepherd" || args[1] != "revoke" || args[2] != "--key" {
		t.Fatalf("finish = %q, want a sshepherd revoke --key command", finish)
	}
	if code, out, stderr := runBin(t, bin, append(args[1:], "--yes", "--known-hosts", kh)...); code != 0 {
		t.Fatalf("finish exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	got = e2eRemoteCat(t, host, port, kh, "overlap")
	if strings.Contains(got, strings.Fields(stale)[1]) || !strings.Contains(got, strings.Fields(ciOld)[1]) {
		t.Errorf("after the finish, overlap must hold only the new key:\n%s", got)
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("audit after the finish exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}
}
```

(`itE2E`, `runBin`, `writeE2EManifest`, `e2eRemoteCat` — `e2e_test.go`; `itKeys`, `itPubLine` — `identity_integration_test.go`. The rotation runs authenticated with the agent's operator key, which stays desired, so the lockout guard is satisfied without `--identity`.)

- [ ] **Step 3:** `GOTOOLCHAIN=go1.26.9 go vet -tags integration ./cmd/sshepherd/` — clean; then `GOTOOLCHAIN=go1.26.9 make integration` — PASS, including `TestE2ERevokeServer` and `TestE2ERotateKeepOld`.

### Task I3: README, CLAUDE.md, spec status

Samples must be **real**: header lines are copied byte-for-byte from the goldens named; the finish-hint sample is copied from actual command output (Step 2). Never hand-write or tidy them.

- [ ] **Step 1: README `### sshepherd revoke`.**
  - Console block at the top: add `$ sshepherd revoke bob --server db-1                 # bob loses db-1 only; his keys and other grants stay` (align the `#` with the existing lines).
  - After the "**Users or keys, not both.**" paragraph, add a paragraph:

    **One server, not the whole user (`--server`).** `revoke USER... --server NAME...` takes the named servers away from each user and changes nothing else — the user entry, its keys and its other grants stay. (Unlike `apply --server`, which only restricts which servers a run touches, `revoke --server` edits the grants.) An explicit `servers:` list loses every occurrence of the server, and an entry left empty is deleted (its comment moves on, as for a removed user). A wildcard grant (`servers: ["*"]`) gets the server appended to `except:` — created right after `servers:` when absent — so it keeps covering servers added later; a wildcard that would then cover no current server is deleted, with a warning that later servers are no longer granted automatically. Refused with exit `3` and nothing edited: `--server` with `--key` (access is per user), with `--operator`, or on an operator user (operators have every server by definition), `--server '*'` (use `revoke USER`), an unknown server, and any user × server pair the user has no access to — every problem is listed in one message. Only the trimmed servers are contacted, there is no `scope:` line, and the save reminder ends `re-grants the removed access`.

    followed by two console blocks copied verbatim from `internal/apply/testdata/edit_header_access.golden` and `internal/apply/testdata/edit_header_access_multi.golden`.
  - JSON paragraph: change "fields by `kind`: `remove-user`, `remove-key`, `rotate`" to "fields by `kind`: `remove-user`, `remove-key`, `rotate` (with `keep_old`), `remove-access` (`access_servers`, `entries_changed`, `entries_removed`, `servers_excepted`, `wildcards_removed`, `no_grants_left`)".
  - Add a recipe after "Recipe: a lost laptop":

    ```console
    $ sshepherd revoke bob --server db-1 --dry-run
    $ sshepherd revoke bob --server db-1
    $ git commit -am "bob: no more db-1" && git push
    ```
    headed **Recipe: take one server away.**

- [ ] **Step 2: README `### sshepherd rotate`.**
  - Intro sentence: "…the old key is dead fleet-wide in the same run — unless `--keep-old` (below)."
  - Change the bullet "Confirmation, saving, `--dry-run`, `--no-apply`, operators and the scope line work exactly as for `revoke`." to end "…as for `revoke` (no scope line under `--keep-old`: nothing is removed)."
  - JSON bullet: add "and `keep_old` (always present on `rotate` entries; `false` for a plain rotation)".
  - Add a paragraph **Overlap (`--keep-old`).** — "For a key held by running systems (CI deploy keys, automation) that cannot all switch at once: the new key is added right after the old one instead of replacing it. It carries the old line's options, `expiry-time=` included (a passed one is refused, as for a plain rotation), and the header says `keeps the old key`. Nothing marks the overlap: the manifest simply lists both keys, `audit` sees both as granted and `apply` keeps both — so the save reminder warns that an apply from a copy without the edit removes the new key. The run ends (text mode only; never under `--json` or `--dry-run`, nor when nothing was saved) with the exact command that finishes the overlap once every client uses the new key — `sshepherd revoke --key OLD`, plus `--config` when not the default and `--operator` for an operator, whose hint gets a second line about `--identity`. It reads `overlap started — …` when every affected server holds both keys, `overlap incomplete — N servers do not have the new key yet …` after a partial run, `overlap recorded, not pushed — …` under `--no-apply`, and `new key recorded — USER has no grants yet …` when no server is affected. `--keep-old` again on the same old key adds another key; a plain `--old OLD` during an overlap replaces the old key."
  - Under it, a console block copied from `internal/apply/testdata/edit_header_keep_old_expiry.golden`, and a console block of real `--no-apply` output produced like this (run from a scratch directory so `--config` is the default and does not appear):

    ```sh
    go build -o /tmp/sshepherd ./cmd/sshepherd
    d=$(mktemp -d) && cd "$d"
    cat > sshepherd.yaml <<'EOF'
    users:
      - {name: deploy, keys: ['expiry-time="20270101" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58 deploy@ci']}
    servers:
      - {name: web-1, host: 10.0.0.1, user: deploy}
      - {name: web-2, host: 10.0.0.2, user: deploy}
    access:
      - {user: deploy, servers: [web-1, web-2]}
    EOF
    echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG56HN0psLeP0Tr0xVmP7/TvKpcWbjym8uT7/M2AUFvx' > deploy_2027.pub
    /tmp/sshepherd rotate deploy --old SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o --new deploy_2027.pub --keep-old --no-apply --yes 2>/dev/null
    ```

    Its stdout (paste what you get; it should be these four lines):

    ```console
    manifest edit: rotate deploy key SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o → SHA256:LA4QoSmstGCy/UHfdU3jKjnPz56pQzud9OmslMh3g8w (keeps the old key; keeps expiry-time="20270101") — 2 servers affected
    manifest sshepherd.yaml updated — commit and push it: an apply from a copy without this edit removes the new key — clients that already switched would be locked out
    no servers contacted — 2 affected servers still carry the old keys; run 'sshepherd apply --server web-1 --server web-2' to push
    overlap recorded, not pushed — run the apply hint above, then, once every client uses the new key, finish with: sshepherd revoke --key SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o
    ```
  - Recipe **Recipe: overlap a deploy key.**

    ```console
    $ ssh-keygen -t ed25519 -f ~/.ssh/deploy_2027
    $ sshepherd rotate deploy --old SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o --new ~/.ssh/deploy_2027.pub --keep-old
    $ git commit -am "deploy key: start the 2027 overlap" && git push
    $ # … switch every client to ~/.ssh/deploy_2027 …
    $ sshepherd revoke --key SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o
    $ git commit -am "deploy key: end the overlap" && git push
    ```

- [ ] **Step 3: README Status table** — the `revoke` / `rotate` row: "Comment-preserving manifest edit + `apply` over the affected servers: offboard a user, take away one server (`--server`), drop a lost key, swap a key in place or overlap old and new (`--keep-old`) (text + `--json`)".

- [ ] **Step 4: `CLAUDE.md` Status** — append one paragraph at the end:

  "**`revoke --server` and `rotate --keep-old`** (specced in `docs/superpowers/specs/2026-11-07-revoke-server-keep-old-design.md`, planned in `docs/superpowers/plans/2026-11-07-revoke-server-keep-old.md`): `revoke USER... --server NAME...` trims per-server access through the new comment-preserving `manifest.RemoveAccess` (explicit items removed, wildcards gain `except:`, emptied entries and wildcards left covering no server deleted with a warning; operators, `--key`, `'*'`, unknown servers and ungranted pairs refused, all problems listed at once), and `rotate --keep-old` overlaps the old and new keys via `manifest.AddKeyAfter` (options and `expiry-time=` carried) and prints the `revoke --key OLD` that finishes the overlap. The save reminder's tail is per edit kind; JSON gains the `remove-access` edit kind and `keep_old` on rotate entries (schema stays 1). The E2E suite adds a `revoke --server` run and a keep-old overlap → finish loop."

- [ ] **Step 5: Spec Status** — in `docs/superpowers/specs/2026-11-07-revoke-server-keep-old-design.md`, change the Status line to `- **Status:** Implemented (plan: docs/superpowers/plans/2026-11-07-revoke-server-keep-old.md)`.

- [ ] **Step 6:** `GOTOOLCHAIN=go1.26.9 go test ./cmd/sshepherd/ -run TestHelpMatchesREADMETables -count=1` — PASS; then diff each README sample against its golden (`grep -F -f` or by eye) — byte-identical.

### Task I4: Commit

- [ ] `git status` — review: only the files listed in this plan (including this plan file). Then:

```bash
git add -A
git commit -m "feat: revoke --server and rotate --keep-old

revoke USER... --server NAME... takes servers away from users without
touching the users or their keys: explicit lists lose every occurrence,
wildcards gain except: (created in the entry's style), emptied entries
and wildcards left covering no server are deleted with a warning.
Operators, --key, --operator, '*', unknown servers and ungranted pairs
are refused before any edit, every problem listed at once.

rotate --keep-old adds the new key right after the old one (options and
expiry-time carried) and prints the revoke --key OLD that finishes the
overlap. New manifest edits RemoveAccess and AddKeyAfter; per-kind save
reminder; JSON gains remove-access and keep_old (schema 1). E2E covers
both.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Verifier (independent) and repair pass

The verifier gets the spec, this plan and the commit — not the agents' hand-backs. It checks:
1. Every decision row (1–8) and every refusal message of the spec, character for character, against the code and a test that pins it.
2. Usage-refusal precedence (spec order 1→4, first match wins, before the manifest is read) and that the `--server` path never calls `operatorGate`.
3. `RemoveAccess` semantics: every occurrence removed; emptied entry deleted with head comment rescued (next entry / section footer); `except:` created right after `servers:` in the same flow/block style; a wildcard left covering nothing deleted and counted in `WildcardsRemoved`; already-excepted servers never appended twice; every output re-parses.
4. Header wording and notes byte-exact (`edit_header_access*.golden`, `edit_header_keep_old*.golden`); count fragments pluralized and omitted when zero.
5. `editPlan` per path: trim — `removesKey` false, `stillHas` "USER still has", trim `saveNote`; keep-old — `removesKey` false, `stillHas` "USER's new key would get no", keep-old `saveNote`, `overlap` set; plain revoke/rotate unchanged.
6. Every finish-hint row and the operator line; none under `--json`, `--dry-run`, declined, nothing-can-land, save-withheld.
7. JSON presence rules: `remove-access` fields always present for that kind (`access_servers` `[]`-safe) and absent elsewhere; `keep_old` present on every rotate entry, absent elsewhere; schema stays 1.
8. README: `--server`/`--keep-old` rows match `--help`; samples byte-identical to their goldens / real output; the `apply --server` vs `revoke --server` sentence present; Status table and `CLAUDE.md` agree.
9. `make check` and `make integration` green.

Findings go to a repair pass that fixes only confirmed findings, re-runs the gates and amends nothing — it commits a follow-up `fix:` commit (same `Co-Authored-By` trailer).

---

## Spec resolutions (where the spec left a choice; this plan's answer)

1. **Count fragments when `EntriesChanged` is 0.** The noun "access entry/entries" attaches to the first fragment present (`(1 access entry removed)`); with every count zero the parenthesis is omitted.
2. **A wildcard deleted under decision 1b** counts in `EntriesRemoved` and `WildcardsRemoved` only — not `EntriesChanged`, not `ServersExcepted`.
3. **Wildcard-removed warning** is printed once per user's edit when `WildcardsRemoved > 0` (two deleted wildcards of one user would print identical lines).
4. **"N servers do not have"** is pluralized: `1 server does not have …`.
5. **Zero affected under `--no-apply`** prints the "new key recorded" row (after `no servers contacted — no server's desired keys changed`), since there is no apply hint above to point at.
6. **README flag cell** is `` `--server` `` (no varname): the spec's help text has no backticks, matching `apply --server`; the `Use` line says `NAME`.
7. **Removed block-list items** take their head and line comments with them (as `RemoveKey`); removed **entries** rescue their head comment (as `RemoveUser`).
8. **Post-load problems** are joined with `"; "` (as `planRevokeKeys`' missing-key list); unknown users keep the existing `unknown user(s): …` wording as the first problem.
9. **`except:` present but null** is rebuilt in place as a sequence in the `servers:` style.
10. **`RemoveAccess` errors** on an unknown user or server (defensive; the command refuses both before calling it).
11. **E2E accounts:** the spec names only `e2e_test.go`, but isolated E2E runs need three new container accounts (`trima`, `trimb`, `overlap`) in `scripts/integration.sh`.
12. **`planRotate` signature** takes a `rotateOpts` struct (`operator`, `keepOld`, `now`) instead of a seventh positional parameter.

---

## Spec coverage

| Spec section | Tasks |
|---|---|
| Decisions 1, 1b (wildcard → `except:`; covering nothing → delete + warn) | M2, R1, R5 (wildcard), V3 |
| Decision 2 (explicit list, every occurrence, emptied entry deleted) | M1, R5 (sole grantee) |
| Decision 3 (operators refused; `--operator` + `--server` usage error) | R3, R4 |
| Decision 4 (strict not-granted pairs, all listed) | R4 |
| Decision 5 (keep-old adds after old; finish printed) | M4, K4, K5, I2 |
| Decision 6 (no overlap state) | K4 (manifest lists both keys), K5 (repeat) |
| Decision 7 (expiry carried; help says so) | K4 (`TestRotateKeepOldExpiryNoGrants`, flag help) |
| Decision 8 (sequential workflow) | Execution model |
| Command surface (help text, USER-only, dedup, `Use`, `Long`) | R3, R5 (dedup) |
| Usage refusals + precedence | R3 |
| Post-load refusals, listed together, no `operatorGate` | R4 |
| `RemoveAccess` incl. duplicates, flow/block `except:`, `WildcardsRemoved`, `AccessRemoval` | M1, M2, M3 |
| What runs (affected = named servers; sole-grantee warning; editPlan fields) | R4, R5 |
| Header line + notes (wildcard warning, no-access-left) | R1, R5 |
| keep-old rules identical to rotate | K5 (`TestRotateKeepOldRefusals`) |
| `AddKeyAfter` via `rotatedLine` | M4, K4 |
| keep-old what runs (full render, guard, K1 survives) + editPlan fields + header | K1, K4 |
| Finish hint table (all rows, operator line, text only) | K3, K4, K5 |
| Overlap lifecycle (audit both, finish via `revoke --key`, repeat) | K4 (lifecycle), K5 (repeat), I2 |
| Save reminder per edit kind | R4, K4 (default pinned by existing revoke/rotate tests) |
| `apply.Edit` / JSON fields + presence rules | R2, K2, R5, K5 |
| Errors / exit codes (no new codes; all refusals exit 3, nothing edited) | R3, R4, K5 |
| Testing — manifest unit + golden | M1–M4 |
| Testing — `internal/apply` header + JSON goldens | R1, R2, K1, K2 |
| Testing — `cmd/sshepherd` hermetic | R3–R5, K3–K5 |
| Testing — integration / E2E | I2 |
| README rows (stage agents) and rest (integrator) | R3, K4, I3 |
| CLAUDE.md Status | I3 |

## Placeholder self-scan

Checked before hand-off: no to-be-decided or deferred-work markers, no "same as an earlier task" cross-references in place of code, no test-less "write tests" steps, and no "implement as appropriate" anywhere in this plan. Every test step carries its Go code; every implement step carries its Go code or an exact text edit; every run step carries its command and expected result; every golden carries its expected bytes. The one interim construct — the `_` for `trim` in R3 — is named and removed in R4.

# `import --json` and `adopt --json` (P10 S8, owner rule) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This plan is executed by the wave runner of `docs/superpowers/plans/2026-11-07-review-remediation.md` ("Reusable workflow skeleton"): lane agents work in git worktrees, never commit, and hand back ownership-filtered patches; the integrator commits once per lane. Where a task says "Hand back", that is the lane's last step, not a commit.

**Commits at:** `docs/superpowers/plans/2026-11-09-p10-s8-import-adopt-json.md`

**Goal:** Build slice S8 of the approved access-model design (`docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`, section "S8. `import --json` and `adopt --json` (owner rule)", answer OP3 = (1)): both commands take `--json`, write one schema-1 discovery and warnings report on stdout, put the manifest where `-o` says or into the report's `manifest` field, and change nothing else.

**Architecture:** `adopt.Plan.Warnings` and `reconcile.Plan.Warnings` become structured (`Warning{Kind, …, Message}`); stderr still prints `Message`, so text output and every existing golden stay byte-identical. Adopt's renderer is the new `internal/adopt/json.go` (no CLI framework); import's is the new `cmd/sshepherd/import_json.go`, because import's run lives in cmd, and it also holds the one warning collector that assigns kinds to import's string warnings. Both command bodies move out of `RunE` into a run struct (`adoptRun`, `importRun`, as `validation` does), because the added branches would otherwise break gocyclo 15.

**Tech Stack:** Go 1.27.3 (`GOTOOLCHAIN=go1.27.3`, the Makefile's `GO_PIN`), Cobra, `encoding/json`, the hermetic `internal/sshconn/sshtest` server through `editFleet`, goleak, golden files (`-update`), golangci-lint (depguard layering, gocyclo 15, wrapcheck, errorlint, revive), `deadcode ./cmd/sshepherd`.

**Base:** `master` at `ce9efcd`, after S1 and S2. Every `file:line` below was read there. The flags are `import --operator-key` and `revoke --from-server`. S8 runs alone as its own wave, before any schema slice.

**Not compiled.** This plan was drafted read-only: the code below was read against `ce9efcd` and its Go blocks were syntax-checked with `gofmt`, but it was never built or run, and no test here has been seen to pass. A lane that finds a build error fixes it to the text's intent and says so in its hand-back.

---

## Design gaps filled here (for the main session)

None of these overrides an answered decision, and no owner answer is needed before the wave runs. Task 12 Step 2 records each in the design. The main session can veto any of them.

1. **Three warning kinds the design does not list.** The design's kind list predates P09 and misses warnings that exist today. Dropping them from `warnings` would make `summary.warnings` disagree with stderr. Consumers already must ignore unknown kinds.
   - adopt `weak_key_skipped` (`skipKey`, `internal/adopt/adopt.go:158`, landed in P09).
   - import `wildcard_grant` (`generateManifest` note at `cmd/sshepherd/import.go:126` and `reconcile.go:340`).
   - import `revocation_memory_dropped` (`warnMemoryLost`, `import.go:26`).
2. **`reconcile.Warning` carries `Identity`, which the design's `Warning{Kind, Server, Fingerprint, User, Date, Message}` omits.** The design says the two revoked kinds use "shapes from P04", and P04's shape (`2026-11-08-revocation-memory-design.md:654-658`) has `identity`. The P04 shape wins. `adopt.Warning` keeps the design's six fields.
3. **`internal/sshcfg` is not edited.** The design lists it, but `sshcfg.Load` already returns its warnings (`sshcfg.go:106`).
4. **`unreadable` holds transport failures only, and `line_issues` is new.** The design's test says `` `unreadable[]` carries `error_kind` ``, and its sample (12 servers, 11 read, 1 partly read) has exactly one row, so a partly read server has no row there. `Plan.Issues` also holds line-level issues on a server that was read (`adopt.go:79,99,128`), and these have no transport error. So `unreadable` holds only issues with an `Issue.Kind`, always with `error_kind` (`fleet.ErrorKindOf` returns `ErrorKindUnknown`, never `""`, for a non-nil error: `internal/fleet/errors.go:83`). Line-level issues go to `line_issues: [{server, detail}]`, an additive, always-present list the design does not name, and `summary.partly_read` still counts those servers.
5. **`jq -r .manifest` is not byte-identical; `jq -j` is.** `jq -r` appends a newline (`printf '{"m":"a\\n"}' | jq -r .m | od -c` shows `a \n \n`). The design's claim at line 440 is a real defect, so the README and the verifier use `jq -j .manifest`, and Task 12 Step 2 corrects line 440.
6. **The helpers receive the collector.** The design says the functions "return their warnings to one collector". Plan decision 11 passes `*importWarnings` into `dropUnsafeHosts`, `deriveUsers`, `collapseTargets`, `warnProxies` and `warnMemoryLost` instead, so each message logs at today's point relative to the `log.Info` lines. Task 12 Step 2 records it.

## How this plan is cut (read first)

### Why the lanes look the way they do

1. **Two rounds, not two parallel lanes.** The design's lane row is A `internal/adopt`, `adopt.go` and B `import_json.go`, `import.go`, `internal/reconcile`, `internal/sshcfg`. Both commands need the same "where did the manifest go" helper, so `manifest_out.go` belongs to one lane. Round 1 (`adopt`) produces `adopt.Output`, `adopt.Placement` and `placeManifest`; round 2 (`import`) consumes them and must compile on round 1 alone.
2. **`deadcode ./cmd/sshepherd` is part of `make check`.** `placeManifest` and `adopt.WriteJSON` land with their caller in `adoptRun`. Everything in `import_json.go` lands with `importRun`. `emitManifest` stays: both commands use it on the non-JSON path. Constants, types and struct fields are exempt.
3. **`TestHelpMatchesREADMETables` reads `README.md`.** Each lane adds a flag row. Each lane applies its own `docsDelta` to its worktree's `README.md` before `make check`; the ownership filter drops that change from the patch, and **the integrator re-applies the `docsDelta` after the patch and before `make check`**.
4. **gocyclo 15 counts function literals toward the enclosing function.** `newAdoptCmd` and `newImportCmd` are close to the limit with their `RunE` literals, so the bodies move out first (Tasks 5 and 8).

### Rounds

| Round | Lane (disjoint files) | Builds on |
|---|---|---|
| 1 | `adopt`: `internal/adopt`, `adopt.go`, `manifest_out.go`, adopt's JSON tests and help golden | `ce9efcd` |
| 2 | `import`: `internal/reconcile`, `import.go`, `import_json.go`, import's JSON tests and help golden | round 1 |

After round 2 the integrator runs Task 12 and an independent verifier runs Task 13. No lane owns either.

### Plan decisions (not in the design; none changes an exit code or a manifest byte)

1. **The list fields are always present, `[]` when empty** (`new_users`, `extensions`, `unreadable`, `line_issues`, `warnings`, `new_servers`, `notes`), following validate's `errors`. These are new documents, so the design's "omitted when empty" rule, which protects existing goldens, does not apply, and `jq '.warnings[]'` must not fail on null. `output` and `manifest` are omitted when absent, as the design says.
2. **`mode` for a non-merge adopt is `generate`**, the word the design gives import.
3. **`import` has no `emitted` field.** The design lists import's fields without it, and import writes a document only when it emitted a manifest.
4. **`import` keeps `schema` and `command`**, by analogy with adopt's example.
5. **`output.written` is `false` only for an in-place update whose bytes are identical** (`publishManifest`'s `bytes.Equal` branch, `manifest_out.go:41`).
6. **`import`'s `summary` describes what the ssh config yielded:** `hosts` is the count `sshcfg.Load` returned (the `parsed N hosts` line), `users` the identity users after target collapse (0 under `--servers-only`), `grants` the sum of those users' server lists with operators excluded. `new_servers`, `new_users` and `extensions` list what the output adds.
7. **`new_servers[].port` is the effective port**, so a default is `22`, not `0`.
8. **`import`'s `new_users` rows are `{name, fingerprint, type, operator?, servers}`.** The design names the list but not the row. `servers` is the user's granted list as written (`["*"]` when compacted), `[]` for an operator.
9. **Reconcile's kinds follow one rule.** Each warning that counts toward a conflict or comes from the manifest-wins identity rules is `merge_conflict`, including an alias whose target is already a manifest server (`reconcile.go:157`). `collapsed_target` is only `CollapseTargets`' own output, among freshly converted hosts. The two tombstone sites keep their P04 kinds, and the wildcard site is `wildcard_grant`.
10. **A host with no `User` is `ssh_config`**, in both modes. It is a fact about the ssh config.
11. **The collector is passed in rather than returned to.** Design gap 6: the design says the functions "return their warnings to one collector". `dropUnsafeHosts`, `deriveUsers`, `collapseTargets`, `warnProxies` and `warnMemoryLost` take `*importWarnings` in place of the logger, so each message prints at exactly today's point relative to the `log.Info` lines.
12. **A manifest's own load warnings stay stderr-only** (`logManifest`, `fleet.go:137`). The design gives these documents no `manifest_warnings`.
13. **The `manifest` field is not sanitized.** `jq -j .manifest` must give the same bytes as a plain run. Every free-text field that neither `config.Parse` nor a parser has already validated goes through `sanitize.Remote`: warnings (`server`, `identity`, `user`, `date`, `message`), `notes`, and the text of `unreadable` and `line_issues`, including import's, as validate does for its own warnings. Exempt, because validated or not remote: `new_users[].name` (`RenderTextIssue` at load and in the self-check, or adopt's ASCII `sanitizeName`), `.type` and `.fingerprint` (parser output), `found_on`, `extensions[]` and `new_servers[]` (`ServerFieldIssue`/`RenderTextIssue` at load or in the self-check), warning fingerprints (parser output) and `output.path` (the operator's own `-o` argument).

### Conventions every lane follows

- Go runs under the pin: prefix every `go` command with `GOTOOLCHAIN=go1.27.3`. The rtk hook summarizes test output; use `rtk proxy go test …` when exact failure lines matter.
- A golden is rewritten only with `-update` and then read back line by line before it is accepted.
- **Failing first.** Every test is run and seen failing (build failure or assertion) before the code it tests exists.
- **gocyclo 15 is a production-code gate;** never `//nolint:gocyclo`.
- **New test variables must not shadow builtins** (revive): no `new`, `len`, `max`, `min`, `copy`, `cap`.
- **Before hand-back:** apply this lane's `docsDelta` to the worktree's `README.md` (gate only), run `make check` (and `make integration` under the runner's lock when the lane says `needsIntegration`), then `git add -A`, unstage every path outside the lane's globs (`README.md` and `CLAUDE.md` always), and write the patch. **Do not list `README.md` in `foreignBreaks`.**
- **`docsDelta`** blocks are integrator-only text for `README.md`, `CLAUDE.md` Status and spec Status. Each `<copy …>` is replaced with the named regenerated golden, verbatim: CLAUDE.md requires README samples to be real. In a lane's gate-only copy the placeholder may stay.

---

## File structure

| File | Round/lane | Responsibility |
|---|---|---|
| `internal/adopt/adopt.go`, `adopt_test.go` | 1 `adopt` | `Warning` and its kinds, `NewUser.Fingerprint`/`Type`, `Issue.Kind` |
| `internal/adopt/json.go` (new), `json_test.go` (new), `testdata/json_*.golden.json` (new) | 1 `adopt` | `Report`, `Output`, `Placement`, `WriteJSON` |
| `cmd/sshepherd/manifest_out.go`, `manifest_out_test.go` | 1 `adopt` | `publishManifest` reports `written`; `placeManifest` |
| `cmd/sshepherd/adopt.go`, `adopt_json_test.go` (new), `testdata/help/adopt.golden` | 1 `adopt` | `adoptOpts`, `adoptRun`, `--json` |
| `internal/reconcile/reconcile.go`, `reconcile_test.go` | 2 `import` | `Warning` and its kinds |
| `cmd/sshepherd/import.go`, `import_test.go`, `testdata/help/import.golden` | 2 `import` | `importOpts`, `importRun`, collector-fed helpers, `--json` |
| `cmd/sshepherd/import_json.go` (new), `import_json_test.go` (new), `testdata/import_json_*.golden.json` (new) | 2 `import` | `importWarnings`, kinds, `importDoc`, the two outcome builders, `writeImportDoc` |

---

## Round 1 — lane `adopt` (Tasks 1–6)

### Task 1: structured adopt warnings

**Files:**
- Modify: `internal/adopt/adopt.go:48-55,87-90,103-107,114-119,134-143,151-187`
- Test: `internal/adopt/adopt_test.go`

- [ ] **Step 1: Migrate the existing assertions to `.Message`.**

Run:

```bash
perl -pi -e 's/slices\.Contains\(p\.Warnings, want\)/slices.ContainsFunc(p.Warnings, func(w Warning) bool { return w.Message == want })/; s/p\.Warnings\[0\]/p.Warnings[0].Message/g; s/strings\.Contains\(w, "wildcard"\)/strings.Contains(w.Message, "wildcard")/' internal/adopt/adopt_test.go
```

- [ ] **Step 2: Write the failing test.** Append to `internal/adopt/adopt_test.go`:

```go
// keyFP is line's SHA256 fingerprint.
func keyFP(t *testing.T, line string) string {
	t.Helper()
	k, err := authkeys.ParseLine(line)
	if err != nil || k == nil {
		t.Fatalf("keyFP: %v", err)
	}
	return k.Fingerprint
}

// TestBuildWarningKinds pins each warning's kind and structured fields. The
// messages are the stderr text and stay pinned by the tests above.
func TestBuildWarningKinds(t *testing.T) {
	k4, k7, dsa := testkeys.Line(t, 4), testkeys.Line(t, 7), testkeys.DSALine(t, 7)
	fp4, fp7, fpDSA := keyFP(t, k4), keyFP(t, k7), keyFP(t, dsa)
	oneServer := "servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n"
	twoServers := "servers:\n  - {name: db-1, host: 10.0.0.3, user: deploy}\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n"
	bob := "users:\n  - {name: bob, keys: [\"" + k4 + "\"]}\n"
	for _, tt := range []struct {
		name    string
		cfg     string
		found   map[string]string
		message string
		want    Warning
	}{
		{
			name:    "revoked key",
			cfg:     oneServer + "revoked:\n  - {fingerprint: " + fp7 + ", user: old, date: 2026-11-08}\n",
			found:   map[string]string{"web-1": k7},
			message: "REVOKED",
			want:    Warning{Kind: WarnRevokedKeySkipped, Server: "web-1", Fingerprint: fp7, User: "old", Date: "2026-11-08"},
		},
		{
			name:    "weak key",
			cfg:     oneServer,
			found:   map[string]string{"web-1": dsa},
			message: "key not adopted",
			want:    Warning{Kind: WarnWeakKeySkipped, Server: "web-1", Fingerprint: fpDSA},
		},
		{
			name:    "except carve-out",
			cfg:     bob + twoServers + "access:\n  - {user: bob, servers: [\"*\"], except: [db-1]}\n",
			found:   map[string]string{"db-1": k4},
			message: "except: list",
			want:    Warning{Kind: WarnExceptSkipped, Server: "db-1", Fingerprint: fp4, User: "bob"},
		},
		{
			name: "revoked access",
			cfg: bob + twoServers + "access:\n  - {user: bob, servers: [web-1]}\n" +
				"revoked:\n  - {user: bob, servers: [db-1], date: 2026-11-08}\n",
			found:   map[string]string{"db-1": k4},
			message: "access was revoked",
			want:    Warning{Kind: WarnRevokedAccessSkipped, Server: "db-1", Fingerprint: fp4, User: "bob", Date: "2026-11-08"},
		},
		{
			name:    "copies differ",
			cfg:     "servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: web-2, host: 10.0.0.2, user: deploy}\n",
			found:   map[string]string{"web-1": k7, "web-2": "no-pty " + k7},
			message: "differs",
			want:    Warning{Kind: WarnKeyDiffers, Server: "web-2", Fingerprint: fp7},
		},
		{
			name:    "comment dropped",
			cfg:     oneServer,
			found:   map[string]string{"web-1": k7 + " alice\tlaptop"},
			message: "adopted without its comment",
			want:    Warning{Kind: WarnCommentDropped, Server: "web-1", Fingerprint: fp7},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := parseConfig(t, tt.cfg)
			read := make(map[string]fleet.ReadResult, len(tt.found))
			for server, line := range tt.found {
				read[server] = fleet.ReadResult{Content: []byte(line + "\n")}
			}
			p := Build(cfg, runAudit(t, cfg, &fakeReader{byName: read}))
			if len(p.Warnings) != 1 {
				t.Fatalf("Warnings = %q, want one", p.Warnings)
			}
			got := p.Warnings[0]
			if !strings.Contains(got.Message, tt.message) {
				t.Errorf("Message = %q, want it to contain %q", got.Message, tt.message)
			}
			got.Message = ""
			if got != tt.want {
				t.Errorf("Warning = %+v, want %+v", got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 3: Run it to verify it fails.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/adopt -run TestBuildWarningKinds`
Expected: FAIL to build, `undefined: Warning`.

- [ ] **Step 4: Implement.** In `internal/adopt/adopt.go`, change `Plan.Warnings` (line 53) to `Warnings   []Warning` and add above `Plan`:

```go
// The Warning kinds adopt assigns. Consumers ignore kinds they do not know.
const (
	WarnRevokedKeySkipped    = "revoked_key_skipped"
	WarnRevokedAccessSkipped = "revoked_access_skipped"
	WarnExceptSkipped        = "except_skipped"
	WarnKeyDiffers           = "key_differs"
	WarnCommentDropped       = "comment_dropped"
	WarnWeakKeySkipped       = "weak_key_skipped"
)

// Warning is one finding for the operator. Message is the stderr text; the
// other fields are the structured form --json carries, omitted when they do
// not apply. User is the tombstone's label on a revoked key and the owner
// otherwise.
type Warning struct {
	Kind        string `json:"kind"`
	Server      string `json:"server,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	User        string `json:"user,omitempty"`
	Date        string `json:"date,omitempty"`
	Message     string `json:"message"`
}
```

Replace the two inline appends in `Build`:

```go
				if pd.line != k.Raw && pd.line != stripComment(k) {
					p.Warnings = append(p.Warnings, Warning{Kind: WarnKeyDiffers, Server: r.Server.Name, Fingerprint: k.Fingerprint,
						Message: fmt.Sprintf("key %s on %s differs from the copy first seen on %s (options/comment); keeping the first",
							k.Fingerprint, r.Server.Name, pd.foundOn[0])})
				}
```

```go
				byFP[k.Fingerprint].line = stripComment(k)
				p.Warnings = append(p.Warnings, Warning{Kind: WarnCommentDropped, Server: r.Server.Name, Fingerprint: k.Fingerprint,
					Message: fmt.Sprintf("key %s on %s: comment %s — adopted without its comment",
						k.Fingerprint, r.Server.Name, issue)})
```

Replace `skipKey`, `revokedWarning` and `ownerSkip` (lines 151-187):

```go
// skipKey reports a key adopt never takes: one the manifest's revoked: list
// remembers (first, so a key that is both warns only as REVOKED), or a weak
// one (emitting it would produce a manifest with a policy conflict).
func skipKey(cfg *config.Config, server string, k authkeys.Key) (Warning, bool) {
	if w, revoked := revokedWarning(cfg, server, k.Fingerprint); revoked {
		return w, true
	}
	if k.Weak != "" {
		return Warning{Kind: WarnWeakKeySkipped, Server: server, Fingerprint: k.Fingerprint,
			Message: fmt.Sprintf("key %s on %s: %s key not adopted", k.Fingerprint, server, k.Weak)}, true
	}
	return Warning{}, false
}

// revokedWarning reports a key the manifest's revoked: list remembers.
func revokedWarning(cfg *config.Config, server, fp string) (Warning, bool) {
	t, ok := cfg.Revoked(fp)
	if !ok {
		return Warning{}, false
	}
	return Warning{Kind: WarnRevokedKeySkipped, Server: server, Fingerprint: fp, User: t.User, Date: t.Date,
		Message: fmt.Sprintf("key %s on %s is REVOKED (%s) — not adopted; run 'sshepherd apply --server %s' to remove it",
			fp, server, t.Label(), server)}, true
}

// ownerSkip reports why a known owner's key found on server is not an
// access extension: their except: list excludes the server, or an access
// tombstone removed it (D1a). Either way audit flags the key as drift.
func ownerSkip(cfg *config.Config, owner, server, fp string) (Warning, bool) {
	if cfg.ExceptCarveOut(owner, server) {
		return Warning{Kind: WarnExceptSkipped, Server: server, Fingerprint: fp, User: owner,
			Message: fmt.Sprintf("key %s of %q found on %q, which their except: list deliberately excludes — not re-granted; audit flags this drift",
				fp, owner, server)}, true
	}
	if t, ok := cfg.AccessRevoked(owner, server); ok {
		return Warning{Kind: WarnRevokedAccessSkipped, Server: server, Fingerprint: fp, User: owner, Date: t.Date,
			Message: fmt.Sprintf("key %s of %q found on %q, whose access was revoked (%s) — not re-granted; audit flags this drift",
				fp, owner, server, t.Date)}, true
	}
	return Warning{}, false
}
```

In `cmd/sshepherd/adopt.go`, `reportPlan` (line 234) must keep compiling:

```go
	for _, w := range plan.Warnings {
		log.Warn(w.Message)
	}
```

- [ ] **Step 5: Run the tests.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/adopt ./cmd/sshepherd -run 'TestBuild|TestReportPlan|TestGenerateAdopt|TestRenderMerged'`
Expected: PASS. No golden changes.

### Task 2: the facts the report needs

**Files:**
- Modify: `internal/adopt/adopt.go:19-24,33-46,58-62,75,132,292`
- Test: `internal/adopt/adopt_test.go`

- [ ] **Step 1: Write the failing test.** Append:

```go
// TestBuildCarriesReportFacts: --json names a new user's key without parsing
// its line again, and tells a transport failure from a line adopt could not
// use.
func TestBuildCarriesReportFacts(t *testing.T) {
	cfg := testCfg(t)
	k7 := testkeys.Line(t, 7)
	r := &fakeReader{
		byName: map[string]fleet.ReadResult{
			"web-1": {Content: []byte(k7 + "\n")},
			"web-2": {Content: []byte("ssh-ed25519 !!!notbase64 broken\n")},
		},
		errs: map[string]error{"db-1": &hintedErr{kind: fleet.ErrorKindDial, hint: testDialHint, err: errors.New("connection refused")}},
	}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 1 || p.NewUsers[0].Fingerprint != keyFP(t, k7) || p.NewUsers[0].Type != "ssh-ed25519" {
		t.Errorf("NewUsers = %+v, want the key's fingerprint and type", p.NewUsers)
	}
	kinds := map[string]fleet.ErrorKind{}
	for _, is := range p.Issues {
		kinds[is.Server] = is.Kind
	}
	if kinds["db-1"] != fleet.ErrorKindDial {
		t.Errorf("db-1 kind = %q, want dial", kinds["db-1"])
	}
	if got, ok := kinds["web-2"]; !ok || got != "" {
		t.Errorf("web-2 kind = %q (present %v), want an issue with no kind", got, ok)
	}
}
```

- [ ] **Step 2: Run it to verify it fails.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/adopt -run TestBuildCarriesReportFacts`
Expected: FAIL to build, `p.NewUsers[0].Fingerprint undefined`.

- [ ] **Step 3: Implement.** Add `"github.com/javadh75/SSHepherd/internal/fleet"` to the imports, then:

```go
// NewUser is one unknown key adopted into a generated user.
type NewUser struct {
	Name        string
	Line        string   // authorized_keys line as found (minus an unsafe comment); first line sshd honors wins
	Fingerprint string   // the key's SHA256 fingerprint
	Type        string   // the key's algorithm, e.g. "ssh-ed25519"
	FoundOn     []string // sorted names of servers where the key was found
}
```

Add to `Issue` (after `Hint string`), with this doc line:

```go
	// Kind classifies a transport failure; "" for a line-level issue on a
	// server that was read.
	Kind fleet.ErrorKind
```

Add `keyType string` to `pending`. In `Build`, line 75 and line 132 become:

```go
			p.Issues = append(p.Issues, Issue{Server: r.Server.Name, Detail: r.Err.Error(), Hint: audit.CleanHint(r.Err), Kind: fleet.ErrorKindOf(r.Err)})
```

```go
			byFP[k.Fingerprint] = &pending{line: k.Raw, comment: k.Comment, keyType: k.Type, foundOn: []string{r.Server.Name}}
```

In `nameUsers`, line 292 becomes:

```go
		users = append(users, NewUser{Name: name, Line: pd.line, Fingerprint: fp, Type: pd.keyType, FoundOn: pd.foundOn})
```

- [ ] **Step 4: Run the tests.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/adopt`
Expected: PASS.

### Task 3: adopt's renderer

**Files:**
- Create: `internal/adopt/json.go`, `internal/adopt/json_test.go`, `internal/adopt/testdata/json_emitted.golden.json`, `internal/adopt/testdata/json_stopped.golden.json`, `internal/adopt/testdata/json_zero_read.golden.json`, `internal/adopt/testdata/json_manifest.golden.json`

- [ ] **Step 1: Write the failing test.** Create `internal/adopt/json_test.go`:

```go
package adopt

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/fleet"
)

var update = flag.Bool("update", false, "rewrite golden files")

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update first): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s:\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

// goldenPlan holds one of everything the document reports.
func goldenPlan() Plan {
	return Plan{
		NewUsers:   []NewUser{{Name: "u-laptop", Line: "ssh-ed25519 AAAA", Fingerprint: "SHA256:fpLaptop", Type: "ssh-ed25519", FoundOn: []string{"web-1"}}},
		Extensions: []Extension{{User: "bob", Servers: []string{"db-1"}}},
		Issues: []Issue{
			{Server: "db-3", Kind: fleet.ErrorKindDial, Detail: "dial 10.0.0.3:22: connection refused", Hint: "check the host, port, and firewall"},
			{Server: "web-9", Detail: "line 3: invalid key"},
		},
		Warnings: []Warning{{
			Kind: WarnRevokedKeySkipped, Server: "web-2", Fingerprint: "SHA256:fpOld", User: "alice", Date: "2026-11-08",
			Message: "key SHA256:fpOld on web-2 is REVOKED (2026-11-08, alice) — not adopted; run 'sshepherd apply --server web-2' to remove it",
		}},
	}
}

func TestWriteJSONEmittedGolden(t *testing.T) {
	var out bytes.Buffer
	err := WriteJSON(&out, goldenPlan(), Report{
		Mode: ModeMerge, Emitted: true,
		Placement: Placement{Output: &Output{Path: "fleet.yaml", Written: true}},
		Servers:   12, Read: 11, PartlyRead: 1, ExitCode: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "json_emitted.golden.json", out.Bytes())
}

func TestWriteJSONStoppedGolden(t *testing.T) {
	var out bytes.Buffer
	if err := WriteJSON(&out, goldenPlan(), Report{Mode: ModeGenerate, Servers: 2, Read: 1, ExitCode: 1}); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "json_stopped.golden.json", out.Bytes())
}

// TestWriteJSONZeroReadGolden is the one exit 3 with a document.
func TestWriteJSONZeroReadGolden(t *testing.T) {
	var out bytes.Buffer
	p := Plan{Issues: []Issue{{Server: "web-1", Kind: fleet.ErrorKindDial, Detail: "dial 10.0.0.1:22: connection refused", Hint: "check the host, port, and firewall"}}}
	if err := WriteJSON(&out, p, Report{Mode: ModeGenerate, Servers: 1, Read: 0, ExitCode: 3}); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "json_zero_read.golden.json", out.Bytes())
}

// TestWriteJSONManifestGolden is an exit 0 run with no -o.
func TestWriteJSONManifestGolden(t *testing.T) {
	var out bytes.Buffer
	yaml := "# generated\nusers: []\n"
	err := WriteJSON(&out, Plan{}, Report{Mode: ModeGenerate, Emitted: true, Placement: Placement{Manifest: &yaml}, Servers: 1, Read: 1, ExitCode: 0})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "json_manifest.golden.json", out.Bytes())
}

// TestWriteJSONManifestField: with no -o the YAML is in the document.
func TestWriteJSONManifestField(t *testing.T) {
	var out bytes.Buffer
	yaml := "# generated\nusers: []\n"
	if err := WriteJSON(&out, Plan{}, Report{Mode: ModeGenerate, Emitted: true, Placement: Placement{Manifest: &yaml}}); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["manifest"] != yaml {
		t.Errorf("manifest = %v, want the YAML unchanged", doc["manifest"])
	}
	if _, ok := doc["output"]; ok {
		t.Errorf("document has output alongside manifest: %s", out.String())
	}
}

// TestWriteJSONListsAreNeverNull: a script's .warnings[] must not fail.
func TestWriteJSONListsAreNeverNull(t *testing.T) {
	var out bytes.Buffer
	if err := WriteJSON(&out, Plan{}, Report{Mode: ModeGenerate}); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"new_users": []`, `"extensions": []`, `"unreadable": []`, `"line_issues": []`, `"warnings": []`} {
		if !strings.Contains(out.String(), field) {
			t.Errorf("document lacks %s:\n%s", field, out.String())
		}
	}
	for _, field := range []string{`"output"`, `"manifest"`} {
		if strings.Contains(out.String(), field) {
			t.Errorf("a stopped run's document must not carry %s:\n%s", field, out.String())
		}
	}
}

// TestWriteJSONSanitizes: encoding/json does not escape C1 or Cf runes, so
// remote text is stripped before it reaches a terminal through jq.
func TestWriteJSONSanitizes(t *testing.T) {
	csi, bidi := string(rune(0x9b)), string(rune(0x202e))
	hostile := "x" + csi + bidi + "y"
	p := Plan{
		Issues: []Issue{
			{Server: hostile, Kind: fleet.ErrorKindDial, Detail: hostile, Hint: hostile},
			{Server: hostile, Detail: hostile},
		},
		Warnings: []Warning{{Kind: WarnCommentDropped, Server: hostile, User: hostile, Date: hostile, Message: hostile}},
	}
	var out bytes.Buffer
	if err := WriteJSON(&out, p, Report{Mode: ModeGenerate}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), csi) || strings.Contains(out.String(), bidi) {
		t.Errorf("hostile runes survived:\n%q", out.String())
	}
	if got := strings.Count(out.String(), `"detail": "xy"`); got != 2 {
		t.Errorf("sanitized detail appears %d times, want 2 (unreadable and line_issues):\n%s", got, out.String())
	}
	if !strings.Contains(out.String(), `"hint": "xy"`) || !strings.Contains(out.String(), `"message": "xy"`) {
		t.Errorf("sanitized text missing:\n%s", out.String())
	}
	if got := strings.Count(out.String(), `"server": "xy"`); got != 3 {
		t.Errorf("sanitized server appears %d times, want 3 (one issue row each, one warning):\n%s", got, out.String())
	}
}
```

- [ ] **Step 2: Run it to verify it fails.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/adopt -run TestWriteJSON`
Expected: FAIL to build, `undefined: WriteJSON`.

- [ ] **Step 3: Implement.** Create `internal/adopt/json.go`:

```go
package adopt

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/javadh75/SSHepherd/internal/sanitize"
)

// The Report.Mode values.
const (
	ModeGenerate = "generate"
	ModeMerge    = "merge"
)

// jsonSchema marks the document's shape; it stays 1, with additive fields.
const jsonSchema = 1

// Output says where -o put the manifest. Written is false only for an
// in-place update whose bytes were identical.
type Output struct {
	Path    string `json:"path"`
	Written bool   `json:"written"`
}

// Placement is where a --json run's manifest went: Output with -o, the bytes
// in Manifest without it, neither when nothing was emitted. Manifest is a
// pointer because an emitted empty manifest (a no-op --merge of a 0-byte
// file) must still appear in the document.
type Placement struct {
	Output   *Output
	Manifest *string
}

// Report is what the document carries beyond the Plan.
type Report struct {
	Mode       string // ModeGenerate or ModeMerge
	Emitted    bool   // a manifest was produced
	Placement  Placement
	Servers    int
	Read       int
	PartlyRead int
	ExitCode   int
}

type jsonSummary struct {
	Servers    int `json:"servers"`
	Read       int `json:"read"`
	PartlyRead int `json:"partly_read"`
	NewUsers   int `json:"new_users"`
	Extensions int `json:"extensions"`
	Warnings   int `json:"warnings"`
	ExitCode   int `json:"exit_code"`
}

type jsonNewUser struct {
	Name        string   `json:"name"`
	Fingerprint string   `json:"fingerprint"`
	Type        string   `json:"type"`
	FoundOn     []string `json:"found_on"`
}

type jsonExtension struct {
	User    string   `json:"user"`
	Servers []string `json:"servers"`
}

// jsonUnreadable is a server the run could not read: it always carries
// error_kind.
type jsonUnreadable struct {
	Server    string `json:"server"`
	ErrorKind string `json:"error_kind"`
	Detail    string `json:"detail"`
	Hint      string `json:"hint,omitempty"`
}

// jsonLineIssue is a line adopt could not use on a server it did read.
type jsonLineIssue struct {
	Server string `json:"server"`
	Detail string `json:"detail"`
}

// jsonDoc is adopt's --json document. The lists are always present; Output
// and Manifest are mutually exclusive and absent when Emitted is false.
type jsonDoc struct {
	Schema     int              `json:"schema"`
	Command    string           `json:"command"`
	Mode       string           `json:"mode"`
	Emitted    bool             `json:"emitted"`
	Output     *Output          `json:"output,omitempty"`
	Manifest   *string          `json:"manifest,omitempty"`
	Summary    jsonSummary      `json:"summary"`
	NewUsers   []jsonNewUser    `json:"new_users"`
	Extensions []jsonExtension  `json:"extensions"`
	Unreadable []jsonUnreadable `json:"unreadable"`
	LineIssues []jsonLineIssue  `json:"line_issues"`
	Warnings   []Warning        `json:"warnings"`
}

// WriteJSON writes the discovery and warnings report for plan. The manifest
// bytes are not sanitized: they must equal a plain run's. Remote text in the
// rest is, because encoding/json does not escape C1 or Cf runes.
func WriteJSON(w io.Writer, p Plan, r Report) error {
	doc := jsonDoc{
		Schema: jsonSchema, Command: "adopt", Mode: r.Mode, Emitted: r.Emitted,
		Output: r.Placement.Output, Manifest: r.Placement.Manifest,
		Summary: jsonSummary{
			Servers: r.Servers, Read: r.Read, PartlyRead: r.PartlyRead,
			NewUsers: len(p.NewUsers), Extensions: len(p.Extensions), Warnings: len(p.Warnings), ExitCode: r.ExitCode,
		},
		NewUsers:   make([]jsonNewUser, 0, len(p.NewUsers)),
		Extensions: make([]jsonExtension, 0, len(p.Extensions)),
		Unreadable: make([]jsonUnreadable, 0, len(p.Issues)),
		LineIssues: make([]jsonLineIssue, 0, len(p.Issues)),
		Warnings:   make([]Warning, 0, len(p.Warnings)),
	}
	for _, u := range p.NewUsers {
		doc.NewUsers = append(doc.NewUsers, jsonNewUser{Name: u.Name, Fingerprint: u.Fingerprint, Type: u.Type, FoundOn: u.FoundOn})
	}
	for _, e := range p.Extensions {
		doc.Extensions = append(doc.Extensions, jsonExtension(e))
	}
	for _, is := range p.Issues {
		if is.Kind == "" {
			doc.LineIssues = append(doc.LineIssues, jsonLineIssue{Server: sanitize.Remote(is.Server), Detail: sanitize.Remote(is.Detail)})
			continue
		}
		doc.Unreadable = append(doc.Unreadable, jsonUnreadable{
			Server: sanitize.Remote(is.Server), ErrorKind: string(is.Kind),
			Detail: sanitize.Remote(is.Detail), Hint: sanitize.Remote(is.Hint),
		})
	}
	for _, x := range p.Warnings {
		x.Server, x.User, x.Date, x.Message = sanitize.Remote(x.Server), sanitize.Remote(x.User), sanitize.Remote(x.Date), sanitize.Remote(x.Message)
		doc.Warnings = append(doc.Warnings, x)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode adopt report: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Create the goldens and read them back.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/adopt -run 'TestWriteJSON.*Golden' -update && GOTOOLCHAIN=go1.27.3 go test ./internal/adopt`
Expected: PASS. Read all four files line by line: the key order is the design's plus the additive list (`schema`, `command`, `mode`, `emitted`, `output` or `manifest`, `summary`, `new_users`, `extensions`, `unreadable`, `line_issues`, `warnings`); `json_stopped.golden.json` and `json_zero_read.golden.json` have neither `output` nor `manifest` and `"emitted": false`; `json_zero_read.golden.json` has `"exit_code": 3`; `json_manifest.golden.json` has `manifest`, no `output` and `"exit_code": 0`; every `unreadable` row has `error_kind`; and `web-9` is a row of `line_issues` with no `error_kind`, not of `unreadable`.

### Task 4: where the manifest went

**Files:**
- Modify: `cmd/sshepherd/manifest_out.go`
- Test: `cmd/sshepherd/manifest_out_test.go:106`

- [ ] **Step 1: Write the failing test.** In `manifest_out_test.go` change line 106 to `_, err = publishManifest(m, out, []byte(tt.data), tt.force)` and append:

```go
// TestPlaceManifest: no -o puts the bytes in the document; -o reports
// whether the file changed, which an identical in-place update did not.
func TestPlaceManifest(t *testing.T) {
	data := []byte("users: []\n")
	src := filepath.Join(t.TempDir(), "m.yaml")
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := readManifest(src)
	if err != nil {
		t.Fatal(err)
	}
	got, err := placeManifest(m, "", data, false)
	if err != nil || got.Output != nil || got.Manifest == nil || *got.Manifest != string(data) {
		t.Errorf("no -o: placement = %+v, err = %v", got, err)
	}
	dst := filepath.Join(t.TempDir(), "new.yaml")
	got, err = placeManifest(m, dst, data, false)
	if err != nil || got.Manifest != nil || got.Output == nil || got.Output.Path != dst || !got.Output.Written {
		t.Errorf("new file: placement = %+v, err = %v", got, err)
	}
	got, err = placeManifest(m, src, data, true)
	if err != nil || got.Output == nil || got.Output.Written {
		t.Errorf("identical in-place update: placement = %+v, err = %v, want written false", got, err)
	}
	if _, err = placeManifest(m, dst, data, false); err == nil {
		t.Error("an existing -o without --force was accepted")
	}
}
```

- [ ] **Step 2: Run it to verify it fails.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestPlaceManifest|TestPublishManifestRoutes'`
Expected: FAIL to build, `undefined: placeManifest`.

- [ ] **Step 3: Implement.** Replace the body of `manifest_out.go` from `emitManifest` down, adding the `adopt` import:

```go
// emitManifest sends a generated manifest to stdout, or to -o through
// publishManifest when out is set.
func emitManifest(stdout io.Writer, src manifestTarget, out string, data []byte, force bool) error {
	if out != "" {
		_, err := publishManifest(src, out, data, force)
		return err
	}
	if _, err := stdout.Write(data); err != nil {
		return fmt.Errorf("write stdout: %w", err)
	}
	return nil
}

// placeManifest is emitManifest under --json: stdout belongs to the
// document, so with no -o the bytes go into it (OP3).
func placeManifest(src manifestTarget, out string, data []byte, force bool) (adopt.Placement, error) {
	if out == "" {
		s := string(data)
		return adopt.Placement{Manifest: &s}, nil
	}
	written, err := publishManifest(src, out, data, force)
	if err != nil {
		return adopt.Placement{}, err
	}
	return adopt.Placement{Output: &adopt.Output{Path: out, Written: written}}, nil
}

// publishManifest writes a generated manifest to -o and reports whether the
// file changed. When out is the very file this run read (adopt's --config,
// adopt/import --merge; symlinks followed) it is an in-place update: --force
// is still required, identical bytes write nothing, and the write goes
// through Save — the manifest lock, the changed-since-read refusal, the
// file's own mode and owner — so it can never undo a concurrent revoke. Any
// other path is a new file (manifest.WriteFile: mode 0600, never clobbered
// without --force).
func publishManifest(src manifestTarget, out string, data []byte, force bool) (bool, error) {
	same, err := src.SameAs(out)
	if err != nil {
		return false, err //nolint:wrapcheck // SameAs names both paths
	}
	if !same {
		if err := manifest.WriteFile(out, data, force); err != nil {
			return false, err //nolint:wrapcheck // "write PATH: …" / "--force" hints are the user-facing text
		}
		return true, nil
	}
	if !force {
		return false, fmt.Errorf("%s is the manifest this run read; pass --force to update it in place", out)
	}
	if bytes.Equal(data, src.Loaded) {
		return false, nil
	}
	if err := src.Save(data); err != nil {
		return false, err
	}
	return true, nil
}
```

- [ ] **Step 4: Run the tests.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestPlaceManifest|TestPublishManifestRoutes'`
Expected: PASS.

### Task 5: `adopt --json`

**Files:**
- Modify: `cmd/sshepherd/adopt.go:251-340`
- Create: `cmd/sshepherd/adopt_json_test.go`

- [ ] **Step 1: Write the failing test.** Create `cmd/sshepherd/adopt_json_test.go`:

```go
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// adoptJSONDoc is what the tests read of adopt's document. The pointers tell
// an absent field from an empty one.
type adoptJSONDoc struct {
	Schema  int    `json:"schema"`
	Command string `json:"command"`
	Mode    string `json:"mode"`
	Emitted bool   `json:"emitted"`
	Output  *struct {
		Path    string `json:"path"`
		Written bool   `json:"written"`
	} `json:"output"`
	Manifest *string `json:"manifest"`
	Summary  struct {
		Servers    int `json:"servers"`
		Read       int `json:"read"`
		PartlyRead int `json:"partly_read"`
		NewUsers   int `json:"new_users"`
		Extensions int `json:"extensions"`
		Warnings   int `json:"warnings"`
		ExitCode   int `json:"exit_code"`
	} `json:"summary"`
	NewUsers []struct {
		Name        string   `json:"name"`
		Fingerprint string   `json:"fingerprint"`
		Type        string   `json:"type"`
		FoundOn     []string `json:"found_on"`
	} `json:"new_users"`
	Unreadable []struct {
		Server    string `json:"server"`
		ErrorKind string `json:"error_kind"`
		Detail    string `json:"detail"`
		Hint      string `json:"hint"`
	} `json:"unreadable"`
	LineIssues []struct {
		Server string `json:"server"`
		Detail string `json:"detail"`
	} `json:"line_issues"`
	Warnings []adoptJSONWarning `json:"warnings"`
}

// adoptJSONWarning is one warning as a script reads it.
type adoptJSONWarning struct {
	Kind        string `json:"kind"`
	Server      string `json:"server"`
	Fingerprint string `json:"fingerprint"`
	User        string `json:"user"`
	Date        string `json:"date"`
}

// adoptJSONCLI runs adopt --json and decodes stdout, which must be exactly
// one document.
func adoptJSONCLI(t *testing.T, args ...string) (int, adoptJSONDoc, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := run(append([]string{"adopt", "--json"}, args...), &out, &errBuf)
	dec := json.NewDecoder(&out)
	var doc adoptJSONDoc
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("exit %d: stdout is not a document: %v (stderr: %s)", code, err, errBuf.String())
	}
	if dec.More() {
		t.Fatalf("stdout holds more than one document")
	}
	return code, doc, errBuf.String()
}

// adoptFixture is one reachable server holding keys 1 and 7, where the
// manifest knows only key 1.
func adoptFixture(t *testing.T) (cfg, kh string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1, 7})
	cfg = writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
		"access:\n  - {user: alice, servers: [web-1]}\n")
	return cfg, kh
}

// TestAdoptJSONManifestMatchesPlainRun is OP3: with no -o the manifest is in
// the document, byte for byte what a plain run prints, and logs stay on
// stderr.
func TestAdoptJSONManifestMatchesPlainRun(t *testing.T) {
	cfg, kh := adoptFixture(t)
	var plain, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", cfg, "--known-hosts", kh}, &plain, &errBuf); code != 0 {
		t.Fatalf("plain exit = %d (stderr: %s)", code, errBuf.String())
	}
	code, doc, stderr := adoptJSONCLI(t, "--config", cfg, "--known-hosts", kh)
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	if doc.Manifest == nil || *doc.Manifest != plain.String() {
		t.Errorf("manifest = %v\nwant %q", doc.Manifest, plain.String())
	}
	if doc.Output != nil {
		t.Errorf("output = %+v, want none without -o", doc.Output)
	}
	if doc.Schema != 1 || doc.Command != "adopt" || doc.Mode != "generate" || !doc.Emitted {
		t.Errorf("doc = %+v", doc)
	}
	if s := doc.Summary; s.Servers != 1 || s.Read != 1 || s.PartlyRead != 0 || s.NewUsers != 1 || s.Extensions != 0 || s.Warnings != 0 || s.ExitCode != 0 {
		t.Errorf("summary = %+v", s)
	}
	if len(doc.NewUsers) != 1 || doc.NewUsers[0].Type != "ssh-ed25519" || doc.NewUsers[0].Fingerprint == "" ||
		len(doc.NewUsers[0].FoundOn) != 1 || doc.NewUsers[0].FoundOn[0] != "web-1" {
		t.Errorf("new_users = %+v", doc.NewUsers)
	}
	if !strings.Contains(stderr, "read 1 of 1 server") {
		t.Errorf("stderr = %q, want the logs there", stderr)
	}
}

// TestAdoptJSONOutputFile: with -o the file holds a plain run's bytes, in
// generate mode and for a --merge that really appends.
func TestAdoptJSONOutputFile(t *testing.T) {
	for name, extra := range map[string][]string{
		"generate":           nil,
		"merge that appends": {"--merge"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, kh := adoptFixture(t)
			flags := append([]string{"--config", cfg, "--known-hosts", kh}, extra...)
			plain := plainManifestFile(t, append([]string{"adopt"}, flags...)...)
			dst := filepath.Join(t.TempDir(), "adopted.yaml")
			code, doc, stderr := adoptJSONCLI(t, append(slices.Clone(flags), "-o", dst)...)
			if code != 0 {
				t.Fatalf("exit = %d (stderr: %s)", code, stderr)
			}
			if doc.Output == nil || doc.Output.Path != dst || !doc.Output.Written || doc.Manifest != nil {
				t.Errorf("output = %+v, manifest = %v", doc.Output, doc.Manifest)
			}
			got, err := os.ReadFile(dst)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plain) {
				t.Errorf("-o bytes differ from a plain run:\n--- got ---\n%s\n--- want ---\n%s", got, plain)
			}
			if parsed := readCfg(t, dst); len(parsed.Users) != 2 {
				t.Errorf("written manifest has %d users, want 2", len(parsed.Users))
			}
		})
	}
}

// TestAdoptJSONInPlaceNoChange: nothing to adopt, so the in-place update
// writes nothing, and the document says so.
func TestAdoptJSONInPlaceNoChange(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
		"access:\n  - {user: alice, servers: [web-1]}\n")
	before, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	code, doc, stderr := adoptJSONCLI(t, "--merge", "--config", cfg, "--known-hosts", kh, "-o", cfg, "--force")
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	if doc.Mode != "merge" || !doc.Emitted || doc.Output == nil || doc.Output.Written {
		t.Errorf("doc = %+v, output = %+v, want merge, emitted, written false", doc, doc.Output)
	}
	after, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("manifest changed:\n%s", after)
	}
}

// TestAdoptJSONStoppedByUnreadable: exit 1, a document, nothing emitted.
func TestAdoptJSONStoppedByUnreadable(t *testing.T) {
	cfg, kh := unreachableFleet(t)
	dst := filepath.Join(t.TempDir(), "adopted.yaml")
	code, doc, stderr := adoptJSONCLI(t, "--config", cfg, "--known-hosts", kh, "-o", dst)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, stderr)
	}
	if doc.Emitted || doc.Output != nil || doc.Manifest != nil {
		t.Errorf("doc = %+v, want nothing emitted", doc)
	}
	if doc.Summary.Servers != 1 || doc.Summary.Read != 0 || doc.Summary.ExitCode != 1 {
		t.Errorf("summary = %+v", doc.Summary)
	}
	if len(doc.Unreadable) != 1 || doc.Unreadable[0].Server != "web-1" || doc.Unreadable[0].ErrorKind != "dial" ||
		doc.Unreadable[0].Detail == "" || doc.Unreadable[0].Hint == "" {
		t.Errorf("unreadable = %+v", doc.Unreadable)
	}
	if !strings.Contains(stderr, "could not be fully read") {
		t.Errorf("stderr = %q, want the strict-gate verdict", stderr)
	}
	if _, err := os.Lstat(dst); err == nil {
		t.Errorf("%s was written", dst)
	}
}

// TestAdoptJSONPartialSomeRead: exit 1, emitted, the gap in the manifest.
func TestAdoptJSONPartialSomeRead(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
		"  - {name: web-2, host: 127.0.0.1, port: "+strconv.Itoa(closedPort(t))+", user: deploy}\naccess:\n  - {user: alice, servers: [web-1]}\n")
	code, doc, stderr := adoptJSONCLI(t, "--config", cfg, "--known-hosts", kh, "--partial")
	if code != adoptPartialExit {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, adoptPartialExit, stderr)
	}
	if !doc.Emitted || doc.Manifest == nil || !strings.Contains(*doc.Manifest, "# WARNING: server web-2 unreadable") {
		t.Errorf("doc = %+v, want the partial manifest", doc)
	}
	if doc.Summary.Servers != 2 || doc.Summary.Read != 1 || doc.Summary.ExitCode != adoptPartialExit {
		t.Errorf("summary = %+v", doc.Summary)
	}
}

// TestAdoptJSONPartialNothingRead is the one exit 3 with a document.
func TestAdoptJSONPartialNothingRead(t *testing.T) {
	cfg, kh := unreachableFleet(t)
	dst := filepath.Join(t.TempDir(), "adopted.yaml")
	code, doc, stderr := adoptJSONCLI(t, "--config", cfg, "--known-hosts", kh, "--partial", "-o", dst)
	if code != 3 {
		t.Fatalf("exit = %d, want 3 (stderr: %s)", code, stderr)
	}
	if doc.Emitted || doc.Output != nil || doc.Manifest != nil || doc.Summary.ExitCode != 3 || len(doc.Unreadable) != 1 {
		t.Errorf("doc = %+v", doc)
	}
	if !strings.Contains(stderr, "read 0 of 1 server — nothing could be adopted") {
		t.Errorf("stderr = %q", stderr)
	}
	if _, err := os.Lstat(dst); err == nil {
		t.Errorf("%s was written", dst)
	}
}

// TestAdoptJSONPartlyRead: a line adopt cannot use leaves the server read:
// it is a row of line_issues, not of unreadable, and the run exits 0.
func TestAdoptJSONPartlyRead(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1}, "ssh-ed25519 !!!notbase64 broken")
	cfg := writeConfig(t, "users: []\nservers:\n"+hosts["web-1"].line("web-1")+"access: []\n")
	code, doc, stderr := adoptJSONCLI(t, "--config", cfg, "--known-hosts", kh, "--partial")
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	if doc.Summary.Read != 1 || doc.Summary.PartlyRead != 1 || doc.Summary.ExitCode != 0 || !doc.Emitted {
		t.Errorf("doc = %+v", doc)
	}
	if len(doc.Unreadable) != 0 {
		t.Errorf("unreadable = %+v, want none: the server was read", doc.Unreadable)
	}
	if len(doc.LineIssues) != 1 || doc.LineIssues[0].Server != "web-1" || doc.LineIssues[0].Detail == "" {
		t.Errorf("line_issues = %+v, want one row for web-1", doc.LineIssues)
	}
}

// TestAdoptJSONReportsSkippedKey: each P04 skip reaches the document in its
// shape.
func TestAdoptJSONReportsSkippedKey(t *testing.T) {
	fp4, fp7 := fingerprintOf(t, testkeys.Line(t, 4)), fingerprintOf(t, testkeys.Line(t, 7))
	for _, tt := range []struct {
		name    string
		seed    byte   // the installed key the run skips
		users   string // user lines added after alice
		revoked string
		want    adoptJSONWarning
	}{
		{
			name:    "revoked key",
			seed:    7,
			revoked: "revoked:\n  - {fingerprint: " + fp7 + ", user: old, date: 2026-11-08}\n",
			want:    adoptJSONWarning{Kind: "revoked_key_skipped", Server: "web-1", Fingerprint: fp7, User: "old", Date: "2026-11-08"},
		},
		{
			name:    "access tombstone",
			seed:    4,
			users:   "  - {name: bob, keys: [" + qk(t, 4) + "]}\n",
			revoked: "revoked:\n  - {user: bob, servers: [web-1], date: 2026-11-08}\n",
			want:    adoptJSONWarning{Kind: "revoked_access_skipped", Server: "web-1", Fingerprint: fp4, User: "bob", Date: "2026-11-08"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
			hosts["web-1"].install(t, []byte{1, tt.seed})
			cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n"+tt.users+"servers:\n"+hosts["web-1"].line("web-1")+
				"access:\n  - {user: alice, servers: [web-1]}\n"+tt.revoked)
			code, doc, stderr := adoptJSONCLI(t, "--config", cfg, "--known-hosts", kh)
			if code != 0 {
				t.Fatalf("exit = %d (stderr: %s)", code, stderr)
			}
			if len(doc.Warnings) != 1 || doc.Summary.Warnings != 1 {
				t.Fatalf("warnings = %+v, summary = %+v", doc.Warnings, doc.Summary)
			}
			if got := doc.Warnings[0]; got != tt.want {
				t.Errorf("warning = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestAdoptJSONToolErrorNoDocument: exit 3 is a message on stderr, not a
// document. want pins the message, so an unknown --json flag (also exit 3
// with empty stdout) cannot pass.
func TestAdoptJSONToolErrorNoDocument(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1})
	alice := "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n"
	rest := "servers:\n" + hosts["web-1"].line("web-1") + "access:\n  - {user: alice, servers: [web-1]}\n"
	cfg := writeConfig(t, alice+rest)
	// carol's key stays listed while revoked: a policy conflict, refused only
	// after the render.
	conflicted := writeConfig(t, alice+"  - {name: carol, keys: ["+qk(t, 7)+"]}\n"+rest+
		"revoked:\n  - {fingerprint: "+fingerprintOf(t, testkeys.Line(t, 7))+", user: old, date: 2026-11-08}\n")
	taken := filepath.Join(t.TempDir(), "taken.yaml")
	if err := os.WriteFile(taken, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tt := range map[string]struct {
		args []string
		want string
	}{
		"missing manifest":        {[]string{"adopt", "--json", "--config", "/nonexistent.yaml", "--known-hosts", kh}, "no manifest at"},
		"bad --identity":          {[]string{"adopt", "--json", "--config", cfg, "--known-hosts", kh, "--identity", "/no/such/id"}, "identity: "},
		"-o exists, no --force":   {[]string{"adopt", "--json", "--config", cfg, "--known-hosts", kh, "-o", taken}, "already exists; pass --force"},
		"keeps a policy conflict": {[]string{"adopt", "--json", "--config", conflicted, "--known-hosts", kh}, "refusing to write the manifest"},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			if code := run(tt.args, &out, &errBuf); code != 3 {
				t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
			}
			if out.Len() != 0 {
				t.Errorf("stdout = %q, want no document", out.String())
			}
			if !strings.Contains(errBuf.String(), tt.want) {
				t.Errorf("stderr = %q, want %q", errBuf.String(), tt.want)
			}
		})
	}
}

// TestAdoptJSONMergeEmptyManifest: a no-op merge of a 0-byte file emits zero
// bytes, and the document still has the field (OP3).
func TestAdoptJSONMergeEmptyManifest(t *testing.T) {
	cfg := writeConfig(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--json", "--merge", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"manifest": ""`) || !strings.Contains(out.String(), `"emitted": true`) {
		t.Errorf("stdout = %s, want an emitted, empty manifest field", out.String())
	}
}

// TestAdoptJSONHostileRemoteComment: a comment read from a server reaches
// neither the report nor its manifest with C1 or Cf runes in it.
func TestAdoptJSONHostileRemoteComment(t *testing.T) {
	csi, bidi := string(rune(0x9b)), string(rune(0x202e))
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1}, testkeys.Line(t, 7)+" x"+csi+bidi+"y")
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
		"access:\n  - {user: alice, servers: [web-1]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--json", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
	}
	if strings.Contains(out.String(), csi) || strings.Contains(out.String(), bidi) {
		t.Errorf("hostile runes survived on stdout:\n%q", out.String())
	}
	var doc adoptJSONDoc
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Warnings) != 1 || doc.Warnings[0].Kind != "comment_dropped" {
		t.Errorf("warnings = %+v, want one comment_dropped", doc.Warnings)
	}
}
```

Add these helpers to the same file; no test in `package main` declares them today, and round 2 uses both:

```go
func fingerprintOf(t *testing.T, line string) string {
	t.Helper()
	k, err := authkeys.ParseLine(line)
	if err != nil || k == nil {
		t.Fatalf("parse %q: %v", line, err)
	}
	return k.Fingerprint
}

// plainManifestFile runs args (a command and its flags, no --json) with -o
// and returns the bytes it wrote.
func plainManifestFile(t *testing.T, args ...string) []byte {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "plain.yaml")
	var out, errBuf bytes.Buffer
	if code := run(append(slices.Clone(args), "-o", dst), &out, &errBuf); code != 0 {
		t.Fatalf("plain exit = %d (stderr: %s)", code, errBuf.String())
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
```

- [ ] **Step 2: Run it to verify it fails.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run TestAdoptJSON`
Expected: FAIL: `unknown flag: --json`, so stdout does not decode, and `TestAdoptJSONToolErrorNoDocument` fails its `want` assertion on every row.

- [ ] **Step 3: Implement.** In `cmd/sshepherd/adopt.go` add `"context"` to the imports and replace `newAdoptCmd` (lines 251-340) with:

```go
// adoptOpts are adopt's own flags; connFlags holds the shared ones.
type adoptOpts struct {
	outPath string
	force   bool
	partial bool
	merge   bool
	json    bool
}

// adoptRun is one adopt run.
type adoptRun struct {
	log    *slog.Logger
	stdout io.Writer
	cf     *connFlags
	opts   adoptOpts
}

func (r *adoptRun) run(ctx context.Context) error {
	ids, err := r.cf.validate()
	if err != nil {
		return err
	}
	m, cfg, mf, err := loadAdoptManifest(r.cf.cfgPath, r.opts.merge)
	if err != nil {
		return err
	}
	logManifest(r.log, cfg)
	results, err := readFleet(ctx, r.log, cfg, cfg.Servers, r.cf, ids, "reading")
	if err != nil {
		return err
	}
	plan := adopt.Build(cfg, results)
	unreadable := plan.UnreadableServers()
	partly := partlyRead(unreadable, results)
	rep := adopt.Report{Mode: adopt.ModeGenerate, Servers: len(cfg.Servers), Read: fleetReadCount(results), PartlyRead: len(partly)}
	if r.opts.merge {
		rep.Mode = adopt.ModeMerge
	}
	if err := reportUnreadable(r.log, plan, unreadable, r.opts.partial); err != nil {
		return r.stop(plan, rep, err)
	}
	if err := reportReadCount(r.log, rep.Servers, rep.Read, rep.PartlyRead, r.opts.partial); err != nil {
		return r.stop(plan, rep, err)
	}
	rendered, err := r.render(m, cfg, mf, plan, gapNotes(unreadable, partly))
	if err != nil {
		return err
	}
	reportPlan(r.log, plan, unreadable)
	// Self-check: never emit a manifest our own loader would reject,
	// nor one that keeps a policy conflict (D29).
	saved, err := config.Parse(rendered)
	if err != nil {
		return fmt.Errorf("bug: generated manifest fails validation: %w", err)
	}
	if err := conflictRefusal(cfg, saved); err != nil {
		return err
	}
	return r.finish(plan, rep, m, rendered)
}

func (r *adoptRun) render(m manifestTarget, cfg *config.Config, mf *manifest.File, plan adopt.Plan, gaps []string) ([]byte, error) {
	if r.opts.merge {
		return renderMergedManifest(mf, m.Loaded, plan, gaps, time.Now().Format("2006-01-02"))
	}
	return generateAdoptManifest(cfg, plan, r.cf.cfgPath, gaps)
}

// stop ends a run that emits no manifest. Under --json the document says
// why, with the exit code the process is about to return: the strict gate
// (1) or a --partial run that read nothing (3, the one exit 3 with a
// document).
func (r *adoptRun) stop(plan adopt.Plan, rep adopt.Report, stopErr error) error {
	if r.opts.json {
		rep.ExitCode = exitCodeFor(stopErr)
		if err := adopt.WriteJSON(r.stdout, plan, rep); err != nil {
			return err //nolint:wrapcheck // "encode adopt report: …"
		}
	}
	return stopErr
}

// finish emits the manifest. The document is written only after -o
// succeeded, so a refused save (exit 3) leaves stdout empty.
func (r *adoptRun) finish(plan adopt.Plan, rep adopt.Report, m manifestTarget, rendered []byte) error {
	var end error
	if r.opts.partial && rep.Read < rep.Servers {
		// The partial manifest is out; the exit code tells a script
		// it is incomplete (exit 1, like audit). A partly read server
		// (only lines adopt could not use) counts as read and keeps
		// exit 0; its gap is marked in the output and on stderr.
		end = fmt.Errorf("%w: read %d of %d servers", errFleetUnreadable, rep.Read, rep.Servers)
	}
	if !r.opts.json {
		if err := emitManifest(r.stdout, m, r.opts.outPath, rendered, r.opts.force); err != nil {
			return err
		}
		return end
	}
	place, err := placeManifest(m, r.opts.outPath, rendered, r.opts.force)
	if err != nil {
		return err
	}
	rep.Emitted, rep.Placement, rep.ExitCode = true, place, exitCodeFor(end)
	if err := adopt.WriteJSON(r.stdout, plan, rep); err != nil {
		return err //nolint:wrapcheck // "encode adopt report: …"
	}
	return end
}

func newAdoptCmd(a *app, stdout io.Writer) *cobra.Command {
	var (
		cf   connFlags
		opts adoptOpts
	)
	cmd := &cobra.Command{
		Use:   "adopt",
		Short: "Generate a manifest that adopts every key already installed on the fleet",
		Long: "Connects to every server in the manifest (same SSH path as audit), reads\n" +
			"the actual authorized_keys, and emits a complete new manifest in which\n" +
			"every installed key is accounted for: keys of known users found beyond\n" +
			"their grants extend that user's access; unknown keys become new users\n" +
			"with access to exactly the servers where they were found. The input\n" +
			"file is modified only when --output names it (with --force); it is then\n" +
			"saved in place under the manifest lock, like revoke. Review the output,\n" +
			"then adopt it as your manifest. Any unreadable server aborts the run\n" +
			"unless --partial is set.\n\n" +
			exitCodesAdopt,
		Example: "  # Bootstrap: append every installed key to a servers-only manifest\n" +
			"  sshepherd adopt --merge -o adopted.yaml\n\n" +
			"  # Regenerate from scratch, even if some servers are down\n" +
			"  sshepherd adopt --partial -o adopted.yaml\n\n" +
			"  # A discovery report for a script; the manifest goes to the file\n" +
			"  sshepherd adopt --merge --json -o adopted.yaml",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := &adoptRun{log: a.logger, stdout: stdout, cf: &cf, opts: opts}
			return r.run(cmd.Context())
		},
	}
	cf.register(cmd, "max concurrent server reads")
	cmd.Flags().StringVarP(&opts.outPath, "output", "o", "", "write the manifest to this file instead of stdout")
	cmd.Flags().BoolVar(&opts.force, "force", false, "allow --output to overwrite an existing file")
	cmd.Flags().BoolVar(&opts.partial, "partial", false, "proceed even if some servers cannot be read (their access will be missing from the output)")
	cmd.Flags().BoolVar(&opts.merge, "merge", false, "merge into --config: preserve its text and append what is new")
	cmd.Flags().BoolVar(&opts.json, "json", false, "emit a machine-readable report on stdout (the manifest goes to -o, or into the report's manifest field)")
	return cmd
}
```

- [ ] **Step 4: Run the tests.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestAdopt|TestQuickStart|TestReport|TestGapNotes'`
Expected: PASS. Every existing adopt test passes unchanged: the non-JSON path is byte-identical.

### Task 6: help golden and hand back

**Files:**
- Modify: `cmd/sshepherd/testdata/help/adopt.golden`

- [ ] **Step 1: See the golden fail, then regenerate it.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run TestHelpGolden`
Expected: FAIL on `adopt`. Then run `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run TestHelpGolden -update` and read `adopt.golden` back: the only changes are the third example and the `--json` flag line.

- [ ] **Step 2: Apply the docsDelta to the worktree's `README.md` (gate only).** Without it `TestHelpMatchesREADMETables` fails on `--json`.

**docsDelta (`README.md`, adopt):**

In `### sshepherd adopt`'s flag table, after the `--merge` row, add:

```markdown
| `--json` | off | Machine-readable report on stdout (schema 1); the manifest goes to `-o`, or into the report's `manifest` field |
```

After the flag table (before `Any unreadable server aborts the run`), add:

````markdown
`--json` replaces the manifest on stdout with one report (schema 1), and changes nothing else: logs stay on stderr and the manifest bytes match a plain run exactly. With `-o` the manifest goes to the file and the report has `output` (`written` is `false` when an in-place update changed nothing). Without `-o` the report has `manifest`, so `sshepherd adopt --json | jq -j .manifest` prints what a plain run prints. A report with `"emitted": false` has neither.

Exit `0` and `1` always write a report. `emitted` is `true` under `--partial` and `false` when unreadable servers stopped the run. Exit `3` writes none, only a message on stderr, with one exception: `--partial` with no server read writes a report with `"emitted": false`. `unreadable` lists servers that could not be read, each with `error_kind`; `line_issues` lists lines adopt could not use on a server it did read, and `summary.partly_read` counts those servers. `warnings` has the kinds `revoked_key_skipped`, `revoked_access_skipped`, `except_skipped`, `key_differs`, `comment_dropped` and `weak_key_skipped`; ignore kinds you do not know.

```json
<copy internal/adopt/testdata/json_emitted.golden.json verbatim>
```
````

In the `## Status` table, change the `adopt` row's `(`--merge` supported)` to `(`--merge` supported, text + `--json`)`.

- [ ] **Step 3: Gate and hand back.** Run `make check` and, because this lane rewrites adopt's command body, `make integration` under the runner's lock. Then `git add -A`, unstage every path outside the lane's globs (`README.md` and `CLAUDE.md` always), and write the patch.

---

## Round 2 — lane `import` (Tasks 7–11)

### Task 7: structured reconcile warnings

**Files:**
- Modify: `internal/reconcile/reconcile.go:54-67,157,184-185,201-202,248-262,273-274,324,330-331,340-341,372-373`
- Test: `internal/reconcile/reconcile_test.go`

- [ ] **Step 1: Migrate the existing assertions.**

Run:

```bash
perl -pi -e 's/wantContains\(t, "Warnings", (\w+)\.Warnings/wantContains(t, "Warnings", messages($1.Warnings)/g' internal/reconcile/reconcile_test.go
```

`wantContains(t, "warnings", warnings, …)` on `CollapseTargets`' result is lowercase and stays as it is: that function still returns strings.

- [ ] **Step 2: Write the failing test.** Append to `internal/reconcile/reconcile_test.go`:

```go
// messages is the stderr text of ws.
func messages(ws []Warning) []string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.Message)
	}
	return out
}

// TestWarningKinds pins each site's kind and structured fields. The messages
// stay pinned by the tests above.
func TestWarningKinds(t *testing.T) {
	k4, k9 := testkeys.Line(t, 4), testkeys.Line(t, 9)
	fp4, fp9 := mustFP(t, k4), mustFP(t, k9)
	web1Differs := []sshcfg.Host{{Alias: "web-1", HostName: "9.9.9.9", User: "deploy"}}
	for _, tt := range []struct {
		name  string
		cfg   *config.Config
		hosts []sshcfg.Host
		users []identity.User
		want  Warning
	}{
		{
			name: "revoked pub",
			cfg: parseCfg(t, "servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\nrevoked:\n"+
				"  - {fingerprint: "+fp9+", user: alice, date: 2026-11-08}\n"),
			users: []identity.User{{Name: "me", Source: "~/.ssh/id_old", Key: k9, Servers: []string{"web-1"}}},
			want:  Warning{Kind: KindRevokedPubSkipped, Identity: "~/.ssh/id_old.pub", Fingerprint: fp9, User: "alice", Date: "2026-11-08"},
		},
		{
			name: "revoked access",
			cfg: parseCfg(t, `
users:
  - {name: bob, keys: ["`+k4+`"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy}
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: bob, servers: [web-1]}
revoked:
  - {user: bob, servers: [db-1], date: 2026-11-08}
`),
			users: []identity.User{{Name: "bob", Source: "~/.ssh/id_bob", Key: k4, Servers: []string{"db-1"}}},
			want:  Warning{Kind: KindRevokedAccessSkipped, Identity: "~/.ssh/id_bob.pub", Server: "db-1", Fingerprint: fp4, User: "bob", Date: "2026-11-08"},
		},
		{
			name:  "server differs",
			cfg:   baseCfg(t),
			hosts: web1Differs,
			want:  Warning{Kind: KindMergeConflict, Server: "web-1"},
		},
		{
			name:  "alias targets a manifest server",
			cfg:   baseCfg(t),
			hosts: []sshcfg.Host{{Alias: "web1.example.com", HostName: "10.0.0.1", User: "deploy"}},
			want:  Warning{Kind: KindMergeConflict, Server: "web1.example.com"},
		},
		{
			name:  "wildcard compaction",
			cfg:   baseCfg(t),
			users: []identity.User{{Name: "dave", Source: "~/.ssh/dave", Key: k9, Servers: []string{"db-1", "web-1"}}},
			want:  Warning{Kind: KindWildcardGrant, User: "dave"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := mustBuild(t, tt.cfg, tt.hosts, tt.users)
			if len(p.Warnings) != 1 {
				t.Fatalf("Warnings = %q, want one", messages(p.Warnings))
			}
			got := p.Warnings[0]
			if got.Message == "" {
				t.Error("Message is empty")
			}
			got.Message = ""
			if got != tt.want {
				t.Errorf("Warning = %+v, want %+v", got, tt.want)
			}
		})
	}
	t.Run("user with no surviving server", func(t *testing.T) {
		p := mustBuild(t, baseCfg(t), web1Differs, []identity.User{{Name: "dave", Source: "~/.ssh/dave", Key: k9, Servers: []string{"web-1"}}})
		if len(p.Warnings) != 2 || p.Warnings[1].Kind != KindMergeConflict || p.Warnings[1].User != "dave" {
			t.Errorf("Warnings = %+v", p.Warnings)
		}
	})
}
```

- [ ] **Step 3: Run it to verify it fails.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/reconcile -run TestWarningKinds`
Expected: FAIL to build, `undefined: Warning`.

- [ ] **Step 4: Implement.** In `reconcile.go`, change `Plan.Warnings` (line 63) to `Warnings   []Warning`, and add above `Plan`:

```go
// The Warning kinds reconcile assigns. Consumers ignore kinds they do not
// know.
const (
	KindMergeConflict        = "merge_conflict"
	KindRevokedPubSkipped    = "revoked_pub_skipped"
	KindRevokedAccessSkipped = "revoked_access_skipped"
	KindWildcardGrant        = "wildcard_grant"
)

// Warning is one finding for the operator. Message is the stderr text; the
// other fields are the structured form --json carries, omitted when they do
// not apply. Identity is the .pub path the key came from.
type Warning struct {
	Kind        string `json:"kind"`
	Server      string `json:"server,omitempty"`
	Identity    string `json:"identity,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	User        string `json:"user,omitempty"`
	Date        string `json:"date,omitempty"`
	Message     string `json:"message"`
}
```

Add `json:"user"` and `json:"servers"` tags to `Extension` (import's document encodes it directly):

```go
type Extension struct {
	User    string   `json:"user"`
	Servers []string `json:"servers"`
}
```

Replace each append. In `servers`:

```go
				b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindMergeConflict, Server: h.Alias,
					Message: sameTarget(h.Alias, owner, "manifest server")})
```

```go
		b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindMergeConflict, Server: h.Alias,
			Message: fmt.Sprintf("server %q in the ssh config differs from the manifest (host/port/user) — manifest kept", h.Alias)})
```

In `users`:

```go
			b.plan.Warnings = append(b.plan.Warnings, Warning{
				Kind: KindRevokedPubSkipped, Identity: pubPath(u.Source), Fingerprint: k.Fingerprint, User: t.User, Date: t.Date,
				Message: fmt.Sprintf("key %s from %s is REVOKED (%s) — not imported", k.Fingerprint, pubPath(u.Source), t.Label()),
			})
```

In `knownKey`:

```go
		case b.conflicted[srv]:
			b.plan.conflicts++
			b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindMergeConflict, Server: srv, User: owner.Name,
				Message: fmt.Sprintf("access for %q to %q dropped: the server conflicts with the manifest", owner.Name, srv)})
		case owner.Operator:
		case b.cfg.Covers(owner.Name, srv):
		case b.cfg.ExceptCarveOut(owner.Name, srv):
			b.plan.conflicts++
			b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindMergeConflict, Server: srv, User: owner.Name,
				Message: fmt.Sprintf("key of %q used for %q in the ssh config, which their except: list deliberately excludes — not re-granted; audit flags this drift",
					owner.Name, srv)})
		default:
			if t, gone := b.cfg.AccessRevoked(owner.Name, srv); gone {
				b.plan.conflicts++
				b.plan.Warnings = append(b.plan.Warnings, Warning{
					Kind: KindRevokedAccessSkipped, Identity: pubPath(u.Source), Server: srv, Fingerprint: fp, User: owner.Name, Date: t.Date,
					Message: fmt.Sprintf("key %s of %q found on %q, whose access was revoked (%s) — not re-granted; audit flags this drift",
						fp, owner.Name, srv, t.Date),
				})
				continue
			}
			extended = b.extend(owner.Name, srv) || extended
```

```go
		if extended {
			b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindMergeConflict, Fingerprint: fp, User: owner.Name,
				Message: fmt.Sprintf("key %s from the ssh config belongs to manifest user %q — extending their access", fp, owner.Name)})
		} else {
```

In `newUser`:

```go
		if len(dropped) > 0 {
			b.plan.conflicts++
			b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindMergeConflict, User: u.Name, Message: notAdded(u.Name, dropped)})
		}
		return
	}
	for _, srv := range dropped {
		b.plan.conflicts++
		b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindMergeConflict, Server: srv, User: u.Name,
			Message: fmt.Sprintf("access for %q to %q dropped: the server conflicts with the manifest", u.Name, srv)})
	}
```

```go
		servers = []string{"*"}
		b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindWildcardGrant, User: name,
			Message: fmt.Sprintf("access for %q covers every server; emitted as wildcard %q (includes servers added later)", name, "*")})
```

In `claim`:

```go
	if renamed {
		b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindMergeConflict, User: name,
			Message: fmt.Sprintf("user name %q already taken, using %q for the incoming key", want, name)})
	}
```

In `cmd/sshepherd/import.go`, make the two readers compile:

```go
	for _, w := range plan.Warnings {
		log.Warn(w.Message)
	}
```

```go
	for _, w := range plan.Warnings {
		comments = append(comments, "WARNING: "+w.Message)
	}
```

- [ ] **Step 5: Run the tests.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/reconcile ./cmd/sshepherd -run 'TestWarningKinds|TestBuild|TestReconcile|TestRenderMergedImport|TestImportMerge'`
Expected: PASS. No golden changes (`import_merge.golden` carries the same `WARNING:` lines).

### Task 8: `importRun` and the collector

No behavior changes in this task. Every existing import test must stay green.

**Files:**
- Modify: `cmd/sshepherd/import.go:26-41,52-73,84-146,173-189,194-212,217-228,256-281,357-458`, `cmd/sshepherd/import_test.go:47,72`
- Create: `cmd/sshepherd/import_json.go`

- [ ] **Step 1: Migrate the two test sites.**

Run:

```bash
perl -pi -e 's/skipped\[0\], "nouser"/skipped[0].Message, "nouser"/; s/notes\[0\], "wildcard"/notes[0].Message, "wildcard"/' cmd/sshepherd/import_test.go
```

- [ ] **Step 2: Run to see the migration fail to build.**

Run: `GOTOOLCHAIN=go1.27.3 go vet ./cmd/sshepherd`
Expected: FAIL, `skipped[0].Message undefined (type string has no field or method Message)`.

- [ ] **Step 3: Create the collector.** Create `cmd/sshepherd/import_json.go`:

```go
package main

import (
	"log/slog"

	"github.com/javadh75/SSHepherd/internal/reconcile"
)

// The warning kinds import assigns itself; reconcile assigns the rest.
// Consumers ignore kinds they do not know.
const (
	importWarnSSHConfig     = "ssh_config"
	importWarnIdentity      = "identity"
	importWarnUnsafeHost    = "unsafe_host"
	importWarnCollapsed     = "collapsed_target"
	importWarnProxy         = "proxy_not_mapped"
	importWarnMemoryDropped = "revocation_memory_dropped"
)

// importWarnings is the one collector for import's warnings: each is logged
// as it is found, exactly as the plain run prints it, and kept for --json.
type importWarnings struct {
	log  *slog.Logger
	list []reconcile.Warning
}

func (c *importWarnings) add(w reconcile.Warning) {
	c.log.Warn(w.Message)
	c.list = append(c.list, w)
}

func (c *importWarnings) addAll(kind string, msgs ...string) {
	for _, m := range msgs {
		c.add(reconcile.Warning{Kind: kind, Message: m})
	}
}
```

- [ ] **Step 4: Feed it.** In `import.go`:

Replace the first and last lines of `warnMemoryLost` (the checks between them are unchanged):

```go
func warnMemoryLost(w *importWarnings, out string, force bool) {
```

```go
	w.addAll(importWarnMemoryDropped, fmt.Sprintf("%s holds revocation memory (serial %d, %s) that this fresh import drops: a revoked key could be re-granted; keep it with --merge %s",
		out, cfg.Serial(), apply.Plural(len(cfg.Tombstones), "revoked: entry", "revoked: entries"), hintArg(out)))
```

`dropUnsafeHosts`: the signature becomes `func dropUnsafeHosts(w *importWarnings, hosts []sshcfg.Host) []sshcfg.Host` and the log line becomes:

```go
			w.addAll(importWarnUnsafeHost, fmt.Sprintf("host %q: %s, skipped (not valid in a manifest)", h.Alias, bad))
```

`generateManifest`: the signature becomes `func generateManifest(hosts []sshcfg.Host, users []identity.User, src string) ([]byte, []reconcile.Warning, error)`, `notes` is declared `[]reconcile.Warning`, and the two appends become:

```go
			notes = append(notes, reconcile.Warning{Kind: importWarnSSHConfig, Message: fmt.Sprintf(
				"host %q: no User resolved, skipped (the manifest requires user)", h.Alias)})
```

```go
			notes = append(notes, reconcile.Warning{Kind: reconcile.KindWildcardGrant, User: u.Name, Message: fmt.Sprintf(
				"access for %q covers every server; emitted as wildcard %q (includes servers added later)", u.Name, "*")})
```

`deriveUsers`:

```go
func deriveUsers(w *importWarnings, serversOnly bool, hosts []sshcfg.Host, operators []string) ([]identity.User, error) {
	if serversOnly {
		return nil, nil
	}
	users, warnings, err := resolveUsers(hosts, operators)
	if err != nil {
		return nil, err
	}
	w.addAll(importWarnIdentity, warnings...)
	w.log.Info("derived " + apply.Plural(len(users), "user", "users") + " from identity files")
	return users, nil
}
```

`collapseTargets` and `warnProxies`:

```go
func collapseTargets(w *importWarnings, hosts []sshcfg.Host, users []identity.User) ([]sshcfg.Host, []identity.User) {
	hosts, users, warnings := reconcile.CollapseTargets(hosts, users)
	w.addAll(importWarnCollapsed, warnings...)
	return hosts, users
}
```

```go
func warnProxies(w *importWarnings, hosts []sshcfg.Host) {
	for _, h := range hosts {
		if serverWorthy(h) && h.Proxy != "" {
			w.addAll(importWarnProxy, fmt.Sprintf("host %q: %s set — dialed directly; bastion hosts are not supported yet", h.Alias, h.Proxy))
		}
	}
}
```

`renderImport` and `mergeImport` return the plan, nil outside `--merge` (keep their doc comments):

```go
func renderImport(w *importWarnings, mf *manifest.File, raw []byte, hosts []sshcfg.Host, users []identity.User, src, date string) ([]byte, *reconcile.Plan, error) {
	if mf != nil {
		return mergeImport(w, mf, raw, hosts, users, src, date)
	}
	rendered, notes, err := generateManifest(hosts, users, src)
	if err != nil {
		return nil, nil, err
	}
	for _, n := range notes {
		w.add(n)
	}
	return rendered, nil, nil
}
```

```go
func mergeImport(w *importWarnings, mf *manifest.File, raw []byte, hosts []sshcfg.Host, users []identity.User, src, date string) ([]byte, *reconcile.Plan, error) {
	var worthy []sshcfg.Host
	for _, h := range hosts {
		if !serverWorthy(h) {
			w.addAll(importWarnSSHConfig, fmt.Sprintf("host %q: no User resolved, skipped (the manifest requires user)", h.Alias))
			continue
		}
		worthy = append(worthy, h)
	}
	plan, err := reconcile.Build(mf.Config(), worthy, users)
	if err != nil {
		return nil, nil, fmt.Errorf("merge: %w", err)
	}
	for _, pw := range plan.Warnings {
		w.add(pw)
	}
	for _, n := range plan.Notes {
		w.log.Info(n)
	}
	if plan.Empty() {
		w.log.Info("nothing to merge: the manifest already covers " + src)
		return raw, &plan, nil
	}
	w.log.Info(mergeSummary(plan))
	rendered, err := renderMergedImport(mf, raw, plan, src, date)
	if err != nil {
		return nil, nil, err
	}
	return rendered, &plan, nil
}
```

Replace `newImportCmd` (lines 357-458) with:

```go
// importOpts are import's flags.
type importOpts struct {
	outPath     string
	force       bool
	serversOnly bool
	operators   []string
	mergePath   string
	json        bool
}

// importRun is one import run.
type importRun struct {
	log    *slog.Logger
	stdout io.Writer
	opts   importOpts
}

func (r *importRun) run(args []string) error {
	if r.opts.serversOnly && len(r.opts.operators) > 0 {
		return fmt.Errorf("--operator-key conflicts with --servers-only (operators are users)")
	}
	src := defaultSSHConfig
	if len(args) == 1 {
		src = args[0]
	}
	srcPath, err := expandHome(src)
	if err != nil {
		return err
	}
	// m stays the zero manifestTarget without --merge: -o is then
	// always a new-file publish.
	var (
		m  manifestTarget
		mf *manifest.File
	)
	if r.opts.mergePath != "" {
		// Read FILE up front: failing fast beats converting first,
		// and the store read is what lets an in-place
		// -o FILE --force refuse a concurrent change.
		m, mf, err = loadMergeTarget(r.log, r.opts.mergePath)
		if err != nil {
			return err
		}
	}
	warns := &importWarnings{log: r.log}
	hosts, sshWarnings, err := sshcfg.Load(srcPath)
	if err != nil {
		return fmt.Errorf("load ssh config: %w", err) // wrapcheck: wrap at package boundary
	}
	parsed := len(hosts)
	r.log.Info("parsed " + src + ": " + apply.Plural(parsed, "host", "hosts"))
	warns.addAll(importWarnSSHConfig, sshWarnings...)
	hosts = dropUnsafeHosts(warns, hosts)
	users, err := deriveUsers(warns, r.opts.serversOnly, hosts, r.opts.operators)
	if err != nil {
		return err
	}
	hosts, users = collapseTargets(warns, hosts, users)
	warnProxies(warns, hosts)
	// The clock is read only here, so tests inject a fixed date.
	rendered, _, err := renderImport(warns, mf, m.Loaded, hosts, users, src, time.Now().Format("2006-01-02"))
	if err != nil {
		return err
	}
	// Self-check: never emit a manifest our own loader would reject,
	// nor (under --merge) one that keeps a policy conflict (D29).
	saved, err := config.Parse(rendered)
	if err != nil {
		return fmt.Errorf("bug: generated manifest fails validation: %w", err)
	}
	if err := conflictRefusal(formerManifest(m), saved); err != nil {
		return err
	}
	if r.opts.mergePath == "" {
		warnMemoryLost(warns, r.opts.outPath, r.opts.force)
	}
	return emitManifest(r.stdout, m, r.opts.outPath, rendered, r.opts.force)
}

func newImportCmd(a *app, stdout io.Writer) *cobra.Command {
	var opts importOpts
	cmd := &cobra.Command{
		Use:   "import [ssh-config-path]",
		Short: "Convert an OpenSSH client config into a starter manifest",
		Long: "Reads an OpenSSH client config (default ~/.ssh/config), resolves each\n" +
			"concrete Host to the HostName/Port/User that ssh would use, and emits a\n" +
			"valid SSHepherd manifest. users: and access: are derived from each host's\n" +
			"IdentityFile (or ssh's default identities when none is set) by reading the\n" +
			"matching .pub files on this machine — run import where you actually ssh\n" +
			"from, and review the result before use. Private keys are never read.\n" +
			"Keys named via --operator-key become operator users: granted every server\n" +
			"implicitly (no access entry) and protected from removal by future apply.\n" +
			"With --merge FILE the existing manifest FILE is preserved — comments\n" +
			"intact — and only what is genuinely new is appended; on any conflict the\n" +
			"manifest wins and the incoming entry is dropped with a warning.\n" +
			"Warnings about skipped entries go to stderr.\n\n" + exitCodesImport,
		Example: "  # Servers only, as the starting point for adopt\n" +
			"  sshepherd import --servers-only -o sshepherd.yaml\n\n" +
			"  # Servers and users from one config, with an operator key\n" +
			"  sshepherd import ~/.ssh/config --operator-key ~/.ssh/ops.pub -o sshepherd.yaml\n\n" +
			"  # Add hosts that are new in the ssh config to an existing manifest\n" +
			"  sshepherd import --merge sshepherd.yaml -o merged.yaml",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			r := &importRun{log: a.logger, stdout: stdout, opts: opts}
			return r.run(args)
		},
	}
	cmd.Flags().StringVarP(&opts.outPath, "output", "o", "", "write the manifest to this file instead of stdout")
	cmd.Flags().BoolVar(&opts.force, "force", false, "allow --output to overwrite an existing file")
	cmd.Flags().BoolVar(&opts.serversOnly, "servers-only", false, "leave the users and access sections empty (skip identity resolution)")
	cmd.Flags().StringArrayVar(&opts.operators, "operator-key", nil,
		"key file `PATH` whose owner is an operator: granted every server and protected from removal (repeatable)")
	cmd.Flags().StringVar(&opts.mergePath, "merge", "",
		"merge into `FILE`: preserve its text and append what is new")
	return cmd
}
```

- [ ] **Step 5: Run the tests.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestImport|TestGenerateManifest|TestRenderMergedImport|TestQuickStart|TestHelp'`
Expected: PASS, every golden unchanged.

### Task 9: import's document

**Files:**
- Modify: `cmd/sshepherd/import_json.go`
- Create: `cmd/sshepherd/import_json_test.go`, `cmd/sshepherd/testdata/import_json_merge.golden.json`, `cmd/sshepherd/testdata/import_json_generate.golden.json`, `cmd/sshepherd/testdata/import_json_manifest.golden.json`

- [ ] **Step 1: Write the failing test.** Create `cmd/sshepherd/import_json_test.go`:

```go
package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/adopt"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/identity"
	"github.com/javadh75/SSHepherd/internal/manifest"
	"github.com/javadh75/SSHepherd/internal/reconcile"
	"github.com/javadh75/SSHepherd/internal/sshcfg"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func importDocBytes(t *testing.T, doc importDoc) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := writeImportDoc(&out, doc); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

var goldenPlacement = adopt.Placement{Output: &adopt.Output{Path: "fleet.yaml", Written: true}}

func TestImportJSONMergeGolden(t *testing.T) {
	mf, err := manifest.Load(commentedMergeSrc(t))
	if err != nil {
		t.Fatal(err)
	}
	users := mergeImportUsers(t)
	plan, err := reconcile.Build(mf.Config(), mergeImportHosts(), users)
	if err != nil {
		t.Fatal(err)
	}
	doc := buildImportDoc(adopt.ModeMerge, goldenPlacement, importStatsOf(3, users), planOutcome(plan), plan.Warnings)
	checkGolden(t, "import_json_merge.golden.json", importDocBytes(t, doc))
}

func TestImportJSONGenerateGolden(t *testing.T) {
	hosts := []sshcfg.Host{
		{Alias: "web-1", HostName: "10.0.0.1", User: "deploy"},
		{Alias: "ci", HostName: "ci.internal", Port: 2222, User: "git"},
		{Alias: "nouser", HostName: "10.0.0.9"},
	}
	users := []identity.User{
		{Name: "javad-work", Source: "~/.ssh/work", Key: testkeys.Line(t, 2), Servers: []string{"web-1", "ci"}},
		{Name: "javad-ops", Source: "~/.ssh/ops", Operator: true, Key: testkeys.Line(t, 3)},
	}
	data, notes, err := generateManifest(hosts, users, "~/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	saved, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	doc := buildImportDoc(adopt.ModeGenerate, goldenPlacement, importStatsOf(3, users), freshOutcome(saved), notes)
	checkGolden(t, "import_json_generate.golden.json", importDocBytes(t, doc))
}

// TestImportJSONManifestGolden: with no -o the YAML is in the document.
func TestImportJSONManifestGolden(t *testing.T) {
	yaml := "# generated by sshepherd import\nusers: []\n"
	doc := buildImportDoc(adopt.ModeGenerate, adopt.Placement{Manifest: &yaml}, importStats{hosts: 1}, importOutcome{}, nil)
	checkGolden(t, "import_json_manifest.golden.json", importDocBytes(t, doc))
}

// TestImportStatsCountsNonOperatorGrants: an operator has no access entry.
func TestImportStatsCountsNonOperatorGrants(t *testing.T) {
	got := importStatsOf(4, []identity.User{
		{Name: "a", Servers: []string{"x", "y"}},
		{Name: "op", Operator: true, Servers: []string{"x", "y"}},
	})
	if got != (importStats{hosts: 4, users: 2, grants: 2}) {
		t.Errorf("stats = %+v", got)
	}
}

// TestBuildImportDocSanitizes: an ssh config is local, but import's warnings
// quote it, and encoding/json does not escape C1 or Cf runes.
func TestBuildImportDocSanitizes(t *testing.T) {
	csi, bidi := string(rune(0x9b)), string(rune(0x202e))
	hostile := "x" + csi + bidi + "y"
	doc := buildImportDoc(adopt.ModeGenerate, adopt.Placement{}, importStats{},
		importOutcome{notes: []string{hostile}},
		[]reconcile.Warning{{Kind: importWarnSSHConfig, Server: hostile, Identity: hostile, User: hostile, Date: hostile, Message: hostile}})
	text := string(importDocBytes(t, doc))
	if strings.Contains(text, csi) || strings.Contains(text, bidi) {
		t.Errorf("hostile runes survived:\n%q", text)
	}
	if !strings.Contains(text, `"message": "xy"`) || !strings.Contains(text, `"xy"`) {
		t.Errorf("sanitized text missing:\n%s", text)
	}
}

// TestBuildImportDocListsAreNeverNull: a script's .warnings[] must not fail.
func TestBuildImportDocListsAreNeverNull(t *testing.T) {
	text := string(importDocBytes(t, buildImportDoc(adopt.ModeGenerate, adopt.Placement{}, importStats{}, importOutcome{}, nil)))
	for _, field := range []string{`"new_servers": []`, `"new_users": []`, `"extensions": []`, `"warnings": []`, `"notes": []`} {
		if !strings.Contains(text, field) {
			t.Errorf("document lacks %s:\n%s", field, text)
		}
	}
}

// TestNewImportUserUnparseableKey: an entry that cannot be parsed keeps its
// name; fingerprint and type stay empty.
func TestNewImportUserUnparseableKey(t *testing.T) {
	got := newImportUser("a", "not a key", false, nil)
	if got.Name != "a" || got.Fingerprint != "" || got.Type != "" || got.Servers == nil {
		t.Errorf("user = %+v", got)
	}
}
```

- [ ] **Step 2: Run it to verify it fails.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestImportJSON|TestImportStats|TestBuildImportDoc|TestNewImportUser'`
Expected: FAIL to build, `undefined: importDoc`.

- [ ] **Step 3: Implement.** In `import_json.go`, replace the import block with:

```go
import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"github.com/javadh75/SSHepherd/internal/adopt"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/identity"
	"github.com/javadh75/SSHepherd/internal/reconcile"
	"github.com/javadh75/SSHepherd/internal/sanitize"
)
```

and append:

```go
// importSchema marks the document's shape; it stays 1, with additive fields.
const importSchema = 1

type importSummary struct {
	Hosts     int `json:"hosts"`
	Users     int `json:"users"`
	Grants    int `json:"grants"`
	Conflicts int `json:"conflicts"`
	Warnings  int `json:"warnings"`
	ExitCode  int `json:"exit_code"`
}

type importServerJSON struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
	User string `json:"user"`
}

type importUserJSON struct {
	Name        string   `json:"name"`
	Fingerprint string   `json:"fingerprint"`
	Type        string   `json:"type"`
	Operator    bool     `json:"operator,omitempty"`
	Servers     []string `json:"servers"`
}

// importDoc is import's --json document, written only on exit 0. The lists
// are always present; Output and Manifest are mutually exclusive. Notes are
// steady-state findings and are not counted in summary.warnings.
type importDoc struct {
	Schema     int                   `json:"schema"`
	Command    string                `json:"command"`
	Mode       string                `json:"mode"`
	Output     *adopt.Output         `json:"output,omitempty"`
	Manifest   *string               `json:"manifest,omitempty"`
	Summary    importSummary         `json:"summary"`
	NewServers []importServerJSON    `json:"new_servers"`
	NewUsers   []importUserJSON      `json:"new_users"`
	Extensions []reconcile.Extension `json:"extensions"`
	Warnings   []reconcile.Warning   `json:"warnings"`
	Notes      []string              `json:"notes"`
}

// importStats is what the ssh config yielded (hosts as parsed, users after
// target collapse, their server grants without operators).
type importStats struct {
	hosts, users, grants int
}

func importStatsOf(parsed int, users []identity.User) importStats {
	grants := 0
	for _, u := range users {
		if !u.Operator {
			grants += len(u.Servers)
		}
	}
	return importStats{hosts: parsed, users: len(users), grants: grants}
}

// importOutcome is what the output adds: a merge's plan, or a fresh
// manifest, where every entry is new.
type importOutcome struct {
	servers    []importServerJSON
	users      []importUserJSON
	extensions []reconcile.Extension
	conflicts  int
	notes      []string
}

// newImportUser names a key for the report. The line has already passed
// config.Parse or identity resolution, so a failed parse leaves the facts
// empty rather than failing a finished run.
func newImportUser(name, line string, operator bool, servers []string) importUserJSON {
	if servers == nil {
		servers = []string{}
	}
	u := importUserJSON{Name: name, Operator: operator, Servers: servers}
	if k, err := authkeys.ParseLine(line); err == nil && k != nil {
		u.Fingerprint, u.Type = k.Fingerprint, k.Type
	}
	return u
}

func planOutcome(plan reconcile.Plan) importOutcome {
	grants := make(map[string][]string, len(plan.NewGrants))
	for _, g := range plan.NewGrants {
		grants[g.User] = g.Servers
	}
	out := importOutcome{
		servers:    make([]importServerJSON, 0, len(plan.NewServers)),
		users:      make([]importUserJSON, 0, len(plan.NewUsers)),
		extensions: append([]reconcile.Extension{}, plan.Extensions...),
		conflicts:  plan.ConflictsSkipped(),
		notes:      plan.Notes,
	}
	for _, s := range plan.NewServers {
		port := s.Port
		if port == 0 {
			port = 22
		}
		out.servers = append(out.servers, importServerJSON{Name: s.Name, Host: s.Host, Port: port, User: s.User})
	}
	for _, u := range plan.NewUsers {
		out.users = append(out.users, newImportUser(u.Name, u.Keys[0], u.Operator, grants[u.Name]))
	}
	return out
}

func freshOutcome(cfg *config.Config) importOutcome {
	grants := make(map[string][]string, len(cfg.Access))
	for _, a := range cfg.Access {
		grants[a.User] = append(grants[a.User], a.Servers...)
	}
	out := importOutcome{
		servers:    make([]importServerJSON, 0, len(cfg.Servers)),
		users:      make([]importUserJSON, 0, len(cfg.Users)),
		extensions: []reconcile.Extension{},
	}
	for _, s := range cfg.Servers {
		out.servers = append(out.servers, importServerJSON{Name: s.Name, Host: s.Host, Port: s.Port, User: s.User})
	}
	for _, u := range cfg.Users {
		out.users = append(out.users, newImportUser(u.Name, u.Keys[0], u.Operator, grants[u.Name]))
	}
	return out
}

// buildImportDoc assembles the document. The manifest bytes are not
// sanitized (they must equal a plain run's); the warnings and notes are.
func buildImportDoc(mode string, place adopt.Placement, stats importStats, out importOutcome, warnings []reconcile.Warning) importDoc {
	doc := importDoc{
		Schema: importSchema, Command: "import", Mode: mode,
		Output: place.Output, Manifest: place.Manifest,
		Summary: importSummary{Hosts: stats.hosts, Users: stats.users, Grants: stats.grants,
			Conflicts: out.conflicts, Warnings: len(warnings)},
		NewServers: out.servers, NewUsers: out.users, Extensions: out.extensions,
		Warnings: make([]reconcile.Warning, 0, len(warnings)),
		Notes:    make([]string, 0, len(out.notes)),
	}
	if doc.NewServers == nil {
		doc.NewServers = []importServerJSON{}
	}
	if doc.NewUsers == nil {
		doc.NewUsers = []importUserJSON{}
	}
	if doc.Extensions == nil {
		doc.Extensions = []reconcile.Extension{}
	}
	for _, w := range warnings {
		w.Server, w.Identity, w.User = sanitize.Remote(w.Server), sanitize.Remote(w.Identity), sanitize.Remote(w.User)
		w.Date, w.Message = sanitize.Remote(w.Date), sanitize.Remote(w.Message)
		doc.Warnings = append(doc.Warnings, w)
	}
	for _, n := range out.notes {
		doc.Notes = append(doc.Notes, sanitize.Remote(n))
	}
	return doc
}

func writeImportDoc(w io.Writer, doc importDoc) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode import report: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Create the goldens and read them back.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestImportJSON.*Golden' -update && GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestImportJSON|TestImportStats|TestBuildImportDoc|TestNewImportUser'`
Expected: PASS. Read all three files line by line:
- Manifest: `manifest` present, no `output`, every list `[]`.
- Merge: `mode` is `merge`, `extensions` has alice, `conflicts` is the same number `mergeSummary` prints for this fixture, and the warnings are `merge_conflict`.
- Generate: `new_servers[].port` is `22` for `web-1`, the `javad-work` grant is compacted to `["*"]` with a `wildcard_grant` warning, the `nouser` warning is `ssh_config`, and `javad-ops` has `"operator": true` and `"servers": []`.

### Task 10: `import --json`

**Files:**
- Modify: `cmd/sshepherd/import.go`, `cmd/sshepherd/import_json.go`
- Test: `cmd/sshepherd/import_json_test.go`

- [ ] **Step 1: Write the failing tests.** Append to `import_json_test.go`, adding `"encoding/json"`, `"os"`, `"path/filepath"` and `"slices"` to its imports:

```go
// importJSONDoc is what the CLI tests read of import's document.
type importJSONDoc struct {
	Schema  int    `json:"schema"`
	Command string `json:"command"`
	Mode    string `json:"mode"`
	Output  *struct {
		Path    string `json:"path"`
		Written bool   `json:"written"`
	} `json:"output"`
	Manifest *string `json:"manifest"`
	Summary  struct {
		Hosts     int `json:"hosts"`
		Users     int `json:"users"`
		Grants    int `json:"grants"`
		Conflicts int `json:"conflicts"`
		Warnings  int `json:"warnings"`
		ExitCode  int `json:"exit_code"`
	} `json:"summary"`
	NewServers []struct {
		Name string `json:"name"`
		Port int    `json:"port"`
	} `json:"new_servers"`
	NewUsers []struct {
		Fingerprint string   `json:"fingerprint"`
		Servers     []string `json:"servers"`
	} `json:"new_users"`
	Warnings []importJSONWarning `json:"warnings"`
	Notes    []string            `json:"notes"`
}

// importJSONWarning is one warning as a script reads it.
type importJSONWarning struct {
	Kind        string `json:"kind"`
	Server      string `json:"server"`
	Identity    string `json:"identity"`
	Fingerprint string `json:"fingerprint"`
	User        string `json:"user"`
	Date        string `json:"date"`
	Message     string `json:"message"`
}

func importJSONCLI(t *testing.T, args ...string) (int, importJSONDoc, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := run(append([]string{"import", "--json"}, args...), &out, &errBuf)
	dec := json.NewDecoder(&out)
	var doc importJSONDoc
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("exit %d: stdout is not a document: %v (stderr: %s)", code, err, errBuf.String())
	}
	if dec.More() {
		t.Fatalf("stdout holds more than one document")
	}
	return code, doc, errBuf.String()
}

// TestImportJSONManifestMatchesPlainRun is OP3.
func TestImportJSONManifestMatchesPlainRun(t *testing.T) {
	hermeticHome(t)
	path := writeSSHConfig(t, "Host web-1\n  HostName 10.0.0.1\n  User deploy\n")
	var plain, errBuf bytes.Buffer
	if code := run([]string{"import", path, "--servers-only"}, &plain, &errBuf); code != 0 {
		t.Fatalf("plain exit = %d (stderr: %s)", code, errBuf.String())
	}
	code, doc, stderr := importJSONCLI(t, path, "--servers-only")
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	if doc.Manifest == nil || *doc.Manifest != plain.String() {
		t.Errorf("manifest = %v\nwant %q", doc.Manifest, plain.String())
	}
	if doc.Schema != 1 || doc.Command != "import" || doc.Mode != "generate" || doc.Output != nil {
		t.Errorf("doc = %+v", doc)
	}
	if s := doc.Summary; s.Hosts != 1 || s.Users != 0 || s.Grants != 0 || s.Conflicts != 0 || s.Warnings != 0 || s.ExitCode != 0 {
		t.Errorf("summary = %+v", s)
	}
	if len(doc.NewServers) != 1 || doc.NewServers[0].Name != "web-1" || doc.NewServers[0].Port != 22 {
		t.Errorf("new_servers = %+v", doc.NewServers)
	}
	if !strings.Contains(stderr, "parsed "+path+": 1 host") {
		t.Errorf("stderr = %q, want the logs there", stderr)
	}
}

// TestImportJSONOutputFile: with -o the file holds a plain run's bytes, for
// a fresh manifest and for a --merge that really appends.
func TestImportJSONOutputFile(t *testing.T) {
	hermeticHome(t)
	path := writeSSHConfig(t, "Host app-1\n  HostName 10.0.0.5\n  User deploy\n")
	for _, tt := range []struct {
		name        string
		extra       []string
		wantServers int
	}{
		{"generate", nil, 1},
		{"merge that appends", []string{"--merge", writeMergeManifest(t)}, 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			flags := append([]string{path, "--servers-only"}, tt.extra...)
			plain := plainManifestFile(t, append([]string{"import"}, flags...)...)
			dst := filepath.Join(t.TempDir(), "m.yaml")
			code, doc, stderr := importJSONCLI(t, append(slices.Clone(flags), "-o", dst)...)
			if code != 0 {
				t.Fatalf("exit = %d (stderr: %s)", code, stderr)
			}
			if doc.Output == nil || doc.Output.Path != dst || !doc.Output.Written || doc.Manifest != nil {
				t.Errorf("output = %+v, manifest = %v", doc.Output, doc.Manifest)
			}
			got, err := os.ReadFile(dst)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plain) {
				t.Errorf("-o bytes differ from a plain run:\n--- got ---\n%s\n--- want ---\n%s", got, plain)
			}
			if parsed := readCfg(t, dst); len(parsed.Servers) != tt.wantServers {
				t.Errorf("written manifest has %d servers, want %d", len(parsed.Servers), tt.wantServers)
			}
		})
	}
}

// TestImportJSONMerge: what the merge adds, through the real command.
func TestImportJSONMerge(t *testing.T) {
	home := hermeticHome(t)
	keyPath := filepath.Join(home, "work")
	if err := os.WriteFile(keyPath+".pub", []byte(testkeys.Line(t, 7)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := writeMergeManifest(t)
	path := writeSSHConfig(t, "Host app-1\n  HostName 10.0.0.5\n  User deploy\n  IdentityFile "+keyPath+"\n")
	code, doc, stderr := importJSONCLI(t, path, "--merge", m)
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	if doc.Mode != "merge" || doc.Manifest == nil || !strings.Contains(*doc.Manifest, "# hand-maintained fleet manifest") {
		t.Errorf("doc = %+v", doc)
	}
	if len(doc.NewServers) != 1 || doc.NewServers[0].Name != "app-1" {
		t.Errorf("new_servers = %+v", doc.NewServers)
	}
	if len(doc.NewUsers) != 1 || doc.NewUsers[0].Fingerprint != fingerprintOf(t, testkeys.Line(t, 7)) ||
		len(doc.NewUsers[0].Servers) != 1 || doc.NewUsers[0].Servers[0] != "app-1" {
		t.Errorf("new_users = %+v", doc.NewUsers)
	}
	if s := doc.Summary; s.Hosts != 1 || s.Users != 1 || s.Grants != 1 {
		t.Errorf("summary = %+v", s)
	}
}

// TestImportJSONNotesAreNotWarnings: steady state is a note, and a no-op
// merge's manifest is the input byte for byte.
func TestImportJSONNotesAreNotWarnings(t *testing.T) {
	hermeticHome(t)
	m := writeMergeManifest(t)
	path := writeSSHConfig(t, "Host web-1\n  HostName 10.0.0.1\n  User deploy\n")
	want, err := os.ReadFile(m)
	if err != nil {
		t.Fatal(err)
	}
	code, doc, stderr := importJSONCLI(t, path, "--servers-only", "--merge", m)
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	if len(doc.Notes) != 1 || !strings.Contains(doc.Notes[0], "already in the manifest") {
		t.Errorf("notes = %v", doc.Notes)
	}
	if doc.Summary.Warnings != 0 || len(doc.Warnings) != 0 {
		t.Errorf("summary = %+v, warnings = %+v", doc.Summary, doc.Warnings)
	}
	if doc.Manifest == nil || *doc.Manifest != string(want) {
		t.Errorf("manifest = %v, want the input unchanged", doc.Manifest)
	}
}

// TestImportJSONWarningKinds: each string-warning source gets its kind, and
// stderr still prints the same line.
func TestImportJSONWarningKinds(t *testing.T) {
	hermeticHome(t)
	path := writeSSHConfig(t, "Host plain\n  HostName 10.0.0.1\n  User deploy\n  IdentityFile /nope/missing\n"+
		"Host \"web 1\"\n  HostName 10.0.0.2\n  User deploy\n"+
		"Host a b\n  HostName 10.0.0.3\n  User deploy\n"+
		"Host jump\n  HostName 10.0.0.4\n  User deploy\n  ProxyJump bastion\n"+
		"Host nouser\n  HostName 10.0.0.9\n"+
		"Match all\n  User x\n")
	code, doc, stderr := importJSONCLI(t, path)
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	seen := map[string]bool{}
	for _, w := range doc.Warnings {
		seen[w.Kind] = true
		if !strings.Contains(stderr, w.Message) {
			t.Errorf("stderr lacks %q:\n%s", w.Message, stderr)
		}
	}
	for _, kind := range []string{importWarnSSHConfig, importWarnIdentity, importWarnUnsafeHost, importWarnCollapsed, importWarnProxy} {
		if !seen[kind] {
			t.Errorf("no %s warning in %+v", kind, doc.Warnings)
		}
	}
	if doc.Summary.Warnings != len(doc.Warnings) {
		t.Errorf("summary.warnings = %d, %d warnings", doc.Summary.Warnings, len(doc.Warnings))
	}
}

func TestImportJSONMemoryDroppedWarning(t *testing.T) {
	hermeticHome(t)
	path := writeSSHConfig(t, "Host web-1\n  HostName 10.0.0.1\n  User deploy\n")
	dst := writeConfig(t, "serial: 3\nusers: []\nservers: []\naccess: []\n")
	code, doc, stderr := importJSONCLI(t, path, "--servers-only", "-o", dst, "--force")
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	if len(doc.Warnings) != 1 || doc.Warnings[0].Kind != importWarnMemoryDropped {
		t.Errorf("warnings = %+v", doc.Warnings)
	}
}

// TestImportJSONMergeSkipKinds drives the kinds no other test sends through
// the collector: both P04 skips in their shapes, a merge conflict and the
// --merge no-User skip (decision 10).
func TestImportJSONMergeSkipKinds(t *testing.T) {
	home := hermeticHome(t)
	oldKey, bobKey := filepath.Join(home, "old"), filepath.Join(home, "bob")
	for keyPath, seed := range map[string]byte{oldKey: 9, bobKey: 4} {
		if err := os.WriteFile(keyPath+".pub", []byte(testkeys.Line(t, seed)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fp9, fp4 := fingerprintOf(t, testkeys.Line(t, 9)), fingerprintOf(t, testkeys.Line(t, 4))
	m := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 4)+"]}\n"+
		"servers:\n  - {name: db-1, host: 10.0.0.3, user: deploy}\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n"+
		"access:\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [web-1]}\n"+
		"revoked:\n  - {fingerprint: "+fp9+", user: old, date: 2026-11-08}\n  - {user: bob, servers: [db-1], date: 2026-11-08}\n")
	path := writeSSHConfig(t, "Host app-1\n  HostName 10.0.0.5\n  User deploy\n  IdentityFile "+oldKey+"\n"+
		"Host db-1\n  HostName 10.0.0.3\n  User deploy\n  IdentityFile "+bobKey+"\n"+
		"Host web-1\n  HostName 9.9.9.9\n  User deploy\n"+
		"Host nouser\n  HostName 10.0.0.9\n")
	code, doc, stderr := importJSONCLI(t, path, "--merge", m)
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	byKind := map[string]importJSONWarning{}
	for _, w := range doc.Warnings {
		byKind[w.Kind] = w
		if !strings.Contains(stderr, w.Message) {
			t.Errorf("stderr lacks %q:\n%s", w.Message, stderr)
		}
	}
	for kind, want := range map[string]importJSONWarning{
		reconcile.KindRevokedPubSkipped:    {Identity: oldKey + ".pub", Fingerprint: fp9, User: "old", Date: "2026-11-08"},
		reconcile.KindRevokedAccessSkipped: {Identity: bobKey + ".pub", Server: "db-1", Fingerprint: fp4, User: "bob", Date: "2026-11-08"},
		reconcile.KindMergeConflict:        {Server: "web-1"},
		importWarnSSHConfig:                {},
	} {
		got, ok := byKind[kind]
		if !ok {
			t.Errorf("no %s warning in %+v", kind, doc.Warnings)
			continue
		}
		want.Kind, want.Message = kind, got.Message
		if got != want {
			t.Errorf("%s = %+v, want %+v", kind, got, want)
		}
	}
	if !strings.Contains(byKind[importWarnSSHConfig].Message, "nouser") {
		t.Errorf("ssh_config message = %q, want the no-User host named", byKind[importWarnSSHConfig].Message)
	}
	if doc.Summary.Warnings != len(doc.Warnings) {
		t.Errorf("summary.warnings = %d, %d warnings", doc.Summary.Warnings, len(doc.Warnings))
	}
}

// TestImportJSONWildcardGrant: a generated grant covering every server is a
// warning, as on stderr.
func TestImportJSONWildcardGrant(t *testing.T) {
	home := hermeticHome(t)
	keyPath := filepath.Join(home, "work")
	if err := os.WriteFile(keyPath+".pub", []byte(testkeys.Line(t, 7)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeSSHConfig(t, "Host a\n  HostName 10.0.0.1\n  User deploy\n  IdentityFile "+keyPath+"\n"+
		"Host b\n  HostName 10.0.0.2\n  User deploy\n  IdentityFile "+keyPath+"\n")
	code, doc, stderr := importJSONCLI(t, path)
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	if len(doc.Warnings) != 1 || doc.Warnings[0].Kind != reconcile.KindWildcardGrant || doc.Warnings[0].User == "" ||
		!strings.Contains(stderr, doc.Warnings[0].Message) {
		t.Errorf("warnings = %+v (stderr: %s)", doc.Warnings, stderr)
	}
	if doc.Summary.Warnings != 1 || len(doc.NewUsers) != 1 || len(doc.NewUsers[0].Servers) != 1 || doc.NewUsers[0].Servers[0] != "*" {
		t.Errorf("summary = %+v, new_users = %+v", doc.Summary, doc.NewUsers)
	}
}

// TestImportJSONMergeEmptyManifest: a no-op merge of a 0-byte file emits zero
// bytes, and the document still has the field (OP3).
func TestImportJSONMergeEmptyManifest(t *testing.T) {
	hermeticHome(t)
	m := writeConfig(t, "")
	path := writeSSHConfig(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", "--json", path, "--servers-only", "--merge", m}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"manifest": ""`) {
		t.Errorf("stdout = %s, want an empty manifest field", out.String())
	}
}

// TestImportJSONToolErrorNoDocument: import never writes a document on exit
// 3. want pins the message, so an unknown --json flag cannot pass.
func TestImportJSONToolErrorNoDocument(t *testing.T) {
	hermeticHome(t)
	path := writeSSHConfig(t, "Host web-1\n  HostName 10.0.0.1\n  User deploy\n")
	taken := filepath.Join(t.TempDir(), "taken.yaml")
	if err := os.WriteFile(taken, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// carol's key stays listed while revoked: a policy conflict, refused only
	// after the render.
	conflicted := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: carol, keys: ["+qk(t, 7)+"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\naccess:\n  - {user: alice, servers: [web-1]}\n"+
		"revoked:\n  - {fingerprint: "+fingerprintOf(t, testkeys.Line(t, 7))+", user: old, date: 2026-11-08}\n")
	for name, tt := range map[string]struct {
		args []string
		want string
	}{
		"missing ssh config":          {[]string{"import", "--json", "/no/such/ssh_config"}, "load ssh config"},
		"-o exists, no --force":       {[]string{"import", "--json", path, "--servers-only", "-o", taken}, "already exists; pass --force"},
		"--merge keeps a conflict":    {[]string{"import", "--json", path, "--servers-only", "--merge", conflicted}, "refusing to write the manifest"},
		"--operator-key with servers": {[]string{"import", "--json", path, "--operator-key", "x", "--servers-only"}, "--operator-key conflicts with --servers-only"},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			if code := run(tt.args, &out, &errBuf); code != 3 {
				t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
			}
			if out.Len() != 0 {
				t.Errorf("stdout = %q, want no document", out.String())
			}
			if !strings.Contains(errBuf.String(), tt.want) {
				t.Errorf("stderr = %q, want %q", errBuf.String(), tt.want)
			}
		})
	}
}
```

`fingerprintOf` and `plainManifestFile` come from round 1's `adopt_json_test.go`. If that lane renamed them, use the new names.

- [ ] **Step 2: Run them to verify they fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestImportJSON(ManifestMatches|Output|Merge|Notes|Warning|Wildcard|Memory|ToolError)'`
Expected: FAIL: `unknown flag: --json`, so stdout does not decode, and `TestImportJSONToolErrorNoDocument` fails its `want` assertion on every row.

- [ ] **Step 3: Wire it.** In `import.go`'s `importRun.run`, change the `renderImport` line to keep the plan:

```go
	rendered, plan, err := renderImport(warns, mf, m.Loaded, hosts, users, src, time.Now().Format("2006-01-02"))
```

and replace the final `emitManifest` return with:

```go
	if !r.opts.json {
		return emitManifest(r.stdout, m, r.opts.outPath, rendered, r.opts.force)
	}
	return r.finishJSON(m, rendered, saved, plan, importStatsOf(parsed, users), warns.list)
```

Add to `newImportCmd`'s `Example`, after the merge example (keep the concatenation):

```go
			"  sshepherd import --merge sshepherd.yaml -o merged.yaml\n\n" +
			"  # A report for a script; the manifest goes to the file\n" +
			"  sshepherd import --json -o sshepherd.yaml",
```

Add the flag after `--merge`:

```go
	cmd.Flags().BoolVar(&opts.json, "json", false, "emit a machine-readable report on stdout (the manifest goes to -o, or into the report's manifest field)")
```

Append to `import_json.go`:

```go
// finishJSON emits the manifest and then the document, so a refused -o
// (exit 3) leaves stdout empty. A nil plan means a fresh manifest.
func (r *importRun) finishJSON(m manifestTarget, rendered []byte, saved *config.Config, plan *reconcile.Plan, stats importStats, warnings []reconcile.Warning) error {
	place, err := placeManifest(m, r.opts.outPath, rendered, r.opts.force)
	if err != nil {
		return err
	}
	mode, outcome := adopt.ModeGenerate, freshOutcome(saved)
	if plan != nil {
		mode, outcome = adopt.ModeMerge, planOutcome(*plan)
	}
	return writeImportDoc(r.stdout, buildImportDoc(mode, place, stats, outcome, warnings))
}
```

- [ ] **Step 4: Run the tests.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestImport|TestBuildImportDoc|TestNewImportUser|TestGenerateManifest|TestRenderMergedImport|TestQuickStart'`
Expected: PASS.

### Task 11: help golden and hand back

**Files:**
- Modify: `cmd/sshepherd/testdata/help/import.golden`

- [ ] **Step 1: See the golden fail, then regenerate it.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run TestHelpGolden`
Expected: FAIL on `import`. Then run `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run TestHelpGolden -update` and read `import.golden` back: the only changes are the fourth example and the `--json` flag line.

- [ ] **Step 2: Apply the docsDelta to the worktree's `README.md` (gate only).**

**docsDelta (`README.md`, import):**

In `### sshepherd import [ssh-config-path]`'s flag table, after the `--merge FILE` row, add:

```markdown
| `--json` | off | Machine-readable report on stdout (schema 1); the manifest goes to `-o`, or into the report's `manifest` field |
```

After the flag table (before ``--merge` is strictly additive``), add:

````markdown
`--json` replaces the manifest on stdout with one report (schema 1), and changes nothing else: logs stay on stderr and the manifest bytes match a plain run exactly. With `-o` the manifest goes to the file and the report has `output`; without it the report has `manifest`, so `sshepherd import --json | jq -j .manifest` prints what a plain run prints. Exit `0` writes a report; exit `3` writes none, only a message on stderr. `new_servers`, `new_users` and `extensions` list what the output adds, and `summary` counts what the ssh config yielded. `notes` are steady-state findings and are not counted in `summary.warnings`. `warnings` has the kinds `revoked_pub_skipped`, `revoked_access_skipped`, `ssh_config`, `identity`, `unsafe_host`, `collapsed_target`, `proxy_not_mapped`, `merge_conflict`, `wildcard_grant` and `revocation_memory_dropped`; ignore kinds you do not know.

```json
<copy cmd/sshepherd/testdata/import_json_merge.golden.json verbatim>
```
````

In `### sshepherd validate`, in the paragraph that starts `` `--json` writes one document``, add after the sentence ending `writes no document.`:

```markdown
`import` and `adopt` are the opposite: they write a document on almost no exit `3`, only `adopt --partial` with no server read does.
```

In `## Exit codes`, after the table and before `` `--help` shows this summary``, add:

```markdown
With `--json`, `audit`, `apply`, `revoke`, `rotate` and `validate` write their report as their own sections say. `adopt` writes one on exit `0` and `1`, with `emitted` saying whether a manifest was produced, and on exit `3` only for `--partial` with no server read. `import` writes one only on exit `0`.
```

In the `## Status` table, change the `import` row's `(`--merge` supported)` to `(`--merge` supported, text + `--json`)`.

- [ ] **Step 3: Gate and hand back.** Run `make check`. Then `git add -A`, unstage every path outside the lane's globs (`README.md` and `CLAUDE.md` always), and write the patch.

---

## Task 12: integrator (no lane owns this)

- [ ] **Step 1: Per lane, in merge order `adopt`, `import`:** `git apply` the patch, apply that lane's `docsDelta` to `README.md` (Task 6 Step 2, Task 11 Step 2), and replace each `<copy …>` with the golden it names. Run `make check`, plus `make integration` for lane `adopt`. Commit the patch, README and the CLAUDE.md block for that lane together. Lane `import`'s commit also carries Step 2.

- [ ] **Step 2: Design amendments** (commit with lane `import`) in `docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`:

  1. Header `Status`: add `S8 built (plan 2026-11-09-p10-s8-import-adopt-json)` beside S1 and S2.
  2. In S8's **Warning kinds**, after the adopt list add `` `weak_key_skipped` (P09, added by the S8 plan) ``. After the import list add `` `wildcard_grant` and `revocation_memory_dropped` (warnings that exist today, added by the S8 plan); a host with no `User` is `ssh_config` ``.
  3. In S8's **Mechanics**, after `Warning{Kind, Server, Fingerprint, User, Date, Message}` add `` (`reconcile.Warning` also has P04's `Identity`) ``.
  4. In S8's **Files** and the S8 row of "Order and parallel lanes", delete `internal/sshcfg` (`sshcfg.Load` already returns its warnings) and add `manifest_out.go`.
  5. After the `unreadable` example, add: `` `unreadable` holds servers that could not be read, each with `error_kind`. A line adopt could not use on a server it did read is a row of the additive, always-present `line_issues: [{server, detail}]`; `summary.partly_read` counts those servers. ``
  6. In S8's **Mechanics**, after "one collector in `import_json.go`" add `` (the helpers receive the collector, so each message logs at today's point) ``.
  7. At line 440, change `jq -r .manifest` to `jq -j .manifest` (`jq -r` appends a newline, so its bytes differ from a plain run's).

- [ ] **Step 3: CLAUDE.md Status** (append after the flag-renames paragraph). Lane `adopt`'s commit appends this:

```markdown
**`adopt --json`** (P10 S8, owner rule, OP3; section S8 of
`docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`): one schema-1 discovery
and warnings report on stdout; the manifest goes to `-o` (`output.written`) or the `manifest`
field, byte-identical to a plain run, and logs stay on stderr. A document on exit 0 and 1 and on
exit 3 only for `--partial` with no server read; `unreadable` (with `error_kind`) holds transport
failures and `line_issues` the lines adopt could not use. `adopt.Plan.Warnings` is structured,
`internal/adopt/json.go` renders it, and the body moved to `adoptRun`. `import --json` follows.
```

Lane `import`'s commit replaces that paragraph with the full block:

```markdown
**`import --json` and `adopt --json`** (P10 S8, owner rule, OP3; specced in section S8 of
`docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`, planned in
`docs/superpowers/plans/2026-11-09-p10-s8-import-adopt-json.md`): every command now offers
`--json`. Both write one schema-1 discovery and warnings report on stdout; the manifest goes to
`-o` (`output.written`) or into the `manifest` field, byte-identical to a plain run, and logs
stay on stderr. `adopt` writes a document on exit 0 and 1 (`emitted` says whether a manifest was
produced) and on exit 3 only for `--partial` with no server read; `import` only on exit 0.
`unreadable` (with `error_kind`) holds transport failures and `line_issues` the lines adopt
could not use. `adopt.Plan.Warnings` and `reconcile.Plan.Warnings` are structured
(`Warning{Kind, …, Message}`, stderr still prints `Message`), `internal/adopt/json.go` renders
adopt's document, and `cmd/sshepherd/import_json.go` renders import's and holds the one
collector that assigns kinds to its string warnings. Command bodies moved to `adoptRun` and
`importRun`.
```

- [ ] **Step 4:** Confirm `TestHelpMatchesREADMETables` and `TestHelpExamplesAndExitCodes` pass with the README as committed, and that the README samples equal the goldens byte for byte.

## Task 13: independent verifier (no lane owns this)

Check against `master` after Task 12 and report findings; change nothing.

- [ ] `adopt --json` on each row of the design's exit table: 0 (document, `emitted: true`), 1 strict (`false`), 1 `--partial` (`true`), 3 (no document), 3 `--partial` zero-read (document, `false`).
- [ ] `import --json`: 0 (document), 3 (no document).
- [ ] With no `-o`, `jq -j .manifest` equals a plain run's stdout byte for byte (regenerate mode, a merge that appends, and a no-op merge). `jq -r` does not, because it appends a newline.
- [ ] `git diff ce9efcd -- cmd/sshepherd/testdata internal/adopt/testdata` changes only `help/adopt.golden`, `help/import.golden` and the seven new JSON goldens (adopt: `json_emitted`, `json_stopped`, `json_zero_read`, `json_manifest`; import: `import_json_merge`, `import_json_generate`, `import_json_manifest`), so text output did not move.
- [ ] Every free-text field that neither `config.Parse` nor a parser validated passes through `sanitize.Remote`: warnings (`server`, `identity`, `user`, `date`, `message`), `notes`, and the text of `unreadable` and `line_issues`. The exempt fields are the ones decision 13 lists, and `manifest` is untouched.
- [ ] Every `unreadable` row has `error_kind`; a partly read server appears only in `line_issues`; an emitted empty manifest still has `"manifest": ""`.
- [ ] `go list -deps ./internal/adopt` names no cobra or transport package (`make layering`).
- [ ] The design amendments of Task 12 Step 2 match the code. No other design text changed.

## Review log

Two independent reviews of the draft, each issue checked against `ce9efcd` and the design. All were applied; none was rejected.

| Issue | Change |
|---|---|
| R0.1 | Added `json_zero_read`, `json_manifest` and `import_json_manifest` goldens; Task 13 counts seven. |
| R0.2 | `TestAdoptJSONOutputFile` and `TestImportJSONOutputFile` compare `-o` bytes with a plain run, generate and a `--merge` that appends. |
| R0.3 | Verified against the design's named test and sample. `unreadable` carries only `Issue.Kind != ""` rows, always with `error_kind` (`ErrorKindOf` never returns `""` for an error); new additive `line_issues`. |
| R0.4, R0.5 | Document-level coverage of `revoked_access_skipped` and `revoked_pub_skipped`, `merge_conflict`, the `--merge` no-User `ssh_config` site, and `wildcard_grant` through the CLI. |
| R0.6 | `TestAdoptJSONHostileRemoteComment` added; the unit test stays. |
| R0.7 | Confirmed by running jq (`61 0a 0a`). `jq -j` in the README, verifier and design line 440. |
| R0.8 | `Placement.Manifest`, `jsonDoc.Manifest` and `importDoc.Manifest` are `*string`; a 0-byte `--merge` document has `"manifest": ""`. |
| R0.9 | Tool-error rows for the post-render `conflictRefusal`, a bad `--identity`, and `--operator-key` with `--servers-only`. |
| R0.10, R1.4 | Decision 13 and Task 13 narrowed to fields not already validated, with the exempt list. Verified: `RenderTextIssue`, `ServerFieldIssue` and `sanitizeName`. |
| R0.11 | Design gap 6 and a Task 12 amendment. |
| R0.12, R1.3 | Lane `adopt` has its own CLAUDE.md text; lane `import` replaces it. |
| R1.1 | `jsonExtension(e)` (S1016). |
| R1.2 | Tool-error tests pin a message, so they fail before `--json` exists. |
| R1.5 | The sanitize fixture's `Issue.Server` is hostile, on both issue shapes. |
| R1.6 | Citations corrected to `import.go:126` and `manifest_out.go:41`. |

---

## Wave lanes (for the runner)

- **`plan`** (the runner's `args.plan`): `docs/superpowers/plans/2026-11-09-p10-s8-import-adopt-json.md`, committed before round 1.
- **`handoffs`** (the runner's `args.handoffs`), one entry: "P10-S8, per lane in the order adopt, import: git apply that lane's patch, apply its docsDelta to README.md (Task 6 Step 2, Task 11 Step 2) replacing each `<copy …>` with the named golden verbatim, then make check (make integration for lane adopt), then commit patch, README and that lane's CLAUDE.md text together, one commit per lane. TestHelpMatchesREADMETables reads README and the patch carries no README change. Lane import's commit also carries Task 12 Step 2. A README.md entry in foreignBreaks is the gate-only delta, not a break."

Rounds run in sequence; lanes inside a round own disjoint files and build only on the previous rounds' commits. Globs are shell `case` patterns (`*` crosses `/`). `README.md` and `CLAUDE.md` are integrator-only: each lane reports its `docsDelta`, applies it to its own worktree for the gate, and the ownership filter drops it. **The integrator must re-apply a lane's `docsDelta` after its patch and before `make check`.**

```json
{
  "rounds": [
    [
      {
        "pkg": "P10-S8",
        "lane": "adopt",
        "kind": "fix",
        "ids": ["owner-rule"],
        "tasks": "Tasks 1-6",
        "files": [
          "internal/adopt/*",
          "cmd/sshepherd/adopt.go",
          "cmd/sshepherd/adopt_json_test.go",
          "cmd/sshepherd/manifest_out.go",
          "cmd/sshepherd/manifest_out_test.go",
          "cmd/sshepherd/testdata/help/adopt.golden"
        ],
        "needsIntegration": true
      }
    ],
    [
      {
        "pkg": "P10-S8",
        "lane": "import",
        "kind": "fix",
        "ids": ["owner-rule"],
        "tasks": "Tasks 7-11",
        "files": [
          "internal/reconcile/*",
          "cmd/sshepherd/import.go",
          "cmd/sshepherd/import_json.go",
          "cmd/sshepherd/import_json_test.go",
          "cmd/sshepherd/import_test.go",
          "cmd/sshepherd/testdata/import_json_*.golden.json",
          "cmd/sshepherd/testdata/help/import.golden"
        ],
        "needsIntegration": false
      }
    ]
  ],
  "mergeOrder": ["P10-S8"]
}
```

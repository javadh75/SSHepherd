# `revoke` and `rotate` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `sshepherd revoke USER...`, `sshepherd revoke --key KEY...` and `sshepherd rotate USER --old KEY --new KEY`: comment-preserving manifest edits that are confirmed once, saved once (locked, compare-and-swap, atomic) after confirmation and before the first remote write, and pushed through `apply`'s existing plan → guard → CAS write → verify → login-probe pipeline on exactly the servers whose rendered `authorized_keys` changes.

**Architecture:** `internal/manifest` gains four node-tree edits (`RemoveUser`, `RemoveKey`, `ReplaceKey`, `SetOperator`) with explicit comment-rescue rules; `internal/apply` gains the pure `Affected` scope computation, the edit header/prompt renderers, `(revoked)`/`(rotated out)` plan labels and the pluralization fix; `cmd/sshepherd` turns apply's run body into `runApply(applyRun)` (plain `apply` keeps its behavior plus a pre-write manifest re-check), adds KEY classification (`keyarg.go`) and the locked CAS manifest save (`edit.go`), and builds `revoke`/`rotate` on a shared edit driver (`editrun.go`).

**Tech Stack:** Go 1.26, `gopkg.in/yaml.v3` node API, `golang.org/x/crypto/ssh`, Cobra, `syscall.Flock` (linux/darwin), `internal/sshconn/sshtest` hermetic SSH servers, Docker sshd for integration/E2E, `go test -fuzz`.

**Spec:** [`docs/superpowers/specs/2026-10-23-revoke-rotate-design.md`](../specs/2026-10-23-revoke-rotate-design.md) (owner-approved). Every code block below was compiled and its tests run (unit, `-race`, hermetic, the Docker integration/E2E suite, and both fuzzers) before this plan was written; expected outputs are real.

---

## Execution groups and stages

Agents each execute **one group**. Groups in the same stage own **disjoint files** and run in parallel; a later stage starts only after the earlier stage is merged.

| Stage | Group | Owns (exclusively) | Tasks |
| ----- | ----- | ------------------ | ----- |
| 1 | **M** — manifest edits | `internal/manifest/**` | M1–M4 |
| 1 | **A** — apply scope, header, labels, plurals | `internal/apply/**` | A1–A4 |
| 2 | **C1** — run body, KEY classification, manifest save | `cmd/sshepherd/{apply,apply_test,edit,edit_test,edit_save_test,edit_lock_unix,edit_lock_other,keyarg,keyarg_test}.go` | C1.1–C1.4 |
| 3 | **C2** — the commands, tests, integration, docs | `cmd/sshepherd/{editrun,editrun_test,revoke,revoke_test,rotate,rotate_test,keyarg_fuzz_test,run,help_readme_test,e2e_test,identity_integration_test}.go`, `cmd/sshepherd/testdata/fuzz/FuzzKeyArg/**`, `Makefile`, `scripts/integration.sh`, `README.md`, `CLAUDE.md`, `docs/superpowers/specs/*.md` (status lines only) | C2.1–C2.7 |

Stage 2 compiles against stage 1's exported API; stage 3 against stage 2's unexported `cmd/sshepherd` API. **Code only against the signatures pinned in [Interfaces](#interfaces)** — never against another group's unpinned internals.

## Conventions

- **Commands.** Run everything from the repo root. Use `go test ./pkg -run 'Regex' -count=1` while iterating; each group ends with its package-wide gate. Exact output lines matter: if your shell proxies `go test` output (the `rtk` hook), prefix with `rtk proxy` to see raw lines.
- **Goldens.** `-update` rewrites `testdata/*.golden`; every golden this plan creates or changes has its exact expected bytes shown — compare after `-update` (`git diff` must show only what the task says).
- **Commits.** Commit steps are given per task (message trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`). Under this repo's workflow (CLAUDE.md: agents do not commit; one integrator commits and keeps README/Status in the same commit), **skip the commit steps when running as a group agent** and leave the tree for the integrator.
- **Gates per stage.** `gofmt -l .` (empty), `go vet ./...`, `go test -race ./...` and `golangci-lint run` over the group's packages must pass at the end of every stage (lint early: `gocyclo`'s cap of 15, `errorlint` and `revive` fail `make check` otherwise). `deadcode ./cmd/sshepherd` and therefore `make check` are expected to **fail after stages 1 and 2** (the new exported/unexported API is unreachable from `main` until stage 3 wires `revoke`/`rotate`); `make check` must pass after stage 3 (Task C2.7). `golangci-lint` must be built with the active toolchain (`make tools` if `make lint` says otherwise).
- **No placeholders.** Where a step says "replace", the old text is unique in the file; replace exactly it.

## Interfaces

Pinned signatures. Later stages code against exactly these.

### `internal/manifest` (Group M → C2)

```go
// UnsupportedError: a manifest config.Parse accepts but the comment-preserving
// edits cannot handle (anchors/aliases, null list entries, exotic keys).
// Load returns it (as error) for those; tell it apart with errors.As.
type UnsupportedError struct{ Reason string }
func (e *UnsupportedError) Error() string // == Reason, command-neutral

type UserRemoval struct {
	Keys   int // key lines the users: entry held
	Grants int // access: entries whose user: named the user
}

func (f *File) RemoveUser(name string) (UserRemoval, error)              // err: `user "X" is not in the manifest`
func (f *File) RemoveKey(fp string) (owner string, lastKey bool, err error) // err: "key SHA256:… is not in the manifest"
func (f *File) ReplaceKey(user, oldFP, newLine string) error              // same index; keeps the slot's comments
func (f *File) SetOperator(user string, on bool) error                    // off removes the operator: key
// Encode's self-check error text becomes "bug: edited manifest fails validation: …".
```

### `internal/apply` (Group A → C1, C2)

```go
func Plural(n int, one, many string) string // "1 key", "2 keys", "0 keys"

type RenderOptions struct {
	Color      bool
	Former     *config.Config // as-loaded config before an edit; nil for plain apply
	FormerNote string         // "" renders "(revoked)"; rotate passes "rotated out"
}

type AffectedSet struct {
	Servers []string // rendered desired bytes differ, manifest order
	Emptied []string // subset: desired empty under edited, non-empty under old
}
func Affected(old, edited *config.Config) AffectedSet

type EditKind string
const (
	EditRemoveUser EditKind = "remove-user"
	EditRemoveKey  EditKind = "remove-key"
	EditRotate     EditKind = "rotate"
)
type Edit struct {
	Kind                        EditKind
	User                        string
	Keys, Grants                int
	Fingerprint, NewFingerprint string
	KeepsExpiry                 string // verbatim option, e.g. `expiry-time="20270101"`
	NoKeysLeft, ClearsOperator  bool
}
type EmptiedServer struct {
	Server string
	Users  []string
	Keys   int
}
type EditSummary struct {
	Edits     []Edit
	Affected  int
	Operators []string
	Emptied   []EmptiedServer
}
func RenderEditHeader(w io.Writer, s EditSummary, opts RenderOptions)
func EditPrompt(operators []string, toWrite, affected int, noApply bool) string // no " [y/N]"
```

### `cmd/sshepherd` (Group C1 → C2)

```go
// edit.go
type runFlags struct {
	cfgPath, knownHosts string
	parallel            int
	dryRun, yes         bool
	idf                 identityFlags
}
func (f *runFlags) register(cmd *cobra.Command) // --config --known-hosts --parallel --dry-run --yes + identity flags

type manifestTarget struct {
	Path     string // --config as given
	Resolved string // filepath.EvalSymlinks(Path)
	Loaded   []byte // exact bytes read
}
func readManifest(path string) (manifestTarget, error)  // err: "read manifest: …"
func (m manifestTarget) Unchanged() error               // err: "manifest PATH changed since it was read; re-run"
func (m manifestTarget) Save(data []byte) error         // lock + CAS + atomic; errManifestLocked when held
var beforeManifestSave = func(manifestTarget) {}        // test seam, start of Save
var errManifestLocked error                             // "manifest is being updated by another sshepherd run; re-run"
func lockManifest(resolved string) (func(), error)      // edit_lock_unix.go / edit_lock_other.go
func lockPath(resolved string) string                   // DIR/.NAME.sshepherd-lock

// keyarg.go
type keyRole string
const (roleKey keyRole = "--key"; roleOld keyRole = "--old"; roleNew keyRole = "--new")
type keyArg struct {
	Arg         string
	Fingerprint string
	Key         *authkeys.Key // nil for a fingerprint argument
}
const maxKeyFile = 64 << 10
func parseKeyArg(role keyRole, arg string) (keyArg, error)
func classifyKeyArg(role keyRole, arg, home string, read func(string) ([]byte, error)) (keyArg, error)
func looksLikeKey(arg string) bool      // spec steps 1–4
func looksLikeKeyLine(arg string) bool  // step 4
func expiryOption(options []string) string
func expiryPassed(option string, now time.Time) (bool, error)

// apply.go
type applyStage int
const (stagePlanned applyStage = iota; stageDeclined; stageConfirmed)
type applyRun struct {
	cfg, former   *config.Config
	formerNote    string
	servers       []config.Server
	preferKeys    func(config.Server) []string
	header        func(io.Writer)
	alwaysConfirm bool
	prompt        func(plans []apply.ServerPlan, toWrite int) (string, error)
	beforeWrite   func(ctx context.Context, plans []apply.ServerPlan, fresh []sshconn.HeldKey) error
	finish        func(plans []apply.ServerPlan, stage applyStage) error
}
func runApply(cmd *cobra.Command, a *app, stdout io.Writer, rf *runFlags, ids identities, run applyRun) error
func confirmGate(cmd *cobra.Command, yes bool, question string) (bool, error)
var promptStreams func(cmd *cobra.Command) (io.Reader, io.Writer, bool) // test seam
func countChanges(plans []apply.ServerPlan) int // unchanged

// apply_test.go / keyarg_test.go test helpers C2 reuses
func usePromptStreams(t *testing.T, in io.Reader, out io.Writer)
type actionReader struct{ once sync.Once; act func(); r io.Reader } // act runs on the first Read
func fpOf(t *testing.T, seed byte) string
func certLine(t *testing.T, seed byte) string
```

**Error texts C2's tests and fuzz target depend on** (C1 must produce exactly these; digits vary):

```text
--key /k/id.pub: larger than 64 KiB — not a public key file
--key /k/id.pub is a private key — pass the public key (/k/id.pub.pub)
--key /k/id.pub: holds 2 key lines — want exactly one
--key /k/id.pub is an SSH certificate, not a public key — pass the plain key (id_ed25519.pub, not id_ed25519-cert.pub)
--key /k/id.pub: does not hold a valid public key line
--new SHA256:…: a fingerprint carries no key — pass the new public key line or its .pub file
rotate keeps the old line's options; edit them in the manifest
malformed fingerprint (want SHA256: followed by 43 base64 characters)
manifest PATH changed since it was read; re-run
```

## File Structure

| File | Group | Responsibility |
| ---- | ----- | -------------- |
| `internal/manifest/manifest.go` (modify) | M | Package doc lists the five edits; `UnsupportedError` with command-neutral reasons; Encode's error text |
| `internal/manifest/edit.go` (new) | M | `RemoveUser`, `RemoveKey`, `ReplaceKey`, `SetOperator`; `removeItems` comment-rescue rule |
| `internal/manifest/edit_test.go` (new) | M | Table/golden tests of every edit and comment position |
| `internal/manifest/fuzz_edit_test.go` (new) + `testdata/fuzz/FuzzManifestEdit/*` | M | `FuzzManifestEdit` + committed seeds |
| `internal/manifest/testdata/edit_{remove_user,multi}.golden` (new) | M | Output goldens proving comments survive |
| `internal/apply/report.go`, `plan.go` (modify) | A | `Plural`; pluralized count strings; `RenderOptions.Former/FormerNote` labels |
| `internal/apply/affected.go` (new) | A | Pure `Affected(old, edited)` |
| `internal/apply/edit.go` (new) | A | `EditSummary`, `RenderEditHeader`, `EditPrompt` |
| `internal/apply/{plural,former,affected,edit}_test.go` (new) + goldens | A | Unit + golden tests; regenerated `plan_*` goldens |
| `cmd/sshepherd/edit.go` (new) | C1 | `runFlags` (shared flag registration); `manifestTarget`: read, re-check, locked CAS atomic save |
| `cmd/sshepherd/edit_lock_unix.go` / `edit_lock_other.go` (new) | C1 | `flock` sidecar lock and owner preservation (linux/darwin); refusal elsewhere |
| `cmd/sshepherd/keyarg.go` (new) | C1 | KEY classification (fingerprint / ssh-keygen output / MD5 / key line / path) and expiry helpers |
| `cmd/sshepherd/apply.go` (modify) | C1 | `runApply(applyRun)` run body, `planFleet`, `writePhase` + `beforeWrite`, `promptStreams` seam, question-based `confirm` |
| `cmd/sshepherd/editrun.go` (new) | C2 | Shared revoke/rotate driver: flags, load, operator gate, affected set, save-only path, hooks, finish hint and scope line |
| `cmd/sshepherd/revoke.go`, `rotate.go` (new) | C2 | Usage rules, target resolution, node edits, one `Encode` |
| `cmd/sshepherd/run.go` (modify) | C2 | Register both commands |
| `cmd/sshepherd/*_test.go` (new/modify) | C1/C2 | Unit, hermetic (`sshtest`), integration/E2E, fuzz |
| `Makefile`, `scripts/integration.sh` (modify) | C2 | Two fuzz targets; `rotatecmd` container user |
| `README.md`, `CLAUDE.md`, spec status lines (modify) | C2 | User docs, Status, Amended-by lines |

Deliberate refinement of the spec's file list: the spec puts KEY classification in `edit.go`; this plan gives it its own `keyarg.go` (one responsibility per file) and adds `editrun.go` for the driver both verbs share.

## Group M — `internal/manifest` removal and replacement edits (stage 1)

Owns `internal/manifest/**` only. Verified `yaml.v3` behavior these tasks rely on (pinned by the tests below): a comment above the first item of a list is that item's `HeadComment`; a comment between items is the next item's `HeadComment`; a document-tail comment rides the **last section key's** `FootComment`, and a section key's `FootComment` is emitted after the section's remaining items (preceded by a blank line when another key follows); an empty sequence encodes as `[]` in either style; removing a pair from a flow mapping is safe; plain-style scalars containing `,`/`"` inside a flow list are re-quoted by the encoder.

### Task M1: `Load` — typed, command-neutral errors; flow-context nulls round-trip [Group M]

**Files:**
- Modify: `internal/manifest/manifest.go` (package doc; `UnsupportedError`; `checkTopLevelKeys`; `checkNodeShapes`; `Load` + `explicitFlowNulls`; `Encode`)
- Test: `internal/manifest/manifest_test.go`

Also fixes a pre-existing round-trip bug `FuzzManifestEdit` found while this plan was verified: an implicit null inside a flow mapping (`{name: a, operator, keys: [...]}`) is accepted by `config.Parse` but `yaml.v3` re-encodes it in flow context as an empty quoted string, which the reparse refuses for a bool/list/int — so `Encode` failed on a manifest `Load` accepted (adopt/import `--merge` were exposed too). `Load` now spells such nulls `null`.

- [ ] **Step 1: Write the failing test**

In `internal/manifest/manifest_test.go`, replace:

```go
import (
	"bytes"
	"flag"
```

with:

```go
import (
	"bytes"
	"errors"
	"flag"
```

Append to the end of `internal/manifest/manifest_test.go`:

```go

// TestLoadUnsupportedIsTyped: a structurally uneditable (but valid)
// manifest is an *UnsupportedError with command-neutral text; a manifest
// config.Parse rejects is not.
func TestLoadUnsupportedIsTyped(t *testing.T) {
	_, err := Load([]byte("users: &u []\nservers: []\naccess: []\n"))
	var ue *UnsupportedError
	if !errors.As(err, &ue) {
		t.Fatalf("err = %v, want *UnsupportedError", err)
	}
	if strings.Contains(ue.Error(), "merge") || !strings.Contains(ue.Error(), "anchor or alias (line 1)") {
		t.Errorf("reason = %q, want command-neutral anchor text", ue.Error())
	}
	if _, err := Load([]byte("userz: []")); errors.As(err, &ue) {
		t.Errorf("a config.Parse rejection must not be an UnsupportedError: %v", err)
	}
}

// TestLoadFlowNullValuesRoundTrip (fuzz-found): an implicit null inside a
// flow mapping must re-encode as null, not as an empty string the reparse
// refuses for a bool, a list or a port.
func TestLoadFlowNullValuesRoundTrip(t *testing.T) {
	for _, in := range []string{
		`users: [{name: a, operator, keys: ["` + testkeys.Line(t, 1) + `"]}]`,
		`users: [{name: a, operator: , keys: ["` + testkeys.Line(t, 1) + `"]}]`,
		"servers: [{name: w, host: h, port, user: u}]",
		"users: [{name: a, keys}]",
	} {
		f, err := Load([]byte(in))
		if err != nil {
			t.Fatalf("Load(%q): %v", in, err)
		}
		out, err := f.Encode()
		if err != nil {
			t.Fatalf("Encode(%q): %v", in, err)
		}
		if _, err := config.Parse(out); err != nil {
			t.Errorf("re-encoded %q rejected: %v\n%s", in, err, out)
		}
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run:

```bash
go test ./internal/manifest -run 'TestLoadUnsupportedIsTyped|TestLoadFlowNullValuesRoundTrip'
```

Expected: FAIL, output includes:

```text
FAIL	github.com/javadh75/SSHepherd/internal/manifest [build failed]
FAIL
internal/manifest/manifest_test.go:421:10: undefined: UnsupportedError
```

- [ ] **Step 3: Implement**

In `internal/manifest/manifest.go`, replace:

```go
// Package manifest provides comment-preserving appends to an existing
// SSHepherd manifest: the file is decoded into a yaml.v3 node tree (comments
// intact) alongside the validated config, new user/server/access entries are
// appended surgically to their section sequences, and the whole document is
// re-encoded. Nothing existing is reordered, rewritten, or removed.
//
// Fidelity contract: comments are preserved; blank lines and quote styles
// may normalize.
package manifest
```

with:

```go
// Package manifest provides comment-preserving edits to an existing
// SSHepherd manifest: the file is decoded into a yaml.v3 node tree (comments
// intact) alongside the validated config, edited surgically, and the whole
// document is re-encoded. The edits are exactly these:
//
//   - Append adds users, servers and access entries at the end of their
//     sections (adopt --merge, import --merge);
//   - RemoveUser deletes a users: entry and every access: entry naming it;
//   - RemoveKey deletes one keys: line, found by fingerprint;
//   - ReplaceKey replaces one keys: line in place (same index);
//   - SetOperator sets or removes a user's operator: flag.
//
// Nothing else is reordered, rewritten, or removed. The edit methods change
// only the node tree — none validates, and Config stays the as-loaded
// config; Encode's config.Parse self-check is the one validation.
//
// Fidelity contract: comments are preserved (a removed users:/access:
// entry's head comment moves to the next entry or the section's footer; a
// removed key line's head comment goes with it); blank lines and quote
// styles may normalize.
package manifest
```

In `internal/manifest/manifest.go`, replace:

```go
// Load parses data twice:
```

with:

```go
// UnsupportedError reports a manifest config.Parse accepts but this package
// cannot edit faithfully (anchors/aliases, null list entries, exotic keys).
// Callers tell it apart from a validation failure with errors.As: the
// manifest is valid, only the comment-preserving edit is impossible.
type UnsupportedError struct {
	Reason string
}

func (e *UnsupportedError) Error() string { return e.Reason }

// Load parses data twice:
```

In `internal/manifest/manifest.go`, replace:

```go
			return fmt.Errorf("manifest contains an unsupported top-level key %q", k.Value)
```

with:

```go
			return &UnsupportedError{Reason: fmt.Sprintf("manifest contains an unsupported top-level key %q", k.Value)}
```

In `internal/manifest/manifest.go`, replace:

```go
		return fmt.Errorf("manifest contains a YAML anchor or alias (line %d); merge does not support them", n.Line)
```

with:

```go
		return &UnsupportedError{Reason: fmt.Sprintf("manifest contains a YAML anchor or alias (line %d); comment-preserving edits do not support them", n.Line)}
```

In `internal/manifest/manifest.go`, replace:

```go
				return fmt.Errorf("manifest contains an unsupported mapping key (line %d)", k.Line)
```

with:

```go
				return &UnsupportedError{Reason: fmt.Sprintf("manifest contains an unsupported mapping key (line %d)", k.Line)}
```

In `internal/manifest/manifest.go`, replace:

```go
				return fmt.Errorf("manifest contains a null list entry (line %d)", item.Line)
```

with:

```go
				return &UnsupportedError{Reason: fmt.Sprintf("manifest contains a null list entry (line %d)", item.Line)}
```

In `internal/manifest/manifest.go`, replace:

```go
	if err := checkNodeShapes(root); err != nil {
		return nil, err
	}
	return &File{root: root, cfg: cfg}, nil
}
```

with:

```go
	if err := checkNodeShapes(root); err != nil {
		return nil, err
	}
	explicitFlowNulls(root, false)
	return &File{root: root, cfg: cfg}, nil
}

// explicitFlowNulls spells every implicit null inside a flow collection as
// `null` (fuzz-found): `{name: a, operator, keys: [...]}` decodes operator
// as an empty null, which the encoder writes back in flow context as an
// empty quoted string — which the reparse refuses for a bool (or a list,
// or a port). Block-context nulls re-encode faithfully and are left alone.
func explicitFlowNulls(n *yaml.Node, inFlow bool) {
	if n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode {
		inFlow = inFlow || n.Style&yaml.FlowStyle != 0
	}
	if inFlow && n.Kind == yaml.ScalarNode && n.Tag == "!!null" && n.Value == "" {
		n.Value = "null"
	}
	for _, c := range n.Content {
		explicitFlowNulls(c, inFlow)
	}
}
```

In `internal/manifest/manifest.go`, replace:

```go
		return nil, fmt.Errorf("bug: merged manifest fails validation: %w", err)
```

with:

```go
		return nil, fmt.Errorf("bug: edited manifest fails validation: %w", err)
```

- [ ] **Step 4: Run the package tests**

`TestLoadRejectsWhatConfigParseRejects` keeps passing: it only asserts a non-nil error.

Run:

```bash
go test ./internal/manifest
```

Expected: PASS, output includes:

```text
ok  	github.com/javadh75/SSHepherd/internal/manifest	(…s)
```

- [ ] **Commit**

```bash
git add internal/manifest/manifest.go internal/manifest/manifest_test.go
git commit -m "$(cat <<'EOF'
feat(manifest): typed, command-neutral UnsupportedError for uneditable manifests

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

### Task M2: `RemoveUser` and `RemoveKey` with the comment-rescue rule [Group M]

**Files:**
- Create: `internal/manifest/edit.go`
- Create: `internal/manifest/edit_test.go`
- Create (via `-update`): `internal/manifest/testdata/edit_remove_user.golden`

Rules implemented by `removeItems`: a removed `users:`/`access:` item's `HeadComment` is prepended to the next surviving sibling's; with no next sibling it is inserted **at the front** of the section key's `FootComment` (so it is emitted after the remaining items and before any document footer already riding there — source order is preserved); the section key's `HeadComment` (which can hold the file header) is never touched; a removed `keys:` item's head comment is dropped; an emptied sequence is set to flow style (`[]`).

- [ ] **Step 1: Write the failing tests**

Create `internal/manifest/edit_test.go`:

```go
package manifest

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// editFixture is a hand-maintained manifest exercising every comment
// position the edit rules name: a file header on the users: key, a section
// heading above the first users: item, head comments on keys: items, line
// comments, a flow-style keys: list, head comments on access: items (first
// and last), and a document footer.
func editFixture(tb testing.TB) string {
	tb.Helper()
	return `# fleet manifest — hand-maintained
# owner: platform team
users:
  # --- contractors ---
  - name: alice # contractor until 2026-12
    keys:
      # alice laptop
      - ` + testkeys.Line(tb, 2) + ` alice@laptop
      # alice desktop
      - ` + testkeys.Line(tb, 3) + ` alice@desk
  # --- staff ---
  - name: bob
    keys: ["` + testkeys.Line(tb, 4) + `"]
  - name: ops
    # break-glass account
    operator: true # vault-held
    keys:
      - ` + testkeys.Line(tb, 1) + ` ops@vault
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: db-1, host: 10.0.0.9, user: deploy}
access:
  # alice: web only
  - user: alice
    servers: [web-1]
  - user: bob
    servers: [web-1, db-1]
  # alice db access (temporary)
  - user: alice
    servers: [db-1]
# reviewed 2026-10-01
`
}

// keyFP is a test key's fingerprint.
func keyFP(tb testing.TB, seed byte) string {
	tb.Helper()
	k, err := authkeys.ParseLine(testkeys.Line(tb, seed))
	if err != nil || k == nil {
		tb.Fatalf("keyFP(%d): %v", seed, err)
	}
	return k.Fingerprint
}

func loadFixture(t *testing.T, in string) *File {
	t.Helper()
	f, err := Load([]byte(in))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return f
}

// encodeParsed encodes f and re-parses the output: every edited manifest
// must satisfy config.Parse.
func encodeParsed(t *testing.T, f *File) (string, *config.Config) {
	t.Helper()
	out, err := f.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("edited manifest rejected by config.Parse: %v\n%s", err, out)
	}
	return string(out), cfg
}

// inOrder asserts each want occurs in s, in the given order.
func inOrder(t *testing.T, s string, wants ...string) {
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

func TestRemoveUserGolden(t *testing.T) {
	f := loadFixture(t, editFixture(t))
	r, err := f.RemoveUser("alice")
	if err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if r.Keys != 2 || r.Grants != 2 {
		t.Errorf("UserRemoval = %+v, want 2 keys and 2 grants", r)
	}
	out, cfg := encodeParsed(t, f)
	if _, ok := cfg.OwnerOf(keyFP(t, 2)); ok {
		t.Error("alice's key survived RemoveUser")
	}
	for _, u := range cfg.Users {
		if u.Name == "alice" {
			t.Error("alice's users: entry survived")
		}
	}
	for _, a := range cfg.Access {
		if a.User == "alice" {
			t.Error("an access: entry for alice survived")
		}
	}
	// The file header stays first; the first item's section heading moves
	// to bob (prepended to bob's own); the first access item's head comment
	// moves to bob's grant; the last access item's comment lands in the
	// section footer, before the document footer.
	inOrder(t, out,
		"# fleet manifest — hand-maintained\n# owner: platform team\nusers:\n",
		"  # --- contractors ---\n  # --- staff ---\n  - name: bob\n",
		"access:\n  # alice: web only\n  - user: bob\n",
		"# alice db access (temporary)\n# reviewed 2026-10-01\n")
	for _, gone := range []string{"alice laptop", "alice desktop", "contractor until 2026-12"} {
		if strings.Contains(out, gone) {
			t.Errorf("a comment inside alice's entry survived (%q):\n%s", gone, out)
		}
	}
	checkGolden(t, "edit_remove_user.golden", []byte(out))
}

// TestRemoveUserLastRescuesToFooter: the last users: item has no next
// sibling, so its head comment rides the users: key's foot comment —
// emitted right after the remaining users, never above the file header.
func TestRemoveUserLastRescuesToFooter(t *testing.T) {
	f2 := loadFixture(t, strings.Replace(editFixture(t), "  - name: ops\n", "  # ops: shared account\n  - name: ops\n", 1))
	if _, err := f2.RemoveUser("ops"); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	out, _ := encodeParsed(t, f2)
	inOrder(t, out, "# fleet manifest — hand-maintained\n", "  - name: bob\n", "# ops: shared account\n", "servers:\n")
	if strings.Index(out, "# ops: shared account") < strings.Index(out, "users:") {
		t.Errorf("rescued comment landed above the file header:\n%s", out)
	}
}

// TestRemoveOnlyItemsLeaveFlowEmpty: removing the only item of a section
// (or of a keys: list) leaves an empty flow sequence, block or flow source.
func TestRemoveOnlyItemsLeaveFlowEmpty(t *testing.T) {
	block := `users:
  - name: bob
    keys:
      - ` + testkeys.Line(t, 4) + `
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - user: bob
    servers: [web-1]
`
	flow := `users: [{name: bob, keys: ["` + testkeys.Line(t, 4) + `"]}]
servers: [{name: web-1, host: 10.0.0.1, user: deploy}]
access: [{user: bob, servers: [web-1]}]
`
	for name, in := range map[string]string{"block": block, "flow": flow} {
		t.Run(name+" user", func(t *testing.T) {
			f := loadFixture(t, in)
			if _, err := f.RemoveUser("bob"); err != nil {
				t.Fatalf("RemoveUser: %v", err)
			}
			out, cfg := encodeParsed(t, f)
			if !strings.Contains(out, "users: []") || !strings.Contains(out, "access: []") {
				t.Errorf("want empty flow users/access:\n%s", out)
			}
			if len(cfg.Users) != 0 || len(cfg.Access) != 0 || len(cfg.Servers) != 1 {
				t.Errorf("config = %+v, want only the server left", cfg)
			}
		})
		t.Run(name+" key", func(t *testing.T) {
			f := loadFixture(t, in)
			owner, last, err := f.RemoveKey(keyFP(t, 4))
			if err != nil || owner != "bob" || !last {
				t.Fatalf("RemoveKey = (%q, %v, %v), want (bob, true, nil)", owner, last, err)
			}
			out, cfg := encodeParsed(t, f)
			if !strings.Contains(out, "keys: []") {
				t.Errorf("want keys: []:\n%s", out)
			}
			if len(cfg.Users) != 1 || len(cfg.Users[0].Keys) != 0 {
				t.Errorf("users = %+v, want bob with no keys", cfg.Users)
			}
		})
	}
}

// TestRemoveKeyPositions: first / last key of a block list; the removed
// line's head comment goes with it (never re-labels the survivor), and
// options/comments/spacing never matter for the match.
func TestRemoveKeyPositions(t *testing.T) {
	t.Run("first", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		owner, last, err := f.RemoveKey(keyFP(t, 2))
		if err != nil || owner != "alice" || last {
			t.Fatalf("RemoveKey = (%q, %v, %v), want (alice, false, nil)", owner, last, err)
		}
		out, cfg := encodeParsed(t, f)
		if strings.Contains(out, "alice laptop") {
			t.Errorf("the removed key's head comment survived:\n%s", out)
		}
		inOrder(t, out, "    keys:\n      # alice desktop\n      - "+testkeys.Line(t, 3))
		if _, ok := cfg.OwnerOf(keyFP(t, 2)); ok {
			t.Error("removed key still owned")
		}
	})
	t.Run("last", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		if _, last, err := f.RemoveKey(keyFP(t, 3)); err != nil || last {
			t.Fatalf("RemoveKey: last=%v err=%v", last, err)
		}
		out, _ := encodeParsed(t, f)
		if strings.Contains(out, "alice desktop") {
			t.Errorf("the removed key's head comment survived:\n%s", out)
		}
		inOrder(t, out, "      # alice laptop\n      - "+testkeys.Line(t, 2)+" alice@laptop\n  # --- staff ---\n")
	})
	t.Run("options and odd spacing still match", func(t *testing.T) {
		in := `users:
  - name: bob
    keys:
      - 'from="10.0.0.1"   ` + testkeys.Line(t, 4) + `   bob@x'
      - ` + testkeys.Line(t, 5) + `
`
		f := loadFixture(t, in)
		if owner, _, err := f.RemoveKey(keyFP(t, 4)); err != nil || owner != "bob" {
			t.Fatalf("RemoveKey = (%q, %v)", owner, err)
		}
		_, cfg := encodeParsed(t, f)
		if len(cfg.Users[0].Keys) != 1 {
			t.Errorf("keys = %v, want only key 5", cfg.Users[0].Keys)
		}
	})
}
```

- [ ] **Step 2: Run them to verify they fail**

Run:

```bash
go test ./internal/manifest -run 'TestRemove'
```

Expected: FAIL, output includes:

```text
FAIL	github.com/javadh75/SSHepherd/internal/manifest [build failed]
FAIL
internal/manifest/edit_test.go:102:14: f.RemoveUser undefined (type *File has no field or method RemoveUser)
internal/manifest/edit_test.go:145:18: f2.RemoveUser undefined (type *File has no field or method RemoveUser)
internal/manifest/edit_test.go:175:19: f.RemoveUser undefined (type *File has no field or method RemoveUser)
internal/manifest/edit_test.go:188:26: f.RemoveKey undefined (type *File has no field or method RemoveKey)
```

- [ ] **Step 3: Implement**

Create `internal/manifest/edit.go`:

```go
package manifest

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/javadh75/SSHepherd/internal/authkeys"
)

// UserRemoval reports what RemoveUser deleted.
type UserRemoval struct {
	Keys   int // key lines the users: entry held
	Grants int // access: entries whose user: named the user
}

// RemoveUser deletes the users: entry named name and every access: entry
// whose user: is name. A removed entry's head comment moves to the next
// entry of its section, or to the section's footer when none follows; its
// line and foot comments go with it. Node tree only: nothing validates
// until Encode.
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
	return r, nil
}

// RemoveKey deletes the keys: line whose parsed fingerprint is fp (options,
// comment and spacing are irrelevant) and reports its owner and whether
// the owner's keys: list is now empty. The line's head comment goes with
// it: it describes that key, and moving it would re-label a survivor.
func (f *File) RemoveKey(fp string) (owner string, lastKey bool, err error) {
	user, keys, idx, err := f.findKey(fp)
	if err != nil {
		return "", false, err
	}
	target := keys.Content[idx]
	removeItems(nil, keys, func(n *yaml.Node) bool { return n == target }, false)
	return scalarField(user, "name"), len(keys.Content) == 0, nil
}

// findKey locates the keys: item whose parsed fingerprint is fp: the
// owning users: entry, its keys: sequence, and the item's index.
func (f *File) findKey(fp string) (user, keys *yaml.Node, idx int, err error) {
	m, err := f.rootMapping()
	if err != nil {
		return nil, nil, 0, err
	}
	_, users := sectionOf(m, "users")
	if users != nil {
		for _, u := range users.Content {
			ks := valueOf(u, "keys")
			if u.Kind != yaml.MappingNode || ks == nil || ks.Kind != yaml.SequenceNode {
				continue
			}
			for i, k := range ks.Content {
				if k.Kind != yaml.ScalarNode {
					continue
				}
				parsed, perr := authkeys.ParseLine(k.Value)
				if perr == nil && parsed != nil && parsed.Fingerprint == fp {
					return u, ks, i, nil
				}
			}
		}
	}
	return nil, nil, 0, fmt.Errorf("key %s is not in the manifest", fp)
}

// sectionOf returns a top-level section's key node and its value when the
// value is a sequence (nil otherwise: missing, null, or another shape).
func sectionOf(m *yaml.Node, key string) (k, seq *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			if v := m.Content[i+1]; v.Kind == yaml.SequenceNode {
				return m.Content[i], v
			}
			return m.Content[i], nil
		}
	}
	return nil, nil
}

// userItem finds the users: entry whose name: is name.
func userItem(users *yaml.Node, name string) *yaml.Node {
	if users == nil {
		return nil
	}
	for _, u := range users.Content {
		if u.Kind == yaml.MappingNode && scalarField(u, "name") == name {
			return u
		}
	}
	return nil
}

// scalarField returns a mapping's scalar value for key ("" if absent or
// not a scalar).
func scalarField(n *yaml.Node, key string) string {
	if n.Kind != yaml.MappingNode {
		return ""
	}
	if v := valueOf(n, key); v != nil && v.Kind == yaml.ScalarNode {
		return v.Value
	}
	return ""
}

// removeItems drops every item of seq that drop selects and returns how
// many it dropped. With rescue, a dropped item's head comment is prepended
// to the next surviving item's, or — when no item survives after it —
// inserted at the front of sectionKey's foot comment, which the encoder
// emits right after the section's remaining items (before any document
// footer already riding there, preserving the source order). The section
// key's head comment, which may hold the file header, is never touched.
// Without rescue, head comments go with their items. An emptied sequence
// is emitted in flow style (`[]`).
func removeItems(sectionKey, seq *yaml.Node, drop func(*yaml.Node) bool, rescue bool) int {
	var kept []*yaml.Node
	pending := ""
	removed := 0
	for _, it := range seq.Content {
		if drop(it) {
			removed++
			if rescue {
				pending = joinComments(pending, it.HeadComment)
			}
			continue
		}
		if pending != "" {
			it.HeadComment = joinComments(pending, it.HeadComment)
			pending = ""
		}
		kept = append(kept, it)
	}
	if pending != "" && sectionKey != nil {
		sectionKey.FootComment = joinComments(pending, sectionKey.FootComment)
	}
	seq.Content = kept
	if len(kept) == 0 {
		seq.Style = yaml.FlowStyle
	}
	return removed
}

// joinComments concatenates two comment blocks, either possibly empty.
func joinComments(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "\n" + b
}
```

- [ ] **Step 4: Generate the golden and run the tests**

Run:

```bash
go test ./internal/manifest -run 'TestRemove' -update
```

Expected: PASS, output includes:

```text
ok  	github.com/javadh75/SSHepherd/internal/manifest	(…s)
```

Expected `internal/manifest/testdata/edit_remove_user.golden` (exact bytes):

```text
# fleet manifest — hand-maintained
# owner: platform team
users:
  # --- contractors ---
  # --- staff ---
  - name: bob
    keys: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58"]
  - name: ops
    # break-glass account
    operator: true # vault-held
    keys:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIqI4910CfGV/VLbLTy6XXLKZwm/HZQSG/N0iAG0D29c ops@vault
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: db-1, host: 10.0.0.9, user: deploy}
access:
  # alice: web only
  - user: bob
    servers: [web-1, db-1]
# alice db access (temporary)
# reviewed 2026-10-01
```

Run:

```bash
go test ./internal/manifest
```

Expected: PASS, output includes:

```text
ok  	github.com/javadh75/SSHepherd/internal/manifest	(…s)
```

- [ ] **Commit**

```bash
git add internal/manifest/edit.go internal/manifest/edit_test.go internal/manifest/testdata/edit_remove_user.golden
git commit -m "$(cat <<'EOF'
feat(manifest): RemoveUser and RemoveKey with head-comment rescue

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

### Task M3: `ReplaceKey`, `SetOperator`, several edits then one `Encode` [Group M]

**Files:**
- Modify: `internal/manifest/edit.go` (append)
- Modify: `internal/manifest/edit_test.go` (append)
- Create (via `-update`): `internal/manifest/testdata/edit_multi.golden`

- [ ] **Step 1: Write the failing tests**

Append to the end of `internal/manifest/edit_test.go`:

```go

// TestRemoveOperatorLastKeyClearsFlag: operator: true with no keys fails
// validation, so the caller clears the flag first; skipping that makes
// Encode's self-check fail (an internal error, nothing written).
func TestRemoveOperatorLastKeyClearsFlag(t *testing.T) {
	f := loadFixture(t, editFixture(t))
	if err := f.SetOperator("ops", false); err != nil {
		t.Fatalf("SetOperator: %v", err)
	}
	owner, last, err := f.RemoveKey(keyFP(t, 1))
	if err != nil || owner != "ops" || !last {
		t.Fatalf("RemoveKey = (%q, %v, %v), want (ops, true, nil)", owner, last, err)
	}
	out, cfg := encodeParsed(t, f)
	for _, u := range cfg.Users {
		if u.Name == "ops" && (u.Operator || len(u.Keys) != 0) {
			t.Errorf("ops = %+v, want a plain user with no keys", u)
		}
	}
	if strings.Contains(out, "vault-held") {
		t.Errorf("the operator: line comment must go with the flag:\n%s", out)
	}
	inOrder(t, out, "  - name: ops\n    # break-glass account\n    keys: []\n")

	g := loadFixture(t, editFixture(t))
	if _, _, err := g.RemoveKey(keyFP(t, 1)); err != nil {
		t.Fatalf("RemoveKey: %v", err)
	}
	if _, err := g.Encode(); err == nil || !strings.Contains(err.Error(), "operator requires at least one valid key") {
		t.Errorf("Encode err = %v, want the operator validation failure", err)
	}
}

// TestReplaceKey: the new line lands at the same index with the slot's
// comments kept; the caller-composed line (old options, new key, chosen
// comment) is stored verbatim — quoted as needed, even inside a flow list.
func TestReplaceKey(t *testing.T) {
	t.Run("block, same index, comments kept", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		newLine := `from="10.0.0.0/8",no-pty ` + testkeys.Line(t, 5) + " alice@laptop"
		if err := f.ReplaceKey("alice", keyFP(t, 2), newLine); err != nil {
			t.Fatalf("ReplaceKey: %v", err)
		}
		out, cfg := encodeParsed(t, f)
		if got := cfg.Users[0].Keys; len(got) != 2 || got[0] != newLine {
			t.Fatalf("alice keys = %q, want the new line first", got)
		}
		inOrder(t, out, "      # alice laptop\n", "      # alice desktop\n")
		if u, ok := cfg.OwnerOf(keyFP(t, 5)); !ok || u.Name != "alice" {
			t.Error("new key not owned by alice")
		}
	})
	t.Run("flow list", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		newLine := `from="10.0.0.1,10.0.0.2" ` + testkeys.Line(t, 5) + " bob, it's new"
		if err := f.ReplaceKey("bob", keyFP(t, 4), newLine); err != nil {
			t.Fatalf("ReplaceKey: %v", err)
		}
		_, cfg := encodeParsed(t, f)
		if got := cfg.Users[1].Keys; len(got) != 1 || got[0] != newLine {
			t.Errorf("bob keys = %q, want [%q]", got, newLine)
		}
	})
	t.Run("wrong owner", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		err := f.ReplaceKey("bob", keyFP(t, 2), testkeys.Line(t, 5))
		if err == nil || !strings.Contains(err.Error(), `belongs to "alice", not "bob"`) {
			t.Errorf("err = %v, want the ownership error", err)
		}
	})
}

func TestSetOperator(t *testing.T) {
	t.Run("on inserts before keys", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		if err := f.SetOperator("bob", true); err != nil {
			t.Fatalf("SetOperator: %v", err)
		}
		out, cfg := encodeParsed(t, f)
		if !cfg.Users[1].Operator {
			t.Errorf("bob not an operator:\n%s", out)
		}
		inOrder(t, out, "  - name: bob\n    operator: true\n    keys:")
	})
	t.Run("on keeps an existing flag", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		if err := f.SetOperator("ops", true); err != nil {
			t.Fatalf("SetOperator: %v", err)
		}
		out, _ := encodeParsed(t, f)
		if strings.Count(out, "operator:") != 1 || !strings.Contains(out, "operator: true # vault-held") {
			t.Errorf("want the one existing flag kept:\n%s", out)
		}
	})
	t.Run("off without a flag is a no-op", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		if err := f.SetOperator("bob", false); err != nil {
			t.Fatalf("SetOperator: %v", err)
		}
		if out, _ := encodeParsed(t, f); strings.Count(out, "operator:") != 1 {
			t.Errorf("unexpected operator change:\n%s", out)
		}
	})
	t.Run("off in a flow mapping", func(t *testing.T) {
		f := loadFixture(t, `users: [{name: ops, operator: true, keys: ["`+testkeys.Line(t, 1)+`", "`+testkeys.Line(t, 2)+`"]}]`)
		if err := f.SetOperator("ops", false); err != nil {
			t.Fatalf("SetOperator: %v", err)
		}
		out, cfg := encodeParsed(t, f)
		if cfg.Users[0].Operator || strings.Contains(out, "operator") {
			t.Errorf("flag survived:\n%s", out)
		}
	})
}

// TestEditsThenOneEncode: several edits on one File, one Encode — the
// shape revoke uses (resolve all targets, edit, encode once).
func TestEditsThenOneEncode(t *testing.T) {
	f := loadFixture(t, editFixture(t))
	if _, err := f.RemoveUser("bob"); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if _, _, err := f.RemoveKey(keyFP(t, 3)); err != nil {
		t.Fatalf("RemoveKey: %v", err)
	}
	if err := f.ReplaceKey("alice", keyFP(t, 2), testkeys.Line(t, 5)+" alice@new"); err != nil {
		t.Fatalf("ReplaceKey: %v", err)
	}
	out, cfg := encodeParsed(t, f)
	if len(cfg.Users) != 2 || len(cfg.Users[0].Keys) != 1 || len(cfg.Access) != 2 {
		t.Errorf("config = %+v", cfg)
	}
	for _, want := range []string{
		"# fleet manifest — hand-maintained", "# --- contractors ---", "# --- staff ---",
		"# alice laptop", "# break-glass account", "# alice: web only",
		"# alice db access (temporary)", "# reviewed 2026-10-01",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	checkGolden(t, "edit_multi.golden", []byte(out))
}

func TestEditErrors(t *testing.T) {
	f := loadFixture(t, editFixture(t))
	if _, err := f.RemoveUser("carol"); err == nil || !strings.Contains(err.Error(), `user "carol" is not in the manifest`) {
		t.Errorf("RemoveUser(carol) err = %v", err)
	}
	if _, _, err := f.RemoveKey(keyFP(t, 9)); err == nil || !strings.Contains(err.Error(), "is not in the manifest") {
		t.Errorf("RemoveKey(unknown) err = %v", err)
	}
	if err := f.SetOperator("carol", false); err == nil {
		t.Error("SetOperator(carol) succeeded")
	}
	if err := f.ReplaceKey("alice", keyFP(t, 9), testkeys.Line(t, 5)); err == nil {
		t.Error("ReplaceKey of an unknown key succeeded")
	}
	empty := loadFixture(t, "")
	if _, err := empty.RemoveUser("bob"); err == nil {
		t.Error("RemoveUser on an empty manifest succeeded")
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run:

```bash
go test ./internal/manifest -run 'TestRemoveOperatorLastKeyClearsFlag|TestReplaceKey|TestSetOperator|TestEditsThenOneEncode|TestEditErrors'
```

Expected: FAIL, output includes:

```text
FAIL	github.com/javadh75/SSHepherd/internal/manifest [build failed]
FAIL
internal/manifest/edit_test.go:256:14: f.SetOperator undefined (type *File has no field or method SetOperator)
internal/manifest/edit_test.go:290:15: f.ReplaceKey undefined (type *File has no field or method ReplaceKey)
internal/manifest/edit_test.go:305:15: f.ReplaceKey undefined (type *File has no field or method ReplaceKey)
internal/manifest/edit_test.go:315:12: f.ReplaceKey undefined (type *File has no field or method ReplaceKey)
```

- [ ] **Step 3: Implement**

Append to the end of `internal/manifest/edit.go`:

```go

// ReplaceKey replaces user's keys: line whose fingerprint is oldFP with
// newLine, at the same index, keeping the line's comments. The caller
// composes newLine (the old line's options, the new key, the chosen
// comment); nothing is validated until Encode.
func (f *File) ReplaceKey(user, oldFP, newLine string) error {
	owner, keys, idx, err := f.findKey(oldFP)
	if err != nil {
		return err
	}
	if name := scalarField(owner, "name"); name != user {
		return fmt.Errorf("key %s belongs to %q, not %q", oldFP, name, user)
	}
	n := keys.Content[idx]
	n.Value = newLine
	n.Tag = "!!str"
	if n.Style == yaml.LiteralStyle || n.Style == yaml.FoldedStyle {
		n.Style = 0 // a key line is one line; let the encoder pick the quoting
	}
	return nil
}

// SetOperator sets user's operator: flag (on) or removes the operator: key
// entirely (off). A removed operator: key's head comment moves to the next
// key of the entry; its line comment goes with it.
func (f *File) SetOperator(user string, on bool) error {
	m, err := f.rootMapping()
	if err != nil {
		return err
	}
	_, users := sectionOf(m, "users")
	item := userItem(users, user)
	if item == nil {
		return fmt.Errorf("user %q is not in the manifest", user)
	}
	for i := 0; i+1 < len(item.Content); i += 2 {
		if item.Content[i].Value != "operator" {
			continue
		}
		if on {
			v := item.Content[i+1]
			v.Kind, v.Tag, v.Value, v.Style = yaml.ScalarNode, "!!bool", "true", 0
			return nil
		}
		head := item.Content[i].HeadComment
		item.Content = append(item.Content[:i], item.Content[i+2:]...)
		if head != "" && i < len(item.Content) {
			item.Content[i].HeadComment = joinComments(head, item.Content[i].HeadComment)
		}
		return nil
	}
	if !on {
		return nil
	}
	pair := []*yaml.Node{strScalar("operator"), {Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"}}
	at := len(item.Content)
	for i := 0; i+1 < len(item.Content); i += 2 {
		if item.Content[i].Value == "keys" {
			at = i
			break
		}
	}
	item.Content = append(item.Content[:at], append(pair, item.Content[at:]...)...)
	return nil
}
```

- [ ] **Step 4: Generate the golden and run the tests**

Run:

```bash
go test ./internal/manifest -run TestEditsThenOneEncode -update
```

Expected: PASS, output includes:

```text
ok  	github.com/javadh75/SSHepherd/internal/manifest	(…s)
```

Expected `internal/manifest/testdata/edit_multi.golden` (exact bytes):

```text
# fleet manifest — hand-maintained
# owner: platform team
users:
  # --- contractors ---
  - name: alice # contractor until 2026-12
    keys:
      # alice laptop
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG56HN0psLeP0Tr0xVmP7/TvKpcWbjym8uT7/M2AUFvx alice@new
  # --- staff ---
  - name: ops
    # break-glass account
    operator: true # vault-held
    keys:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIqI4910CfGV/VLbLTy6XXLKZwm/HZQSG/N0iAG0D29c ops@vault
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: db-1, host: 10.0.0.9, user: deploy}
access:
  # alice: web only
  - user: alice
    servers: [web-1]
  # alice db access (temporary)
  - user: alice
    servers: [db-1]
# reviewed 2026-10-01
```

Run:

```bash
go test ./internal/manifest
```

Expected: PASS, output includes:

```text
ok  	github.com/javadh75/SSHepherd/internal/manifest	(…s)
```

- [ ] **Commit**

```bash
git add internal/manifest/edit.go internal/manifest/edit_test.go internal/manifest/testdata/edit_multi.golden
git commit -m "$(cat <<'EOF'
feat(manifest): ReplaceKey and SetOperator node edits

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

### Task M4: `FuzzManifestEdit` and its seed corpus [Group M]

**Files:**
- Create: `internal/manifest/fuzz_edit_test.go`
- Create: `internal/manifest/testdata/fuzz/FuzzManifestEdit/seed-operator-last-key`
- Create: `internal/manifest/testdata/fuzz/FuzzManifestEdit/seed-remove-wildcard-user`
- Create: `internal/manifest/testdata/fuzz/FuzzManifestEdit/seed-flow-null-operator`

(The `make fuzz` line for this target is added by Group C2, which owns the `Makefile`.)

- [ ] **Step 1: Write the fuzz target and the committed seeds**

Create `internal/manifest/fuzz_edit_test.go`:

```go
package manifest

import (
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// FuzzManifestEdit asserts the removal edits' safety property: on any
// manifest Load accepts, RemoveKey (clearing an operator's flag first when
// it removes the operator's last key, exactly as revoke does) and
// RemoveUser always yield a manifest config.Parse accepts, and the removed
// fingerprint is never owned by anyone in the output. pick selects the
// edit and its target: even → RemoveKey, odd → RemoveUser.
func FuzzManifestEdit(f *testing.F) {
	f.Add(editFixture(f), uint8(0))
	f.Add(editFixture(f), uint8(1))
	f.Add(editFixture(f), uint8(4))
	f.Add(editFixture(f), uint8(5))
	f.Add(commentedFixture(f), uint8(2))
	f.Add(`users: [{name: ops, operator: true, keys: ["`+testkeys.Line(f, 1)+`"]}]`, uint8(0))
	f.Add("users: []\nservers: []\naccess: []\n", uint8(0))
	f.Fuzz(func(t *testing.T, in string, pick uint8) {
		mf, err := Load([]byte(in))
		if err != nil {
			t.Skip()
		}
		cfg := mf.Config()
		type ownedKey struct {
			fp, owner string
		}
		var keys []ownedKey
		for _, u := range cfg.Users {
			for _, line := range u.Keys {
				k, err := authkeys.ParseLine(line)
				if err != nil || k == nil {
					t.Fatalf("validated key line %q does not parse: %v", line, err)
				}
				keys = append(keys, ownedKey{k.Fingerprint, u.Name})
			}
		}
		var gone []string // fingerprints that must not be owned afterwards
		if pick%2 == 0 {
			if len(keys) == 0 {
				t.Skip()
			}
			k := keys[int(pick/2)%len(keys)]
			owner, _ := cfg.OwnerOf(k.fp)
			if owner.Operator && len(owner.Keys) == 1 {
				if err := mf.SetOperator(owner.Name, false); err != nil {
					t.Fatalf("SetOperator(%q): %v", owner.Name, err)
				}
			}
			got, _, err := mf.RemoveKey(k.fp)
			if err != nil || got != k.owner {
				t.Fatalf("RemoveKey(%s) = (%q, %v), want owner %q", k.fp, got, err, k.owner)
			}
			gone = append(gone, k.fp)
		} else {
			if len(cfg.Users) == 0 {
				t.Skip()
			}
			u := cfg.Users[int(pick/2)%len(cfg.Users)]
			if _, err := mf.RemoveUser(u.Name); err != nil {
				t.Fatalf("RemoveUser(%q): %v", u.Name, err)
			}
			for _, k := range keys {
				if k.owner == u.Name {
					gone = append(gone, k.fp)
				}
			}
		}
		out, err := mf.Encode()
		if err != nil {
			t.Fatalf("Encode after edit on input %q: %v", in, err)
		}
		after, err := config.Parse(out)
		if err != nil {
			t.Fatalf("edited manifest rejected for input %q:\n%s\nerr: %v", in, out, err)
		}
		for _, fp := range gone {
			if u, ok := after.OwnerOf(fp); ok {
				t.Errorf("removed key %s still owned by %q (input %q):\n%s", fp, u.Name, in, out)
			}
		}
	})
}
```

Create `internal/manifest/testdata/fuzz/FuzzManifestEdit/seed-operator-last-key`:

```
go test fuzz v1
string("users:\n  # break-glass\n  - name: ops\n    operator: true\n    keys:\n      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIqI4910CfGV/VLbLTy6XXLKZwm/HZQSG/N0iAG0D29c ops@vault\n  - name: bob\n    keys: [\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58\"]\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\naccess:\n  - user: bob\n    servers: [\"*\"]\n# footer\n")
uint8(0)
```

Create `internal/manifest/testdata/fuzz/FuzzManifestEdit/seed-remove-wildcard-user`:

```
go test fuzz v1
string("users:\n  # --- staff ---\n  - name: bob\n    keys: [\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58\"]\n  - name: carol\n    keys: []\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: db-1, host: 10.0.0.9, user: deploy}\naccess:\n  # everyone but db\n  - user: bob\n    servers: [\"*\"]\n    except: [db-1]\n")
uint8(1)
```

Create `internal/manifest/testdata/fuzz/FuzzManifestEdit/seed-flow-null-operator` (the regression input for Task M1's flow-null fix):

```
go test fuzz v1
string("users: [{name: 0,operator,keys: [\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA000000000000000000000000000000000000000000\"]}]")
byte('\x14')
```

- [ ] **Step 2: Run the seeds, then fuzz briefly**

Run:

```bash
go test ./internal/manifest -run FuzzManifestEdit -v 2>&1 | grep -E '^(--- |ok)'
```

Expected: PASS, output includes:

```text
--- PASS: FuzzManifestEdit (…s)
ok  	github.com/javadh75/SSHepherd/internal/manifest	(…s)
```

Run:

```bash
go test ./internal/manifest -run '^$' -fuzz=FuzzManifestEdit -fuzztime=20s
```

Expected: PASS, output includes:

```text
PASS
ok  	github.com/javadh75/SSHepherd/internal/manifest	(…s)
```

If the fuzzer finds a failure it writes the input to `testdata/fuzz/FuzzManifestEdit/`; fix the bug, keep the input as a regression seed.

- [ ] **Step 3: Group M gate**

Run:

```bash
gofmt -l internal/manifest && go vet ./internal/manifest && go test -race ./internal/manifest && golangci-lint run ./internal/manifest/...
```

Expected: PASS, output includes:

```text
ok  	github.com/javadh75/SSHepherd/internal/manifest	(…s)
```

- [ ] **Commit**

```bash
git add internal/manifest/fuzz_edit_test.go internal/manifest/testdata/fuzz/FuzzManifestEdit
git commit -m "$(cat <<'EOF'
test(manifest): FuzzManifestEdit with committed seeds

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

## Group A — `internal/apply`: plurals, labels, scope, edit header (stage 1)

Owns `internal/apply/**` only.

### Task A1: Exhaustive pluralization of count strings [Group A]

**Files:**
- Modify: `internal/apply/report.go` (`Plural`; `→ N keys desired`; normalize detail)
- Modify: `internal/apply/plan.go` (wipe refusal; unparseable refusal via a `theLines` helper, keeping `planOne` under `gocyclo`'s 15; lockout refusal)
- Create: `internal/apply/plural_test.go`
- Modify: `internal/apply/report_test.go`, `internal/apply/identity_test.go` (assertions)
- Regenerate: `internal/apply/testdata/{plan_identity,plan_mixed,plan_mixed_color,plan_security,plan_security_color}.golden`

Every count string agrees with its number: `N key(s) installed`, `N key(s) and N unparseable line(s) installed`, `N unparseable line(s)` (and `fix the line`/`fix the lines`), `removing N non-key line(s)`, `removing N duplicate key line(s)`, `→ N key(s) desired`, and the lockout refusal (`none of the 2 keys you hold … would remain` / `the 1 key you hold … would not remain`). Ratios (`1/4 servers converged`, `apply 1 of 1 servers?`) are left as they are — they read as "N of M servers".

- [ ] **Step 1: Write the failing tests and update the existing assertions**

Create `internal/apply/plural_test.go`:

```go
package apply

import (
	"bytes"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func TestPlural(t *testing.T) {
	for _, tt := range []struct {
		n    int
		want string
	}{{0, "0 keys"}, {1, "1 key"}, {2, "2 keys"}} {
		if got := Plural(tt.n, "key", "keys"); got != tt.want {
			t.Errorf("Plural(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

// TestPluralizedCountStrings: every count string the plan and report print
// agrees with its number, singular and plural.
func TestPluralizedCountStrings(t *testing.T) {
	cfg := emptyDesiredCfg(t) // alice (k2) on web-1; bare has no grants
	web1 := renderedFor(t, cfg, "web-1")
	tests := []struct {
		name, server, content string
		want                  string
	}{
		{"one key wipe", "bare", testkeys.Line(t, 9) + "\n", "1 key installed but manifest grants none"},
		{"two keys wipe", "bare", testkeys.Line(t, 9) + "\n" + testkeys.Line(t, 8) + "\n", "2 keys installed but manifest grants none"},
		{"key and unparseable line wipe", "bare", testkeys.Line(t, 9) + "\ngarbage\n", "1 key and 1 unparseable line installed but manifest grants none"},
		{"keys and unparseable lines wipe", "bare", testkeys.Line(t, 9) + "\n" + testkeys.Line(t, 8) + "\ngarbage\nmore garbage\n", "2 keys and 2 unparseable lines installed"},
		{"one unparseable line", "web-1", testkeys.Line(t, 2) + "\ngarbage\n", "1 unparseable line — refusing to rewrite a file that could not be fully read (fix the line or"},
		{"two unparseable lines", "web-1", testkeys.Line(t, 2) + "\ngarbage\nmore\n", "2 unparseable lines — refusing to rewrite a file that could not be fully read (fix the lines or"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			read := map[string]audit.ReadResult{"web-1": {Content: web1}, "bare": {}}
			read[tt.server] = audit.ReadResult{Content: []byte(tt.content)}
			p := planFor(t, buildPlans(t, cfg, &fakeReader{byName: read}, []string{fp(t, 2)}), tt.server)
			if !strings.Contains(p.Refusal, tt.want) {
				t.Errorf("Refusal = %q, want it to contain %q", p.Refusal, tt.want)
			}
		})
	}

	t.Run("one key desired, plural non-key and duplicate lines", func(t *testing.T) {
		content := "# a\n\n" + testkeys.Line(t, 2) + " x\n" + testkeys.Line(t, 2) + " y\n" + testkeys.Line(t, 2) + " z\n"
		read := map[string]audit.ReadResult{"web-1": {Content: []byte(content)}}
		plans := buildPlans(t, cfg, &fakeReader{byName: read}, []string{fp(t, 2)})
		var buf bytes.Buffer
		Render(&buf, cfg, plans, RenderOptions{})
		for _, want := range []string{"→ 1 key desired", "removing 2 non-key lines (comments/blank)", "removing 2 duplicate key lines"} {
			if !strings.Contains(buf.String(), want) {
				t.Errorf("report lacks %q:\n%s", want, buf.String())
			}
		}
	})
}
```

In `internal/apply/report_test.go`, replace:

```go
		"normalize: removing 1 non-key lines (comments/blank)",
```

with:

```go
		"normalize: removing 1 non-key line (comments/blank)",
```

In `internal/apply/report_test.go`, replace:

```go
		"db-1 (deploy@10.0.0.9:22)  REFUSED: 1 keys installed but manifest grants none — refusing to wipe",
```

with:

```go
		"db-1 (deploy@10.0.0.9:22)  REFUSED: 1 key installed but manifest grants none — refusing to wipe",
```

In `internal/apply/report_test.go`, replace:

```go
		"removing 1 duplicate key lines (some carry options different from the first copy",
```

with:

```go
		"removing 1 duplicate key line (some carry options different from the first copy",
```

In `internal/apply/identity_test.go`, replace:

```go
			"none of the 1 keys you hold (identity files + agent) would remain in web-1's authorized_keys",
```

with:

```go
			"the 1 key you hold (identity files + agent) would not remain in web-1's authorized_keys",
```

- [ ] **Step 2: Run them to verify they fail**

Run:

```bash
go test ./internal/apply -run 'TestPlural|TestRenderPlanMixedGolden|TestIdentity'
```

Expected: FAIL, output includes:

```text
FAIL	github.com/javadh75/SSHepherd/internal/apply [build failed]
FAIL
internal/apply/plural_test.go:17:13: undefined: Plural
```

- [ ] **Step 3: Implement**

In `internal/apply/report.go`, replace:

```go
// RenderOptions tunes report presentation.
type RenderOptions struct {
	Color bool // ANSI-color glyphs and key words; off = byte-identical to plain
}
```

with:

```go
// RenderOptions tunes report presentation.
type RenderOptions struct {
	Color bool // ANSI-color glyphs and key words; off = byte-identical to plain
}

// Plural renders a count with its noun: "1 key", "2 keys", "0 keys".
func Plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
```

In `internal/apply/report.go`, replace:

```go
	fmt.Fprintf(w, "  → %d keys desired · %d add · %d remove · %d rewrite\n",
		len(p.Desired), len(p.Add), len(p.Remove), len(p.Rewrites))
```

with:

```go
	fmt.Fprintf(w, "  → %s desired · %d add · %d remove · %d rewrite\n",
		Plural(len(p.Desired), "key", "keys"), len(p.Add), len(p.Remove), len(p.Rewrites))
```

In `internal/apply/report.go`, replace:

```go
		parts = append(parts, fmt.Sprintf("removing %d non-key lines (comments/blank)", n.NonKeyLines))
```

with:

```go
		parts = append(parts, fmt.Sprintf("removing %s (comments/blank)", Plural(n.NonKeyLines, "non-key line", "non-key lines")))
```

In `internal/apply/report.go`, replace:

```go
		d := fmt.Sprintf("removing %d duplicate key lines", n.Duplicates)
```

with:

```go
		d := "removing " + Plural(n.Duplicates, "duplicate key line", "duplicate key lines")
```

In `internal/apply/plan.go`, replace:

```go
		p.Refusal = fmt.Sprintf("%d keys installed but manifest grants none — refusing to wipe",
			len(r.Diff.Unauthorized))
		if n := len(r.ParseErrs); n > 0 {
			p.Refusal = fmt.Sprintf(
				"%d keys and %d unparseable lines installed but manifest grants none — refusing to wipe",
				len(r.Diff.Unauthorized), n)
		}
```

with:

```go
		p.Refusal = fmt.Sprintf("%s installed but manifest grants none — refusing to wipe",
			Plural(len(r.Diff.Unauthorized), "key", "keys"))
		if n := len(r.ParseErrs); n > 0 {
			p.Refusal = fmt.Sprintf(
				"%s and %s installed but manifest grants none — refusing to wipe",
				Plural(len(r.Diff.Unauthorized), "key", "keys"), Plural(n, "unparseable line", "unparseable lines"))
		}
```

In `internal/apply/plan.go`, replace:

```go
		p.Refusal = fmt.Sprintf(
			"%d unparseable line(s) — refusing to rewrite a file that could not be fully read (fix the line(s) or correct authorized_keys_file)", n)
```

with:

```go
		p.Refusal = fmt.Sprintf(
			"%s — refusing to rewrite a file that could not be fully read (fix %s or correct authorized_keys_file)",
			Plural(n, "unparseable line", "unparseable lines"), theLines(n))
```

In `internal/apply/plan.go`, replace:

```go
func planOne(cfg *config.Config, r audit.ServerResult, held []sshconn.HeldKey) (ServerPlan, error) {
```

with:

```go
// theLines words the unparseable-line refusal's fix ("the line" / "the
// lines"); a helper so planOne stays under the gocyclo cap.
func theLines(n int) string {
	if n == 1 {
		return "the line"
	}
	return "the lines"
}

func planOne(cfg *config.Config, r audit.ServerResult, held []sshconn.HeldKey) (ServerPlan, error) {
```

In `internal/apply/plan.go`, replace:

```go
	refusal := fmt.Sprintf(
		"none of the %d keys you hold (identity files + agent) would remain in %s's authorized_keys — applying would lock this session out (held: %s). Add one of your keys to the manifest (or mark its user operator: true)",
		len(set), server, heldList(held))
```

with:

```go
	held1 := fmt.Sprintf("none of the %d keys you hold (identity files + agent) would remain", len(set))
	if len(set) == 1 {
		held1 = "the 1 key you hold (identity files + agent) would not remain"
	}
	refusal := fmt.Sprintf(
		"%s in %s's authorized_keys — applying would lock this session out (held: %s). Add one of your keys to the manifest (or mark its user operator: true)",
		held1, server, heldList(held))
```

- [ ] **Step 4: Regenerate the plan goldens and review the diff**

Run:

```bash
go test ./internal/apply -update
```

Expected: PASS, output includes:

```text
ok  	github.com/javadh75/SSHepherd/internal/apply	(…s)
```

Run:

```bash
git diff -U0 internal/apply/testdata | grep -E '^[-+][^-+]'
```

Expected: PASS, output includes:

```text
-  → 1 keys desired · 1 add · 0 remove · 0 rewrite
+  → 1 key desired · 1 add · 0 remove · 0 rewrite
-db-1 (deploy@10.0.0.9:22)  REFUSED: 1 keys installed but manifest grants none — refusing to wipe
+db-1 (deploy@10.0.0.9:22)  REFUSED: 1 key installed but manifest grants none — refusing to wipe
-  ~  (formatting)                                                                         normalize: removing 1 non-key lines (comments/blank)
+  ~  (formatting)                                                                         normalize: removing 1 non-key line (comments/blank)
-db-1 (deploy@10.0.0.9:22)  \x1b[1;31mREFUSED:\x1b[0m 1 keys installed but manifest grants none — refusing to wipe
+db-1 (deploy@10.0.0.9:22)  \x1b[1;31mREFUSED:\x1b[0m 1 key installed but manifest grants none — refusing to wipe
-  \x1b[0;33m~\x1b[0m  (formatting)                                                                         normalize: removing 1 non-key lines (comments/blank)
+  \x1b[0;33m~\x1b[0m  (formatting)                                                                         normalize: removing 1 non-key line (comments/blank)
-  ~  (formatting)                                                                         normalize: removing 1 duplicate key lines (some carry options different from the first copy)
+  ~  (formatting)                                                                         normalize: removing 1 duplicate key line (some carry options different from the first copy)
-  \x1b[0;33m~\x1b[0m  (formatting)                                                                         normalize: removing 1 duplicate key lines (some carry options different from the first copy)
+  \x1b[0;33m~\x1b[0m  (formatting)                                                                         normalize: removing 1 duplicate key line (some carry options different from the first copy)
```

The diff must show **only** these seven singular/plural changes — plain apply's report is otherwise unchanged:

Expected `internal/apply/testdata/plan_identity.golden` (exact bytes):

```text
web-1 (deploy@10.0.0.1:22)  REFUSED: none of the 2 keys you hold (identity files + agent) would remain in web-1's authorized_keys — applying would lock this session out (held: SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o (/home/ci/.ssh/ci_old), SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4 (agent)). Add one of your keys to the manifest (or mark its user operator: true); rotating an --identity key? pass the new key with another --identity, so the guard and the post-write login probe can use it

web-2 (deploy@10.0.0.2:22)
  +  alice  SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  add (authorized, missing)
  note: the audited file is absent yet login succeeded — sshd may consult
        another key source; creating the file is purely additive
  warning: only SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4 (agent) keeps access; none of your --identity keys survives — a run without this agent will be locked out
  → 1 key desired · 1 add · 0 remove · 0 rewrite

```

Expected `internal/apply/testdata/plan_mixed.golden` (exact bytes):

```text
db-1 (deploy@10.0.0.9:22)  REFUSED: 1 key installed but manifest grants none — refusing to wipe

web-1 (deploy@10.0.0.1:22)
  +  bob                 SHA256:zbv/nU7iZdO0fB0DalMI70dP6/yFD8sctXvvW4+OokY  ssh-ed25519  add (authorized, missing)
  -  (unknown)           SHA256:doxiASlJnKSD9j+JpVoWpfEFHjUrsF9ZYr+cir4FYjo  ssh-ed25519  remove (unauthorized)
  ~  alice (alice@work)  SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  rewrite comment: "alice@old" → "alice@work"
  ~  (formatting)                                                                         normalize: removing 1 non-key line (comments/blank)
  → 2 keys desired · 1 add · 1 remove · 1 rewrite

web-2 (deploy@10.0.0.2:22)  converged (no changes)

web-3 (deploy@10.0.0.3:22)  ERROR: dial tcp 10.0.0.3:22: connection refused

```

Expected `internal/apply/testdata/plan_mixed_color.golden` (exact bytes — each ESC byte is shown as the four characters `\x1b`):

```text
db-1 (deploy@10.0.0.9:22)  \x1b[1;31mREFUSED:\x1b[0m 1 key installed but manifest grants none — refusing to wipe

web-1 (deploy@10.0.0.1:22)
  \x1b[0;32m+\x1b[0m  bob                 SHA256:zbv/nU7iZdO0fB0DalMI70dP6/yFD8sctXvvW4+OokY  ssh-ed25519  add (authorized, missing)
  \x1b[0;31m-\x1b[0m  (unknown)           SHA256:doxiASlJnKSD9j+JpVoWpfEFHjUrsF9ZYr+cir4FYjo  ssh-ed25519  remove (unauthorized)
  \x1b[0;33m~\x1b[0m  alice (alice@work)  SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  rewrite comment: "alice@old" → "alice@work"
  \x1b[0;33m~\x1b[0m  (formatting)                                                                         normalize: removing 1 non-key line (comments/blank)
  → 2 keys desired · 1 add · 1 remove · 1 rewrite

web-2 (deploy@10.0.0.2:22)  converged (no changes)

web-3 (deploy@10.0.0.3:22)  \x1b[0;31mERROR:\x1b[0m dial tcp 10.0.0.3:22: connection refused

```

Expected `internal/apply/testdata/plan_security.golden` (exact bytes):

```text
web-1 (deploy@10.0.0.1:22)
  ~  alice (alice@work)  SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  rewrite options: "from=\"10.0.0.5\",command=\"/usr/bin/pg_dump-wrapper\"" → (none)
  ~  (formatting)                                                                         normalize: removing 1 duplicate key line (some carry options different from the first copy)
  -  (authorized_keys2)                                                                   disable ~/.ssh/authorized_keys2 → ~/.ssh/authorized_keys2.sshepherd.disabled (unmanaged; sshd would keep accepting its keys)
  warning: the rewrite of alice (alice@work)'s key drops restrictive option(s) "from=\"10.0.0.5\"", "command=\"/usr/bin/pg_dump-wrapper\"" — the manifest line grants more than the server does today
  → 3 keys desired · 0 add · 0 remove · 1 rewrite

```

Expected `internal/apply/testdata/plan_security_color.golden` (exact bytes — each ESC byte is shown as the four characters `\x1b`):

```text
web-1 (deploy@10.0.0.1:22)
  \x1b[0;33m~\x1b[0m  alice (alice@work)  SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  \x1b[1;31mrewrite options: "from=\"10.0.0.5\",command=\"/usr/bin/pg_dump-wrapper\"" → (none)\x1b[0m
  \x1b[0;33m~\x1b[0m  (formatting)                                                                         normalize: removing 1 duplicate key line (some carry options different from the first copy)
  \x1b[0;31m-\x1b[0m  (authorized_keys2)                                                                   disable ~/.ssh/authorized_keys2 → ~/.ssh/authorized_keys2.sshepherd.disabled (unmanaged; sshd would keep accepting its keys)
  \x1b[1;31mwarning:\x1b[0m the rewrite of alice (alice@work)'s key drops restrictive option(s) "from=\"10.0.0.5\"", "command=\"/usr/bin/pg_dump-wrapper\"" — the manifest line grants more than the server does today
  → 3 keys desired · 0 add · 0 remove · 1 rewrite

```

- [ ] **Step 5: Run the package**

Run:

```bash
go test ./internal/apply
```

Expected: PASS, output includes:

```text
ok  	github.com/javadh75/SSHepherd/internal/apply	(…s)
```

- [ ] **Commit**

```bash
git add internal/apply/report.go internal/apply/plan.go internal/apply/plural_test.go internal/apply/report_test.go internal/apply/identity_test.go internal/apply/testdata
git commit -m "$(cat <<'EOF'
fix(apply): singular/plural for every report count string

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

### Task A2: `RenderOptions.Former` — `(revoked)` / `(rotated out)` labels [Group A]

**Files:**
- Modify: `internal/apply/report.go` (`RenderOptions`, `label`, `renderChange`)
- Create: `internal/apply/former_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/apply/former_test.go`:

```go
package apply

import (
	"bytes"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestRenderFormerLabels: a key the edited config no longer owns is
// labeled from the former config — "(revoked)" by default, the given note
// for rotate — and a key neither config knows stays "(unknown)".
func TestRenderFormerLabels(t *testing.T) {
	former := planCfg(t) // op k1 operator, alice k2, bob k3 on web-1
	edited, err := config.Parse([]byte(`
users:
  - {name: op, operator: true, comment: "op@sshepherd", keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 5) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: bob, servers: [web-1]}
`))
	if err != nil {
		t.Fatal(err)
	}
	content := testkeys.Line(t, 1) + " op@sshepherd\n" + testkeys.Line(t, 2) + " alice@work\n" +
		testkeys.Line(t, 3) + " bob\n" + testkeys.Line(t, 9) + " stray\n"
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {Content: []byte(content)}}}
	plans := buildPlans(t, edited, r, []string{fp(t, 1)})

	for _, tt := range []struct {
		note string
		want []string
	}{
		{"", []string{"alice (revoked)", "bob (revoked)", "(unknown)"}},
		{"rotated out", []string{"alice (rotated out)", "bob (rotated out)"}},
	} {
		var buf bytes.Buffer
		Render(&buf, edited, plans, RenderOptions{Former: former, FormerNote: tt.note})
		for _, want := range tt.want {
			if !strings.Contains(buf.String(), want) {
				t.Errorf("note %q: report lacks %q:\n%s", tt.note, want, buf.String())
			}
		}
	}
	var plain bytes.Buffer
	Render(&plain, edited, plans, RenderOptions{})
	if strings.Contains(plain.String(), "(revoked)") || strings.Count(plain.String(), "(unknown)") != 3 {
		t.Errorf("plain apply (no Former) must label every unowned key (unknown):\n%s", plain.String())
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run:

```bash
go test ./internal/apply -run TestRenderFormerLabels
```

Expected: FAIL, output includes:

```text
FAIL	github.com/javadh75/SSHepherd/internal/apply [build failed]
FAIL
internal/apply/former_test.go:43:45: unknown field Former in struct literal of type RenderOptions
internal/apply/former_test.go:43:61: unknown field FormerNote in struct literal of type RenderOptions
```

- [ ] **Step 3: Implement**

In `internal/apply/report.go`, replace:

```go
type RenderOptions struct {
	Color bool // ANSI-color glyphs and key words; off = byte-identical to plain
}
```

with:

```go
type RenderOptions struct {
	Color bool // ANSI-color glyphs and key words; off = byte-identical to plain
	// Former is the as-loaded config before a revoke/rotate edit; nil for
	// plain apply. A key the rendered config no longer owns is labeled with
	// its former owner ("alice (revoked)") instead of "(unknown)".
	Former *config.Config
	// FormerNote is the parenthesized note on such a label: "revoked" when
	// empty, "rotated out" for rotate.
	FormerNote string
}
```

In `internal/apply/report.go`, replace:

```go
// label mirrors audit's row label: the owning user (with their comment:
// when set), or "(unknown)" for a key the manifest does not know.
func label(cfg *config.Config, k authkeys.Key) string {
	u, ok := cfg.OwnerOf(k.Fingerprint)
	if !ok {
		return "(unknown)"
	}
```

with:

```go
// label mirrors audit's row label: the owning user (with their comment:
// when set); for a key only opts.Former owns, its former owner and the
// edit's note ("alice (revoked)", "deploy (rotated out)"); else
// "(unknown)" for a key the manifest does not know.
func label(cfg *config.Config, opts RenderOptions, k authkeys.Key) string {
	u, ok := cfg.OwnerOf(k.Fingerprint)
	if !ok {
		if opts.Former != nil {
			if fu, fok := opts.Former.OwnerOf(k.Fingerprint); fok {
				note := opts.FormerNote
				if note == "" {
					note = "revoked"
				}
				return fmt.Sprintf("%s (%s)", fu.Name, note)
			}
		}
		return "(unknown)"
	}
```

In `internal/apply/report.go`, replace:

```go
			renderChange(w, cfg, p, pal)
```

with:

```go
			renderChange(w, cfg, p, pal, opts)
```

In `internal/apply/report.go`, replace:

```go
func renderChange(w io.Writer, cfg *config.Config, p ServerPlan, pal palette) {
```

with:

```go
func renderChange(w io.Writer, cfg *config.Config, p ServerPlan, pal palette, opts RenderOptions) {
```

In `internal/apply/report.go`, replace **both** occurrences of:

```go
label(cfg, k)
```

with:

```go
label(cfg, opts, k)
```

In `internal/apply/report.go`, replace **both** occurrences of:

```go
label(cfg, rw.Key)
```

with:

```go
label(cfg, opts, rw.Key)
```

- [ ] **Step 4: Run the package (plain apply's goldens must not change)**

Run:

```bash
go test ./internal/apply
```

Expected: PASS, output includes:

```text
ok  	github.com/javadh75/SSHepherd/internal/apply	(…s)
```

- [ ] **Commit**

```bash
git add internal/apply/report.go internal/apply/former_test.go
git commit -m "$(cat <<'EOF'
feat(apply): label keys only the former config owns (revoked / rotated out)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

### Task A3: `Affected` — the edit's server scope [Group A]

**Files:**
- Create: `internal/apply/affected.go`
- Create: `internal/apply/affected_test.go`

A server is affected iff the file apply would render for it differs between the old and the edited config (same renderer `Build` uses, so comment-only changes count). `Emptied` is the subset left with an empty desired set that was non-empty before.

- [ ] **Step 1: Write the failing test**

Create `internal/apply/affected_test.go`:

```go
package apply

import (
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// affectedFleet: ops (operator, k1) everywhere; alice (k2) on web-1 and
// web-2; bob (k3) everywhere but db-1 via a wildcard; carol (k4) alone on
// db-1; dave (k5) granted nowhere. Servers: web-1, web-2, db-1, lone (no
// grants but the operator).
func affectedFleet(t *testing.T, users string, access string) *config.Config {
	t.Helper()
	y := "users:\n" + users + `
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
  - {name: db-1, host: 10.0.0.9, user: deploy}
access:
` + access
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("affectedFleet: %v\n%s", err, y)
	}
	return cfg
}

func TestAffected(t *testing.T) {
	k := func(seed byte) string { return `"` + testkeys.Line(t, seed) + `"` }
	alice := "  - {name: alice, keys: [" + k(2) + "]}\n"
	bob := "  - {name: bob, keys: [" + k(3) + "]}\n"
	carol := "  - {name: carol, keys: [" + k(4) + "]}\n"
	dave := "  - {name: dave, keys: [" + k(5) + "]}\n"
	ops := "  - {name: ops, operator: true, keys: [" + k(1) + "]}\n"
	aliceGrant := "  - {user: alice, servers: [web-1, web-2]}\n"
	bobGrant := "  - {user: bob, servers: [\"*\"], except: [db-1]}\n"
	carolGrant := "  - {user: carol, servers: [db-1]}\n"
	full := affectedFleet(t, alice+bob+carol+dave, aliceGrant+bobGrant+carolGrant)

	tests := []struct {
		name        string
		old, edited *config.Config
		servers     []string
		emptied     []string
	}{
		{"wildcard with except: only the covered servers",
			full, affectedFleet(t, alice+carol+dave, aliceGrant+carolGrant),
			[]string{"web-1", "web-2"}, nil},
		{"operator fleet-wide grant touches every server",
			affectedFleet(t, ops+alice, aliceGrant), affectedFleet(t, alice, aliceGrant),
			[]string{"web-1", "web-2", "db-1"}, []string{"db-1"}},
		{"user with no grants: zero servers",
			full, affectedFleet(t, alice+bob+carol, aliceGrant+bobGrant+carolGrant),
			nil, nil},
		{"rotation touches only that user's servers",
			full, affectedFleet(t, strings.Replace(alice, k(2), k(6), 1)+bob+carol+dave, aliceGrant+bobGrant+carolGrant),
			[]string{"web-1", "web-2"}, nil},
		{"sole grantee server is emptied",
			full, affectedFleet(t, alice+bob+dave, aliceGrant+bobGrant),
			[]string{"db-1"}, []string{"db-1"}},
		{"identical configs: nothing",
			full, full, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Affected(tt.old, tt.edited)
			if !slices.Equal(got.Servers, tt.servers) || !slices.Equal(got.Emptied, tt.emptied) {
				t.Errorf("Affected = %+v, want servers %v emptied %v", got, tt.servers, tt.emptied)
			}
		})
	}
}

// TestAffectedCommentOnlyChange: a rotation that changes only the rendered
// comment still changes the bytes, so the server is affected.
func TestAffectedCommentOnlyChange(t *testing.T) {
	line := testkeys.Line(t, 2)
	mk := func(comment string) *config.Config {
		return affectedFleet(t, `  - {name: alice, keys: ["`+line+comment+`"]}`+"\n", "  - {user: alice, servers: [web-2]}\n")
	}
	if got := Affected(mk(" old@x"), mk(" new@x")); !slices.Equal(got.Servers, []string{"web-2"}) {
		t.Errorf("Affected = %+v, want web-2", got)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run:

```bash
go test ./internal/apply -run TestAffected
```

Expected: FAIL, output includes:

```text
FAIL	github.com/javadh75/SSHepherd/internal/apply [build failed]
FAIL
internal/apply/affected_test.go:70:11: undefined: Affected
internal/apply/affected_test.go:85:12: undefined: Affected
```

- [ ] **Step 3: Implement**

Create `internal/apply/affected.go`:

```go
package apply

import (
	"bytes"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
)

// AffectedSet is the scope of a manifest edit (revoke/rotate): the servers
// whose rendered desired file changes between the old and the new config.
type AffectedSet struct {
	// Servers lists the servers whose rendered desired bytes differ, in
	// manifest order — including servers where reality already matches
	// the new render (apply reports them converged).
	Servers []string
	// Emptied is the subset whose desired set is empty under the new config
	// but not the old: apply never empties a server, so a key removed by
	// the edit cannot be removed there by SSHepherd.
	Emptied []string
}

// Affected compares, per server, the file apply would render under old and
// under edited. Pure. Both configs must hold the same servers (revoke and
// rotate never change the server list); servers are walked in edited's
// manifest order.
func Affected(old, edited *config.Config) AffectedSet {
	var s AffectedSet
	for _, srv := range edited.Servers {
		before, after := renderFor(old, srv.Name), renderFor(edited, srv.Name)
		if before != nil && after != nil && bytes.Equal(before, after) {
			continue
		}
		s.Servers = append(s.Servers, srv.Name)
		if len(edited.DesiredFor(srv.Name)) == 0 && len(old.DesiredFor(srv.Name)) > 0 {
			s.Emptied = append(s.Emptied, srv.Name)
		}
	}
	return s
}

// renderFor renders a server's desired file exactly as Build does; nil on
// a render failure (impossible for a validated config), which Affected
// treats as "changed" — over-including a server is the safe direction.
func renderFor(cfg *config.Config, server string) []byte {
	out, err := authkeys.Render(desiredEntries(cfg, server))
	if err != nil {
		return nil
	}
	return out
}
```

- [ ] **Step 4: Run it**

Run:

```bash
go test ./internal/apply -run TestAffected -v 2>&1 | grep -E '^\s*--- '
```

Expected: PASS, output includes:

```text
--- PASS: TestAffected (…s)
    --- PASS: TestAffected/wildcard_with_except:_only_the_covered_servers (…s)
    --- PASS: TestAffected/operator_fleet-wide_grant_touches_every_server (…s)
    --- PASS: TestAffected/user_with_no_grants:_zero_servers (…s)
    --- PASS: TestAffected/rotation_touches_only_that_user's_servers (…s)
    --- PASS: TestAffected/sole_grantee_server_is_emptied (…s)
```

- [ ] **Commit**

```bash
git add internal/apply/affected.go internal/apply/affected_test.go
git commit -m "$(cat <<'EOF'
feat(apply): Affected computes the servers an edit changes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

### Task A4: Edit header and prompt (`EditSummary`, `RenderEditHeader`, `EditPrompt`) [Group A]

**Files:**
- Create: `internal/apply/edit.go`
- Create: `internal/apply/edit_test.go`
- Create (via `-update`): `internal/apply/testdata/edit_header_{user,key,rotate,operator,operator_color,none}.golden`, `internal/apply/testdata/edit_prompt.golden`

Header layout: one `manifest edit:` line per edit — with ` — N server(s) affected` on the line itself when there is exactly one edit, else a closing `manifest edit: N changes — …` line; then a `note:` per user left without keys (the operator-flag variant when cleared); an `OPERATOR:` line (bold red) per operator target; a `warning:` (yellow) per emptied server. Same palette as the plan report; plain when color is off.

- [ ] **Step 1: Write the failing tests**

Create `internal/apply/edit_test.go`:

```go
package apply

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestRenderEditHeaderGoldens(t *testing.T) {
	tests := []struct {
		golden string
		s      EditSummary
		color  bool
	}{
		{"edit_header_user.golden", EditSummary{
			Edits:    []Edit{{Kind: EditRemoveUser, User: "alice", Keys: 2, Grants: 3}},
			Affected: 3,
			Emptied:  []EmptiedServer{{Server: "db-1", Users: []string{"alice"}, Keys: 1}},
		}, false},
		{"edit_header_key.golden", EditSummary{
			Edits:    []Edit{{Kind: EditRemoveKey, User: "bob", Fingerprint: fp(t, 3), NoKeysLeft: true}},
			Affected: 2,
		}, false},
		{"edit_header_rotate.golden", EditSummary{
			Edits: []Edit{{Kind: EditRotate, User: "deploy", Fingerprint: fp(t, 4), NewFingerprint: fp(t, 5),
				KeepsExpiry: `expiry-time="20270101"`}},
			Affected: 5,
		}, false},
		{"edit_header_operator.golden", EditSummary{
			Edits: []Edit{
				{Kind: EditRemoveKey, User: "ops-bot", Fingerprint: fp(t, 1), NoKeysLeft: true, ClearsOperator: true},
				{Kind: EditRemoveUser, User: "alice", Keys: 1, Grants: 1},
			},
			Affected:  1,
			Operators: []string{"ops-bot"},
			Emptied:   []EmptiedServer{{Server: "db-1", Users: []string{"alice", "ops-bot"}, Keys: 2}},
		}, false},
		{"edit_header_operator_color.golden", EditSummary{
			Edits:     []Edit{{Kind: EditRemoveUser, User: "ops-bot", Keys: 2, Grants: 0}},
			Affected:  4,
			Operators: []string{"ops-bot"},
			Emptied:   []EmptiedServer{{Server: "db-1", Users: []string{"ops-bot"}, Keys: 2}},
		}, true},
		{"edit_header_none.golden", EditSummary{
			Edits:    []Edit{{Kind: EditRemoveUser, User: "dave", Keys: 1, Grants: 0}},
			Affected: 0,
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.golden, func(t *testing.T) {
			var buf bytes.Buffer
			RenderEditHeader(&buf, tt.s, RenderOptions{Color: tt.color})
			checkGolden(t, tt.golden, buf.Bytes())
		})
	}
}

// TestRenderEditHeaderShapes pins the key phrases independent of goldens.
func TestRenderEditHeaderShapes(t *testing.T) {
	var buf bytes.Buffer
	RenderEditHeader(&buf, EditSummary{
		Edits:    []Edit{{Kind: EditRemoveUser, User: "alice", Keys: 1, Grants: 1}},
		Affected: 1,
		Emptied:  []EmptiedServer{{Server: "db-1", Users: []string{"alice"}, Keys: 1}},
	}, RenderOptions{})
	for _, want := range []string{
		"manifest edit: remove user alice (1 key, 1 access grant) — 1 server affected\n",
		"warning: db-1 would have no granted keys — apply never empties a server, so alice's key stays installed there; grant another user (or an operator) on db-1 first, or remove the key by hand\n",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("header lacks %q:\n%s", want, buf.String())
		}
	}
}

func TestRenderEditHeaderColorStrippedEqualsPlain(t *testing.T) {
	s := EditSummary{
		Edits:     []Edit{{Kind: EditRemoveUser, User: "ops-bot", Keys: 2}},
		Affected:  4,
		Operators: []string{"ops-bot"},
		Emptied:   []EmptiedServer{{Server: "db-1", Users: []string{"ops-bot"}, Keys: 2}},
	}
	var plain, color bytes.Buffer
	RenderEditHeader(&plain, s, RenderOptions{})
	RenderEditHeader(&color, s, RenderOptions{Color: true})
	stripped := color.String()
	for _, code := range []string{codeBoldRed, codeYellow} {
		stripped = strings.ReplaceAll(stripped, "\x1b["+code+"m", "")
	}
	if stripped = strings.ReplaceAll(stripped, "\x1b[0m", ""); stripped != plain.String() {
		t.Errorf("stripped color = %q, want plain %q", stripped, plain.String())
	}
}

// TestEditPromptGolden pins every prompt form, exactly as confirm prints
// it (question + " [y/N]").
func TestEditPromptGolden(t *testing.T) {
	var buf bytes.Buffer
	for _, q := range []string{
		EditPrompt(nil, 2, 3, false),
		EditPrompt(nil, 0, 3, false),
		EditPrompt(nil, 0, 0, false),
		EditPrompt(nil, 0, 3, true),
		EditPrompt([]string{"ops-bot"}, 1, 4, false),
		EditPrompt([]string{"ops-bot", "ci"}, 0, 2, true),
	} {
		fmt.Fprintln(&buf, q+" [y/N]")
	}
	want := "save manifest edit and write 2 of 3 affected servers? [y/N]\n"
	if !strings.HasPrefix(buf.String(), want) {
		t.Errorf("first prompt = %q, want %q", strings.SplitAfter(buf.String(), "\n")[0], want)
	}
	checkGolden(t, "edit_prompt.golden", buf.Bytes())
}
```

- [ ] **Step 2: Run them to verify they fail**

Run:

```bash
go test ./internal/apply -run 'TestRenderEditHeader|TestEditPrompt'
```

Expected: FAIL, output includes:

```text
FAIL	github.com/javadh75/SSHepherd/internal/apply [build failed]
FAIL
internal/apply/edit_test.go:13:10: undefined: EditSummary
internal/apply/edit_test.go:16:31: undefined: EditSummary
internal/apply/edit_test.go:17:16: undefined: Edit
internal/apply/edit_test.go:17:28: undefined: EditRemoveUser
```

- [ ] **Step 3: Implement**

Create `internal/apply/edit.go`:

```go
package apply

import (
	"fmt"
	"io"
	"strings"
)

// EditKind names one manifest edit revoke/rotate performs.
type EditKind string

// The three edits.
const (
	EditRemoveUser EditKind = "remove-user" // revoke USER
	EditRemoveKey  EditKind = "remove-key"  // revoke --key
	EditRotate     EditKind = "rotate"      // rotate USER --old --new
)

// Edit is one manifest edit, resolved against the as-loaded config.
type Edit struct {
	Kind EditKind
	// User is the removed user (EditRemoveUser), the removed key's owner
	// (EditRemoveKey), or the rotated user (EditRotate).
	User string
	// Keys and Grants count what EditRemoveUser deletes: the user's key
	// lines and the access: entries naming the user.
	Keys, Grants int
	// Fingerprint is the removed key (EditRemoveKey) or the old key
	// (EditRotate); NewFingerprint is the rotated-in key.
	Fingerprint, NewFingerprint string
	// KeepsExpiry is the old line's expiry-time= option, verbatim, that a
	// rotation carries over ("" when none).
	KeepsExpiry string
	// NoKeysLeft (EditRemoveKey) reports that the owner has no keys left
	// after the whole edit; ClearsOperator that the owner was an operator
	// whose flag the edit clears (operator: true needs a key).
	NoKeysLeft, ClearsOperator bool
}

// EmptiedServer is an affected server left with no granted keys: the
// removed keys stay installed there (apply never empties a server).
type EmptiedServer struct {
	Server string
	Users  []string // owners of the keys that stay installed, old-config order
	Keys   int      // how many removed keys were granted there
}

// EditSummary is everything the edit header shows.
type EditSummary struct {
	Edits     []Edit
	Affected  int      // servers whose rendered desired file changes
	Operators []string // operator targets, acknowledged with --operator
	Emptied   []EmptiedServer
}

// RenderEditHeader writes the manifest-edit header printed above the
// per-server plan (and alone under --no-apply): one line per edit (the
// affected-server count on the line of a lone edit, else on a closing
// line), a note per user left without keys, an OPERATOR line per operator
// target, and a warning per emptied server.
func RenderEditHeader(w io.Writer, s EditSummary, opts RenderOptions) {
	pal := palette{on: opts.Color}
	affected := Plural(s.Affected, "server", "servers") + " affected"
	if s.Affected == 0 {
		affected = "no servers affected"
	}
	for _, e := range s.Edits {
		line := "manifest edit: " + editText(e)
		if len(s.Edits) == 1 {
			line += " — " + affected
		}
		fmt.Fprintln(w, line)
	}
	if len(s.Edits) > 1 {
		fmt.Fprintf(w, "manifest edit: %d changes — %s\n", len(s.Edits), affected)
	}
	for _, e := range s.Edits {
		switch {
		case e.ClearsOperator:
			fmt.Fprintf(w, "note: %s has no keys left, so its operator flag is cleared — 'sshepherd revoke %s' removes the user\n", e.User, e.User)
		case e.NoKeysLeft:
			fmt.Fprintf(w, "note: %s has no keys left — 'sshepherd revoke %s' removes the user\n", e.User, e.User)
		}
	}
	for _, op := range s.Operators {
		fmt.Fprintf(w, "%s %s is an operator (fleet-wide, protected); --operator given\n", pal.paint(codeBoldRed, "OPERATOR:"), op)
	}
	for _, e := range s.Emptied {
		fmt.Fprintf(w, "%s %s would have no granted keys — apply never empties a server, so %s installed there; grant another user (or an operator) on %s first, or remove the key by hand\n",
			pal.paint(codeYellow, "warning:"), e.Server, stayText(e), e.Server)
	}
}

// editText describes one edit.
func editText(e Edit) string {
	switch e.Kind {
	case EditRemoveUser:
		return fmt.Sprintf("remove user %s (%s, %s)", e.User,
			Plural(e.Keys, "key", "keys"), Plural(e.Grants, "access grant", "access grants"))
	case EditRemoveKey:
		return fmt.Sprintf("remove key %s from %s", e.Fingerprint, e.User)
	default:
		t := fmt.Sprintf("rotate %s key %s → %s", e.User, e.Fingerprint, e.NewFingerprint)
		if e.KeepsExpiry != "" {
			t += fmt.Sprintf(" (keeps %s)", e.KeepsExpiry)
		}
		return t
	}
}

// stayText names what stays installed on an emptied server.
func stayText(e EmptiedServer) string {
	switch {
	case len(e.Users) > 1:
		return "the keys of " + strings.Join(e.Users, ", ") + " stay"
	case e.Keys > 1:
		return e.Users[0] + "'s keys stay"
	case len(e.Users) == 1:
		return e.Users[0] + "'s key stays"
	}
	return "the removed key stays"
}

// EditPrompt is revoke/rotate's confirmation question (confirm appends
// " [y/N] "): the save is always asked for, with the write count when
// servers will be written, prefixed "OPERATOR NAME: " per operator target.
func EditPrompt(operators []string, toWrite, affected int, noApply bool) string {
	var b strings.Builder
	for _, op := range operators {
		fmt.Fprintf(&b, "OPERATOR %s: ", op)
	}
	switch {
	case noApply:
		b.WriteString("save manifest edit?")
	case toWrite == 0:
		b.WriteString("save manifest edit (no servers need a write)?")
	default:
		fmt.Fprintf(&b, "save manifest edit and write %d of %d affected servers?", toWrite, affected)
	}
	return b.String()
}
```

- [ ] **Step 4: Generate the goldens and run the tests**

Run:

```bash
go test ./internal/apply -run 'TestRenderEditHeader|TestEditPrompt' -update
```

Expected: PASS, output includes:

```text
ok  	github.com/javadh75/SSHepherd/internal/apply	(…s)
```

Expected `internal/apply/testdata/edit_header_key.golden` (exact bytes):

```text
manifest edit: remove key SHA256:zbv/nU7iZdO0fB0DalMI70dP6/yFD8sctXvvW4+OokY from bob — 2 servers affected
note: bob has no keys left — 'sshepherd revoke bob' removes the user
```

Expected `internal/apply/testdata/edit_header_none.golden` (exact bytes):

```text
manifest edit: remove user dave (1 key, 0 access grants) — no servers affected
```

Expected `internal/apply/testdata/edit_header_operator.golden` (exact bytes):

```text
manifest edit: remove key SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8 from ops-bot
manifest edit: remove user alice (1 key, 1 access grant)
manifest edit: 2 changes — 1 server affected
note: ops-bot has no keys left, so its operator flag is cleared — 'sshepherd revoke ops-bot' removes the user
OPERATOR: ops-bot is an operator (fleet-wide, protected); --operator given
warning: db-1 would have no granted keys — apply never empties a server, so the keys of alice, ops-bot stay installed there; grant another user (or an operator) on db-1 first, or remove the key by hand
```

Expected `internal/apply/testdata/edit_header_operator_color.golden` (exact bytes — each ESC byte is shown as the four characters `\x1b`):

```text
manifest edit: remove user ops-bot (2 keys, 0 access grants) — 4 servers affected
\x1b[1;31mOPERATOR:\x1b[0m ops-bot is an operator (fleet-wide, protected); --operator given
\x1b[0;33mwarning:\x1b[0m db-1 would have no granted keys — apply never empties a server, so ops-bot's keys stay installed there; grant another user (or an operator) on db-1 first, or remove the key by hand
```

Expected `internal/apply/testdata/edit_header_rotate.golden` (exact bytes):

```text
manifest edit: rotate deploy key SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o → SHA256:LA4QoSmstGCy/UHfdU3jKjnPz56pQzud9OmslMh3g8w (keeps expiry-time="20270101") — 5 servers affected
```

Expected `internal/apply/testdata/edit_header_user.golden` (exact bytes):

```text
manifest edit: remove user alice (2 keys, 3 access grants) — 3 servers affected
warning: db-1 would have no granted keys — apply never empties a server, so alice's key stays installed there; grant another user (or an operator) on db-1 first, or remove the key by hand
```

Expected `internal/apply/testdata/edit_prompt.golden` (exact bytes):

```text
save manifest edit and write 2 of 3 affected servers? [y/N]
save manifest edit (no servers need a write)? [y/N]
save manifest edit (no servers need a write)? [y/N]
save manifest edit? [y/N]
OPERATOR ops-bot: save manifest edit and write 1 of 4 affected servers? [y/N]
OPERATOR ops-bot: OPERATOR ci: save manifest edit? [y/N]
```

Run:

```bash
go test ./internal/apply
```

Expected: PASS, output includes:

```text
ok  	github.com/javadh75/SSHepherd/internal/apply	(…s)
```

- [ ] **Step 5: Group A gate**

Run:

```bash
gofmt -l internal/apply && go vet ./internal/apply && go test -race ./internal/apply && go build ./... && golangci-lint run ./internal/apply/...
```

Expected: PASS, output includes:

```text
ok  	github.com/javadh75/SSHepherd/internal/apply	(…s)
```

- [ ] **Commit**

```bash
git add internal/apply/edit.go internal/apply/edit_test.go internal/apply/testdata
git commit -m "$(cat <<'EOF'
feat(apply): manifest-edit header and confirmation prompt

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

## Group C1 — `cmd/sshepherd`: run body, KEY classification, manifest save (stage 2)

Starts after stage 1 is merged (uses `apply.Plural` and `apply.RenderOptions.Former`). Group A's pluralization breaks no `cmd/sshepherd` assertion (verified: `TestApplyServerFilterSkippedNote`'s `(1 servers skipped by --server)` is a `cmd` string this group pluralizes itself in Task C1.2; `0/1 servers converged` and the E2E `unparseable line` check still match).

### Task C1.1: Shared flags and the manifest target (`edit.go`) [Group C1]

**Files:**
- Create: `cmd/sshepherd/edit.go`
- Create: `cmd/sshepherd/edit_test.go`

`runFlags.register` declares exactly apply's flags and help texts (`--config`, `--known-hosts`, `--parallel`, `--dry-run`, `--yes`, `--dry-run`⊕`--yes`, the three identity flags) so `revoke`/`rotate` share them. `manifestTarget` keeps the exact bytes read and the symlink-resolved path: the save's compare-and-swap and plain apply's pre-write re-check compare against them.

- [ ] **Step 1: Write the failing test**

Create `cmd/sshepherd/edit_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadManifestAndUnchanged(t *testing.T) {
	path := writeConfig(t, "users: []\n")
	m, err := readManifest(path)
	if err != nil {
		t.Fatalf("readManifest: %v", err)
	}
	if string(m.Loaded) != "users: []\n" || m.Path != path {
		t.Errorf("target = %+v", m)
	}
	if err := m.Unchanged(); err != nil {
		t.Errorf("Unchanged on an untouched file: %v", err)
	}
	if err := os.WriteFile(path, []byte("users: []\n# edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Unchanged(); err == nil || !strings.Contains(err.Error(), "manifest "+path+" changed since it was read; re-run") {
		t.Errorf("Unchanged = %v, want the changed-manifest error", err)
	}
	if _, err := readManifest(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("readManifest of a missing file succeeded")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run:

```bash
go test ./cmd/sshepherd -run TestReadManifestAndUnchanged
```

Expected: FAIL, output includes:

```text
FAIL	github.com/javadh75/SSHepherd/cmd/sshepherd [build failed]
FAIL
cmd/sshepherd/edit_test.go:12:12: undefined: readManifest
cmd/sshepherd/edit_test.go:28:15: undefined: readManifest
```

- [ ] **Step 3: Implement**

Create `cmd/sshepherd/edit.go`:

```go
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// runFlags are the flags apply, revoke and rotate share, registered with
// apply's defaults and help text (apply adds --server on top).
type runFlags struct {
	cfgPath    string
	knownHosts string
	parallel   int
	dryRun     bool
	yes        bool
	idf        identityFlags
}

// register declares the shared flags on cmd.
func (f *runFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.cfgPath, "config", "sshepherd.yaml", "path to the manifest")
	cmd.Flags().StringVar(&f.knownHosts, "known-hosts", defaultKnownHosts, "path to known_hosts (strict host-key checking)")
	cmd.Flags().IntVar(&f.parallel, "parallel", defaultParallel, "max concurrent server connections")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "plan and report only; never write")
	cmd.Flags().BoolVar(&f.yes, "yes", false, "skip the confirmation prompt (automation)")
	cmd.MarkFlagsMutuallyExclusive("dry-run", "yes")
	f.idf.register(cmd)
}

// manifestTarget is the manifest as a run read it: the path given, the
// resolved file (symlinks followed — the save writes there and leaves the
// link intact), and the exact bytes read, which the save's compare-and-swap
// and plain apply's pre-write re-check compare against.
type manifestTarget struct {
	Path     string
	Resolved string
	Loaded   []byte
}

// readManifest reads the manifest once and resolves its real path.
func readManifest(path string) (manifestTarget, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the user's own --config flag
	if err != nil {
		return manifestTarget{}, fmt.Errorf("read manifest: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return manifestTarget{}, fmt.Errorf("read manifest: %w", err)
	}
	return manifestTarget{Path: path, Resolved: resolved, Loaded: data}, nil
}

// Unchanged re-reads the resolved file: a manifest that changed since it
// was read (a concurrent revoke, a hand edit, a git pull) must not be
// planned against or overwritten.
func (m manifestTarget) Unchanged() error {
	now, err := os.ReadFile(m.Resolved)
	if err != nil {
		return fmt.Errorf("re-read manifest %s: %w", m.Path, err)
	}
	if !bytes.Equal(now, m.Loaded) {
		return fmt.Errorf("manifest %s changed since it was read; re-run", m.Path)
	}
	return nil
}
```

- [ ] **Step 4: Run it**

Run:

```bash
go test ./cmd/sshepherd -run TestReadManifestAndUnchanged
```

Expected: PASS, output includes:

```text
ok  	github.com/javadh75/SSHepherd/cmd/sshepherd	(…s)
```

- [ ] **Commit**

```bash
git add cmd/sshepherd/edit.go cmd/sshepherd/edit_test.go
git commit -m "$(cat <<'EOF'
feat(cmd): shared run flags and the manifest read target

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

### Task C1.2: `runApply(applyRun)` — apply's reusable run body + pre-write manifest re-check [Group C1]

**Files:**
- Modify (full replacement): `cmd/sshepherd/apply.go`
- Modify: `cmd/sshepherd/apply_test.go`

What changes, precisely:

- `newApplyCmd` reads the manifest with `readManifest` + `config.Parse` (same `load manifest: …` errors), registers flags through `runFlags`, and calls `runApply` with plain apply's values: `prompt` = `apply N of M servers?`, `beforeWrite` = `m.Unchanged()` (a manifest replaced while the prompt waited — say by a concurrent `revoke` — stops the run with exit 3 and nothing written), `finish` = abort log on decline + summary + `(N server(s) skipped by --server)` + exit mapping.
- `runApply` = header (before anything connects) → `applyPreflight` → `planFleet` (phase 1, unchanged logic) → `apply.Render` with `Former`/`FormerNote` → `--dry-run` or (nothing to write and not `alwaysConfirm`) → `finish(stagePlanned)`; else `prompt` (may refuse) → `confirmGate` → declined → `finish(stageDeclined)`; zero writes → `beforeWrite(ctx, plans, nil)` → `finish(stageConfirmed)`; otherwise `writePhase`.
- `writePhase` re-lists held keys, then calls `beforeWrite(ctx, plans, fresh)` **before** `apply.Execute` starts any worker; an error returns with nothing written.
- `confirm`/`confirmGate` take the question text (`confirm` appends ` [y/N] `); `promptStreams` is the TTY seam tests override.
- Plain apply's report bytes are unchanged (its goldens differ only by Group A's pluralization).

- [ ] **Step 1: Update the existing tests and add the failing ones**

In `cmd/sshepherd/apply_test.go`, replace:

```go
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
```

with:

```go
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/authkeys"
```

In `cmd/sshepherd/apply_test.go`, replace:

```go
confirm(context.Background(), strings.NewReader(tt.in), &errBuf, tt.tty, tt.yes, 3, 12)
```

with:

```go
confirm(context.Background(), strings.NewReader(tt.in), &errBuf, tt.tty, tt.yes, "apply 3 of 12 servers?")
```

In `cmd/sshepherd/apply_test.go`, replace:

```go
confirm(ctx, pr, io.Discard, true, false, 1, 1)
```

with:

```go
confirm(ctx, pr, io.Discard, true, false, "apply 1 of 1 servers?")
```

In `cmd/sshepherd/apply_test.go`, replace:

```go
"(1 servers skipped by --server)"
```

with:

```go
"(1 server skipped by --server)"
```

Append to the end of `cmd/sshepherd/apply_test.go`:

```go

// usePromptStreams makes the confirmation prompt read in and write out as
// if both were a terminal.
func usePromptStreams(t *testing.T, in io.Reader, out io.Writer) {
	t.Helper()
	saved := promptStreams
	promptStreams = func(*cobra.Command) (io.Reader, io.Writer, bool) { return in, out, true }
	t.Cleanup(func() { promptStreams = saved })
}

// actionReader runs act once, on its first Read, then reads from r: a
// prompt answer that does something "while the prompt waits".
type actionReader struct {
	once sync.Once
	act  func()
	r    io.Reader
}

func (a *actionReader) Read(p []byte) (int, error) {
	a.once.Do(a.act)
	return a.r.Read(p)
}

// TestApplyRefusesChangedManifest: a manifest replaced while apply waited
// at its prompt (a concurrent revoke) is never planned-against-and-written:
// exit 3, the server untouched.
func TestApplyRefusesChangedManifest(t *testing.T) {
	home := shortHome(t)
	srv, hostKey, cfg := hermeticFleet(t, home)
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
	target := filepath.Join(home, ".ssh", "authorized_keys")
	before, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	var prompt bytes.Buffer
	usePromptStreams(t, &actionReader{
		act: func() {
			raw, err := os.ReadFile(cfg)
			if err != nil {
				t.Error(err)
			}
			if err := os.WriteFile(cfg, append(raw, "# edited by a concurrent run\n"...), 0o600); err != nil {
				t.Error(err)
			}
		},
		r: strings.NewReader("y\n"),
	}, &prompt)
	var out, errBuf bytes.Buffer
	code := run([]string{"apply", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
	if code != 3 {
		t.Fatalf("exit = %d, want 3\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "manifest "+cfg+" changed since it was read; re-run") {
		t.Errorf("stderr = %q, want the changed-manifest refusal", errBuf.String())
	}
	if !strings.Contains(prompt.String(), "apply 1 of 1 servers? [y/N]") {
		t.Errorf("prompt = %q", prompt.String())
	}
	if after, _ := os.ReadFile(target); !bytes.Equal(after, before) {
		t.Errorf("authorized_keys written despite the refusal:\n%s", after)
	}
}

// TestApplyDeclinedPrompt: "n" at the prompt writes nothing, logs the
// abort and exits 1 (pending changes) — plain apply's long-standing
// behavior, now through the shared run body; no edit header or manifest
// save line ever appears for plain apply.
func TestApplyDeclinedPrompt(t *testing.T) {
	home := shortHome(t)
	srv, hostKey, cfg := hermeticFleet(t, home)
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
	usePromptStreams(t, strings.NewReader("n\n"), io.Discard)
	var out, errBuf bytes.Buffer
	code := run([]string{"apply", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("exit = %d, want 1\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "aborted; no changes made") {
		t.Errorf("stderr = %q, want the abort line", errBuf.String())
	}
	if !strings.Contains(out.String(), "1 pending  → exit 1") {
		t.Errorf("stdout = %q, want the pending summary", out.String())
	}
	for _, never := range []string{"manifest edit:", "updated — commit and push"} {
		if strings.Contains(out.String(), never) {
			t.Errorf("plain apply printed %q:\n%s", never, out.String())
		}
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run:

```bash
go test ./cmd/sshepherd -run 'TestApply|TestConfirm'
```

Expected: FAIL, output includes:

```text
FAIL	github.com/javadh75/SSHepherd/cmd/sshepherd [build failed]
FAIL
cmd/sshepherd/apply_test.go:257:96: not enough arguments in call to confirm
	want (context.Context, io.Reader, io.Writer, bool, bool, int, int)
cmd/sshepherd/apply_test.go:285:56: not enough arguments in call to confirm
	want (context.Context, io.Reader, io.Writer, bool, bool, int, int)
```

- [ ] **Step 3: Replace `cmd/sshepherd/apply.go`**

Replace the whole of `cmd/sshepherd/apply.go` with:

```go
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshread"
	"github.com/javadh75/SSHepherd/internal/sshwrite"
)

func newApplyCmd(a *app, stdout io.Writer) *cobra.Command {
	var (
		rf        runFlags
		serverSel []string
	)
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Make each server's authorized_keys match the manifest (writes to the fleet)",
		Long: "Makes each targeted server's authorized_keys equal the manifest's rendered\n" +
			"desired state — a FULL-FILE rewrite (managed header, operator keys first,\n" +
			"decided comment policy). Non-key lines (hand-written comments, blank lines)\n" +
			"are DELETED by the rewrite; the plan shows a normalize row with the count\n" +
			"before anything is written. Flow: read the whole fleet, show one plan,\n" +
			"confirm once (interactive prompt, or --yes), then write only drifted\n" +
			"servers — atomically (length-checked temp file + rename, under a\n" +
			"per-file lock), with a .sshepherd.bak backup of the previous version, a\n" +
			"one-time .sshepherd.orig of the pre-SSHepherd file, and a read-back\n" +
			"verify. A server whose file changed after the plan was read is refused\n" +
			"(re-run apply), and so is the whole run when the manifest itself changed\n" +
			"since it was read. A self-lockout guard refuses any write that would leave\n" +
			"no key you hold (identity files + agent) on a server; after each write a\n" +
			"fresh login offering only the surviving keys must succeed, or the\n" +
			"previous file is restored. --yes skips only the confirmation: an\n" +
			"encrypted --identity key may still prompt for its passphrase.\n" +
			"Ctrl-C stops new writes; started ones finish. --dry-run previews the\n" +
			"plan and never writes.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ids, err := validateFlags(rf.parallel, &rf.idf)
			if err != nil {
				return err
			}
			log := a.logger
			m, err := readManifest(rf.cfgPath)
			if err != nil {
				return fmt.Errorf("load manifest: %w", err)
			}
			cfg, err := config.Parse(m.Loaded)
			if err != nil {
				return fmt.Errorf("load manifest: %w", err) // wrapcheck: wrap at package boundary
			}
			log.Info(fmt.Sprintf("loaded manifest: %d users, %d servers", len(cfg.Users), len(cfg.Servers)))
			for _, w := range cfg.Warnings {
				log.Warn(w)
			}
			targets, err := selectServers(cfg, serverSel)
			if err != nil {
				return err
			}
			skipped := len(cfg.Servers) - len(targets)
			ropts := apply.RenderOptions{Color: a.reportColor}
			if len(targets) == 0 {
				apply.Render(stdout, cfg, nil, ropts)
				return nil
			}
			return runApply(cmd, a, stdout, &rf, ids, applyRun{
				cfg:     cfg,
				servers: targets,
				// Offer each server's granted keys first (operators first),
				// so many held keys cannot exhaust sshd's MaxAuthTries
				// before the key that matters is tried.
				preferKeys: func(s config.Server) []string { return audit.GrantedFingerprints(cfg, s.Name) },
				prompt: func(_ []apply.ServerPlan, toWrite int) (string, error) {
					return fmt.Sprintf("apply %d of %d servers?", toWrite, len(targets)), nil
				},
				// A concurrent revoke may have replaced the manifest while
				// this run planned against the old one: writing that plan
				// would reinstall the revoked key.
				beforeWrite: func(context.Context, []apply.ServerPlan, []sshconn.HeldKey) error {
					return m.Unchanged()
				},
				finish: func(plans []apply.ServerPlan, stage applyStage) error {
					if stage == stageDeclined {
						log.Error("aborted; no changes made")
					}
					apply.RenderSummary(stdout, plans, ropts)
					if skipped > 0 {
						fmt.Fprintf(stdout, "(%s skipped by --server)\n", apply.Plural(skipped, "server", "servers"))
					}
					if apply.ExitCode(plans) != 0 {
						return errNonCompliant
					}
					return nil
				},
			})
		},
	}
	rf.register(cmd)
	cmd.Flags().StringArrayVar(&serverSel, "server", nil, "restrict the run to this server (repeatable; canary rollout)")
	return cmd
}

// applyStage tells an applyRun's finish how far the run got.
type applyStage int

const (
	stagePlanned   applyStage = iota // plan shown, nothing confirmed: --dry-run, or nothing to confirm
	stageDeclined                    // the confirmation prompt was declined
	stageConfirmed                   // confirmed: beforeWrite passed and the writes (if any) ran
)

// applyRun parameterizes runApply: plain apply passes the loaded config
// and its whole selection; revoke/rotate pass the edited config, the
// affected servers and the edit's hooks.
type applyRun struct {
	cfg        *config.Config               // the config the plan renders (the edited one for revoke/rotate)
	former     *config.Config               // the as-loaded config before an edit; nil for plain apply
	formerNote string                       // label note for keys only former owns: "" (revoked) or "rotated out"
	servers    []config.Server              // the servers to plan, manifest order; never empty
	preferKeys func(config.Server) []string // fingerprints offered first on every dial (read and write)
	header     func(io.Writer)              // printed to stdout before anything connects; nil prints nothing
	// alwaysConfirm asks even when no server needs a write (the manifest
	// edit is itself a change).
	alwaysConfirm bool
	// prompt returns the confirmation question (confirm appends " [y/N] "),
	// or an error that ends the run before any prompt.
	prompt func(plans []apply.ServerPlan, toWrite int) (string, error)
	// beforeWrite runs once after confirmation and before any write: inside
	// writePhase after the post-prompt held-key re-list when a server will
	// be written (fresh is that listing), else straight after the prompt
	// (fresh nil). An error ends the run with nothing written.
	beforeWrite func(ctx context.Context, plans []apply.ServerPlan, fresh []sshconn.HeldKey) error
	// finish renders the tail of the report and maps the run to its exit.
	finish func(plans []apply.ServerPlan, stage applyStage) error
}

// runApply is apply's run body over run.servers: preflight (known_hosts,
// key files, credentials, held keys), phase-1 read and plan, the report,
// the confirmation gate, beforeWrite, the writes, finish.
func runApply(cmd *cobra.Command, a *app, stdout io.Writer, rf *runFlags, ids identities, run applyRun) error {
	ctx, log := cmd.Context(), a.logger
	if run.header != nil {
		run.header(stdout)
	}
	pre, err := applyPreflight(ctx, log, rf.knownHosts, ids)
	if err != nil {
		return err
	}
	plans, err := planFleet(ctx, log, pre, run, rf.parallel)
	if err != nil {
		return err
	}
	apply.Render(stdout, run.cfg, plans, apply.RenderOptions{Color: a.reportColor, Former: run.former, FormerNote: run.formerNote})

	toWrite := countChanges(plans)
	if rf.dryRun || (toWrite == 0 && !run.alwaysConfirm) {
		return run.finish(plans, stagePlanned) // a preview, or nothing to confirm
	}
	question, err := run.prompt(plans, toWrite)
	if err != nil {
		return err
	}
	ok, err := confirmGate(cmd, rf.yes, question)
	if err != nil {
		return err
	}
	if !ok {
		return run.finish(plans, stageDeclined)
	}
	if toWrite == 0 {
		if err := run.beforeWrite(ctx, plans, nil); err != nil {
			return err
		}
		return run.finish(plans, stageConfirmed)
	}
	log.Info(fmt.Sprintf("applying %d servers (parallelism %d)…", toWrite, rf.parallel))
	if err := writePhase(ctx, log, pre, run.preferKeys, plans, rf.parallel, run.beforeWrite); err != nil {
		return err
	}
	return run.finish(plans, stageConfirmed)
}

// planFleet is phase 1: audit's pipeline over run.servers, then the plan
// from run.cfg.
func planFleet(ctx context.Context, log *slog.Logger, pre preflight, run applyRun, parallel int) ([]apply.ServerPlan, error) {
	reader := &sshread.Client{
		KnownHostsPath: pre.khPath,
		KnownHosts:     pre.kh,
		Creds:          pre.creds,
		DialTimeout:    dialTimeout,
		PreferKeys:     run.preferKeys,
		Log:            log,
	}
	log.Info(fmt.Sprintf("planning %d servers (parallelism %d)…", len(run.servers), parallel))
	start := time.Now()
	results := audit.Run(ctx, run.cfg, reader, audit.Options{
		Parallel:         parallel,
		PerServerTimeout: perServerTimeout,
		Servers:          run.servers,
		Logger:           log,
	})
	logFleetReadDone(log, run.cfg, results, start)
	if err := interrupted(ctx); err != nil {
		return nil, err // nothing written: phase 2 never started
	}
	plans, err := apply.Build(run.cfg, results, pre.held)
	if err != nil {
		return nil, fmt.Errorf("plan: %w", err) // wrapcheck: wrap at package boundary
	}
	return plans, nil
}

// writePhase runs phase 2 over the drifted servers. The prompt can wait
// indefinitely: agent keys may expire (ssh-add -t) or be removed, or the
// agent vanish, meanwhile — so the held keys are re-listed first and the
// per-server guard re-check and the post-write login probe use what is
// held now. A degraded listing (agent gone, key files left) is used as is,
// never replaced; only a failed listing (no key files, agent gone) leaves
// it empty, which fails every write through the guard rather than
// guessing. beforeWrite (the manifest re-check or save) runs after the
// re-list and before any worker starts; its error writes nothing.
func writePhase(ctx context.Context, log *slog.Logger, pre preflight, preferKeys func(config.Server) []string,
	plans []apply.ServerPlan, parallel int,
	beforeWrite func(context.Context, []apply.ServerPlan, []sshconn.HeldKey) error,
) error {
	fresh, err := pre.creds.Held(ctx)
	if err != nil {
		log.Error(fmt.Sprintf("%s: %v — no server will be written", relistPrefix(pre.creds), err))
		fresh = nil
	}
	if beforeWrite != nil {
		if err := beforeWrite(ctx, plans, fresh); err != nil {
			return err
		}
	}
	writer := &sshwrite.FleetWriter{
		Dialer: &sshconn.Dialer{
			KnownHostsPath: pre.khPath,
			KnownHosts:     pre.kh,
			Creds:          pre.creds,
			DialTimeout:    dialTimeout,
			PreferKeys:     preferKeys,
			Log:            log,
		},
		Log: log,
	}
	apply.Execute(ctx, plans, writer, apply.ExecOptions{
		Parallel:         parallel,
		PerServerTimeout: perServerTimeout,
		Held:             fresh,
		Logger:           log,
	})
	if n := apply.Interrupted(plans); n > 0 {
		log.Error(fmt.Sprintf("interrupted: %d servers not started (nothing written there); started writes finished", n))
	}
	return nil
}

// preflight is what apply's pre-dial checks hand to both phases.
type preflight struct {
	khPath string
	kh     *sshconn.KnownHosts  // parsed once, shared by the reader and the writer
	creds  *sshconn.Credentials // the run's one credential source: reader, writer, probe
	held   []sshconn.HeldKey    // the plan-time guard's ground truth
}

// applyPreflight runs apply's pre-dial checks in the order of operations:
// known_hosts (parsed exactly once per run; both phases share the
// snapshot), then the key files (may prompt), then the credentials check —
// apply needs plain held keys — and the held-key capture that is the
// self-lockout guard's ground truth.
func applyPreflight(ctx context.Context, log *slog.Logger, knownHosts string, ids identities) (preflight, error) {
	var pre preflight
	var err error
	if pre.khPath, err = expandHome(knownHosts); err != nil {
		return pre, err
	}
	if pre.kh, err = sshread.LoadKnownHosts(pre.khPath); err != nil {
		return pre, fmt.Errorf("known_hosts preflight: %w", err)
	}
	if pre.creds, err = ids.credentials(ctx, log); err != nil {
		return pre, err
	}
	if err := checkCredentials(ctx, pre.creds, true); err != nil {
		return pre, err
	}
	if pre.held, err = pre.creds.Held(ctx); err != nil {
		return pre, fmt.Errorf("agent preflight: %w", err)
	}
	return pre, nil
}

// relistPrefix words a failed post-confirmation re-list: the
// pre---identity wording for an agent-only run, a key-neutral one when
// --identity keys are in the union.
func relistPrefix(creds *sshconn.Credentials) string {
	if len(creds.Files) == 0 {
		return "re-listing agent keys after confirmation"
	}
	return "re-listing the keys you hold after confirmation"
}

// countChanges tallies the servers phase 2 would write.
func countChanges(plans []apply.ServerPlan) int {
	n := 0
	for _, p := range plans {
		if p.Class == apply.ClassChange {
			n++
		}
	}
	return n
}

// selectServers resolves --server names to manifest servers, preserving
// manifest order and deduplicating; no names selects the whole fleet. An
// unknown name is a usage error — a canary typo must not silently apply
// nothing.
func selectServers(cfg *config.Config, names []string) ([]config.Server, error) {
	if len(names) == 0 {
		return cfg.Servers, nil
	}
	known := make(map[string]bool, len(cfg.Servers))
	for _, s := range cfg.Servers {
		known[s.Name] = true
	}
	wanted := make(map[string]bool, len(names))
	for _, n := range names {
		if !known[n] {
			return nil, fmt.Errorf("--server: unknown server %q", n)
		}
		wanted[n] = true
	}
	var targets []config.Server
	for _, s := range cfg.Servers {
		if wanted[s.Name] {
			targets = append(targets, s)
		}
	}
	return targets, nil
}

// promptStreams returns the confirmation prompt's input, output and TTY
// verdict: stdin, stderr, and whether both are terminals. A test seam —
// run() never wires a terminal.
var promptStreams = func(cmd *cobra.Command) (io.Reader, io.Writer, bool) {
	in, errW := cmd.InOrStdin(), cmd.ErrOrStderr()
	return in, errW, stdioIsTTY(in, errW)
}

// confirmGate runs confirm on the command's streams: the prompt goes to
// stderr and the answer comes from stdin, so `apply > plan.txt` captures
// exactly the report. Ctrl-C at the prompt is an interrupted run (exit 3,
// nothing written).
func confirmGate(cmd *cobra.Command, yes bool, question string) (bool, error) {
	in, errW, tty := promptStreams(cmd)
	ok, err := confirm(cmd.Context(), in, errW, tty, yes, question)
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(errW)
		return false, interrupted(cmd.Context())
	}
	return ok, err
}

// confirm gates phase 2. --yes short-circuits; otherwise a TTY prompts once
// on stderr, defaulting to no; non-TTY without --yes is a usage error —
// automation must opt in explicitly, never by accident of a pipe. Ctrl-C at
// the prompt cancels ctx and returns ctx's error at once: the stdin read
// runs in a goroutine, so the signal is not swallowed while it blocks (the
// abandoned read ends when the process exits).
func confirm(ctx context.Context, in io.Reader, errW io.Writer, tty, yes bool, question string) (bool, error) {
	if yes {
		return true, nil
	}
	if !tty {
		return false, errors.New("confirmation required: re-run with --yes (or --dry-run to preview) — stdin/stderr is not a terminal")
	}
	fmt.Fprintf(errW, "%s [y/N] ", question)
	answer := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(in)
		if !sc.Scan() {
			close(answer) // EOF (Ctrl-D) declines
			return
		}
		answer <- sc.Text()
	}()
	var text string
	select {
	case <-ctx.Done():
		return false, fmt.Errorf("confirmation: %w", ctx.Err())
	case text = <-answer:
	}
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// stdioIsTTY reports whether both in and errW are terminals — the prompt
// contract needs both: stdin to read the answer, stderr to show the
// question even when stdout is redirected.
func stdioIsTTY(in io.Reader, errW io.Writer) bool {
	fi, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(fi.Fd())) {
		return false
	}
	fe, ok := errW.(*os.File)
	return ok && term.IsTerminal(int(fe.Fd()))
}
```

- [ ] **Step 4: Run the whole package**

Run:

```bash
go test ./cmd/sshepherd
```

Expected: PASS, output includes:

```text
ok  	github.com/javadh75/SSHepherd/cmd/sshepherd	(…s)
```

Run:

```bash
go test ./cmd/sshepherd -run 'TestApplyRefusesChangedManifest|TestApplyDeclinedPrompt|TestApplyHermetic' -v 2>&1 | grep -E '^--- '
```

Expected: PASS, output includes:

```text
--- PASS: TestApplyHermetic (…s)
--- PASS: TestApplyRefusesChangedManifest (…s)
--- PASS: TestApplyDeclinedPrompt (…s)
```

- [ ] **Commit**

```bash
git add cmd/sshepherd/apply.go cmd/sshepherd/apply_test.go
git commit -m "$(cat <<'EOF'
refactor(apply): runApply(applyRun) run body; re-check the manifest before writing

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

### Task C1.3: KEY classification and expiry helpers (`keyarg.go`) [Group C1]

**Files:**
- Create: `cmd/sshepherd/keyarg.go`
- Create: `cmd/sshepherd/keyarg_test.go`

Classification order (spec § KEY arguments): `SHA256:` prefix → fingerprint (43 unpadded base64 chars, one trailing `=` stripped); contains ` SHA256:` → that token; `MD5:` or hex-colon → refused; whitespace, a known key type at the start (`ssh-ed25519`, `ssh-ed448`, `ssh-rsa`, `ssh-dss`, `ecdsa-sha2-*`, `sk-ssh-ed25519*`, `sk-ecdsa-sha2-*` — whole type names, so `ssh-keys/alice.pub` stays a path and a user named `ssh-admin` is not "a key") or an authorized_keys option name → key line (parse errors shown, `; quote the whole line`); otherwise → path (`~/` from `$HOME`, 64 KiB cap, exactly one key line). `--new` refuses fingerprints and options. Path errors name the argument and **never** include file bytes — not even a parse error, since `authkeys` errors can quote a declared type token from the file. `expiryPassed` reads sshd's `YYYYMMDD[HHMM[SS]]` (local time; `Z` suffix = UTC).

- [ ] **Step 1: Write the failing tests**

Create `cmd/sshepherd/keyarg_test.go`:

```go
package main

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// fpOf is a test key's fingerprint.
func fpOf(t *testing.T, seed byte) string {
	t.Helper()
	k, err := authkeys.ParseLine(testkeys.Line(t, seed))
	if err != nil || k == nil {
		t.Fatalf("fpOf(%d): %v", seed, err)
	}
	return k.Fingerprint
}

// certLine is an authorized_keys-format user certificate for key seed.
func certLine(t *testing.T, seed byte) string {
	t.Helper()
	cert := sshtest.UserCert(t, sshtest.Key(seed), sshtest.Key(50), "deploy")
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
}

func TestClassifyKeyArg(t *testing.T) {
	fp1 := fpOf(t, 1)
	files := map[string]string{
		"/home/u/.ssh/id.pub": testkeys.Line(t, 1) + " me@laptop\n",
		"ssh-keys/alice.pub":  testkeys.Line(t, 1) + "\n",
		"/k/two.pub":          testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n",
		"/k/none.pub":         "# only a comment\n\n",
		"/k/cert.pub":         certLine(t, 1) + "\n",
		"/k/opts.pub":         `from="10.0.0.1" ` + testkeys.Line(t, 1) + "\n",
		"/k/garbage.pub":      "ssh-ed25519 !!!notbase64\n",
		"/k/putty":            "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n",
		"/k/big.pub":          strings.Repeat("#", maxKeyFile+1),
	}
	read := func(p string) ([]byte, error) {
		if c, ok := files[p]; ok {
			return []byte(c), nil
		}
		return nil, errors.New("open " + p + ": no such file or directory")
	}
	tests := []struct {
		name    string
		role    keyRole
		arg     string
		wantFP  string
		wantKey bool
		wantErr string
	}{
		{"fingerprint", roleKey, fp1, fp1, false, ""},
		{"padded fingerprint", roleOld, fp1 + "=", fp1, false, ""},
		{"malformed fingerprint", roleKey, "SHA256:abc", "", false, "--key SHA256:abc: malformed fingerprint"},
		{"pasted ssh-keygen -lf output", roleKey, "256 " + fp1 + " me@laptop (ED25519)", fp1, false, ""},
		{"pasted output, malformed", roleKey, "256 SHA256:short me (ED25519)", "", false, "malformed fingerprint"},
		{"MD5 prefix", roleKey, "MD5:aa:bb:cc", "", false, "MD5 fingerprints are not supported — use ssh-keygen -l -E sha256 -f FILE"},
		{"hex colon", roleOld, "aa:bb:cc:dd:ee:ff", "", false, "MD5 fingerprints are not supported"},
		{"key line", roleKey, testkeys.Line(t, 1) + " me@laptop", fp1, true, ""},
		{"key line with options", roleKey, "restrict " + testkeys.Line(t, 1), fp1, true, ""},
		{"broken key line", roleKey, "ssh-ed25519 !!!notbase64", "", false, "not a valid public key line"},
		{"broken key line says quote", roleKey, "ssh-ed25519", "", false, "quote the whole line"},
		{"~/ path", roleKey, "~/.ssh/id.pub", fp1, true, ""},
		{"path starting with ssh-", roleKey, "ssh-keys/alice.pub", fp1, true, ""},
		{"missing path lists the forms", roleKey, "/k/nope.pub", "", false, "pass a SHA256: fingerprint, a public-key line, or a .pub file path"},
		{"missing path for --new", roleNew, "/k/nope.pub", "", false, "pass a public-key line or a .pub file path"},
		{"multi-key .pub", roleKey, "/k/two.pub", "", false, "--key /k/two.pub: holds 2 key lines — want exactly one"},
		{"empty .pub", roleKey, "/k/none.pub", "", false, "holds 0 key lines"},
		{"certificate file", roleOld, "/k/cert.pub", "", false, "--old /k/cert.pub is an SSH certificate, not a public key — pass the plain key (id_ed25519.pub, not id_ed25519-cert.pub)"},
		{"certificate line", roleKey, certLine(t, 1), "", false, "is an SSH certificate, not a public key"},
		{"unparseable file", roleKey, "/k/garbage.pub", "", false, "--key /k/garbage.pub: does not hold a valid public key line"},
		{"PuTTY private key", roleKey, "/k/putty", "", false, "--key /k/putty is a private key — pass the public key (/k/putty.pub)"},
		{"oversized file", roleKey, "/k/big.pub", "", false, "larger than 64 KiB"},
		{"--new fingerprint", roleNew, fp1, "", false, "--new " + fp1 + ": a fingerprint carries no key"},
		{"--new key line with options", roleNew, "restrict " + testkeys.Line(t, 1), "", false, "rotate keeps the old line's options; edit them in the manifest"},
		{"--new file with options", roleNew, "/k/opts.pub", "", false, "rotate keeps the old line's options; edit them in the manifest"},
		{"--new plain file", roleNew, "/home/u/.ssh/id.pub", fp1, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := classifyKeyArg(tt.role, tt.arg, "/home/u", read)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("classifyKeyArg: %v", err)
			}
			if got.Fingerprint != tt.wantFP || (got.Key != nil) != tt.wantKey || got.Arg != tt.arg {
				t.Errorf("got %+v, want fp %s, key %v", got, tt.wantFP, tt.wantKey)
			}
		})
	}
}

// TestClassifyPrivateKeyNeverQuotesContents: neither the BEGIN line nor any
// byte after it reaches the error — for a synthetic file and for a real
// OpenSSH private key on disk.
func TestClassifyPrivateKeyNeverQuotesContents(t *testing.T) {
	material := "c2VjcmV0LWtleS1tYXRlcmlhbA"
	content := "-----BEGIN OPENSSH " + "PRIVATE KEY-----\n" + material + "\n"
	read := func(string) ([]byte, error) { return []byte(content), nil }
	_, err := classifyKeyArg(roleKey, "/k/id_ed25519", "", read)
	if err == nil || !strings.Contains(err.Error(), "/k/id_ed25519 is a private key — pass the public key (/k/id_ed25519.pub)") {
		t.Fatalf("err = %v, want the private-key refusal", err)
	}
	if strings.Contains(err.Error(), material) || strings.Contains(err.Error(), "BEGIN") {
		t.Errorf("error quotes the file: %v", err)
	}

	path := sshtest.WriteKeyFile(t, t.TempDir(), "id_ed25519", sshtest.Key(7), nil)
	body, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	_, err = parseKeyArg(roleOld, path)
	if err == nil || !strings.Contains(err.Error(), "is a private key") {
		t.Fatalf("err = %v, want the private-key refusal", err)
	}
	for _, line := range strings.Split(string(body), "\n")[1:] {
		if len(line) >= 8 && strings.Contains(err.Error(), line) {
			t.Errorf("error quotes key material %q", line)
		}
	}
	// The .pub next to it is accepted.
	if got, err := parseKeyArg(roleNew, path+".pub"); err != nil || got.Fingerprint != sshtest.Fingerprint(t, sshtest.Key(7)) {
		t.Errorf("parseKeyArg(.pub) = (%+v, %v)", got, err)
	}
}

func TestLooksLikeKey(t *testing.T) {
	for arg, want := range map[string]bool{
		"alice":                  false,
		"deploy-bot":             false,
		"ssh-admin":              false,
		"ssh-keys/alice.pub":     false,
		"ops.team":               false,
		fpOf(t, 1):               true,
		"256 " + fpOf(t, 1):      true,
		"MD5:aa:bb":              true,
		"aa:bb:cc":               true,
		"ssh-ed25519":            true,
		"restrict":               true,
		"from=10.0.0.1":          true,
		"no-pty,restrict":        true,
		testkeys.Line(t, 1):      true,
		"alice bob":              true,
		"ecdsa-sha2-nistp256":    true,
		"sk-ssh-ed25519@openssh": true,
	} {
		if got := looksLikeKey(arg); got != want {
			t.Errorf("looksLikeKey(%q) = %v, want %v", arg, got, want)
		}
	}
}

func TestExpiry(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	if got := expiryOption([]string{"no-pty", `Expiry-Time="20270101"`}); got != `Expiry-Time="20270101"` {
		t.Errorf("expiryOption = %q, want the option verbatim", got)
	}
	if got := expiryOption([]string{"no-pty"}); got != "" {
		t.Errorf("expiryOption = %q, want none", got)
	}
	tests := []struct {
		opt     string
		passed  bool
		wantErr bool
	}{
		{`expiry-time="20200101"`, true, false},
		{`expiry-time="20991231"`, false, false},
		{`expiry-time="202610231159Z"`, true, false},
		{`expiry-time="20261023120100Z"`, false, false},
		{`expiry-time="2026"`, false, true},
		{`expiry-time="2026xx01"`, false, true},
	}
	for _, tt := range tests {
		passed, err := expiryPassed(tt.opt, now)
		if passed != tt.passed || (err != nil) != tt.wantErr {
			t.Errorf("expiryPassed(%s) = (%v, %v), want (%v, err=%v)", tt.opt, passed, err, tt.passed, tt.wantErr)
		}
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run:

```bash
go test ./cmd/sshepherd -run 'TestClassify|TestLooksLikeKey|TestExpiry'
```

Expected: FAIL, output includes:

```text
FAIL	github.com/javadh75/SSHepherd/cmd/sshepherd [build failed]
FAIL
cmd/sshepherd/keyarg_test.go:45:46: undefined: maxKeyFile
cmd/sshepherd/keyarg_test.go:55:11: undefined: keyRole
cmd/sshepherd/keyarg_test.go:61:19: undefined: roleKey
cmd/sshepherd/keyarg_test.go:62:26: undefined: roleOld
```

- [ ] **Step 3: Implement**

Create `cmd/sshepherd/keyarg.go`:

```go
package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
)

// keyRole is which flag a KEY argument came from: it decides the accepted
// forms (--new carries a key, so no fingerprint) and whether options are
// allowed (never on --new: rotate keeps the old line's options).
type keyRole string

const (
	roleKey keyRole = "--key"
	roleOld keyRole = "--old"
	roleNew keyRole = "--new"
)

// keyArg is one classified KEY argument.
type keyArg struct {
	Arg         string        // the argument as given, for messages
	Fingerprint string        // SHA256:…, always set
	Key         *authkeys.Key // the parsed line; nil for a fingerprint argument
}

// maxKeyFile caps a .pub read: a public key file is a line or two.
const maxKeyFile = 64 << 10

var (
	hexColonFP = regexp.MustCompile(`^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+$`)
	// keyTypePrefixes are the key types (and type families) that mark a
	// bare argument as a (possibly broken) key line rather than a path:
	// whole type names, so a path like ssh-keys/alice.pub or a user named
	// ssh-admin is not mistaken for a key.
	keyTypePrefixes = []string{"ssh-ed25519", "ssh-ed448", "ssh-rsa", "ssh-dss", "ecdsa-sha2-", "sk-ssh-ed25519", "sk-ecdsa-sha2-"}
	// keyOptionNames mirrors config's authorized_keys option allow-list:
	// an argument starting with one ("restrict,…", "from=…") is a key line.
	keyOptionNames = []string{
		"agent-forwarding", "cert-authority", "command", "environment", "expiry-time", "from",
		"no-agent-forwarding", "no-port-forwarding", "no-pty", "no-touch-required", "no-user-rc",
		"no-x11-forwarding", "permitlisten", "permitopen", "port-forwarding", "principals", "pty",
		"restrict", "tunnel", "user-rc", "verify-required", "x11-forwarding",
	}
)

// parseKeyArg classifies a KEY argument from the real filesystem: ~/
// expands from $HOME (as --identity does) and a path is read with a 64 KiB
// cap.
func parseKeyArg(role keyRole, arg string) (keyArg, error) {
	home, _ := os.UserHomeDir() // "" makes a ~/ path fail with a clear error
	return classifyKeyArg(role, arg, home, readKeyFile)
}

// readKeyFile reads at most maxKeyFile+1 bytes of path, so an oversized
// file is detected without reading it whole.
func readKeyFile(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator's own KEY argument
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return data, nil
}

// classifyKeyArg implements the spec's KEY classification, in order:
// SHA256 fingerprint; pasted `ssh-keygen -lf` output; MD5 (refused); key
// line; path. read is the file seam. Errors name the argument and never
// quote file contents.
func classifyKeyArg(role keyRole, arg, home string, read func(string) ([]byte, error)) (keyArg, error) {
	a := keyArg{Arg: arg}
	switch {
	case strings.HasPrefix(arg, "SHA256:"):
		return fingerprintArg(role, arg, arg)
	case strings.Contains(arg, " SHA256:"):
		for _, f := range strings.Fields(arg) {
			if strings.HasPrefix(f, "SHA256:") {
				return fingerprintArg(role, arg, f)
			}
		}
	case strings.HasPrefix(arg, "MD5:") || hexColonFP.MatchString(arg):
		return a, fmt.Errorf("%s %s: MD5 fingerprints are not supported — use ssh-keygen -l -E sha256 -f FILE", role, arg)
	case looksLikeKeyLine(arg):
		k, err := parseKeyLine(role, arg)
		if err != nil {
			return a, fmt.Errorf("%s: %w", role, err)
		}
		a.Key, a.Fingerprint = k, k.Fingerprint
		return a, nil
	}
	return pathArg(role, arg, home, read)
}

// looksLikeKey reports whether arg classifies as a fingerprint or a key
// line (steps 1–4): a revoke USER argument that does is a usage error.
func looksLikeKey(arg string) bool {
	return strings.HasPrefix(arg, "SHA256:") || strings.Contains(arg, " SHA256:") ||
		strings.HasPrefix(arg, "MD5:") || hexColonFP.MatchString(arg) || looksLikeKeyLine(arg)
}

// looksLikeKeyLine: whitespace, a key-type prefix, or an option prefix.
func looksLikeKeyLine(arg string) bool {
	if strings.ContainsAny(arg, " \t") {
		return true
	}
	for _, p := range keyTypePrefixes {
		if strings.HasPrefix(arg, p) {
			return true
		}
	}
	name := strings.ToLower(arg)
	if i := strings.IndexAny(name, "=,"); i >= 0 {
		name = name[:i]
	}
	for _, o := range keyOptionNames {
		if name == o {
			return true
		}
	}
	return false
}

// fingerprintArg validates a SHA256 fingerprint token: 43 characters of
// unpadded base64 (one trailing "=" is stripped).
func fingerprintArg(role keyRole, arg, token string) (keyArg, error) {
	a := keyArg{Arg: arg}
	if role == roleNew {
		return a, fmt.Errorf("--new %s: a fingerprint carries no key — pass the new public key line or its .pub file", arg)
	}
	b64 := strings.TrimSuffix(strings.TrimPrefix(token, "SHA256:"), "=")
	if raw, err := base64.RawStdEncoding.DecodeString(b64); err != nil || len(b64) != 43 || len(raw) != 32 {
		return a, fmt.Errorf("%s %s: malformed fingerprint (want SHA256: followed by 43 base64 characters)", role, arg)
	}
	a.Fingerprint = "SHA256:" + b64
	return a, nil
}

// parseKeyLine parses a key-line argument (typed by the operator, so the
// parse error may be shown).
func parseKeyLine(role keyRole, line string) (*authkeys.Key, error) {
	if isCertLine(line) {
		return nil, certError(line)
	}
	k, err := authkeys.ParseLine(line)
	if err != nil {
		return nil, fmt.Errorf("not a valid public key line: %w; quote the whole line", err)
	}
	if k == nil {
		return nil, errors.New("not a valid public key line: blank or a comment; quote the whole line")
	}
	if isCertType(k.Type) {
		return nil, certError(line)
	}
	if role == roleNew && len(k.Options) > 0 {
		return nil, errors.New("rotate keeps the old line's options; edit them in the manifest")
	}
	return k, nil
}

// pathArg reads a .pub file: exactly one key line (blank and # lines
// ignored). Messages never quote the file's contents.
func pathArg(role keyRole, arg, home string, read func(string) ([]byte, error)) (keyArg, error) {
	a := keyArg{Arg: arg}
	path := arg
	if strings.HasPrefix(path, "~/") {
		if home == "" {
			return a, fmt.Errorf("%s %s: cannot expand ~/ (no home directory)", role, arg)
		}
		path = filepath.Join(home, path[2:])
	}
	data, err := read(path)
	if err != nil {
		forms := "a SHA256: fingerprint, a public-key line, or a .pub file path"
		if role == roleNew {
			forms = "a public-key line or a .pub file path"
		}
		return a, fmt.Errorf("%s %s: %w — pass %s", role, arg, err, forms)
	}
	return keyFileArg(role, arg, data)
}

// keyFileArg checks a .pub file's contents: at most 64 KiB, not a private
// key, exactly one plain public-key line, no options for --new. Messages
// name the argument and never quote the contents.
func keyFileArg(role keyRole, arg string, data []byte) (keyArg, error) {
	a := keyArg{Arg: arg}
	if len(data) > maxKeyFile {
		return a, fmt.Errorf("%s %s: larger than 64 KiB — not a public key file", role, arg)
	}
	if isPrivateKey(data) {
		return a, fmt.Errorf("%s %s is a private key — pass the public key (%s.pub)", role, arg, arg)
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
			lines = append(lines, t)
		}
	}
	if len(lines) != 1 {
		return a, fmt.Errorf("%s %s: holds %d key lines — want exactly one", role, arg, len(lines))
	}
	if isCertLine(lines[0]) {
		return a, fmt.Errorf("%s %s is an SSH certificate, not a public key — pass the plain key (id_ed25519.pub, not id_ed25519-cert.pub)", role, arg)
	}
	k, err := authkeys.ParseLine(lines[0])
	if err != nil || k == nil {
		return a, fmt.Errorf("%s %s: does not hold a valid public key line", role, arg)
	}
	if isCertType(k.Type) {
		return a, fmt.Errorf("%s %s is an SSH certificate, not a public key — pass the plain key (id_ed25519.pub, not id_ed25519-cert.pub)", role, arg)
	}
	if role == roleNew && len(k.Options) > 0 {
		return a, fmt.Errorf("%s %s: rotate keeps the old line's options; edit them in the manifest", role, arg)
	}
	a.Key, a.Fingerprint = k, k.Fingerprint
	return a, nil
}

// isPrivateKey: the first non-blank line opens a PEM/OpenSSH or PuTTY
// private key, or the file mentions PRIVATE KEY anywhere.
func isPrivateKey(data []byte) bool {
	if bytes.Contains(data, []byte("PRIVATE KEY")) {
		return true
	}
	for _, l := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		return strings.HasPrefix(t, "-----BEGIN") || strings.HasPrefix(t, "PuTTY-User-Key-File")
	}
	return false
}

// isCertLine reports whether any of a line's first two fields is a
// certificate key type (the second covers a line with options).
func isCertLine(line string) bool {
	f := strings.Fields(line)
	for i := 0; i < len(f) && i < 2; i++ {
		if isCertType(f[i]) {
			return true
		}
	}
	return false
}

func isCertType(t string) bool { return strings.HasSuffix(t, "-cert-v01@openssh.com") }

func certError(arg string) error {
	return fmt.Errorf("%s is an SSH certificate, not a public key — pass the plain key (id_ed25519.pub, not id_ed25519-cert.pub)", arg)
}

// expiryOption returns the expiry-time= option of a key line's options,
// verbatim ("" when none).
func expiryOption(options []string) string {
	for _, o := range options {
		if strings.HasPrefix(strings.ToLower(o), "expiry-time=") {
			return o
		}
	}
	return ""
}

// expiryPassed reports whether an expiry-time="…" option (sshd's
// YYYYMMDD[HHMM[SS]] format, local time unless suffixed Z for UTC) is at
// or before now.
func expiryPassed(option string, now time.Time) (bool, error) {
	_, v, _ := strings.Cut(option, "=")
	v = strings.Trim(v, `"`)
	loc := time.Local
	if strings.HasSuffix(v, "Z") || strings.HasSuffix(v, "z") {
		v, loc = v[:len(v)-1], time.UTC
	}
	layouts := map[int]string{8: "20060102", 12: "200601021504", 14: "20060102150405"}
	layout, ok := layouts[len(v)]
	if !ok {
		return false, fmt.Errorf("cannot read %s (want YYYYMMDD[HHMM[SS]][Z])", option)
	}
	t, err := time.ParseInLocation(layout, v, loc)
	if err != nil {
		return false, fmt.Errorf("cannot read %s (want YYYYMMDD[HHMM[SS]][Z])", option)
	}
	return !t.After(now), nil
}
```

- [ ] **Step 4: Run them**

Run:

```bash
go test ./cmd/sshepherd -run 'TestClassify|TestLooksLikeKey|TestExpiry' -v 2>&1 | grep -E '^--- '
```

Expected: PASS, output includes:

```text
--- PASS: TestClassifyKeyArg (…s)
--- PASS: TestClassifyPrivateKeyNeverQuotesContents (…s)
--- PASS: TestLooksLikeKey (…s)
--- PASS: TestExpiry (…s)
```

- [ ] **Commit**

```bash
git add cmd/sshepherd/keyarg.go cmd/sshepherd/keyarg_test.go
git commit -m "$(cat <<'EOF'
feat(cmd): KEY argument classification and expiry-time helpers

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

### Task C1.4: Locked, compare-and-swap, atomic manifest save [Group C1]

**Files:**
- Modify (full replacement): `cmd/sshepherd/edit.go`
- Create: `cmd/sshepherd/edit_lock_unix.go`
- Create: `cmd/sshepherd/edit_lock_other.go`
- Create: `cmd/sshepherd/edit_save_test.go`

`Save` order: test seam → `flock(LOCK_EX|LOCK_NB)` on the persistent sidecar `DIR/.NAME.sshepherd-lock` (mode 0600, never deleted, so the lock survives the rename's inode change; held → `errManifestLocked`) → CAS re-read of the resolved file → `os.CreateTemp` (O_EXCL) in the same directory → `Chmod` to the original's permission bits (not the umask) → `Chown` to the original's uid/gid when they differ from the process's (failure → `would change the manifest's owner`, before the rename) → `writeSynced` (write + fsync + close, from `manifest_out.go`) → `rename` over the resolved path (a symlink is followed, the link left intact) → `syncDir`. Off linux/darwin `lockManifest` refuses, so nothing is saved unlocked.

- [ ] **Step 1: Write the failing tests**

Create `cmd/sshepherd/edit_save_test.go`:

```go
//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// saveTarget writes content to a fresh manifest and reads it back as a
// target.
func saveTarget(t *testing.T, content string) manifestTarget {
	t.Helper()
	m, err := readManifest(writeConfig(t, content))
	if err != nil {
		t.Fatalf("readManifest: %v", err)
	}
	return m
}

func TestManifestSave(t *testing.T) {
	m := saveTarget(t, "users: []\n")
	if err := m.Save([]byte("users: []\n# saved\n")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := os.ReadFile(m.Path)
	if err != nil || string(got) != "users: []\n# saved\n" {
		t.Fatalf("manifest = (%q, %v), want the saved bytes", got, err)
	}
	fi, err := os.Stat(lockPath(m.Resolved))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("lock sidecar = (%v, %v), want it kept at mode 0600", fi, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(m.Resolved))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// TestManifestSaveCASConflict: a manifest rewritten between the read and
// the save (the seam stands in for a concurrent editor) is never
// overwritten.
func TestManifestSaveCASConflict(t *testing.T) {
	m := saveTarget(t, "users: []\n")
	saved := beforeManifestSave
	beforeManifestSave = func(mt manifestTarget) {
		if err := os.WriteFile(mt.Resolved, []byte("users: []\n# someone else\n"), 0o600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeManifestSave = saved })
	err := m.Save([]byte("users: []\n# mine\n"))
	if err == nil || !strings.Contains(err.Error(), "changed since it was read; re-run") {
		t.Fatalf("Save = %v, want the compare-and-swap refusal", err)
	}
	if got, _ := os.ReadFile(m.Path); string(got) != "users: []\n# someone else\n" {
		t.Errorf("manifest = %q, want the concurrent edit kept", got)
	}
}

// TestManifestSaveRace: two saves from the same read race; exactly one
// lands — the other meets the lock or the compare-and-swap.
func TestManifestSaveRace(t *testing.T) {
	for range 20 {
		m := saveTarget(t, "users: []\n")
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = m.Save([]byte("users: []\n# writer " + string(rune('A'+i)) + "\n"))
			}()
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, errManifestLocked), strings.Contains(err.Error(), "changed since it was read"):
			default:
				t.Fatalf("unexpected save error: %v", err)
			}
		}
		if ok != 1 {
			t.Fatalf("%d saves succeeded (errs %v), want exactly one", ok, errs)
		}
	}
}

func TestManifestSaveLockHeld(t *testing.T) {
	m := saveTarget(t, "users: []\n")
	unlock, err := lockManifest(m.Resolved)
	if err != nil {
		t.Fatalf("lockManifest: %v", err)
	}
	defer unlock()
	if err := m.Save([]byte("users: []\n# x\n")); !errors.Is(err, errManifestLocked) {
		t.Fatalf("Save = %v, want errManifestLocked", err)
	}
	if got, _ := os.ReadFile(m.Path); string(got) != "users: []\n" {
		t.Errorf("manifest changed under a held lock: %q", got)
	}
}

// TestManifestSaveFollowsSymlink: a symlinked manifest in another
// directory is saved at its target (lock and temp file there); the link
// itself is left intact.
func TestManifestSaveFollowsSymlink(t *testing.T) {
	realDir, linkDir := t.TempDir(), t.TempDir()
	target := filepath.Join(realDir, "fleet.yaml")
	if err := os.WriteFile(target, []byte("users: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(linkDir, "sshepherd.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	m, err := readManifest(link)
	if err != nil {
		t.Fatalf("readManifest: %v", err)
	}
	if err := m.Save([]byte("users: []\n# saved\n")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link replaced: %v %v", fi, err)
	}
	if got, _ := os.ReadFile(target); string(got) != "users: []\n# saved\n" {
		t.Errorf("target = %q, want the saved bytes", got)
	}
	resolvedDir, _ := filepath.EvalSymlinks(realDir)
	if _, err := os.Stat(filepath.Join(resolvedDir, ".fleet.yaml.sshepherd-lock")); err != nil {
		t.Errorf("lock sidecar not next to the target: %v", err)
	}
	if entries, _ := os.ReadDir(linkDir); len(entries) != 1 {
		t.Errorf("link directory gained files: %v", entries)
	}
}

// TestManifestSaveKeepsMode: a 0640 manifest stays 0640 under umask 077 —
// the temp file's mode is set explicitly, not left to the umask.
func TestManifestSaveKeepsMode(t *testing.T) {
	m := saveTarget(t, "users: []\n")
	if err := os.Chmod(m.Resolved, 0o640); err != nil {
		t.Fatal(err)
	}
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })
	if err := m.Save([]byte("users: []\n# saved\n")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(m.Resolved)
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v (%v), want 0640", fi.Mode().Perm(), err)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run:

```bash
go test ./cmd/sshepherd -run TestManifestSave
```

Expected: FAIL, output includes:

```text
FAIL	github.com/javadh75/SSHepherd/cmd/sshepherd [build failed]
FAIL
cmd/sshepherd/edit_save_test.go:28:14: m.Save undefined (type manifestTarget has no field or method Save)
cmd/sshepherd/edit_save_test.go:35:21: undefined: lockPath
cmd/sshepherd/edit_save_test.go:52:11: undefined: beforeManifestSave
cmd/sshepherd/edit_save_test.go:53:2: undefined: beforeManifestSave
```

- [ ] **Step 3: Implement**

Replace the whole of `cmd/sshepherd/edit.go` with:

```go
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// runFlags are the flags apply, revoke and rotate share, registered with
// apply's defaults and help text (apply adds --server on top).
type runFlags struct {
	cfgPath    string
	knownHosts string
	parallel   int
	dryRun     bool
	yes        bool
	idf        identityFlags
}

// register declares the shared flags on cmd.
func (f *runFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.cfgPath, "config", "sshepherd.yaml", "path to the manifest")
	cmd.Flags().StringVar(&f.knownHosts, "known-hosts", defaultKnownHosts, "path to known_hosts (strict host-key checking)")
	cmd.Flags().IntVar(&f.parallel, "parallel", defaultParallel, "max concurrent server connections")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "plan and report only; never write")
	cmd.Flags().BoolVar(&f.yes, "yes", false, "skip the confirmation prompt (automation)")
	cmd.MarkFlagsMutuallyExclusive("dry-run", "yes")
	f.idf.register(cmd)
}

// manifestTarget is the manifest as a run read it: the path given, the
// resolved file (symlinks followed — the save writes there and leaves the
// link intact), and the exact bytes read, which the save's compare-and-swap
// and plain apply's pre-write re-check compare against.
type manifestTarget struct {
	Path     string
	Resolved string
	Loaded   []byte
}

// readManifest reads the manifest once and resolves its real path.
func readManifest(path string) (manifestTarget, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the user's own --config flag
	if err != nil {
		return manifestTarget{}, fmt.Errorf("read manifest: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return manifestTarget{}, fmt.Errorf("read manifest: %w", err)
	}
	return manifestTarget{Path: path, Resolved: resolved, Loaded: data}, nil
}

// Unchanged re-reads the resolved file: a manifest that changed since it
// was read (a concurrent revoke, a hand edit, a git pull) must not be
// planned against or overwritten.
func (m manifestTarget) Unchanged() error {
	now, err := os.ReadFile(m.Resolved)
	if err != nil {
		return fmt.Errorf("re-read manifest %s: %w", m.Path, err)
	}
	if !bytes.Equal(now, m.Loaded) {
		return fmt.Errorf("manifest %s changed since it was read; re-run", m.Path)
	}
	return nil
}

// beforeManifestSave is a test seam: it runs at the start of Save, before
// the lock and the compare-and-swap.
var beforeManifestSave = func(manifestTarget) {}

// Save replaces the manifest with data, once: under an exclusive
// non-blocking flock on a persistent sidecar (.NAME.sshepherd-lock next to
// the resolved file, never deleted, so the lock outlives the rename's inode
// change), after a compare-and-swap against the bytes read, through an
// O_EXCL temp file in the same directory carrying the original's permission
// bits and owner, fsynced, renamed over the resolved path, directory
// fsynced.
func (m manifestTarget) Save(data []byte) error {
	beforeManifestSave(m)
	unlock, err := lockManifest(m.Resolved)
	if err != nil {
		return err
	}
	defer unlock()
	if err := m.Unchanged(); err != nil {
		return err
	}
	fi, err := os.Stat(m.Resolved)
	if err != nil {
		return fmt.Errorf("save manifest %s: %w", m.Path, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(m.Resolved), "."+filepath.Base(m.Resolved)+".tmp-*")
	if err != nil {
		return fmt.Errorf("save manifest %s: %w", m.Path, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op once renamed
	if err := tmp.Chmod(fi.Mode().Perm()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("save manifest %s: %w", m.Path, err)
	}
	if err := keepOwner(tmp, fi); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("save manifest %s: %w", m.Path, err)
	}
	if err := writeSynced(tmp, m.Path, data); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), m.Resolved); err != nil {
		return fmt.Errorf("save manifest %s: %w", m.Path, err)
	}
	return syncDir(m.Resolved)
}

// lockPath is the persistent lock sidecar for a resolved manifest path.
func lockPath(resolved string) string {
	return filepath.Join(filepath.Dir(resolved), "."+filepath.Base(resolved)+".sshepherd-lock")
}

// errManifestLocked is returned when another run holds the manifest lock.
var errManifestLocked = errors.New("manifest is being updated by another sshepherd run; re-run")
```

Create `cmd/sshepherd/edit_lock_unix.go`:

```go
//go:build linux || darwin

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// lockManifest takes an exclusive, non-blocking flock on the manifest's
// persistent sidecar (mode 0600, never deleted). A held lock is
// errManifestLocked; the returned func releases it.
func lockManifest(resolved string) (func(), error) {
	path := lockPath(resolved)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- sidecar next to the user's own manifest
	if err != nil {
		return nil, fmt.Errorf("lock manifest: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { // #nosec G115 -- fd fits an int
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errManifestLocked
		}
		return nil, fmt.Errorf("lock manifest %s: %w", path, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) // #nosec G115 -- fd fits an int
		_ = f.Close()
	}, nil
}

// keepOwner gives tmp the original manifest's uid/gid when they differ
// from the process's; a failed chown refuses the save before the rename
// rather than silently changing the manifest's owner.
func keepOwner(tmp *os.File, orig fs.FileInfo) error {
	st, ok := orig.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	uid, gid := int(st.Uid), int(st.Gid)
	if uid == os.Getuid() && gid == os.Getgid() {
		return nil
	}
	if err := tmp.Chown(uid, gid); err != nil {
		return fmt.Errorf("would change the manifest's owner (%d:%d): %w", uid, gid, err)
	}
	return nil
}
```

Create `cmd/sshepherd/edit_lock_other.go`:

```go
//go:build !linux && !darwin

package main

import (
	"errors"
	"io/fs"
	"os"
)

// lockManifest is unavailable off linux/darwin: without flock the save
// cannot exclude a concurrent run, so revoke/rotate refuse to save.
func lockManifest(string) (func(), error) {
	return nil, errors.New("saving the manifest needs flock, available on linux and darwin only")
}

// keepOwner is a no-op where lockManifest already refuses.
func keepOwner(*os.File, fs.FileInfo) error { return nil }
```

- [ ] **Step 4: Run them (the race test loops 20 times)**

Run:

```bash
go test -race ./cmd/sshepherd -run TestManifestSave -v 2>&1 | grep -E '^--- '
```

Expected: PASS, output includes:

```text
--- PASS: TestManifestSave (…s)
--- PASS: TestManifestSaveCASConflict (…s)
--- PASS: TestManifestSaveRace (…s)
--- PASS: TestManifestSaveLockHeld (…s)
--- PASS: TestManifestSaveFollowsSymlink (…s)
--- PASS: TestManifestSaveKeepsMode (…s)
```

Check the non-unix build still compiles:

```bash
GOOS=windows go vet ./cmd/sshepherd
```

Expected: PASS

- [ ] **Step 5: Group C1 gate**

Run:

```bash
gofmt -l cmd && go vet ./... && go test -race ./cmd/sshepherd ./internal/... && go build ./... && golangci-lint run ./cmd/... ./internal/...
```

Expected: PASS, output includes:

```text
ok  	github.com/javadh75/SSHepherd/cmd/sshepherd	(…s)
ok  	github.com/javadh75/SSHepherd/internal/adopt	(…s)
ok  	github.com/javadh75/SSHepherd/internal/apply	(…s)
ok  	github.com/javadh75/SSHepherd/internal/audit	(…s)
ok  	github.com/javadh75/SSHepherd/internal/authkeys	(…s)
ok  	github.com/javadh75/SSHepherd/internal/clog	(…s)
```

- [ ] **Commit**

```bash
git add cmd/sshepherd/edit.go cmd/sshepherd/edit_lock_unix.go cmd/sshepherd/edit_lock_other.go cmd/sshepherd/edit_save_test.go
git commit -m "$(cat <<'EOF'
feat(cmd): locked compare-and-swap atomic manifest save

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

## Group C2 — `revoke`, `rotate`, tests, integration, docs (stage 3)

Starts after stage 2 is merged. Codes against the C1 and stage-1 interfaces pinned above.

### Task C2.1: The shared edit driver (`editrun.go`) [Group C2]

**Files:**
- Create: `cmd/sshepherd/editrun.go`
- Create: `cmd/sshepherd/editrun_test.go`

`editrun.go` holds everything both verbs share — steps 1 (flag rules), 2 (load) and 4–8 of the spec's order of operations:

- `editFlags` = `runFlags` + `--operator` + `--no-apply`; `validate` refuses `--no-apply` with any of `--identity`, `--identity-passphrase-file`, `--identity-passphrase`, `--known-hosts`, `--parallel` (`cmd.Flags().Changed`), else runs apply's `validateFlags`.
- `loadForEdit`: `readManifest` + `manifest.Load`; a `*manifest.UnsupportedError` becomes `cannot edit PATH: REASON — edit the manifest by hand and run 'sshepherd apply'`.
- `operatorGate`: operator targets need `--operator` (all named in one message); `--operator` without one is refused.
- `editPlan` + `encodeEdit` (the one `Encode`; its bytes feed the plan, `Affected` and the save).
- `runEdit`: new manifest warnings; `apply.Affected`; emptied-server detail; header. Zero affected or `--no-apply` → `saveOnly` (no credentials, no connections). Otherwise `runApply` with: `preferKeys` = old-config grants then new-config grants (deduplicated); `alwaysConfirm`; `prompt` refusing when **nothing can land** (no change/converged plan and ≥ 1 refused — unreachable is not a refusal) with `nothing saved — X still has access on N servers; …`; `beforeWrite` = ctx check (exit 3) → `nothing saved — none of the keys you hold would survive …` when change plans exist, none keeps a fresh held key and none is converged (exit 1) → `saveEdit`; `finish` = decline (`aborted; manifest not changed, nothing written`, exit 1, no summary) / summary / finish hint for not-converged, non-emptied servers / scope line.
- `saveEdit` prints `manifest PATH updated — commit and push it: an apply from a copy without this edit re-grants the removed key`.

- [ ] **Step 1: Write the failing unit tests**

Create `cmd/sshepherd/editrun_test.go`:

```go
package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func TestApplyHint(t *testing.T) {
	for _, tt := range []struct {
		cfg     string
		servers []string
		want    string
	}{
		{"sshepherd.yaml", []string{"web-1"}, "sshepherd apply --server web-1"},
		{"/etc/fleet.yaml", []string{"web-1", "db-1"}, "sshepherd apply --config /etc/fleet.yaml --server web-1 --server db-1"},
		{"my fleet.yaml", []string{"web-1"}, "sshepherd apply --config 'my fleet.yaml' --server web-1"},
	} {
		if got := applyHint(tt.cfg, tt.servers); got != tt.want {
			t.Errorf("applyHint(%q, %v) = %q, want %q", tt.cfg, tt.servers, got, tt.want)
		}
	}
}

func TestNothingCanLand(t *testing.T) {
	p := func(c apply.Class) apply.ServerPlan { return apply.ServerPlan{Class: c} }
	for _, tt := range []struct {
		name  string
		plans []apply.ServerPlan
		want  bool
	}{
		{"all refused", []apply.ServerPlan{p(apply.ClassRefused), p(apply.ClassRefused)}, true},
		{"refused + unreachable", []apply.ServerPlan{p(apply.ClassRefused), p(apply.ClassUnreachable)}, true},
		{"all unreachable can converge later", []apply.ServerPlan{p(apply.ClassUnreachable)}, false},
		{"one change lands", []apply.ServerPlan{p(apply.ClassRefused), p(apply.ClassChange)}, false},
		{"one converged lands", []apply.ServerPlan{p(apply.ClassRefused), p(apply.ClassConverged)}, false},
	} {
		if got := nothingCanLand(tt.plans); got != tt.want {
			t.Errorf("%s: nothingCanLand = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestAnySurvivor(t *testing.T) {
	k1, err := authkeys.ParseLine(testkeys.Line(t, 1))
	if err != nil || k1 == nil {
		t.Fatal(err)
	}
	desired := []apply.ServerPlan{{Class: apply.ClassChange, Desired: []authkeys.Key{*k1}}}
	if anySurvivor(desired, nil) {
		t.Error("no held keys cannot survive")
	}
	if !anySurvivor(desired, []sshconn.HeldKey{{Fingerprint: fpOf(t, 1), Source: sshconn.SourceAgent}}) {
		t.Error("a held desired key survives")
	}
	if anySurvivor([]apply.ServerPlan{{Class: apply.ClassRefused, Desired: desired[0].Desired}},
		[]sshconn.HeldKey{{Fingerprint: fpOf(t, 1)}}) {
		t.Error("only change plans count")
	}
}

func TestOperatorGate(t *testing.T) {
	cfg, err := config.Parse([]byte("users:\n" +
		"  - {name: ops, operator: true, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n" +
		"  - {name: ci, operator: true, keys: [\"" + testkeys.Line(t, 2) + "\"]}\n" +
		"  - {name: alice, keys: [\"" + testkeys.Line(t, 3) + "\"]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operatorGate(cfg, []string{"alice", "ops", "ci"}, false); err == nil ||
		err.Error() != "ops, ci are operators (fleet-wide, protected); pass --operator to confirm" {
		t.Errorf("err = %v", err)
	}
	if _, err := operatorGate(cfg, []string{"alice"}, true); err == nil || !strings.Contains(err.Error(), "drop the flag") {
		t.Errorf("err = %v", err)
	}
	ops, err := operatorGate(cfg, []string{"ops", "alice", "ops"}, true)
	if err != nil || !slices.Equal(ops, []string{"ops"}) {
		t.Errorf("operatorGate = (%v, %v), want [ops]", ops, err)
	}
	if ops, err := operatorGate(cfg, []string{"alice"}, false); err != nil || len(ops) != 0 {
		t.Errorf("operatorGate = (%v, %v), want no operators", ops, err)
	}
}

func TestUnionFPs(t *testing.T) {
	if got := unionFPs([]string{"a", "b"}, []string{"b", "c"}); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Errorf("unionFPs = %v", got)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run:

```bash
go test ./cmd/sshepherd -run 'TestApplyHint|TestNothingCanLand|TestAnySurvivor|TestOperatorGate|TestUnionFPs'
```

Expected: FAIL, output includes:

```text
FAIL	github.com/javadh75/SSHepherd/cmd/sshepherd [build failed]
FAIL
cmd/sshepherd/editrun_test.go:25:13: undefined: applyHint
cmd/sshepherd/editrun_test.go:44:13: undefined: nothingCanLand
cmd/sshepherd/editrun_test.go:56:5: undefined: anySurvivor
cmd/sshepherd/editrun_test.go:59:6: undefined: anySurvivor
```

- [ ] **Step 3: Implement**

Create `cmd/sshepherd/editrun.go`:

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/manifest"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// editFlags are revoke's and rotate's flags: apply's shared set plus the
// operator acknowledgement and --no-apply.
type editFlags struct {
	run      runFlags
	operator bool
	noApply  bool
}

func (f *editFlags) register(cmd *cobra.Command) {
	f.run.register(cmd)
	cmd.Flags().BoolVar(&f.operator, "operator", false,
		"confirm that a target is, or belongs to, an operator user (fleet-wide, protected)")
	cmd.Flags().BoolVar(&f.noApply, "no-apply", false,
		"edit and save the manifest after confirmation; contact no server")
}

// connectionFlags are the flags --no-apply would leave silently unused.
var connectionFlags = []string{"identity", "identity-passphrase-file", "identity-passphrase", "known-hosts", "parallel"}

// validate is step 1's flag half (exit 3 before the manifest is read):
// --no-apply refuses the connection flags; otherwise --parallel and the
// identity flags are checked exactly as apply checks them.
func (f *editFlags) validate(cmd *cobra.Command) (identities, error) {
	if f.noApply {
		for _, name := range connectionFlags {
			if cmd.Flags().Changed(name) {
				return identities{}, fmt.Errorf("--no-apply contacts no server, so --%s would be unused; drop one of them", name)
			}
		}
		return identities{}, nil
	}
	return validateFlags(f.run.parallel, &f.run.idf)
}

// loadForEdit is step 2: read the manifest once (exact bytes + resolved
// path) and load its node tree. A valid manifest the comment-preserving
// edits cannot handle is its own refusal.
func loadForEdit(log *slog.Logger, path string) (manifestTarget, *manifest.File, error) {
	m, err := readManifest(path)
	if err != nil {
		return manifestTarget{}, nil, fmt.Errorf("load manifest: %w", err)
	}
	mf, err := manifest.Load(m.Loaded)
	var ue *manifest.UnsupportedError
	if errors.As(err, &ue) {
		return manifestTarget{}, nil, fmt.Errorf("cannot edit %s: %s — edit the manifest by hand and run 'sshepherd apply'", path, ue.Reason)
	}
	if err != nil {
		return manifestTarget{}, nil, fmt.Errorf("load manifest: %w", err)
	}
	cfg := mf.Config()
	log.Info(fmt.Sprintf("loaded manifest: %d users, %d servers", len(cfg.Users), len(cfg.Servers)))
	for _, w := range cfg.Warnings {
		log.Warn(w)
	}
	return m, mf, nil
}

// operatorGate enforces the operator protection contract over every
// resolved target user before any edit: an operator target needs
// --operator, and --operator needs an operator target (a habitually
// passed flag would empty the gate). Returns the operator targets.
func operatorGate(cfg *config.Config, users []string, acknowledged bool) ([]string, error) {
	var ops []string
	for _, name := range users {
		for _, u := range cfg.Users {
			if u.Name == name && u.Operator && !slices.Contains(ops, name) {
				ops = append(ops, name)
			}
		}
	}
	switch {
	case len(ops) == 1 && !acknowledged:
		return nil, fmt.Errorf("%s is an operator (fleet-wide, protected); pass --operator to confirm", ops[0])
	case len(ops) > 1 && !acknowledged:
		return nil, fmt.Errorf("%s are operators (fleet-wide, protected); pass --operator to confirm", strings.Join(ops, ", "))
	case len(ops) == 0 && acknowledged:
		return nil, errors.New("--operator given but no target is an operator; drop the flag")
	}
	return ops, nil
}

// editPlan is a resolved, encoded manifest edit (steps 1–3), ready for
// runEdit (steps 4–8).
type editPlan struct {
	target     manifestTarget
	former     *config.Config // the as-loaded config
	encoded    []byte         // the one Encode: the plan, Affected and the save all use these bytes
	edited     *config.Config // config.Parse(encoded)
	summary    apply.EditSummary
	formerNote string // "" (revoked) or "rotated out"
	removesKey bool   // print the scope line after the writes
	stillHas   string // "alice still has" — for the nothing-can-land refusal
}

// encodeEdit is step 3's one Encode; its built-in config.Parse self-check
// is the only validation (a failure is an internal error, nothing saved).
func encodeEdit(mf *manifest.File) ([]byte, *config.Config, error) {
	out, err := mf.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("edit manifest: %w", err)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		return nil, nil, fmt.Errorf("edit manifest: %w", err)
	}
	return out, cfg, nil
}

// runEdit is steps 4–8: the affected set and header, then either the
// save-only path (zero affected, or --no-apply) or apply's pipeline over
// the affected servers with the save in beforeWrite.
func runEdit(cmd *cobra.Command, a *app, stdout io.Writer, f *editFlags, ids identities, ep editPlan) error {
	log := a.logger
	for _, w := range ep.edited.Warnings {
		if !slices.Contains(ep.former.Warnings, w) {
			log.Warn(w)
		}
	}
	aff := apply.Affected(ep.former, ep.edited)
	ep.summary.Affected = len(aff.Servers)
	ep.summary.Emptied = emptiedServers(ep.former, aff.Emptied)
	ropts := apply.RenderOptions{Color: a.reportColor, Former: ep.former, FormerNote: ep.formerNote}
	header := func(w io.Writer) { apply.RenderEditHeader(w, ep.summary, ropts) }
	if f.noApply || len(aff.Servers) == 0 {
		header(stdout)
		return saveOnly(cmd, log, stdout, f, ep, aff.Servers)
	}
	return runApply(cmd, a, stdout, &f.run, ids, applyRun{
		cfg:        ep.edited,
		former:     ep.former,
		formerNote: ep.formerNote,
		servers:    serversNamed(ep.edited, aff.Servers),
		// Sessions authenticate with what is installed now: the old
		// config's grants first, then the new one's.
		preferKeys: func(s config.Server) []string {
			return unionFPs(audit.GrantedFingerprints(ep.former, s.Name), audit.GrantedFingerprints(ep.edited, s.Name))
		},
		header:        header,
		alwaysConfirm: true,
		prompt: func(plans []apply.ServerPlan, toWrite int) (string, error) {
			if nothingCanLand(plans) {
				log.Error(fmt.Sprintf("nothing saved — %s access on %s; fix the refusals and re-run, or record the change without touching servers with --no-apply",
					ep.stillHas, apply.Plural(len(plans), "server", "servers")))
				return "", errNonCompliant
			}
			return apply.EditPrompt(ep.summary.Operators, toWrite, len(plans), false), nil
		},
		beforeWrite: func(ctx context.Context, plans []apply.ServerPlan, fresh []sshconn.HeldKey) error {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("interrupted: %w — manifest not saved, nothing written", err)
			}
			if countChanges(plans) > 0 && !anySurvivor(plans, fresh) && !anyConverged(plans) {
				log.Error("nothing saved — none of the keys you hold would survive on any server (did a key expire after the plan?)")
				return errNonCompliant
			}
			return saveEdit(stdout, ep)
		},
		finish: func(plans []apply.ServerPlan, stage applyStage) error {
			return finishEdit(stdout, log, ep, aff, f.run.cfgPath, plans, stage, ropts)
		},
	})
}

// saveOnly confirms and saves without contacting any server: zero
// affected servers, or --no-apply. --dry-run stops before the prompt.
func saveOnly(cmd *cobra.Command, log *slog.Logger, stdout io.Writer, f *editFlags, ep editPlan, affected []string) error {
	if f.run.dryRun {
		log.Info("dry run — manifest not changed")
		return nil
	}
	ok, err := confirmGate(cmd, f.run.yes, apply.EditPrompt(ep.summary.Operators, 0, len(affected), f.noApply))
	if err != nil {
		return err
	}
	if !ok {
		log.Error("aborted; manifest not changed, nothing written")
		return errNonCompliant
	}
	if err := saveEdit(stdout, ep); err != nil {
		return err
	}
	switch {
	case f.noApply && len(affected) == 0:
		fmt.Fprintln(stdout, "no servers contacted — no server's desired keys changed")
	case f.noApply:
		verb := "carry"
		if len(affected) == 1 {
			verb = "carries"
		}
		fmt.Fprintf(stdout, "no servers contacted — %s still %s the old keys; run '%s' to push\n",
			apply.Plural(len(affected), "affected server", "affected servers"), verb, applyHint(f.run.cfgPath, affected))
	case ep.removesKey:
		printScope(stdout, 0, len(ep.edited.Servers))
	}
	return nil
}

// saveEdit is step 7's save, then the reminder that the manifest is the
// source of truth only once it is committed.
func saveEdit(stdout io.Writer, ep editPlan) error {
	if err := ep.target.Save(ep.encoded); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "manifest %s updated — commit and push it: an apply from a copy without this edit re-grants the removed key\n", ep.target.Path)
	return nil
}

// finishEdit renders step 8's tail and maps the exit code.
func finishEdit(stdout io.Writer, log *slog.Logger, ep editPlan, aff apply.AffectedSet, cfgPath string,
	plans []apply.ServerPlan, stage applyStage, ropts apply.RenderOptions,
) error {
	if stage == stageDeclined {
		log.Error("aborted; manifest not changed, nothing written")
		return errNonCompliant
	}
	apply.RenderSummary(stdout, plans, ropts)
	if stage == stageConfirmed {
		var pending []string
		for _, p := range plans {
			converged := p.Class == apply.ClassConverged || (p.Class == apply.ClassChange && p.Outcome == apply.OutcomeApplied)
			if !converged && !slices.Contains(aff.Emptied, p.Server.Name) {
				pending = append(pending, p.Server.Name)
			}
		}
		if len(pending) > 0 {
			fmt.Fprintf(stdout, "manifest updated; %s not converged — finish with: %s\n",
				apply.Plural(len(pending), "server", "servers"), applyHint(cfgPath, pending))
		}
		if ep.removesKey {
			printScope(stdout, len(plans), len(ep.edited.Servers))
		}
	}
	if apply.ExitCode(plans) != 0 {
		return errNonCompliant
	}
	return nil
}

func printScope(w io.Writer, contacted, fleet int) {
	fmt.Fprintf(w, "scope: only servers whose grants changed were contacted (%d of %d); the removed key may still be installed elsewhere as drift — run 'sshepherd audit' to confirm, 'sshepherd apply' to sweep\n",
		contacted, fleet)
}

// shellSafe matches arguments that need no quoting in a hint.
var shellSafe = regexp.MustCompile(`^[A-Za-z0-9@%+=:,./_-]+$`)

func hintArg(s string) string {
	if shellSafe.MatchString(s) {
		return s
	}
	return sshconn.ShQuote(s)
}

// applyHint is the apply command that finishes the job: --config when it
// is not the default, one --server per server.
func applyHint(cfgPath string, servers []string) string {
	parts := []string{"sshepherd apply"}
	if cfgPath != "sshepherd.yaml" {
		parts = append(parts, "--config "+hintArg(cfgPath))
	}
	for _, s := range servers {
		parts = append(parts, "--server "+hintArg(s))
	}
	return strings.Join(parts, " ")
}

// nothingCanLand: no affected server is change-planned or converged, and
// at least one is refused (unreachable servers can converge later).
func nothingCanLand(plans []apply.ServerPlan) bool {
	refused := false
	for _, p := range plans {
		switch p.Class {
		case apply.ClassChange, apply.ClassConverged:
			return false
		case apply.ClassRefused:
			refused = true
		}
	}
	return refused
}

// anySurvivor: some change-planned server keeps a key held under the
// post-prompt listing.
func anySurvivor(plans []apply.ServerPlan, fresh []sshconn.HeldKey) bool {
	held := make(map[string]bool, len(fresh))
	for _, k := range fresh {
		held[k.Fingerprint] = true
	}
	for _, p := range plans {
		if p.Class == apply.ClassChange && len(apply.Survivors(p.Desired, held)) > 0 {
			return true
		}
	}
	return false
}

func anyConverged(plans []apply.ServerPlan) bool {
	return slices.ContainsFunc(plans, func(p apply.ServerPlan) bool { return p.Class == apply.ClassConverged })
}

// emptiedServers details each emptied server for the header: the former
// owners of the keys that stay installed there.
func emptiedServers(former *config.Config, names []string) []apply.EmptiedServer {
	out := make([]apply.EmptiedServer, 0, len(names))
	for _, name := range names {
		keys := former.DesiredFor(name)
		e := apply.EmptiedServer{Server: name, Keys: len(keys)}
		for _, k := range keys {
			if u, ok := former.OwnerOf(k.Fingerprint); ok && !slices.Contains(e.Users, u.Name) {
				e.Users = append(e.Users, u.Name)
			}
		}
		out = append(out, e)
	}
	return out
}

// serversNamed returns cfg's servers named in names, manifest order.
func serversNamed(cfg *config.Config, names []string) []config.Server {
	var out []config.Server
	for _, s := range cfg.Servers {
		if slices.Contains(names, s.Name) {
			out = append(out, s)
		}
	}
	return out
}

// unionFPs concatenates fingerprint lists, first occurrence wins.
func unionFPs(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		for _, fp := range l {
			if !slices.Contains(out, fp) {
				out = append(out, fp)
			}
		}
	}
	return out
}

// keyName names a key argument in messages: the argument as given, or its
// fingerprint when the argument was a whole key line.
func keyName(k keyArg) string {
	if k.Key != nil && looksLikeKeyLine(k.Arg) {
		return k.Fingerprint
	}
	return k.Arg
}
```

- [ ] **Step 4: Run them**

Run:

```bash
go test ./cmd/sshepherd -run 'TestApplyHint|TestNothingCanLand|TestAnySurvivor|TestOperatorGate|TestUnionFPs'
```

Expected: PASS, output includes:

```text
ok  	github.com/javadh75/SSHepherd/cmd/sshepherd	(…s)
```

- [ ] **Commit**

```bash
git add cmd/sshepherd/editrun.go cmd/sshepherd/editrun_test.go
git commit -m "$(cat <<'EOF'
feat(cmd): shared revoke/rotate edit driver

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

### Task C2.2: `sshepherd revoke` [Group C2]

**Files:**
- Create: `cmd/sshepherd/revoke.go`
- Modify: `cmd/sshepherd/run.go` (register the command)
- Create: `cmd/sshepherd/revoke_test.go`

Hermetic tests (`internal/sshconn/sshtest`: in-process servers running `/bin/sh` under a temp `HOME`, an in-memory agent) cover every command-level bullet of the spec's Testing section: revoke user end to end (comments kept, `(revoked)` label, scope line); every server already converged → always confirms, saves, exit 0; `--dry-run` exit codes (1 pending, 0 converged, 0 zero-affected with no connection) and nothing saved; declined prompt; CAS conflict via `beforeManifestSave`; symlinked manifest in another directory; nothing can land; sole-grantee server (header warning before the plan, excluded from the hint); partial failure (unreachable server → exit 1, saved, `finish with: sshepherd apply --config … --server web-2`); held keys gone after the prompt (agent socket removed by the prompt seam); Ctrl-C at the prompt (exit 3, nothing saved); `--no-apply` (zero connections) and `--dry-run --no-apply` (header only); operators (mixed targets refused naming every operator, `--operator` without one refused, `OPERATOR:` header + prompt prefix, last operator key clears the flag); `revoke --key` leaving an ungranted server's copy alone with the scope line; de-duplication; every usage rule.

- [ ] **Step 1: Write the failing tests**

Create `cmd/sshepherd/revoke_test.go`:

```go
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// editHost is one hermetic server of an edit fleet.
type editHost struct {
	home string
	srv  *sshtest.Server
}

// editFleet starts one in-process server per name, each accepting logins
// from the keys of the given seeds and running commands under its own
// HOME, with an agent holding key 1 on SSH_AUTH_SOCK. It returns the hosts
// and a known_hosts file covering them all; the agent socket path is
// returned so a test can make the agent vanish.
func editFleet(t *testing.T, accept []byte, names ...string) (map[string]editHost, string, string) {
	t.Helper()
	host := sshtest.Signer(t, sshtest.Key(40))
	var authorized []ssh.PublicKey
	for _, seed := range accept {
		authorized = append(authorized, sshtest.Signer(t, sshtest.Key(seed)).PublicKey())
	}
	hosts := make(map[string]editHost, len(names))
	var lines []string
	for _, name := range names {
		home := shortHome(t)
		if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
			t.Fatal(err)
		}
		srv := sshtest.NewServer(t, sshtest.ServerConfig{
			HostKeys:   []ssh.Signer{host},
			Authorized: authorized,
			Handle:     sshtest.ShellHandler(home),
		})
		hosts[name] = editHost{home: home, srv: srv}
		lines = append(lines, srv.KnownHostsLine(host.PublicKey()))
	}
	sock := sshtest.Agent(t, sshtest.Key(1))
	t.Setenv("SSH_AUTH_SOCK", sock)
	return hosts, sshtest.KnownHostsFile(t, lines...), sock
}

// install writes h's authorized_keys: one plain line per seed, plus extra
// raw lines.
func (h editHost) install(t *testing.T, seeds []byte, extra ...string) {
	t.Helper()
	var b strings.Builder
	for _, s := range seeds {
		b.WriteString(testkeys.Line(t, s) + "\n")
	}
	for _, l := range extra {
		b.WriteString(l + "\n")
	}
	if err := os.WriteFile(filepath.Join(h.home, ".ssh", "authorized_keys"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// keys returns h's authorized_keys.
func (h editHost) keys(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.home, ".ssh", "authorized_keys"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// line is h's servers: entry.
func (h editHost) line(name string) string {
	return fmt.Sprintf("  - {name: %s, host: 127.0.0.1, port: %d, user: deploy}\n", name, h.srv.Port)
}

// qk is a quoted manifest key line for seed.
func qk(t *testing.T, seed byte) string { return `"` + testkeys.Line(t, seed) + `"` }

// readCfg parses the manifest at path.
func readCfg(t *testing.T, path string) *config.Config {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatalf("saved manifest invalid: %v\n%s", err, raw)
	}
	return cfg
}

// fileBytes reads path.
func fileBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// twoUserFleet: alice (k1, held by the agent) and bob (k2) both granted
// web-1 and web-2, both keys installed on both.
func twoUserFleet(t *testing.T) (map[string]editHost, string, string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	for _, h := range hosts {
		h.install(t, []byte{1, 2})
	}
	cfg := writeConfig(t, "# fleet manifest — hand-maintained\nusers:\n"+
		"  - {name: alice, keys: ["+qk(t, 1)+"]}\n"+
		"  # bob leaves on Friday\n"+
		"  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: bob, servers: [web-1, web-2]}\n")
	return hosts, kh, cfg
}

func TestRevokeUserHermetic(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	var out, errBuf bytes.Buffer
	code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	for _, want := range []string{
		"manifest edit: remove user bob (1 key, 1 access grant) — 2 servers affected\n",
		"bob (revoked)",
		"remove (unauthorized)",
		"manifest " + cfg + " updated — commit and push it: an apply from a copy without this edit re-grants the removed key\n",
		"web-1: applied · verified",
		"web-2: applied · verified",
		"scope: only servers whose grants changed were contacted (2 of 2)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	saved := readCfg(t, cfg)
	if len(saved.Users) != 1 || saved.Users[0].Name != "alice" || len(saved.Access) != 1 {
		t.Errorf("saved manifest = %+v, want alice only", saved)
	}
	if raw := string(fileBytes(t, cfg)); !strings.Contains(raw, "# fleet manifest — hand-maintained") {
		t.Errorf("the file header comment was lost:\n%s", raw)
	}
	for name, h := range hosts {
		got := h.keys(t)
		if strings.Contains(got, testkeys.Line(t, 2)) || !strings.Contains(got, testkeys.Line(t, 1)) {
			t.Errorf("%s authorized_keys = %q, want alice only", name, got)
		}
	}
}

// TestRevokeAlreadyConverged: the edit changes the desired file, but the
// server already holds the new render — no write, yet the manifest edit is
// itself a change: always confirmed, then saved, exit 0.
func TestRevokeAlreadyConverged(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	render := authkeys.ManagedHeader + "\n" + testkeys.Line(t, 1) + " alice\n"
	for _, h := range hosts {
		h.install(t, nil, strings.TrimSuffix(render, "\n"))
	}
	before := fileBytes(t, cfg)

	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 ||
		!strings.Contains(errBuf.String(), "confirmation required") {
		t.Fatalf("non-TTY without --yes: exit %d, stderr %q; want 3 (the edit always asks)", code, errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Fatal("manifest saved without confirmation")
	}

	var prompt bytes.Buffer
	usePromptStreams(t, strings.NewReader("y\n"), &prompt)
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"revoke", "bob", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(prompt.String(), "save manifest edit (no servers need a write)? [y/N]") {
		t.Errorf("prompt = %q", prompt.String())
	}
	if !strings.Contains(out.String(), "converged (no changes)") || !strings.Contains(out.String(), "updated — commit and push it") {
		t.Errorf("stdout = %s", out.String())
	}
	if len(readCfg(t, cfg).Users) != 1 {
		t.Error("manifest not saved")
	}
}

func TestRevokeDryRun(t *testing.T) {
	t.Run("pending change: exit 1, nothing saved or written", func(t *testing.T) {
		hosts, kh, cfg := twoUserFleet(t)
		before := fileBytes(t, cfg)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("exit = %d, want 1\n%s", code, out.String())
		}
		if !bytes.Equal(fileBytes(t, cfg), before) || strings.Contains(out.String(), "updated") {
			t.Error("--dry-run saved the manifest")
		}
		if !strings.Contains(out.String(), "2 pending  → exit 1") {
			t.Errorf("stdout lacks the apply-style summary:\n%s", out.String())
		}
		if !strings.Contains(hosts["web-1"].keys(t), testkeys.Line(t, 2)) {
			t.Error("--dry-run wrote a server")
		}
	})
	t.Run("already converged: exit 0", func(t *testing.T) {
		hosts, kh, cfg := twoUserFleet(t)
		for _, h := range hosts {
			h.install(t, nil, authkeys.ManagedHeader, testkeys.Line(t, 1)+" alice")
		}
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d, want 0\n%s\n%s", code, out.String(), errBuf.String())
		}
	})
	t.Run("zero affected: exit 0, no connection", func(t *testing.T) {
		hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
		cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: dave, keys: ["+qk(t, 5)+"]}\n"+
			"servers:\n"+hosts["web-1"].line("web-1")+"access:\n  - {user: alice, servers: [web-1]}\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "dave", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d, want 0\n%s\n%s", code, out.String(), errBuf.String())
		}
		if !strings.Contains(out.String(), "manifest edit: remove user dave (1 key, 0 access grants) — no servers affected") {
			t.Errorf("stdout = %s", out.String())
		}
		if len(hosts["web-1"].srv.Attempts()) != 0 {
			t.Error("a zero-affected run connected")
		}
	})
}

// TestRevokeDeduplicates: a user or a key named twice is one edit.
func TestRevokeDeduplicates(t *testing.T) {
	_, _, cfg := twoUserFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "bob", "--no-apply", "--dry-run", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
	if out.String() != "manifest edit: remove user bob (1 key, 1 access grant) — 2 servers affected\n" {
		t.Errorf("stdout = %q", out.String())
	}
	out.Reset()
	if code := run([]string{"revoke", "--key", fpOf(t, 2), "--key", testkeys.Line(t, 2), "--no-apply", "--dry-run", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
	if strings.Count(out.String(), "manifest edit: remove key") != 1 {
		t.Errorf("stdout = %q, want one key edit", out.String())
	}
}

func TestRevokeDeclined(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	before := fileBytes(t, cfg)
	var prompt bytes.Buffer
	usePromptStreams(t, strings.NewReader("n\n"), &prompt)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, errBuf.String())
	}
	if !strings.Contains(prompt.String(), "save manifest edit and write 2 of 2 affected servers? [y/N]") {
		t.Errorf("prompt = %q", prompt.String())
	}
	if !strings.Contains(errBuf.String(), "aborted; manifest not changed, nothing written") {
		t.Errorf("stderr = %q", errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) || !strings.Contains(hosts["web-1"].keys(t), testkeys.Line(t, 2)) {
		t.Error("a declined revoke changed something")
	}
}

// TestRevokeCASConflict: the manifest rewritten after the plan and before
// the save (the seam stands in for a concurrent edit) — exit 3, nothing
// saved, no server written.
func TestRevokeCASConflict(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	saved := beforeManifestSave
	beforeManifestSave = func(m manifestTarget) {
		if err := os.WriteFile(m.Resolved, append(fileBytes(t, m.Resolved), "# concurrent\n"...), 0o600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeManifestSave = saved })
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "changed since it was read; re-run") {
		t.Errorf("stderr = %q", errBuf.String())
	}
	if !strings.Contains(string(fileBytes(t, cfg)), "bob") || !strings.Contains(hosts["web-2"].keys(t), testkeys.Line(t, 2)) {
		t.Error("a refused save still edited the manifest or wrote a server")
	}
}

func TestRevokeSymlinkedManifest(t *testing.T) {
	_, kh, cfg := twoUserFleet(t)
	link := filepath.Join(t.TempDir(), "sshepherd.yaml")
	if err := os.Symlink(cfg, link); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--config", link, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the symlink was replaced")
	}
	if len(readCfg(t, cfg).Users) != 1 {
		t.Error("the link target was not saved")
	}
}

// TestRevokeNothingCanLand: every affected server refused — no prompt,
// nothing saved, exit 1.
func TestRevokeNothingCanLand(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	for _, h := range hosts {
		h.install(t, []byte{1, 2}, "this line is not a key")
	}
	before := fileBytes(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "nothing saved — bob still has access on 2 servers; fix the refusals and re-run, or record the change without touching servers with --no-apply") {
		t.Errorf("stderr = %q", errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("manifest saved although nothing could land")
	}
}

// TestRevokeSoleGrantee: db-1's only grantee is revoked — warned in the
// header before any connection, refused (apply never empties a server),
// excluded from the finish hint; web-1 converges; the manifest is saved.
func TestRevokeSoleGrantee(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "db-1")
	hosts["web-1"].install(t, []byte{1, 2})
	hosts["db-1"].install(t, []byte{2})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["db-1"].line("db-1")+
		"access:\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [web-1, db-1]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s\n%s", code, out.String(), errBuf.String())
	}
	s := out.String()
	warn := "warning: db-1 would have no granted keys — apply never empties a server, so bob's key stays installed there"
	if !strings.Contains(s, warn) || strings.Index(s, warn) > strings.Index(s, "db-1 (deploy@") {
		t.Errorf("the emptied-server warning must head the report:\n%s", s)
	}
	if !strings.Contains(s, "web-1: applied · verified") || strings.Contains(s, "finish with:") {
		t.Errorf("want web-1 applied and no finish hint (db-1 is excluded):\n%s", s)
	}
	if len(readCfg(t, cfg).Users) != 1 {
		t.Error("manifest not saved")
	}
	if !strings.Contains(hosts["db-1"].keys(t), testkeys.Line(t, 2)) {
		t.Error("db-1 was emptied")
	}
}

// TestRevokePartialFailure: one affected server unreachable — exit 1, the
// manifest saved, and the hint names the server left to converge.
func TestRevokePartialFailure(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1, 2})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+
		fmt.Sprintf("  - {name: web-2, host: 127.0.0.1, port: %d, user: deploy}\n", closedPort(t))+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: bob, servers: [web-1, web-2]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s\n%s", code, out.String(), errBuf.String())
	}
	if want := "manifest updated; 1 server not converged — finish with: sshepherd apply --config " + cfg + " --server web-2\n"; !strings.Contains(out.String(), want) {
		t.Errorf("stdout lacks %q:\n%s", want, out.String())
	}
	if len(readCfg(t, cfg).Users) != 1 {
		t.Error("manifest not saved")
	}
}

// TestRevokeHeldKeysGoneAfterPrompt: the agent vanishes while the prompt
// waits — no change-planned server keeps a held key, none is converged:
// nothing saved, exit 1.
func TestRevokeHeldKeysGoneAfterPrompt(t *testing.T) {
	hosts, kh, sock := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1, 2})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+"access:\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [web-1]}\n")
	before := fileBytes(t, cfg)
	usePromptStreams(t, &actionReader{act: func() { _ = os.Remove(sock) }, r: strings.NewReader("y\n")}, io.Discard)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "nothing saved — none of the keys you hold would survive on any server") {
		t.Errorf("stderr = %q", errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("manifest saved without a surviving held key")
	}
}

// TestRevokeInterruptedAtPrompt: Ctrl-C before the save — exit 3, nothing
// saved or written.
func TestRevokeInterruptedAtPrompt(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	before := fileBytes(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	usePromptStreams(t, &actionReader{act: cancel, r: pr}, io.Discard)
	var out, errBuf bytes.Buffer
	if code := runContext(ctx, []string{"revoke", "bob", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3\n%s", code, errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) || !strings.Contains(hosts["web-1"].keys(t), testkeys.Line(t, 2)) {
		t.Error("an interrupted revoke changed something")
	}
}

func TestRevokeNoApply(t *testing.T) {
	hosts, _, cfg := twoUserFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
	if want := "no servers contacted — 2 affected servers still carry the old keys; run 'sshepherd apply --config " + cfg + " --server web-1 --server web-2' to push\n"; !strings.Contains(out.String(), want) {
		t.Errorf("stdout lacks %q:\n%s", want, out.String())
	}
	for name, h := range hosts {
		if len(h.srv.Attempts()) != 0 {
			t.Errorf("--no-apply connected to %s", name)
		}
	}
	if len(readCfg(t, cfg).Users) != 1 {
		t.Error("manifest not saved")
	}

	t.Run("--dry-run --no-apply prints the header only", func(t *testing.T) {
		_, _, cfg := twoUserFleet(t)
		before := fileBytes(t, cfg)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--no-apply", "--dry-run", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if out.String() != "manifest edit: remove user bob (1 key, 1 access grant) — 2 servers affected\n" {
			t.Errorf("stdout = %q", out.String())
		}
		if !bytes.Equal(fileBytes(t, cfg), before) {
			t.Error("--dry-run --no-apply saved")
		}
	})
}

func TestRevokeOperator(t *testing.T) {
	setup := func(t *testing.T) (editHost, string, string) {
		hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
		hosts["web-1"].install(t, []byte{2, 1, 3})
		cfg := writeConfig(t, "users:\n  - {name: ops-bot, operator: true, keys: ["+qk(t, 2)+"]}\n"+
			"  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: carol, keys: ["+qk(t, 3)+"]}\n"+
			"servers:\n"+hosts["web-1"].line("web-1")+"access:\n  - {user: alice, servers: [web-1]}\n  - {user: carol, servers: [web-1]}\n")
		return hosts["web-1"], kh, cfg
	}
	t.Run("mixed targets without --operator: whole command refused", func(t *testing.T) {
		h, kh, cfg := setup(t)
		before := fileBytes(t, cfg)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "carol", "ops-bot", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 {
			t.Fatalf("exit = %d, want 3", code)
		}
		if !strings.Contains(errBuf.String(), "ops-bot is an operator (fleet-wide, protected); pass --operator to confirm") {
			t.Errorf("stderr = %q", errBuf.String())
		}
		if !bytes.Equal(fileBytes(t, cfg), before) || len(h.srv.Attempts()) != 0 {
			t.Error("a refused revoke edited or connected")
		}
	})
	t.Run("--operator without an operator target", func(t *testing.T) {
		_, kh, cfg := setup(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "carol", "--operator", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 ||
			!strings.Contains(errBuf.String(), "--operator given but no target is an operator; drop the flag") {
			t.Fatalf("exit = %d, stderr %q", code, errBuf.String())
		}
	})
	t.Run("--operator: header and prompt prefix", func(t *testing.T) {
		h, kh, cfg := setup(t)
		var prompt bytes.Buffer
		usePromptStreams(t, strings.NewReader("y\n"), &prompt)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "ops-bot", "--operator", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
		}
		if !strings.Contains(out.String(), "OPERATOR: ops-bot is an operator (fleet-wide, protected); --operator given") {
			t.Errorf("stdout = %s", out.String())
		}
		if !strings.Contains(prompt.String(), "OPERATOR ops-bot: save manifest edit and write 1 of 1 affected servers? [y/N]") {
			t.Errorf("prompt = %q", prompt.String())
		}
		if strings.Contains(h.keys(t), testkeys.Line(t, 2)) {
			t.Error("the operator key is still installed")
		}
	})
	t.Run("--key of an operator's last key clears the flag", func(t *testing.T) {
		_, kh, cfg := setup(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "--key", fpOf(t, 2), "--operator", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if !strings.Contains(out.String(), "note: ops-bot has no keys left, so its operator flag is cleared") {
			t.Errorf("stdout = %s", out.String())
		}
		saved := readCfg(t, cfg)
		if saved.Users[0].Name != "ops-bot" || saved.Users[0].Operator || len(saved.Users[0].Keys) != 0 {
			t.Errorf("ops-bot = %+v, want a keyless non-operator", saved.Users[0])
		}
	})
}

// TestRevokeKeyLeavesUngrantedDrift: bob's key is also installed on web-2,
// which never granted it — revoke --key contacts only web-1, so web-2
// keeps it, and the scope line says so.
func TestRevokeKeyLeavesUngrantedDrift(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	hosts["web-1"].install(t, []byte{1, 2})
	hosts["web-2"].install(t, []byte{1, 2})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: bob, servers: [web-1]}\n")
	pub := filepath.Join(t.TempDir(), "bob.pub")
	if err := os.WriteFile(pub, []byte(testkeys.Line(t, 2)+" bob@laptop\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "--key", pub, "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	for _, want := range []string{
		"manifest edit: remove key " + fpOf(t, 2) + " from bob — 1 server affected\n",
		"note: bob has no keys left — 'sshepherd revoke bob' removes the user\n",
		"scope: only servers whose grants changed were contacted (1 of 2); the removed key may still be installed elsewhere as drift — run 'sshepherd audit' to confirm, 'sshepherd apply' to sweep\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	if len(hosts["web-2"].srv.Attempts()) != 0 || !strings.Contains(hosts["web-2"].keys(t), testkeys.Line(t, 2)) {
		t.Error("web-2 was contacted or changed")
	}
	if strings.Contains(hosts["web-1"].keys(t), testkeys.Line(t, 2)) {
		t.Error("web-1 still holds the revoked key")
	}
}

func TestRevokeUsage(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	cfgBody := "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n  - {name: bob, keys: [" + qk(t, 2) + "]}\n"
	tests := []struct {
		name string
		args []string
		body string
		want string
	}{
		{"no target", []string{"revoke"}, cfgBody, "nothing to revoke"},
		{"users and --key", []string{"revoke", "bob", "--key", fpOf(t, 2)}, cfgBody, "users or --key, not both"},
		{"user that looks like a key", []string{"revoke", fpOf(t, 2)}, cfgBody, "looks like a key — did you mean --key?"},
		{"--dry-run with --yes", []string{"revoke", "bob", "--dry-run", "--yes"}, cfgBody, "dry-run"},
		{"--no-apply with --identity", []string{"revoke", "bob", "--no-apply", "--identity", "/k/id"}, cfgBody, "--no-apply contacts no server, so --identity would be unused"},
		{"--no-apply with --known-hosts", []string{"revoke", "bob", "--no-apply", "--known-hosts", "/x"}, cfgBody, "--known-hosts would be unused"},
		{"--no-apply with --parallel", []string{"revoke", "bob", "--no-apply", "--parallel", "2"}, cfgBody, "--parallel would be unused"},
		{"unknown users listed", []string{"revoke", "carol", "bob", "dave"}, cfgBody, "unknown users: carol, dave"},
		{"key not in the manifest", []string{"revoke", "--key", fpOf(t, 9)}, cfgBody,
			fpOf(t, 9) + " is not in the manifest; apply already removes keys the manifest does not grant — run 'sshepherd audit' to find where it is installed"},
		{"malformed --key", []string{"revoke", "--key", "SHA256:nope"}, cfgBody, "malformed fingerprint"},
		{"anchors cannot be edited", []string{"revoke", "bob"}, "users: &u []\nservers: []\naccess: []\n",
			"cannot edit CFG: manifest contains a YAML anchor or alias (line 1); comment-preserving edits do not support them — edit the manifest by hand and run 'sshepherd apply'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := writeConfig(t, tt.body)
			before := fileBytes(t, cfg)
			var out, errBuf bytes.Buffer
			args := append(append([]string{}, tt.args...), "--config", cfg)
			if code := run(args, &out, &errBuf); code != 3 {
				t.Fatalf("exit = %d, want 3\n%s", code, errBuf.String())
			}
			if want := strings.ReplaceAll(tt.want, "CFG", cfg); !strings.Contains(errBuf.String(), want) {
				t.Errorf("stderr = %q, want %q", errBuf.String(), want)
			}
			if !bytes.Equal(fileBytes(t, cfg), before) {
				t.Error("a usage error changed the manifest")
			}
		})
	}
	t.Run("missing manifest", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--config", filepath.Join(t.TempDir(), "none.yaml")}, &out, &errBuf); code != 3 {
			t.Fatalf("exit = %d, want 3", code)
		}
	})
}
```

- [ ] **Step 2: Run them to verify they fail**

Run:

```bash
go test ./cmd/sshepherd -run TestRevoke
```

Expected: FAIL, output includes:

```text
--- FAIL: TestRevokeUserHermetic (…s)
--- FAIL: TestRevokeAlreadyConverged (…s)
--- FAIL: TestRevokeDryRun (…s)
--- FAIL: TestRevokeDeduplicates (…s)
--- FAIL: TestRevokeDeclined (…s)
--- FAIL: TestRevokeCASConflict (…s)
```

- [ ] **Step 3: Implement**

Create `cmd/sshepherd/revoke.go`:

```go
package main

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/manifest"
)

func newRevokeCmd(a *app, stdout io.Writer) *cobra.Command {
	var (
		f    editFlags
		keys []string
	)
	cmd := &cobra.Command{
		Use:   "revoke {USER... | --key KEY...}",
		Short: "Remove users or keys from the manifest and push the change to the servers it affects",
		Long: "Edits the manifest — comments preserved — and pushes the edit through\n" +
			"apply's pipeline, restricted to the servers whose rendered\n" +
			"authorized_keys changes. 'revoke USER...' removes each user and every\n" +
			"access entry naming them (offboarding); 'revoke --key KEY...' removes\n" +
			"single keys (a lost laptop): KEY is a SHA256: fingerprint, a public-key\n" +
			"line, or a .pub file path. Operator users (and their keys) need\n" +
			"--operator. The plan is shown and confirmed once; the manifest is saved\n" +
			"after confirmation and before the first write, so commit and push it\n" +
			"afterwards. --dry-run changes nothing; --no-apply saves the edit without\n" +
			"contacting any server. A server whose only grantee is revoked is never\n" +
			"emptied: the key stays installed there (a warning says so).",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ids, err := f.validate(cmd)
			if err != nil {
				return err
			}
			users, keyArgs, err := revokeTargets(args, keys)
			if err != nil {
				return err
			}
			m, mf, err := loadForEdit(a.logger, f.run.cfgPath)
			if err != nil {
				return err
			}
			var ep editPlan
			if len(users) > 0 {
				ep, err = planRevokeUsers(mf, users, f.operator)
			} else {
				ep, err = planRevokeKeys(mf, keyArgs, f.operator)
			}
			if err != nil {
				return err
			}
			ep.target = m
			return runEdit(cmd, a, stdout, &f, ids, ep)
		},
	}
	f.register(cmd)
	cmd.Flags().StringArrayVar(&keys, "key", nil,
		"`KEY` to revoke: a SHA256: fingerprint, a public-key line, or a .pub file path (repeatable)")
	return cmd
}

// revokeTargets applies revoke's usage rules and classifies --key
// arguments (step 1): users and keys are exclusive, one is required, a
// user argument that looks like a key is a mistake, and duplicates are
// dropped silently.
func revokeTargets(args, keys []string) ([]string, []keyArg, error) {
	switch {
	case len(args) > 0 && len(keys) > 0:
		return nil, nil, errors.New("revoke takes users or --key, not both")
	case len(args) == 0 && len(keys) == 0:
		return nil, nil, errors.New("nothing to revoke: name the users, or pass --key KEY")
	}
	var users []string
	for _, u := range args {
		if looksLikeKey(u) {
			return nil, nil, fmt.Errorf("%s looks like a key — did you mean --key?", u)
		}
		if !slices.Contains(users, u) {
			users = append(users, u)
		}
	}
	var out []keyArg
	for _, k := range keys {
		ka, err := parseKeyArg(roleKey, k)
		if err != nil {
			return nil, nil, err
		}
		if !slices.ContainsFunc(out, func(o keyArg) bool { return o.Fingerprint == ka.Fingerprint }) {
			out = append(out, ka)
		}
	}
	return users, out, nil
}

// planRevokeUsers resolves and applies 'revoke USER...'.
func planRevokeUsers(mf *manifest.File, users []string, operator bool) (editPlan, error) {
	cfg := mf.Config()
	var unknown []string
	for _, name := range users {
		if !slices.ContainsFunc(cfg.Users, func(u config.User) bool { return u.Name == name }) {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		return editPlan{}, fmt.Errorf("unknown %s: %s", pluralWord(len(unknown), "user", "users"), strings.Join(unknown, ", "))
	}
	ops, err := operatorGate(cfg, users, operator)
	if err != nil {
		return editPlan{}, err
	}
	ep := editPlan{former: cfg, summary: apply.EditSummary{Operators: ops}}
	for _, name := range users {
		r, err := mf.RemoveUser(name)
		if err != nil {
			return editPlan{}, fmt.Errorf("edit manifest: %w", err)
		}
		ep.summary.Edits = append(ep.summary.Edits, apply.Edit{Kind: apply.EditRemoveUser, User: name, Keys: r.Keys, Grants: r.Grants})
		ep.removesKey = ep.removesKey || r.Keys > 0
	}
	ep.stillHas = strings.Join(users, ", ") + " still " + pluralWord(len(users), "has", "have")
	if ep.encoded, ep.edited, err = encodeEdit(mf); err != nil {
		return editPlan{}, err
	}
	return ep, nil
}

// planRevokeKeys resolves and applies 'revoke --key KEY...'. Keys are
// unique across users (config rejects duplicates), so each owner is
// unambiguous. An operator losing its last key loses the flag first
// (operator: true with no keys fails validation).
func planRevokeKeys(mf *manifest.File, keys []keyArg, operator bool) (editPlan, error) {
	cfg := mf.Config()
	var missing []string
	var owners []string
	removing := map[string]int{}
	for _, k := range keys {
		u, ok := cfg.OwnerOf(k.Fingerprint)
		if !ok {
			missing = append(missing, fmt.Sprintf("%s is not in the manifest; apply already removes keys the manifest does not grant — run 'sshepherd audit' to find where it is installed", keyName(k)))
			continue
		}
		if !slices.Contains(owners, u.Name) {
			owners = append(owners, u.Name)
		}
		removing[u.Name]++
	}
	if len(missing) > 0 {
		return editPlan{}, errors.New(strings.Join(missing, "; "))
	}
	ops, err := operatorGate(cfg, owners, operator)
	if err != nil {
		return editPlan{}, err
	}
	cleared := map[string]bool{}
	for _, name := range ops {
		for _, u := range cfg.Users {
			if u.Name == name && removing[name] == len(u.Keys) {
				if err := mf.SetOperator(name, false); err != nil {
					return editPlan{}, fmt.Errorf("edit manifest: %w", err)
				}
				cleared[name] = true
			}
		}
	}
	ep := editPlan{former: cfg, removesKey: true, summary: apply.EditSummary{Operators: ops}}
	for _, k := range keys {
		owner, last, err := mf.RemoveKey(k.Fingerprint)
		if err != nil {
			return editPlan{}, fmt.Errorf("edit manifest: %w", err)
		}
		ep.summary.Edits = append(ep.summary.Edits, apply.Edit{
			Kind: apply.EditRemoveKey, User: owner, Fingerprint: k.Fingerprint,
			NoKeysLeft: last, ClearsOperator: last && cleared[owner],
		})
	}
	ep.stillHas = "the revoked " + pluralWord(len(keys), "key still has", "keys still have")
	if ep.encoded, ep.edited, err = encodeEdit(mf); err != nil {
		return editPlan{}, err
	}
	return ep, nil
}

// pluralWord picks the singular or plural form for n.
func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
```

In `cmd/sshepherd/run.go`, replace:

```go
	root.AddCommand(newApplyCmd(a, stdout))
```

with:

```go
	root.AddCommand(newApplyCmd(a, stdout))
	root.AddCommand(newRevokeCmd(a, stdout))
```

- [ ] **Step 4: Run them**

Run:

```bash
go test -race ./cmd/sshepherd -run TestRevoke -v 2>&1 | grep -E '^--- '
```

Expected: PASS, output includes:

```text
--- PASS: TestRevokeUserHermetic (…s)
--- PASS: TestRevokeAlreadyConverged (…s)
--- PASS: TestRevokeDryRun (…s)
--- PASS: TestRevokeDeduplicates (…s)
--- PASS: TestRevokeDeclined (…s)
--- PASS: TestRevokeCASConflict (…s)
```

- [ ] **Commit**

```bash
git add cmd/sshepherd/revoke.go cmd/sshepherd/revoke_test.go cmd/sshepherd/run.go
git commit -m "$(cat <<'EOF'
feat: sshepherd revoke (users or keys), saved once and applied to affected servers

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

### Task C2.3: `sshepherd rotate` [Group C2]

**Files:**
- Create: `cmd/sshepherd/rotate.go`
- Modify: `cmd/sshepherd/run.go`
- Create: `cmd/sshepherd/rotate_test.go`

Resolution order against the as-loaded config, all exit 3 before any edit: unknown user; `--old` not in the manifest / owned by someone else (named); `--new` equal to `--old`; `--new` already owned (named); operator gate; a passed carried-over `expiry-time=` (at the run's start — `rotateNow` seam). The new line is `authkeys.RenderLine` of the new key material with the **old line's options** and comment = new key's, else the old inline comment; `ReplaceKey` keeps the index and the slot's comments; `operator: true` is untouched. `formerNote` is `rotated out`.

- [ ] **Step 1: Write the failing tests**

Create `cmd/sshepherd/rotate_test.go`:

```go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// writePub writes a .pub file holding line and returns its path.
func writePub(t *testing.T, name, line string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRotateOwnKeyWithNewIdentity: alice rotates the key the agent logs in
// with; the new private key is passed with --identity so the guard and
// the post-write probe can use it. The old line's options and inline
// comment carry over (the new .pub has no comment).
func TestRotateOwnKeyWithNewIdentity(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1, 5}, "web-1")
	h := hosts["web-1"]
	h.install(t, nil, "no-pty "+testkeys.Line(t, 1)+" alice@old")
	cfg := writeConfig(t, "users:\n  - name: alice\n    keys:\n      # alice's laptop\n      - 'no-pty "+testkeys.Line(t, 1)+" alice@old'\n"+
		"servers:\n"+h.line("web-1")+"access:\n  - {user: alice, servers: [web-1]}\n")
	newKey := sshtest.WriteKeyFile(t, t.TempDir(), "id_new", sshtest.Key(5), nil)
	var out, errBuf bytes.Buffer
	code := run([]string{"rotate", "alice", "--old", fpOf(t, 1), "--new", newKey + ".pub", "--yes",
		"--config", cfg, "--known-hosts", kh, "--identity", newKey}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	for _, want := range []string{
		"manifest edit: rotate alice key " + fpOf(t, 1) + " → " + fpOf(t, 5) + " — 1 server affected\n",
		"alice (rotated out)",
		"removes the key this session logged in with",
		"web-1: applied · verified",
		"scope: only servers whose grants changed were contacted (1 of 1)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	wantLine := "no-pty " + testkeys.Line(t, 5) + " alice@old"
	if got := readCfg(t, cfg).Users[0].Keys; len(got) != 1 || got[0] != wantLine {
		t.Errorf("manifest keys = %q, want [%q]", got, wantLine)
	}
	if !strings.Contains(string(fileBytes(t, cfg)), "# alice's laptop") {
		t.Error("the key's head comment was lost")
	}
	if got := h.keys(t); !strings.Contains(got, wantLine) || strings.Contains(got, testkeys.Line(t, 1)) {
		t.Errorf("authorized_keys = %q, want only the new key", got)
	}
}

// TestRotateCommentRule: the new key's comment wins; without one, the old
// line's inline comment; operator: true is kept.
func TestRotateCommentRule(t *testing.T) {
	body := "users:\n  - {name: ops, operator: true, keys: ['" + testkeys.Line(t, 1) + " ops@old']}\n"
	for _, tt := range []struct {
		name, newLine, want string
	}{
		{"new comment wins", testkeys.Line(t, 5) + " ops@new", testkeys.Line(t, 5) + " ops@new"},
		{"old comment kept", testkeys.Line(t, 5), testkeys.Line(t, 5) + " ops@old"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := writeConfig(t, body)
			var out, errBuf bytes.Buffer
			code := run([]string{"rotate", "ops", "--old", fpOf(t, 1), "--new", writePub(t, "n.pub", tt.newLine),
				"--operator", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf)
			if code != 0 {
				t.Fatalf("exit = %d\n%s", code, errBuf.String())
			}
			u := readCfg(t, cfg).Users[0]
			if !u.Operator || len(u.Keys) != 1 || u.Keys[0] != tt.want {
				t.Errorf("ops = %+v, want operator with [%q]", u, tt.want)
			}
			if !strings.Contains(out.String(), "OPERATOR: ops is an operator") || !strings.Contains(out.String(), "no servers contacted — no server's desired keys changed") {
				t.Errorf("stdout = %s", out.String())
			}
		})
	}
}

// TestRotateKeepsExpiry: a future expiry-time= carries over and is named
// in the header; a passed one refuses before any edit.
func TestRotateKeepsExpiry(t *testing.T) {
	saved := rotateNow
	rotateNow = func() time.Time { return time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { rotateNow = saved })
	mk := func(expiry string) string {
		return writeConfig(t, "users:\n  - {name: deploy, keys: ['expiry-time=\""+expiry+"\" "+testkeys.Line(t, 1)+"']}\n")
	}
	newPub := writePub(t, "n.pub", testkeys.Line(t, 5))

	cfg := mk("20990101")
	var out, errBuf bytes.Buffer
	if code := run([]string{"rotate", "deploy", "--old", fpOf(t, 1), "--new", newPub, "--no-apply", "--dry-run", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `(keeps expiry-time="20990101") — no servers affected`) {
		t.Errorf("stdout = %s", out.String())
	}

	cfg = mk("20200101")
	before := fileBytes(t, cfg)
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"rotate", "deploy", "--old", fpOf(t, 1), "--new", newPub, "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	if !strings.Contains(errBuf.String(), `the old line's expiry-time="20200101" has passed; the new key would be rejected by sshd — update or remove expiry-time in the manifest first`) {
		t.Errorf("stderr = %q", errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("a refused rotation edited the manifest")
	}
}

func TestRotateRefusals(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	body := "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n  - {name: bob, keys: [" + qk(t, 2) + "]}\n" +
		"  - {name: ops, operator: true, keys: [" + qk(t, 3) + "]}\n"
	newPub := writePub(t, "n.pub", testkeys.Line(t, 5))
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no USER", []string{"rotate", "--old", fpOf(t, 1), "--new", newPub}, "rotate takes exactly one USER (got 0)"},
		{"two USERs", []string{"rotate", "alice", "bob", "--old", fpOf(t, 1), "--new", newPub}, "rotate takes exactly one USER (got 2)"},
		{"missing --new", []string{"rotate", "alice", "--old", fpOf(t, 1)}, "rotate needs both --old KEY and --new KEY"},
		{"--new as a fingerprint", []string{"rotate", "alice", "--old", fpOf(t, 1), "--new", fpOf(t, 5)}, "a fingerprint carries no key"},
		{"options on --new", []string{"rotate", "alice", "--old", fpOf(t, 1), "--new", "restrict " + testkeys.Line(t, 5)}, "rotate keeps the old line's options; edit them in the manifest"},
		{"unknown user", []string{"rotate", "carol", "--old", fpOf(t, 1), "--new", newPub}, "unknown user: carol"},
		{"--old owned by someone else", []string{"rotate", "alice", "--old", fpOf(t, 2), "--new", newPub}, "--old " + fpOf(t, 2) + " belongs to bob, not alice"},
		{"--old not in the manifest", []string{"rotate", "alice", "--old", fpOf(t, 9), "--new", newPub}, "--old " + fpOf(t, 9) + " is not in the manifest"},
		{"--new already owned", []string{"rotate", "alice", "--old", fpOf(t, 1), "--new", testkeys.Line(t, 2)}, "is already in the manifest (owned by bob)"},
		{"--new same as --old", []string{"rotate", "alice", "--old", fpOf(t, 1), "--new", testkeys.Line(t, 1)}, "--new is the same key as --old"},
		{"operator without --operator", []string{"rotate", "ops", "--old", fpOf(t, 3), "--new", newPub}, "ops is an operator (fleet-wide, protected); pass --operator to confirm"},
		{"--operator on a non-operator", []string{"rotate", "alice", "--old", fpOf(t, 1), "--new", newPub, "--operator"}, "--operator given but no target is an operator"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := writeConfig(t, body)
			var out, errBuf bytes.Buffer
			args := append(append([]string{}, tt.args...), "--no-apply", "--yes", "--config", cfg)
			if code := run(args, &out, &errBuf); code != 3 {
				t.Fatalf("exit = %d, want 3\n%s", code, errBuf.String())
			}
			if !strings.Contains(errBuf.String(), tt.want) {
				t.Errorf("stderr = %q, want %q", errBuf.String(), tt.want)
			}
			if !bytes.Equal(fileBytes(t, cfg), []byte(body)) {
				t.Error("a refused rotation edited the manifest")
			}
		})
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run:

```bash
go test ./cmd/sshepherd -run TestRotate
```

Expected: FAIL, output includes:

```text
FAIL	github.com/javadh75/SSHepherd/cmd/sshepherd [build failed]
FAIL
cmd/sshepherd/rotate_test.go:97:11: undefined: rotateNow
cmd/sshepherd/rotate_test.go:98:2: undefined: rotateNow
cmd/sshepherd/rotate_test.go:99:21: undefined: rotateNow
```

- [ ] **Step 3: Implement**

Create `cmd/sshepherd/rotate.go`:

```go
package main

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/manifest"
)

// rotateNow is the clock the expiry-time check reads (a test seam).
var rotateNow = time.Now

func newRotateCmd(a *app, stdout io.Writer) *cobra.Command {
	var (
		f       editFlags
		oldFlag string
		newFlag string
	)
	cmd := &cobra.Command{
		Use:   "rotate USER --old KEY --new KEY",
		Short: "Replace one of a user's keys in the manifest and push the swap to the servers it affects",
		Long: "Replaces USER's --old key with --new in the manifest, in place — the old\n" +
			"line's options (from=, command=, restrict, …) carry over; the comment is\n" +
			"the new key's, else the old line's — and pushes the swap through\n" +
			"apply's pipeline on the servers that grant USER. The old key is dead\n" +
			"fleet-wide in the same run. --old is a SHA256: fingerprint, a public-key\n" +
			"line, or a .pub path; --new is a public-key line or a .pub path. Rotating\n" +
			"the key you log in with? Pass the new private key with --identity, so the\n" +
			"lockout guard and the post-write login probe can use it. Operators need\n" +
			"--operator (the flag is kept). Saves and confirms like revoke.",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("rotate takes exactly one USER (got %d)", len(args))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ids, err := f.validate(cmd)
			if err != nil {
				return err
			}
			if oldFlag == "" || newFlag == "" {
				return errors.New("rotate needs both --old KEY and --new KEY")
			}
			oldArg, err := parseKeyArg(roleOld, oldFlag)
			if err != nil {
				return err
			}
			newArg, err := parseKeyArg(roleNew, newFlag)
			if err != nil {
				return err
			}
			m, mf, err := loadForEdit(a.logger, f.run.cfgPath)
			if err != nil {
				return err
			}
			ep, err := planRotate(mf, args[0], oldArg, newArg, f.operator, rotateNow())
			if err != nil {
				return err
			}
			ep.target = m
			return runEdit(cmd, a, stdout, &f, ids, ep)
		},
	}
	f.register(cmd)
	cmd.Flags().StringVar(&oldFlag, "old", "", "the `KEY` to rotate out: a SHA256: fingerprint, a public-key line, or a .pub file path")
	cmd.Flags().StringVar(&newFlag, "new", "", "the `KEY` to rotate in: a public-key line or a .pub file path")
	return cmd
}

// planRotate resolves and applies 'rotate USER --old --new' against the
// as-loaded config: ownership, novelty, operator and expiry checks, then
// the one in-place replacement.
func planRotate(mf *manifest.File, user string, oldArg, newArg keyArg, operator bool, now time.Time) (editPlan, error) {
	cfg := mf.Config()
	var u *config.User
	for i := range cfg.Users {
		if cfg.Users[i].Name == user {
			u = &cfg.Users[i]
		}
	}
	if u == nil {
		return editPlan{}, fmt.Errorf("unknown user: %s", user)
	}
	owner, ok := cfg.OwnerOf(oldArg.Fingerprint)
	switch {
	case !ok:
		return editPlan{}, fmt.Errorf("--old %s is not in the manifest", keyName(oldArg))
	case owner.Name != user:
		return editPlan{}, fmt.Errorf("--old %s belongs to %s, not %s", keyName(oldArg), owner.Name, user)
	case newArg.Fingerprint == oldArg.Fingerprint:
		return editPlan{}, errors.New("--new is the same key as --old")
	}
	if o, taken := cfg.OwnerOf(newArg.Fingerprint); taken {
		return editPlan{}, fmt.Errorf("--new %s is already in the manifest (owned by %s)", keyName(newArg), o.Name)
	}
	ops, err := operatorGate(cfg, []string{user}, operator)
	if err != nil {
		return editPlan{}, err
	}
	line, expiry, err := rotatedLine(*u, oldArg, newArg, now)
	if err != nil {
		return editPlan{}, err
	}
	if err := mf.ReplaceKey(user, oldArg.Fingerprint, line); err != nil {
		return editPlan{}, fmt.Errorf("edit manifest: %w", err)
	}
	ep := editPlan{
		former: cfg, formerNote: "rotated out", removesKey: true,
		stillHas: user + "'s old key still has",
		summary: apply.EditSummary{Operators: ops, Edits: []apply.Edit{{
			Kind: apply.EditRotate, User: user, Fingerprint: oldArg.Fingerprint,
			NewFingerprint: newArg.Fingerprint, KeepsExpiry: expiry,
		}}},
	}
	if ep.encoded, ep.edited, err = encodeEdit(mf); err != nil {
		return editPlan{}, err
	}
	return ep, nil
}

// rotatedLine composes the replacement manifest line: the new key with
// the old line's options and the comment rule (the new key's comment, else
// the old line's). A carried-over expiry-time= that has passed at now is
// refused; the option is returned for the header ("" when none).
func rotatedLine(u config.User, oldArg, newArg keyArg, now time.Time) (line, expiry string, err error) {
	oldKey, err := manifestKey(u, oldArg.Fingerprint)
	if err != nil {
		return "", "", err
	}
	expiry = expiryOption(oldKey.Options)
	if expiry != "" {
		passed, err := expiryPassed(expiry, now)
		if err != nil {
			return "", "", fmt.Errorf("--old %s: %w", keyName(oldArg), err)
		}
		if passed {
			return "", "", fmt.Errorf("the old line's %s has passed; the new key would be rejected by sshd — update or remove expiry-time in the manifest first", expiry)
		}
	}
	comment := newArg.Key.Comment
	if comment == "" {
		comment = oldKey.Comment
	}
	if issue := authkeys.RenderTextIssue(comment); issue != "" {
		return "", "", fmt.Errorf("--new %s: the key's comment %s", keyName(newArg), issue)
	}
	line, err = authkeys.RenderLine(authkeys.RenderEntry{
		Key:     authkeys.Key{Raw: newArg.Key.Raw, Options: oldKey.Options, Fingerprint: newArg.Fingerprint},
		Comment: comment,
	})
	if err != nil {
		return "", "", fmt.Errorf("--new %s: %w", keyName(newArg), err)
	}
	return line, expiry, nil
}

// manifestKey parses u's manifest line for fingerprint fp.
func manifestKey(u config.User, fp string) (authkeys.Key, error) {
	for _, line := range u.Keys {
		if k, err := authkeys.ParseLine(line); err == nil && k != nil && k.Fingerprint == fp {
			return *k, nil
		}
	}
	return authkeys.Key{}, fmt.Errorf("bug: %s's key %s not found in the manifest", u.Name, fp)
}
```

In `cmd/sshepherd/run.go`, replace:

```go
	root.AddCommand(newRevokeCmd(a, stdout))
```

with:

```go
	root.AddCommand(newRevokeCmd(a, stdout))
	root.AddCommand(newRotateCmd(a, stdout))
```

- [ ] **Step 4: Run them**

Run:

```bash
go test -race ./cmd/sshepherd -run TestRotate -v 2>&1 | grep -E '^--- '
```

Expected: PASS, output includes:

```text
--- PASS: TestRotateOwnKeyWithNewIdentity (…s)
--- PASS: TestRotateCommentRule (…s)
--- PASS: TestRotateKeepsExpiry (…s)
--- PASS: TestRotateRefusals (…s)
```

- [ ] **Commit**

```bash
git add cmd/sshepherd/rotate.go cmd/sshepherd/rotate_test.go cmd/sshepherd/run.go
git commit -m "$(cat <<'EOF'
feat: sshepherd rotate swaps a key in place and applies it

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

### Task C2.4: `FuzzKeyArg`, seeds, and both `make fuzz` targets [Group C2]

**Files:**
- Create: `cmd/sshepherd/keyarg_fuzz_test.go`
- Create: `cmd/sshepherd/testdata/fuzz/FuzzKeyArg/seed-cert-file`, `.../seed-two-lines`
- Modify: `Makefile`

Property: classification never panics for any argument and role, never succeeds without a fingerprint, and a `.pub` file's error is always one of five fixed texts (digits normalized) — so no byte of the file can be echoed.

- [ ] **Step 1: Write the fuzz target and seeds**

Create `cmd/sshepherd/keyarg_fuzz_test.go`:

```go
package main

import (
	"regexp"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// fuzzPubPath is the fixed path FuzzKeyArg reads fuzzed contents from.
const fuzzPubPath = "/k/id.pub"

// keyFileErrors are the only error texts a .pub read may produce, digits
// normalized to N: each names the argument and nothing else — no byte of
// the file can reach an error.
var keyFileErrors = map[string]bool{
	"--key /k/id.pub: larger than N KiB — not a public key file":                                                     true,
	"--key /k/id.pub is a private key — pass the public key (/k/id.pub.pub)":                                         true,
	"--key /k/id.pub: holds N key lines — want exactly one":                                                          true,
	"--key /k/id.pub is an SSH certificate, not a public key — pass the plain key (id_edN.pub, not id_edN-cert.pub)": true,
	"--key /k/id.pub: does not hold a valid public key line":                                                         true,
}

var digits = regexp.MustCompile(`[0-9]+`)

// FuzzKeyArg: KEY classification never panics on any argument, for any
// role, and a .pub file's error never echoes its contents.
func FuzzKeyArg(f *testing.F) {
	line := testkeys.Line(f, 1)
	f.Add("SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8", []byte(line+"\n"))
	f.Add("256 SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8 me (ED25519)", []byte("# c\n"+line+" me\n"))
	f.Add("MD5:aa:bb", []byte(line+"\n"+line+"\n"))
	f.Add(line+" me@x", []byte("-----BEGIN OPENSSH "+"PRIVATE KEY-----\nc2VjcmV0\n"))
	f.Add("restrict "+line, []byte("PuTTY-User-Key-File-3: ssh-ed25519\n"))
	f.Add("~/.ssh/id.pub", []byte("ssh-ed25519-cert-v01@openssh.com AAAA x\n"))
	f.Add("aa:bb:cc", []byte("ssh-ed25519 !!!\n"))
	f.Fuzz(func(t *testing.T, arg string, content []byte) {
		read := func(string) ([]byte, error) { return content, nil }
		for _, role := range []keyRole{roleKey, roleOld, roleNew} {
			got, err := classifyKeyArg(role, arg, "/home/u", read)
			if err == nil && got.Fingerprint == "" {
				t.Fatalf("classifyKeyArg(%s, %q) succeeded without a fingerprint", role, arg)
			}
			_ = looksLikeKey(arg)
		}
		_, err := classifyKeyArg(roleKey, fuzzPubPath, "/home/u", read)
		if err == nil {
			return
		}
		if msg := digits.ReplaceAllString(err.Error(), "N"); !keyFileErrors[msg] {
			t.Fatalf("unexpected .pub error (may echo file content): %q\ncontent: %q", err.Error(), content)
		}
	})
}
```

Create `cmd/sshepherd/testdata/fuzz/FuzzKeyArg/seed-cert-file`:

```
go test fuzz v1
string("--key")
[]byte("# a certificate, not a key\nssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29t id-cert\n")
```

Create `cmd/sshepherd/testdata/fuzz/FuzzKeyArg/seed-two-lines`:

```
go test fuzz v1
string("~/.ssh/id_ed25519.pub")
[]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIqI4910CfGV/VLbLTy6XXLKZwm/HZQSG/N0iAG0D29c a\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOU b\n")
```

In `Makefile`, replace:

```makefile
	$(GO) test -run='^$$' -fuzz=FuzzMergeRoundTrip -fuzztime=15s ./internal/manifest
```

with:

```makefile
	$(GO) test -run='^$$' -fuzz=FuzzMergeRoundTrip -fuzztime=15s ./internal/manifest
	$(GO) test -run='^$$' -fuzz=FuzzManifestEdit -fuzztime=15s ./internal/manifest
	$(GO) test -run='^$$' -fuzz=FuzzKeyArg -fuzztime=15s ./cmd/sshepherd
```

- [ ] **Step 2: Run the seeds and fuzz briefly**

Run:

```bash
go test ./cmd/sshepherd -run FuzzKeyArg
```

Expected: PASS, output includes:

```text
ok  	github.com/javadh75/SSHepherd/cmd/sshepherd	(…s)
```

Run:

```bash
go test ./cmd/sshepherd -run '^$' -fuzz=FuzzKeyArg -fuzztime=20s
```

Expected: PASS, output includes:

```text
PASS
ok  	github.com/javadh75/SSHepherd/cmd/sshepherd	(…s)
```

- [ ] **Commit**

```bash
git add cmd/sshepherd/keyarg_fuzz_test.go cmd/sshepherd/testdata/fuzz/FuzzKeyArg Makefile
git commit -m "$(cat <<'EOF'
test(cmd): FuzzKeyArg; make fuzz runs both new targets

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

### Task C2.5: Integration and E2E — adopt → apply → revoke --key → audit → rotate → audit; headless rotate [Group C2]

**Files:**
- Modify: `scripts/integration.sh` (container user `rotatecmd`, seeded with `ci_old.pub`)
- Modify: `cmd/sshepherd/e2e_test.go` (the loop)
- Modify: `cmd/sshepherd/identity_integration_test.go` (headless `rotate`)

The loop revokes the stale key by its `.pub` (`$SSHEPHERD_IT_KEYS/stale.pub`), audits clean, keeps the lockout-guard check, then rotates the operator's agent key to the key file `ci_old` (passed with `--identity`, so the guard and probe can use it) and audits clean with `--identity`. The headless test rotates `ci_old` → `ci_new` (encrypted, passphrase file) with no agent at all.

- [ ] **Step 1: Add the container user**

In `scripts/integration.sh`, replace:

```bash
    for u in writer virgin sym e2e cas locked verifyfail drop lockout unparse idaudit idenc rotate e2eh; do
      adduser
```

with:

```bash
    for u in writer virgin sym e2e cas locked verifyfail drop lockout unparse idaudit idenc rotate e2eh rotatecmd; do
      adduser
```

In `scripts/integration.sh`, replace:

```bash
    cp /seed/ci_old.pub /home/rotate/.ssh/authorized_keys
```

with:

```bash
    cp /seed/ci_old.pub /home/rotate/.ssh/authorized_keys
    cp /seed/ci_old.pub /home/rotatecmd/.ssh/authorized_keys
```

In `scripts/integration.sh`, replace:

```bash
    for u in writer virgin sym e2e cas locked verifyfail drop lockout unparse idaudit idenc rotate e2eh; do
      chown
```

with:

```bash
    for u in writer virgin sym e2e cas locked verifyfail drop lockout unparse idaudit idenc rotate e2eh rotatecmd; do
      chown
```

- [ ] **Step 2: Rewrite the E2E loop**

In `cmd/sshepherd/e2e_test.go`, replace:

```go
// TestE2EApplyLoop drives the built binary through the spec's full write
// loop against the docker fleet: adopt → apply --yes (first write,
// normalizes everything) → apply --dry-run (no-op, byte-stable) → revoke by
// manifest edit → apply --dry-run (plan) → apply --yes → audit exits 0 —
// then the lockout guard trips on a manifest holding none of the agent's
// keys, and a final audit proves the file was untouched. Ordered subtests:
// each stage's on-server state is the next stage's input.
func TestE2EApplyLoop(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	dir := t.TempDir()
```

with:

```go
// TestE2EApplyLoop drives the built binary through the testing policy's
// distribute → audit → revoke → rotate flow against the docker fleet:
// adopt → apply --yes (first write, normalizes everything) → apply
// --dry-run (no-op, byte-stable) → revoke --key --dry-run (plan, manifest
// untouched) → revoke --key --yes → audit exits 0 → the lockout guard trips
// on a manifest holding none of the agent's keys (file untouched) → rotate
// the operator's agent key to a key-file key → audit exits 0. Ordered
// subtests: each stage's on-server state is the next stage's input.
func TestE2EApplyLoop(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	keys := itKeys(t)
	dir := t.TempDir()
```

In `cmd/sshepherd/e2e_test.go`, replace:

```go
	t.Run("revoking the stale grant plans a remove", func(t *testing.T) {
		code, out, _ := runBin(t, bin, "apply", "--dry-run", "--config", m0, "--known-hosts", kh)
		if code != 1 {
			t.Fatalf("dry-run exit = %d, want 1 (pending change)\n%s", code, out)
		}
		if !strings.Contains(out, "remove (unauthorized)") {
			t.Errorf("plan lacks the remove row:\n%s", out)
		}
	})

	t.Run("apply the revoke and audit clean", func(t *testing.T) {
		if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", m0, "--known-hosts", kh); code != 0 {
			t.Fatalf("apply exit = %d (stderr: %s)\n%s", code, stderr, out)
		}
		if code, out, stderr := runBin(t, bin, "audit", "--config", m0, "--known-hosts", kh); code != 0 {
			t.Fatalf("audit exit = %d, want 0 — the distribute→audit loop must close (stderr: %s)\n%s", code, stderr, out)
		}
	})

```

with:

```go
	stalePub := filepath.Join(keys, "stale.pub")

	t.Run("revoke --key --dry-run plans the remove and saves nothing", func(t *testing.T) {
		before, err := os.ReadFile(adopted)
		if err != nil {
			t.Fatal(err)
		}
		code, out, stderr := runBin(t, bin, "revoke", "--key", stalePub, "--dry-run", "--config", adopted, "--known-hosts", kh)
		if code != 1 {
			t.Fatalf("dry-run exit = %d, want 1 (pending change) (stderr: %s)\n%s", code, stderr, out)
		}
		for _, want := range []string{"manifest edit: remove key ", "(revoked)", "remove (unauthorized)"} {
			if !strings.Contains(out, want) {
				t.Errorf("plan lacks %q:\n%s", want, out)
			}
		}
		if after, _ := os.ReadFile(adopted); string(after) != string(before) {
			t.Error("--dry-run changed the manifest")
		}
	})

	t.Run("revoke --key saves the manifest and converges", func(t *testing.T) {
		code, out, stderr := runBin(t, bin, "revoke", "--key", stalePub, "--yes", "--config", adopted, "--known-hosts", kh)
		if code != 0 {
			t.Fatalf("revoke exit = %d (stderr: %s)\n%s", code, stderr, out)
		}
		for _, want := range []string{"has no keys left", "updated — commit and push it", "applied · verified", "scope: only servers whose grants changed were contacted (1 of 1)"} {
			if !strings.Contains(out, want) {
				t.Errorf("revoke output lacks %q:\n%s", want, out)
			}
		}
	})

	t.Run("audit is clean after the revoke", func(t *testing.T) {
		if code, out, stderr := runBin(t, bin, "audit", "--config", adopted, "--known-hosts", kh); code != 0 {
			t.Fatalf("audit exit = %d, want 0 — the revoke loop must close (stderr: %s)\n%s", code, stderr, out)
		}
		if code, out, stderr := runBin(t, bin, "audit", "--config", m0, "--known-hosts", kh); code != 0 {
			t.Fatalf("audit (m0) exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
		}
	})

```

In `cmd/sshepherd/e2e_test.go`, replace:

```go
		// The file is untouched: the m0 audit still passes byte-for-byte.
		if code, out, stderr := runBin(t, bin, "audit", "--config", m0, "--known-hosts", kh); code != 0 {
			t.Fatalf("post-refusal audit exit = %d, want 0 (the refused write must not have touched the file) (stderr: %s)\n%s", code, stderr, out)
		}
	})
}

```

with:

```go
		// The file is untouched: the m0 audit still passes byte-for-byte.
		if code, out, stderr := runBin(t, bin, "audit", "--config", m0, "--known-hosts", kh); code != 0 {
			t.Fatalf("post-refusal audit exit = %d, want 0 (the refused write must not have touched the file) (stderr: %s)\n%s", code, stderr, out)
		}
	})

	ciOld := filepath.Join(keys, "ci_old")

	t.Run("rotate swaps the operator key for a key-file key", func(t *testing.T) {
		code, out, stderr := runBin(t, bin, "rotate", "op", "--old", os.Getenv("SSHEPHERD_IT_PUB"), "--new", ciOld+".pub",
			"--operator", "--yes", "--config", adopted, "--known-hosts", kh, "--identity", ciOld)
		if code != 0 {
			t.Fatalf("rotate exit = %d (stderr: %s)\n%s", code, stderr, out)
		}
		for _, want := range []string{"OPERATOR: op is an operator", "op (rotated out)", "removes the key this session logged in with", "applied · verified"} {
			if !strings.Contains(out, want) {
				t.Errorf("rotate output lacks %q:\n%s", want, out)
			}
		}
		b, err := os.ReadFile(adopted)
		if err != nil || !strings.Contains(string(b), strings.Fields(itPubLine(t, keys, "ci_old"))[1]) ||
			strings.Contains(string(b), strings.Fields(pub)[1]) {
			t.Errorf("manifest after rotate must hold ci_old and not the agent key (%v):\n%s", err, b)
		}
	})

	t.Run("audit is clean after the rotation", func(t *testing.T) {
		if code, out, stderr := runBin(t, bin, "audit", "--config", adopted, "--known-hosts", kh, "--identity", ciOld); code != 0 {
			t.Fatalf("audit exit = %d, want 0 — the rotate loop must close (stderr: %s)\n%s", code, stderr, out)
		}
	})
}

```

- [ ] **Step 3: Add the headless rotate test**

Append to the end of `cmd/sshepherd/identity_integration_test.go`:

```go

// TestIntegrationHeadlessRotateCommand: 'rotate' with no agent — the old
// key logs in, the new key (encrypted, passphrase file) survives the guard
// and is what the post-write probe proves; the manifest now holds the new
// key and a headless audit with only the new key is clean.
func TestIntegrationHeadlessRotateCommand(t *testing.T) {
	bin, host, port, kh, _ := itE2E(t)
	keys := itKeys(t)
	m := writeE2EManifest(t, t.TempDir(), "m.yaml", `
users:
  - {name: ci, operator: true, keys: ["`+itPubLine(t, keys, "ci_old")+`"]}
servers:
  - {name: rotatecmd, host: `+host+`, port: `+port+`, user: rotatecmd}
`)
	ciOld, ciNew := filepath.Join(keys, "ci_old"), filepath.Join(keys, "ci_new")
	code, out, stderr := runHeadless(t, bin, "rotate", "ci", "--old", ciOld+".pub", "--new", ciNew+".pub",
		"--operator", "--yes", "--config", m, "--known-hosts", kh,
		"--identity", ciOld, "--identity", ciNew, "--identity-passphrase", ciNew+"="+ciNew+".pass")
	if code != 0 || !strings.Contains(out, "applied · verified") {
		t.Fatalf("headless rotate exit = %d, want 0 + applied (stderr: %s)\n%s", code, stderr, out)
	}
	b, err := os.ReadFile(m)
	if err != nil {
		t.Fatal(err)
	}
	newFields := strings.Fields(itPubLine(t, keys, "ci_new"))
	if !strings.Contains(string(b), newFields[1]) || strings.Contains(string(b), strings.Fields(itPubLine(t, keys, "ci_old"))[1]) {
		t.Errorf("manifest does not hold exactly the new key:\n%s", b)
	}
	if code, out, stderr := runHeadless(t, bin, "audit", "--config", m, "--known-hosts", kh,
		"--identity", ciNew, "--identity-passphrase", ciNew+"="+ciNew+".pass"); code != 0 {
		t.Fatalf("headless audit with the new key exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}
}
```

- [ ] **Step 4: Compile with the tag, then run the suite (Docker)**

Run:

```bash
go vet -tags=integration ./cmd/sshepherd
```

Expected: PASS

Run: `make integration`

Expected (verified run; `apk add` needs network — retry on a transient DNS error):

```text
--- PASS: TestE2EApplyLoop
    --- PASS: TestE2EApplyLoop/adopt_discovers_the_stale_key
    --- PASS: TestE2EApplyLoop/first_apply_normalizes_and_verifies
    --- PASS: TestE2EApplyLoop/re-apply_is_a_byte-stable_no-op
    --- PASS: TestE2EApplyLoop/revoke_--key_--dry-run_plans_the_remove_and_saves_nothing
    --- PASS: TestE2EApplyLoop/revoke_--key_saves_the_manifest_and_converges
    --- PASS: TestE2EApplyLoop/audit_is_clean_after_the_revoke
    --- PASS: TestE2EApplyLoop/lockout_guard_refuses_and_leaves_the_file_alone
    --- PASS: TestE2EApplyLoop/rotate_swaps_the_operator_key_for_a_key-file_key
    --- PASS: TestE2EApplyLoop/audit_is_clean_after_the_rotation
--- PASS: TestIntegrationHeadlessRotateCommand
ok  	github.com/javadh75/SSHepherd/cmd/sshepherd
```

- [ ] **Commit**

```bash
git add scripts/integration.sh cmd/sshepherd/e2e_test.go cmd/sshepherd/identity_integration_test.go
git commit -m "$(cat <<'EOF'
test: E2E adopt → apply → revoke → audit → rotate → audit; headless rotate

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

### Task C2.6: README, help tables, Status, spec cross-references [Group C2]

**Files:**
- Modify: `cmd/sshepherd/help_readme_test.go` (command lists)
- Modify: `README.md`
- Modify: `CLAUDE.md` (Status)
- Modify: `docs/superpowers/specs/2026-10-23-revoke-rotate-design.md`, `2026-07-19-apply-slice-design.md`, `2026-07-10-operator-users-wildcard-access-design.md`, `2026-07-16-adopt-merge-design.md` (status / Amended-by lines)

README samples below are copied from the goldens created in Group A (`edit_header_*.golden`, `edit_prompt.golden`) and the regenerated `plan_*` goldens — never hand-edited. The flag tables list exactly what `--help` prints (pinned by `TestHelpMatchesREADMETables`).

- [ ] **Step 1: Extend the help/README tests (they fail until the README has the sections)**

In `cmd/sshepherd/help_readme_test.go`, replace:

```go
// TestHelpMatchesREADMETables: every local flag of audit/adopt/apply
```

with:

```go
// TestHelpMatchesREADMETables: every local flag of audit/adopt/apply/revoke/rotate
```

In `cmd/sshepherd/help_readme_test.go`, replace:

```go
	for _, name := range []string{"audit", "adopt", "apply"} {
		t.Run(name
```

with:

```go
	for _, name := range []string{"audit", "adopt", "apply", "revoke", "rotate"} {
		t.Run(name
```

In `cmd/sshepherd/help_readme_test.go`, replace:

```go
	for _, name := range []string{"audit", "adopt", "apply"} {
		var out, errBuf bytes.Buffer
```

with:

```go
	for _, name := range []string{"audit", "adopt", "apply", "revoke", "rotate"} {
		var out, errBuf bytes.Buffer
```

Run:

```bash
go test ./cmd/sshepherd -run TestHelpMatchesREADMETables
```

Expected: FAIL, output includes:

```text
--- FAIL: TestHelpMatchesREADMETables (…s)
    --- FAIL: TestHelpMatchesREADMETables/revoke (…s)
        help_readme_test.go:77: README has no `sshepherd revoke` section
    --- FAIL: TestHelpMatchesREADMETables/rotate (…s)
        help_readme_test.go:77: README has no `sshepherd rotate` section
```

- [ ] **Step 2: Update the README**

In `README.md`, replace:

```markdown
REFUSED: 1 keys installed but manifest grants none
```

with:

```markdown
REFUSED: 1 key installed but manifest grants none
```

In `README.md`, replace:

```markdown
normalize: removing 1 non-key lines (comments/blank)
```

with:

```markdown
normalize: removing 1 non-key line (comments/blank)
```

In `README.md`, replace:

```markdown
normalize: removing 1 duplicate key lines (some carry
```

with:

```markdown
normalize: removing 1 duplicate key line (some carry
```

In `README.md`, replace:

```markdown
  → 1 keys desired · 1 add · 0 remove · 0 rewrite
```

with:

```markdown
  → 1 key desired · 1 add · 0 remove · 0 rewrite
```

In `README.md`, replace:

```markdown
- **Revoke / rotate** — edit the manifest, run `apply`. That's the whole workflow.
```

with:

```markdown
- **Revoke / rotate** — `sshepherd revoke alice` or `sshepherd rotate alice --old … --new …`
  edits the manifest (comments kept) and pushes the change to exactly the servers it
  affects, through `apply`'s safety model.
```

In `README.md`, replace:

```markdown
Early development, but the core loop works end to end: **adopt → apply → audit**.
```

with:

```markdown
Early development, but the core loop works end to end: **adopt → apply → revoke /
rotate → audit**.
```

In `README.md`, replace:

```markdown
| `revoke` / `rotate` | — | Not separate commands: both reduce to a manifest edit plus `apply` |
```

with:

```markdown
| `revoke` / `rotate` | ✅ | Comment-preserving manifest edit + `apply` over the affected servers: offboard a user, drop a lost key, swap a key in place |
```

In `README.md`, replace:

```markdown
`audit`, `adopt` and `apply` authenticate with the SSH agent, `--identity` key
files, or both
```

with:

```markdown
`audit`, `adopt`, `apply`, `revoke` and `rotate` authenticate with the SSH agent,
`--identity` key files, or both
```

In `README.md`, replace:

~~~~markdown
### 4. Offboard someone

Delete their `users:` entry (or just the keys they no longer own) from the
manifest, then:

```console
$ sshepherd apply --server web-1   # canary one host first
$ sshepherd apply                  # then the rest of the fleet
```
~~~~

with:

~~~~markdown
### 4. Offboard someone

```console
$ sshepherd revoke alice --dry-run   # preview: the edit header and the plan
$ sshepherd revoke alice             # confirm once: save the manifest, then write
$ git commit -am "offboard alice" && git push
$ sshepherd audit
```

`revoke` removes the user and every `access:` entry naming them, keeps the
manifest's comments, and writes only the servers whose rendered `authorized_keys`
changes. See [`sshepherd revoke`](#sshepherd-revoke) and
[`sshepherd rotate`](#sshepherd-rotate).
~~~~

In `README.md`, replace:

```markdown
Monitoring-style, shared by `audit` and `apply` (code `2` is `audit`-only):
```

with:

```markdown
Monitoring-style, shared by `audit`, `apply`, `revoke` and `rotate` (code `2` is
`audit`-only):
```

In `README.md`, replace:

```markdown
(possible impersonation) — `apply` never returns `2` |
```

with:

```markdown
(possible impersonation) — `apply`, `revoke` and `rotate` never return `2` |
```

In `README.md`, replace:

```markdown
interrupted `audit`/`adopt`, `apply` interrupted before any write |
```

with:

```markdown
interrupted `audit`/`adopt`, `apply` interrupted before any write, a manifest that changed since it was read, a `revoke`/`rotate` refused before anything is saved (unknown user or key, an operator target without `--operator`, a manifest the edits cannot handle, a concurrent save) |
```

In `README.md`, replace:

```markdown
**Refusals, not guesses.**
```

with:

```markdown
**Manifest edits save before they write.** `revoke` and `rotate` save the edited
manifest exactly once — after the confirmation and before the first server is
written — under a lock (`.NAME.sshepherd-lock` next to the manifest, never deleted),
only if the file still holds the bytes the run read (otherwise
`manifest PATH changed since it was read; re-run`), atomically (a temp file with the
original's mode and owner, fsynced, renamed over the file; a symlinked manifest is
saved at its target). The worst crash leaves the manifest ahead of the fleet —
reported by `audit`, finished by any `apply` — never a revoked key the next `apply`
reinstalls. **Commit and push the manifest afterwards**: an `apply` run from a copy
without the edit grants the removed key again.

**Plain `apply` re-checks the manifest.** Just before its first write, `apply`
re-reads the manifest; if a concurrent `revoke` (or anything else) changed it since
the plan was made, the run stops with nothing written (`exit 3`) instead of
reinstalling a revoked key.

**Refusals, not guesses.**
```

In `README.md`, replace:

```markdown
cmd/sshepherd/       CLI: root command, audit, import, adopt, apply, E2E tests
```

with:

```markdown
cmd/sshepherd/       CLI: root command, audit, import, adopt, apply, revoke, rotate, E2E tests
```

In `README.md`, replace:

```markdown
internal/manifest/   comment-preserving manifest editing
```

with:

```markdown
internal/manifest/   comment-preserving manifest edits (append, remove, replace, operator flag)
```

In `README.md`, replace:

```markdown
specced in
[`docs/superpowers/specs/2026-10-16-identity-keyfile-auth-design.md`](docs/superpowers/specs/2026-10-16-identity-keyfile-auth-design.md).
```

with:

```markdown
specced in
[`docs/superpowers/specs/2026-10-16-identity-keyfile-auth-design.md`](docs/superpowers/specs/2026-10-16-identity-keyfile-auth-design.md);
`revoke` and `rotate` in
[`docs/superpowers/specs/2026-10-23-revoke-rotate-design.md`](docs/superpowers/specs/2026-10-23-revoke-rotate-design.md).
```

In `README.md`, insert the two command sections before `## Authentication` — replace:

```markdown

## Authentication
```

with:

~~~~markdown

### `sshepherd revoke`

Removes users or keys from the manifest — comments preserved — and pushes the edit
through `apply`'s pipeline (plan → confirm → guarded write → verify → login probe),
restricted to the servers whose rendered `authorized_keys` changes.

```console
$ sshepherd revoke alice                       # offboard: alice and every access entry naming her
$ sshepherd revoke --key ~/lost-laptop.pub     # one key: a fingerprint, a key line, or a .pub path
$ sshepherd revoke --key SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4
```

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--key KEY` | none | Key to revoke: a `SHA256:` fingerprint, a public-key line, or a `.pub` file path (repeatable) |
| `--operator` | off | Confirm that a target is, or belongs to, an operator user (fleet-wide, protected) |
| `--no-apply` | off | Edit and save the manifest after confirmation; contact no server |
| `--config` | `sshepherd.yaml` | Path to the manifest |
| `--known-hosts` | `~/.ssh/known_hosts` | `known_hosts` path (strict checking) |
| `--parallel` | `32` | Max concurrent server connections |
| `--dry-run` | off | Plan and report only; never write (the manifest is not changed) |
| `--yes` | off | Skip the confirmation prompt (automation) |
| `--identity PATH` | none | Private key file to authenticate with, in addition to `ssh-agent` (repeatable); `~/` expands from `$HOME` |
| `--identity-passphrase-file FILE` | none | Default passphrase file for any encrypted `--identity` key |
| `--identity-passphrase KEY=FILE` | none | Passphrase file for one `--identity` key (repeatable); split at the **first** `=` |

**Users or keys, not both.** `revoke USER...` deletes each user and every `access:`
entry whose `user:` is that user (unknown users are listed and nothing happens).
`revoke --key KEY...` removes each key line from its owner; a user left with no keys
stays with `keys: []`. A `KEY` is a `SHA256:` fingerprint (pasted `ssh-keygen -lf`
output works), a public-key line (quote it), or a path to a `.pub` file holding
exactly one key. MD5 fingerprints, certificates (`*-cert.pub`) and private keys are
refused with the fix; an error never quotes a file's contents. A key the manifest
does not grant is refused too — `apply` already removes it; `sshepherd audit` shows
where it is installed.

**The edit header** heads the plan:

```console
manifest edit: remove user alice (2 keys, 3 access grants) — 3 servers affected
warning: db-1 would have no granted keys — apply never empties a server, so alice's key stays installed there; grant another user (or an operator) on db-1 first, or remove the key by hand
```

```console
manifest edit: remove key SHA256:zbv/nU7iZdO0fB0DalMI70dP6/yFD8sctXvvW4+OokY from bob — 2 servers affected
note: bob has no keys left — 'sshepherd revoke bob' removes the user
```

**Scope.** Only servers whose rendered file changes are contacted, and on those the
full render also converges any other drift (shown in the plan). A revoked key still
installed on a server that never granted it is drift `revoke` does not reach — the
run ends with a `scope:` line pointing at `sshepherd audit` and `sshepherd apply`.

**Confirmation.** `revoke` always asks — even when every affected server already
matches, since the manifest edit is itself a change — or needs `--yes`. The prompt
names what will happen (all forms, from the golden test):

```console
save manifest edit and write 2 of 3 affected servers? [y/N]
save manifest edit (no servers need a write)? [y/N]
save manifest edit (no servers need a write)? [y/N]
save manifest edit? [y/N]
OPERATOR ops-bot: save manifest edit and write 1 of 4 affected servers? [y/N]
OPERATOR ops-bot: OPERATOR ci: save manifest edit? [y/N]
```

Declining exits `1` with `aborted; manifest not changed, nothing written`. When no
affected server can converge (every one refused), nothing is saved and the run
exits `1` without a prompt. `--dry-run` saves nothing and exits exactly as
`apply --dry-run` would. After the save the run prints
`manifest PATH updated — commit and push it: …`; servers left unconverged (failed,
refused for a fixable reason, unreachable, interrupted) are named in a ready-made
`sshepherd apply --server …` command.

**`--no-apply`** shows the header, asks, saves, and contacts nothing; it refuses
`--identity*`, `--known-hosts` and `--parallel` (they would be silently unused).
`--dry-run --no-apply` prints the header only.

**Operators.** A target that is, or belongs to, an `operator: true` user refuses the
whole command until you pass `--operator` (and `--operator` with no operator target
is refused too); `--yes` never substitutes for it. With it, the header carries an
`OPERATOR:` line, the prompt is prefixed `OPERATOR NAME: `, and revoking an
operator's last key also clears its `operator:` flag. The lockout guard still
applies on top.

**Limitations.**

- **A server is never emptied.** If the revoked user was a server's only grantee,
  the header warns (`would have no granted keys`), that server is refused, and the
  key stays installed — grant another user (or an operator) there first, or remove
  the key by hand.
- **Anchors and aliases.** A manifest using YAML anchors/aliases (or null list
  entries) cannot be edited faithfully:
  `cannot edit PATH: … — edit the manifest by hand and run 'sshepherd apply'`.
- **Fidelity.** Comments are preserved: a removed entry's comment moves to the next
  entry (or the section's end); a removed key line's own comment goes with it. Blank
  lines and quoting may normalize — review the `git diff` before you commit.

**Recipe: offboard someone.**

```console
$ sshepherd revoke alice --dry-run
$ sshepherd revoke alice
$ git commit -am "offboard alice" && git push
$ sshepherd audit
```

**Recipe: a lost laptop.**

```console
$ sshepherd revoke --key ~/keys/alice-laptop.pub
$ git commit -am "revoke alice's laptop key" && git push
$ sshepherd audit
```

### `sshepherd rotate`

Replaces one of a user's keys in place and pushes the swap the same way: the old key
is dead fleet-wide in the same run.

```console
$ sshepherd rotate deploy --old SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o --new ~/.ssh/deploy_2027.pub
```

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--old KEY` | — | Key to rotate out: a `SHA256:` fingerprint, a public-key line, or a `.pub` file path |
| `--new KEY` | — | Key to rotate in: a public-key line or a `.pub` file path |
| `--operator` | off | Confirm that the user is an operator (fleet-wide, protected); the flag is kept |
| `--no-apply` | off | Edit and save the manifest after confirmation; contact no server |
| `--config` | `sshepherd.yaml` | Path to the manifest |
| `--known-hosts` | `~/.ssh/known_hosts` | `known_hosts` path (strict checking) |
| `--parallel` | `32` | Max concurrent server connections |
| `--dry-run` | off | Plan and report only; never write (the manifest is not changed) |
| `--yes` | off | Skip the confirmation prompt (automation) |
| `--identity PATH` | none | Private key file to authenticate with, in addition to `ssh-agent` (repeatable); `~/` expands from `$HOME` |
| `--identity-passphrase-file FILE` | none | Default passphrase file for any encrypted `--identity` key |
| `--identity-passphrase KEY=FILE` | none | Passphrase file for one `--identity` key (repeatable); split at the **first** `=` |

- `--old` must belong to `USER`; `--new` must not already be in the manifest and
  must differ from `--old`.
- The new line replaces the old at the same position. The old line's **options**
  (`from=`, `command=`, `restrict`, …) carry over; options written on `--new` are
  refused (`rotate keeps the old line's options; edit them in the manifest`).
- The **comment** is the new key's, else the old line's inline comment.
- A carried-over `expiry-time=` that has already passed is refused before any edit
  (the new key would be rejected by sshd); a future one is named in the header.
- Confirmation, saving, `--dry-run`, `--no-apply`, operators and the scope line work
  exactly as for `revoke`.

```console
manifest edit: rotate deploy key SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o → SHA256:LA4QoSmstGCy/UHfdU3jKjnPz56pQzud9OmslMh3g8w (keeps expiry-time="20270101") — 5 servers affected
```

**Rotating the key you log in with.** Pass the new private key with `--identity`, so
the lockout guard sees it survive and the post-write login probe proves it — headless
too:

```console
$ sshepherd rotate ci --operator --old ~/.ssh/ci_old.pub --new ~/.ssh/ci_new.pub \
    --yes --identity ~/.ssh/ci_old --identity ~/.ssh/ci_new
$ git commit -am "rotate the ci key" && git push
$ sshepherd audit --identity ~/.ssh/ci_new
```

## Authentication
~~~~

Run:

```bash
go test ./cmd/sshepherd -run 'TestHelp'
```

Expected: PASS, output includes:

```text
ok  	github.com/javadh75/SSHepherd/cmd/sshepherd	(…s)
```

- [ ] **Step 3: Status and spec cross-references**

In `CLAUDE.md`, replace:

```markdown
the guard for a headless run. Headless rotation (old + new `--identity`) is
covered end to end by the integration suite.
```

with:

```markdown
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
`runApply(applyRun)`, and plain `apply` re-checks the manifest before writing.
Report count strings are pluralized. The E2E loop is adopt → apply → revoke
--key → audit → rotate → audit, plus a headless `rotate`.
```

In `docs/superpowers/specs/2026-10-23-revoke-rotate-design.md`, replace:

```markdown
- **Status:** Approved design (brainstorm 2026-10-23), revised after an
  adversarial three-lens critique (safety, feasibility against the code,
  operator UX); pending owner review of the written spec.
```

with:

```markdown
- **Status:** Implemented (2026-10-23) — see
  `docs/superpowers/plans/2026-10-23-revoke-rotate.md`. Approved design
  (brainstorm 2026-10-23), revised after an adversarial three-lens critique
  (safety, feasibility against the code, operator UX), owner-approved.
```

In `docs/superpowers/specs/2026-07-19-apply-slice-design.md`, replace:

```markdown
- **Amended by:** [`--identity` key-file auth](2026-10-16-identity-keyfile-auth-design.md) (2026-10-16) — the guard's "held keys" are no longer agent-only.
```

with:

```markdown
- **Amended by:** [`--identity` key-file auth](2026-10-16-identity-keyfile-auth-design.md) (2026-10-16) — the guard's "held keys" are no longer agent-only; [`revoke` / `rotate`](2026-10-23-revoke-rotate-design.md) (2026-10-23) — the deferred verbs, apply's run reusable as `runApply`, plain `apply` re-checks the manifest before writing.
```

In `docs/superpowers/specs/2026-07-10-operator-users-wildcard-access-design.md`, replace:

```markdown
- **Status:** Implemented (2026-07-10) — see docs/superpowers/plans/2026-07-10-operator-users-wildcard-access.md
```

with:

```markdown
- **Status:** Implemented (2026-07-10) — see docs/superpowers/plans/2026-07-10-operator-users-wildcard-access.md
- **Amended by:** [`revoke` / `rotate`](2026-10-23-revoke-rotate-design.md) (2026-10-23) — implements the protection contract: operator targets need `--operator`.
```

In `docs/superpowers/specs/2026-07-16-adopt-merge-design.md`, replace:

```markdown
- **Status:** Implemented (2026-07-16)
```

with:

```markdown
- **Status:** Implemented (2026-07-16)
- **Amended by:** [`revoke` / `rotate`](2026-10-23-revoke-rotate-design.md) (2026-10-23) — `internal/manifest` also removes and replaces entries; Load's rejection texts are command-neutral.
```

- [ ] **Step 4: Roadmap memory (integrator, outside the repo)**

In `~/.claude/projects/-Users-javad-w-personal-SSHepherd/memory/roadmap-next-slices.md`, replace the paragraph's first line

```text
As of 2026-10-16 the review-hardening pass (ca549fa, 53 findings) also
```

with

```text
As of 2026-10-23 item 2 (`revoke`/`rotate`) shipped, folding in the item-5
pluralization debt — next up is item 3 (`apply --json`).
As of 2026-10-16 the review-hardening pass (ca549fa, 53 findings) also
```

- [ ] **Commit**

```bash
git add README.md CLAUDE.md cmd/sshepherd/help_readme_test.go docs/superpowers/specs
git commit -m "$(cat <<'EOF'
docs: revoke and rotate in README, Status and spec cross-references

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

### Task C2.7: Full gate [Group C2]

**Files:** none (verification only).

- [ ] **Step 1: Formatting, vet, dead code, race tests with coverage**

Run:

```bash
test -z "$(gofmt -l .)" && go vet ./... && deadcode ./cmd/sshepherd && go test -race -covermode=atomic -coverprofile=coverage.out ./... >/dev/null && go tool cover -func=coverage.out | tail -1
```

Expected: PASS, output includes:

```text
total:									(statements)			90.0%
```

Coverage stays well above the 80% gate (verified: ~90%).

- [ ] **Step 2: The CI gate and the slow suites**

Run, in order: `make check` (tidy, fmt, vet, lint, deadcode, gosec/govulncheck/gitleaks, coverage — all must pass; if `make lint` reports a toolchain mismatch, `make tools` first), `make integration` (Docker), `make -k fuzz` (every target, 15s each). Expected: each exits 0.

- [ ] **Step 3: Integrator commit (if group agents did not commit)**

One commit (or one per stage) containing code, tests, goldens, README and Status together — the README must never trail the code.

## Self-review

### Spec coverage

| Spec requirement | Task(s) |
| ---------------- | ------- |
| Command surface, KEY forms, classification order, every refusal (missing path lists forms, private key never quoted, certificate, zero/several lines, MD5, `--new` fingerprint/options) | C1.3 (`keyarg.go` + `TestClassifyKeyArg`, `TestClassifyPrivateKeyNeverQuotesContents`), C2.4 (`FuzzKeyArg`) |
| Usage rules (users⊕`--key`, no target, rotate arity, `--dry-run`⊕`--yes`, `--no-apply` with connection flags, USER that looks like a key) | C2.1 (`editFlags.validate`), C2.2 (`revokeTargets`, `TestRevokeUsage`), C2.3 (`TestRotateRefusals`) |
| `revoke USER...` (unknown listed, dedup), `revoke --key` (not-in-manifest text, `keys: []` + note, dedup) | M2, C2.2 |
| `rotate` (ownership, novelty, same index, options carried, options on `--new` refused, expiry passed/future, comment rule, operator kept) | M3, C1.3, C2.3 |
| Operators (refused by default, all named, `--operator` without target refused, last key clears flag, `OPERATOR` header + prompt prefix, `--yes` never substitutes) | C2.1 (`operatorGate`), C2.2 (`TestRevokeOperator`), A4 (header/prompt goldens) |
| Order of operations 1–8 (no network before 5, no write before 7) | C2.1 (`runEdit`, `saveOnly`), C1.2 (`runApply`) |
| Step 2 uneditable manifest → `cannot edit PATH: …` | M1 (`UnsupportedError`), C2.1, `TestRevokeUsage/anchors_cannot_be_edited` |
| Step 3 one `Encode`, new warnings printed | C2.1 (`encodeEdit`, `runEdit`) |
| Step 4 `Affected` / `Emptied` + header warning before connections | A3, A4, C2.1, `TestRevokeSoleGrantee` |
| Step 5 key preference old-then-new; probe survivors under new config; `(revoked)`/`(rotated out)` labels | C2.1 (`preferKeys`), A2, `TestRotateOwnKeyWithNewIdentity` |
| Step 6 always confirm, three prompt forms + prefix, nothing-can-land, decline, `--dry-run` exits as apply | A4 (`edit_prompt.golden`), C1.2, C2.1, `TestRevokeAlreadyConverged`, `TestRevokeNothingCanLand`, `TestRevokeDeclined`, `TestRevokeDryRun` |
| Step 7 save once; in `beforeWrite` after the re-list and before `Execute`; ctx check; no-survivor refusal; lock/CAS/atomic/mode/owner/symlink; "commit and push" line | C1.2 (`writePhase`), C1.4 (`Save`), C2.1, `TestManifestSave*`, `TestRevokeHeldKeysGoneAfterPrompt`, `TestRevokeInterruptedAtPrompt`, `TestRevokeCASConflict`, `TestRevokeSymlinkedManifest` |
| Step 8 finish hint (emptied excluded) and scope line | C2.1 (`finishEdit`), `TestRevokePartialFailure`, `TestRevokeSoleGrantee`, `TestRevokeKeyLeavesUngrantedDrift` |
| `--no-apply`, `--dry-run --no-apply` | C2.1, `TestRevokeNoApply` |
| Plain `apply` re-checks the manifest; goldens change only by pluralization | C1.2 (`TestApplyRefusesChangedManifest`), A1 (golden diff review) |
| `internal/manifest` edits + comment rules + command-neutral Load + package doc | M1–M3 |
| `internal/apply` `Affected`, `EditSummary`/`RenderEditHeader`, `RenderOptions.Former`, pluralization | A1–A4 |
| Testing: manifest unit (block/flow, first/last/only, rescue to sibling/footer never above header, keys comments dropped, `keys: []`, operator flag, ReplaceKey, several edits one Encode, goldens, re-parse) | M2, M3 |
| Testing: `Affected` (wildcard+except, operator, no grants, rotation, sole grantee) | A3 |
| Testing: every hermetic command bullet | C1.2, C1.4, C2.2, C2.3 (mapping in C2.2's intro) |
| Testing: Integration/E2E loop + headless rotate | C2.5 |
| Testing: `FuzzManifestEdit`, `FuzzKeyArg`, committed seeds | M4, C2.4 |
| Testing: goleak/race/coverage | existing `TestMain` per package (no new packages); `-race` in every gate; C2.7 |
| Docs: README rows/tables/recipes/limitations/safety notes/fidelity; help-test lists; CLAUDE.md; Amended-by lines; roadmap memory | C2.6 |

### Spec ambiguities resolved in this plan

1. **Rescued comment vs an existing section footer.** The spec says a rescued head comment is "appended to the section key's `FootComment`". `yaml.v3` puts the document footer (e.g. `# reviewed 2026-10-01`) on the last section key's `FootComment`, so a literal append would move the rescued comment *below* the footer. `removeItems` inserts it at the **front** of the foot comment, preserving source order (pinned by `edit_remove_user.golden`).
2. **Header with several edits.** The spec's shapes show one edit per line with the count inline. With more than one edit, each edit gets its own line and a closing `manifest edit: N changes — M servers affected` line carries the count (`edit_header_operator.golden`).
3. **Emptied-server wording** for several keys/users: `alice's key stays` / `alice's keys stay` / `the keys of alice, ops-bot stay` (`stayText`).
4. **`--no-apply` output.** The save always prints the spec's `manifest PATH updated — commit and push it: …` line; `--no-apply` then prints `no servers contacted — N affected server(s) still carry/carries the old keys; run 'sshepherd apply --config … --server …' to push` (or `… — no server's desired keys changed`) instead of repeating "manifest PATH updated".
5. **Finish/push hints** include `--config PATH` when it is not the default `sshepherd.yaml` (shell-quoted when needed), so the printed command is runnable as-is.
6. **Zero affected servers** (e.g. revoking a user with no grants) asks with the `(no servers need a write)` prompt, saves, and prints the scope line `(0 of M)` when a key was removed — the removed key may still sit on servers as drift.
7. **Declined edit prints no summary**: the summary's `→ exit N` could read 0 while a declined edit exits 1.
8. **`applyRun` fields.** The spec lists `loadedBytes`; plain apply's loaded bytes live in `manifestTarget`, captured by its `beforeWrite` closure (`m.Unchanged()`), and `formerNote` is added for the rotate label. No other field.
9. **Pluralization scope.** "Every count string" covers counts of keys/lines (including the lockout refusal and apply's `(N server(s) skipped by --server)`); ratios (`1/4 servers converged`, `apply 1 of 1 servers?`) are left unchanged.
10. **Interrupt inside `beforeWrite`.** A ctx cancelled between the prompt and the save exits 3 with `interrupted: … — manifest not saved, nothing written`.
11. **Non-unix builds.** `flock` is linux/darwin only (like `keyfile`'s terminal code); elsewhere the save refuses rather than writing unlocked.
12. **File layout.** KEY classification lives in `keyarg.go` and the shared verb driver in `editrun.go` (the spec named only `edit.go`, `revoke.go`, `rotate.go`).

### Placeholder and type-consistency scan

Every code step carries complete code; every expected output above was captured from running that exact step against a pristine copy of the repo (the plan builder replays all edits in order and fails on any mismatch). An independent replay of the whole plan then ran the full `make check` set — `gofmt`, `go vet` (also `-tags=integration` and `GOOS=windows`), `golangci-lint` v2.12.2 built with go1.26.4 (0 issues; it first caught `gocyclo` > 15 in `planOne`/`pathArg`/`planRotate`, a non-wrapping `%v`, and a `real` shadowing the builtin — fixed above via `theLines`, `keyFileArg`, `rotatedLine`, `%w`, `target`), `deadcode`, `gosec`, `gitleaks` (a test variable named `secret` tripped `generic-api-key`; renamed `material`), `go mod tidy -diff`, race tests with coverage (90.0% on go1.26.4) — plus `make integration` and 30 s of each new fuzzer. Signatures used across groups match the [Interfaces](#interfaces) section (`RemoveUser`/`RemoveKey`/`ReplaceKey`/`SetOperator`, `Affected(old, edited)`, `RenderEditHeader`, `EditPrompt`, `RenderOptions{Former, FormerNote}`, `runApply`/`applyRun`, `manifestTarget.Save`, `classifyKeyArg`/`parseKeyArg`).

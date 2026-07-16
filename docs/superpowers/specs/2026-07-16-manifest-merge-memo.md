- **Status:** Proposed — awaiting owner decision (drafted 2026-07-16 by parallel design workflow)

# Design-draft memo: manifest merging for `import` and `adopt`

- **Date:** 2026-07-16
- **Status:** Draft for owner review — no code
- **Prior art:** `docs/superpowers/specs/2026-07-09-import-ssh-config-design.md` (deferred: "Merging into an existing manifest"), `docs/superpowers/specs/2026-07-10-adopt-fleet-discovery-design.md` (deferred: "In-place manifest merging or comment-preserving YAML round-trip")
- **Code read:** `cmd/sshepherd/manifest_out.go`, `cmd/sshepherd/import.go`, `cmd/sshepherd/adopt.go`, `internal/adopt/adopt.go`, `internal/config/config.go`

## Context

Both generators are deliberately generate-only today: `-o` refuses to overwrite without `--force`, and both specs explicitly deferred merging. But the two commands are *not* equally far from merging, and that asymmetry should drive the design:

- **`adopt` already has merge semantics, just not merge rendering.** It loads the manifest, attributes every unauthorized key against it (`cfg.OwnerOf` hit → access `Extension` for the owning user; miss → `NewUser`), respects `except:` carve-outs, resolves name collisions against existing users with `-2`/`-3` suffixes, and emits *existing sections verbatim + additions* in a fixed order (`generateAdoptManifest`). What it loses is everything `config.Parse` discards: the operator's comments, blank lines, key ordering nuances. The output is semantically a merge, textually a regeneration.
- **`import` has neither.** It never looks at an existing manifest; it converts `~/.ssh/config` from scratch. Re-running import after adding one host to `config.d/` produces a whole new draft the operator must reconcile by hand — exactly the toil this project exists to remove (and the user's real `~/.ssh/config` is now an `Include`-per-company layout that changes often).

So "merging" is really two features: a **comment-preserving output mode** (benefits adopt immediately) and **import-vs-manifest reconciliation logic** (new semantics, new conflict surface).

## What merging means, per section

Identity keys differ per section, and that drives everything:

- **`servers:`** — keyed by `name` (validation rejects duplicates, `*` reserved). Merge = add entries whose name is absent. A name collision with *different* `host`/`port`/`user` is a genuine conflict (see conflict rules). Only import can produce this; in adopt the servers *came from* the manifest, so its server section is always a pass-through.
- **`users:`** — the real key is the **key fingerprint**, not the name. `config.validateUsers` rejects the same fingerprint under two users, so a merge that naively appends an import-derived user whose key already exists in the manifest produces output the `config.Parse` self-check rejects as "bug:". Merge must dedupe by fingerprint first, name second. Name is only a label; fingerprint is identity.
- **`access:`** — the friendliest section: the config layer already unions duplicate grants silently (`validateAccess`'s `granted` map), so appending entries is semantically idempotent. Two invariants must hold: never emit a grant that violates a wildcard user's `except:` carve-out (adopt's `hasExceptCarveOut` rule, already implemented), and never emit `except:` without `["*"]`.

### Per command

**`adopt --merge` (or whatever the flag is)** changes only *rendering*: instead of round-tripping the manifest through `config.Parse` and re-encoding `manifestOut`, take the original file text, preserve it, and append the plan's `NewUsers`/`Extensions` (plus the header/partial warnings — which now must go somewhere that isn't "line 1 of a regenerated file"; likely above the appended block). `internal/adopt.Build` needs zero changes.

**`import --merge`** is additive reconciliation, and must be **strictly additive**: a host that disappeared from `~/.ssh/config` must *not* be removed from the manifest — the manifest is the source of truth; ssh config is one input. Removal is a human decision (or a future `prune`). Concretely:

1. Load the existing manifest (full `config.Parse`, so we get `OwnerOf` and validation for free).
2. Servers: add aliases not present by name; conflicts per rules below.
3. Users: for each identity-derived user, look up its key fingerprint via `OwnerOf`. Known → do **not** create a user; optionally extend the owning user's access (adopt's `Extension` concept, reusable as-is). Unknown → new user, name-collision-suffixed like adopt.
4. Access: append; union semantics absorb overlap.

The `--operator` interaction needs one rule: `import --merge --operator k.pub` where `k`'s fingerprint already belongs to a non-operator manifest user should be an error or loud warning, never a silent `operator: true` flip on someone's hand-written user — operator status protects keys from future revocation, so promoting must be explicit.

## The comment-preserving round-trip problem

The adopt spec already rejected in-place regeneration precisely because "YAML re-encode loses the user's comments". Three strategies:

**A. `yaml.v3` node API (decode to `*yaml.Node`, surgically append, re-encode).** Decoding into a `yaml.Node` preserves `HeadComment`/`LineComment`/`FootComment`; merge appends new mapping nodes to the three section sequences and re-encodes the whole document. *Honest trade-offs:* blank lines between blocks are **not** modeled and vanish; comment indentation in nested structures has known re-indent quirks; quoting/flow styles mostly survive via `Style` but some scalars re-normalize; long lines may re-fold at the encoder's width. Also strategic: `gopkg.in/yaml.v3` upstream is archived/unmaintained — building on its node-API corner cases deepens a dependency we may eventually have to replace (goccy/go-yaml has richer comment support, but the project's supply-chain stance — depguard, SBOM, hand-rolled `internal/sshcfg` over a dep — argues against adding it for this). Fidelity contract: "your comments survive; your whitespace aesthetics may not."

**B. Regenerate-and-lose-comments (status quo).** Zero new machinery, already golden-tested. Acceptable for a fresh draft; **not** acceptable as a merge target — the whole point of merging is that the manifest is now a hand-maintained, commented file. Rejected for merge, retained as the non-merge default.

**C. Text-splice append (parse for positions, insert rendered lines, touch nothing else).** Parse with the node API only to learn where each section's sequence ends (`yaml.Node.Line`), render the new entries with the existing `manifestOut` encoder, and splice the text in. Byte-perfect preservation of everything existing — the strongest fidelity, and the diff is beautiful. *Honest trade-offs:* yaml.v3 nodes carry start positions, not end positions, so "where does the last item of `users:` end" must be inferred from the next node/EOF — fiddly around trailing comments; and the killer detail: our own generators emit empty sections as flow-style `users: []`, which is exactly the common bootstrap case — appending to it requires rewriting that one line to block style, so "never touch existing lines" is already false in the most common flow. More edge cases per unit of value than A.

**Recommendation: A**, with a documented fidelity contract (comments preserved; blank lines and quote styles may normalize) and a hard safety net: golden round-trip tests on commented fixtures, a fuzz target (project rule: fuzz all parsers — a merge round-trip is a parser), the existing `config.Parse` self-check on the merged output, and the existing atomic `writeFileNoClobber` for any file write. If the owner insists on byte-perfect diffs, C is buildable later behind the same interface.

## Conflict rules

| Conflict | Rule | Rationale |
|---|---|---|
| Same server name, different host/port/user (import only) | **Manifest wins; warn on stderr + header comment** | The manifest is the source of truth; a silent overwrite could redirect a future `apply` at a different machine. Skip-and-warn is loud, reviewable, and reversible. A `--prefer` override is deferrable. |
| Same key fingerprint, different user name | **Manifest owner wins; no new user; optionally extend owner's access; warn** | `config.Parse` rejects duplicate fingerprints anyway — this rule turns a would-be self-check "bug:" abort into the correct semantic. Mirrors adopt's known-key path exactly. |
| Same user name, different key | **Suffix incoming name (`-2`, `-3`) + warn; never append the key to the existing user** | Adopt's existing collision rule. Appending would grant a possibly-different human everything the existing user has. Loud over-splitting beats quiet identity merging (the adopt spec's locked stance). |
| Overlapping access grants | **Append; config-layer union absorbs it** | Already-defined semantics; duplicates are harmless. |
| Server in a user's wildcard `except:` | **Never re-grant; warn; leave for audit** | Locked adopt decision, carried unchanged into any merge mode. |
| `--operator` key owned by an existing non-operator user | **Error (or refuse the flip)** | Operator status changes apply/revoke protection; must be an explicit manifest edit. |

## UX

- **Flag:** `--merge FILE` on `import` (names the manifest to merge into). On `adopt`, the manifest is already `--config`, so a boolean `--merge` ("preserve the input file's text; append additions") suffices — no second path. Avoid overloading `-o`: output destination and merge source are different roles. `--into` reads nicely but `--merge` states the semantic; pick one and use it on both commands.
- **Output contract unchanged:** stdout by default, `-o`/`--force`/atomic no-clobber as today. This preserves adopt's locked "input untouched" decision — merge is a *rendering mode*, not an in-place mutation. In-place is then spelled explicitly: `adopt --merge -o sshepherd.yaml --force`, which is honest about what it does and already write-safe (temp file + rename).
- **Dry-run/diff:** stdout *is* the dry run. Add a one-line summary via the existing leveled logger ("merged: +2 users, +1 server, +3 access entries, 1 conflict skipped"). A built-in `--diff` is tempting but duplicative — the operator has `git diff` and the file is meant to be committed; defer it.
- **Header:** don't stack a fresh `# generated by…` header on every merge run. Append a dated `# merged by sshepherd import from <src> on <date>` comment above the appended block instead, so history accretes where the additions live.

## Scope slicing — recommendation

**Slice 1 — comment-preserving append, adopt first.** Build `internal/manifest` (or a sub-file of `internal/config`): load a manifest file into a `yaml.Node` tree alongside the validated `*Config`, `AppendUsers/AppendServers/AppendAccess` node surgery, encode. Wire it as `adopt --merge`. No new conflict logic — adopt's attribution already handles every conflict its inputs can produce. Golden tests on commented fixtures, fuzz the round-trip, self-check retained. This ships the hard, reusable part against the command that needs zero semantic work.

**Slice 1 must NOT do:** import reconciliation, any deletion/pruning, reordering or normalizing existing entries, interactive conflict resolution, heuristic user identity merging (still deferred, per adopt spec), byte-perfect blank-line fidelity.

**Slice 2 — `import --merge FILE`:** the reconciliation table above (fingerprint dedupe, manifest-wins server conflicts, name suffixing, optional access extension), reusing slice 1's renderer and adopt's `Extension` shape.

**Never in scope for merge:** removing anything from a manifest. That is `apply`/`prune` territory with its own safety story.

## Open decisions (owner only)

1. **Fidelity contract:** accept strategy A's "comments yes, blank lines/quote style no" — or require the byte-splice (C) level of fidelity, at the cost of the flow-`[]` rewrite and end-position edge cases?
2. **yaml.v3 dependence:** comfortable deepening into an archived library's node API, or is this the moment to evaluate goccy/go-yaml against the depguard/supply-chain stance?
3. **Conflict default for import server clashes:** manifest-wins-and-warn (recommended) vs hard error (nothing written)? And is a `--prefer=manifest|source` override wanted ever, or is that a footgun?
4. **Should `import --merge` extend access for already-known keys** (adopt-like `Extension`), or only add net-new users/servers and leave known-key placement entirely to `adopt`? (Leaner import keeps one command per concern; extension makes a single `import --merge` run more complete.)
5. **Flag spelling:** `--merge` vs `--into`, and whether `adopt --merge` should even be a flag or eventually the default once trusted.
6. **In-place blessing:** is `--merge -o <same file> --force` an acceptable spelling for in-place, or does the owner want it refused outright to keep "input untouched" absolute?

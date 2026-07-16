- **Status:** Decided 2026-07-16 — Option A for write-time (`comment` → inline → `name`, with the
  multi-key warning and full-file-render-in-apply mitigations) and Option 2 for
  drift reporting (opt-in `--comments`, informational only, exit codes
  untouched). The "can land now" items are implemented; the write path itself
  waits for the apply slice.

# Decision memo: key comments at write time, and comment drift in audit

**For:** project owner, before the apply slice is designed
**Date:** 2026-07-16
**Settles two open questions from** `docs/superpowers/specs/2026-07-06-audit-slice-design.md`:
1. interaction between `users[].comment` and a key's inline comment at write time
2. whether audit should report comment drift (informational, non-failing)

---

## Context — what the code says today

- **`internal/config/config.go:24`** — `User.Comment` is documented as *"written as the key comment by the apply slice"*, and validated (no line breaks, so it can never forge an extra `authorized_keys` line). The audit spec's field-semantics section already sketches a write-time fallback order: **`comment` → the key's own inline comment → `name`** — but flags the interaction as an open question.
- **`internal/authkeys/authkeys.go`** — `Key` carries both `Comment` (parsed trailing comment) and `Raw` (the original line verbatim). `Diff` is **fingerprint-identity only**; comments and options are invisible to it, and the audit spec explicitly lists comment mismatches as "not drift in v1".
- **`internal/audit/report.go:143` (`label`)** — the report already *displays* `Comment` next to the owner name (`alice (alice@sshepherd)`), so the field has a live read-side use regardless of what write-time does.
- **Round-trip reality:** `import` (`cmd/sshepherd/import.go:63`) sets `comment:` to the `.pub`'s inline comment *and* stores the full key line — so for imported manifests the two are identical today. `adopt` (`internal/adopt/adopt.go:97`) preserves the discovered line verbatim (`Key.Raw`) and derives the generated user *name* from the inline comment (`sanitizeName`), but sets no `comment:` field. Adopt also already warns when the same fingerprint appears with differing comments/options across servers ("keeping the first").

One structural fact shapes everything below: **`keys:` is a list.** A user can hold several keys (`alice@laptop`, `alice@yubikey`), so any policy where a single user-level `comment:` overwrites every key's comment erases per-key distinction on the server — which matters for the future `rotate` slice ("which of alice's keys is the old one?").

---

## Decision (a): write-time comment policy

### Option A — user `comment:` wins when set; fallback inline comment; fallback `name` *(the spec's sketched order)*

Apply writes each key as `options… key-material COMMENT` where `COMMENT` = `user.Comment` if non-empty, else the key line's own inline comment, else `user.name`.

- **Pros:** The manifest is genuinely authoritative — an operator can normalize on-server attribution fleet-wide ("alice — platform-team") without editing every key line. Every written key is guaranteed a non-empty, meaningful comment (worst case the user's manifest name), so anyone `cat`-ing `authorized_keys` on a box can answer "whose key is this?" — squarely the project's audit mission. Matches the doc string on `User.Comment` and the spec's field semantics, so no doc churn.
- **Cons:** Setting `comment:` on a multi-key user collapses all keys to the same comment — per-key identity (`@laptop` vs `@yubikey`) is lost on the server (it survives in the manifest key lines, so nothing is destroyed, but on-server distinction is gone). It also rewrites content the key owner put there, which some operators find surprising.
- **Round-trip/adopt:** benign in practice. Imported manifests already have `comment:` == inline comment, so A writes byte-identical comments. Adopting a post-apply fleet finds only known fingerprints — no new users, no churn. The only visible effect is on hand-edited manifests where someone deliberately set `comment:`, which is exactly the case where they want it enforced.

### Option B — manifest key line verbatim; `comment:` becomes display-only metadata

Apply writes `Key.Raw` exactly as it appears in `keys:`; `users[].comment` is only ever a report label (its sole use today, in `report.go` `label()`).

- **Pros:** Simplest possible write path — the file is a pure concatenation of manifest lines, trivially golden-testable, and `adopt → apply → adopt` is byte-for-byte idempotent. Per-key comments always survive. Zero surprise: what you see in the manifest is what lands on the server.
- **Cons:** Contradicts the existing `User.Comment` doc string and the spec's field semantics — the field's name becomes a lie ("comment" that is never written as a comment) and needs renaming or re-documenting. Keys whose manifest line has no inline comment get **no attribution on the server at all**, undermining the human-auditability story. The `comment:` knob loses its one future purpose while keeping its misleading name.
- **Round-trip/adopt:** perfect, trivially.

### Option C — inline comment wins; `comment:` only fills gaps (inline → `comment` → `name`)

The inverse precedence: a key's own inline comment is preserved; the user-level field is a default for comment-less keys; `name` is the last resort.

- **Pros:** Preserves per-key identity automatically (no multi-key collapse) while still guaranteeing attribution for bare keys. Nearly as round-trip-clean as B.
- **Cons:** `comment:` becomes weak — it silently does nothing for any key that already has an inline comment, which is *most* keys (ssh-keygen adds `user@host` by default). An operator who sets `comment: "alice — platform team"` and finds it ignored on 9 of 10 keys will file that as a bug. The precedence inversion also flips the documented semantics, so it has A's doc churn with less of A's power.

### Recommendation: **Option A** — confirm the spec's fallback order (`comment` → inline → `name`)

It is the only option where `comment:` does what its name, its doc string, and the spec all already promise, and it is the only one that guarantees attribution while giving the operator an explicit normalization knob. The multi-key collapse is real but self-inflicted and opt-in: leave `comment:` unset and inline comments survive untouched (i.e., A *degrades to* C's behavior for users without the field). Two mitigations worth writing into the apply spec:

1. A validation **warning** (not error) when `comment:` is set on a user with 2+ keys, so the collapse is a conscious choice.
2. Nail down apply's write model at the same time: **full-file render from the manifest** (not surgical fingerprint edits). With surgical edits, an already-present key never gets its comment rewritten and Option A only applies to newly added lines — the policy would be half-enforced forever. Full-file render is also what the CLAUDE.md golden-test requirement assumes. This is the one genuine dependency between this decision and apply's design.

---

## Decision (b): should audit report comment drift?

"Comment drift" = for a key that is present-and-authorized (fingerprint matches), the on-server trailing comment differs from the write-policy's desired comment (under Option A: `comment` → inline → `name`). It is definitionally cosmetic — fingerprint identity is untouched — so it must **never** affect the exit code or the compliant/drift/critical classification.

### Option 1 — never report it

- **Pros:** zero noise; keeps the report focused on access-relevant drift; nothing to build.
- **Cons:** comments are the on-server half of the audit story — an operator reading `authorized_keys` directly sees attribution that SSHepherd knows is stale and said nothing about. Also removes the only pre-apply way to preview what apply's comment normalization would rewrite.

### Option 2 — opt-in flag, informational rows

E.g. `sshepherd audit --comments`: OK rows whose actual comment differs from the desired one gain an informational annotation (`✓ alice … present & authorized · comment differs: "old@box" → "alice@sshepherd"`); JSON gains the field only when the flag is set. Exit code untouched.

- **Pros:** auditability on demand with silence by default. Critically, on any fleet that has **never been applied**, nearly every key's comment can differ from the Option-A desired comment — always-on reporting would drown real drift in dozens of informational lines during exactly the adoption phase where audit output matters most. Opt-in also doubles as a free **dry-run preview of apply's comment rewrites**.
- **Cons:** one more flag; discoverability is only as good as `--help`; drift nobody asks about still rots silently.

### Option 3 — always-informational

- **Pros:** nothing hides; no flag to remember.
- **Cons:** the pre-apply noise problem above, plus it changes the default report and JSON shape (golden tests, downstream parsers) for a cosmetic signal. The report's signal-to-noise is a product feature; this spends it on the lowest-value drift class.

### Recommendation: **Option 2 — opt-in flag, informational only, never affects exit codes.**

Revisit "on by default" only after apply exists and fleets are normally converged (at which point drift lines would be rare and meaningful).

---

## What depends on the apply slice vs what can land now

**Genuinely blocked on apply:**
- The write path itself, and the decision it forces: full-file render vs surgical edit (recommend full-file, see above — it is what makes Option A actually converge).
- Golden tests of the rendered `authorized_keys`.

**Can land now, independent of apply:**
1. **Spec update** — promote the fallback order from "sketched" to decided in the audit spec (or the future apply spec), closing both open questions.
2. **A pure `DesiredComment(u User, k Key) string` helper** (in `config` or `authkeys`) encoding `comment → inline → name`, fully unit-testable today. Apply, the drift check, and any future `sshepherd render` all consume it — writing it now fixes the contract before apply's design starts.
3. **The multi-key `comment:` validation warning** in `config.validate` (needs the leveled logger already in place, or a returned-warnings mechanism).
4. **The `--comments` audit flag itself.** Everything it needs exists except one small seam: `Diff`'s `OK` slice keeps only the *desired* `Key`, so the actual (on-server) comment for a matched fingerprint is currently dropped — `internal/authkeys` `Result.OK` would need to become a desired/actual pair (or `Result` grows an `ActualByFingerprint` map). Small, test-covered change; reasonable to land now or fold into the apply slice, whichever sequences better.

**Bottom line:** confirm Option A (user `comment:` wins, inline fallback, `name` last resort) plus full-file rendering in apply; add comment-drift reporting as an opt-in, informational-only audit flag. Deciding both now unblocks the apply slice design with the comment contract fixed, and lets the `DesiredComment` helper, validation warning, and spec edits land immediately.

